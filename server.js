import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT || 8787);
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);
const NODE_ENV = String(process.env.NODE_ENV || "development").trim().toLowerCase();
const IS_PROD = NODE_ENV === "production";

const SMTP_HOST = String(process.env.SMTP_HOST || "").trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_SECURE = String(process.env.SMTP_SECURE || "true").toLowerCase() === "true";
const SMTP_USER = String(process.env.SMTP_USER || "").trim();
const SMTP_PASS = String(process.env.SMTP_PASS || "").trim();
const EMAIL_PROVIDER = String(process.env.EMAIL_PROVIDER || "smtp").trim().toLowerCase();
const BREVO_API_KEY = String(process.env.BREVO_API_KEY || "").trim();
const FROM_NAME = String(process.env.FROM_NAME || "Portfolio").trim();
const FROM_EMAIL = String(process.env.FROM_EMAIL || SMTP_USER).trim();
const RESUME_FILE_PATH = String(process.env.RESUME_FILE_PATH || "").trim();
const SESSION_SECRET = String(process.env.SESSION_SECRET || "").trim();
const ADMIN_PASSWORD_HASH = String(process.env.ADMIN_PASSWORD_HASH || "").trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "").trim();
const SESSION_COOKIE_NAME = "admin_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

function parseCookies(req) {
  const raw = String(req.headers.cookie || "");
  const out = {};
  raw.split(";").forEach(part => {
    const idx = part.indexOf("=");
    if (idx < 0) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (!key) return;
    out[key] = decodeURIComponent(val);
  });
  return out;
}

function signTokenPart(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
}

function createSessionToken() {
  const payload = {
    exp: Date.now() + SESSION_TTL_MS,
    typ: "admin"
  };
  const payloadPart = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = signTokenPart(payloadPart);
  return `${payloadPart}.${sig}`;
}

function verifySessionToken(token) {
  if (!token || !token.includes(".")) return false;
  const [payloadPart, providedSig] = token.split(".");
  if (!payloadPart || !providedSig) return false;
  const expectedSig = signTokenPart(payloadPart);
  const a = Buffer.from(providedSig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8"));
    if (!payload || payload.typ !== "admin") return false;
    if (typeof payload.exp !== "number" || Date.now() > payload.exp) return false;
    return true;
  } catch {
    return false;
  }
}

function verifyPassword(password) {
  const candidate = String(password || "");
  if (!candidate) return false;

  if (ADMIN_PASSWORD_HASH.startsWith("scrypt$")) {
    const parts = ADMIN_PASSWORD_HASH.split("$");
    if (parts.length !== 3) return false;
    const salt = Buffer.from(parts[1], "base64");
    const expected = Buffer.from(parts[2], "base64");
    const derived = crypto.scryptSync(candidate, salt, expected.length);
    return crypto.timingSafeEqual(expected, derived);
  }

  if (ADMIN_PASSWORD) {
    const expected = Buffer.from(ADMIN_PASSWORD);
    const received = Buffer.from(candidate);
    if (expected.length !== received.length) return false;
    return crypto.timingSafeEqual(expected, received);
  }

  return false;
}

function requireAdminAuth(req, res, next) {
  if (!SESSION_SECRET) {
    return res.status(500).json({ error: "Server not configured: missing SESSION_SECRET" });
  }
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE_NAME];
  if (!verifySessionToken(token)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function validateServerConfig() {
  if (!SESSION_SECRET) {
    throw new Error("Missing SESSION_SECRET.");
  }
  if (!ADMIN_PASSWORD_HASH && !ADMIN_PASSWORD) {
    throw new Error("Missing admin password config. Set ADMIN_PASSWORD_HASH (recommended) or ADMIN_PASSWORD.");
  }
  if (EMAIL_PROVIDER === "smtp" && (!SMTP_HOST || !SMTP_USER || !SMTP_PASS)) {
    throw new Error("Missing SMTP configuration. Check SMTP_HOST, SMTP_USER, SMTP_PASS.");
  }
  if (EMAIL_PROVIDER === "brevo" && !BREVO_API_KEY) {
    throw new Error("Missing BREVO_API_KEY for brevo provider.");
  }
  if (!RESUME_FILE_PATH) {
    throw new Error("Missing RESUME_FILE_PATH.");
  }
  const absPath = path.resolve(RESUME_FILE_PATH);
  if (!fs.existsSync(absPath)) {
    throw new Error(`Resume file not found: ${absPath}`);
  }
  return absPath;
}

const resumeAbsolutePath = validateServerConfig();
const resumeFileName = path.basename(resumeAbsolutePath);
const resumeFileBase64 = fs.readFileSync(resumeAbsolutePath).toString("base64");

const transporter = EMAIL_PROVIDER === "smtp"
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: {
        user: SMTP_USER,
        pass: SMTP_PASS
      }
    })
  : null;

app.set("trust proxy", 1);
app.use(helmet());
app.use(express.json({ limit: "32kb" }));
app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Blocked by CORS"));
  },
  credentials: true
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});
app.use("/api", limiter);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

app.post("/api/admin/login", loginLimiter, (req, res) => {
  const password = String(req.body?.password || "");
  if (!verifyPassword(password)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  const token = createSessionToken();
  res.cookie(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: IS_PROD ? "none" : "lax",
    maxAge: SESSION_TTL_MS,
    path: "/"
  });
  return res.json({ ok: true });
});

app.post("/api/admin/logout", (_req, res) => {
  res.clearCookie(SESSION_COOKIE_NAME, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: IS_PROD ? "none" : "lax",
    path: "/"
  });
  return res.json({ ok: true });
});

app.get("/api/admin/me", requireAdminAuth, (_req, res) => {
  return res.json({ ok: true, authenticated: true });
});

app.post("/api/send-resume", requireAdminAuth, async (req, res) => {
  try {
    const toEmail = String(req.body?.toEmail || "").trim().toLowerCase();
    const toName = String(req.body?.toName || "").trim().slice(0, 120) || "there";

    if (!isValidEmail(toEmail)) {
      return res.status(400).json({ error: "Invalid recipient email" });
    }

    let info = null;
    if (EMAIL_PROVIDER === "brevo") {
      const apiRes = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "api-key": BREVO_API_KEY
        },
        body: JSON.stringify({
          sender: { name: FROM_NAME, email: FROM_EMAIL },
          to: [{ email: toEmail, name: toName }],
          subject: "Your requested resume",
          textContent: `Hi ${toName},\n\nThanks for your interest. Please find my resume attached.\n\nBest regards,\n${FROM_NAME}`,
          attachment: [
            {
              name: resumeFileName,
              content: resumeFileBase64
            }
          ]
        })
      });
      if (!apiRes.ok) {
        const errText = await apiRes.text();
        throw new Error(errText || "Brevo send failed");
      }
      info = await apiRes.json();
    } else {
      info = await transporter.sendMail({
        from: `"${FROM_NAME}" <${FROM_EMAIL}>`,
        to: toEmail,
        subject: "Your requested resume",
        text: `Hi ${toName},\n\nThanks for your interest. Please find my resume attached.\n\nBest regards,\n${FROM_NAME}`,
        attachments: [
          {
            filename: resumeFileName,
            path: resumeAbsolutePath,
            contentType: "application/pdf"
          }
        ]
      });
    }

    return res.json({ ok: true, messageId: info.messageId || info.messageId || "sent" });
  } catch (error) {
    console.error("send-resume error", error);
    return res.status(500).json({ error: "Failed to send resume email" });
  }
});

app.listen(PORT, () => {
  console.log(`Resume mail API listening on http://localhost:${PORT}`);
});
