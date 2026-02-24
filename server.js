import fs from "node:fs";
import path from "node:path";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT || 8787);
const AUTOSEND_API_KEY = String(process.env.AUTOSEND_API_KEY || "").trim();
const ALLOWED_ORIGINS = String(process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

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

function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || "").trim());
}

function requireApiKey(req, res, next) {
  if (!AUTOSEND_API_KEY) {
    return res.status(500).json({ error: "Server not configured: missing AUTOSEND_API_KEY" });
  }
  const provided = String(req.header("x-api-key") || "").trim();
  if (!provided || provided !== AUTOSEND_API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function validateServerConfig() {
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
  }
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});
app.use("/api", limiter);

app.get("/health", (_req, res) => {
  res.json({ ok: true, ts: new Date().toISOString() });
});

app.post("/api/send-resume", requireApiKey, async (req, res) => {
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
