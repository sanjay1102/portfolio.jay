import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import nodemailer from "nodemailer";
import pg from "pg";
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
const DATABASE_URL = String(process.env.DATABASE_URL || "").trim();
const FROM_NAME = String(process.env.FROM_NAME || "Portfolio").trim();
const FROM_EMAIL = String(process.env.FROM_EMAIL || SMTP_USER).trim();
const RESUME_FILE_PATH = String(process.env.RESUME_FILE_PATH || "").trim();
const SESSION_SECRET = String(process.env.SESSION_SECRET || "").trim();
const ADMIN_PASSWORD_HASH = String(process.env.ADMIN_PASSWORD_HASH || "").trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "").trim();
const SESSION_COOKIE_NAME = "admin_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const DB_ENABLED = Boolean(DATABASE_URL);
const { Pool } = pg;
let dbPool = null;

function createDbPool() {
  if (!DB_ENABLED) return null;
  const useSsl = IS_PROD && !/localhost|127\.0\.0\.1/i.test(DATABASE_URL);
  return new Pool({
    connectionString: DATABASE_URL,
    ssl: useSsl ? { rejectUnauthorized: false } : false
  });
}

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
dbPool = createDbPool();

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
app.use(express.json({ limit: "10mb" }));
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
  res.json({ ok: true, ts: new Date().toISOString(), dbEnabled: DB_ENABLED });
});

async function ensureDbSchema() {
  if (!dbPool) return;
  await dbPool.query(`
    CREATE TABLE IF NOT EXISTS site_settings (
      id SMALLINT PRIMARY KEY CHECK (id = 1),
      name TEXT,
      title TEXT,
      email TEXT,
      default_sender_email TEXT,
      phone TEXT,
      location TEXT,
      linkedin TEXT,
      articles_url TEXT,
      status TEXT,
      about_intro TEXT,
      summary TEXT,
      medium_profile_url TEXT,
      medium_articles_url TEXT,
      resume_auto_send TEXT,
      resume_file_url TEXT,
      resume_backend_url TEXT,
      emailjs_public_key TEXT,
      emailjs_service_id TEXT,
      emailjs_template_id TEXT,
      photo_data_url TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS media_assets (
      id BIGSERIAL PRIMARY KEY,
      kind TEXT NOT NULL,
      filename TEXT,
      mime_type TEXT,
      size_bytes INTEGER,
      data_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS projects (
      id BIGINT PRIMARY KEY,
      title TEXT,
      status TEXT,
      description TEXT,
      tools TEXT,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS experiences (
      id BIGINT PRIMARY KEY,
      period TEXT,
      role_title TEXT,
      company TEXT,
      is_current BOOLEAN NOT NULL DEFAULT FALSE,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS experience_points (
      id BIGSERIAL PRIMARY KEY,
      experience_id BIGINT NOT NULL REFERENCES experiences(id) ON DELETE CASCADE,
      point_text TEXT,
      sort_order INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS certifications (
      id BIGINT PRIMARY KEY,
      title TEXT,
      provider TEXT,
      year TEXT,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS trainings (
      id BIGINT PRIMARY KEY,
      title TEXT,
      provider TEXT,
      year TEXT,
      document_asset_id BIGINT REFERENCES media_assets(id) ON DELETE SET NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS articles (
      id BIGINT PRIMARY KEY,
      title TEXT,
      url TEXT,
      tag TEXT,
      year TEXT,
      excerpt TEXT,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS medium_articles (
      id BIGINT PRIMARY KEY,
      title TEXT,
      url TEXT,
      tag TEXT,
      year TEXT,
      excerpt TEXT,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS volunteerings (
      id BIGINT PRIMARY KEY,
      title TEXT,
      venue TEXT,
      date_text TEXT,
      description TEXT,
      photo_asset_id BIGINT REFERENCES media_assets(id) ON DELETE SET NULL,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS resume_requests (
      id BIGINT PRIMARY KEY,
      name TEXT,
      email TEXT,
      status TEXT,
      email_send_status TEXT,
      email_send_error TEXT,
      created_at_text TEXT,
      approved_at_text TEXT,
      email_sent_at_text TEXT,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await dbPool.query(`
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'experiences'
          AND column_name = 'current_role'
      ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'experiences'
          AND column_name = 'is_current'
      ) THEN
        ALTER TABLE experiences RENAME COLUMN "current_role" TO is_current;
      END IF;
    END $$;
  `);
}

const safeArr = (v) => (Array.isArray(v) ? v : []);
const safeObj = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});
const safeStr = (v, max = 5000) => String(v || "").slice(0, max);
const safeId = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : Date.now();
};
const safeBool = (v) => Boolean(v);
const isSafeDocDataUrl = (value) => /^data:(application\/pdf|image\/(png|jpeg|jpg|webp|gif));base64,/i.test(String(value || ""));
const isSafeImageDataUrl = (value) => /^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(String(value || ""));

async function clearNormalizedTables(client) {
  await client.query("DELETE FROM experience_points");
  await client.query("DELETE FROM trainings");
  await client.query("DELETE FROM volunteerings");
  await client.query("DELETE FROM experiences");
  await client.query("DELETE FROM projects");
  await client.query("DELETE FROM certifications");
  await client.query("DELETE FROM articles");
  await client.query("DELETE FROM medium_articles");
  await client.query("DELETE FROM resume_requests");
  await client.query("DELETE FROM media_assets");
}

async function writeSnapshotToNormalized(client, snapshot) {
  const s = safeObj(snapshot);
  const settings = safeObj(s.settings);

  await client.query(
    `
    INSERT INTO site_settings (
      id,name,title,email,default_sender_email,phone,location,linkedin,articles_url,status,about_intro,summary,
      medium_profile_url,medium_articles_url,resume_auto_send,resume_file_url,resume_backend_url,
      emailjs_public_key,emailjs_service_id,emailjs_template_id,photo_data_url,updated_at
    ) VALUES (
      1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,NOW()
    )
    ON CONFLICT (id) DO UPDATE SET
      name=EXCLUDED.name,title=EXCLUDED.title,email=EXCLUDED.email,default_sender_email=EXCLUDED.default_sender_email,
      phone=EXCLUDED.phone,location=EXCLUDED.location,linkedin=EXCLUDED.linkedin,articles_url=EXCLUDED.articles_url,
      status=EXCLUDED.status,about_intro=EXCLUDED.about_intro,summary=EXCLUDED.summary,
      medium_profile_url=EXCLUDED.medium_profile_url,medium_articles_url=EXCLUDED.medium_articles_url,
      resume_auto_send=EXCLUDED.resume_auto_send,resume_file_url=EXCLUDED.resume_file_url,resume_backend_url=EXCLUDED.resume_backend_url,
      emailjs_public_key=EXCLUDED.emailjs_public_key,emailjs_service_id=EXCLUDED.emailjs_service_id,
      emailjs_template_id=EXCLUDED.emailjs_template_id,photo_data_url=EXCLUDED.photo_data_url,updated_at=NOW()
    `,
    [
      safeStr(settings.name, 120),
      safeStr(settings.title, 180),
      safeStr(settings.email, 160),
      safeStr(settings.defaultSenderEmail, 160),
      safeStr(settings.phone, 80),
      safeStr(settings.location, 120),
      safeStr(settings.linkedin, 500),
      safeStr(settings.articlesUrl, 500),
      safeStr(settings.status, 40),
      safeStr(settings.aboutIntro, 2000),
      safeStr(settings.summary, 2000),
      safeStr(settings.mediumProfileUrl, 500),
      safeStr(settings.mediumArticlesUrl, 500),
      safeStr(settings.resumeAutoSend, 40),
      safeStr(settings.resumeFileUrl, 500),
      safeStr(settings.resumeBackendUrl, 500),
      safeStr(settings.emailjsPublicKey, 240),
      safeStr(settings.emailjsServiceId, 240),
      safeStr(settings.emailjsTemplateId, 240),
      safeStr(settings.photo, 3_000_000)
    ]
  );

  const projects = safeArr(s.projects);
  for (let i = 0; i < projects.length; i += 1) {
    const p = safeObj(projects[i]);
    await client.query(
      `INSERT INTO projects (id,title,status,description,tools,sort_order,updated_at) VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
      [safeId(p.id), safeStr(p.title, 200), safeStr(p.status, 40), safeStr(p.desc, 2000), safeStr(p.tools, 2000), i]
    );
  }

  const experiences = safeArr(s.experiences);
  for (let i = 0; i < experiences.length; i += 1) {
    const e = safeObj(experiences[i]);
    const experienceId = safeId(e.id);
    await client.query(
      `INSERT INTO experiences (id,period,role_title,company,is_current,sort_order,updated_at) VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
      [experienceId, safeStr(e.period, 120), safeStr(e.role, 200), safeStr(e.company, 240), safeBool(e.current), i]
    );
    const points = safeArr(e.points);
    for (let j = 0; j < points.length; j += 1) {
      await client.query(
        `INSERT INTO experience_points (experience_id,point_text,sort_order) VALUES ($1,$2,$3)`,
        [experienceId, safeStr(points[j], 1200), j]
      );
    }
  }

  const certifications = safeArr(s.certifications);
  for (let i = 0; i < certifications.length; i += 1) {
    const c = safeObj(certifications[i]);
    await client.query(
      `INSERT INTO certifications (id,title,provider,year,sort_order,updated_at) VALUES ($1,$2,$3,$4,$5,NOW())`,
      [safeId(c.id), safeStr(c.title, 240), safeStr(c.provider, 200), safeStr(c.year, 20), i]
    );
  }

  const trainings = safeArr(s.trainings);
  for (let i = 0; i < trainings.length; i += 1) {
    const t = safeObj(trainings[i]);
    const doc = safeObj(t.document);
    let documentAssetId = null;
    if (doc.dataUrl && isSafeDocDataUrl(doc.dataUrl)) {
      const insertAsset = await client.query(
        `INSERT INTO media_assets (kind,filename,mime_type,size_bytes,data_url,updated_at) VALUES ('training_document',$1,$2,$3,$4,NOW()) RETURNING id`,
        [safeStr(doc.name, 240), safeStr(doc.mimeType, 120), Number(doc.size) || null, safeStr(doc.dataUrl, 3_000_000)]
      );
      documentAssetId = insertAsset.rows[0].id;
    }
    await client.query(
      `INSERT INTO trainings (id,title,provider,year,document_asset_id,sort_order,updated_at) VALUES ($1,$2,$3,$4,$5,$6,NOW())`,
      [safeId(t.id), safeStr(t.title, 240), safeStr(t.provider, 200), safeStr(t.year, 20), documentAssetId, i]
    );
  }

  const articles = safeArr(s.articles);
  for (let i = 0; i < articles.length; i += 1) {
    const a = safeObj(articles[i]);
    await client.query(
      `INSERT INTO articles (id,title,url,tag,year,excerpt,sort_order,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
      [safeId(a.id), safeStr(a.title, 240), safeStr(a.url, 500), safeStr(a.tag, 80), safeStr(a.year, 20), safeStr(a.excerpt, 2500), i]
    );
  }

  const mediumArticles = safeArr(s.mediumArticles);
  for (let i = 0; i < mediumArticles.length; i += 1) {
    const a = safeObj(mediumArticles[i]);
    await client.query(
      `INSERT INTO medium_articles (id,title,url,tag,year,excerpt,sort_order,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
      [safeId(a.id), safeStr(a.title, 240), safeStr(a.url, 500), safeStr(a.tag, 80), safeStr(a.year, 20), safeStr(a.excerpt, 2500), i]
    );
  }

  const volunteerings = safeArr(s.volunteerings);
  for (let i = 0; i < volunteerings.length; i += 1) {
    const v = safeObj(volunteerings[i]);
    const photo = safeObj(v.photo);
    let photoAssetId = null;
    if (photo.dataUrl && isSafeImageDataUrl(photo.dataUrl)) {
      const insertAsset = await client.query(
        `INSERT INTO media_assets (kind,filename,mime_type,size_bytes,data_url,updated_at) VALUES ('volunteering_photo',$1,$2,$3,$4,NOW()) RETURNING id`,
        [safeStr(photo.name, 240), safeStr(photo.mimeType, 120), Number(photo.size) || null, safeStr(photo.dataUrl, 3_000_000)]
      );
      photoAssetId = insertAsset.rows[0].id;
    }
    await client.query(
      `INSERT INTO volunteerings (id,title,venue,date_text,description,photo_asset_id,sort_order,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
      [safeId(v.id), safeStr(v.title, 240), safeStr(v.venue, 200), safeStr(v.date, 40), safeStr(v.description, 3000), photoAssetId, i]
    );
  }

  const resumeRequests = safeArr(s.resumeRequests);
  for (let i = 0; i < resumeRequests.length; i += 1) {
    const r = safeObj(resumeRequests[i]);
    await client.query(
      `
      INSERT INTO resume_requests (
        id,name,email,status,email_send_status,email_send_error,created_at_text,approved_at_text,email_sent_at_text,sort_order,updated_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
      `,
      [
        safeId(r.id),
        safeStr(r.name, 200),
        safeStr(r.email, 240),
        safeStr(r.status, 40),
        safeStr(r.emailSendStatus, 40),
        safeStr(r.emailSendError, 2000),
        safeStr(r.createdAt, 120),
        safeStr(r.approvedAt, 120),
        safeStr(r.emailSentAt, 120),
        i
      ]
    );
  }
}

async function loadSnapshotFromNormalized(client) {
  const hasDataResult = await client.query(`
    SELECT (
      EXISTS(SELECT 1 FROM site_settings WHERE id = 1) OR
      EXISTS(SELECT 1 FROM projects) OR
      EXISTS(SELECT 1 FROM experiences) OR
      EXISTS(SELECT 1 FROM certifications) OR
      EXISTS(SELECT 1 FROM trainings) OR
      EXISTS(SELECT 1 FROM articles) OR
      EXISTS(SELECT 1 FROM medium_articles) OR
      EXISTS(SELECT 1 FROM volunteerings) OR
      EXISTS(SELECT 1 FROM resume_requests)
    ) AS has_data
  `);
  if (!hasDataResult.rows[0]?.has_data) return null;

  const settingsQ = await client.query("SELECT * FROM site_settings WHERE id = 1");
  const settingsRow = settingsQ.rows[0] || {};
  const projectsQ = await client.query("SELECT * FROM projects ORDER BY sort_order ASC, id ASC");
  const experiencesQ = await client.query("SELECT * FROM experiences ORDER BY sort_order ASC, id ASC");
  const pointsQ = await client.query("SELECT * FROM experience_points ORDER BY sort_order ASC, id ASC");
  const certsQ = await client.query("SELECT * FROM certifications ORDER BY sort_order ASC, id ASC");
  const trainingsQ = await client.query(`
    SELECT t.*, m.filename, m.mime_type, m.size_bytes, m.data_url
    FROM trainings t
    LEFT JOIN media_assets m ON m.id = t.document_asset_id
    ORDER BY t.sort_order ASC, t.id ASC
  `);
  const articlesQ = await client.query("SELECT * FROM articles ORDER BY sort_order ASC, id ASC");
  const mediumQ = await client.query("SELECT * FROM medium_articles ORDER BY sort_order ASC, id ASC");
  const volQ = await client.query(`
    SELECT v.*, m.filename, m.mime_type, m.size_bytes, m.data_url
    FROM volunteerings v
    LEFT JOIN media_assets m ON m.id = v.photo_asset_id
    ORDER BY v.sort_order ASC, v.id ASC
  `);
  const reqQ = await client.query("SELECT * FROM resume_requests ORDER BY sort_order ASC, id ASC");

  const pointsByExperience = new Map();
  for (const p of pointsQ.rows) {
    const arr = pointsByExperience.get(Number(p.experience_id)) || [];
    arr.push(p.point_text || "");
    pointsByExperience.set(Number(p.experience_id), arr);
  }

  return {
    projects: projectsQ.rows.map(p => ({
      id: Number(p.id),
      title: p.title || "",
      status: p.status || "",
      desc: p.description || "",
      tools: p.tools || ""
    })),
    experiences: experiencesQ.rows.map(e => ({
      id: Number(e.id),
      period: e.period || "",
      role: e.role_title || "",
      company: e.company || "",
      current: Boolean(e.is_current),
      points: pointsByExperience.get(Number(e.id)) || []
    })),
    certifications: certsQ.rows.map(c => ({
      id: Number(c.id),
      title: c.title || "",
      provider: c.provider || "",
      year: c.year || ""
    })),
    trainings: trainingsQ.rows.map(t => ({
      id: Number(t.id),
      title: t.title || "",
      provider: t.provider || "",
      year: t.year || "",
      document: t.data_url ? {
        name: t.filename || "training-document",
        mimeType: t.mime_type || "",
        size: t.size_bytes || 0,
        dataUrl: t.data_url
      } : null
    })),
    articles: articlesQ.rows.map(a => ({
      id: Number(a.id),
      title: a.title || "",
      url: a.url || "",
      tag: a.tag || "",
      year: a.year || "",
      excerpt: a.excerpt || ""
    })),
    mediumArticles: mediumQ.rows.map(a => ({
      id: Number(a.id),
      title: a.title || "",
      url: a.url || "",
      tag: a.tag || "",
      year: a.year || "",
      excerpt: a.excerpt || ""
    })),
    volunteerings: volQ.rows.map(v => ({
      id: Number(v.id),
      title: v.title || "",
      venue: v.venue || "",
      date: v.date_text || "",
      description: v.description || "",
      photo: v.data_url ? {
        name: v.filename || "volunteering-photo",
        mimeType: v.mime_type || "",
        size: v.size_bytes || 0,
        dataUrl: v.data_url
      } : null
    })),
    resumeRequests: reqQ.rows.map(r => ({
      id: Number(r.id),
      name: r.name || "",
      email: r.email || "",
      status: r.status || "",
      emailSendStatus: r.email_send_status || "",
      emailSendError: r.email_send_error || "",
      createdAt: r.created_at_text || "",
      approvedAt: r.approved_at_text || "",
      emailSentAt: r.email_sent_at_text || ""
    })),
    settings: {
      name: settingsRow.name || "",
      title: settingsRow.title || "",
      email: settingsRow.email || "",
      defaultSenderEmail: settingsRow.default_sender_email || "",
      phone: settingsRow.phone || "",
      location: settingsRow.location || "",
      linkedin: settingsRow.linkedin || "",
      articlesUrl: settingsRow.articles_url || "",
      status: settingsRow.status || "",
      aboutIntro: settingsRow.about_intro || "",
      summary: settingsRow.summary || "",
      mediumProfileUrl: settingsRow.medium_profile_url || "",
      mediumArticlesUrl: settingsRow.medium_articles_url || "",
      resumeAutoSend: settingsRow.resume_auto_send || "",
      resumeFileUrl: settingsRow.resume_file_url || "",
      resumeBackendUrl: settingsRow.resume_backend_url || "",
      emailjsPublicKey: settingsRow.emailjs_public_key || "",
      emailjsServiceId: settingsRow.emailjs_service_id || "",
      emailjsTemplateId: settingsRow.emailjs_template_id || "",
      photo: settingsRow.photo_data_url || ""
    }
  };
}

function toPublicPortfolioState(data) {
  const d = data && typeof data === "object" ? data : {};
  const s = d.settings && typeof d.settings === "object" ? d.settings : {};
  return {
    projects: Array.isArray(d.projects) ? d.projects : [],
    experiences: Array.isArray(d.experiences) ? d.experiences : [],
    certifications: Array.isArray(d.certifications) ? d.certifications : [],
    trainings: Array.isArray(d.trainings) ? d.trainings : [],
    articles: Array.isArray(d.articles) ? d.articles : [],
    mediumArticles: Array.isArray(d.mediumArticles) ? d.mediumArticles : [],
    volunteerings: Array.isArray(d.volunteerings) ? d.volunteerings : [],
    settings: {
      name: s.name || "",
      title: s.title || "",
      email: s.email || "",
      defaultSenderEmail: s.defaultSenderEmail || "",
      phone: s.phone || "",
      location: s.location || "",
      linkedin: s.linkedin || "",
      articlesUrl: s.articlesUrl || "",
      status: s.status || "",
      aboutIntro: s.aboutIntro || "",
      summary: s.summary || "",
      mediumProfileUrl: s.mediumProfileUrl || "",
      mediumArticlesUrl: s.mediumArticlesUrl || "",
      resumeAutoSend: s.resumeAutoSend || "",
      resumeFileUrl: s.resumeFileUrl || "",
      photo: s.photo || ""
    }
  };
}

app.get("/api/public/portfolio-state", async (_req, res) => {
  if (!dbPool) {
    return res.status(503).json({ error: "Database not configured. Set DATABASE_URL." });
  }
  const client = await dbPool.connect();
  try {
    const data = await loadSnapshotFromNormalized(client);
    if (!data) return res.json({ ok: true, data: null, updatedAt: null });
    return res.json({ ok: true, data: toPublicPortfolioState(data), updatedAt: new Date().toISOString() });
  } catch (error) {
    console.error("public portfolio-state read error", error);
    return res.status(500).json({ error: "Failed to read portfolio state" });
  } finally {
    client.release();
  }
});

app.get("/api/admin/portfolio-state", requireAdminAuth, async (_req, res) => {
  if (!dbPool) {
    return res.status(503).json({ error: "Database not configured. Set DATABASE_URL." });
  }
  const client = await dbPool.connect();
  try {
    const data = await loadSnapshotFromNormalized(client);
    if (!data) return res.json({ ok: true, data: null, updatedAt: null });
    return res.json({ ok: true, data, updatedAt: new Date().toISOString() });
  } catch (error) {
    console.error("portfolio-state read error", error);
    return res.status(500).json({ error: "Failed to read portfolio state" });
  } finally {
    client.release();
  }
});

app.put("/api/admin/portfolio-state", requireAdminAuth, async (req, res) => {
  if (!dbPool) {
    return res.status(503).json({ error: "Database not configured. Set DATABASE_URL." });
  }
  const data = req.body?.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return res.status(400).json({ error: "Invalid payload. Expected object in data." });
  }
  const client = await dbPool.connect();
  try {
    await client.query("BEGIN");
    await clearNormalizedTables(client);
    await writeSnapshotToNormalized(client, data);
    await client.query("COMMIT");
    return res.json({ ok: true });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("portfolio-state write error", error);
    return res.status(500).json({ error: "Failed to save portfolio state" });
  } finally {
    client.release();
  }
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

ensureDbSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Resume mail API listening on http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error("Failed to initialize backend schema", err);
    process.exit(1);
  });
