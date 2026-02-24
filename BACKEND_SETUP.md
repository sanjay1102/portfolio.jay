# Secure Resume Auto-Send Setup

This project now supports secure resume auto-send using a backend API (`server.js`).
Your resume stays private on the server and is sent as an email attachment.

## 1. Install dependencies

```bash
npm install
```

## 2. Configure environment

```bash
cp .env.example .env
```

Update `.env`:

- `AUTOSEND_API_KEY`: long random secret (at least 32 chars)
- `ALLOWED_ORIGINS`: your frontend domain(s)
- `SMTP_*`: your SMTP provider credentials
- `FROM_NAME` / `FROM_EMAIL`
- `RESUME_FILE_PATH`: absolute path to your private PDF on the server

## 3. Run backend

```bash
npm run dev
```

Health check:

```bash
curl http://localhost:8787/health
```

## 4. Connect frontend admin settings

In your site Admin -> Settings:

- `Auto Send Resume` = `Enabled via secure backend API`
- `Backend API URL` = `https://your-backend-domain.com` (or `http://localhost:8787` in local dev)
- `Backend API Key` = same value as `AUTOSEND_API_KEY`
- `Default Sender Email` = your sender mailbox

Save settings, then approve a resume request.

## Free safer options

1. Backend hosting (free tiers):
- Render Web Service (free tier)
- Railway trial/free credits
- Fly.io free allowance (small apps)

2. SMTP providers with free plans:
- Gmail + App Password (small/personal volume)
- Brevo (Sendinblue) free tier SMTP
- Mailgun trial/free tier (region dependent)

3. File storage safety:
- Keep resume on backend filesystem/private storage only.
- Do not use public Google Drive links for private resumes.

## Security notes

- API is protected by `x-api-key`, CORS allowlist, rate limiting, and helmet.
- Do not commit `.env`.
- Rotate `AUTOSEND_API_KEY` if exposed.
- For stronger production security, move admin login/auth to backend and replace static localStorage auth.
