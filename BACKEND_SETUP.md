# Secure Resume Auto-Send Setup

This project supports secure resume auto-send using a backend API (`server.js`).
Your resume stays private on the server and is sent as an email attachment.

## 1. Install dependencies

```bash
npm install
```

## 2. Configure environment

```bash
cp .env.example .env
```

Required:

- `AUTOSEND_API_KEY`: long random secret (at least 32 chars)
- `ALLOWED_ORIGINS`: your frontend domain(s)
- `RESUME_FILE_PATH`: absolute path to your private PDF on the server
- `FROM_NAME` / `FROM_EMAIL`

Mail provider modes:

1. `EMAIL_PROVIDER=smtp`:
- Set `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` (+ optional port/secure)

2. `EMAIL_PROVIDER=brevo` (recommended on Render free):
- Set `BREVO_API_KEY`

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

## Render-specific notes

- Set `ALLOWED_ORIGINS` to your frontend Render URL.
- Set `RESUME_FILE_PATH` to repo path inside Render, e.g.:

```env
RESUME_FILE_PATH=/opt/render/project/src/private/SanjayNathan_Resumee.pdf
```

- Backend now sets `trust proxy` to avoid rate-limit proxy warnings on Render.
- If SMTP times out on free hosting, use `EMAIL_PROVIDER=brevo` instead of SMTP.

## Security notes

- API is protected by `x-api-key`, CORS allowlist, rate limiting, and helmet.
- Do not commit `.env`.
- Rotate `AUTOSEND_API_KEY` if exposed.
