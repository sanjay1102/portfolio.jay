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
