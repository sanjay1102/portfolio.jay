# Portfolio Database Design

## Phase 1 (implemented)

Purpose: stop admin data loss across domains/devices with minimal frontend risk.

Table:

- `portfolio_state`
  - `id SMALLINT PRIMARY KEY CHECK (id = 1)`
  - `data JSONB NOT NULL`
  - `updated_at TIMESTAMPTZ NOT NULL`

Behavior:

- Admin login pulls latest `portfolio_state` from backend DB.
- Admin saves push updated state to backend DB.
- Frontend localStorage remains as client cache.

## Phase 2 (implemented)

Backend now persists state into relational tables:

- `site_settings`
- `projects`
- `experiences`
- `experience_points`
- `certifications`
- `trainings`
- `articles`
- `medium_articles`
- `volunteerings`
- `resume_requests`
- `media_assets` (for documents/photos)

Notes:

- Frontend still calls the same `GET/PUT /api/admin/portfolio-state` endpoints.
- Backend maps that state to normalized tables.
- No full-blob table is required for normal operation.
