# Fraud-Checker-BD 🇧🇩

A community-driven fraud reporting, verification, and search platform that maps isolated
scam incidents into unified, searchable fraudster profiles — so people can check a name,
phone number, or NID **before** trusting someone with their money.

---

## Features

- **Public, no-login reporting** — victims submit imposter details, scam details, evidence
  files, and (optionally hidden) reporter contact info.
- **Admin moderation queue** — JWT-protected console to review evidence and approve / reject
  / delete reports, with an audit trail.
- **Identity consolidation** — on approval, an incident is matched (by any phone or NID) to an
  existing fraudster profile, or a new one is created.
- **Fast normalized search** — Unicode-aware text search by name, nickname, phone, NID, GD
  number, scam type, location, or description.
- **Evidence handling** — photos and proof files are stored in **GridFS** and streamed on
  demand (never inlined into JSON), keeping responses small and fast.

## Tech stack

| Layer     | Choice |
|-----------|--------|
| Runtime   | Node.js (≥ 18) |
| Backend   | Express.js REST API |
| Database  | MongoDB (Atlas) + GridFS for uploads |
| Auth      | JWT (bcrypt-hashed passwords), rate-limited login |
| Security  | helmet + Content-Security-Policy, server-side validation, output escaping |
| Frontend  | HTML + vanilla JS (Fetch API) + Tailwind CSS (built locally, no CDN) |

## Getting started

```bash
# 1. Install dependencies
npm install

# 2. Configure environment (see below)
cp .env.example .env   # then edit values

# 3. Build the stylesheet (committed, but rebuild after UI changes)
npm run build:css

# 4. Run
npm start              # http://localhost:3000
```

On first run an admin is seeded. In **development** (no `ADMIN_PASSWORD` set) it is
**`admin` / `admin123`** and the admin panel forces you to change it on first login. In
**production** the app refuses to start unless `ADMIN_PASSWORD` (and `JWT_SECRET`) are set.
Admins can rotate their own password from the panel (this invalidates their other sessions).

### Environment variables (`.env`)

| Variable         | Required | Description |
|------------------|----------|-------------|
| `MONGODB_URI`    | yes      | MongoDB connection string |
| `DB_NAME`        | no       | Database name (default `fraud_checker_db`) |
| `PORT`           | no       | HTTP port (default `3000`) |
| `JWT_SECRET`     | prod: yes | Secret for signing admin sessions. In production the app refuses to start if unset; in dev an ephemeral one is generated. Generate with `openssl rand -hex 48`. |
| `ADMIN_USERNAME` | no       | Username for the seeded first admin (default `admin`). |
| `ADMIN_PASSWORD` | prod: yes | Password for the seeded first admin. Required in production. |
| `BASE_URL`       | no       | Canonical public origin for sitemap / OG / canonical URLs (falls back to the request Host in dev). |
| `NODE_ENV`       | no       | Set to `production` in real deployments (enables hard-fail safety checks). |
| `SEED_SAMPLE`    | no       | Set to `true` to seed demo data into an empty DB (off by default). |

## Scripts

| Command            | Description |
|--------------------|-------------|
| `npm start`        | Start the server |
| `npm test`         | Run the unit tests (`node --test`) |
| `npm run lint`     | ESLint |
| `npm run format`   | Prettier (JS/JSON/MD) |
| `npm run build:css`| Build `public/tailwind.css` from `src/input.css` |

## API overview

Public:
- `GET  /api/search?q=&category=&sort=&limit=&skip=` — search approved reports (matches name, phone, NID, MFS wallet, etc.)
- `GET  /api/check?phone=&nid=` — quick lookup: report counts, intrinsic number risk, and an aggregate 0-100 risk score
- `GET  /api/recent` — latest approved reports (browse feed)
- `GET  /api/stats/public` — public transparency numbers
- `GET  /api/events/:id/details` — one approved report (+ linked profile + trust/risk)
- `GET  /api/events/:id/picture` · `/proofs/:index` — stream imposter photo / proof file
- `GET  /api/profiles/:id` — consolidated fraudster profile (NIDs masked)
- `POST /api/events` — submit a report (multipart; requires a truthfulness `consent`)
- `POST /api/events/:id/dispute` — right-of-reply on an approved report
- `GET  /report/:id` · `/number/:phone` · `/profile/:id` — crawlable share bridges (OG meta + JSON-LD)
- `GET  /sitemap.xml` · `/healthz` — sitemap / liveness probe

Admin adds `POST /api/admin/change-password` (self-service) and server-side search on the
event lists (`?q=&scam_type=&min_loss=&sort=evidence`).

Admin (require `Authorization: Bearer <jwt>`):
- `POST   /api/admin/login`
- `GET    /api/admin/moderation-queue` · `/events/live` · `/events/rejected`
- `GET    /api/admin/events/:id/details`
- `PATCH  /api/admin/events/:id/approve` · `/reject`
- `DELETE /api/admin/events/:id`
- `GET    /api/admin/imposters` · `/api/admin/reporters`

## Project structure

```text
fraud-checker-bd/
├── server.js            # Express app, routes, DB init/migrations
├── lib/util.js          # Pure helpers + constants + validation (unit-tested)
├── tests/util.test.js   # node:test unit tests
├── src/input.css        # Tailwind entry (built to public/tailwind.css)
├── public/              # Static frontend
│   ├── shared.js        # Shared client helpers (escaping, formatting, toasts)
│   ├── index.html       # Search + landing
│   ├── submit.html      # Report form
│   ├── event-detail.html, imposter-profile.html
│   └── admin.html       # Moderation console
├── Dockerfile, docker-compose.yml
└── .github/workflows/ci.yml
```

## Docker

```bash
docker compose up --build   # reads MONGODB_URI etc. from .env
```

## Security notes

Passwords are bcrypt-hashed, admin routes are JWT-protected, inputs are validated/coerced
(blocking NoSQL-operator injection), all user output is escaped client-side, and a CSP is
applied. Before production: change the seeded admin password and rotate any credentials that
were shared in plaintext.
