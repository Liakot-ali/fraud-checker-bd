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

Default admin login is seeded on first run: **`admin` / `admin123`** — change it before any
real deployment.

### Environment variables (`.env`)

| Variable       | Required | Description |
|----------------|----------|-------------|
| `MONGODB_URI`  | yes      | MongoDB connection string |
| `DB_NAME`      | no       | Database name (default `fraud_checker_db`) |
| `PORT`         | no       | HTTP port (default `3000`) |
| `JWT_SECRET`   | yes\*    | Secret for signing admin sessions. \*If unset, an ephemeral one is generated and sessions reset on restart. |

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
- `GET  /api/search?q=&limit=&skip=` — search approved reports
- `GET  /api/events/:id/details` — one approved report (+ linked profile)
- `GET  /api/events/:id/picture` — stream imposter photo
- `GET  /api/events/:id/proofs/:index` — stream a proof file
- `GET  /api/profiles/:id` — consolidated fraudster profile
- `POST /api/events` — submit a report (multipart)
- `GET  /healthz` — liveness probe

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
