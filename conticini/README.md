# ⚓ Conticini — private boat management

Boat documents and expense log for the private area of a sailing yacht,
packaged as a single Docker container. Flask + SQLite, no external services.

One codebase serves any number of boats: all boat-specific values (boat name,
URL prefix, admin credentials) come from environment variables — no per-boat
code changes.

## Features

- **Document archive** — boat PDFs (insurance, safety certificates, contracts,
  radio licence, manuals, quotes, service records), up to 20 MB each.
  Upload and download are protected by magic-byte verification, not just the
  file extension.
- **Expense log** — amounts in multiple currencies, categories, optional
  receipts/attachments (PDF/JPG/PNG), paid/unpaid status with payment date,
  filters by date range/category/payment status, per-category subtotals and
  per-year overview with each user's share.
- **Full editing** — expenses and documents can be corrected after creation
  (all fields), with confirmation required before any deletion.
- **Boat position history** — optional backend for the nautilus telemetry
  app: valid GPS fixes are POSTed to `/internal/boat/position` (dedup < 25 m)
  and read back via `/internal/boat/track-history`, authenticated with a
  shared `X-Internal-Token`.

## Security

- Argon2id password hashing
- Mandatory TOTP two-factor auth (Google Authenticator), QR shown at first
  login, admin can reset a user's 2FA
- CSRF token on every POST, HttpOnly/Secure/SameSite=Strict cookies
- Login rate limiting (5 attempts → 15 min lock per IP+username)
- Files stored outside the web root with UUID names, served only on
  authenticated routes after magic-byte checks
- CSP without inline scripts (external `static/app.js` only)

## Running

```bash
cp .env.example .env   # fill in your values
docker compose up -d --build
```

The app listens on `:8080` and works both directly and behind a reverse
proxy with a URL prefix (`CONTICINI_PREFIX`, e.g. `/gestionale`).

## Users

The admin account is created on first boot from `ADMIN_USERNAME` /
`ADMIN_PASSWORD`; afterwards users are managed from the UI (admin only).
Every user must configure TOTP at first login.
