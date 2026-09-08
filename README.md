# Northstar Access

Secure login demo built with Express and SQLite.

## Run locally

1. Install Node.js 20 or newer.
2. Run `npm install`.
3. Copy `.env.example` to `.env` and set a long random `SESSION_SECRET`.
4. Run `npm start`.
5. Open `http://localhost:3000`.

The SQLite database and session database are created in `data/` on first start. The app includes bcrypt password hashing, strict validation, parameterized SQL, Helmet headers, rate limiting, CSRF tokens, secure session cookies, logout, and optional TOTP 2FA.

For production, serve behind HTTPS, set `NODE_ENV=production`, use a strong secret from a secret manager, and configure a trusted reverse proxy.
