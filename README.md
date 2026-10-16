<div align="center">

# 🛡️ Northstar Access — Secure Login System

**An enterprise-grade, security-hardened authentication and session management platform built with Node.js, Express, and SQLite.**

[![Test Suite](https://github.com/rabigupta-123/https-github.com-rabigupta123-SecureLoginSystem/actions/workflows/test.yml/badge.svg)](https://github.com/rabigupta-123/https-github.com-rabigupta123-SecureLoginSystem/actions)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express-4.21.2-blue.svg)](https://expressjs.com/)
[![SQLite3](https://img.shields.io/badge/SQLite-3-003B57.svg?logo=sqlite)](https://www.sqlite.org/)
[![Security Hardened](https://img.shields.io/badge/Security-OWASP%20Hardened-green.svg)](#security-architecture--threat-defense)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Architecture](#system-architecture) • [Key Features](#core-security-features) • [API Reference](#api-specification) • [Local Setup](#getting-started) • [Running Tests](#automated-test-suite) • [Production Hardening](#production-deployment-checklist)

---

</div>

## 📌 Executive Overview

**Northstar Access** is a reference implementation of modern, defensive web authentication. It demonstrates how to protect user identities and server state against common OWASP Top 10 web vulnerabilities—such as credential stuffing, brute-force attacks, Cross-Site Request Forgery (CSRF), session fixation, user enumeration timing attacks, and SQL injection—without relying on external cloud authentication silos.

The application couples a lightweight, persistent SQLite back-end with cryptographic best practices (Bcrypt, RFC 6238 TOTP two-factor authentication, and timing-safe token comparison) and an accessible, responsive front-end.

---

## 🔒 Core Security Features

| Defense Category | Implementation | Security Benefit |
| :--- | :--- | :--- |
| **Password Hashing** | `bcryptjs` (12 salt rounds) | Computationally expensive adaptive one-way hashing resistant to GPU cracking and rainbow tables. |
| **Timing Attack Mitigation** | Constant-time dummy hash comparison | Prevents username/email enumeration by ensuring failed logins take identical computation time whether an account exists or not. |
| **Brute-Force & Lockout** | Dual-layer: `express-rate-limit` + SQLite attempt tracker | Locks out accounts for 15 minutes after 5 consecutive failed attempts per IP/account; throttles malicious automated bots. |
| **CSRF Defense** | 64-hex cryptographically random tokens | Verified using `crypto.timingSafeEqual` across state-changing HTTP methods (`POST`, `PUT`, `DELETE`). |
| **Session Security** | `express-session` with SQLite persistent store | Session fixation protection via mandatory `session.regenerate()` upon login, registration, and 2FA elevation; `HttpOnly` and `SameSite=Lax` cookies. |
| **Two-Factor Auth (2FA)** | Time-based One-Time Passwords (TOTP / RFC 6238) | Authenticator-compatible (Google Authenticator, Microsoft Authenticator, Authy, 1Password) with scannable QR codes and secret verification. |
| **Database Safety** | Parameterized SQL queries & SQLite WAL mode | Completely prevents SQL injection (SQLi) vulnerabilities while enabling high-concurrency read/write operations. |
| **HTTP Hardening** | `helmet` middleware & disabled `x-powered-by` | Automatic prevention of clickjacking (`X-Frame-Options`), MIME-sniffing, and server fingerprint leakage. |

---

## 🏗️ System Architecture

```
                  +----------------------------------------------+
                  |               Client Browser                 |
                  |     (HTML5 + Vanilla CSS + ES6 Fetch API)    |
                  +----------------------+-----------------------+
                                         |
                                         | HTTPS / REST
                                         v
                  +----------------------------------------------+
                  |            Express Application               |
                  |                                              |
                  |  +----------------------------------------+  |
                  |  | Security Pipeline                      |  |
                  |  |  - Helmet (Security headers)           |  |
                  |  |  - IP Rate Limiter                     |  |
                  |  |  - JSON Parser (10kb body limit)       |  |
                  |  |  - Express Session (connect-sqlite3)   |  |
                  |  |  - Timing-Safe CSRF Guard              |  |
                  |  +----------------------------------------+  |
                  |                      |                       |
                  |  +-------------------+--------------------+  |
                  |  | API Handlers & Auth Services           |  |
                  |  |  - Registration & Credentials Check    |  |
                  |  |  - Login & Brute-force Lockout         |  |
                  |  |  - TOTP 2FA Service (otplib + qrcode)  |  |
                  |  |  - Session Invalidation & Logout       |  |
                  |  +-------------------+--------------------+  |
                  +----------------------|-----------------------+
                                         |
                                         v
                  +----------------------------------------------+
                  |               SQLite Persistence             |
                  |     (users, login_attempts, sessions)        |
                  +----------------------------------------------+
```

---

## 📂 Project Structure

```text
secure-login-system/
├── .github/
│   └── workflows/
│       └── test.yml           # Continuous Integration test runner (Node 20, 22)
├── data/                      # Auto-created SQLite database directory (git-ignored)
│   ├── northstar.sqlite       # User accounts & lockout attempts
│   └── sessions.sqlite        # Persistent session store
├── public/                    # Static front-end assets
│   ├── app.js                 # Authentication client logic (tab switching, forms, CSRF)
│   ├── dashboard.html         # Protected user workspace with 2FA setup & management
│   ├── dashboard.js           # Supplementary dashboard management script
│   ├── index.html             # High-conversion secure login and registration UI
│   └── styles.css             # Polished design system tokens and responsive styles
├── test/
│   └── auth.test.js           # 23-test end-to-end suite covering all auth flows
├── .env.example               # Environment variables template
├── .gitignore                 # Production ignore rules
├── package.json               # Manifest, dependencies, and test scripts
├── README.md                  # System documentation and setup guide
└── server.js                  # Modular Express server, security middleware & API endpoints
```

---

## 🚀 Getting Started

### Prerequisites

- **Node.js**: `v20.0.0` or later (LTS recommended)
- **npm**: `v9.0.0` or later

### 1. Clone & Install

```bash
git clone https://github.com/rabigupta-123/https-github.com-rabigupta123-SecureLoginSystem.git
cd https-github.com-rabigupta123-SecureLoginSystem
npm install
```

### 2. Configure Environment

Copy the example environment configuration:

```bash
cp .env.example .env
```

Ensure `.env` contains your runtime settings:

```ini
PORT=3000
SESSION_SECRET=replace-with-a-cryptographically-secure-random-string-at-least-32-chars
NODE_ENV=development
```

> [!TIP]
> You can generate a strong random secret using Node's crypto CLI:
> ```bash
> node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
> ```

### 3. Run the Application

```bash
# Start in production mode
npm start

# Or start with automatic file reload (development)
npm run dev
```

Visit [`http://localhost:3000`](http://localhost:3000) in your browser.

---

## 🧪 Automated Test Suite

The project includes an exhaustive, automated regression and security test suite using Node's native test runner (`node:test`) and `supertest`.

### Run Tests

```bash
npm test
```

### Test Coverage Highlights

The suite validates **23 automated tests** across 4 core functional domains:

- **1. Static Assets & CSRF Protection**
  - Serves root HTML with security headers (`X-Frame-Options`, no `x-powered-by`).
  - Issues fresh 64-character hexadecimal CSRF tokens.
  - Rejects state-changing requests missing CSRF tokens (`403 Forbidden`).
  - Rejects state-changing requests with forged/tampered CSRF tokens (`403 Forbidden`).
- **2. User Registration & Input Validation**
  - Rejects names shorter than 2 characters (`400 Bad Request`).
  - Rejects invalid email syntax (`400 Bad Request`).
  - Rejects passwords shorter than 12 characters (`400 Bad Request`).
  - Successfully hashes password with Bcrypt and creates accounts (`201 Created`).
  - Rejects duplicate email registrations (`409 Conflict`).
- **3. Authentication & Brute-Force Lockout**
  - Rejects missing password on login (`400 Bad Request`).
  - Rejects incorrect password (`401 Unauthorized`).
  - Rejects non-existent accounts with identical timing (`401 Unauthorized`).
  - Successfully verifies credentials and regenerates session (`200 OK`).
  - Automatically locks out accounts after 5 failed attempts (`429 Too Many Attempts`).
  - Invalidates server session and clears client cookie on logout.
- **4. Two-Factor Authentication (TOTP 2FA)**
  - Rejects unauthorized access to 2FA configuration (`401 Unauthorized`).
  - Generates secure secret key, otpauth URI, and Base64 QR code.
  - Validates 6-digit TOTP confirmation code format and reject malformed codes gracefully.
  - Enforces two-step verification on subsequent sign-ins when 2FA is active.
  - Allows authenticated users to safely disable 2FA.

---

## 📡 API Specification

### Authentication & Session Endpoints

| Method | Endpoint | Auth | CSRF | Description | Status Codes |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `GET` | `/api/csrf` | No | No | Returns a fresh CSRF token for the session. | `200` |
| `POST` | `/api/register` | No | Yes | Registers a new account and initializes session. | `201`, `400`, `403`, `409` |
| `POST` | `/api/login` | No | Yes | Authenticates user; prompts for 2FA if enabled. | `200`, `400`, `401`, `403`, `429` |
| `GET` | `/api/me` | Yes | No | Returns the authenticated user's profile. | `200`, `401` |
| `POST` | `/api/logout` | Yes | Yes | Destroys server session and clears session cookie. | `200`, `401`, `403` |

### Two-Factor Authentication Endpoints

| Method | Endpoint | Auth | CSRF | Description | Status Codes |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `POST` | `/api/2fa/setup` | Yes | Yes | Generates a new TOTP secret and QR code data URL. | `200`, `400`, `401`, `403` |
| `POST` | `/api/2fa/enable` | Yes | Yes | Verifies 6-digit code and activates 2FA on account. | `200`, `400`, `401`, `403` |
| `POST` | `/api/2fa/verify` | Pending | Yes | Validates TOTP code during two-step login flow. | `200`, `400`, `401`, `403` |
| `POST` | `/api/2fa/disable` | Yes | Yes | Deactivates 2FA and purges the shared secret. | `200`, `400`, `401`, `403` |

---

## 🛡️ Production Deployment Checklist

Before exposing the service to public traffic, ensure the following steps are satisfied:

1. **Enforce HTTPS / TLS**:
   - Set `NODE_ENV=production` in the production environment so cookies have the `secure: true` flag enabled.
   - Serve behind a reverse proxy (such as Nginx, Cloudflare, or AWS ALB) with SSL/TLS termination.
2. **Configure Reverse Proxy Trust**:
   - If terminating SSL at a proxy, ensure `app.set('trust proxy', 1)` is enabled so client IP resolution correctly feeds the rate limiter and brute-force detection.
3. **Secret Key Management**:
   - Never commit `.env` or production secrets to source control.
   - Inject `SESSION_SECRET` via a secret manager (AWS Secrets Manager, HashiCorp Vault, Doppler, or GitHub Actions Secrets).
4. **Database Backups & Redundancy**:
   - Regularly backup `data/northstar.sqlite` using SQLite's online backup API or scheduled snapshot jobs.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
