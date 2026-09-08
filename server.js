require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { generateSecret, generateURI, verify } = require('otplib');
const QRCode = require('qrcode');

const app = express();
const port = Number(process.env.PORT || 3000);
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new sqlite3.Database(path.join(dataDir, 'northstar.sqlite'));
const query = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows)));
const run = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, function onRun(error) { error ? reject(error) : resolve(this); }));
const DUMMY_PASSWORD_HASH = '$2b$12$C6UzMDM.H6dfI/f/IKcEe.V0M0mZ8P7XqQkXK2c3Y6vYvR8Jt9x7u';
const LOCKOUT_LIMIT = 5;
const LOCKOUT_MINUTES = 15;

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
const cleanName = (name) => String(name || '').trim().replace(/\s+/g, ' ');
const publicUser = (user) => ({ id: user.id, name: user.name, email: user.email, twoFactorEnabled: Boolean(user.two_factor_enabled) });
function csrfToken(req) {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  return req.session.csrfToken;
}
function requireCsrf(req, res, next) {
  const sent = req.get('x-csrf-token');
  const expected = req.session.csrfToken;
  if (!sent || !expected || sent.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected))) return res.status(403).json({ error: 'Request could not be verified.' });
  next();
}
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Please sign in first.' });
  next();
}
function validateCredentials(body, isRegistration) {
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  const name = cleanName(body.name);
  if (!emailPattern.test(email) || email.length > 254) return 'Enter a valid email address.';
  if (password.length < (isRegistration ? 12 : 8) || password.length > 128) return isRegistration ? 'Password must be 12 to 128 characters.' : 'Enter your password.';
  if (isRegistration && (name.length < 2 || name.length > 60)) return 'Name must be 2 to 60 characters.';
  return null;
}

(async () => {
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    two_factor_enabled INTEGER NOT NULL DEFAULT 0,
    two_factor_secret TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS login_attempts (
    email TEXT NOT NULL,
    ip TEXT NOT NULL,
    failed_count INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (email, ip)
  )`);
  await run('PRAGMA journal_mode = WAL');

  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(express.json({ limit: '10kb' }));
  app.use(express.static(path.join(__dirname, 'public')));
  app.use(session({
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir }),
    secret: process.env.SESSION_SECRET || (process.env.NODE_ENV === 'production' ? (() => { throw new Error('SESSION_SECRET is required in production'); })() : 'local-development-secret-change-me'),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 8 }
  }));

  const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-8', legacyHeaders: false, message: { error: 'Too many attempts. Try again in a few minutes.' } });
  app.get('/api/csrf', (req, res) => res.json({ csrfToken: csrfToken(req) }));

  app.post('/api/register', authLimiter, requireCsrf, async (req, res) => {
    const error = validateCredentials(req.body, true);
    if (error) return res.status(400).json({ error });
    const email = normalizeEmail(req.body.email);
    try {
      const passwordHash = await bcrypt.hash(String(req.body.password), 12);
      const result = await run('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [cleanName(req.body.name), email, passwordHash]);
      req.session.regenerate((regenerateError) => {
        if (regenerateError) return res.status(500).json({ error: 'Could not start your session.' });
        req.session.userId = result.lastID;
        csrfToken(req);
        res.status(201).json({ ok: true });
      });
    } catch (dbError) {
      if (dbError.code === 'SQLITE_CONSTRAINT') return res.status(409).json({ error: 'An account with that email already exists.' });
      res.status(500).json({ error: 'Could not create your account.' });
    }
  });

  app.post('/api/login', authLimiter, requireCsrf, async (req, res) => {
    const error = validateCredentials(req.body, false);
    if (error) return res.status(400).json({ error });
    const email = normalizeEmail(req.body.email);
    const ip = req.ip;
    const attempt = await query('SELECT * FROM login_attempts WHERE email = ? AND ip = ?', [email, ip]);
    if (attempt[0] && attempt[0].locked_until > Date.now()) return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
    const rows = await query('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];
    const valid = await bcrypt.compare(String(req.body.password), user ? user.password_hash : DUMMY_PASSWORD_HASH);
    if (!user || !valid) {
      const failedCount = (attempt[0]?.failed_count || 0) + 1;
      const lockedUntil = failedCount >= LOCKOUT_LIMIT ? Date.now() + LOCKOUT_MINUTES * 60 * 1000 : 0;
      await run('INSERT INTO login_attempts (email, ip, failed_count, locked_until) VALUES (?, ?, ?, ?) ON CONFLICT(email, ip) DO UPDATE SET failed_count = excluded.failed_count, locked_until = excluded.locked_until', [email, ip, failedCount, lockedUntil]);
      return res.status(401).json({ error: 'Email or password is incorrect.' });
    }
    await run('DELETE FROM login_attempts WHERE email = ? AND ip = ?', [email, ip]);
    if (user.two_factor_enabled) {
      req.session.pendingUserId = user.id;
      return res.json({ requiresTwoFactor: true });
    }
    await regenerate(req);
    req.session.userId = user.id;
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    res.json({ ok: true });
  });

  app.post('/api/2fa/verify', authLimiter, requireCsrf, async (req, res) => {
    const userId = req.session.pendingUserId;
    const rows = userId ? await query('SELECT * FROM users WHERE id = ?', [userId]) : [];
    const user = rows[0];
    const result = user && user.two_factor_secret ? await verify({ token: String(req.body.token || ''), secret: user.two_factor_secret }) : { valid: false };
    if (!result.valid) return res.status(401).json({ error: 'That verification code is not valid.' });
    delete req.session.pendingUserId;
    req.session.userId = user.id;
    res.json({ ok: true });
  });

  app.get('/api/me', requireAuth, async (req, res) => {
    const rows = await query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    if (!rows[0]) return res.status(401).json({ error: 'Please sign in again.' });
    res.json({ user: publicUser(rows[0]), csrfToken: csrfToken(req) });
  });

  app.post('/api/2fa/setup', requireAuth, requireCsrf, async (req, res) => {
    const rows = await query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    const user = rows[0];
    if (!user || user.two_factor_enabled) return res.status(400).json({ error: 'Two-factor authentication is already enabled.' });
    const secret = generateSecret();
    await run('UPDATE users SET two_factor_secret = ? WHERE id = ?', [secret, user.id]);
    const uri = generateURI({ issuer: 'Northstar Access', label: user.email, secret });
    res.json({ qrCode: await QRCode.toDataURL(uri), secret });
  });

  app.post('/api/2fa/enable', requireAuth, requireCsrf, async (req, res) => {
    const rows = await query('SELECT * FROM users WHERE id = ?', [req.session.userId]);
    const user = rows[0];
    const result = user && user.two_factor_secret ? await verify({ token: String(req.body.token || ''), secret: user.two_factor_secret }) : { valid: false };
    if (!result.valid) return res.status(400).json({ error: 'Enter a valid code to confirm setup.' });
    await run('UPDATE users SET two_factor_enabled = 1 WHERE id = ?', [user.id]);
    res.json({ ok: true });
  });

  app.post('/api/logout', requireAuth, requireCsrf, (req, res) => req.session.destroy(() => res.json({ ok: true })));
  app.listen(port, () => console.log(`Northstar Access running at http://localhost:${port}`));
})().catch((error) => { console.error(error); process.exit(1); });
