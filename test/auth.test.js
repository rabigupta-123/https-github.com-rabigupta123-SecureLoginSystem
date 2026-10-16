process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-session-secret-must-be-long-and-random-12345';
const path = require('path');
const fs = require('fs');

const testDbPath = path.join(__dirname, '..', 'data', 'test.sqlite');
if (fs.existsSync(testDbPath)) {
  try { fs.unlinkSync(testDbPath); } catch (_) {}
}
process.env.TEST_DB_PATH = testDbPath;

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { generate } = require('otplib');
const { app, initDb, run, db } = require('../server.js');

describe('Northstar Access - Secure Login System Test Suite', () => {
  before(async () => {
    await initDb();
    await run('DELETE FROM users');
    await run('DELETE FROM login_attempts');
  });

  after(async () => {
    await new Promise((resolve) => db.close(resolve));
    try {
      if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
      const walPath = `${testDbPath}-wal`;
      const shmPath = `${testDbPath}-shm`;
      if (fs.existsSync(walPath)) fs.unlinkSync(walPath);
      if (fs.existsSync(shmPath)) fs.unlinkSync(shmPath);
    } catch (_) {}
  });

  describe('1. Static Assets & CSRF Protection', () => {
    test('serves the landing page with secure headers', async () => {
      const res = await request(app).get('/');
      assert.equal(res.status, 200);
      assert.equal(res.headers['x-powered-by'], undefined);
      assert.ok(res.headers['x-frame-options']);
      assert.ok(res.text.includes('Northstar'));
    });

    test('issues a fresh 64-hex CSRF token', async () => {
      const res = await request(app).get('/api/csrf');
      assert.equal(res.status, 200);
      assert.ok(res.body.csrfToken);
      assert.equal(typeof res.body.csrfToken, 'string');
      assert.equal(res.body.csrfToken.length, 64);
    });

    test('rejects state-changing request without CSRF token with 403', async () => {
      const agent = request.agent(app);
      await agent.get('/api/csrf');

      const res = await agent.post('/api/register').send({
        name: 'Jane Doe',
        email: 'jane@example.com',
        password: 'Password12345!'
      });
      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Request could not be verified.');
    });

    test('rejects state-changing request with invalid CSRF token with 403', async () => {
      const agent = request.agent(app);
      await agent.get('/api/csrf');

      const res = await agent
        .post('/api/register')
        .set('x-csrf-token', '0000000000000000000000000000000000000000000000000000000000000000')
        .send({
          name: 'Jane Doe',
          email: 'jane@example.com',
          password: 'Password12345!'
        });
      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Request could not be verified.');
    });
  });

  describe('2. User Registration & Validation', () => {
    test('rejects registration with missing or short name (<2 chars)', async () => {
      const agent = request.agent(app);
      const csrfRes = await agent.get('/api/csrf');

      const res = await agent
        .post('/api/register')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          name: 'A',
          email: 'valid@example.com',
          password: 'SuperSecurePassword123!'
        });
      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Name must be 2 to 60 characters.');
    });

    test('rejects registration with invalid email format', async () => {
      const agent = request.agent(app);
      const csrfRes = await agent.get('/api/csrf');

      const res = await agent
        .post('/api/register')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          name: 'Valid Name',
          email: 'invalid-email-address',
          password: 'SuperSecurePassword123!'
        });
      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Enter a valid email address.');
    });

    test('rejects registration with short password (<12 chars)', async () => {
      const agent = request.agent(app);
      const csrfRes = await agent.get('/api/csrf');

      const res = await agent
        .post('/api/register')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          name: 'Valid Name',
          email: 'valid@example.com',
          password: 'short'
        });
      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Password must be 12 to 128 characters.');
    });

    test('successfully registers a user with valid credentials', async () => {
      const agent = request.agent(app);
      const csrfRes = await agent.get('/api/csrf');

      const res = await agent
        .post('/api/register')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          name: 'Alice Cooper',
          email: 'alice@example.com',
          password: 'SuperSecretPassword2026!'
        });
      assert.equal(res.status, 201);
      assert.equal(res.body.ok, true);

      // Session should immediately be active
      const meRes = await agent.get('/api/me');
      assert.equal(meRes.status, 200);
      assert.equal(meRes.body.user.email, 'alice@example.com');
      assert.equal(meRes.body.user.name, 'Alice Cooper');
      assert.equal(meRes.body.user.twoFactorEnabled, false);
      assert.equal(meRes.body.user.password_hash, undefined);
    });

    test('rejects duplicate email registration with 409 Conflict', async () => {
      const agent = request.agent(app);
      const csrfRes = await agent.get('/api/csrf');

      const res = await agent
        .post('/api/register')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          name: 'Alice Duplicate',
          email: 'alice@example.com',
          password: 'AnotherPassword12345!'
        });
      assert.equal(res.status, 409);
      assert.equal(res.body.error, 'An account with that email already exists.');
    });
  });

  describe('3. Authentication, Sessions & Brute-Force Lockout', () => {
    test('rejects login with missing password', async () => {
      const agent = request.agent(app);
      const csrfRes = await agent.get('/api/csrf');

      const res = await agent
        .post('/api/login')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          email: 'alice@example.com',
          password: ''
        });
      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Enter your password.');
    });

    test('rejects login with incorrect password with 401', async () => {
      const agent = request.agent(app);
      const csrfRes = await agent.get('/api/csrf');

      const res = await agent
        .post('/api/login')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          email: 'alice@example.com',
          password: 'WrongPassword123!'
        });
      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Email or password is incorrect.');
    });

    test('rejects login for non-existent user with 401', async () => {
      const agent = request.agent(app);
      const csrfRes = await agent.get('/api/csrf');

      const res = await agent
        .post('/api/login')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          email: 'nobody@example.com',
          password: 'SomePassword123!'
        });
      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Email or password is incorrect.');
    });

    test('successfully logs in with valid credentials (regenerates session)', async () => {
      const agent = request.agent(app);
      const csrfRes = await agent.get('/api/csrf');

      const res = await agent
        .post('/api/login')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          email: 'alice@example.com',
          password: 'SuperSecretPassword2026!'
        });
      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);

      // Verify authenticated profile
      const meRes = await agent.get('/api/me');
      assert.equal(meRes.status, 200);
      assert.equal(meRes.body.user.email, 'alice@example.com');
    });

    test('locks out account after 5 failed login attempts (429 status)', async () => {
      const agent = request.agent(app);
      const targetEmail = 'lockout-test@example.com';

      // Register target user first
      let csrfRes = await agent.get('/api/csrf');
      await agent
        .post('/api/register')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          name: 'Lockout Target',
          email: targetEmail,
          password: 'TargetPassword123!'
        });

      // Clear session to simulate attacker
      const attacker = request.agent(app);
      csrfRes = await attacker.get('/api/csrf');

      // 5 consecutive wrong attempts
      for (let i = 0; i < 5; i++) {
        const failRes = await attacker
          .post('/api/login')
          .set('x-csrf-token', csrfRes.body.csrfToken)
          .send({
            email: targetEmail,
            password: 'BadPasswordAttempt!'
          });
        assert.equal(failRes.status, 401);
      }

      // 6th attempt should be blocked with 429
      const lockedRes = await attacker
        .post('/api/login')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          email: targetEmail,
          password: 'TargetPassword123!'
        });
      assert.equal(lockedRes.status, 429);
      assert.ok(lockedRes.body.error.includes('Too many failed attempts'));
    });

    test('logout destroys session and clears cookie', async () => {
      const agent = request.agent(app);
      let csrfRes = await agent.get('/api/csrf');

      // Login
      await agent
        .post('/api/login')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          email: 'alice@example.com',
          password: 'SuperSecretPassword2026!'
        });

      // Verify logged in
      const meBefore = await agent.get('/api/me');
      assert.equal(meBefore.status, 200);

      // Refresh CSRF for logout
      csrfRes = await agent.get('/api/csrf');

      // Logout
      const logoutRes = await agent
        .post('/api/logout')
        .set('x-csrf-token', csrfRes.body.csrfToken);
      assert.equal(logoutRes.status, 200);
      assert.equal(logoutRes.body.ok, true);

      // Verify logged out
      const meAfter = await agent.get('/api/me');
      assert.equal(meAfter.status, 401);
    });
  });

  describe('4. Two-Factor Authentication (TOTP 2FA)', () => {
    let twoFaAgent;
    let twoFaSecret;
    const twoFaEmail = 'twofa-user@example.com';
    const twoFaPassword = 'StrongPassword2026!';

    before(async () => {
      twoFaAgent = request.agent(app);
      const csrfRes = await twoFaAgent.get('/api/csrf');
      await twoFaAgent
        .post('/api/register')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          name: 'TwoFa User',
          email: twoFaEmail,
          password: twoFaPassword
        });
    });

    test('unauthenticated 2FA setup request returns 401', async () => {
      const unauthAgent = request.agent(app);
      const csrfRes = await unauthAgent.get('/api/csrf');
      const res = await unauthAgent
        .post('/api/2fa/setup')
        .set('x-csrf-token', csrfRes.body.csrfToken);
      assert.equal(res.status, 401);
    });

    test('authenticated user can initiate 2FA setup and get secret & QR code', async () => {
      const csrfRes = await twoFaAgent.get('/api/csrf');
      const res = await twoFaAgent
        .post('/api/2fa/setup')
        .set('x-csrf-token', csrfRes.body.csrfToken);

      assert.equal(res.status, 200);
      assert.ok(res.body.secret);
      assert.ok(res.body.qrCode);
      assert.ok(res.body.qr);
      assert.ok(res.body.uri);
      twoFaSecret = res.body.secret;
    });

    test('rejects 2FA enablement with invalid token format gracefully (no crash)', async () => {
      const csrfRes = await twoFaAgent.get('/api/csrf');
      const res = await twoFaAgent
        .post('/api/2fa/enable')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({ token: '123' });

      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Verification code must be 6 digits.');
    });

    test('rejects 2FA enablement with wrong 6-digit code', async () => {
      const csrfRes = await twoFaAgent.get('/api/csrf');
      const res = await twoFaAgent
        .post('/api/2fa/enable')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({ token: '000000' });

      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Enter a valid code to confirm setup.');
    });

    test('successfully enables 2FA with valid TOTP code', async () => {
      const validToken = await generate({ secret: twoFaSecret });
      const csrfRes = await twoFaAgent.get('/api/csrf');

      const res = await twoFaAgent
        .post('/api/2fa/enable')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({ token: validToken });

      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);

      // Verify status in profile
      const meRes = await twoFaAgent.get('/api/me');
      assert.equal(meRes.body.user.twoFactorEnabled, true);
    });

    test('rejects 2FA setup if 2FA is already enabled', async () => {
      const csrfRes = await twoFaAgent.get('/api/csrf');
      const res = await twoFaAgent
        .post('/api/2fa/setup')
        .set('x-csrf-token', csrfRes.body.csrfToken);

      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Two-factor authentication is already enabled.');
    });

    test('login with 2FA requires second step verification', async () => {
      const loginAgent = request.agent(app);
      let csrfRes = await loginAgent.get('/api/csrf');

      // Step 1: Submit email & password
      const loginRes = await loginAgent
        .post('/api/login')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({
          email: twoFaEmail,
          password: twoFaPassword
        });

      assert.equal(loginRes.status, 200);
      assert.equal(loginRes.body.requiresTwoFactor, true);

      // User must NOT be authorized yet
      const meUnfinished = await loginAgent.get('/api/me');
      assert.equal(meUnfinished.status, 401);

      // Step 2 with invalid token length
      csrfRes = await loginAgent.get('/api/csrf');
      const invalidLenRes = await loginAgent
        .post('/api/2fa/verify')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({ token: 'abc' });
      assert.equal(invalidLenRes.status, 400);

      // Step 2 with incorrect 6-digit code
      const wrongCodeRes = await loginAgent
        .post('/api/2fa/verify')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({ token: '999999' });
      assert.equal(wrongCodeRes.status, 401);
      assert.equal(wrongCodeRes.body.error, 'That verification code is not valid.');

      // Step 2 with valid TOTP code
      const validToken = await generate({ secret: twoFaSecret });
      const verifyRes = await loginAgent
        .post('/api/2fa/verify')
        .set('x-csrf-token', csrfRes.body.csrfToken)
        .send({ token: validToken });

      assert.equal(verifyRes.status, 200);
      assert.equal(verifyRes.body.ok, true);

      // Now session is fully authenticated
      const meFinished = await loginAgent.get('/api/me');
      assert.equal(meFinished.status, 200);
      assert.equal(meFinished.body.user.email, twoFaEmail);
    });

    test('authenticated user can disable 2FA', async () => {
      const csrfRes = await twoFaAgent.get('/api/csrf');
      const res = await twoFaAgent
        .post('/api/2fa/disable')
        .set('x-csrf-token', csrfRes.body.csrfToken);

      assert.equal(res.status, 200);
      assert.equal(res.body.ok, true);

      // Profile shows 2FA disabled
      const meRes = await twoFaAgent.get('/api/me');
      assert.equal(meRes.body.user.twoFactorEnabled, false);
    });
  });
});
