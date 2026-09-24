// End-to-end test. Needs mongodb-memory-server and supertest, which are not
// dependencies of this service. Point TEST_DEPS_DIR at a project that has them:
//   TEST_DEPS_DIR=../tupple_dev node tests/two-factor.e2e.js
const path = require('path'); const { createRequire } = require('module');
const TD = createRequire(require('path').resolve(process.env.TEST_DEPS_DIR || '.', 'package.json'));
const A = createRequire(require('path').join(__dirname, '..', 'package.json'));
process.env.JWT_SECRET = 'test-secret'; process.env.JWT_EXPIRE = '1d';
(async () => {
  const { MongoMemoryServer } = TD('mongodb-memory-server'); const request = TD('supertest');
  const mongoose = A('mongoose'); const express = A('express');
  const mongod = await MongoMemoryServer.create(); await mongoose.connect(mongod.getUri());
  const User = A('./models/User');
  const app = express(); app.use(express.json()); app.use('/api/auth', A('./routes/auth'));
  const server = await new Promise(res => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
  const base = `http://127.0.0.1:${server.address().port}`; // one server: see note in app-user-auth.test.mjs
  let pass = 0, fail = 0; const check = (n, c, d='') => c ? (pass++, console.log('  PASS  ' + n)) : (fail++, console.log('  FAIL  ' + n + '  ' + d));
  const mk = (email, twofa) => User.create({ name: 'U', email, password: 'Str0ngPassw0rd!', isActive: true, emailVerified: true, TwoFactorAuth: twofa });
  await mk('two@example.com', true); await mk('plain@example.com', false);
  const issueOtp = async email => { const u = await User.findOne({ email }); const c = u.generateEmailVerificationOTP(); await u.save({ validateBeforeSave: false }); return c; };
  const me = t => request(base).get('/api/auth/me').set('Authorization', `Bearer ${t}`);

  console.log('\n--- 2FA is now enforced by the server ---');
  let r = await request(base).post('/api/auth/login').send({ email: 'two@example.com', password: 'Str0ngPassw0rd!' });
  const tok = r.body.token;
  check('login response unchanged for old builds (still has token + twofactor)', r.status === 200 && !!tok && r.body.user.twofactor === true);
  r = await me(tok);
  check('that token alone is refused before the code', r.status === 401 && r.body.code === 'MFA_REQUIRED', `status ${r.status} ${JSON.stringify(r.body)}`);
  let code = await issueOtp('two@example.com');
  r = await request(base).post('/api/auth/verify-twofactorotp').send({ otp: code });   // exactly what shipped builds send
  check('correct code accepted (old-build request shape)', r.status === 200, `status ${r.status}`);
  r = await me(tok);
  check('same token works after the code', r.status === 200, `status ${r.status}`);
  r = await request(base).post('/api/auth/verify-twofactorotp').send({ otp: code });
  check('a used code cannot be replayed', r.status === 400, `status ${r.status}`);

  console.log('\n--- a second login needs its own code ---');
  r = await request(base).post('/api/auth/login').send({ email: 'two@example.com', password: 'Str0ngPassw0rd!' });
  check('new login token refused until its own code', (await me(r.body.token)).status === 401);
  check('first session still works', (await me(tok)).status === 200);

  console.log('\n--- accounts without 2FA are unaffected ---');
  r = await request(base).post('/api/auth/login').send({ email: 'plain@example.com', password: 'Str0ngPassw0rd!' });
  check('non-2FA token works immediately', (await me(r.body.token)).status === 200);

  console.log('\n--- brute force ---');
  code = await issueOtp('two@example.com');
  for (let i = 0; i < 5; i++) await request(base).post('/api/auth/verify-twofactorotp').send({ otp: '000000' === code ? '111111' : '000000', email: 'two@example.com' });
  r = await request(base).post('/api/auth/verify-twofactorotp').send({ otp: code, email: 'two@example.com' });
  check('after 5 wrong guesses even the right code is refused', r.status === 429, `status ${r.status}`);
  code = await issueOtp('two@example.com');
  r = await request(base).post('/api/auth/verify-twofactorotp').send({ otp: code, email: 'two@example.com' });
  check('a freshly issued code works again', r.status === 200, `status ${r.status}`);

  console.log('\n--- update-email ---');
  code = await issueOtp('plain@example.com');
  for (let i = 0; i < 5; i++) await request(base).post('/api/auth/update-email').send({ email: 'plain@example.com', new_email: 'attacker@example.com', otp: '000000' === code ? '111111' : '000000' });
  r = await request(base).post('/api/auth/update-email').send({ email: 'plain@example.com', new_email: 'attacker@example.com', otp: code });
  check('update-email locks after 5 wrong codes', r.status === 429, `status ${r.status}`);
  check('email was not changed', !!(await User.findOne({ email: 'plain@example.com' })));
  code = await issueOtp('plain@example.com');
  r = await request(base).post('/api/auth/update-email').send({ email: 'plain@example.com', new_email: 'new@example.com', otp: code });
  check('legit email change works with a fresh code', r.status === 200 && !!(await User.findOne({ email: 'new@example.com' })), `status ${r.status}`);
  r = await request(base).post('/api/auth/update-email').send({ email: 'new@example.com', new_email: 'x@example.com', otp: code });
  check('that code cannot be reused', r.status === 400, `status ${r.status}`);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  server.close(); await mongoose.disconnect(); await mongod.stop(); process.exit(fail ? 1 : 0);
})().catch(e => { console.error('E2E error:', e); process.exit(1); });
