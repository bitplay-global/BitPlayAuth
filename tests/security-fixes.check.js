/**
 * Security fixes of 2026-10-21, against the real app and an in-memory
 * MongoDB. Each check replays an attack seen in the audit or the logs.
 *
 * Run: node tests/security-fixes.check.js
 * (needs: npm install --no-save supertest mongodb-memory-server)
 */
const { MongoMemoryServer } = require('mongodb-memory-server');

let pass = 0, fail = 0;
const check = (n, c, d = '') => (c ? (pass++, console.log(`  PASS  ${n}`)) : (fail++, console.log(`  FAIL  ${n}  ${d}`)));

(async () => {
  const mongod = await MongoMemoryServer.create();
  process.env.MONGODB_URI = mongod.getUri('authsec');
  process.env.PORT = '0';
  process.env.JWT_SECRET = 'test-secret-test-secret-test-secret-123';
  process.env.JWT_EXPIRE = '1d';
  process.env.NODE_ENV = 'test';
  delete process.env.AUTH_ADMIN_API_KEY;
  const request = require('supertest');
  const mongoose = require('mongoose');
  const app = require('../server');
  await new Promise(r => (mongoose.connection.readyState === 1 ? r() : mongoose.connection.once('open', r)));
  const User = require('../models/User');
  const api = request(app);

  const victim = await User.create({ name: 'Victim', email: 'victim@example.com', password: 'oldpass123', emailVerified: true });

  console.log('\n--- password reset needs the emailed code ---');
  let res = await api.put('/api/auth/resetpassword/victim@example.com').send({ password: 'hacked123' });
  check('reset with only the email is refused (was a full takeover)', res.status === 400, `${res.status} ${JSON.stringify(res.body)}`);
  let login = await api.post('/api/auth/login').send({ email: 'victim@example.com', password: 'hacked123' });
  check('...and the attacker password does not work', login.status !== 200 || !login.body.token);

  await api.post('/api/auth/forgotpassword').send({ email: 'victim@example.com' });
  const otp = (await User.findOne({ email: 'victim@example.com' })).emailVerificationOTP;
  res = await api.get(`/api/auth/verify-email-otp/000000/${encodeURIComponent('victim@example.com')}`);
  check('wrong code refused', res.status === 400);
  res = await api.get(`/api/auth/verify-email-otp/${otp}/${encodeURIComponent('someone-else@example.com')}`);
  check('right code but another email: refused (codes are per account now)', res.status === 400);
  res = await api.get(`/api/auth/verify-email-otp/${otp}/${encodeURIComponent('victim@example.com')}`);
  check('right code for this email: accepted (the app flow)', res.status === 200, JSON.stringify(res.body));
  res = await api.put('/api/auth/resetpassword/victim@example.com').send({ password: 'newpass123' });
  check('then the reset works', res.status === 200 && res.body.success === true, JSON.stringify(res.body));
  check('...and returns no login token (no 2FA bypass)', !res.body.token);
  login = await api.post('/api/auth/login').send({ email: 'victim@example.com', password: 'newpass123' });
  check('new password logs in', login.status === 200 && !!login.body.token, `${login.status}`);
  res = await api.put('/api/auth/resetpassword/victim@example.com').send({ password: 'again12345' });
  check('the window is single use', res.status === 400);

  await api.post('/api/auth/forgotpassword').send({ email: 'victim@example.com' });
  for (let i = 0; i < 5; i++) await api.get(`/api/auth/verify-email-otp/11111${i}/${encodeURIComponent('victim@example.com')}`);
  const real = (await User.findOne({ email: 'victim@example.com' })).emailVerificationOTP;
  res = await api.get(`/api/auth/verify-email-otp/${real}/${encodeURIComponent('victim@example.com')}`);
  check('after 5 wrong guesses even the right code is refused (no brute force)', res.status === 429, `${res.status}`);

  console.log('\n--- email change needs the CURRENT mailbox ---');
  await User.updateOne({ email: 'victim@example.com' }, { $unset: { emailVerificationOTP: 1 } });
  res = await api.post('/api/auth/update-email-otp').send({ email: 'victim@example.com', new_email: 'attacker@evil.test' });
  const afterReq = await User.findOne({ email: 'victim@example.com' });
  check('code is created for the victim account (sent to the victim, not the attacker)', res.status === 200 && !!afterReq.emailVerificationOTP);
  res = await api.post('/api/auth/update-email').send({ email: 'victim@example.com', new_email: 'attacker@evil.test', otp: '123456' });
  check('attacker cannot finish without the code from the victim mailbox', res.status === 400 && !!(await User.findOne({ email: 'victim@example.com' })));
  await User.create({ name: 'Other', email: 'taken@example.com', password: 'whatever1' });
  res = await api.post('/api/auth/update-email-otp').send({ email: 'victim@example.com', new_email: 'taken@example.com' });
  check('new address already used by another account: refused', res.status === 400);

  console.log('\n--- auth-service admin API is closed ---');
  for (const [m, path] of [['get', '/api/admin/users?limit=3'], ['get', '/api/admin/dashboard'], ['get', `/api/admin/users/${victim._id}`], ['delete', `/api/admin/users/${victim._id}`], ['put', `/api/admin/users/${victim._id}/status`]]) {
    res = await api[m](path).send({ isActive: false });
    check(`${m.toUpperCase()} ${path.split('?')[0]} -> 404`, res.status === 404, `${res.status}`);
  }
  check('victim still exists and is active', !!(await User.findOne({ _id: victim._id, isActive: { $ne: false } })));

  console.log('\n--- query-operator injection refused ---');
  for (const [path, body] of [
    ['/api/auth/forgotpassword', { email: { $regex: '^v' } }],
    ['/api/auth/login', { email: { $ne: null }, password: { $ne: null } }],
    ['/api/auth/update-email-otp', { email: { $ne: null }, new_email: 'x@evil.test' }],
  ]) {
    res = await api.post(path).send(body);
    check(`${path} with an operator body -> 400`, res.status === 400, `${res.status}`);
  }
  res = await api.post('/api/auth/login').send({ email: 'victim@example.com', password: 'newpass123' });
  check('normal login still fine', res.status === 200);

  await mongoose.disconnect();
  await mongod.stop();
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
