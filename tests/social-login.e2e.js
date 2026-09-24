// End-to-end test. Needs mongodb-memory-server and supertest, which are not
// dependencies of this service. Point TEST_DEPS_DIR at a project that has them:
//   TEST_DEPS_DIR=../tupple_dev node tests/social-login.e2e.js
const path = require('path');
const { createRequire } = require('module');
const TD = createRequire(require('path').resolve(process.env.TEST_DEPS_DIR || '.', 'package.json'));
const authRequire = createRequire(require('path').join(__dirname, '..', 'package.json'));
const crypto = require('crypto');

process.env.JWT_SECRET = 'test-secret'; process.env.JWT_EXPIRE = '1d'; process.env.JWT_COOKIE_EXPIRE = '1';

const key = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...key.publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256' };
global.fetch = async (url) => ({ status: url.includes('appleid.apple.com/auth/keys') ? 200 : 400,
  json: async () => url.includes('appleid.apple.com/auth/keys') ? { keys: [jwk] } : { error: 'invalid' } });
const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const appleToken = email => { const h = b64({ alg: 'RS256', kid: 'k1' }), p = b64({ iss: 'https://appleid.apple.com', aud: 'com.bitplaypro.bitplaypro', sub: 's', email, email_verified: 'true', iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000) + 600 }); return `${h}.${p}.${crypto.sign('RSA-SHA256', Buffer.from(`${h}.${p}`), key.privateKey).toString('base64url')}`; };

(async () => {
  const { MongoMemoryServer } = TD('mongodb-memory-server');
  const request = TD('supertest');
  const mongoose = authRequire('mongoose');
  const express = authRequire('express');
  const mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
  const User = authRequire('./models/User');
  const app = express(); app.use(express.json()); app.use('/api/auth', authRequire('./routes/auth'));
  const server = await new Promise(res => { const s = app.listen(0, '127.0.0.1', () => res(s)); });
  const base = `http://127.0.0.1:${server.address().port}`; // one server: see note in app-user-auth.test.mjs

  await User.create({ name: 'Victim', email: 'victim@example.com', password: 'Str0ngPassw0rd!', isActive: true, emailVerified: true });
  let pass = 0, fail = 0; const check = (n, c, d='') => c ? (pass++, console.log('  PASS  ' + n)) : (fail++, console.log('  FAIL  ' + n + '  ' + d));

  // 1. the attack that works in production today
  let r = await request(base).post('/api/auth/social-login').send({ provider: 'google', providerId: 'x', email: 'victim@example.com' });
  check('forged google login (no token) refused', r.status === 401 && !r.body.token, `status ${r.status} token=${!!r.body.token}`);
  r = await request(base).post('/api/auth/social-login').send({ provider: 'apple', providerId: 'x', email: 'victim@example.com', accessToken: 'fake' });
  check('forged apple login (fake token) refused', r.status === 401 && !r.body.token, `status ${r.status}`);
  r = await request(base).post('/api/auth/social-login').send({ provider: 'apple', providerId: 'x', email: 'victim@example.com', accessToken: appleToken('attacker@example.com') });
  check('genuine token for ATTACKER cannot open victim account', r.status !== 200 || (r.body.user && r.body.user.email !== 'victim@example.com'), JSON.stringify(r.body).slice(0,120));

  // 2. genuine sign-in into the existing account
  r = await request(base).post('/api/auth/social-login').send({ provider: 'apple', providerId: 's', email: 'VICTIM@example.com', accessToken: appleToken('Victim@Example.com') });
  check('genuine Apple sign-in succeeds with a token', r.status === 200 && !!r.body.token, `status ${r.status} ${JSON.stringify(r.body).slice(0,140)}`);
  check('it reaches the existing account (no duplicate)', (await User.countDocuments({ email: 'victim@example.com' })) === 1);
  check('total users unchanged except attacker', (await User.countDocuments({})) <= 2);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  server.close(); await mongoose.disconnect(); await mongod.stop(); process.exit(fail ? 1 : 0);
})().catch(e => { console.error('E2E error:', e); process.exit(1); });
