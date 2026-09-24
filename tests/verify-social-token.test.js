/**
 * Social sign-in verification. The endpoint used to trust `email` from the
 * request body; these tests pin that no credential, a forged one, a token for a
 * different app, an expired one and an unverified email are all refused, while
 * each genuine path the shipped app uses still works.
 *
 * Run: node tests/verify-social-token.test.js   (no dependencies, no network)
 */
const crypto = require('crypto');

// Signing key playing Apple and Firebase; a second key plays an attacker.
const good = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const evil = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = 'test-kid';

const jwk = { ...good.publicKey.export({ format: 'jwk' }), kid: KID, alg: 'RS256', use: 'sig' };
// Firebase publishes x509 certificates; a raw SPKI PEM is accepted by
// crypto.createPublicKey the same way, which is all the verifier needs.
const pem = good.publicKey.export({ type: 'spki', format: 'pem' });

let googleTokenInfo = null; // what the stubbed tokeninfo endpoint returns
global.fetch = async (url) => {
  const json = (status, body) => ({ status, json: async () => body });
  if (url.startsWith('https://appleid.apple.com/auth/keys')) return json(200, { keys: [jwk] });
  if (url.startsWith('https://www.googleapis.com/robot/v1/metadata/x509/')) return json(200, { [KID]: pem });
  if (url.startsWith('https://oauth2.googleapis.com/tokeninfo')) {
    return googleTokenInfo ? json(200, googleTokenInfo) : json(400, { error: 'invalid_token' });
  }
  return json(404, {});
};

const { verifySocialIdentity } = require('../utils/verifySocialToken');

const now = () => Math.floor(Date.now() / 1000);
function sign(payload, { key = good.privateKey, header = {} } = {}) {
  const h = Buffer.from(JSON.stringify({ alg: 'RS256', kid: KID, typ: 'JWT', ...header })).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.sign('RSA-SHA256', Buffer.from(`${h}.${p}`), key).toString('base64url');
  return `${h}.${p}.${sig}`;
}
const apple = (over = {}) => sign({
  iss: 'https://appleid.apple.com', aud: 'com.bitplaypro.bitplaypro', sub: 'apple-sub',
  email: 'Victim@Example.com', email_verified: 'true', iat: now(), exp: now() + 600, ...over,
});
const firebase = (over = {}) => sign({
  iss: 'https://securetoken.google.com/bitplay-3fbe7', aud: 'bitplay-3fbe7', sub: 'fb-uid',
  email: 'user@example.com', email_verified: true, iat: now(), exp: now() + 600, ...over,
});

let pass = 0, fail = 0;
async function expect(name, fn, shouldPass, check) {
  try {
    const r = await fn();
    if (shouldPass && (!check || check(r))) { pass++; console.log(`  PASS  ${name}`); }
    else { fail++; console.log(`  FAIL  ${name}  -- ${shouldPass ? 'unexpected result ' + JSON.stringify(r) : 'was accepted'}`); }
  } catch (e) {
    if (!shouldPass) { pass++; console.log(`  PASS  ${name}  (${e.code})`); }
    else { fail++; console.log(`  FAIL  ${name}  -- ${e.code || e.message}`); }
  }
}

(async () => {
  console.log('\n--- the bypass that worked before: no credential at all ---');
  await expect('google with no token', () => verifySocialIdentity({ provider: 'google' }), false);
  await expect('apple with no token', () => verifySocialIdentity({ provider: 'apple' }), false);
  await expect('unknown provider', () => verifySocialIdentity({ provider: 'facebook', accessToken: 'x' }), false);

  console.log('\n--- Apple identity token (what the shipped app sends) ---');
  await expect('genuine Apple token accepted, email lowercased',
    () => verifySocialIdentity({ provider: 'apple', accessToken: apple() }), true,
    r => r.email === 'victim@example.com' && r.method === 'apple_identity_token');
  await expect('signed by an attacker key', () => verifySocialIdentity({ provider: 'apple', accessToken: apple({}) .replace(/\.[^.]+$/, '.' + crypto.sign('RSA-SHA256', Buffer.from('x'), evil.privateKey).toString('base64url')) }), false);
  await expect('token forged with attacker key and matching kid',
    () => verifySocialIdentity({ provider: 'apple', accessToken: sign({ iss: 'https://appleid.apple.com', aud: 'com.bitplaypro.bitplaypro', email: 'victim@example.com', email_verified: 'true', iat: now(), exp: now() + 600 }, { key: evil.privateKey }) }), false);
  await expect('expired', () => verifySocialIdentity({ provider: 'apple', accessToken: apple({ exp: now() - 3600 }) }), false);
  await expect('issued for another app', () => verifySocialIdentity({ provider: 'apple', accessToken: apple({ aud: 'com.someone.else' }) }), false);
  await expect('wrong issuer', () => verifySocialIdentity({ provider: 'apple', accessToken: apple({ iss: 'https://evil.example' }) }), false);
  await expect('unverified email', () => verifySocialIdentity({ provider: 'apple', accessToken: apple({ email_verified: 'false' }) }), false);
  await expect('no email in token', () => verifySocialIdentity({ provider: 'apple', accessToken: apple({ email: undefined }) }), false);
  await expect('alg "none" refused',
    () => verifySocialIdentity({ provider: 'apple', accessToken: sign({ iss: 'https://appleid.apple.com', aud: 'com.bitplaypro.bitplaypro', email: 'a@b.com', email_verified: 'true', exp: now() + 600 }, { header: { alg: 'none' } }) }), false);
  await expect('garbage token', () => verifySocialIdentity({ provider: 'apple', accessToken: 'not-a-jwt' }), false);

  console.log('\n--- Google (what the shipped app sends) ---');
  googleTokenInfo = null;
  await expect('a made-up access token Google rejects', () => verifySocialIdentity({ provider: 'google', accessToken: 'made-up' }), false);
  googleTokenInfo = { aud: '1063839909090-uscqt78cicu2udmo6spb8jute4vcfl3j.apps.googleusercontent.com', email: 'User@Gmail.com', email_verified: 'true', expires_in: '3000', sub: 'g-sub' };
  await expect('genuine access token for this app accepted',
    () => verifySocialIdentity({ provider: 'google', accessToken: 'real' }), true,
    r => r.email === 'user@gmail.com' && r.method === 'google_access_token');
  googleTokenInfo = { ...googleTokenInfo, aud: 'someone-elses-client.apps.googleusercontent.com', azp: 'someone-elses-client.apps.googleusercontent.com' };
  await expect('valid Google token minted for a different app', () => verifySocialIdentity({ provider: 'google', accessToken: 'other-app' }), false);
  googleTokenInfo = { aud: '1063839909090-tuitpjcj2lj0qgutd2pfa9d7ttarjd43.apps.googleusercontent.com', email: 'u@gmail.com', email_verified: 'false', expires_in: '3000' };
  await expect('Google account with unverified email', () => verifySocialIdentity({ provider: 'google', accessToken: 'unverified' }), false);
  googleTokenInfo = { aud: '1063839909090-tuitpjcj2lj0qgutd2pfa9d7ttarjd43.apps.googleusercontent.com', email: 'u@gmail.com', email_verified: 'true', expires_in: '0' };
  await expect('expired Google token', () => verifySocialIdentity({ provider: 'google', accessToken: 'expired' }), false);
  googleTokenInfo = { iss: 'https://accounts.google.com', aud: '1063839909090-eq6h8v5p2h8o9bj4omdj7hm0m7le0e3h.apps.googleusercontent.com', email: 'id@gmail.com', email_verified: true, expires_in: '3000' };
  await expect('genuine Google ID token accepted',
    () => verifySocialIdentity({ provider: 'google', idToken: 'real-id-token' }), true, r => r.method === 'google_id_token');

  console.log('\n--- Firebase ID token (newer app builds) ---');
  await expect('genuine Firebase token accepted', () => verifySocialIdentity({ provider: 'google', firebaseIdToken: firebase() }), true, r => r.method === 'firebase');
  await expect('Firebase token for another project', () => verifySocialIdentity({ provider: 'google', firebaseIdToken: firebase({ aud: 'other-project', iss: 'https://securetoken.google.com/other-project' }) }), false);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  process.exit(fail ? 1 : 0);
})();
