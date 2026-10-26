/**
 * Server-side proof that a social sign-in really happened.
 *
 * /api/auth/social-login used to take `email` from the request body and issue a
 * login token for whichever account had that address. Nothing checked the
 * Google or Apple credential, so posting
 *   { provider: 'google', providerId: 'x', email: '<anyone>' }
 * logged the caller in as that person -- including accounts created with a
 * password, and without changing the password, so the owner never noticed.
 *
 * This verifies the provider's own signed credential and returns the email the
 * PROVIDER vouches for. The request body's email is never trusted.
 *
 * Accepts what app builds already in users' hands send, so nobody is locked out:
 *   - Google: `accessToken` (and `idToken` when present), checked with Google
 *   - Apple:  `accessToken`, which the app fills with Apple's identity token,
 *             an RS256 JWT verified against Apple's published keys
 * and, for newer builds, a Firebase ID token (`firebaseIdToken`), since the app
 * already signs in through Firebase Auth before calling this endpoint.
 *
 * No dependencies: signatures are checked with Node's built-in crypto.
 */
const crypto = require('crypto');
const https = require('https');

const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'bitplay-3fbe7';

// OAuth client IDs are public identifiers, not secrets. Web, Android and iOS
// clients from google-services.json / GoogleService-Info.plist.
const GOOGLE_CLIENT_IDS = (process.env.GOOGLE_CLIENT_IDS ||
  [
    '1063839909090-eq6h8v5p2h8o9bj4omdj7hm0m7le0e3h.apps.googleusercontent.com',
    '1063839909090-uscqt78cicu2udmo6spb8jute4vcfl3j.apps.googleusercontent.com',
    '1063839909090-tuitpjcj2lj0qgutd2pfa9d7ttarjd43.apps.googleusercontent.com',
  ].join(','))
  .split(',').map(s => s.trim()).filter(Boolean);

// Native Sign in with Apple issues tokens whose audience is the app bundle id.
const APPLE_AUDIENCES = (process.env.APPLE_AUDIENCES || 'com.bitplaypro.bitplaypro')
  .split(',').map(s => s.trim()).filter(Boolean);

const CLOCK_SKEW_SEC = 120;
const KEY_CACHE_MS = 60 * 60 * 1000;
const HTTP_TIMEOUT_MS = 8000;

class SocialVerificationError extends Error {
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}

/** GET a URL and parse JSON. Uses fetch when present, https otherwise. */
function getJson(url) {
  if (typeof fetch === 'function') {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
    return fetch(url, { signal: controller.signal })
      .then(async res => ({ status: res.status, body: await res.json().catch(() => ({})) }))
      .finally(() => clearTimeout(timer));
  }
  return new Promise((resolve, reject) => {
    const req = https.get(url, res => {
      let raw = '';
      res.on('data', c => { raw += c; });
      res.on('end', () => {
        let body = {};
        try { body = JSON.parse(raw); } catch (_) { /* leave empty */ }
        resolve({ status: res.statusCode, body });
      });
    });
    req.setTimeout(HTTP_TIMEOUT_MS, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

const keyCache = new Map();
async function cachedKeys(url) {
  const hit = keyCache.get(url);
  if (hit && Date.now() - hit.at < KEY_CACHE_MS) return hit.keys;
  const { status, body } = await getJson(url);
  if (status !== 200) throw new SocialVerificationError('Could not fetch signing keys', 'KEYS_UNAVAILABLE');
  keyCache.set(url, { at: Date.now(), keys: body });
  return body;
}

function b64urlJson(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

/**
 * Verify an RS256 JWT. `resolveKey(kid)` returns a KeyObject.
 * Returns the payload only when signature, issuer, audience and time all check out.
 */
async function verifyRs256Jwt(token, { resolveKey, issuers, audiences }) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new SocialVerificationError('Malformed token', 'MALFORMED');

  let header, payload;
  try {
    header = b64urlJson(parts[0]);
    payload = b64urlJson(parts[1]);
  } catch (_) {
    throw new SocialVerificationError('Malformed token', 'MALFORMED');
  }

  // Pin the algorithm: never let the token choose "none" or an HMAC scheme.
  if (header.alg !== 'RS256' || !header.kid) {
    throw new SocialVerificationError('Unsupported token algorithm', 'BAD_ALG');
  }

  const key = await resolveKey(header.kid);
  if (!key) throw new SocialVerificationError('Unknown signing key', 'UNKNOWN_KID');

  const signatureOk = crypto.verify(
    'RSA-SHA256',
    Buffer.from(`${parts[0]}.${parts[1]}`),
    key,
    Buffer.from(parts[2], 'base64url'),
  );
  if (!signatureOk) throw new SocialVerificationError('Invalid token signature', 'BAD_SIGNATURE');

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp + CLOCK_SKEW_SEC < now) {
    throw new SocialVerificationError('Token expired', 'EXPIRED');
  }
  if (typeof payload.iat === 'number' && payload.iat - CLOCK_SKEW_SEC > now) {
    throw new SocialVerificationError('Token issued in the future', 'BAD_IAT');
  }
  if (!issuers.includes(payload.iss)) {
    throw new SocialVerificationError('Wrong token issuer', 'BAD_ISSUER');
  }
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.some(a => audiences.includes(a))) {
    throw new SocialVerificationError('Token was not issued for this app', 'BAD_AUDIENCE');
  }
  return payload;
}

async function verifyFirebaseIdToken(token) {
  const certsUrl = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
  const payload = await verifyRs256Jwt(token, {
    issuers: [`https://securetoken.google.com/${FIREBASE_PROJECT_ID}`],
    audiences: [FIREBASE_PROJECT_ID],
    resolveKey: async kid => {
      const certs = await cachedKeys(certsUrl);
      return certs[kid] ? crypto.createPublicKey(certs[kid]) : null;
    },
  });
  if (!payload.sub) throw new SocialVerificationError('Token has no subject', 'NO_SUBJECT');
  return { email: payload.email, emailVerified: payload.email_verified === true, subject: payload.sub };
}

async function verifyAppleIdentityToken(token) {
  const payload = await verifyRs256Jwt(token, {
    issuers: ['https://appleid.apple.com'],
    audiences: APPLE_AUDIENCES,
    resolveKey: async kid => {
      const { keys = [] } = await cachedKeys('https://appleid.apple.com/auth/keys');
      const jwk = keys.find(k => k.kid === kid);
      return jwk ? crypto.createPublicKey({ key: jwk, format: 'jwk' }) : null;
    },
  });
  // Apple sends email_verified as a boolean or the string "true".
  const verified = payload.email_verified === true || payload.email_verified === 'true';
  return { email: payload.email, emailVerified: verified, subject: payload.sub };
}

/** Google ID token (JWT) or access token, validated by Google's tokeninfo endpoint. */
async function verifyGoogleToken({ idToken, accessToken }) {
  const param = idToken ? `id_token=${encodeURIComponent(idToken)}` : `access_token=${encodeURIComponent(accessToken)}`;
  const { status, body } = await getJson(`https://oauth2.googleapis.com/tokeninfo?${param}`);
  if (status !== 200 || !body) {
    throw new SocialVerificationError('Google did not accept this token', 'GOOGLE_REJECTED');
  }
  if (Number(body.expires_in) <= 0) {
    throw new SocialVerificationError('Token expired', 'EXPIRED');
  }
  if (idToken && !['accounts.google.com', 'https://accounts.google.com'].includes(body.iss)) {
    throw new SocialVerificationError('Wrong token issuer', 'BAD_ISSUER');
  }
  // A token minted for some other app must not work here.
  if (!GOOGLE_CLIENT_IDS.includes(body.aud) && !GOOGLE_CLIENT_IDS.includes(body.azp)) {
    // Client ids are public; logging which one lets a legitimate build (for
    // example a debug-signed one) be recognised and added to GOOGLE_CLIENT_IDS.
    throw new SocialVerificationError(`Token was not issued for this app (aud ${body.aud || '-'}, azp ${body.azp || '-'})`, 'BAD_AUDIENCE');
  }
  const verified = body.email_verified === true || body.email_verified === 'true';
  return { email: body.email, emailVerified: verified, subject: body.sub };
}

/**
 * @returns {Promise<{ email: string, subject: string, method: string }>}
 * @throws {SocialVerificationError} whenever the sign-in cannot be proven.
 */
async function verifySocialIdentity({ provider, accessToken, idToken, firebaseIdToken }) {
  let result;
  let method;

  if (firebaseIdToken) {
    result = await verifyFirebaseIdToken(firebaseIdToken);
    method = 'firebase';
  } else if (provider === 'google' && (idToken || accessToken)) {
    result = await verifyGoogleToken({ idToken, accessToken });
    method = idToken ? 'google_id_token' : 'google_access_token';
  } else if (provider === 'apple' && accessToken) {
    result = await verifyAppleIdentityToken(accessToken);
    method = 'apple_identity_token';
  } else {
    throw new SocialVerificationError('No verifiable sign-in credential was provided', 'NO_CREDENTIAL');
  }

  if (!result.email) {
    throw new SocialVerificationError('The sign-in provider did not share an email address', 'NO_EMAIL');
  }
  // An unverified address proves nothing about who owns the matching account.
  if (!result.emailVerified) {
    throw new SocialVerificationError('The email address has not been verified by the provider', 'EMAIL_UNVERIFIED');
  }
  return { email: String(result.email).trim().toLowerCase(), subject: result.subject, method };
}

module.exports = {
  verifySocialIdentity,
  SocialVerificationError,
  // exported for tests
  _internals: { verifyRs256Jwt, keyCache },
};
