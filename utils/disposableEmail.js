/**
 * Rejects sign-ups from disposable / throwaway email providers.
 *
 * Applies to registration only. Existing accounts are never re-checked: people
 * already using the app keep working whatever they signed up with, which is the
 * explicit requirement -- this is about who gets in from here on.
 *
 * The list is loaded once at startup into a Set, so the check is a hash lookup
 * on the request path rather than a scan of ~5,400 entries.
 */
const fs = require('fs');
const path = require('path');

const LIST_PATH = path.join(__dirname, '..', 'data', 'disposable-email-domains.txt');

let blockedDomains = new Set();

try {
  blockedDomains = new Set(
    fs
      .readFileSync(LIST_PATH, 'utf8')
      .split('\n')
      .map(line => line.trim().toLowerCase())
      .filter(line => line && !line.startsWith('#')),
  );
  console.log(`[DisposableEmail] Loaded ${blockedDomains.size} blocked domains`);
} catch (err) {
  // Never block sign-ups because the file is missing: a deploy that loses the
  // list should degrade to "allow everyone", not lock the front door.
  console.error(`[DisposableEmail] Could not load ${LIST_PATH}: ${err.message}`);
}

/**
 * @param {string} email
 * @returns {boolean} true when the address belongs to a known throwaway provider
 */
function isDisposableEmail(email) {
  if (blockedDomains.size === 0) return false;

  const at = String(email ?? '').trim().toLowerCase().lastIndexOf('@');
  if (at === -1) return false;
  const domain = String(email).trim().toLowerCase().slice(at + 1);
  if (!domain) return false;

  // Check the domain and each parent, so a listed provider cannot be dodged by
  // signing up as user@anything.mailinator.com.
  const labels = domain.split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    if (blockedDomains.has(labels.slice(i).join('.'))) return true;
  }
  return false;
}

module.exports = { isDisposableEmail, blockedDomainCount: () => blockedDomains.size };
