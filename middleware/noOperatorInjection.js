/**
 * Refuses requests that try to smuggle MongoDB query operators.
 *
 * Express turns ?email[$ne]= or a JSON body {"email": {"$ne": null}} into
 * objects, and the controllers pass email/otp fields straight into
 * User.findOne. That allowed reading which emails exist one character at a
 * time ({"$regex": "^a"}) and sending another user's code to an attacker.
 *
 * Refused: any query value that is not a plain string (or array of strings),
 * and any key starting with "$" anywhere in the query or body.
 * Same rule as the backend's middleware/noOperatorInjection.js.
 */
const MAX_DEPTH = 20;

function hasOperatorKey(value, depth = 0) {
  if (depth > MAX_DEPTH || value == null || typeof value !== 'object') return false;
  for (const key of Object.keys(value)) {
    if (key.startsWith('$')) return true;
    if (hasOperatorKey(value[key], depth + 1)) return true;
  }
  return false;
}

function hasNestedQueryObject(query) {
  for (const v of Object.values(query || {})) {
    if (v == null || typeof v === 'string') continue;
    if (Array.isArray(v) && v.every(x => typeof x === 'string')) continue;
    return true;
  }
  return false;
}

function noOperatorInjection(req, res, next) {
  if (hasNestedQueryObject(req.query) || hasOperatorKey(req.query) || hasOperatorKey(req.body) || hasOperatorKey(req.params)) {
    console.warn(`[Security] refused operator injection: ${req.method} ${String(req.originalUrl).slice(0, 200)} from ${req.ip}`);
    return res.status(400).json({ success: false, message: 'Invalid request.' });
  }
  next();
}

module.exports = noOperatorInjection;
module.exports.hasOperatorKey = hasOperatorKey;
