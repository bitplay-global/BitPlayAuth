#!/bin/sh
# The one list of checks run by BOTH the pre-commit and pre-push hooks.
#
# Exists because a change was once committed while its test suite was printing
# failures: nothing gated the commit. Now nothing is committed or pushed unless
# every check passes. A suite counts only if it prints
# "=== N passed, 0 failed ===" AND exits 0.
# Plain POSIX sh, every command written out (zsh does not word-split commands
# held in a variable, which once made checks silently not run).

cd "$(git rev-parse --show-toplevel)" || exit 1
failed=0

guard() {
  label=$1; shift
  if out=$("$@" 2>&1); then printf '  ok    %s\n' "$label"
  else printf '  FAIL  %s\n%s\n' "$label" "$out"; failed=1; fi
}

suite() {
  label=$1; shift
  out=$("$@" 2>&1); code=$?
  result=$(printf '%s\n' "$out" | grep -E '=== [0-9]+ passed, [0-9]+ failed ===' | tail -1)
  if [ "$code" -eq 0 ] && printf '%s' "$result" | grep -q ' 0 failed'; then
    printf '  ok    %-26s %s\n' "$label" "$result"
  else
    printf '  FAIL  %-26s exit %s %s\n' "$label" "$code" "${result:-(no result line -- suite did not run)}"
    printf '%s\n' "$out" | grep -E 'FAIL|Error' | head -15
    failed=1
  fi
}

echo "Security checks (bitplay-auth):"
guard "no tracked secrets"  sh -c '! git ls-files | grep -qE "(^|/)\.env$"'
guard "model indexes"       node scripts/check-model-indexes.js
suite "social token verify" node tests/verify-social-token.test.js
suite "disposable emails"   node tests/disposable-email.test.js

# The end-to-end suites borrow mongodb-memory-server and supertest from the
# backend checkout. Missing them is a failure, not a skip; opt out explicitly
# with SKIP_E2E=1.
DEPS=${TEST_DEPS_DIR:-../tupple_dev}
if [ -f "$DEPS/node_modules/mongodb-memory-server/package.json" ]; then
  suite "two-factor e2e"    env TEST_DEPS_DIR="$DEPS" node tests/two-factor.e2e.js
  suite "social login e2e"  env TEST_DEPS_DIR="$DEPS" node tests/social-login.e2e.js
elif [ "$SKIP_E2E" = "1" ]; then
  echo "  SKIP  e2e suites -- SKIP_E2E=1 (login, 2FA and social-login flows NOT tested)"
else
  echo "  FAIL  e2e suites -- need $DEPS with node_modules (or set SKIP_E2E=1 deliberately)"
  failed=1
fi

if [ "$failed" -ne 0 ]; then
  echo ""
  echo "Refusing: fix the failures above. Account security may be at risk."
  exit 1
fi
echo "All security checks passed."
