const { isDisposableEmail, blockedDomainCount } = require('../utils/disposableEmail');
let pass = 0, fail = 0;
const check = (n, c, d = '') => c ? (pass++, console.log(`  PASS  ${n}`)) : (fail++, console.log(`  FAIL  ${n}  ${d}`));

console.log(`\n  ${blockedDomainCount()} domains loaded\n`);
console.log('--- blocked ---');
for (const e of ['a@0-mail.com','a@10minutemail.com','a@mailinator.com','a@guerrillamail.com','a@yopmail.com','a@temp-mail.org'])
  check(e, isDisposableEmail(e));

console.log('\n--- real providers must still work ---');
for (const e of ['a@gmail.com','a@googlemail.com','a@icloud.com','a@privaterelay.appleid.com','a@outlook.com','a@yahoo.co.in','a@proton.me','a@adaptsmedia.com'])
  check(e, !isDisposableEmail(e));

console.log('\n--- evasion ---');
check('uppercase is caught', isDisposableEmail('A@MAILINATOR.COM'));
check('subdomain is caught', isDisposableEmail('a@mail.mailinator.com'));
check('surrounding spaces are caught', isDisposableEmail('  a@mailinator.com  '));
check('plus-addressing is caught', isDisposableEmail('a+tag@mailinator.com'));
// notmailinator.com is itself on the list, so it is not a lookalike. Use a
// domain that merely ends with a listed one's characters.
check('a domain that only looks similar is allowed', !isDisposableEmail('a@notamailinator.com'));
check('a listed domain is not matched as a suffix of another', !isDisposableEmail('a@xmailinator.com'));

console.log('\n--- malformed input is never a crash ---');
for (const e of ['', null, undefined, 'nope', '@', 'a@', 123, {}])
  check(JSON.stringify(e), isDisposableEmail(e) === false);

console.log(`\n=== ${pass} passed, ${fail} failed ===`);
process.exit(fail ? 1 : 0);
