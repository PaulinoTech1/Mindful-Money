// Advisor demo dataset (static/simplefin-client.js generateDemoTransactions).
// Run: node tests/demo_dataset.test.mjs
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);
const { generateDemoTransactions } = require('../static/simplefin-client.js');

const a = generateDemoTransactions(12);
const b = generateDemoTransactions(12);
assert.equal(JSON.stringify(a), JSON.stringify(b), 'deterministic');
assert.ok(a.length > 600, 'a year of activity');
assert.equal(new Set(a.map((r) => r.id)).size, a.length, 'ids unique');

// Window independence: the same date yields the same rows and ids.
const six = generateDemoTransactions(6);
const firstSixDate = six[0].date;
const tail = a.filter((r) => r.date >= firstSixDate);
assert.equal(JSON.stringify(tail.map(({ id, merchant, amount }) => [id, merchant, amount]).filter(([, m]) => !/Visa Payment|Payment received/.test(m))),
  JSON.stringify(six.map(({ id, merchant, amount }) => [id, merchant, amount]).filter(([, m]) => !/Visa Payment|Payment received/.test(m))),
  'rows for a date do not depend on the window');

// Professional content only.
const banned = /fans ?only|onlyfans|scammer|foreclosure|dc unc|casino|betting|draftkings|fanduel|poker|lottery|strip club|adult|xxx/i;
const names = new Set(a.flatMap((r) => [r.merchant, r.bank, r.account_label]));
assert.deepEqual([...names].filter((n) => banned.test(n)), [], 'no unprofessional names');

// Shape and padding: each sealed plaintext is far below the 8192-byte bucket cap.
for (const r of a) {
  assert.match(r.date, /^\d{4}-\d{2}-\d{2}$/);
  assert.ok(Number.isFinite(r.amount) && typeof r.merchant === 'string' && r.id);
  assert.ok(typeof r.category === 'string' && r.category);
  const withEdits = { ...r, notes: 'x'.repeat(200), tags: ['a', 'b'], splits: [], excluded: false, fraud_status: '' };
  assert.ok(Buffer.byteLength(JSON.stringify(withEdits)) < 1024, 'record fits the smallest buckets');
}

// Accounts and transfers.
const accounts = new Set(a.map((r) => r.account));
assert.deepEqual([...accounts].sort(), ['demo_401k', 'demo_brokerage', 'demo_card', 'demo_checking', 'demo_ira', 'demo_savings']);
const sum = (f) => a.filter(f).reduce((s, r) => s + r.amount, 0);
for (const [from, to] of [['Transfer to Roth IRA', 'demo_ira'], ['Transfer to Emergency Fund', 'demo_savings'], ['Transfer to Brokerage', 'demo_brokerage']]) {
  assert.ok(Math.abs(sum((r) => r.merchant === from) + sum((r) => r.account === to)) < 0.005, from + ' balances');
}
assert.ok(Math.abs(sum((r) => r.merchant === 'Northbridge Visa Payment') + sum((r) => r.merchant === 'Payment received, thank you')) < 0.005, 'card payments balance');
assert.ok(a.filter((r) => /Transfer to|Visa Payment|Payment received|401\(k\)|Contribution|Transfer from|529/.test(r.merchant)).every((r) => r.is_transfer === true), 'transfers flagged');

// Hooks the browser tests rely on.
assert.equal(a.filter((r) => r.merchant === 'Peloton App').every((r) => r.amount === 44), true, 'fixed Peloton charge');
assert.ok(a.some((r) => r.merchant === 'Firestone Complete Auto Care'), 'one-off car repair');
console.log('demo_dataset: all assertions passed');
