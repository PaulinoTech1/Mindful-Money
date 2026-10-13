"use strict";
/* simplefin-client.js
 *
 * Client-side bank-feed adapters for Mindful Money.
 *
 * Zero-knowledge rationale: the old server-side /api/relay fetched plaintext
 * bank transactions (SimpleFin or demo data) and handed them to the browser.
 * That put plaintext on the server, even transiently. These adapters run
 * entirely in the browser instead: the SimpleFin access URL, its Basic-auth
 * credentials, and every plaintext transaction never leave the client. The
 * server only ever receives blind_index + sealed (hex ciphertext) records.
 *
 * Credential handling rule: the access URL is a secret equivalent to a
 * password. It is never logged, never included in an error message, and only
 * ever sent (as an Authorization header) to the bridge host it names.
 *
 * Contents:
 *   fetchSimpleFinTransactions(accessUrl, days) - live SimpleFin bridge fetch
 *   generateDemoTransactions(months)            - deterministic demo data
 *     (bit-identical port of fakebank.py; same seed, same Mersenne Twister
 *     stream as CPython's random.Random, same generation logic)
 */

function SimpleFinError(message) {
  const e = new Error(message);
  e.name = "SimpleFinError";
  return e;
}
function SimpleFinAccessRevoked(message) {
  const e = new Error(message);
  e.name = "SimpleFinAccessRevoked";
  return e;
}
function SimpleFinUnavailable(message) {
  const e = new Error(message);
  e.name = "SimpleFinUnavailable";
  return e;
}

/* ------------------------------------------------------------------ */
/* Exact decimal rounding (ROUND_HALF_EVEN), matching Python's          */
/* Decimal.quantize / round(float, 2). Operates on exact values, never  */
/* on binary-float approximations, so halfway cases round correctly.   */
/* ------------------------------------------------------------------ */

function roundHalfEvenParts(intVal, scale10) {
  // Round the exact value intVal / 10^scale10 to 2 decimal places,
  // half-even. intVal is a non-negative BigInt.
  const drop = scale10 - 2;
  let hundredths;
  if (drop <= 0) {
    hundredths = intVal * (10n ** BigInt(-drop));
  } else {
    const div = 10n ** BigInt(drop);
    const q = intVal / div;
    const r = intVal % div;
    const cmp = r * 2n - div;
    if (cmp < 0n) hundredths = q;
    else if (cmp > 0n) hundredths = q + 1n;
    else hundredths = (q % 2n === 0n) ? q : q + 1n;
  }
  return Number(hundredths) / 100;
}

function decomposeDouble(x) {
  // Exact decomposition of a non-negative finite double into
  // { intVal: BigInt, scale10: number } with x == intVal / 10^scale10.
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setFloat64(0, x);
  const hi = dv.getUint32(0);
  const lo = dv.getUint32(4);
  const expBits = (hi >>> 20) & 0x7ff;
  let mant = (BigInt(hi & 0xfffff) << 32n) | BigInt(lo);
  let e;
  if (expBits === 0) {
    e = -1074; // subnormal: no implicit leading 1
  } else {
    mant |= (1n << 52n);
    e = expBits - 1075; // 1023 bias + 52 mantissa bits
  }
  if (e >= 0) return { intVal: mant << BigInt(e), scale10: 0 };
  // 2^e = 5^(-e) / 10^(-e)
  return { intVal: mant * (5n ** BigInt(-e)), scale10: -e };
}

function pyRound2(x) {
  // Faithful port of Python's round(float, 2): correctly-rounded
  // round-half-even of the exact binary value.
  if (x === 0 || !Number.isFinite(x)) return x;
  const neg = x < 0;
  const parts = decomposeDouble(Math.abs(x));
  const r = roundHalfEvenParts(parts.intVal, parts.scale10);
  return neg ? -r : r;
}

function negateRound2dp(amountStr) {
  // Faithful port of: float((-Decimal(amountStr)).quantize(Decimal("0.01")))
  // Input is a validated decimal string; the negation + half-even rounding
  // happen on the exact decimal value, never on a float.
  let s = String(amountStr).trim();
  let neg = true; // SimpleFin is inflow-positive; the app is spend-positive
  if (s.charAt(0) === "-") { neg = false; s = s.slice(1); }
  else if (s.charAt(0) === "+") { s = s.slice(1); }
  let exp = 0;
  const ePos = s.search(/[eE]/);
  if (ePos !== -1) { exp = parseInt(s.slice(ePos + 1), 10); s = s.slice(0, ePos); }
  const dot = s.indexOf(".");
  const intPart = dot === -1 ? s : s.slice(0, dot);
  const fracPart = dot === -1 ? "" : s.slice(dot + 1);
  const digits = (intPart + fracPart).replace(/^0+/, "");
  if (digits === "") return 0;
  // value = int(digits) * 10^(exp - len(fracPart))
  const shift = exp - fracPart.length; // scale10 for the integer `digits`
  const r = roundHalfEvenParts(BigInt(digits), -shift);
  return neg ? -r : r;
}

/* ------------------------------------------------------------------ */
/* SimpleFin schema validation (port of simplefin_models.py).          */
/* Fail closed: anything unexpected -> one generic error, no partial   */
/* data, and never anything derived from the access URL.               */
/* ------------------------------------------------------------------ */

const SF_MAX_ACCOUNTS = 200;
const SF_MAX_TXNS = 20000;
const SF_MAX_ERRORS = 200;
const SF_MAX_ID = 300;
const SF_MAX_NAME = 500;
const SF_MAX_DESC = 4000;
const SF_MAX_CURRENCY = 16;
const SF_MAX_AMOUNT_LEN = 64;
const SF_MAX_AMOUNT_MAG = 1e12;
const SF_MIN_TS = 0;
const SF_MAX_TS = 4102444800; // 2100-01-01
const SF_MAX_BODY_BYTES = 20 * 1024 * 1024;
const SF_AMOUNT_RE = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/;

function sfFail() {
  throw SimpleFinUnavailable("SimpleFin returned an unexpected response.");
}

function sfOptText(v, maxLen) {
  if (v === null || v === undefined) return null;
  if (typeof v !== "string" || v.length > maxLen || v.indexOf("\0") !== -1) sfFail();
  return v;
}

function sfReqText(v, maxLen) {
  if (typeof v !== "string" || v.length > maxLen || v.indexOf("\0") !== -1) sfFail();
  return v;
}

function sfTimestamp(v) {
  if (v === null || v === undefined) return null;
  if (typeof v !== "number" || !Number.isInteger(v) || v < SF_MIN_TS || v > SF_MAX_TS) sfFail();
  return v;
}

function sfTransaction(t) {
  if (t === null || typeof t !== "object" || Array.isArray(t)) sfFail();
  const id = sfReqText(t.id, SF_MAX_ID);
  const posted = sfTimestamp(t.posted);
  const transactedAt = sfTimestamp(t.transacted_at);
  if (typeof t.amount !== "string" || t.amount.length === 0 ||
      t.amount.length > SF_MAX_AMOUNT_LEN || !SF_AMOUNT_RE.test(t.amount)) sfFail();
  const mag = Number(t.amount);
  if (!Number.isFinite(mag) || Math.abs(mag) > SF_MAX_AMOUNT_MAG) sfFail();
  const description = sfOptText(t.description, SF_MAX_DESC);
  const payee = sfOptText(t.payee, SF_MAX_DESC);
  sfOptText(t.memo, SF_MAX_DESC); // validated, unused downstream
  let pending = false;
  if (t.pending !== undefined) {
    if (typeof t.pending !== "boolean") sfFail();
    pending = t.pending;
  }
  return { id: id, posted: posted, transacted_at: transactedAt, amount: t.amount,
           description: description, payee: payee, pending: pending };
}

function sfAccount(a) {
  if (a === null || typeof a !== "object" || Array.isArray(a)) sfFail();
  const id = sfReqText(a.id, SF_MAX_ID);
  const name = sfOptText(a.name, SF_MAX_NAME);
  let currency = null;
  if (a.currency !== undefined && a.currency !== null) {
    if (typeof a.currency !== "string" || a.currency.length > SF_MAX_CURRENCY ||
        a.currency.indexOf("\0") !== -1) sfFail();
    currency = a.currency;
  }
  let org = null;
  if (a.org !== undefined && a.org !== null) {
    if (typeof a.org !== "object" || Array.isArray(a.org)) sfFail();
    org = { name: sfOptText(a.org.name, SF_MAX_NAME) };
  }
  let transactions = [];
  if (a.transactions !== undefined) {
    if (!Array.isArray(a.transactions) || a.transactions.length > SF_MAX_TXNS) sfFail();
    transactions = a.transactions.map(sfTransaction);
  }
  return { id: id, name: name, currency: currency, org: org, transactions: transactions };
}

function sfParseAccountSet(body) {
  if (body === null || typeof body !== "object" || Array.isArray(body)) sfFail();
  let accounts = [];
  if (body.accounts !== undefined) {
    if (!Array.isArray(body.accounts) || body.accounts.length > SF_MAX_ACCOUNTS) sfFail();
    accounts = body.accounts.map(sfAccount);
  }
  let errors = [];
  if (body.errors !== undefined) {
    if (!Array.isArray(body.errors) || body.errors.length > SF_MAX_ERRORS) sfFail();
    for (const e of body.errors) {
      if (typeof e !== "string") continue;
      if (e.indexOf("\0") !== -1) sfFail();
      errors.push(e.slice(0, SF_MAX_DESC));
    }
  }
  return { accounts: accounts, errors: errors };
}

function detectAccountType(name) {
  const lowered = String(name === null || name === undefined ? "" : name).toLowerCase();
  const pairs = [
    ["checking", "Checking"],
    ["savings", "Savings"],
    ["credit", "Credit Card"],
    ["401", "401(k)"],
    ["ira", "IRA"],
    ["brokerage", "Brokerage"],
    ["loan", "Loan"],
  ];
  for (let i = 0; i < pairs.length; i++) {
    if (lowered.indexOf(pairs[i][0]) !== -1) return pairs[i][1];
  }
  return "Account";
}

function base64Utf8(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  if (typeof btoa !== "undefined") return btoa(bin);
  return Buffer.from(bin, "binary").toString("base64"); // node fallback
}

/* ------------------------------------------------------------------ */
/* fetchSimpleFinTransactions(accessUrl, days)                          */
/* ------------------------------------------------------------------ */

async function fetchSimpleFinTransactions(accessUrl, days) {
  if (typeof accessUrl !== "string" || accessUrl.trim() === "") {
    throw SimpleFinUnavailable("A SimpleFin access URL is required.");
  }
  let nDays = Math.floor(Number(days));
  if (!Number.isFinite(nDays) || nDays < 1) nDays = 90;
  nDays = Math.min(nDays, 90);

  const clean = accessUrl.trim().replace(/\/+$/, "");
  let parsed;
  try {
    parsed = new URL(clean);
  } catch (e) {
    throw SimpleFinUnavailable("The SimpleFin access URL is not a valid URL.");
  }
  if (parsed.protocol !== "https:") {
    throw SimpleFinUnavailable("The SimpleFin access URL must use HTTPS.");
  }

  const headers = {
    "Accept": "application/json",
    "User-Agent": "mindful-money-simplefin/1.0",
  };
  if (parsed.username) {
    // Credentials travel only in this header, for this one request, to the
    // one host named by the access URL. Never forwarded across a redirect
    // (redirects are refused outright) and never logged.
    headers["Authorization"] = "Basic " + base64Utf8(parsed.username + ":" + parsed.password);
  }
  const host = parsed.hostname + (parsed.port ? ":" + parsed.port : "");
  const path = parsed.pathname.replace(/\/+$/, "");
  const base = parsed.protocol + "//" + host + path + parsed.search;
  const start = Math.floor(Date.now() / 1000) - nDays * 86400;
  const target = base + "/accounts?start-date=" + start;

  const ctrl = new AbortController();
  const timer = setTimeout(function () { ctrl.abort(); }, 30000);
  let resp;
  try {
    resp = await fetch(target, { headers: headers, redirect: "error", signal: ctrl.signal });
  } catch (e) {
    throw SimpleFinUnavailable("Could not reach SimpleFin. Check your network connection and try again.");
  } finally {
    clearTimeout(timer);
  }

  if (resp.status === 403) {
    throw SimpleFinAccessRevoked(
      "SimpleFin refused the connection (HTTP 403). The access URL may have been " +
      "revoked or already claimed elsewhere. Disable this connection and set it up " +
      "again with a fresh token.");
  }
  if (resp.status === 402) {
    throw SimpleFinUnavailable("SimpleFin reports that payment is required for this connection.");
  }
  if (resp.status !== 200) {
    throw SimpleFinUnavailable("SimpleFin returned HTTP " + resp.status + ".");
  }

  let text;
  try {
    text = await resp.text();
  } catch (e) {
    throw SimpleFinUnavailable("Could not read the SimpleFin response.");
  }
  if (text.length > SF_MAX_BODY_BYTES) {
    throw SimpleFinUnavailable("SimpleFin returned an unexpectedly large response.");
  }
  let body;
  try {
    body = JSON.parse(text);
  } catch (e) {
    throw SimpleFinUnavailable("SimpleFin returned an unexpected response.");
  }

  const set = sfParseAccountSet(body);
  if (set.accounts.length === 0 && set.errors.length > 0) {
    throw SimpleFinUnavailable("SimpleFin reported an error for this connection.");
  }

  const rows = [];
  for (const account of set.accounts) {
    const accountId = account.id;
    const bank = (account.org && account.org.name) ? account.org.name : "Unknown institution";
    const accountLabel = account.name || accountId;
    const accountType = detectAccountType(accountLabel);
    for (const txn of account.transactions) {
      const posted = (txn.posted !== null && txn.posted !== undefined) ? txn.posted : txn.transacted_at;
      if (posted === null || posted === undefined) continue;
      rows.push({
        id: "simplefin_" + accountId + "_" + (txn.id || posted),
        merchant: txn.payee || txn.description || "Unknown",
        amount: negateRound2dp(txn.amount),
        date: new Date(posted * 1000).toISOString().slice(0, 10),
        pending: txn.pending === true,
        account: accountId,
        bank: bank,
        account_label: accountLabel,
        account_type: accountType,
        source: "simplefin",
      });
    }
  }
  rows.sort(function (a, b) { return a.date < b.date ? -1 : a.date > b.date ? 1 : 0; });
  return rows;
}

/* ------------------------------------------------------------------ */
/* Deterministic demo data: the Carter household (advisor demo).        */
/*                                                                     */
/* Persona (docs/DEMO_DATASET.md): Ethan (38, mechanical engineer) and  */
/* Priya (36, physical therapist) Carter, a dual-income household near */
/* Charlotte, NC with two children, Leo (4, daycare) and Maya (8,      */
/* after-school tutoring). Paid biweekly on alternating Fridays.       */
/*                                                                     */
/* Determinism: every calendar day draws from its own MT19937 stream    */
/* seeded with DEMO_SEED + the day number, so a given date always       */
/* produces the same transactions with the same ids whatever the        */
/* window, and a refresh updates rows instead of duplicating them.     */
/* Financial institutions are fictional; merchants are mainstream.     */
/* ------------------------------------------------------------------ */

const DEMO_SEED = 20261013;
const DEMO_CREEP_START = Date.UTC(2025, 9, 1);
const DEMO_CREEP_END = Date.UTC(2026, 9, 1);

const DEMO_ACCOUNTS = {
  demo_checking: { bank: "Northbridge Bank", label: "Joint checking", type: "Checking" },
  demo_card: { bank: "Northbridge Bank", label: "Rewards Visa", type: "Credit card" },
  demo_savings: { bank: "Northbridge Bank", label: "Emergency fund", type: "Savings" },
  demo_401k: { bank: "Keystone Retirement", label: "Ethan's 401(k)", type: "401(k)" },
  demo_ira: { bank: "Keystone Investments", label: "Priya's Roth IRA", type: "IRA" },
  demo_brokerage: { bank: "Keystone Investments", label: "Joint brokerage", type: "Brokerage" },
};

// Paychecks: [merchant, net amount, week parity]. Alternating Fridays.
const DEMO_PAYCHECKS = [
  ["Atlas Engineering Payroll", 3185.00, 0],
  ["Novant Health Payroll", 2465.00, 1],
];
// Ethan's 401(k), per Atlas paycheck (6% deferral, 3% employer match).
const DEMO_401K = [["401(k) Employee Deferral", 290.00], ["401(k) Employer Match", 145.00]];

// Monthly fixed items from checking: [merchant, amount, day, category, seasonal key, tag]
const DEMO_MONTHLY_CHECKING = [
  ["Rocket Mortgage", 2640.00, 1, "Housing", null, ""],
  ["Bright Horizons Child Care", 1450.00, 1, "Other", null, "childcare"],
  ["Toyota Financial Services", 465.00, 5, "Transport", null, ""],
  ["State Farm Auto & Home", 212.40, 8, "Health & insurance", null, "insurance"],
  ["Northwestern Mutual Life", 86.00, 8, "Health & insurance", null, "insurance"],
  ["Duke Energy", 138.00, 12, "Utilities", "summer", ""],
  ["Piedmont Natural Gas", 62.00, 14, "Utilities", "winter", ""],
  ["Charlotte Water", 74.00, 16, "Utilities", null, ""],
  ["Spectrum Internet", 79.99, 18, "Utilities", "fixed", ""],
  ["Verizon Wireless", 164.80, 20, "Utilities", "fixed", ""],
  ["Kumon Learning Center", 160.00, 3, "Other", "school", "education"],
  ["St. Jude Children's Research Hospital", 50.00, 25, "Other", "fixed", "giving"],
];

// Transfers out of checking to the household's own accounts (is_transfer).
// [merchant in checking, amount, day, destination account, merchant there]
const DEMO_TRANSFERS = [
  ["Transfer to Roth IRA", 500.00, 2, "demo_ira", "Contribution from checking"],
  ["Transfer to Emergency Fund", 400.00, 2, "demo_savings", "Transfer from checking"],
  ["Transfer to Brokerage", 300.00, 2, "demo_brokerage", "Contribution from checking"],
  ["NC 529 Plan Contribution", 150.00, 2, null, null],
];

// Card subscriptions: [merchant, amount, day]. Peloton App is the unused one.
const DEMO_SUBSCRIPTIONS = [
  ["Netflix", 15.49, 4],
  ["Spotify Family", 16.99, 7],
  ["Disney+", 13.99, 11],
  ["Amazon Prime", 14.99, 13],
  ["Apple iCloud+", 2.99, 15],
  ["Peloton App", 44.00, 19],
];

// Card spending: [merchant, typical, spread, times per week, category, kind]
// kind: "weekday" (Mon to Fri only), "weekend" (boosted Sat/Sun), "dining"
// (frequency and size creep up over the period), "" otherwise.
const DEMO_CARD_SPEND = [
  ["Harris Teeter", 38.00, 14.00, 0.6, "Groceries", ""],
  ["Target", 84.00, 30.00, 0.8, "Shopping", "weekend"],
  ["Amazon", 46.00, 28.00, 1.1, "Shopping", ""],
  ["Shell", 54.00, 9.00, 1.2, "Transport", ""],
  ["Starbucks", 7.40, 1.60, 2.2, "Dining", "dining"],
  ["Chipotle", 31.00, 7.00, 0.7, "Dining", "dining"],
  ["Panera Bread", 38.00, 9.00, 0.5, "Dining", "dining"],
  ["DoorDash", 48.00, 12.00, 0.6, "Dining", "dining"],
  ["Olive Garden", 92.00, 18.00, 0.25, "Dining", "dining"],
  ["CVS Pharmacy", 27.00, 14.00, 0.5, "Health & insurance", ""],
  ["The Home Depot", 118.00, 60.00, 0.3, "Shopping", "weekend"],
  ["Uber", 24.00, 8.00, 0.15, "Transport", ""],
  ["Atrium Health", 45.00, 20.00, 0.1, "Health & insurance", ""],
];

// Calendar events (month 1..12): [month, day, account, merchant, amount, category, tag]
// Negative amount = money in. They anchor the advisor talking points.
const DEMO_EVENTS = [
  [1, 9, "demo_card", "Costco Annual Membership", 130.00, "Shopping", ""],
  [2, 17, "demo_card", "Firestone Complete Auto Care", 1238.60, "Transport", "car repair"],
  [3, 13, "demo_checking", "Atlas Engineering Annual Bonus", -4800.00, "Income", "bonus"],
  [4, 21, "demo_checking", "IRS Treas 310 Tax Refund", -2340.00, "Refund", "tax refund"],
  [6, 10, "demo_checking", "YMCA Summer Day Camp", 640.00, "Other", "childcare"],
  [7, 1, "demo_checking", "YMCA Summer Day Camp", 640.00, "Other", "childcare"],
  [7, 8, "demo_card", "Delta Air Lines", 1864.40, "Transport", "vacation"],
  [7, 19, "demo_card", "Marriott Myrtle Beach", 1412.75, "Shopping", "vacation"],
  [8, 1, "demo_checking", "YMCA Summer Day Camp", 640.00, "Other", "childcare"],
  [8, 23, "demo_card", "Target Back to School", 286.30, "Shopping", "back to school"],
  [11, 28, "demo_card", "Best Buy", 642.18, "Shopping", "holiday"],
  [12, 6, "demo_card", "Amazon Holiday Gifts", 488.92, "Shopping", "holiday"],
  [12, 18, "demo_checking", "Habitat for Humanity", 500.00, "Other", "giving"],
];

function createSeededRandom(seedInt) {
  const N = 624, M = 397;
  const MATRIX_A = 0x9908b0df;
  const UPPER_MASK = 0x80000000, LOWER_MASK = 0x7fffffff;
  const mt = new Uint32Array(N);
  let idx = N;

  function initGenrand(seed) {
    mt[0] = seed >>> 0;
    for (let i = 1; i < N; i++) {
      mt[i] = (Math.imul(1812433253, mt[i - 1] ^ (mt[i - 1] >>> 30)) + i) >>> 0;
    }
  }

  function initByArray(key) {
    initGenrand(19650218);
    let i = 1, j = 0;
    let k = Math.max(N, key.length);
    for (; k > 0; k--) {
      const x = (mt[i] ^ Math.imul(mt[i - 1] ^ (mt[i - 1] >>> 30), 1664525)) >>> 0;
      mt[i] = (x + key[j] + j) >>> 0;
      i++; j++;
      if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
      if (j >= key.length) j = 0;
    }
    for (let kk = N - 1; kk > 0; kk--) {
      const x = (mt[i] ^ Math.imul(mt[i - 1] ^ (mt[i - 1] >>> 30), 1566083941)) >>> 0;
      mt[i] = (x - i) >>> 0;
      i++;
      if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
    }
    mt[0] = 0x80000000;
    idx = N;
  }

  function twist() {
    for (let i = 0; i < N; i++) {
      const y = ((mt[i] & UPPER_MASK) | (mt[(i + 1) % N] & LOWER_MASK)) >>> 0;
      mt[i] = (mt[(i + M) % N] ^ (y >>> 1) ^ ((y & 1) ? MATRIX_A : 0)) >>> 0;
    }
    idx = 0;
  }

  function int32() {
    if (idx >= N) twist();
    let y = mt[idx++];
    y ^= y >>> 11;
    y ^= (y << 7) & 0x9d2c5680;
    y ^= (y << 15) & 0xefc60000;
    y ^= y >>> 18;
    return y >>> 0;
  }

  function random() {
    // genrand_res53
    const a = int32() >>> 5;
    const b = int32() >>> 6;
    return (a * 67108864 + b) / 9007199254740992;
  }

  function uniform(a, b) {
    return a + (b - a) * random();
  }

  function choice(seq) {
    // CPython _randbelow: rejection sampling on getrandbits(bit_length(n))
    const n = seq.length;
    const k = 32 - Math.clz32(n);
    for (;;) {
      const r = int32() >>> (32 - k);
      if (r < n) return seq[r];
    }
  }

  // CPython's gauss caches the second Box-Muller normal in gauss_next
  // (cleared by seed()); a call that hits the cache consumes no draws.
  let gaussNext = null;

  function gauss(mu, sigma) {
    let z = gaussNext;
    gaussNext = null;
    if (z === null) {
      const x2pi = random() * (2 * Math.PI);
      const g2rad = Math.sqrt(-2.0 * Math.log(1.0 - random()));
      z = Math.cos(x2pi) * g2rad;
      gaussNext = Math.sin(x2pi) * g2rad;
    }
    return mu + z * sigma;
  }

  // Seed like CPython's random.Random(int): absolute value split into
  // little-endian 32-bit words, then init_by_array.
  let vv = BigInt(seedInt);
  if (vv < 0n) vv = -vv;
  const words = [];
  if (vv === 0n) words.push(0);
  while (vv > 0n) { words.push(Number(vv & 0xffffffffn)); vv >>= 32n; }
  initByArray(words);

  return { random: random, uniform: uniform, choice: choice, gauss: gauss };
}

function generateDemoTransactions(months) {
  if (months === undefined) months = 12;
  const now = new Date();
  const tYear = now.getFullYear(), tMonth = now.getMonth(), tDay = now.getDate();
  // Anchor to the first of the month so the first month is complete.
  let y = tYear, m = (tMonth + 1) - months;
  while (m <= 0) { m += 12; y -= 1; }
  const DAY = 86400000;
  const startMs = Date.UTC(y, m - 1, 1);
  const todayMs = Date.UTC(tYear, tMonth, tDay);

  const rows = [];
  const idCounts = {};
  const cardByMonth = {};

  function fmtDate(ms) { return new Date(ms).toISOString().slice(0, 10); }
  function slug(s) { return s.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, ""); }

  function add(ms, merchant, amount, account, category, opts) {
    if (ms > todayMs) return;
    opts = opts || {};
    const date = fmtDate(ms);
    // Stable id: account, date and merchant (plus a same-day counter).
    const base = account + "_" + date.replace(/-/g, "") + "_" + slug(merchant);
    const n = idCounts[base] || 0;
    idCounts[base] = n + 1;
    const meta = DEMO_ACCOUNTS[account];
    const row = {
      id: n ? base + "_" + n : base,
      merchant: merchant,
      amount: pyRound2(amount),
      date: date,
      pending: false,
      account: account,
      bank: meta.bank,
      account_label: meta.label,
      account_type: meta.type,
      category: category,
      source: "fakebank",
    };
    if (opts.transfer) row.is_transfer = true;
    if (opts.tag) row.tags = [opts.tag];
    rows.push(row);
    if (account === "demo_card" && !opts.transfer) {
      const ym = date.slice(0, 7);
      cardByMonth[ym] = (cardByMonth[ym] || 0) + row.amount;
    }
  }

  for (let t = startMs; t <= todayMs; t += DAY) {
    const d = new Date(t);
    const dom = d.getUTCDate();
    const month = d.getUTCMonth() + 1;
    const weekday = (d.getUTCDay() + 6) % 7; // Monday=0
    const dayNumber = Math.round(t / DAY);
    const rng = createSeededRandom(DEMO_SEED + dayNumber);
    // Dining creep is anchored to fixed dates, not to the window, so a
    // refresh never rewrites past rows. It rises over DEMO_CREEP_START to
    // DEMO_CREEP_END and stays flat afterwards.
    const progress = Math.min(1, Math.max(0, (t - DEMO_CREEP_START) / (DEMO_CREEP_END - DEMO_CREEP_START)));

    // Paychecks on alternating Fridays (absolute week parity, window independent).
    if (weekday === 4) {
      const parity = Math.floor((dayNumber + 3) / 7) % 2;
      for (const [merchant, net, p] of DEMO_PAYCHECKS) {
        if (parity !== p) continue;
        add(t, merchant, -net * rng.uniform(0.995, 1.005), "demo_checking", "Income");
        if (p === 0) {
          for (const [k, amt] of DEMO_401K) add(t, k, -amt, "demo_401k", "Investing", { transfer: true });
        }
      }
    }

    // Monthly checking bills with seasonality.
    for (const [merchant, amount, day, category, season, tag] of DEMO_MONTHLY_CHECKING) {
      if (dom !== day) continue;
      if (season === "school" && (month === 6 || month === 7 || month === 8)) continue;
      let amt = amount;
      if (season === "summer") amt *= ({ 6: 1.45, 7: 1.7, 8: 1.6, 9: 1.2, 12: 1.15, 1: 1.25, 2: 1.15 })[month] || 1.0;
      if (season === "winter") amt *= ({ 11: 1.6, 12: 2.3, 1: 2.6, 2: 2.2, 3: 1.5, 6: 0.45, 7: 0.4, 8: 0.4 })[month] || 1.0;
      if (season !== "fixed" && amount < 1000) amt *= rng.uniform(0.94, 1.06);
      add(t, merchant, amt, "demo_checking", category, { tag: tag });
    }

    // Weekly grocery run on Saturdays; Costco every other Sunday.
    if (weekday === 5) add(t, "Harris Teeter", rng.gauss(172.0, 18.0), "demo_card", "Groceries");
    if (weekday === 6 && Math.floor((dayNumber + 3) / 7) % 2 === 1) {
      add(t, "Costco Wholesale", rng.gauss(236.0, 30.0), "demo_card", "Groceries");
    }

    // Monthly transfers to the household's own accounts.
    for (const [merchant, amount, day, dest, destMerchant] of DEMO_TRANSFERS) {
      if (dom !== day) continue;
      add(t, merchant, amount, "demo_checking", "Investing", { transfer: true, tag: dest ? "" : "529" });
      if (dest) add(t, destMerchant, -amount, dest, "Investing", { transfer: true });
    }

    // Card subscriptions.
    for (const [merchant, amount, day] of DEMO_SUBSCRIPTIONS) {
      if (dom === day) add(t, merchant, amount, "demo_card", "Subscriptions");
    }

    // Everyday card spending.
    for (const [merchant, typical, spread, perWeek, category, kind] of DEMO_CARD_SPEND) {
      let rate = perWeek / 7;
      let size = typical;
      if (kind === "weekend" && weekday >= 5) rate *= 1.8;
      if (kind === "dining") {
        // Dining creep: roughly 1.6x by the end of the period.
        rate *= 0.75 + 0.6 * progress;
        size *= 0.92 + 0.2 * progress;
      }
      if (merchant === "Starbucks" && weekday >= 5) rate *= 0.3;
      if (month === 12 && category === "Shopping") rate *= 1.6;
      const draw = rng.random();
      const amt = Math.max(3.0, rng.gauss(size, spread));
      if (draw < rate) add(t, merchant, amt, "demo_card", category);
    }

    // Calendar events.
    for (const [em, ed, account, merchant, amount, category, tag] of DEMO_EVENTS) {
      if (em === month && ed === dom) add(t, merchant, amount, account, category, { tag: tag });
    }

    // Card paid in full on the 20th for the previous month's statement.
    if (dom === 20) {
      const prev = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - 1, 1));
      const ym = prev.toISOString().slice(0, 7);
      if (cardByMonth[ym]) {
        const bill = pyRound2(cardByMonth[ym]);
        add(t, "Northbridge Visa Payment", bill, "demo_checking", "Other", { transfer: true });
        add(t, "Payment received, thank you", -bill, "demo_card", "Other", { transfer: true });
      }
    }
  }

  rows.sort(function (a, b) { return a.date < b.date ? -1 : a.date > b.date ? 1 : (a.id < b.id ? -1 : a.id > b.id ? 1 : 0); });
  return rows;
}

/* ------------------------------------------------------------------ */
/* CSV bank statement parser (client-side only)                        */
/*                                                                     */
/* Parses common bank CSV formats. All parsing happens in the browser;  */
/* the raw CSV never touches the server. Returns transactions in the    */
/* same shape as fetchSimpleFinTransactions().                         */
/*                                                                     */
/* Supported columns (case-insensitive, auto-detected):                */
/*   Date, Description/Merchant, Amount, (optional) Account, Type       */
/* ------------------------------------------------------------------ */

function parseBankCSV(csvText) {
  if (typeof csvText !== "string" || !csvText.trim()) {
    throw new Error("Empty CSV file");
  }
  var lines = csvText.trim().split(/\r?\n/);
  if (lines.length < 2) {
    throw new Error("CSV must have a header row and at least one data row");
  }

  // Parse header
  var headers = parseCSVLine(lines[0]).map(function(h) { return h.toLowerCase().trim(); });

  // Auto-detect columns
  var dateIdx = findCol(headers, ["date", "transaction date", "posted", "posting date"]);
  var descIdx = findCol(headers, ["description", "merchant", "payee", "memo", "details"]);
  var amountIdx = findCol(headers, ["amount", "value"]);
  var debitIdx = findCol(headers, ["debit", "withdrawal", "paid out"]);
  var creditIdx = findCol(headers, ["credit", "deposit", "paid in"]);

  if (dateIdx === -1) throw new Error("CSV must have a Date column");
  if (descIdx === -1) throw new Error("CSV must have a Description/Merchant column");
  if (amountIdx === -1 && (debitIdx === -1 || creditIdx === -1)) {
    throw new Error("CSV must have an Amount column (or Debit/Credit columns)");
  }

  var transactions = [];
  var rejected = [];
  var seenIds = {};
  for (var i = 1; i < lines.length; i++) {
    if (!lines[i].trim()) continue;
    var cols = parseCSVLine(lines[i]);
    var rowNum = i + 1;

    var date = cols[dateIdx] ? cols[dateIdx].trim() : "";
    var merchant = cols[descIdx] ? cols[descIdx].trim() : "";
    if (!date || !merchant) {
      rejected.push({row: rowNum, reason: !date ? "missing date" : "missing merchant/description"});
      continue;
    }

    // Normalize date to YYYY-MM-DD
    date = normalizeDate(date);
    if (!date) {
      rejected.push({row: rowNum, reason: "unparseable date: " + cols[dateIdx]});
      continue;
    }

    var amount;
    if (amountIdx !== -1) {
      amount = parseAmount(cols[amountIdx]);
    } else {
      var debit = parseAmount(cols[debitIdx] || "0");
      var credit = parseAmount(cols[creditIdx] || "0");
      amount = credit - debit;
    }
    if (amount === null || isNaN(amount)) {
      rejected.push({row: rowNum, reason: "unparseable amount"});
      continue;
    }

    // Sanitize: strip control chars, limit length, prevent code injection
    // (data is encrypted before storage, but defense in depth)
    merchant = merchant.replace(/[\x00-\x1F\x7F]/g, "").slice(0, 200);

    var txnId = "csv-" + i + "-" + Math.abs(hashStr(date + merchant + amount));
    if (seenIds[txnId]) {
      rejected.push({row: rowNum, reason: "duplicate of row " + seenIds[txnId]});
      continue;
    }
    seenIds[txnId] = rowNum;
    transactions.push({
      id: txnId,
      date: date,
      merchant: merchant,
      amount: Math.round(amount * 100) / 100,
      pending: false,
      account: "csv-import",
      bank: "CSV Import",
      account_label: "Imported",
      account_type: "checking",
      source: "csv",
    });
  }

  // Reconciliation: track what was accepted, rejected, and why
  var reconciliation = {
    total_rows: lines.length - 1,
    accepted: transactions.length,
    rejected: rejected,
    total_debits: 0,
    total_credits: 0,
  };
  for (var j = 0; j < transactions.length; j++) {
    if (transactions[j].amount < 0) reconciliation.total_debits -= transactions[j].amount;
    else reconciliation.total_credits += transactions[j].amount;
  }

  if (!transactions.length) {
    throw new Error("No valid transactions found in CSV. " +
      rejected.length + " rows rejected: " +
      rejected.slice(0, 3).map(function(r) { return "row " + r.row + " (" + r.reason + ")"; }).join("; "));
  }
  return { transactions: transactions, reconciliation: reconciliation };
}

function parseCSVLine(line) {
  var result = [];
  var current = "";
  var inQuotes = false;
  for (var i = 0; i < line.length; i++) {
    var c = line[i];
    if (c === '"') {
      if (inQuotes && line[i+1] === '"') { current += '"'; i++; }
      else inQuotes = !inQuotes;
    } else if (c === "," && !inQuotes) {
      result.push(current); current = "";
    } else {
      current += c;
    }
  }
  result.push(current);
  return result;
}

function findCol(headers, names) {
  for (var j = 0; j < names.length; j++) {
    var idx = headers.indexOf(names[j]);
    if (idx !== -1) return idx;
  }
  return -1;
}

function parseAmount(s) {
  if (!s) return null;
  // Remove currency symbols, commas, whitespace
  var clean = String(s).replace(/[$,\s]/g, "").replace(/[()]/g, function(m) { return m === "(" ? "-" : ""; });
  var n = parseFloat(clean);
  return isNaN(n) ? null : n;
}

function normalizeDate(s) {
  // Try common formats, output YYYY-MM-DD
  s = s.trim();
  var m;
  // YYYY-MM-DD
  if ((m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/))) {
    return m[1] + "-" + m[2].padStart(2, "0") + "-" + m[3].padStart(2, "0");
  }
  // MM/DD/YYYY or M/D/YYYY
  if ((m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/))) {
    return m[3] + "-" + m[1].padStart(2, "0") + "-" + m[2].padStart(2, "0");
  }
  // DD/MM/YYYY (if first > 12)
  if ((m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/)) && parseInt(m[1]) > 12) {
    return m[3] + "-" + m[2].padStart(2, "0") + "-" + m[1].padStart(2, "0");
  }
  return null;
}

function hashStr(s) {
  var h = 0;
  for (var i = 0; i < s.length; i++) {
    h = ((h << 5) - h + s.charCodeAt(i)) | 0;
  }
  return h;
}

/* Export for both classic <script> (top-level function declarations are
 * already globals) and CommonJS (node tests). */
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    fetchSimpleFinTransactions: fetchSimpleFinTransactions,
    generateDemoTransactions: generateDemoTransactions,
    parseBankCSV: parseBankCSV,
    SimpleFinError: SimpleFinError,
    SimpleFinAccessRevoked: SimpleFinAccessRevoked,
    SimpleFinUnavailable: SimpleFinUnavailable,
  };
}
