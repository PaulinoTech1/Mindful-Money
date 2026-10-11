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
/* Deterministic demo data (bit-identical port of fakebank.py).         */
/*                                                                     */
/* The PRNG below reproduces CPython's random.Random(SEED) exactly:    */
/* MT19937 seeded via init_by_array over the seed's little-endian      */
/* 32-bit words, random() via genrand_res53, uniform/choice/gauss      */
/* matching CPython's formulas (gauss caches the spare Box-Muller normal */
/* in gauss_next, choice uses _randbelow rejection sampling). Combined   */
/* round-half-even decimal rounding, generateDemoTransactions()        */
/* produces byte-identical output to fakebank.generate().              */
/* ------------------------------------------------------------------ */

const DEMO_SEED = 20260802;

const DEMO_ACCOUNTS = {
  demo_checking: { bank: "Scammers Inc", label: "Everyday checking", type: "Checking" },
  demo_ira: { bank: "Wells Foreclosure", label: "Traditional IRA", type: "IRA" },
  demo_401k: { bank: "DC Unc", label: "Employer 401(k)", type: "401(k)" },
};

// (merchant, typical amount, spread, times per week)
const DEMO_RECURRING_WEEKLY = [
  ["Blue Bottle Coffee", 6.25, 1.75, 4],
  ["MTA OMNY", 2.90, 0.00, 6],
  ["Trader Joe's", 78.00, 26.00, 1],
  ["Sweetgreen", 15.40, 3.20, 2],
];

const DEMO_OCCASIONAL = [
  ["Amazon", 42.00, 35.00, 0.9],
  ["Duane Reade", 21.50, 12.00, 0.5],
  ["Uber", 18.75, 9.00, 0.8],
  ["Whole Foods Market", 63.00, 24.00, 0.6],
  ["Lucali", 88.00, 22.00, 0.2],
  ["Rough Trade Records", 34.00, 15.00, 0.25],
  ["Citi Bike", 4.95, 0.00, 0.4],
  ["Paragon Sports", 96.00, 48.00, 0.15],
];

const DEMO_MONTHLY_FIXED = [
  ["Stuyvesant Town Rent", 2150.00, 1],
  ["Fans Only", 423.23, 1],
  ["Con Edison", 104.00, 8],
  ["Verizon Fios", 79.99, 12],
  ["Spotify", 11.99, 4],
  ["Netflix", 15.49, 17],
  ["Equinox", 215.00, 2],
  ["State Farm Auto", 128.40, 22],
];

const DEMO_PAYCHECK = ["Meridian Systems Payroll", 2415.00];
const DEMO_IRA_CONTRIBUTION = ["IRA Contribution", 500.00];
const DEMO_K401_EMPLOYEE = ["401(k) Employee Deferral", 375.00];
const DEMO_K401_MATCH = ["401(k) Employer Match", 187.50];

// Irregular larger expenses
const DEMO_IRREGULAR = [
  ["Delta Air Lines", 428.00, 140.00],
  ["Weill Cornell Physicians", 215.00, 95.00],
  ["Apple Store", 329.00, 180.00],
  ["Con Edison True-Up", 186.00, 40.00],
  ["Enterprise Rent-A-Car", 264.00, 70.00],
  ["Warby Parker", 195.00, 0.00],
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
  if (months === undefined) months = 6;
  const rng = createSeededRandom(DEMO_SEED);
  const now = new Date();
  const tYear = now.getFullYear(), tMonth = now.getMonth(), tDay = now.getDate();
  // Anchor to the first of the month, else the earliest month is missing
  // its rent charge and the chart opens on a misleading spike.
  let y = tYear, m = (tMonth + 1) - months;
  while (m <= 0) { m += 12; y -= 1; }
  const DAY = 86400000;
  const startMs = Date.UTC(y, m - 1, 1);
  const todayMs = Date.UTC(tYear, tMonth, tDay);

  const rows = [];
  const counts = { demo_checking: 0, demo_ira: 0, demo_401k: 0 };

  function fmtDate(ms) { return new Date(ms).toISOString().slice(0, 10); }
  function fmtYM(ms) {
    const d = new Date(ms);
    return d.getUTCFullYear() + String(d.getUTCMonth() + 1).padStart(2, "0");
  }

  function add(ms, merchant, amount, account) {
    if (account === undefined) account = "demo_checking";
    if (ms > todayMs) return;
    const seq = counts[account] || 0;
    // Keep the legacy checking IDs stable when adding a new recurring
    // charge. The monthly charge gets its own deterministic ID, so a
    // refresh updates old rows instead of duplicating the feed.
    const isFansOnly = account === "demo_checking" && merchant === "Fans Only";
    let id;
    if (isFansOnly) id = "demo_fans_only_" + fmtYM(ms);
    else if (account === "demo_checking") id = "demo_" + String(seq).padStart(5, "0");
    else id = account + "_" + String(seq).padStart(5, "0");
    const meta = DEMO_ACCOUNTS[account];
    rows.push({
      id: id,
      merchant: merchant,
      amount: pyRound2(amount),
      date: fmtDate(ms),
      pending: false,
      account: account,
      bank: meta.bank,
      account_label: meta.label,
      account_type: meta.type,
      source: "fakebank",
    });
    if (!isFansOnly) counts[account] = seq + 1;
  }

  for (let t = startMs; t <= todayMs; t += DAY) {
    const d = new Date(t);
    const dom = d.getUTCDate();
    const weekday = (d.getUTCDay() + 6) % 7; // Monday=0, like Python
    const daysSinceStart = Math.round((t - startMs) / DAY);

    // Paycheck every other Friday.
    if (weekday === 4 && Math.floor(daysSinceStart / 7) % 2 === 0) {
      add(t, DEMO_PAYCHECK[0], -pyRound2(DEMO_PAYCHECK[1] * rng.uniform(0.98, 1.02)));
      // Retirement contributions are separate encrypted account feeds,
      // not checking-account expenses.
      add(t, DEMO_K401_EMPLOYEE[0], -DEMO_K401_EMPLOYEE[1], "demo_401k");
      add(t, DEMO_K401_MATCH[0], -DEMO_K401_MATCH[1], "demo_401k");
    }

    // One monthly contribution to the individual retirement account.
    if (dom === 15) {
      add(t, DEMO_IRA_CONTRIBUTION[0], -DEMO_IRA_CONTRIBUTION[1], "demo_ira");
    }

    // Fixed monthly bills.
    for (let fi = 0; fi < DEMO_MONTHLY_FIXED.length; fi++) {
      const merchant = DEMO_MONTHLY_FIXED[fi][0];
      const amount = DEMO_MONTHLY_FIXED[fi][1];
      const billDom = DEMO_MONTHLY_FIXED[fi][2];
      if (dom === billDom) {
        const jitter = (merchant.startsWith("Spotify") || merchant.startsWith("Netflix") ||
                        merchant.startsWith("Fans Only"))
          ? 1.0 : rng.uniform(0.9, 1.15);
        add(t, merchant, amount * jitter);
      }
    }

    // Weekly habits, weighted toward weekdays for coffee and transit.
    for (let wi = 0; wi < DEMO_RECURRING_WEEKLY.length; wi++) {
      const merchant = DEMO_RECURRING_WEEKLY[wi][0];
      const amount = DEMO_RECURRING_WEEKLY[wi][1];
      const spread = DEMO_RECURRING_WEEKLY[wi][2];
      const perWeek = DEMO_RECURRING_WEEKLY[wi][3];
      if (rng.random() < perWeek / 7) {
        if ((merchant === "Blue Bottle Coffee" || merchant === "MTA OMNY") && weekday >= 5) continue;
        add(t, merchant, Math.max(1.0, rng.gauss(amount, spread)));
      }
    }

    // Occasional discretionary spending, heavier on weekends.
    const weekendBoost = weekday >= 5 ? 1.6 : 1.0;
    for (let oi = 0; oi < DEMO_OCCASIONAL.length; oi++) {
      const merchant = DEMO_OCCASIONAL[oi][0];
      const amount = DEMO_OCCASIONAL[oi][1];
      const spread = DEMO_OCCASIONAL[oi][2];
      const perWeek = DEMO_OCCASIONAL[oi][3];
      if (rng.random() < (perWeek * weekendBoost) / 7) {
        add(t, merchant, Math.max(1.0, rng.gauss(amount, spread)));
      }
    }

    // Irregular one-offs, roughly twice a month across the whole list.
    if (rng.random() < 2.0 / 30) {
      const pick = rng.choice(DEMO_IRREGULAR);
      add(t, pick[0], Math.max(20.0, rng.gauss(pick[1], pick[2])));
    }
  }

  rows.sort(function (a, b) { return a.date < b.date ? -1 : a.date > b.date ? 1 : 0; });
  return rows;
}

/* Export for both classic <script> (top-level function declarations are
 * already globals) and CommonJS (node tests). */
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    fetchSimpleFinTransactions: fetchSimpleFinTransactions,
    generateDemoTransactions: generateDemoTransactions,
    SimpleFinError: SimpleFinError,
    SimpleFinAccessRevoked: SimpleFinAccessRevoked,
    SimpleFinUnavailable: SimpleFinUnavailable,
  };
}
