/* Vault client.
   Everything security-relevant and every number on screen is computed here,
   on the device. The server is a blob store: it never sees a passphrase, a
   key, a merchant name or an amount. */

'use strict';

const $ = (id) => document.getElementById(id);
let S = null;                 // sodium, after ready
let KEYS = null;              // { publicKey, privateKey, indexKey }
let TXNS = [];                // decrypted, in memory only
let CHARTS = {};
let CSRF = '';
let PASSKEY_REQUIRED = false;
let PASSKEY_AUTHENTICATED = false;
let EDITING_TRANSACTION_ID = null;

const apiFetch = async (url, options = {}) => {
  const opts = { credentials: 'same-origin', ...options, headers: { ...(options.headers || {}) } };
  const method = (opts.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD'].includes(method)) opts.headers['X-CSRF-Token'] = CSRF;
  const response = await fetch(url, opts);
  const contentType = response.headers.get('content-type') || '';
  const data = contentType.includes('application/json') ? await response.json().catch(() => ({})) : {};
  if (!response.ok) throw new Error(data.error || (response.status === 401 ? 'Your passkey session expired.' : 'Request failed.'));
  if (typeof data.csrf_token === 'string') CSRF = data.csrf_token;
  return data;
};
const api = apiFetch;

const b64ToBytes = (value) => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((value.length + 3) % 4)), (c) => c.charCodeAt(0));
const bytesToB64 = (value) => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const publicKeyOptions = (o) => ({ ...o, challenge: b64ToBytes(o.challenge), user: o.user ? { ...o.user, id: b64ToBytes(o.user.id) } : undefined, excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64ToBytes(c.id) })), allowCredentials: (o.allowCredentials || []).map((c) => ({ ...c, id: b64ToBytes(c.id) })) });
const credentialJSON = (c) => ({
  id: c.id, rawId: bytesToB64(c.rawId), type: c.type,
  response: c.response.attestationObject ? {
    attestationObject: bytesToB64(c.response.attestationObject), clientDataJSON: bytesToB64(c.response.clientDataJSON),
    transports: c.response.getTransports ? c.response.getTransports() : [],
  } : {
    authenticatorData: bytesToB64(c.response.authenticatorData), clientDataJSON: bytesToB64(c.response.clientDataJSON),
    signature: bytesToB64(c.response.signature), userHandle: c.response.userHandle ? bytesToB64(c.response.userHandle) : null,
  },
  clientExtensionResults: c.getClientExtensionResults(),
});

/* ---- DEMO ONLY -----------------------------------------------------------
   Fixed salts so a page reload can re-derive the same key without a signup
   flow. A real build generates random salts per user at signup and stores
   them alongside the public key. Do not ship this constant.            */
const DEMO_SALT_ENC  = new Uint8Array([73,26,201,4,155,88,17,240,63,129,7,198,44,90,231,12]);
const DEMO_SALT_IDX  = new Uint8Array([9,144,37,222,101,58,175,20,86,3,249,130,66,11,193,77]);

/* ---------- categorization: on the device, never on the server ---------- */

const RULES = [
  [/payroll|deposit/i,                                  'Income'],
  [/rent|stuyvesant/i,                                  'Housing'],
  [/trader joe|whole foods/i,                           'Groceries'],
  [/blue bottle|sweetgreen|lucali/i,                    'Dining'],
  [/mta|omny|uber|citi bike|enterprise|delta air/i,     'Transport'],
  [/con edison|verizon/i,                               'Utilities'],
  [/spotify|netflix|fans only/i,                        'Subscriptions'],
  [/amazon|apple store|rough trade|paragon|warby/i,     'Shopping'],
  [/duane reade|weill cornell|equinox|state farm/i,     'Health & insurance'],
  [/ira contribution|401\(k\)|employee deferral|employer match/i, 'Investing'],
];

const CAT_COLOR = {
  'Housing':            '#2e4b6b',
  'Groceries':          '#1f6b54',
  'Dining':             '#9e3b3b',
  'Transport':          '#7a5c2e',
  'Utilities':          '#4a6572',
  'Subscriptions':      '#6b4a7a',
  'Shopping':           '#a66a2e',
  'Health & insurance': '#3a7a7a',
  'Investing':          '#8a5b31',
  'Income':             '#1f6b54',
  'Uncategorized':      '#74879a',
};

const categorize = (merchant) => {
  for (const [re, cat] of RULES) if (re.test(merchant)) return cat;
  return 'Uncategorized';
};

/* ---------- crypto ---------- */

async function deriveKeys(passphrase) {
  const A = S.crypto_pwhash_ALG_ARGON2ID13;
  const ops = S.crypto_pwhash_OPSLIMIT_INTERACTIVE;
  const mem = S.crypto_pwhash_MEMLIMIT_INTERACTIVE;

  // Seeded keypair so the same passphrase always yields the same identity.
  const seed = S.crypto_pwhash(32, passphrase, DEMO_SALT_ENC, ops, mem, A);
  const kp = S.crypto_box_seed_keypair(seed);
  const indexKey = S.crypto_pwhash(32, passphrase, DEMO_SALT_IDX, ops, mem, A);

  return { publicKey: kp.publicKey, privateKey: kp.privateKey, indexKey };
}

const seal = (obj) =>
  S.to_hex(S.crypto_box_seal(S.from_string(JSON.stringify(obj)), KEYS.publicKey));

const open = (hex) =>
  JSON.parse(S.to_string(
    S.crypto_box_seal_open(S.from_hex(hex), KEYS.publicKey, KEYS.privateKey)));

const blindIndex = (id) =>
  S.to_hex(S.crypto_generichash(32, S.from_string(id), KEYS.indexKey));

// Empirical Shannon entropy of the characters entered. This is a local
// estimate, not a password-cracking guarantee; no passphrase data is stored or
// transmitted by this measurement.
function updatePassphraseEntropy() {
  const value = $('pass').value.trim();
  const output = $('passEntropy');
  if (!value.length) {
    output.dataset.level = '';
    output.textContent = 'Shannon entropy: 0.00 bits — enter a passphrase.';
    return;
  }
  const chars = [...value];
  const counts = new Map();
  for (const char of chars) counts.set(char, (counts.get(char) || 0) + 1);
  const bitsPerCharacter = [...counts.values()].reduce((sum, count) => {
    const probability = count / chars.length;
    return sum - probability * Math.log2(probability);
  }, 0);
  const entropy = bitsPerCharacter * chars.length;
  const [level, message] = chars.length <= 8
    ? ['weak', 'Lost kid, get a better passphrase']
    : chars.length <= 14
      ? ['decent', 'Decent, Buddy']
      : ['good', "Good, but you're still Cooked."];
  output.dataset.level = level;
  output.textContent = `Shannon entropy: ${entropy.toFixed(2)} bits — ${message}`;
}

/* ---------- formatting ---------- */

const money = (n, sign) => {
  const s = Math.abs(n).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  return (sign && n < 0 ? '\u2212' : '') + '$' + s;
};
const monthName = (ym) => {
  const [y, m] = ym.split('-');
  return new Date(y, m - 1, 1).toLocaleString('en-US', { month: 'short' });
};

/* ---------- flow ---------- */

async function unlock() {
  const pass = $('pass').value.trim();
  if (!pass) { $('gateNote').textContent = 'Enter a passphrase to continue.'; return; }

  $('unlockBtn').disabled = true;
  $('gateNote').textContent = 'Deriving key\u2026';
  await new Promise((r) => setTimeout(r, 30));   // let the label paint

  try {
    KEYS = await deriveKeys(pass);
    await load(true);
    await api('/api/vault/unlocked', { method: 'POST' });
  } catch (_error) {
    KEYS = null; TXNS = [];
    $('unlockBtn').disabled = false;
    $('gateNote').textContent = 'Incorrect vault passphrase or the records could not be decrypted.';
    return;
  }

  $('lock').dataset.state = 'open';
  $('lockLabel').textContent = 'Unlocked';
  $('statKey').textContent = S.to_hex(KEYS.publicKey).slice(0, 12);
  $('stats').hidden = false;
  $('syncBtn').hidden = false;
  $('resetBtn').hidden = false;
  $('gate').hidden = true;
  $('security').hidden = false;
  await refreshSecurity();
  $('unlockBtn').disabled = false;
}

async function load(duringUnlock = false) {
  const { records } = await api('/api/records');

  if (!records.length) { if (!duringUnlock) $('empty').hidden = false; else $('empty').hidden = false; return; }

  // Decrypt everything locally. ~20MB for a decade of history, so the whole
  // corpus lives in memory and every aggregate is computed here.
  let decrypted = records.map((r) => open(r.sealed));

  // Records written by older versions do not contain encrypted institution
  // metadata. Fetch it again, merge and re-seal it here in the browser so the
  // names become visible without ever adding plaintext columns server-side.
  if (decrypted.some((t) => !t.bank || !t.account_label || !t.account_type || t.bank === 'Wells Forclosure')) {
    const { transactions } = await api('/api/relay', { method: 'POST' });
    const metadata = new Map(transactions.map((t) => [t.account, {
      bank: t.bank, account_label: t.account_label, account_type: t.account_type,
    }]));
    decrypted = decrypted.map((t) => ({ ...t, ...(metadata.get(t.account) || {}) }));
    const migrated = records.map((record, index) => ({
      blind_index: record.blind_index,
      sealed: seal(decrypted[index]),
    }));
    await api('/api/records', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ records: migrated }),
    });
  }

  TXNS = decrypted.map((t) => ({
    ...t, category: t.category || categorize(t.merchant),
    notes: typeof t.notes === 'string' ? t.notes : '',
    tags: Array.isArray(t.tags) ? t.tags : [],
    splits: Array.isArray(t.splits) ? t.splits : [],
    is_transfer: Boolean(t.is_transfer), excluded: Boolean(t.excluded),
  }))
                  .sort((a, b) => a.date.localeCompare(b.date));

  $('statRecords').textContent = TXNS.length;
  renderAccounts();
  $('empty').hidden = true;
  $('dash').hidden = false;
  $('viewToggle').hidden = false;
  render();
}

async function connect() {
  $('connectBtn').disabled = true;
  $('syncBtn').disabled = true;
  $('connectNote').textContent = 'Fetching from bank\u2026';

  // The server relays plaintext in this response and stores none of it.
  const { transactions } = await api('/api/relay', { method: 'POST' });

  $('connectNote').textContent = `Encrypting ${transactions.length} transactions in your browser\u2026`;
  await new Promise((r) => setTimeout(r, 30));

  const prior = new Map(TXNS.map((t) => [t.id, t]));
  const editable = ['merchant', 'category', 'notes', 'tags', 'splits', 'is_transfer', 'excluded'];
  const sealedRows = transactions.map((t) => ({
    blind_index: blindIndex(t.id),
    sealed: seal(editable.reduce((merged, key) => {
      if (prior.has(t.id) && Object.hasOwn(prior.get(t.id), key)) merged[key] = prior.get(t.id)[key];
      return merged;
    }, { ...t })),
  }));

  await api('/api/records', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ records: sealedRows }),
  });

  $('connectNote').textContent = '';
  $('connectBtn').disabled = false;
  $('syncBtn').disabled = false;
  await load();
}

/* ---------- aggregates ---------- */

function monthly() {
  const m = new Map();
  for (const t of TXNS) {
    if (!reportable(t)) continue;
    const k = t.date.slice(0, 7);
    if (!m.has(k)) m.set(k, { in: 0, out: 0 });
    if (t.amount < 0) m.get(k).in -= t.amount; else m.get(k).out += t.amount;
  }
  return [...m.entries()].sort();
}

function byCategory() {
  const m = new Map();
  for (const t of TXNS) {
    if (!reportable(t) || t.amount <= 0) continue;
    const parts = t.splits.length ? t.splits : [{ category: t.category, amount: t.amount }];
    for (const part of parts) m.set(part.category, (m.get(part.category) || 0) + part.amount);
  }
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}

function runningBalance() {
  let bal = 0;
  const byDay = new Map();
  for (const t of TXNS) { if (t.excluded) continue; bal -= t.amount; byDay.set(t.date, bal); }
  return [...byDay.entries()];
}

function topMerchants(n = 8) {
  const m = new Map();
  for (const t of TXNS) {
    if (!reportable(t) || t.amount <= 0) continue;
    if (!m.has(t.merchant)) m.set(t.merchant, { n: 0, sum: 0 });
    const e = m.get(t.merchant); e.n++; e.sum += t.amount;
  }
  return [...m.entries()].sort((a, b) => b[1].n - a[1].n).slice(0, n);
}

const reportable = (t) => !t.excluded && !t.is_transfer;

// Bank details exist only inside decrypted records. Net flows are derived
// here from encrypted amounts and are never sent to or stored by the server.
function accountGroups() {
  const groups = new Map();
  for (const txn of TXNS) {
    if (!groups.has(txn.account)) groups.set(txn.account, []);
    groups.get(txn.account).push(txn);
  }
  return groups;
}

const accountMeta = (id, rows) => {
  const txn = rows[0] || {};
  return { bank: txn.bank || id, label: txn.account_label || 'Encrypted account', type: txn.account_type || 'Account' };
};

function renderAccounts() {
  const groups = accountGroups();
  $('accounts').hidden = false;
  $('accountList').innerHTML = [...groups.entries()].map(([id, rows]) => {
    const meta = accountMeta(id, rows);
    const net = rows.filter(reportable).reduce((sum, t) => sum - t.amount, 0);
    return `<div class="accountItem">
      <div class="accountBank">${meta.bank}</div>
      <div class="accountLabel">${meta.type} · ${meta.label}<span>${rows.length} records</span></div>
      <div class="accountFlow">Net flow ${money(net, true)}</div>
    </div>`;
  }).join('');

  const totalVisible = [...groups.values()].reduce((sum, rows) => sum + rows.filter(reportable).reduce((inner, t) => inner + (t.amount < 0 ? -t.amount : 0), 0), 0);
  $('dashboardAccounts').innerHTML = [...groups.entries()].map(([id, rows]) => {
    const meta = accountMeta(id, rows);
    const contributions = rows.filter(reportable).reduce((sum, t) => sum + (t.amount < 0 ? -t.amount : 0), 0);
    const net = rows.filter(reportable).reduce((sum, t) => sum - t.amount, 0);
    const retirement = meta.type !== 'Checking';
    const amount = retirement ? contributions : net;
    const amountLabel = retirement ? 'Contributed' : 'Net flow';
    const width = totalVisible ? Math.max(5, Math.round((contributions / totalVisible) * 100)) : 5;
    return `<article class="accountCard ${retirement ? 'retirement' : 'checking'}">
      <div class="accountCardTop"><span class="accountCardType">${meta.type}</span><span class="accountCardBadge">${rows.length} records</span></div>
      <div class="accountCardBank">${meta.bank}</div>
      <div class="accountCardLabel">${meta.label}</div>
      <div class="accountCardAmount"><small>${amountLabel}</small>${money(amount, true)}</div>
      <div class="accountCardMeta">${retirement ? 'Retirement contributions' : 'Everyday account movement'}</div>
      <progress class="accountBar" aria-label="${width}% of deposits" max="100" value="${width}"></progress>
    </article>`;
  }).join('');
}

/* ---------- private local assistant -----------------------------------
   This deliberately uses the decrypted TXNS array in this page only. It is
   a small private assistant rather than a remote LLM: no chat text,
   merchant name, amount or date is sent anywhere.                           */

const localCurrentMonth = () => new Date().toISOString().slice(0, 7);
const localMonthLabel = (ym) => new Date(ym + '-01').toLocaleString('en-US', { month: 'long', year: 'numeric' });
const localMonthRows = (ym) => TXNS.filter((t) => t.date.slice(0, 7) === ym);
const localTotals = (rows) => rows.reduce((a, t) => {
  if (!reportable(t)) return a;
  if (t.amount < 0) a.in -= t.amount; else a.out += t.amount;
  return a;
}, { in: 0, out: 0 });
const localCompleteMonths = () => monthly().filter(([k]) => k !== localCurrentMonth());
const localShare = (amount, total) => total ? Math.round((amount / total) * 100) : 0;

function localMonthReport(key, phrase) {
  const totals = localTotals(localMonthRows(key));
  const net = totals.in - totals.out;
  return `${phrase || localMonthLabel(key)}: income ${money(totals.in)}, spending ${money(totals.out)}, net ${money(net, true)}. ` +
    (net >= 0 ? 'The math behaved for once.' : 'Spending won this round.');
}

function localSummary() {
  const totals = localTotals(TXNS);
  const net = totals.in - totals.out;
  const months = monthly();
  const cats = byCategory();
  const frequent = topMerchants(1)[0];
  const latest = localCompleteMonths().slice(-1)[0] || months.slice(-1)[0];
  const accountCount = new Set(TXNS.map((t) => t.account)).size;
  const pieces = [
    `Across ${months.length} months, ${TXNS.length} transactions, and ${accountCount} accounts, income was ${money(totals.in)} and spending was ${money(totals.out)}.`,
    `Net cash flow was ${money(net, true)} — ${net >= 0 ? 'a respectable escape from the red.' : 'the red carpet has been rolled out for spending.'}`,
  ];
  if (cats.length) {
    const share = localShare(cats[0][1], totals.out);
    pieces.push(`Your largest spending category was ${cats[0][0]} at ${money(cats[0][1])} (${share}% of spending) — ${share >= 40 ? 'spectacularly over the top.' : 'the largest slice, though not exactly subtle.'}`);
  }
  if (frequent) pieces.push(`Your most frequent merchant was ${frequent[0]} with ${frequent[1].n} visits — an eccentric little recurring character.`);
  if (latest) pieces.push(localMonthReport(latest[0], `For ${localMonthLabel(latest[0])}`));
  return pieces.join(' ');
}

function localAccountReport() {
  const groups = accountGroups();
  return 'Accounts — three banks, three distinct financial personalities:\n' + [...groups.entries()].map(([id, rows]) => {
    const meta = accountMeta(id, rows);
    const net = rows.filter(reportable).reduce((sum, t) => sum - t.amount, 0);
    return `${meta.type} at ${meta.bank} — ${rows.length} records, net flow ${money(net, true)}`;
  }).join('\n');
}

let CHAT_CHART_INDEX = 0;
const CHAT_CHARTS = {};
let LAST_ATTITUDE = -1;

const CHAT_ATTITUDE = [
  'I did the arithmetic. You supplied the plot twist.',
  'The numbers are being more honest with you than you have been with them.',
  'I can explain the result; making it look innocent is outside my mandate.',
  'Consider this the receipt your optimism conveniently misplaced.',
  'No judgment. Fine, a measured amount of judgment.',
  'The spreadsheet has declined to participate in your denial.',
  'You asked for insight. Unfortunately, the transactions kept evidence.',
  'I remain on your side, though your spending has mounted a persuasive counterargument.',
];

function chatAttitude(question) {
  const q = question.toLowerCase();
  const contextual = q.includes('spend') || q.includes('expense')
    ? ['Your wallet would like to be included in future decision-making.', 'Bold spending strategy. The numbers have filed a dissent.']
    : q.includes('income') || q.includes('pay')
      ? ['Income arrived heroically; what happened afterward was less distinguished.']
      : q.includes('chart') || q.includes('graph')
        ? ['I made it visual in case the digits were too subtle.']
        : [];
  const choices = CHAT_ATTITUDE.concat(contextual);
  const random = new Uint32Array(1);
  crypto.getRandomValues(random);
  let index = random[0] % choices.length;
  if (choices.length > 1 && index === LAST_ATTITUDE) index = (index + 1) % choices.length;
  LAST_ATTITUDE = index;
  return choices[index];
}

function localMathReport() {
  const expenses = TXNS.filter((t) => reportable(t) && t.amount > 0).map((t) => t.amount).sort((a, b) => a - b);
  const totals = localTotals(TXNS);
  const mean = expenses.length ? totals.out / expenses.length : 0;
  const middle = Math.floor(expenses.length / 2);
  const median = expenses.length ? (expenses.length % 2 ? expenses[middle] : (expenses[middle - 1] + expenses[middle]) / 2) : 0;
  const largest = expenses.at(-1) || 0;
  const cats = byCategory();
  const top = cats[0];
  const share = top ? localShare(top[1], totals.out) : 0;
  return `Mathematical analysis: ${expenses.length} expenses totaling ${money(totals.out)}. ` +
    `Average charge ${money(mean)}; median charge ${money(median)}; largest charge ${money(largest)}. ` +
    (top ? `${top[0]} accounts for ${share}% of spending.` : 'No spending categories found.') +
    ' The arithmetic is sound; the spending choices remain under review.';
}

function localGraphicAnswer(question) {
  const q = question.toLowerCase();
  const id = `chatChart${++CHAT_CHART_INDEX}`;
  const chartBase = {
    responsive: true,
    maintainAspectRatio: false,
    animation: { duration: 350 },
    plugins: { legend: { display: false } },
  };

  if (q.includes('category') || q.includes('where') || q.includes('goes')) {
    const data = byCategory().slice(0, 8);
    return {
      text: 'A spending-by-category chart, because apparently the budget wanted a pie chart before admitting what happened.',
      chart: {
        id,
        config: {
          type: 'doughnut',
          data: {
            labels: data.map(([name]) => name),
            datasets: [{ data: data.map(([, amount]) => amount), backgroundColor: data.map(([name]) => CAT_COLOR[name] || '#74879a'), borderWidth: 2, borderColor: '#fff' }],
          },
          options: { ...chartBase, cutout: '56%', plugins: { legend: { display: true, position: 'right', labels: { color: TICK, font: { size: 11 }, boxWidth: 10 } }, tooltip: { callbacks: { label: (c) => ` ${c.label}: ${money(c.raw)}` } } } },
        },
      },
    };
  }

  if (q.includes('account') || q.includes('bank') || q.includes('ira') || q.includes('401') || q.includes('retirement') || q.includes('contribution')) {
    const data = [...accountGroups().entries()].map(([id, rows]) => {
      const meta = accountMeta(id, rows);
      const reportRows = rows.filter(reportable);
      const total = meta.type === 'Checking'
        ? reportRows.reduce((sum, t) => sum - t.amount, 0)
        : reportRows.reduce((sum, t) => sum + (t.amount < 0 ? -t.amount : 0), 0);
      return { label: `${meta.type} · ${meta.bank}`, total };
    });
    return {
      text: 'Account flows, rendered locally. Retirement gets the contribution spotlight; checking gets the net-flow reality check.',
      chart: {
        id,
        config: {
          type: 'bar',
          data: { labels: data.map((item) => item.label), datasets: [{ data: data.map((item) => item.total), backgroundColor: ['#2e6c91', '#8a5b31', '#8a5b31'], borderRadius: 4 }] },
          options: {
            ...chartBase,
            indexAxis: 'y',
            scales: {
              x: axis({ ticks: { color: TICK, callback: (v) => '$' + (v / 1000).toFixed(1) + 'k' } }),
              y: axis({ grid: { display: false } }),
            },
            plugins: { tooltip: { callbacks: { label: (c) => ` ${money(c.raw)}` } } },
          },
        },
      },
    };
  }

  const rows = monthly();
  const spendingOnly = q.includes('spending') && !q.includes('income') && !q.includes('cash flow');
  const incomeOnly = q.includes('income') && !q.includes('spending');
  const datasets = [];
  if (!spendingOnly) datasets.push({ label: 'Income', data: rows.map(([, values]) => values.in), backgroundColor: '#18784e', borderRadius: 3 });
  if (!incomeOnly) datasets.push({ label: 'Spending', data: rows.map(([, values]) => values.out), backgroundColor: '#ae3c42', borderRadius: 3 });
  return {
    text: 'Monthly cash flow, rendered locally. The bars are factual; the financial decisions remain gloriously eccentric.',
    chart: {
      id,
      config: {
        type: 'bar',
        data: { labels: rows.map(([key]) => monthName(key)), datasets },
        options: {
          ...chartBase,
          plugins: { legend: { display: datasets.length > 1, position: 'bottom', labels: { color: TICK, font: { size: 11 }, boxWidth: 10 } }, tooltip: { callbacks: { label: (c) => ` ${c.dataset.label}: ${money(c.raw)}` } } },
          scales: { x: axis({ grid: { display: false } }), y: axis({ ticks: { callback: (v) => '$' + (v / 1000).toFixed(1) + 'k' } }) },
        },
      },
    },
  };
}

function localAssistantAnswer(question) {
  const q = question.toLowerCase().trim();
  if (!TXNS.length) return 'Your vault has no decrypted transactions yet. Connect the demo bank first.';
  if (/^(hi|hello|hey|thanks|thank you)\b/.test(q)) {
    return 'Hello. I can summarize spending, income, categories, merchants, monthly patterns, and net cash flow. I bring arithmetic, opinions, and absolutely no chill. Everything stays in this browser.';
  }
  if (q.includes('help') || q.includes('what can')) {
    return 'Try “give me a summary,” “where did most of my money go?”, “how much did I spend last month?”, “what was my income?”, or “who are my most frequent merchants?” I have numbers, not clairvoyance.';
  }
  if (/(chart|graph|plot|visuali[sz]|trend|doughnut|bar graph)/.test(q)) {
    return localGraphicAnswer(question);
  }
  if (q.includes('math') || q.includes('average') || q.includes('mean') || q.includes('median') || q.includes('calculate') || q.includes('percentage')) {
    return localMathReport();
  }
  if (q.includes('account') || q.includes('bank') || q.includes('ira') || q.includes('401')) {
    return localAccountReport();
  }
  if (q.includes('summary') || q.includes('summarize') || q.includes('overview') || q.includes('how am i doing')) {
    return localSummary();
  }
  if (q.includes('top') || q.includes('frequent') || q.includes('merchant')) {
    const tops = topMerchants(5);
    return 'Most frequent merchants — an eccentric little cast of characters:\n' + tops.map(([name, v], i) => `${i + 1}. ${name} — ${v.n} visits, ${money(v.sum)} total`).join('\n');
  }

  const merchantNames = [...new Set(TXNS.map((t) => t.merchant))].sort((a, b) => b.length - a.length);
  const merchant = merchantNames.find((name) => q.includes(name.toLowerCase()));
  if (merchant) {
    let rows = TXNS.filter((t) => reportable(t) && t.merchant === merchant && t.amount > 0);
    let period = 'all available data';
    if (q.includes('last month')) {
      const complete = localCompleteMonths();
      if (complete.length) { rows = rows.filter((t) => t.date.startsWith(complete.at(-1)[0])); period = localMonthLabel(complete.at(-1)[0]); }
    } else if (q.includes('this month')) {
      rows = rows.filter((t) => t.date.startsWith(localCurrentMonth()));
      period = localMonthLabel(localCurrentMonth());
    }
    return `${merchant}: ${money(rows.reduce((sum, t) => sum + t.amount, 0))} across ${rows.length} charge${rows.length === 1 ? '' : 's'} in ${period}. A factual report, not an intervention.`;
  }

  const category = Object.keys(CAT_COLOR).find((name) => q.includes(name.toLowerCase()));
  if (category && q.includes('spend')) {
    const rows = TXNS.filter((t) => reportable(t) && t.category === category && t.amount > 0);
    const amount = rows.reduce((sum, t) => sum + t.amount, 0);
    const share = localShare(amount, localTotals(TXNS).out);
    return `${category}: ${money(amount)} across ${rows.length} transaction${rows.length === 1 ? '' : 's'} (${share}% of spending). ${share >= 40 ? 'That is objectively over the top.' : 'Not a scandal, merely the largest available slice.'}`;
  }
  if (q.includes('category') || q.includes('where') || q.includes('goes') || q.includes('went')) {
    const cats = byCategory().slice(0, 5);
    return 'Spending by category — the fiscal personality test:\n' + cats.map(([name, amount], i) => `${i + 1}. ${name} — ${money(amount)}`).join('\n');
  }
  if (q.includes('last month')) {
    const complete = localCompleteMonths();
    return complete.length ? localMonthReport(complete.at(-1)[0], `Last month (${localMonthLabel(complete.at(-1)[0])})`) : 'There is no complete month in the available data yet.';
  }
  if (q.includes('this month')) return localMonthReport(localCurrentMonth(), `This month (${localMonthLabel(localCurrentMonth())})`);
  if (q.includes('month') || q.includes('monthly')) {
    return monthly().map(([key, values]) => `${localMonthLabel(key)} — income ${money(values.in)}, spending ${money(values.out)}, net ${money(values.in - values.out, true)}`).join('\n');
  }
  if (q.includes('income') || q.includes('earned') || q.includes('pay')) {
    const income = localTotals(TXNS).in;
    return `Income across the available data was ${money(income)} from ${TXNS.filter((t) => reportable(t) && t.amount < 0).length} income transactions. Good: money arrived. The eccentric part is how quickly it found somewhere else to be.`;
  }
  if (q.includes('balance') || q.includes('net cash') || q.includes('cash flow')) {
    const totals = localTotals(TXNS);
    const net = totals.in - totals.out;
    return `Net cash flow across the available data was ${money(net, true)}: ${money(totals.in)} in and ${money(totals.out)} out. ${net >= 0 ? 'Miraculously, the inflow won.' : 'Spending remains undefeated.'}`;
  }
  if (q.includes('largest') || q.includes('biggest') || q.includes('expensive')) {
    const largest = TXNS.filter((t) => reportable(t) && t.amount > 0).sort((a, b) => b.amount - a.amount)[0];
    return largest ? `The largest single expense was ${money(largest.amount)} at ${largest.merchant} on ${largest.date}. Over the top? Possibly. Confirmed by the arithmetic? Absolutely.` : 'There are no expenses in the available data.';
  }
  if (q.includes('recent')) {
    return 'Recent activity — the latest evidence:\n' + TXNS.filter(reportable).slice(-5).reverse().map((t) => `${t.date} — ${t.merchant}, ${t.amount < 0 ? 'income ' + money(-t.amount) : 'spent ' + money(t.amount)}`).join('\n');
  }
  return 'I can answer questions about your summary, spending, income, categories, merchants, monthly patterns, largest expenses, and net cash flow. Try asking for a summary. I promise to be accurate and only mildly judgmental.';
}

function appendChatMessage(role, text) {
  const bubble = document.createElement('div');
  bubble.className = `chatBubble ${role}`;
  bubble.textContent = text;
  const chart = arguments[2];
  if (chart) {
    bubble.classList.add('hasChart');
    const graph = document.createElement('div');
    graph.className = 'chatGraph';
    const canvas = document.createElement('canvas');
    canvas.id = chart.id;
    canvas.setAttribute('aria-label', 'Locally generated financial chart');
    graph.appendChild(canvas);
    bubble.appendChild(graph);
  }
  $('chatMessages').appendChild(bubble);
  if (chart) CHAT_CHARTS[chart.id] = new Chart($(chart.id), chart.config);
  $('chatMessages').scrollTop = $('chatMessages').scrollHeight;
}

function askChat() {
  const input = $('chatInput');
  const question = input.value.trim();
  if (!question) return;
  appendChatMessage('user', question);
  input.value = '';
  const answer = localAssistantAnswer(question);
  const text = typeof answer === 'string' ? answer : answer.text;
  appendChatMessage('bot', `${text}\n\n${chatAttitude(question)}`, typeof answer === 'string' ? null : answer.chart);
  input.focus();
}

function initChat() {
  $('chatSend').addEventListener('click', askChat);
  $('chatInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') askChat(); });
  document.querySelectorAll('[data-prompt]').forEach((button) => {
    button.addEventListener('click', () => {
      $('chatInput').value = button.dataset.prompt;
      askChat();
    });
  });
}

/* ---------- encrypted transaction editor ------------------------------ */

function openTransactionEditor(id) {
  const txn = TXNS.find((t) => t.id === id);
  if (!txn) return;
  EDITING_TRANSACTION_ID = id;
  $('editMerchant').value = txn.merchant;
  $('editCategory').value = txn.category;
  $('editNotes').value = txn.notes;
  $('editTags').value = txn.tags.join(', ');
  $('editTransfer').checked = txn.is_transfer;
  $('editExcluded').checked = txn.excluded;
  $('editSplits').value = txn.splits.map((part) => `${part.category}: ${part.amount.toFixed(2)}`).join('\n');
  $('editSplitHint').textContent = txn.amount > 0
    ? `Optional. One “Category: amount” per line; entries must total ${money(txn.amount)}.`
    : 'Splits are available for spending transactions only.';
  $('editSplits').disabled = txn.amount <= 0;
  $('editError').textContent = '';
  $('transactionEditor').showModal();
}

function parseSplits(value, amount) {
  if (!value.trim()) return [];
  if (amount <= 0) throw new Error('Income transactions cannot be split.');
  const splits = value.split('\n').filter((line) => line.trim()).map((line) => {
    const match = line.match(/^(.{1,50}):\s*(\d+(?:\.\d{1,2})?)$/);
    if (!match) throw new Error(`Invalid split: “${line.trim()}”. Use Category: amount.`);
    return { category: match[1].trim(), amount: Number(match[2]) };
  });
  const total = splits.reduce((sum, part) => sum + part.amount, 0);
  if (splits.some((part) => part.amount <= 0) || Math.abs(total - amount) > 0.005) {
    throw new Error(`Split amounts must be positive and total ${money(amount)}.`);
  }
  return splits;
}

async function saveTransactionEdit(event) {
  event.preventDefault();
  const txn = TXNS.find((t) => t.id === EDITING_TRANSACTION_ID);
  if (!txn) return;
  const error = $('editError');
  try {
    const merchant = $('editMerchant').value.trim();
    if (!merchant || merchant.length > 120) throw new Error('Merchant must be between 1 and 120 characters.');
    const notes = $('editNotes').value.trim();
    if (notes.length > 1000) throw new Error('Notes cannot exceed 1,000 characters.');
    const tags = [...new Set($('editTags').value.split(',').map((tag) => tag.trim()).filter(Boolean))];
    if (tags.length > 10 || tags.some((tag) => tag.length > 40)) throw new Error('Use at most 10 tags, each 40 characters or fewer.');
    const updated = {
      ...txn, merchant, category: $('editCategory').value, notes, tags,
      splits: parseSplits($('editSplits').value, txn.amount),
      is_transfer: $('editTransfer').checked, excluded: $('editExcluded').checked,
    };
    await api('/api/records', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ records: [{ blind_index: blindIndex(updated.id), sealed: seal(updated) }] }),
    });
    TXNS[TXNS.findIndex((t) => t.id === updated.id)] = updated;
    $('transactionEditor').close();
    renderAccounts();
    render();
  } catch (failure) {
    error.textContent = failure.message;
  }
}

/* ---------- charts ---------- */

const GRID = '#e2e9ed', TICK = '#74879a';
const baseOpts = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  animation: { duration: 380 },
};
const axis = (extra = {}) => ({
  grid: { color: GRID, drawTicks: false },
  border: { display: false },
  ticks: { color: TICK, font: { size: 11 }, padding: 8 },
  ...extra,
});

function draw(id, cfg) {
  CHARTS[id]?.destroy();
  CHARTS[id] = new Chart($(id), cfg);
}

function render() {
  const months = monthly();
  const cats = byCategory();
  const bal = runningBalance();
  const tops = topMerchants();

  // Headline uses the last COMPLETE month. The current month is partial by
  // definition -- on the 2nd it has rent but no paycheck, which would render
  // as an alarming loss in the largest number on the page.
  const currentKey = new Date().toISOString().slice(0, 7);
  const complete = months.filter(([k]) => k !== currentKey);
  const [lastKey, last] = (complete.length ? complete : months).slice(-1)[0];
  const net = last.in - last.out;
  $('periodLabel').textContent =
    new Date(lastKey + '-01').toLocaleString('en-US', { month: 'long', year: 'numeric' });
  $('figureNet').textContent = money(net, true);
  $('figureNet').className = 'figure ' + (net < 0 ? 'debit' : 'credit');
  $('figureSub').textContent = net < 0
    ? 'Spending outpaced income this month.'
    : 'Income covered spending this month.';
  $('figureIn').textContent = money(last.in);
  $('figureOut').textContent = money(last.out);

  draw('chMonthly', {
    type: 'bar',
    data: {
      labels: months.map(([k]) => monthName(k)),
      datasets: [
        { label: 'In',  data: months.map(([, v]) => v.in),  backgroundColor: '#1f6b54', borderRadius: 2 },
        { label: 'Out', data: months.map(([, v]) => v.out), backgroundColor: '#9e3b3b', borderRadius: 2 },
      ],
    },
    options: {
      ...baseOpts,
      plugins: { legend: { display: true, position: 'bottom', labels: { boxWidth: 10, boxHeight: 10, color: TICK, font: { size: 11 } } } },
      scales: { x: axis({ grid: { display: false } }), y: axis({ ticks: { color: TICK, font: { size: 11 }, padding: 8, callback: (v) => '$' + (v / 1000) + 'k' } }) },
    },
  });

  draw('chCategory', {
    type: 'doughnut',
    data: {
      labels: cats.map(([c]) => c),
      datasets: [{
        data: cats.map(([, v]) => v),
        backgroundColor: cats.map(([c]) => CAT_COLOR[c] || '#74879a'),
        borderWidth: 2, borderColor: '#fff',
      }],
    },
    options: {
      ...baseOpts,
      cutout: '58%',
      plugins: {
        legend: { display: true, position: 'right', labels: { boxWidth: 9, boxHeight: 9, color: TICK, font: { size: 11 }, padding: 9 } },
        tooltip: { callbacks: { label: (c) => ` ${c.label}  ${money(c.raw)}` } },
      },
    },
  });

  draw('chBalance', {
    type: 'line',
    data: {
      labels: bal.map(([d]) => d),
      datasets: [{
        data: bal.map(([, v]) => v),
        borderColor: '#2e4b6b', borderWidth: 1.5,
        backgroundColor: 'rgba(46,75,107,.08)', fill: true,
        pointRadius: 0, tension: .25,
      }],
    },
    options: {
      ...baseOpts,
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ' ' + money(c.raw, true) } } },
      scales: {
        x: axis({ grid: { display: false }, ticks: { color: TICK, font: { size: 11 }, maxTicksLimit: 6, callback(v) { return monthName(this.getLabelForValue(v).slice(0, 7)); } } }),
        y: axis({ ticks: { color: TICK, font: { size: 11 }, padding: 8, callback: (v) => '$' + (v / 1000).toFixed(0) + 'k' } }),
      },
    },
  });

  draw('chMerchants', {
    type: 'bar',
    data: {
      labels: tops.map(([m]) => m),
      datasets: [{
        data: tops.map(([, v]) => v.n),
        backgroundColor: '#3d5162', borderRadius: 2, barThickness: 16,
      }],
    },
    options: {
      ...baseOpts,
      indexAxis: 'y',
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (c) => ` ${c.raw} visits \u00b7 ${money(tops[c.dataIndex][1].sum)} total` } } },
      scales: { x: axis({ ticks: { color: TICK, font: { size: 11 }, precision: 0 } }), y: axis({ grid: { display: false }, ticks: { color: '#3d5162', font: { size: 12 } } }) },
    },
  });

  $('ledgerBody').innerHTML = TXNS.slice(-14).reverse().map((t) => {
    const state = [t.is_transfer ? 'Transfer' : '', t.excluded ? 'Excluded' : '', t.splits.length ? `${t.splits.length} splits` : '', t.tags.length ? t.tags.join(', ') : ''].filter(Boolean).join(' · ');
    const category = t.splits.length ? `Split (${t.splits.length})` : t.category;
    return `
    <tr class="${t.excluded ? 'excludedRow' : ''}">
      <td class="date">${t.date}</td>
      <td title="${escapeHtml(t.notes)}">${escapeHtml(t.merchant)}${state ? `<span class="transactionState">${escapeHtml(state)}</span>` : ''}</td>
      <td><span class="tag cat-${category.toLowerCase().replace(/[^a-z]+/g, '-')}">${escapeHtml(category)}</span></td>
      <td class="num ${t.amount < 0 ? 'credit' : ''}">${t.amount < 0 ? money(-t.amount) : '\u2212' + money(t.amount)}</td>
      <td><button class="editTransaction" data-edit-transaction="${escapeHtml(t.id)}">Edit</button></td>
    </tr>`;
  }).join('');
  $('ledgerBody').querySelectorAll('[data-edit-transaction]').forEach((button) => {
    button.addEventListener('click', () => openTransactionEditor(button.dataset.editTransaction));
  });
}

/* ---------- server view ---------- */

async function renderServerView() {
  const d = await api('/api/server-view');

  $('svFigure').textContent = `${d.record_count} rows \u00d7 ${d.columns.length} columns`;
  $('statReadable').textContent = '0';

  draw('chSizes', {
    type: 'bar',
    data: {
      labels: d.size_histogram.map((s) => s.bytes + 'B'),
      datasets: [{ data: d.size_histogram.map((s) => s.n), backgroundColor: '#2b6c9b', borderRadius: 2 }],
    },
    options: { ...baseOpts, scales: { x: axis({ grid: { display: false } }), y: axis() } },
  });

  draw('chDays', {
    type: 'bar',
    data: {
      labels: d.write_days.map((w) => w.d.slice(5, 10)),
      datasets: [{ data: d.write_days.map((w) => w.n), backgroundColor: '#4a6572', borderRadius: 2 }],
    },
    options: { ...baseOpts, scales: { x: axis({ grid: { display: false } }), y: axis() } },
  });

  $('rawBody').innerHTML = d.sample.map((r) => `
    <tr><td>${r.blind_index.slice(0, 24)}\u2026</td><td>${r.sealed.slice(0, 96)}\u2026</td></tr>
  `).join('');
}

function toggleView() {
  const on = !document.body.classList.contains('sv');
  document.body.classList.toggle('sv', on);
  $('dash').hidden = on;
  $('serverview').hidden = !on;
  if (on) renderServerView();
  window.scrollTo({ top: 0, behavior: 'instant' });
}

async function reset() {
  if (!confirm('Clear every encrypted transaction from this vault? This cannot be undone.')) return;
  await api('/api/records', { method: 'DELETE' });
  location.reload();
}

async function resetPassphrase() {
  if (!confirm('Resetting the vault passphrase permanently erases all encrypted financial records because the old key cannot be recovered. Continue?')) return;
  const note = $('gateNote');
  $('resetPassphraseBtn').disabled = true;
  try {
    await api('/api/records', { method: 'DELETE' });
    KEYS = null; TXNS = [];
    $('pass').value = '';
    updatePassphraseEntropy();
    $('gate').querySelector('h1').textContent = 'Set a new passphrase';
    note.textContent = 'Vault data erased. Enter a new passphrase, unlock, then reconnect the demo banks.';
    $('pass').focus();
  } catch (error) {
    note.textContent = error.message;
  } finally {
    $('resetPassphraseBtn').disabled = false;
  }
}

/* ---------- optional passkeys ---------- */

function webauthnMessage(error) {
  if (!window.PublicKeyCredential) return 'This browser does not support WebAuthn passkeys.';
  if (error?.name === 'NotAllowedError') return 'The passkey ceremony was cancelled or timed out.';
  return error?.message || 'The passkey operation failed.';
}

async function registerPasskey() {
  const note = $('securityNote');
  try {
    if (!window.PublicKeyCredential) throw new Error('This browser does not support WebAuthn passkeys.');
    note.textContent = 'Waiting for your authenticator…';
    const options = await api('/api/passkeys/register/options', { method: 'POST' });
    const credential = await navigator.credentials.create({ publicKey: publicKeyOptions(options) });
    const result = await api('/api/passkeys/register/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ credential: credentialJSON(credential), label: $('passkeyLabel').value || 'Passkey' }) });
    if (result.verified) { PASSKEY_REQUIRED = true; PASSKEY_AUTHENTICATED = true; await refreshSecurity(); note.textContent = 'Passkey protection is enabled. Future access requires your passkey and then your passphrase.'; }
  } catch (error) { note.textContent = webauthnMessage(error); }
}

async function loginPasskey() {
  const note = $('passkeyGateNote');
  try {
    note.textContent = 'Waiting for your authenticator…';
    const options = await api('/api/passkeys/login/options', { method: 'POST' });
    const credential = await navigator.credentials.get({ publicKey: publicKeyOptions(options) });
    const result = await api('/api/passkeys/login/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ credential: credentialJSON(credential) }) });
    CSRF = result.csrf_token; PASSKEY_AUTHENTICATED = true;
    $('passkeyGate').hidden = true; $('gate').hidden = false; $('gate').querySelector('h1').textContent = 'Unlock vault with passphrase';
    $('gateNote').textContent = 'Passkey accepted. Your passphrase now decrypts the vault locally.';
  } catch (error) { note.textContent = webauthnMessage(error); }
}

async function refreshSecurity() {
  $('passkeyState').textContent = PASSKEY_REQUIRED ? 'Enabled' : 'Not enabled';
  $('enablePasskeyBtn').hidden = PASSKEY_REQUIRED;
  $('addPasskeyBtn').hidden = !PASSKEY_REQUIRED;
  $('disablePasskeyBtn').hidden = !PASSKEY_REQUIRED;
  $('signOutBtn').hidden = !PASSKEY_REQUIRED;
  if (!PASSKEY_REQUIRED) { $('passkeyList').innerHTML = ''; return; }
  const { passkeys } = await api('/api/passkeys');
  $('passkeyList').innerHTML = passkeys.map((p) => `<div class="passkeyItem"><span>${escapeHtml(p.label)}${p.backed_up ? ' · backed up' : ''}</span><button data-rename="${p.credential_id}">Rename</button><button data-remove="${p.credential_id}">Remove</button></div>`).join('');
  $('passkeyList').querySelectorAll('[data-rename]').forEach((button) => button.onclick = async () => { const label = prompt('New passkey label'); if (label) { await api(`/api/passkeys/${button.dataset.rename}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label }) }); await refreshSecurity(); } });
  $('passkeyList').querySelectorAll('[data-remove]').forEach((button) => button.onclick = async () => { try { await api(`/api/passkeys/${button.dataset.remove}`, { method: 'DELETE' }); await refreshSecurity(); } catch (e) { $('securityNote').textContent = e.message; } });
}

function lockVault() {
  if (KEYS) { KEYS.privateKey?.fill(0); KEYS.indexKey?.fill(0); KEYS.publicKey?.fill(0); }
  KEYS = null; TXNS = [];
  Object.values(CHARTS).forEach((c) => c.destroy()); CHARTS = {};
  Object.values(CHAT_CHARTS).forEach((c) => c.destroy());
  $('ledgerBody').textContent = ''; $('accountList').textContent = ''; $('dashboardAccounts').textContent = ''; $('chatMessages').textContent = ''; $('rawBody').textContent = '';
  ['dash','empty','serverview','security','stats','accounts','syncBtn','resetBtn','viewToggle'].forEach((id) => $(id).hidden = true);
  document.body.classList.remove('sv'); $('pass').value = ''; updatePassphraseEntropy(); $('lock').dataset.state = 'locked'; $('lockLabel').textContent = 'Locked';
  $('unlockBtn').disabled = false;
  $('gate').hidden = false; $('gate').querySelector('h1').textContent = 'Unlock vault with passphrase';
}

async function signOut() {
  lockVault();
  await api('/api/logout', { method: 'POST' });
  CSRF = ''; PASSKEY_AUTHENTICATED = false;
  const s = await api('/api/session'); CSRF = s.csrf_token;
  $('gate').hidden = true; $('passkeyGate').hidden = false;
}

async function disablePasskeys() {
  if (!confirm('Disable passkey protection and return to passphrase-only access?')) return;
  try { await api('/api/passkeys/disable', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ confirm_unlocked: true }) }); PASSKEY_REQUIRED = false; PASSKEY_AUTHENTICATED = false; await refreshSecurity(); $('securityNote').textContent = 'Passkey protection disabled. Passphrase-only access is restored.'; } catch (e) { $('securityNote').textContent = e.message; }
}

/* ---------- boot ---------- */

(async () => {
  const sessionInfo = await api('/api/session'); CSRF = sessionInfo.csrf_token;
  const status = await api('/api/passkeys/status'); PASSKEY_REQUIRED = status.passkey_required; PASSKEY_AUTHENTICATED = status.authenticated;
  await sodium.ready;
  S = sodium;
  $('unlockBtn').addEventListener('click', unlock);
  $('pass').addEventListener('input', updatePassphraseEntropy);
  $('pass').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
  $('connectBtn').addEventListener('click', connect);
  $('syncBtn').addEventListener('click', connect);
  $('viewToggle').addEventListener('click', toggleView);
  $('resetBtn').addEventListener('click', reset);
  $('resetPassphraseBtn').addEventListener('click', resetPassphrase);
  $('passkeyLoginBtn').addEventListener('click', loginPasskey);
  $('enablePasskeyBtn').addEventListener('click', registerPasskey);
  $('addPasskeyBtn').addEventListener('click', registerPasskey);
  $('lockVaultBtn').addEventListener('click', lockVault);
  $('signOutBtn').addEventListener('click', signOut);
  $('disablePasskeyBtn').addEventListener('click', disablePasskeys);
  $('transactionEditForm').addEventListener('submit', saveTransactionEdit);
  $('editCancel').addEventListener('click', () => $('transactionEditor').close());
  $('editCancelX').addEventListener('click', () => $('transactionEditor').close());
  initChat();
  if (PASSKEY_REQUIRED && !PASSKEY_AUTHENTICATED) { $('gate').hidden = true; $('passkeyGate').hidden = false; }
  else $('gateNote').textContent = 'Deriving a key takes a moment \u2014 that slowness is deliberate.';
})();
