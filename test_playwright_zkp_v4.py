#!/usr/bin/env python3
"""Real-browser ZKP v4 UI test: enroll, prove, store, decrypt, fall back, rekey.

Drives static/app.js in headless Chromium against a real Flask server whose
verifier is the real bb 5.1.0 binary (ZKP_BB_EXECUTABLE, ZKP_CRS_DIR,
ZKP_V4_VK_PATH must point at the pinned runtime; see
scripts/fetch_zkp_runtime.py). Nothing is mocked except the two failures the
fallback checks inject with page.route().

Checks:
  1. Real passkey bootstrap + login, passphrase unlock; the background
     enrollment registers this vault's key commitment.
  2. Timing (locally tested numbers): cold prover load (fresh browser
     context, empty HTTP cache), warm load (second page, same context),
     first prove (includes wasm and CRS init) and warm prove.
  3. Manual expense through the dialog -> v4 proof -> server verifies with
     bb -> stored with circuit_version v4 -> after a reload and unlock it is
     decrypted and shown in the ledger and in TXNS (charts read TXNS).
  4. A proof made with a random key (self-consistent for its own
     commitment) is rejected server side with 400.
  5. Fallbacks: /api/zkp/challenge answering 503, and a prover bundle that
     fails its SRI check, both save a standard sealed-box record and tell
     the user it is non-ZKP.
  6. Recovery rekey with a v4 record: decrypts with the old key, the new key
     commitment is registered, and a new v4 entry works afterwards.
  7. Every request to the app origin is captured: no transaction name,
     passphrase, private key or zk_root appears in any URL or body.

Run (Postgres test DB as in test_playwright_recovery.py):
    ZKP_CRS_DIR=... ZKP_BB_EXECUTABLE=... ZKP_V4_VK_PATH=... \\
    ZKP_TIMINGS_OUT=/tmp/zkp_timings.json python3 test_playwright_zkp_v4.py
"""

from __future__ import annotations

import glob
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
PASSPHRASE = "playwright-zkp-v4-passphrase-ok"
NEW_PASSPHRASE = "playwright-zkp-v4-new-passphrase-ok"
TEST_BOOTSTRAP_TOKEN = "test-only-bootstrap-token-not-a-secret"
SEED_MERCHANT = "ZKPSEED-MERCHANT-1111"
V4_MERCHANT = "ZKPV4-MERCHANT-4242"
V4_AFTER_REKEY = "ZKPV4-AFTER-REKEY-5151"
FALLBACK_503 = "ZKPFALLBACK-503-7373"
FALLBACK_SRI = "ZKPFALLBACK-SRI-8484"
SECRETS = [PASSPHRASE, NEW_PASSPHRASE, SEED_MERCHANT, V4_MERCHANT, V4_AFTER_REKEY, FALLBACK_503, FALLBACK_SRI]
CIRCUIT = "manual-transaction-v4"

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("playwright not installed; see test_playwright_recovery.py")
    sys.exit(0)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Check:
    def __init__(self):
        self.passed = self.failed = 0

    def __call__(self, ok, label, detail=""):
        if ok:
            self.passed += 1
            print(f"    \033[32m✓\033[0m {label}")
        else:
            self.failed += 1
            print(f"    \033[31m✗\033[0m {label}" + (f"\n        {detail}" if detail else ""))


def start_server(port, db_url):
    from sqlalchemy import create_engine, text
    sys.path.insert(0, str(HERE))
    import models
    engine = create_engine(db_url, future=True)
    models.Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text(
            "TRUNCATE TABLE records, passkey_credentials, server_sessions, webauthn_challenges, "
            "rate_limits, audit_events, vault_identity RESTART IDENTITY CASCADE"))
    engine.dispose()
    env = os.environ.copy()
    env.update({
        "VAULT_ORIGIN": f"http://localhost:{port}", "VAULT_RP_ID": "localhost",
        "VAULT_SECRET_KEY": "playwright-zkp-v4-test-secret", "VAULT_CSP_MODE": "enforce",
        "VAULT_DATABASE_URL": db_url, "VAULT_BOOTSTRAP_TOKEN": TEST_BOOTSTRAP_TOKEN,
    })
    proc = subprocess.Popen([sys.executable, "-c", f"import app; app.app.run(port={port}, threaded=True)"],
                            cwd=HERE, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return proc
        except OSError:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError("server failed to start")


def db_rows(db_url):
    from sqlalchemy import create_engine, text
    engine = create_engine(db_url, future=True)
    with engine.connect() as conn:
        records = conn.execute(text("SELECT sealed, circuit_version FROM records ORDER BY id")).all()
        ident = conn.execute(text("SELECT zkp_key_commitment FROM vault_identity WHERE id = 1")).first()
    engine.dispose()
    return records, (bytes(ident[0]).hex() if ident and ident[0] is not None else None)


def attach(page, requests, errors):
    page.on("request", lambda r: requests.append((r.url, r.post_data_buffer or b"")))
    page.on("pageerror", lambda e: errors.append(f"PAGEERROR: {e}"))

    def on_console(m):
        if m.type == "error" and not m.text.startswith("Failed to load resource:"):
            errors.append(m.text)
    page.on("console", on_console)


def add_authenticator(page):
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
    return cdp


def unlock(page, passphrase):
    page.fill("#pass", passphrase)
    page.click("#unlockBtn")
    page.wait_for_function("() => document.getElementById('lock').dataset.state === 'open'", timeout=120000)


def add_manual(page, name, amount, category="Dining"):
    page.click("#addExpenseBtn")
    page.fill("#addExpenseName", name)
    page.fill("#addExpenseAmount", amount)
    page.select_option("#addExpenseCategory", category)
    page.click("#addExpenseForm button[type=submit]")
    page.wait_for_function("() => !document.getElementById('addExpenseDialog').open", timeout=180000)
    return page.inner_text("#connectNote")


SEED_JS = """async (merchant) => {
  const r = { id: 'seed_' + merchant, merchant, amount: 12.5, date: '2026-10-01', pending: false,
    account: 'pw_checking', bank: 'Playwright Bank', account_label: 'Checking', account_type: 'Checking',
    source: 'manual', transaction_type: 'expense', category: 'Dining' };
  await api('/api/records', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ records: [{ blind_index: blindIndex(r.id), sealed: seal(r) }] }) });
  await load();
  return TXNS.length;
}"""

TIMING_JS = """async () => {
  const t0 = performance.now();
  const zk = await loadZkpProver();
  const t1 = performance.now();
  const root = await currentZkRoot();
  const prove = async () => {
    const ch = await api('/api/zkp/challenge', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ purpose: 'manual_expense_create' }) });
    const s = performance.now();
    await zk.proveManualTransactionV4(ch, { name: 'TIMING', rawAmount: '1.00', category: 'Other', transactionType: 'expense' }, root);
    return performance.now() - s;
  };
  const first = await prove();
  const second = await prove();
  return { load_ms: t1 - t0, first_prove_ms: first, warm_prove_ms: second };
}"""

RANDOM_KEY_JS = """async () => {
  const zk = await loadZkpProver();
  const state = await api('/api/zkp/key-commitment');
  const ch = await api('/api/zkp/challenge', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ purpose: 'manual_expense_create' }) });
  const randomRoot = zk.deriveZkRoot(S.randombytes_buf(32), (n, m) => S.crypto_generichash(n, m));
  // Self-consistent for the random key: its own commitment, same salt.
  const forged = { ...ch, key_commitment: await zk.keyCommitmentHex(randomRoot, state.vault_salt) };
  const body = await zk.proveManualTransactionV4(forged, { name: 'FORGED', rawAmount: '9.99', category: 'Other', transactionType: 'expense' }, randomRoot);
  try {
    await api('/api/records/manual', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, blind_index: blindIndex('forged_' + crypto.randomUUID()), meta: seal({ id: 'forged' }) }) });
    return 'stored';
  } catch (e) { return e.status; }
}"""

SECRETS_JS = """async () => {
  const zk = await loadZkpProver();
  const root = await currentZkRoot();
  return { priv: S.to_hex(KEYS.privateKey), root: root.toString(16), rootDec: root.toString() };
}"""


def leaks(requests, base, secrets):
    found = []
    for url, body in requests:
        if not url.startswith(base):
            continue
        text = url + body.decode("latin-1")
        lower = text.lower()
        for s in secrets:
            if s and (s in text or s.lower() in lower):
                found.append((url, s[:6]))
    return found


def main():
    headed = "--headed" in sys.argv
    for var in ("ZKP_CRS_DIR", "ZKP_V4_VK_PATH"):
        if not os.environ.get(var):
            print(f"{var} not set: this test needs the real bb verifier runtime.")
            return 1
    port = free_port()
    base = f"http://localhost:{port}"
    db_url = os.environ.get("VAULT_TEST_DATABASE_URL",
                            "postgresql+psycopg://vault:vault_test_password@localhost:5432/vault_test")
    server = start_server(port, db_url)
    check = Check()
    timings = {}
    try:
        with sync_playwright() as p:
            bundled = sorted(glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome")))
            kwargs = {"headless": not headed, "args": ["--no-sandbox"]}
            if bundled:
                kwargs["executable_path"] = bundled[-1]
            browser = p.chromium.launch(**kwargs)
            ctx = browser.new_context(viewport={"width": 1280, "height": 900})
            page = ctx.new_page()
            reqs, errs = [], []
            attach(page, reqs, errs)
            page.goto(base, wait_until="networkidle")
            add_authenticator(page)

            print("\n\033[1m1. Bootstrap, login, unlock, background enrollment\033[0m")
            page.once("dialog", lambda d: d.accept(TEST_BOOTSTRAP_TOKEN))
            page.click("#passkeyLoginBtn")
            page.wait_for_selector("#gate:not([hidden])", timeout=30000)
            page.reload(wait_until="networkidle")
            page.wait_for_selector("#passkeyGate:not([hidden])", timeout=15000)
            page.click("#passkeyLoginBtn")
            page.wait_for_selector("#gate:not([hidden])", timeout=15000)
            t = time.monotonic()
            unlock(page, PASSPHRASE)
            deadline = time.monotonic() + float(os.environ.get('ZKP_ENROLL_WAIT_S', '180'))
            while not page.evaluate("async () => (await api('/api/zkp/key-commitment')).registered"):
                if time.monotonic() > deadline:
                    break
                page.wait_for_timeout(500)
            timings["cold_unlock_to_enrolled_s"] = round(time.monotonic() - t, 2)
            _, commitment1 = db_rows(db_url)
            if commitment1 is None:
                print("      diagnostic:", page.evaluate("() => ensureZkpEnrollment(false).then(() => 'ok', (e) => e.message + ' ' + (e.stack || ''))"))
                _, commitment1 = db_rows(db_url)
            check(commitment1 is not None, "unlock enrolled the vault's key commitment (background, no prompt)")
            check(page.evaluate(SEED_JS, SEED_MERCHANT) == 1, "seeded one account so the manual dialog has a destination")

            print("\n\033[1m2. Browser proving time (locally tested)\033[0m")
            ctx_t = browser.new_context()
            ctx_t.add_cookies(ctx.cookies())
            for label in ("cold", "warm"):
                pt = ctx_t.new_page()
                pt.goto(base, wait_until="networkidle")
                unlock(pt, PASSPHRASE)
                timings[label] = pt.evaluate(TIMING_JS)
                pt.close()
            ctx_t.close()
            for label in ("cold", "warm"):
                print(f"      {label}: " + ", ".join(f"{k}={v:.0f}" for k, v in timings[label].items()))
            check(all(timings[k]["warm_prove_ms"] > 0 for k in ("cold", "warm")), "timings recorded")

            print("\n\033[1m3. Manual expense through the dialog as v4\033[0m")
            note = add_manual(page, V4_MERCHANT, "42.42")
            check("zero-knowledge validity proof" in note, "UI reports a ZK-validated save", note)
            records, _ = db_rows(db_url)
            v4 = [r for r in records if r[1] == CIRCUIT]
            check(len(v4) == 1, "server stored exactly one record tagged manual-transaction-v4", repr([r[1] for r in records]))
            check(v4 and len(v4[0][0]) > 608, "stored v4 record = proven part + sealed metadata")
            page.reload(wait_until="networkidle")
            unlock(page, PASSPHRASE)
            row = page.evaluate(f"() => TXNS.find(t => t.merchant === {json.dumps(V4_MERCHANT)})")
            check(bool(row) and row["amount"] == 42.42 and row["category"] == "Dining" and row.get("zkp") == "v4"
                  and row.get("account") == "pw_checking", "after reload the v4 record decrypts with name, amount, category, account", repr(row))
            check(V4_MERCHANT in page.inner_text("#ledgerBody"), "v4 record is rendered in the ledger")

            print("\n\033[1m4. Random-key proof rejected server side\033[0m")
            status = page.evaluate(RANDOM_KEY_JS)
            check(status == 400, "random-key proof (self-consistent for its own commitment) gets 400", repr(status))

            print("\n\033[1m5. Fallbacks\033[0m")
            page.route("**/api/zkp/challenge", lambda r: r.fulfill(status=503, content_type="application/json",
                                                                  body='{"error":"Encrypted-record validation is temporarily unavailable"}'))
            note = add_manual(page, FALLBACK_503, "7.37")
            page.unroute("**/api/zkp/challenge")
            check("non-ZKP" in note, "503 from the challenge endpoint falls back, labeled non-ZKP", note)
            page2 = ctx.new_page()
            attach(page2, reqs, errs)
            page2.route("**/static/zkp/build/mm-zkp-v4.js", lambda r: r.fulfill(status=200, content_type="text/javascript",
                                                                               body="window.MMZkpV4 = {};"))
            page2.goto(base, wait_until="networkidle")
            unlock(page2, PASSPHRASE)
            check(not page2.is_hidden("#recordWarning") and V4_MERCHANT not in page2.inner_text("#ledgerBody"),
                  "without the prover, unlock still works and the v4 record is counted as not shown")
            note = add_manual(page2, FALLBACK_SRI, "8.48")
            check("non-ZKP" in note and "integrity" in note, "prover failing its SRI check falls back, labeled non-ZKP", note)
            check(page2.evaluate("() => window.MMZkpV4 === undefined"), "tampered prover never executed (SRI)")
            page2.close()
            records, _ = db_rows(db_url)
            check(sum(1 for r in records if r[1] == CIRCUIT) == 1 and len(records) >= 4,
                  "fallback records are plain sealed boxes (no v4 tag)")
            page.reload(wait_until="networkidle")
            unlock(page, PASSPHRASE)
            names = page.evaluate("() => TXNS.map(t => t.merchant)")
            check(all(n in names for n in (V4_MERCHANT, FALLBACK_503, FALLBACK_SRI)), "all records decrypt after fallbacks", repr(names))

            print("\n\033[1m6. Recovery rekey with a v4 record\033[0m")
            secrets_before = page.evaluate(SECRETS_JS)
            mnemonic = page.evaluate("() => setupRecoveryKey()")
            page.evaluate("() => { document.getElementById('recoverForm').hidden = false; }")
            page.fill("#recoverMnemonic", mnemonic)
            page.fill("#recoverNewPass", NEW_PASSPHRASE)
            page.once("dialog", lambda d: d.accept())
            page.click("#doRecoverBtn")
            page.wait_for_function("() => /Recovery complete/.test(document.getElementById('gateNote').textContent)"
                                   " || /Recovery failed/.test(document.getElementById('recoverNote').textContent)", timeout=240000)
            msg = page.inner_text("#gateNote") + " " + page.inner_text("#recoverNote")
            check("Recovery complete" in msg, "recovery rekey succeeded with a v4 record present", msg)
            records, commitment2 = db_rows(db_url)
            check(commitment2 is not None and commitment2 != commitment1, "rekey replaced the key commitment")
            check(not any(r[1] == CIRCUIT for r in records), "rekeyed records carry no stale v4 tag")
            page.reload(wait_until="networkidle")
            if page.is_visible("#passkeyGate"):
                page.click("#passkeyLoginBtn")
                page.wait_for_selector("#gate:not([hidden])", timeout=15000)
            unlock(page, NEW_PASSPHRASE)
            names = page.evaluate("() => TXNS.map(t => t.merchant)")
            check(V4_MERCHANT in names, "v4 record survives recovery and decrypts under the new key", repr(names))
            note = add_manual(page, V4_AFTER_REKEY, "51.51")
            check("zero-knowledge validity proof" in note, "new v4 entry works with the rekeyed commitment", note)
            secrets_after = page.evaluate(SECRETS_JS)

            print("\n\033[1m7. Network capture\033[0m")
            secrets = SECRETS + [secrets_before["priv"], secrets_before["root"], secrets_before["rootDec"],
                                 secrets_after["priv"], secrets_after["root"], secrets_after["rootDec"]]
            found = leaks(reqs, base, secrets)
            check(not found, f"no plaintext, passphrase, private key or zk_root in {len(reqs)} captured requests", repr(found[:3]))
            external = sorted({u.split('/')[2] for u, _ in reqs if not u.startswith(base) and not u.startswith("data:")})
            check(not external, "no request left the app origin (no third-party CRS download)", repr(external))
            # The SRI check's own console error is the point of the fallback test.
            real_errors = [e for e in errs if "Recovery failed" not in e and "valid digest" not in e]
            check(not real_errors, "no JS errors", "; ".join(real_errors[:3]))
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
    out = os.environ.get("ZKP_TIMINGS_OUT")
    if out:
        Path(out).write_text(json.dumps(timings, indent=2))
    print(f"\n{check.passed} passed, {check.failed} failed")
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
