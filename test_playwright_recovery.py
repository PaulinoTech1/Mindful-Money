#!/usr/bin/env python3
"""Real-browser backup recovery + plaintext-exposure test (Stage 2, Test D).

Drives the actual UI and JavaScript in headless Chromium: a real WebAuthn
bootstrap ceremony (CDP virtual authenticator), real Argon2id key derivation
(WASM), real libsodium sealed boxes, real HTTP upload/download, and the real
exportBackup()/importBackup() implementation. The Python simulator tests in
test_demo.py cover the crypto logic; this test proves the real
browser-to-server integration preserves the privacy guarantees.

What it proves:
  Phase 1 - browser A: real passkey bootstrap, passphrase unlock, create
            encrypted records, export an encrypted backup file.
  Phase 2 - browser B (fresh storage, same vault): unlock, import the backup,
            and recover every transaction byte-identical.
  Phase 3 - browser C (fresh storage, NEW vault / identity 2): unlock
            (server auto-generates fresh salts), import the backup, and
            observe the outcome. Currently the restore is rejected with a
            salt-mismatch error even though the backup carries its salts --
            this is the P1 #3 defect ("backup restore does not apply the
            backup's KDF salts"). Phase 3 locks in the exact failure
            signature so the fix can be verified against it.
  All phases - every outbound request to the app origin is intercepted and
            asserted to contain no transaction plaintext and no passphrase.

WebAuthn strategy: phase 1 performs the real bootstrap ceremony against a
CDP virtual authenticator. Phases 2-3 bypass the ceremony by minting a Flask
session cookie for the target identity (the task explicitly sanctions this);
the recovery and plaintext-exposure assertions -- the point of this test --
still run end-to-end in the real browser.

Run:
    pip install -r requirements-dev.txt   # includes playwright
    python -m playwright install chromium  # once per machine
    python3 test_playwright_recovery.py [--headed]

The test starts its own Flask server on a free loopback port against the
disposable Postgres test database (VAULT_TEST_DATABASE_URL, defaulting to
the same database test_demo.py uses), truncated fresh at startup.
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
BACKUP_PATH = Path("/tmp/playwright-recovery-backup.json")

PASSPHRASE = "playwright-recovery-passphrase"
# TEST-ONLY dummy bootstrap token, set only in this test server's env.
TEST_BOOTSTRAP_TOKEN = "test-only-bootstrap-token-not-a-secret"
MERCHANTS = [
    "PLAYWRIGHT-MERCHANT-9999",
    "PLAYWRIGHT-MERCHANT-1000",
    "PLAYWRIGHT-MERCHANT-1001",
]
AMOUNTS = [99.99, 10.00, 10.01]
EXPECTED = sorted(zip(MERCHANTS, AMOUNTS), key=lambda t: t[0])
SECRETS = MERCHANTS + [PASSPHRASE]

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("playwright not installed. Run:")
    print("  pip install -r requirements-dev.txt && python -m playwright install chromium")
    sys.exit(0)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Check:
    def __init__(self):
        self.passed = self.failed = 0

    def __call__(self, ok: bool, label: str, detail: str = "") -> None:
        if ok:
            self.passed += 1
            print(f"    \033[32m✓\033[0m {label}")
        else:
            self.failed += 1
            print(f"    \033[31m✗\033[0m {label}" + (f"\n        {detail}" if detail else ""))


def start_server(port: int, test_db_url: str) -> subprocess.Popen:
    """Truncate the disposable test DB and launch Flask on a free port."""
    from sqlalchemy import create_engine, text
    sys.path.insert(0, str(HERE))
    import models
    engine = create_engine(test_db_url, future=True)
    models.Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text(
            "TRUNCATE TABLE records, passkey_credentials, server_sessions, "
            "webauthn_challenges, rate_limits, audit_events, vault_identity RESTART IDENTITY CASCADE"
        ))
    engine.dispose()

    server_env = os.environ.copy()
    server_env.update({
        "VAULT_ORIGIN": f"http://localhost:{port}",
        "VAULT_RP_ID": "localhost",
        "VAULT_SECRET_KEY": "playwright-recovery-test-secret",
        "VAULT_CSP_MODE": "enforce",
        "VAULT_DATABASE_URL": test_db_url,
        "VAULT_BOOTSTRAP_TOKEN": TEST_BOOTSTRAP_TOKEN,
    })
    proc = subprocess.Popen(
        [sys.executable, "-c", f"import app; app.app.run(port={port})"],
        cwd=HERE, env=server_env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return proc
        except OSError:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError("server failed to start")


def attach_interception(page, request_log: list, error_log: list) -> None:
    """Record every outbound request (url + body) and every JS error.

    Chromium logs failed fetches (e.g. the expected 404 from GET
    /api/kdf/salts on a fresh vault, which the app then resolves via
    POST /api/kdf/salts/generate) as console errors; those resource-load
    notes are filtered out so the check only fails on real app errors.
    """
    page.on("request", lambda r: request_log.append((r.url, r.post_data or "")))
    page.on("pageerror", lambda e: error_log.append(f"PAGEERROR: {e}"))
    def on_console(m):
        if m.type == "error" and not m.text.startswith("Failed to load resource:"):
            error_log.append(m.text)
    page.on("console", on_console)


def check_no_plaintext_leak(check: Check, request_log: list, base: str, label: str) -> None:
    """No transaction plaintext or passphrase may reach the app origin."""
    leaked = []
    for url, body in request_log:
        if not url.startswith(base):
            continue
        for secret in SECRETS:
            if secret in url or secret in body:
                leaked.append(url)
                break
    check(not leaked, f"{label}: no plaintext in outbound requests",
          f"leaked via: {leaked[:3]}")


def add_virtual_authenticator(page):
    """Attach a CDP virtual authenticator (same recipe as test_browser.py)."""
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    authenticator_id = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True,
        "automaticPresenceSimulation": True,
    }})["authenticatorId"]
    return cdp, authenticator_id


def do_bootstrap(page, check: Check) -> None:
    """Real first-passkey enrollment through the bootstrap UI.

    The bootstrap flow prompts for a token via prompt(); the test server runs
    with the test-only TEST_BOOTSTRAP_TOKEN, so the token check is exercised.
    """
    cdp, authenticator_id = add_virtual_authenticator(page)
    try:
        def handle_prompt(dialog):
            dialog.accept(TEST_BOOTSTRAP_TOKEN)
            page.remove_listener("dialog", handle_prompt)
        page.on("dialog", handle_prompt)
        page.click("#passkeyLoginBtn")  # relabeled "Create passkey" in bootstrap mode
        page.wait_for_selector("#gate:not([hidden])", timeout=30000)
        check("Create your vault passphrase" in page.inner_text("#gate"),
              "real WebAuthn bootstrap ceremony enrolled the first passkey",
              page.inner_text("#gateNote"))
        # Bootstrap verify enrolls but deliberately does not set
        # authenticated_at (only login_verify does), so complete a real
        # passkey login with the same authenticator before unlocking.
        page.reload(wait_until="networkidle")
        page.wait_for_selector("#passkeyGate:not([hidden])", timeout=15000)
        page.click("#passkeyLoginBtn")
        page.wait_for_selector("#gate:not([hidden])", timeout=15000)
        check("Passkey accepted" in page.inner_text("#gateNote"),
              "passkey login after bootstrap reaches the passphrase gate",
              page.inner_text("#gateNote"))
    finally:
        cdp.send("WebAuthn.removeVirtualAuthenticator",
                 {"authenticatorId": authenticator_id})


def import_backup(page, passphrase: str) -> list:
    """Drive the current import UI (static/app.js importBackup).

    The unlock gate clears #pass after derivation, so importBackup asks for
    the passphrase with prompt() and reports the outcome with alert()
    ("Restored N records from backup." or "Restore failed: ...").
    Returns every dialog as (type, message) in order.
    """
    seen: list = []

    def on_dialog(dialog):
        seen.append((dialog.type, dialog.message))
        if dialog.type == "prompt":
            dialog.accept(passphrase)
        else:
            dialog.accept()

    page.on("dialog", on_dialog)
    try:
        page.set_input_files("#importFile", str(BACKUP_PATH))
        deadline = time.time() + 90
        while time.time() < deadline and not any(
                t == "alert" for t, _ in seen):
            page.wait_for_timeout(250)
    finally:
        page.remove_listener("dialog", on_dialog)
    return seen


def passphrase_unlock(page) -> None:
    """Passphrase unlock through the real gate UI (gate must be visible)."""
    page.fill("#pass", PASSPHRASE)
    page.click("#unlockBtn")
    page.wait_for_function(
        "() => document.getElementById('lock').dataset.state === 'open'",
        timeout=60000,
    )


def session_cookie_for_identity(identity_id: int) -> dict:
    """Mint a Flask session cookie for an identity via the test client.

    Used to bypass the WebAuthn ceremony in phases 2-3; the recovery and
    exposure assertions still execute end-to-end in the real browser.
    Requires VAULT_SECRET_KEY / VAULT_DATABASE_URL env to match the server.
    """
    sys.path.insert(0, str(HERE))
    import app as server_app
    client = server_app.app.test_client()
    client.get("/api/session")
    with client.session_transaction() as sess:
        sess["identity_id"] = identity_id
        sess["authenticated_at"] = time.time()
    cookie_name = server_app.app.config["SESSION_COOKIE_NAME"]
    cookie = client.get_cookie(cookie_name)
    if cookie is None:
        raise RuntimeError("could not mint session cookie")
    return {"name": cookie.key, "value": cookie.value}


CREATE_RECORDS_JS = """async (items) => {
  // Build records exactly like submitManualTransaction() does and upload
  // them through the app's real seal()/blindIndex()/api() path.
  for (const [merchant, amount] of items) {
    const manual = {
      id: 'pw_' + merchant,
      merchant: merchant,
      amount: amount,
      date: '2026-10-12',
      pending: false,
      account: 'pw_checking',
      bank: 'Playwright Bank',
      account_label: 'Checking',
      account_type: 'Checking',
      source: 'manual',
      transaction_type: 'expense',
      category: 'Dining',
    };
    await api('/api/records', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ records: [{ blind_index: blindIndex(manual.id), sealed: seal(manual) }] }),
    });
  }
  await load();
  return TXNS.length;
}"""


def main() -> int:
    headed = "--headed" in sys.argv
    port = free_port()
    base = f"http://localhost:{port}"
    test_db_url = os.environ.get(
        "VAULT_TEST_DATABASE_URL",
        "postgresql+psycopg://vault:vault_test_password@localhost:5432/vault_test",
    )
    # Env must match the server for in-process Flask test-client cookie minting.
    os.environ["VAULT_SECRET_KEY"] = "playwright-recovery-test-secret"
    os.environ["VAULT_DATABASE_URL"] = test_db_url

    server = start_server(port, test_db_url)
    check = Check()

    try:
        with sync_playwright() as p:
            bundled = sorted(glob.glob(os.path.expanduser(
                "~/.cache/ms-playwright/chromium-*/chrome-linux*/chrome")))
            launch_kwargs = {"headless": not headed, "args": ["--no-sandbox"]}
            if bundled:
                launch_kwargs["executable_path"] = bundled[-1]
            browser = p.chromium.launch(**launch_kwargs)

            # ---------- Phase 1: bootstrap, create, export (browser A) ----------
            print("\n\033[1mPhase 1: real bootstrap, create records, export backup\033[0m")
            ctx_a = browser.new_context(viewport={"width": 1280, "height": 900},
                                        accept_downloads=True)
            page_a = ctx_a.new_page()
            req_a: list = []
            err_a: list = []
            attach_interception(page_a, req_a, err_a)

            page_a.goto(base, wait_until="networkidle")
            check(page_a.is_visible("#passkeyGate"),
                  "fresh vault shows the first-passkey bootstrap gate")
            do_bootstrap(page_a, check)
            passphrase_unlock(page_a)
            check(page_a.get_attribute("#lock", "data-state") == "open",
                  "browser A unlocked via passphrase gate")

            created = page_a.evaluate(CREATE_RECORDS_JS, [list(m) for m in EXPECTED])
            check(created == len(EXPECTED),
                  f"browser A encrypted and uploaded {created} records via real seal()/api()",
                  f"expected {len(EXPECTED)}")

            with page_a.expect_download(timeout=30000) as dl_info:
                page_a.click("#exportBtn")
            raw = Path(dl_info.value.path()).read_text()
            backup = json.loads(raw)
            BACKUP_PATH.write_text(raw)
            check(backup.get("format") == "mindful-money-backup",
                  "backup file has the expected format envelope")
            check(backup.get("record_count") == len(EXPECTED)
                  and len(backup.get("records", [])) == len(EXPECTED),
                  "backup contains all records")
            check(bool(backup.get("kdf", {}).get("salt_enc"))
                  and bool(backup.get("integrity")) and bool(backup.get("canary")),
                  "backup carries KDF salts, integrity hash, and canary")
            check(all(s not in raw for s in MERCHANTS),
                  "backup file itself contains no plaintext merchants")
            check(not err_a, "browser A: no JS console errors", "; ".join(err_a[:3]))
            check_no_plaintext_leak(check, req_a, base, "browser A")
            ctx_a.close()

            # ---------- Phase 2: fresh browser, same vault, restore ----------
            print("\n\033[1mPhase 2: fresh browser, import backup, compare\033[0m")
            cookie1 = session_cookie_for_identity(1)
            ctx_b = browser.new_context(viewport={"width": 1280, "height": 900},
                                        accept_downloads=True)
            ctx_b.add_cookies([{**cookie1, "url": base}])
            page_b = ctx_b.new_page()
            req_b: list = []
            err_b: list = []
            attach_interception(page_b, req_b, err_b)

            page_b.goto(base, wait_until="networkidle")
            check(page_b.is_visible("#gate"),
                  "authenticated session skips the passkey gate")
            passphrase_unlock(page_b)
            check(page_b.get_attribute("#lock", "data-state") == "open",
                  "browser B unlocked with the same passphrase")

            check(page_b.evaluate("() => typeof S.memcmp === 'function'"),
                  "bundled libsodium exposes constant-time memcmp (used by restore)")
            dialogs_b = import_backup(page_b, PASSPHRASE)
            check(dialogs_b[:1] and dialogs_b[0][0] == "prompt",
                  "import asks for the vault passphrase (gate cleared #pass)", repr(dialogs_b))
            msg_b = next((m for t, m in dialogs_b if t == "alert"), "")
            check(f"Restored {len(EXPECTED)} records" in msg_b,
                  "import reports all records restored", f"dialog said: {msg_b!r}")

            page_b.wait_for_function(
                f"() => TXNS && TXNS.length === {len(EXPECTED)}", timeout=60000)
            recovered = page_b.evaluate(
                "() => TXNS.map(t => [t.merchant, t.amount])"
                ".sort((a, b) => a[0] < b[0] ? -1 : 1)")
            check([tuple(r) for r in recovered] == EXPECTED,
                  "every recovered transaction matches the original plaintext",
                  f"got {recovered}")
            check(not err_b, "browser B: no JS console errors", "; ".join(err_b[:3]))
            check_no_plaintext_leak(check, req_b, base, "browser B")
            ctx_b.close()

            # ---------- Phase 3: new vault restore (P1 #3 defect probe) ----------
            print("\n\033[1mPhase 3: new-vault restore -- P1 #3 defect probe\033[0m")
            from sqlalchemy import create_engine, text
            from sqlalchemy.orm import Session
            import models as _models
            engine = create_engine(test_db_url, future=True)
            with Session(engine) as s:
                s.add(_models.VaultIdentity(
                    id=2, user_handle=b"playwright-device-c",
                    passkey_required=False, kdf_version=1))
                s.flush()  # ensure the identity row exists before the credential
                s.add(_models.PasskeyCredential(
                    identity_id=2, credential_id=b"pw-defect-probe",
                    credential_public_key=b"x", label="probe",
                    sign_count=0, transports=[]))
                s.commit()
            engine.dispose()

            cookie2 = session_cookie_for_identity(2)
            ctx_c = browser.new_context(viewport={"width": 1280, "height": 900},
                                        accept_downloads=True)
            ctx_c.add_cookies([{**cookie2, "url": base}])
            page_c = ctx_c.new_page()
            req_c: list = []
            err_c: list = []
            attach_interception(page_c, req_c, err_c)

            page_c.goto(base, wait_until="networkidle")
            passphrase_unlock(page_c)  # deriveKeys -> 404 salts -> generate fresh salts
            check(page_c.get_attribute("#lock", "data-state") == "open",
                  "browser C unlocked against the new vault")

            # Security property under the current UI: a backup from another
            # vault is only accepted with the passphrase that produced it.
            # importBackup verifies the HMAC and canary with candidate keys
            # BEFORE touching server salts, so a wrong passphrase must be
            # rejected and must not change this vault's salts.
            salts_before = page_c.evaluate("() => api('/api/kdf/salts')")
            dialogs_bad = import_backup(page_c, "definitely-not-the-passphrase")
            msg_bad = next((m for t, m in dialogs_bad if t == "alert"), "")
            check(msg_bad.startswith("Restore failed:") and
                  ("Integrity check failed" in msg_bad or "wrong passphrase" in msg_bad),
                  "foreign backup with wrong passphrase is rejected", f"got: {msg_bad!r}")
            salts_after = page_c.evaluate("() => api('/api/kdf/salts')")
            check(salts_before == salts_after,
                  "rejected restore leaves this vault's KDF salts unchanged")
            check(page_c.evaluate("() => TXNS.length") == 0,
                  "rejected restore imports nothing")

            # With the right passphrase, cross-vault restore is the intended
            # path (salts migrated after full validation).
            dialogs_c = import_backup(page_c, PASSPHRASE)
            msg_c = next((m for t, m in dialogs_c if t == "alert"), "")
            check(f"Restored {len(EXPECTED)} records" in msg_c,
                  "new-vault restore with the right passphrase succeeds", f"got: {msg_c!r}")
            if f"Restored {len(EXPECTED)} records" in msg_c:
                page_c.wait_for_function(
                    f"() => TXNS && TXNS.length === {len(EXPECTED)}", timeout=60000)
                recovered_c = page_c.evaluate(
                    "() => TXNS.map(t => [t.merchant, t.amount])"
                    ".sort((a, b) => a[0] < b[0] ? -1 : 1)")
                check([tuple(r) for r in recovered_c] == EXPECTED,
                      "new-vault recovery is byte-identical", f"got {recovered_c}")

            # Bug D regression: after restore the vault must unlock again with
            # the backup's salts AND its KDF version (stored atomically by
            # /api/kdf/salts/migrate). Reload and unlock from scratch.
            page_c.reload(wait_until="networkidle")
            check(page_c.is_visible("#gate"), "restored vault: reload shows the passphrase gate")
            passphrase_unlock(page_c)
            page_c.wait_for_function(
                f"() => TXNS && TXNS.length === {len(EXPECTED)}", timeout=60000)
            reloaded_c = page_c.evaluate(
                "() => TXNS.map(t => [t.merchant, t.amount])"
                ".sort((a, b) => a[0] < b[0] ? -1 : 1)")
            check([tuple(r) for r in reloaded_c] == EXPECTED,
                  "restored vault unlocks after reload with identical records", f"got {reloaded_c}")
            check(page_c.evaluate("() => api('/api/kdf/salts').then(r => r.kdf_version)") == 3,
                  "restored vault stores the backup's kdf_version (3)")
            check_no_plaintext_leak(check, req_c, base, "browser C")
            ctx_c.close()

            # ---------- Phase 4: v3 backup into an empty v1 vault (bug D) ----------
            print("\n\033[1mPhase 4: v3 backup into an empty v1 vault (bug D)\033[0m")
            engine = create_engine(test_db_url, future=True)
            with Session(engine) as s:
                s.add(_models.VaultIdentity(
                    id=3, user_handle=b"playwright-device-d", passkey_required=False,
                    kdf_version=1, kdf_salt_enc=os.urandom(16), kdf_salt_idx=os.urandom(16)))
                s.flush()
                s.add(_models.PasskeyCredential(
                    identity_id=3, credential_id=b"pw-bug-d-probe",
                    credential_public_key=b"x", label="probe", sign_count=0, transports=[]))
                s.commit()
            engine.dispose()
            ctx_d = browser.new_context(viewport={"width": 1280, "height": 900}, accept_downloads=True)
            ctx_d.add_cookies([{**session_cookie_for_identity(3), "url": base}])
            page_d = ctx_d.new_page()
            req_d: list = []
            err_d: list = []
            attach_interception(page_d, req_d, err_d)
            page_d.goto(base, wait_until="networkidle")
            passphrase_unlock(page_d)   # derives v1 keys on this vault's own salts
            check(page_d.evaluate("() => api('/api/kdf/salts').then(r => r.kdf_version)") == 1,
                  "phase 4 vault starts at kdf_version 1")
            msg_d = next((m for t, m in import_backup(page_d, PASSPHRASE) if t == "alert"), "")
            check(f"Restored {len(EXPECTED)} records" in msg_d,
                  "v3 backup restores into a v1 vault", f"got: {msg_d!r}")
            page_d.reload(wait_until="networkidle")
            passphrase_unlock(page_d)
            page_d.wait_for_function(
                f"() => TXNS && TXNS.length === {len(EXPECTED)}", timeout=60000)
            reloaded_d = page_d.evaluate(
                "() => TXNS.map(t => [t.merchant, t.amount])"
                ".sort((a, b) => a[0] < b[0] ? -1 : 1)")
            check([tuple(r) for r in reloaded_d] == EXPECTED,
                  "after reload the v1 vault unlocks as v3 with identical records", f"got {reloaded_d}")
            check(page_d.evaluate("() => api('/api/kdf/salts').then(r => r.kdf_version)") == 3,
                  "kdf_version moved to 3 together with the salts")
            # Bug E regression: a record in the largest bucket (8192 bytes
            # padded) seals to the server's max size and round-trips.
            big = page_d.evaluate("""async () => {
                const obj = { id: 'big-record', merchant: 'M'.repeat(8100), amount: -1, date: '2026-10-12' };
                const sealed = seal(obj);
                await api('/api/records', { method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ records: [{ blind_index: blindIndex(obj.id), sealed }] }) });
                const { records } = await api('/api/records');
                const mine = records.find(r => r.blind_index === blindIndex(obj.id));
                const back = mine ? open(mine.sealed) : null;
                return { hexLen: sealed.length, plainLen: JSON.stringify(obj).length,
                         ok: !!back && back.merchant === obj.merchant && back.amount === -1 };
            }""")
            check(big["hexLen"] == 16480 and big["ok"],
                  f"~8 KB record ({big['plainLen']} bytes) seals to the max size and round-trips", repr(big))
            check(not any("M" * 64 in body or "M" * 64 in url for url, body in req_d),
                  "~8 KB record plaintext never leaves the browser")
            check_no_plaintext_leak(check, req_d, base, "browser D")

            # ---------- Phase 5: recovery with the recovery key (bugs L, M, K) ----------
            # Vault D (identity 3) holds the restored records plus the ~8 KB
            # record. Set up a recovery key, "forget" the passphrase, recover
            # with the key and a new passphrase through the real UI, then
            # check: reload + unlock with the new passphrase gives identical
            # records, the old passphrase fails, re-syncing the same
            # transactions creates no duplicates (K), and the same recovery
            # key still works for a second recovery.
            print("\n\033[1mPhase 5: recovery key -> new passphrase (bugs L, M, K)\033[0m")
            NEW_PASS = "recovered-vault passphrase 2026 #one"
            NEXT_PASS = "second-recovery passphrase 2026 #two"
            page_d.evaluate("() => load()")  # include the ~8 KB record added above
            before_k = sorted(page_d.evaluate("() => TXNS.map(t => [t.id, t.merchant.slice(0, 30), t.merchant.length, t.amount])"))
            count_before = page_d.evaluate("() => api('/api/records').then(r => r.records.length)")
            mnemonic = page_d.evaluate("() => setupRecoveryKey()")
            check(isinstance(mnemonic, str) and len(mnemonic.split()) == 32, "recovery key set up (32 words)")

            def recover_via_ui(page, words: str, new_pass: str, label: str) -> None:
                # Simulates a fresh passkey sign-in (the WebAuthn ceremony is
                # bypassed as in phases 2-4) so the blob gate's step-up
                # window is satisfied, then uses the real locked-gate UI.
                page.context.add_cookies([{**session_cookie_for_identity(3), "url": base}])
                page.reload(wait_until="networkidle")
                page.wait_for_selector("#gate:not([hidden])")
                page.click("#forgotPassBtn")
                page.fill("#recoverMnemonic", words)
                page.fill("#recoverNewPass", new_pass)
                page.once("dialog", lambda d: d.accept())
                page.click("#doRecoverBtn")
                page.wait_for_function(
                    "() => /Recovery complete|Recovery failed/.test("
                    "document.getElementById('gateNote').textContent + document.getElementById('recoverNote').textContent)",
                    timeout=180000)
                note = page.inner_text("#gateNote") + " | " + page.inner_text("#recoverNote")
                check("Recovery complete" in note, f"{label}: recovery completes through the locked gate", note)

            def unlock_with(page, passphrase: str) -> str:
                page.reload(wait_until="networkidle")
                page.wait_for_selector("#gate:not([hidden])")
                page.fill("#pass", passphrase)
                page.click("#unlockBtn")
                page.wait_for_function(
                    "() => document.getElementById('lock').dataset.state === 'open' || "
                    "/Incorrect/.test(document.getElementById('gateNote').textContent)", timeout=120000)
                return page.get_attribute("#lock", "data-state")

            req_mark = len(req_d)
            recover_via_ui(page_d, mnemonic, NEW_PASS, "first recovery")
            check(page_d.evaluate("() => KEYS === null"), "vault is locked after recovery (no auto unlock)")
            check(unlock_with(page_d, NEW_PASS) == "open", "reload + unlock with the NEW passphrase",
                  page_d.inner_text("#gateNote"))
            after_k = sorted(page_d.evaluate("() => TXNS.map(t => [t.id, t.merchant.slice(0, 30), t.merchant.length, t.amount])"))
            check(after_k == before_k, f"all {len(before_k)} records identical after recovery", f"{after_k} vs {before_k}")
            check(page_d.evaluate("() => api('/api/kdf/salts').then(r => r.kdf_version)") == 3, "kdf_version is 3")
            # K: blind indexes match the NEW index key, so a re-sync upserts.
            in_sync = page_d.evaluate("""async () => {
                const { records } = await api('/api/records');
                const want = new Set(TXNS.map(t => blindIndex(t.id)));
                return records.length === want.size && records.every(r => want.has(r.blind_index));
            }""")
            check(in_sync, "K: every stored blind index equals HMAC(id) under the new index key")
            page_d.evaluate(CREATE_RECORDS_JS, [[m, a] for m, a in EXPECTED])
            count_after_sync = page_d.evaluate("() => api('/api/records').then(r => r.records.length)")
            check(count_after_sync == count_before,
                  "K: re-syncing the same transactions creates no duplicates",
                  f"{count_before} -> {count_after_sync}")
            check(unlock_with(page_d, PASSPHRASE) != "open"
                  and "Incorrect" in page_d.inner_text("#gateNote"), "the OLD passphrase no longer unlocks")
            recover_via_ui(page_d, mnemonic, NEXT_PASS, "same recovery key again")
            check(unlock_with(page_d, NEXT_PASS) == "open"
                  and sorted(page_d.evaluate("() => TXNS.map(t => [t.id, t.merchant.slice(0, 30), t.merchant.length, t.amount])")) == before_k,
                  "the recovery key still works after a recovery (blob rewrapped to the new seed)")
            leaked = [u for u, body in req_d[req_mark:] if mnemonic.split()[0] + " " + mnemonic.split()[1] in body
                      or NEW_PASS in body or NEXT_PASS in body or NEW_PASS in u]
            check(not leaked, "recovery words and new passphrases never leave the browser")
            check_no_plaintext_leak(check, req_d, base, "browser D after recovery")
            ctx_d.close()

            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)

    total = check.passed + check.failed
    color = "32" if not check.failed else "31"
    print(f"\n\033[{color}m{check.passed}/{total} passing\033[0m\n")
    return 0 if not check.failed else 1


if __name__ == "__main__":
    sys.exit(main())
