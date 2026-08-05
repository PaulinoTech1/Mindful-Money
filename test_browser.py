#!/usr/bin/env python3
"""End-to-end browser test. Drives the real UI and saves screenshots.

    pip install playwright && python3 -m playwright install chromium
    python3 test_browser.py

Optional -- test_demo.py covers correctness without a browser. This one
exercises the actual JavaScript: real Argon2id in WASM, real Chart.js
rendering, and the server-view toggle. Screenshots land in screenshots/.

Add --headed to watch it happen in a visible window.
"""

from __future__ import annotations

import socket
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
SHOTS = HERE / "screenshots"
PASSPHRASE = "demo passphrase"

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("playwright not installed. Run:")
    print("  pip install playwright && python3 -m playwright install chromium")
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


def canvas_has_content(page, canvas_id: str) -> bool:
    """A chart that failed to draw leaves a uniform canvas. Sample the pixels."""
    return page.evaluate(
        """(id) => {
            const c = document.getElementById(id);
            if (!c || !c.width) return false;
            const d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
            const seen = new Set();
            for (let i = 0; i < d.length; i += 400) seen.add(d[i] + ',' + d[i+1] + ',' + d[i+2]);
            return seen.size > 3;
        }""",
        canvas_id,
    )


def main() -> int:
    headed = "--headed" in sys.argv
    SHOTS.mkdir(exist_ok=True)
    port = free_port()
    db = HERE / "e2e-test.db"
    db.unlink(missing_ok=True)

    server_env = os.environ.copy()
    server_env.update({"VAULT_ORIGIN": f"http://localhost:{port}", "VAULT_RP_ID": "localhost", "VAULT_SECRET_KEY": "browser-test-secret-not-for-production", "VAULT_CSP_MODE": "enforce"})
    env_server = subprocess.Popen(
        [sys.executable, "-c",
         f"import app; app.DB = __import__('pathlib').Path(r'{db}'); "
         f"app.app.run(port={port})"],
        cwd=HERE, env=server_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    base = f"http://localhost:{port}"
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.2)
    else:
        print("server failed to start")
        env_server.terminate()
        return 1

    check = Check()
    print("\n\033[1mBrowser end-to-end\033[0m\n")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=not headed, args=["--no-sandbox"])
            page = browser.new_page(viewport={"width": 1440, "height": 1000})

            errors: list[str] = []
            requests: list[str] = []
            request_bodies: list[str] = []
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.on("pageerror", lambda e: errors.append(f"PAGEERROR: {e}"))
            page.on("request", lambda r: (requests.append(r.url), request_bodies.append(r.post_data or "")))

            # --- unlock -------------------------------------------------
            print("  Unlock")
            page.goto(base, wait_until="networkidle")
            check(page.is_visible("#gate"), "passphrase gate shown on first load")
            missing_csrf = page.evaluate("() => fetch('/api/relay', {method: 'POST'}).then(r => r.status)")
            check(missing_csrf == 403, "unsafe browser request without CSRF is rejected")
            csrf = page.evaluate("() => CSRF")
            hostile = page.request.post(f"{base}/api/relay", headers={
                "Origin": "http://localhost.evil", "X-CSRF-Token": csrf,
            })
            check(hostile.status == 403, "unsafe request with hostile Origin is rejected")
            errors.clear()  # Chromium logs the deliberately rejected raw fetch as a resource error.
            page.screenshot(path=SHOTS / "1-unlock.png")

            t0 = time.time()
            page.fill("#pass", PASSPHRASE)
            page.click("#unlockBtn")
            page.wait_for_selector("#empty:not([hidden]), #dash:not([hidden])", timeout=30000)
            page.wait_for_function("() => document.getElementById('lock').dataset.state === 'open'", timeout=30000)
            kdf_ms = int((time.time() - t0) * 1000)

            check(page.get_attribute("#lock", "data-state") == "open", "vault reports unlocked")
            check(200 < kdf_ms < 15000, f"key derived in {kdf_ms}ms", f"got {kdf_ms}ms")
            check(
                page.inner_text("#statKey").startswith("95208c801d1d"),
                "public key matches the known test vector",
                f"got {page.inner_text('#statKey')}",
            )

            # --- connect ------------------------------------------------
            print("\n  Connect and encrypt")
            page.click("#connectBtn")
            page.wait_for_selector("#dash:not([hidden])", timeout=60000)
            page.wait_for_timeout(2500)

            records = int(page.inner_text("#statRecords"))
            check(records > 200, f"{records} transactions encrypted in-browser and stored")
            check(page.inner_text("#statReadable") == "0", "readable-by-server counter is zero")
            accounts_text = page.inner_text("#accounts")
            check("Scammers Inc" in accounts_text, "checking account shows Scammers Inc")
            check("Wells Forclosure" in accounts_text and "IRA" in accounts_text, "IRA shows Wells Forclosure")
            check("DC Unc" in accounts_text and "401(k)" in accounts_text, "401(k) shows DC Unc")
            dashboard_accounts = page.query_selector_all("#dashboardAccounts .accountCard")
            check(len(dashboard_accounts) == 3, "dashboard shows three account cards")
            check("Scammers Inc" in page.inner_text("#dashboardAccounts"), "dashboard visual includes checking bank")
            check("Wells Forclosure" in page.inner_text("#dashboardAccounts") and "DC Unc" in page.inner_text("#dashboardAccounts"), "dashboard visual includes both investment banks")
            page.click("#syncBtn")
            page.wait_for_function("() => !document.getElementById('syncBtn').disabled", timeout=60000)
            page.wait_for_function(
                f"() => document.getElementById('statRecords').textContent === '{records}'",
                timeout=60000,
            )
            check(int(page.inner_text("#statRecords")) == records, "refreshing accounts does not duplicate records")

            # --- dashboard ----------------------------------------------
            print("\n  Dashboard")
            headline = page.inner_text("#figureNet")
            check("$" in headline, f"headline figure renders  ({headline})")
            for cid, label in [
                ("chMonthly", "monthly income and spending"),
                ("chCategory", "category breakdown"),
                ("chBalance", "running balance"),
                ("chMerchants", "top merchants"),
            ]:
                check(canvas_has_content(page, cid), f"chart drew: {label}")

            rows = page.query_selector_all("#ledgerBody tr")
            check(len(rows) == 14, f"ledger lists {len(rows)} recent transactions")
            check(
                len(page.query_selector_all("#ledgerBody .tag")) == len(rows),
                "every row categorized on-device",
            )
            user_view_text = page.inner_text("#dash")
            check("Blue Bottle Coffee" in user_view_text, "merchant names visible to the user")

            # --- local assistant ---------------------------------------
            print("\n  Local assistant")
            before_chat_requests = list(requests)
            page.fill("#chatInput", "Give me a summary of my finances")
            page.click("#chatSend")
            page.wait_for_function(
                "() => document.querySelectorAll('#chatMessages .chatBubble').length >= 3"
            )
            chat_text = page.inner_text("#chatMessages")
            check("Across" in chat_text, "assistant summarizes decrypted transactions locally")
            check("LOCAL ONLY" in page.inner_text("#assistant"), "assistant shows its local-only privacy boundary")
            check(requests == before_chat_requests, "chat question made no network request", str(requests[len(before_chat_requests):]))
            page.fill("#chatInput", "How much did I spend at Fans Only last month?")
            page.click("#chatSend")
            page.wait_for_function(
                "() => document.querySelectorAll('#chatMessages .chatBubble').length >= 5"
            )
            check("$423.23" in page.inner_text("#chatMessages"), "assistant reports the exact Fans Only charge")
            page.fill("#chatInput", "Graph my spending by category")
            page.click("#chatSend")
            page.wait_for_selector("#chatMessages .chatGraph canvas")
            graph_id = page.query_selector_all("#chatMessages .chatGraph canvas")[-1].get_attribute("id")
            check(graph_id and canvas_has_content(page, graph_id), "assistant renders a local spending graph")
            page.fill("#chatInput", "Calculate my average and median expense")
            page.click("#chatSend")
            page.wait_for_function("() => document.querySelector('#chatMessages').innerText.includes('Mathematical analysis')")
            check("Mathematical analysis" in page.inner_text("#chatMessages"), "assistant provides local mathematical analysis")
            check(requests == before_chat_requests, "charts and math made no network request", str(requests[len(before_chat_requests):]))
            page.screenshot(path=SHOTS / "2-dashboard.png", full_page=True)

            # --- server view --------------------------------------------
            print("\n  Server view")
            page.click("#viewToggle")
            page.wait_for_selector("#serverview:not([hidden])", timeout=15000)
            page.wait_for_timeout(1500)

            sv_text = page.inner_text("#serverview")
            leaked = [m for m in ("Blue Bottle", "Stuyvesant", "Spotify", "Trader Joe")
                      if m in sv_text]
            check(not leaked, "no merchant name appears in the server view", f"leaked: {leaked}")
            check(str(records) in sv_text, "server view reports the real row count")

            raw = page.query_selector_all("#rawBody tr")
            check(len(raw) > 0, f"{len(raw)} raw ciphertext rows displayed")
            first = page.inner_text("#rawBody tr:first-child td:last-child")
            check(
                all(c in "0123456789abcdef\u2026" for c in first),
                "stored values are pure hex",
                f"got {first[:40]}",
            )
            for cid, label in [("chSizes", "blob size histogram"), ("chDays", "writes per day")]:
                check(canvas_has_content(page, cid), f"chart drew: {label}")
            page.screenshot(path=SHOTS / "3-server-view.png", full_page=True)

            # --- reload persistence -------------------------------------
            print("\n  Reload")
            page.goto(base, wait_until="networkidle")
            page.fill("#pass", PASSPHRASE)
            page.click("#unlockBtn")
            page.wait_for_selector("#dash:not([hidden])", timeout=30000)
            check(
                int(page.inner_text("#statRecords")) == records,
                "same passphrase re-derives the key and reopens the data",
            )

            # --- optional passkeys (Chromium virtual authenticator) ----
            print("\n  Optional passkeys")
            cdp = page.context.new_cdp_session(page)
            cdp.send("WebAuthn.enable", {"enableUI": False})
            authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }})["authenticatorId"]
            page.fill("#passkeyLabel", "Test laptop")
            page.click("#enablePasskeyBtn")
            try:
                page.wait_for_function("() => document.querySelector('#passkeyState').innerText === 'Enabled'", timeout=15000)
            except Exception:
                print("    passkey error:", page.inner_text("#securityNote"))
                raise
            page.wait_for_function("() => document.querySelectorAll('#passkeyList .passkeyItem').length === 1", timeout=15000)
            check("Test laptop" in page.inner_text("#passkeyList"), "optional passkey enrollment succeeds", page.inner_text("#passkeyList"))

            page.reload(wait_until="networkidle")
            check(page.is_visible("#gate"), "authenticated reload proceeds to passphrase stage")
            page.click("#signOutBtn") if page.is_visible("#signOutBtn") else None
            if not page.is_visible("#passkeyGate"):
                # A reload is authenticated but locked; explicitly expire it through the API.
                page.evaluate("() => signOut()")
            page.wait_for_selector("#passkeyGate:not([hidden])")
            check(page.is_visible("#passkeyGate"), "sign out returns to passkey screen")
            page.click("#passkeyLoginBtn")
            page.wait_for_selector("#gate:not([hidden])", timeout=15000)
            check("Passkey accepted" in page.inner_text("#gateNote"), "passkey login precedes vault unlock")
            page.fill("#pass", "wrong passphrase")
            page.click("#unlockBtn")
            page.wait_for_function("() => document.querySelector('#gateNote').innerText.includes('Incorrect')", timeout=30000)
            check(page.is_visible("#gate"), "wrong passphrase still fails after valid passkey")
            page.fill("#pass", PASSPHRASE); page.click("#unlockBtn")
            page.wait_for_selector("#dash:not([hidden])", timeout=30000)
            cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})
            authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
                "protocol": "ctap2", "transport": "usb", "hasResidentKey": True,
                "hasUserVerification": True, "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }})["authenticatorId"]
            page.fill("#passkeyLabel", "Backup key")
            page.click("#addPasskeyBtn")
            try:
                page.wait_for_function("() => document.querySelectorAll('#passkeyList .passkeyItem').length === 2", timeout=15000)
            except Exception:
                print("    second passkey error:", page.inner_text("#securityNote"), page.inner_text("#passkeyList"))
                raise
            check(len(page.query_selector_all("#passkeyList .passkeyItem")) == 2, "a second passkey can be added")
            page.once("dialog", lambda dialog: dialog.accept("Renamed laptop"))
            page.click("#passkeyList [data-rename]")
            page.wait_for_function("() => document.querySelector('#passkeyList').innerText.includes('Renamed laptop')")
            check("Renamed laptop" in page.inner_text("#passkeyList"), "passkey rename succeeds")
            page.click("#passkeyList [data-remove]")
            page.wait_for_function("() => document.querySelectorAll('#passkeyList .passkeyItem').length === 1")
            check(len(page.query_selector_all("#passkeyList .passkeyItem")) == 1, "passkey removal succeeds")
            page.click("#lockVaultBtn")
            check(page.is_visible("#gate") and not page.is_visible("#passkeyGate"), "lock clears vault but preserves passkey session")
            page.fill("#pass", PASSPHRASE); page.click("#unlockBtn"); page.wait_for_selector("#dash:not([hidden])", timeout=30000)
            page.on("dialog", lambda dialog: dialog.accept())
            page.click("#disablePasskeyBtn")
            page.wait_for_function("() => document.querySelector('#passkeyState').innerText === 'Not enabled'")
            check(page.is_visible("#security"), "disabling restores passphrase-only mode")
            check(all(PASSPHRASE not in body for body in request_bodies), "passphrase never appears in network request bodies")
            cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})

            # --- mobile --------------------------------------------------
            print("\n  Responsive")
            page.set_viewport_size({"width": 390, "height": 844})
            page.wait_for_timeout(900)
            overflow = page.evaluate(
                "document.documentElement.scrollWidth > window.innerWidth + 2"
            )
            check(not overflow, "no horizontal overflow at 390px")
            page.screenshot(path=SHOTS / "4-mobile.png", full_page=True)

            check(not errors, "no console errors", "; ".join(errors[:3]))
            browser.close()
    finally:
        env_server.terminate()
        env_server.wait(timeout=10)
        db.unlink(missing_ok=True)

    total = check.passed + check.failed
    color = "32" if not check.failed else "31"
    print(f"\n\033[{color}m{check.passed}/{total} passing\033[0m")
    print(f"screenshots -> {SHOTS}/\n")
    return 0 if not check.failed else 1


if __name__ == "__main__":
    sys.exit(main())
