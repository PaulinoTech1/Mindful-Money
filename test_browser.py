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

    # Reuse the same disposable Postgres test database test_demo.py uses,
    # truncated fresh -- there's no single file to delete/recreate anymore.
    test_db_url = os.environ.get(
        "VAULT_TEST_DATABASE_URL",
        "postgresql+psycopg://vault:vault_dev_only_password@localhost:5432/vault_test",
    )
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
        "VAULT_ORIGIN": f"http://localhost:{port}", "VAULT_RP_ID": "localhost",
        "VAULT_SECRET_KEY": "browser-test-secret-not-for-production", "VAULT_CSP_MODE": "enforce",
        "VAULT_DATABASE_URL": test_db_url,
    })
    env_server = subprocess.Popen(
        [sys.executable, "-c", f"import app; app.app.run(port={port})"],
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
            check("Wells Foreclosure" in accounts_text and "IRA" in accounts_text, "IRA shows Wells Foreclosure")
            check("DC Unc" in accounts_text and "401(k)" in accounts_text, "401(k) shows DC Unc")
            dashboard_accounts = page.query_selector_all("#dashboardAccounts .accountCard")
            check(len(dashboard_accounts) == 3, "dashboard shows three account cards")
            check("Scammers Inc" in page.inner_text("#dashboardAccounts"), "dashboard visual includes checking bank")
            check("Wells Foreclosure" in page.inner_text("#dashboardAccounts") and "DC Unc" in page.inner_text("#dashboardAccounts"), "dashboard visual includes both investment banks")
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
            check("Changes are encrypted in your browser" in page.inner_text(".ledgerEditNote"), "ledger explains encrypted editing")
            check(
                len(page.query_selector_all("#ledgerBody .tag")) == len(rows),
                "every row categorized on-device",
            )
            user_view_text = page.inner_text("#dash")
            check("Blue Bottle Coffee" in user_view_text, "merchant names visible to the user")
            check(page.is_visible("#fraudWatch"), "browser-only unusual activity watch is visible")
            check("not confirmed fraud" in page.inner_text("#fraudWatch"), "detector presents a clear statistical caveat")
            check(len(page.query_selector_all("#fraudList [data-review-anomaly]")) > 0, "historical baseline produces explainable review candidates")
            flagged_before = int(page.inner_text("#fraudCount"))
            page.locator("#fraudList [data-mark-safe]").first.click()
            page.wait_for_function(f"() => Number(document.querySelector('#fraudCount').textContent) === {flagged_before - 1}")
            check("Marked safe" in page.inner_text("#fraudActionNote"), "user can validate a statistical flag as safe")

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
            page.fill("#chatInput", "Make a projection")
            page.click("#chatSend")
            page.wait_for_function("() => document.querySelector('#chatMessages').innerText.includes('next month or the next three months')")
            check(len(page.query_selector_all("#chatMessages .chatFollowUps button")) >= 2, "assistant asks a clickable follow-up question")
            page.get_by_role("button", name="Next 3 months", exact=True).last.click()
            page.wait_for_function("() => document.querySelector('#chatMessages').innerText.includes('robust Theil')")
            check("historical residual variability" in page.inner_text("#chatMessages"), "assistant projects cash flow with an uncertainty caveat")
            page.get_by_role("button", name="Project categories", exact=True).last.click()
            page.wait_for_function("() => document.querySelector('#chatMessages').innerText.includes('Next-month category projection')")
            check(requests == before_chat_requests, "follow-ups and projections make no network request", str(requests[len(before_chat_requests):]))

            # --- encrypted transaction editing ------------------------
            expense_row = page.locator("#ledgerBody tr").filter(has=page.locator("td.num:not(.credit)")).first
            amount_text = expense_row.locator("td.num").inner_text()
            cents = round(float("".join(c for c in amount_text if c.isdigit() or c == ".")) * 100)
            first_cents = cents // 2
            second_cents = cents - first_cents
            expense_row.locator("[data-edit-transaction]").click()
            page.fill("#editMerchant", "Edited Merchant")
            page.select_option("#editCategory", label="Groceries")
            page.fill("#editNotes", "Private operator note")
            page.fill("#editTags", "reviewed, reimbursable")
            page.fill("#editSplits", f"Groceries: {first_cents / 100:.2f}\nDining: {second_cents / 100:.2f}")
            page.check("#editTransfer")
            page.check("#editExcluded")
            page.select_option("#editFraudStatus", "fraud")
            page.click("#transactionEditForm button[type=submit]")
            page.wait_for_selector("#transactionEditor", state="hidden")
            ledger_text = page.inner_text("#ledgerBody")
            check("Edited Merchant" in ledger_text, "merchant rename persists in the decrypted ledger")
            check("Flagged fraud by you" in ledger_text and "Transfer" in ledger_text and "Excluded" in ledger_text and "2 splits" in ledger_text, "user fraud flag, transfer, exclusion, tags, and splits are reflected")
            check("user fraud" in page.inner_text("#fraudList").lower(), "any transaction can be explicitly flagged as fraud")
            check(all("Private operator note" not in body and "Edited Merchant" not in body for body in request_bodies), "transaction edits reach the server only as ciphertext")
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
            check("Edited Merchant" in page.inner_text("#ledgerBody"), "encrypted transaction edits survive reload")

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

            # --- manual expense entry -------------------------------------
            print("\n  Manual expense entry")
            invalid = page.evaluate("""() => {
                const name = (v) => { try { validateExpenseName(v); return null; } catch (e) { return e.message; } };
                const amt = (v) => { try { validateExpenseAmount(v); return null; } catch (e) { return e.message; } };
                const cat = (v) => { try { validateExpenseCategory(v); return null; } catch (e) { return e.message; } };
                return {
                    emptyName: name(''), whitespaceName: name('   '), nullName: name(null),
                    arrayName: name([]), objectName: name({}), tooLongName: name('a'.repeat(121)),
                    okName: name("Bob's Burgers"),
                    emptyAmount: amt(''), zeroAmount: amt('0'), negativeAmount: amt('-1'),
                    nanAmount: amt('NaN'), infAmount: amt('Infinity'), expAmount: amt('1e10'),
                    hexAmount: amt('0x20'), currencyAmount: amt('$10'), commaAmount: amt('1,000.00'),
                    precisionAmount: amt('12.345'), boolAmount: amt(true), arrayAmount: amt([]),
                    tooBigAmount: amt('1000000000.00'), okAmount: amt('12.34'),
                    forgedCategory: cat('<script>alert(1)</script>'), okCategory: cat('Groceries'),
                    blankCategory: cat(''),
                };
            }""")
            check(invalid["emptyName"] is not None, "empty expense name rejected")
            check(invalid["whitespaceName"] is not None, "whitespace-only expense name rejected")
            check(invalid["nullName"] is not None, "null expense name rejected")
            check(invalid["arrayName"] is not None, "array expense name rejected")
            check(invalid["objectName"] is not None, "object expense name rejected")
            check(invalid["tooLongName"] is not None, "121-character expense name rejected")
            check(invalid["okName"] is None, "apostrophe in a legitimate name is accepted", str(invalid["okName"]))
            check(invalid["emptyAmount"] is not None, "empty amount rejected")
            check(invalid["zeroAmount"] is not None, "zero amount rejected")
            check(invalid["negativeAmount"] is not None, "negative amount rejected")
            check(invalid["nanAmount"] is not None, "NaN amount rejected")
            check(invalid["infAmount"] is not None, "Infinity amount rejected")
            check(invalid["expAmount"] is not None, "exponent-notation amount rejected")
            check(invalid["hexAmount"] is not None, "hex amount rejected")
            check(invalid["currencyAmount"] is not None, "currency-symbol amount rejected")
            check(invalid["commaAmount"] is not None, "thousands-separator amount rejected")
            check(invalid["precisionAmount"] is not None, "3-decimal amount rejected outright, not silently rounded")
            check(invalid["boolAmount"] is not None, "boolean amount rejected (bool is not treated as numeric)")
            check(invalid["arrayAmount"] is not None, "array amount rejected")
            check(invalid["tooBigAmount"] is not None, "amount above the configured maximum rejected")
            check(invalid["okAmount"] is None, "well-formed amount accepted", str(invalid["okAmount"]))
            check(invalid["forgedCategory"] is not None, "arbitrary/forged category string rejected")
            check(invalid["okCategory"] is None, "allowlisted category accepted")
            check(invalid["blankCategory"] is None, "blank category accepted as 'no category'")

            records_before = int(page.inner_text("#statRecords"))
            before_manual_requests = list(request_bodies)
            page.click("#addExpenseBtn")
            page.wait_for_selector("#addExpenseDialog[open]")
            xss_name = "<img src=x onerror=alert(1)>"
            page.fill("#addExpenseName", xss_name)
            page.fill("#addExpenseAmount", "45.67")
            page.select_option("#addExpenseCategory", label="Dining")
            fired = []
            page.once("dialog", lambda d: (fired.append(d.message), d.dismiss()))
            page.click("#addExpenseForm button[type=submit]")
            page.wait_for_selector("#addExpenseDialog", state="hidden")
            check(int(page.inner_text("#statRecords")) == records_before + 1, "manual expense adds exactly one record")
            check(not fired, "no alert() fired from the injected expense name", str(fired))
            ledger_text = page.inner_text("#ledgerBody")
            check(xss_name in ledger_text, "XSS-payload expense name renders as literal visible text")
            check(page.query_selector("#ledgerBody img") is None, "payload never became a live <img> element")
            check(
                all(xss_name not in body for body in request_bodies[len(before_manual_requests):]),
                "manual expense name reaches the server only as ciphertext, never plaintext",
            )
            manual_entry = page.evaluate("() => { const t = TXNS.find(x => x.merchant.includes('img src')); return t && {source: t.source, category: t.category, account: t.account}; }")
            check(manual_entry and manual_entry["source"] == "manual", "manual entry is tagged source=manual, not forgeable as simplefin/fakebank")
            check(manual_entry and manual_entry["category"] == "Dining", "selected category is preserved")
            check("Manual entries" in page.inner_text("#accounts"), "manual entries show as their own account group, not mixed into a bank's")

            # Two deliberate, separately-submitted identical expenses must
            # both be kept -- no content-based deduplication.
            for _ in range(2):
                page.click("#addExpenseBtn")
                page.wait_for_selector("#addExpenseDialog[open]")
                page.fill("#addExpenseName", "Coffee")
                page.fill("#addExpenseAmount", "3.50")
                page.click("#addExpenseForm button[type=submit]")
                page.wait_for_selector("#addExpenseDialog", state="hidden")
            check(
                int(page.inner_text("#statRecords")) == records_before + 3,
                "two deliberately identical manual expenses are both kept, not deduplicated",
            )

            # A double-click / resubmit race must not create two records
            # from one logical submission.
            page.click("#addExpenseBtn")
            page.wait_for_selector("#addExpenseDialog[open]")
            page.fill("#addExpenseName", "Race condition test")
            page.fill("#addExpenseAmount", "9.99")
            page.evaluate("""() => {
                const form = document.getElementById('addExpenseForm');
                form.dispatchEvent(new Event('submit', { cancelable: true }));
                form.dispatchEvent(new Event('submit', { cancelable: true }));
            }""")
            page.wait_for_selector("#addExpenseDialog", state="hidden")
            page.wait_for_timeout(500)
            check(
                int(page.inner_text("#statRecords")) == records_before + 4,
                "a double-submit race is not turned into two records by the in-flight guard",
            )

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

    total = check.passed + check.failed
    color = "32" if not check.failed else "31"
    print(f"\n\033[{color}m{check.passed}/{total} passing\033[0m")
    print(f"screenshots -> {SHOTS}/\n")
    return 0 if not check.failed else 1


if __name__ == "__main__":
    sys.exit(main())
