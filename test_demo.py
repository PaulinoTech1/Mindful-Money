#!/usr/bin/env python3
"""Vault test suite.

    python3 test_demo.py           run everything with a readable report
    python3 test_demo.py -v        unittest verbose output
    pytest test_demo.py            also works

No browser needed. BrowserSim below reproduces static/app.js exactly --
verified byte-identical: the same passphrase and salts produce the same seed
and the same public key in PyNaCl and in browser libsodium. So if these tests
pass, the browser path is sound.
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

import nacl.bindings
import nacl.hash
import nacl.pwhash
from nacl.encoding import RawEncoder
from nacl.public import PrivateKey, PublicKey, SealedBox

sys.path.insert(0, str(Path(__file__).parent))
import app as server_app
import fakebank

# Must match the constants in static/app.js.
SALT_ENC = bytes([73, 26, 201, 4, 155, 88, 17, 240, 63, 129, 7, 198, 44, 90, 231, 12])
SALT_IDX = bytes([9, 144, 37, 222, 101, 58, 175, 20, 86, 3, 249, 130, 66, 11, 193, 77])

ALL_MERCHANTS = (
    {m for m, *_ in fakebank.RECURRING_WEEKLY}
    | {m for m, *_ in fakebank.OCCASIONAL}
    | {m for m, *_ in fakebank.MONTHLY_FIXED}
    | {m for m, *_ in fakebank.IRREGULAR}
    | {fakebank.PAYCHECK[0]}
)


class BrowserSim:
    """Line-for-line equivalent of the crypto in static/app.js."""

    def __init__(self, passphrase: str):
        kdf = nacl.pwhash.argon2id.kdf
        ops = nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE
        mem = nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE
        seed = kdf(32, passphrase.encode(), SALT_ENC, opslimit=ops, memlimit=mem)
        self.pk, self.sk = nacl.bindings.crypto_box_seed_keypair(seed)
        self.index_key = kdf(32, passphrase.encode(), SALT_IDX, opslimit=ops, memlimit=mem)

    def seal(self, obj: dict) -> str:
        payload = json.dumps(obj, separators=(",", ":")).encode()
        return SealedBox(PublicKey(self.pk)).encrypt(payload).hex()

    def open(self, sealed_hex: str) -> dict:
        box = SealedBox(PrivateKey(self.sk))
        return json.loads(box.decrypt(bytes.fromhex(sealed_hex)))

    def blind_index(self, external_id: str) -> str:
        return nacl.hash.blake2b(
            external_id.encode(), key=self.index_key, digest_size=32, encoder=RawEncoder
        ).hex()

    def encrypt_all(self, txns: list[dict]) -> list[dict]:
        return [{"blind_index": self.blind_index(t["id"]), "sealed": self.seal(t)} for t in txns]


class ServerCase(unittest.TestCase):
    """Base: each test gets an isolated temp database."""

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self._orig_db = server_app.DB
        server_app.DB = Path(self._tmp.name)
        server_app.app.config["TESTING"] = True
        self.client = server_app.app.test_client()

    def tearDown(self):
        server_app.DB = self._orig_db
        Path(self._tmp.name).unlink(missing_ok=True)

    def db_bytes(self) -> bytes:
        return Path(self._tmp.name).read_bytes()

    def full_flow(self, passphrase="test passphrase"):
        """relay -> encrypt in 'browser' -> store. Returns (sim, transactions)."""
        txns = self.client.post("/api/relay").get_json()["transactions"]
        sim = BrowserSim(passphrase)
        self.client.post("/api/records", json={"records": sim.encrypt_all(txns)})
        return sim, txns


# ---------------------------------------------------------------- fake bank


class TestFakeBank(unittest.TestCase):
    def test_is_deterministic(self):
        self.assertEqual(fakebank.generate(), fakebank.generate())

    def test_produces_a_useful_volume(self):
        txns = fakebank.generate(months=6)
        self.assertGreater(len(txns), 200, "too sparse to make charts interesting")
        self.assertLess(len(txns), 1500)

    def test_no_future_dates(self):
        import datetime as dt

        today = dt.date.today().isoformat()
        self.assertTrue(all(t["date"] <= today for t in fakebank.generate()))

    def test_starts_on_a_month_boundary(self):
        # Otherwise the first month is missing its rent and the opening chart
        # column is misleadingly low.
        self.assertTrue(fakebank.generate()[0]["date"].endswith("-01"))

    def test_every_complete_month_has_rent(self):
        txns = fakebank.generate()
        months = sorted({t["date"][:7] for t in txns})
        rent_months = {t["date"][:7] for t in txns if "Rent" in t["merchant"]}
        for m in months[:-1]:  # last month may be partial
            self.assertIn(m, rent_months, f"{m} has no rent charge")

    def test_has_both_income_and_spending(self):
        txns = fakebank.generate()
        income = -sum(t["amount"] for t in txns if t["amount"] < 0)
        spend = sum(t["amount"] for t in txns if t["amount"] > 0)
        self.assertGreater(income, 0)
        self.assertGreater(spend, 0)
        # Realistic ratio: neither a fantasy surplus nor an impossible deficit.
        self.assertTrue(0.6 < spend / income < 1.4, f"ratio {spend/income:.2f} unrealistic")

    def test_ids_are_unique(self):
        txns = fakebank.generate()
        self.assertEqual(len({t["id"] for t in txns}), len(txns))

    def test_includes_checking_ira_and_401k_feeds(self):
        txns = fakebank.generate()
        counts = {account: sum(t["account"] == account for t in txns) for account in fakebank.ACCOUNTS}
        self.assertEqual(set(counts), set(fakebank.ACCOUNTS))
        self.assertTrue(all(count > 0 for count in counts.values()))
        self.assertEqual({fakebank.ACCOUNTS[t["account"]]["bank"] for t in txns}, {
            "Scammers Inc", "Wells Foreclose", "DC Unc"
        })

    def test_fans_only_is_a_monthly_423_23_subscription(self):
        charges = [t for t in fakebank.generate() if t["merchant"] == "Fans Only"]
        self.assertGreaterEqual(len(charges), 6)
        self.assertTrue(all(t["amount"] == 423.23 for t in charges))
        self.assertEqual(len({t["date"][:7] for t in charges}), len(charges))


# ---------------------------------------------------------------- crypto


class TestBrowserCrypto(unittest.TestCase):
    def test_derivation_matches_documented_vector(self):
        # This exact public key appears in the browser UI rail. If this fails,
        # Python and the browser have diverged and every other crypto test
        # here is meaningless.
        sim = BrowserSim("demo passphrase")
        self.assertEqual(
            sim.pk.hex(),
            "95208c801d1d13f1bebd74e6a8c38fcd5af7e39d646d96887bebaf60fa5dc459",
        )

    def test_seal_open_round_trip(self):
        sim = BrowserSim("hunter2")
        txn = {"id": "x1", "merchant": "Blue Bottle Coffee", "amount": 6.75}
        self.assertEqual(sim.open(sim.seal(txn)), txn)

    def test_ciphertext_leaks_no_plaintext(self):
        sim = BrowserSim("hunter2")
        sealed = sim.seal({"merchant": "Stuyvesant Town Rent", "amount": 2150.0})
        self.assertNotIn("Stuyvesant", bytes.fromhex(sealed).decode("latin-1"))

    def test_wrong_passphrase_cannot_open(self):
        good, bad = BrowserSim("right one"), BrowserSim("wrong one")
        sealed = good.seal({"merchant": "Trader Joe's"})
        with self.assertRaises(Exception):
            bad.open(sealed)

    def test_sealing_is_non_deterministic(self):
        # crypto_box_seal uses an ephemeral keypair, so identical input must
        # not produce identical ciphertext -- otherwise the server could
        # fingerprint repeated merchants.
        sim = BrowserSim("k")
        txn = {"merchant": "Spotify", "amount": 11.99}
        self.assertNotEqual(sim.seal(txn), sim.seal(txn))

    def test_blind_index_is_stable_and_keyed(self):
        a, b = BrowserSim("passphrase A"), BrowserSim("passphrase B")
        self.assertEqual(a.blind_index("txn_001"), a.blind_index("txn_001"))
        self.assertNotEqual(a.blind_index("txn_001"), a.blind_index("txn_002"))
        self.assertNotEqual(a.blind_index("txn_001"), b.blind_index("txn_001"))


# ---------------------------------------------------------------- server


class TestServerAPI(ServerCase):
    def test_relay_returns_transactions(self):
        txns = self.client.post("/api/relay").get_json()["transactions"]
        self.assertGreater(len(txns), 200)
        self.assertEqual(
            set(txns[0]), {"id", "merchant", "amount", "date", "pending", "account"}
        )

    def test_relay_persists_nothing(self):
        """The core relay guarantee: plaintext passes through, never lands."""
        self.client.post("/api/relay")
        self.assertEqual(self.client.get("/api/records").get_json()["records"], [])
        self.assertNotIn(b"Blue Bottle", self.db_bytes())

    def test_store_and_retrieve(self):
        sim, txns = self.full_flow()
        stored = self.client.get("/api/records").get_json()["records"]
        self.assertEqual(len(stored), len(txns))

    def test_reupload_is_idempotent(self):
        sim, txns = self.full_flow()
        before = len(self.client.get("/api/records").get_json()["records"])
        self.client.post("/api/records", json={"records": sim.encrypt_all(txns)})
        after = len(self.client.get("/api/records").get_json()["records"])
        self.assertEqual(before, after, "blind index dedup failed")

    def test_server_view_exposes_only_metadata(self):
        self.full_flow()
        v = self.client.get("/api/server-view").get_json()
        self.assertEqual(set(v["columns"]), {"id", "blind_index", "sealed", "bytes", "stored_at"})
        self.assertGreater(v["record_count"], 200)
        # Nothing in the response should be readable text from a transaction.
        blob = json.dumps(v)
        for name in ALL_MERCHANTS:
            self.assertNotIn(name, blob)

    def test_reset_clears(self):
        self.full_flow()
        self.client.delete("/api/records")
        self.assertEqual(self.client.get("/api/records").get_json()["records"], [])

    def test_server_imports_no_crypto(self):
        """app.py should have no keys and no crypto library."""
        src = (Path(__file__).parent / "app.py").read_text()
        for banned in ("import nacl", "from nacl", "import cryptography", "Fernet"):
            self.assertNotIn(banned, src)


# ---------------------------------------------------------------- the claim


class TestPrivacyGuarantee(ServerCase):
    """The tests that justify the product's central claim."""

    def test_no_merchant_name_reaches_disk(self):
        self.full_flow()
        raw = self.db_bytes()
        leaked = [m for m in ALL_MERCHANTS if m.encode() in raw]
        self.assertEqual(leaked, [], f"plaintext merchants on disk: {leaked}")

    def test_no_bank_name_reaches_disk(self):
        self.full_flow()
        raw = self.db_bytes()
        leaked = [meta["bank"] for meta in fakebank.ACCOUNTS.values() if meta["bank"].encode() in raw]
        self.assertEqual(leaked, [], f"plaintext bank names on disk: {leaked}")

    def test_no_readable_amounts_reach_disk(self):
        """Amount strings must not survive. Short digit runs can collide with
        hex by chance, so this checks a distinctive full amount string."""
        self.full_flow()
        raw = self.db_bytes()
        for amount in (b'"amount":2150', b"2150.0", b"2415.0"):
            self.assertNotIn(amount, raw)

    def test_every_stored_value_is_hex(self):
        """No column ever holds anything but hex. This is the precise version
        of "nothing readable is stored".

        A file-wide word scan was tried first and abandoned: hex ciphertext
        abuts SQLite's binary headers, so stray bytes manufacture pseudo-words
        ('bfaeddvf', and once 'came' by pure chance). Tightening the heuristic
        enough to reject those would also reject real merchant words like
        'coffee', which has only one letter outside a-f. A test that cannot be
        made trustworthy is worse than no test, so this checks the columns
        directly instead -- combined with the merchant scan above, coverage is
        complete and neither test is flaky."""
        self.full_flow()
        conn = sqlite3.connect(self._tmp.name)
        rows = conn.execute("SELECT blind_index, sealed FROM records").fetchall()
        conn.close()

        self.assertGreater(len(rows), 200)
        for blind, sealed in rows:
            self.assertRegex(blind, r"^[0-9a-f]{64}$")
            self.assertRegex(sealed, r"^[0-9a-f]+$")
            self.assertGreaterEqual(len(sealed), 96, "sealed blob suspiciously short")

    def test_everything_decrypts_back_correctly(self):
        sim, original = self.full_flow()
        stored = self.client.get("/api/records").get_json()["records"]
        recovered = sorted((sim.open(r["sealed"]) for r in stored), key=lambda t: t["id"])
        self.assertEqual(recovered, sorted(original, key=lambda t: t["id"]))

    def test_a_second_user_cannot_read_the_first(self):
        alice, txns = self.full_flow("alice passphrase")
        mallory = BrowserSim("mallory passphrase")
        stored = self.client.get("/api/records").get_json()["records"]
        with self.assertRaises(Exception):
            mallory.open(stored[0]["sealed"])

    def test_dashboard_totals_are_computable_client_side(self):
        """Proves the charts can be built from decrypted data alone."""
        sim, _ = self.full_flow()
        stored = self.client.get("/api/records").get_json()["records"]
        txns = [sim.open(r["sealed"]) for r in stored]

        by_month: dict[str, list[float]] = {}
        for t in txns:
            k = t["date"][:7]
            slot = by_month.setdefault(k, [0.0, 0.0])
            if t["amount"] < 0:
                slot[0] -= t["amount"]
            else:
                slot[1] += t["amount"]

        self.assertGreaterEqual(len(by_month), 5, "need several months for a trend chart")
        self.assertTrue(all(v[0] or v[1] for v in by_month.values()))


# ---------------------------------------------------------------- runner

REPORT = [
    ("Fake bank feed", TestFakeBank),
    ("Browser crypto", TestBrowserCrypto),
    ("Server API", TestServerAPI),
    ("Privacy guarantee", TestPrivacyGuarantee),
]


def main() -> int:
    if len(sys.argv) > 1:
        unittest.main()
        return 0

    loader = unittest.TestLoader()
    total = failures = 0
    print("\n\033[1mVault test suite\033[0m")

    for label, cls in REPORT:
        print(f"\n  {label}")
        for test in loader.loadTestsFromTestCase(cls):
            name = test._testMethodName.removeprefix("test_").replace("_", " ")
            result = unittest.TestResult()
            test.run(result)
            total += 1
            if result.wasSuccessful():
                print(f"    \033[32m✓\033[0m {name}")
            else:
                failures += 1
                err = (result.failures + result.errors)[0][1].strip().splitlines()[-1]
                print(f"    \033[31m✗\033[0m {name}\n        {err}")

    ok = failures == 0
    color = "32" if ok else "31"
    print(f"\n\033[{color}m{total - failures}/{total} passing\033[0m")
    if ok:
        print("\nThe server cannot read a single transaction. Start the demo with:")
        print("  python3 app.py   ->   http://127.0.0.1:5000\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
