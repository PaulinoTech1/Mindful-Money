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
import os
import re
import sys
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

import nacl.bindings
import nacl.hash
import nacl.pwhash
from nacl.encoding import RawEncoder
from nacl.public import PrivateKey, PublicKey, SealedBox
from sqlalchemy import create_engine, text

sys.path.insert(0, str(Path(__file__).parent))
import app as server_app
import db as dbmod
import fakebank
import models

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


TEST_DATABASE_URL = os.environ.get(
    "VAULT_TEST_DATABASE_URL",
    "postgresql+psycopg://vault:vault_dev_only_password@localhost:5432/vault_test",
)
_ALL_TABLES = (
    "records", "vault_identity", "passkey_credentials", "server_sessions",
    "webauthn_challenges", "rate_limits", "audit_events",
)


def whole_database_scan(engine) -> bytes:
    """Postgres analogue of reading the whole SQLite file as raw bytes:
    every text/bytea/jsonb cell across every table, concatenated. Used by
    the privacy tests to assert plaintext never lands anywhere."""
    with engine.connect() as conn:
        columns = conn.execute(text(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema='public' AND data_type IN "
            "('text','character varying','character','bytea','jsonb','json')"
        )).fetchall()
        chunks = []
        for table, column in columns:
            for (value,) in conn.execute(text(f'SELECT "{column}" FROM "{table}"')).fetchall():
                if value is not None:
                    chunks.append(value if isinstance(value, (bytes, bytearray)) else str(value).encode())
        return b"".join(chunks)


_TEST_ENGINE = create_engine(TEST_DATABASE_URL, future=True)
models.Base.metadata.create_all(_TEST_ENGINE)
dbmod.rebind(TEST_DATABASE_URL)


class ServerCase(unittest.TestCase):
    """Base: each test gets an isolated, truncated Postgres database.

    Module-level engine setup (above), not setUpClass/tearDownClass: this
    repo's custom test runner (see main() below) calls .run() directly on
    individual TestCase instances rather than through a TestSuite, so
    class-level fixtures never fire. Module-level code always runs exactly
    once regardless of how the suite is invoked (custom runner, plain
    unittest, or pytest), which is what class fixtures would have relied on.
    """

    _engine = _TEST_ENGINE

    def setUp(self):
        with self._engine.begin() as conn:
            conn.execute(text(f"TRUNCATE TABLE {','.join(_ALL_TABLES)} RESTART IDENTITY CASCADE"))
        server_app.app.config["TESTING"] = True
        self.client = server_app.app.test_client()

    def raw_conn(self):
        return self._engine.connect()

    def db_bytes(self) -> bytes:
        return whole_database_scan(self._engine)

    def security_headers(self):
        token = self.client.get("/api/session").get_json()["csrf_token"]
        return {"Origin": server_app.ORIGIN, "X-CSRF-Token": token}

    def unsafe(self, method, path, **kwargs):
        headers = {**self.security_headers(), **kwargs.pop("headers", {})}
        return getattr(self.client, method)(path, headers=headers, **kwargs)

    def full_flow(self, passphrase="test passphrase"):
        """relay -> encrypt in 'browser' -> store. Returns (sim, transactions)."""
        txns = self.unsafe("post", "/api/relay").get_json()["transactions"]
        sim = BrowserSim(passphrase)
        self.unsafe("post", "/api/records", json={"records": sim.encrypt_all(txns)})
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
            "Scammers Inc", "Wells Foreclosure", "DC Unc"
        })
        self.assertTrue(all(t["bank"] == fakebank.ACCOUNTS[t["account"]]["bank"] for t in txns))
        self.assertTrue(all(t["account_label"] == fakebank.ACCOUNTS[t["account"]]["label"] for t in txns))
        self.assertTrue(all(t["account_type"] == fakebank.ACCOUNTS[t["account"]]["type"] for t in txns))

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
        txns = self.unsafe("post", "/api/relay").get_json()["transactions"]
        self.assertGreater(len(txns), 200)
        self.assertEqual(
            set(txns[0]), {"id", "merchant", "amount", "date", "pending", "account",
                           "bank", "account_label", "account_type", "source"}
        )

    def test_relay_persists_nothing(self):
        """The core relay guarantee: plaintext passes through, never lands."""
        self.unsafe("post", "/api/relay")
        self.assertEqual(self.client.get("/api/records").get_json()["records"], [])
        self.assertNotIn(b"Blue Bottle", self.db_bytes())

    def test_store_and_retrieve(self):
        sim, txns = self.full_flow()
        stored = self.client.get("/api/records").get_json()["records"]
        self.assertEqual(len(stored), len(txns))

    def test_reupload_is_idempotent(self):
        sim, txns = self.full_flow()
        before = len(self.client.get("/api/records").get_json()["records"])
        self.unsafe("post", "/api/records", json={"records": sim.encrypt_all(txns)})
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
        self.unsafe("delete", "/api/records")
        self.assertEqual(self.client.get("/api/records").get_json()["records"], [])

    def test_server_imports_no_crypto(self):
        """app.py should have no keys and no crypto library."""
        src = (Path(__file__).parent / "app.py").read_text()
        for banned in ("import nacl", "from nacl", "import cryptography", "Fernet"):
            self.assertNotIn(banned, src)


class TestOptionalPasskeys(ServerCase):
    def csrf(self):
        return self.client.get("/api/session").get_json()["csrf_token"]

    def headers(self):
        return {"Origin": server_app.ORIGIN, "X-CSRF-Token": self.csrf()}

    def set_required(self, required=True):
        self.client.get("/api/passkeys/status")
        with server_app.app.app_context():
            table = models.VaultIdentity.__table__
            server_app.db().execute(table.update().where(table.c.id == 1).values(passkey_required=required))
            server_app.db().commit()

    def authenticate(self, unlocked=False):
        with self.client.session_transaction() as sess:
            sess["identity_id"] = 1
            sess["authenticated_at"] = __import__("time").time()
            sess["vault_unlocked"] = unlocked

    def test_passphrase_only_mode_preserves_records_api(self):
        self.assertEqual(self.client.get("/api/records").status_code, 200)
        self.assertEqual(self.client.post("/api/records", json={"records": []}, headers=self.headers()).status_code, 200)

    def test_protected_record_and_metadata_apis_require_authentication(self):
        self.set_required()
        for method, path in (("get", "/api/records"), ("post", "/api/records"), ("post", "/api/relay"), ("get", "/api/server-view"), ("delete", "/api/records")):
            response = getattr(self.client, method)(path, json={} if method == "post" else None, headers=self.headers() if method in {"post", "delete"} else None)
            self.assertEqual(response.status_code, 401, path)

    def test_enrollment_requires_unlocked_vault(self):
        response = self.client.post("/api/passkeys/register/options", headers=self.headers())
        self.assertEqual(response.status_code, 403)

    def test_failed_registration_does_not_enable_protection_and_is_single_use(self):
        with self.client.session_transaction() as sess:
            sess["vault_unlocked"] = True
        self.assertEqual(self.client.post("/api/passkeys/register/options", headers=self.headers()).status_code, 200)
        with patch.object(server_app, "verify_registration_response", side_effect=server_app.WebAuthnException("bad")):
            first = self.client.post("/api/passkeys/register/verify", json={"credential": {}}, headers=self.headers())
        second = self.client.post("/api/passkeys/register/verify", json={"credential": {}}, headers=self.headers())
        self.assertEqual((first.status_code, second.status_code), (400, 400))
        self.assertFalse(self.client.get("/api/passkeys/status").get_json()["passkey_required"])

    def test_expired_challenge_is_rejected(self):
        with self.client.session_transaction() as sess:
            sess["vault_unlocked"] = True
        self.client.post("/api/passkeys/register/options", headers=self.headers())
        with server_app.app.app_context():
            table = models.WebAuthnChallenge.__table__
            server_app.db().execute(table.update().values(expires_at=1))
            server_app.db().commit()
        self.assertEqual(self.client.post("/api/passkeys/register/verify", json={}, headers=self.headers()).status_code, 400)

    def test_successful_registration_commits_before_enforcement(self):
        with self.client.session_transaction() as sess:
            sess["vault_unlocked"] = True
        self.client.post("/api/passkeys/register/options", headers=self.headers())
        verified = SimpleNamespace(credential_id=b"cred", credential_public_key=b"public", sign_count=0, credential_device_type="single_device", credential_backed_up=False)
        payload = {"credential": {"response": {"transports": ["internal"]}}, "label": "Laptop"}
        with patch.object(server_app, "verify_registration_response", return_value=verified):
            response = self.client.post("/api/passkeys/register/verify", json=payload, headers=self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.client.get("/api/passkeys/status").get_json()["passkey_required"])

    def test_unknown_credential_and_authentication_challenge_single_use(self):
        with server_app.app.app_context():
            table = models.PasskeyCredential.__table__
            server_app.db().execute(table.insert().values(identity_id=1, credential_id=b"cred", credential_public_key=b"\x01", label="Key"))
            server_app.db().commit()
        self.client.post("/api/passkeys/login/options", headers=self.headers())
        first = self.client.post("/api/passkeys/login/verify", json={"credential": {"id": "missing"}}, headers=self.headers())
        second = self.client.post("/api/passkeys/login/verify", json={"credential": {"id": "missing"}}, headers=self.headers())
        self.assertEqual((first.status_code, second.status_code), (400, 400))

    def test_logout_invalidates_session(self):
        self.set_required(); self.authenticate()
        token = self.csrf()
        self.assertEqual(self.client.post("/api/logout", headers={"Origin": server_app.ORIGIN, "X-CSRF-Token": token}).status_code, 200)
        self.assertEqual(self.client.get("/api/records").status_code, 401)

    def test_last_passkey_cannot_be_removed(self):
        self.set_required(); self.authenticate(unlocked=True)
        with server_app.app.app_context():
            table = models.PasskeyCredential.__table__
            server_app.db().execute(table.insert().values(identity_id=1, credential_id=b"cred", credential_public_key=b"\x01", label="Only key"))
            server_app.db().commit()
        response = self.client.delete("/api/passkeys/Y3JlZA", headers=self.headers())
        self.assertEqual(response.status_code, 409)

    def test_disable_requires_authentication_unlock_and_confirmation(self):
        self.set_required()
        self.assertEqual(self.client.post("/api/passkeys/disable", json={"confirm_unlocked": True}, headers=self.headers()).status_code, 401)
        self.authenticate(unlocked=True)
        self.assertEqual(self.client.post("/api/passkeys/disable", json={}, headers=self.headers()).status_code, 400)
        self.assertEqual(self.client.post("/api/passkeys/disable", json={"confirm_unlocked": True}, headers=self.headers()).status_code, 200)
        self.assertEqual(self.client.get("/api/records").status_code, 200)

    def test_csrf_rejects_protected_writes(self):
        self.set_required(); self.authenticate()
        self.assertEqual(self.client.post("/api/records", json={"records": []}, headers={"Origin": server_app.ORIGIN}).status_code, 403)

    def test_sessions_contain_no_passphrase_or_key(self):
        self.authenticate(unlocked=True)
        with self.client.session_transaction() as sess:
            serialized = repr(dict(sess)).lower()
        self.assertNotIn("passphrase", serialized)
        self.assertNotIn("private", serialized)
        self.assertNotIn("vault_key", serialized)


class TestSecurityIncrement(ServerCase):
    def setUp(self):
        super().setUp()
        self._upload_limit = server_app.RATE_LIMITS["upload"]
        server_app.RATE_LIMITS["upload"] = (100, 60)

    def tearDown(self):
        server_app.RATE_LIMITS["upload"] = self._upload_limit
        super().tearDown()

    def test_cookie_is_opaque_and_session_is_server_side(self):
        self.client.get("/api/session")
        cookie = self.client.get_cookie(server_app.COOKIE_NAME)
        self.assertRegex(cookie.value, r"^[A-Za-z0-9_-]{43}$")
        self.assertNotIn("csrf", cookie.value.lower())
        with self.raw_conn() as conn:
            row = conn.execute(text("SELECT csrf_token,session_id_hash FROM server_sessions")).fetchone()
        self.assertIsNotNone(row)
        self.assertNotEqual(row[1], cookie.value)

    def test_expired_session_cookie_creates_a_new_session(self):
        first = self.client.get("/api/session").get_json()["csrf_token"]
        with self._engine.begin() as conn:
            conn.execute(text("UPDATE server_sessions SET expires_at=0"))
        second = self.client.get("/api/session").get_json()["csrf_token"]
        self.assertNotEqual(first, second)

    def test_logout_revokes_and_old_cookie_cannot_be_reused(self):
        token = self.client.get("/api/session").get_json()["csrf_token"]
        old = self.client.get_cookie(server_app.COOKIE_NAME).value
        response = self.client.post("/api/logout", headers={"Origin": server_app.ORIGIN, "X-CSRF-Token": token})
        self.assertEqual(response.status_code, 200)
        replay = server_app.app.test_client()
        replay.set_cookie(server_app.COOKIE_NAME, old)
        replacement = replay.get("/api/session")
        self.assertNotEqual(replacement.get_json()["csrf_token"], token)

    def test_every_unsafe_endpoint_rejects_missing_origin_or_csrf(self):
        token = self.client.get("/api/session").get_json()["csrf_token"]
        endpoints = [
            ("post", "/api/relay", None), ("post", "/api/records", {"records": []}),
            ("delete", "/api/records", None), ("post", "/api/vault/unlocked", None),
            ("post", "/api/logout", None), ("post", "/api/passkeys/login/options", None),
        ]
        for method, path, body in endpoints:
            kwargs = {"json": body} if body is not None else {}
            self.assertEqual(getattr(self.client, method)(path, headers={"X-CSRF-Token": token}, **kwargs).status_code, 403, path)
            self.assertEqual(getattr(self.client, method)(path, headers={"Origin": server_app.ORIGIN}, **kwargs).status_code, 403, path)

    def test_origin_must_match_exactly(self):
        token = self.client.get("/api/session").get_json()["csrf_token"]
        hostile = ["null", "https://localhost:5000", "http://localhost.evil:5000", "http://localhost:5001", "http://user@localhost:5000", "http://localhost:5000/path"]
        for origin in hostile:
            r = self.client.post("/api/relay", headers={"Origin": origin, "X-CSRF-Token": token})
            self.assertEqual(r.status_code, 403, origin)
        self.assertEqual(self.unsafe("post", "/api/relay").status_code, 200)

    def test_development_accepts_equivalent_loopback_origin(self):
        token = self.client.get("/api/session").get_json()["csrf_token"]
        response = self.client.post("/api/relay", headers={
            "Origin": "http://127.0.0.1:5000", "X-CSRF-Token": token,
        })
        self.assertEqual(response.status_code, 200)

    def test_upload_validation_is_atomic(self):
        good = {"blind_index": "a" * 64, "sealed": "b" * 96}
        invalid_payloads = [
            [], {}, {"records": {}}, {"records": [None]},
            {"records": [{}]}, {"records": [{**good, "extra": 1}]},
            {"records": [{**good, "blind_index": "A" * 64}]},
            {"records": [{**good, "blind_index": "a" * 63}]},
            {"records": [{**good, "blind_index": "g" * 64}]},
            {"records": [{**good, "sealed": "b" * 97}]},
            {"records": [{**good, "sealed": "B" * 96}]},
            {"records": [{**good, "sealed": "z" * 96}]},
            {"records": [{**good, "sealed": "b" * 94}]},
            {"records": [good, good]},
            {"records": [good, {"blind_index": "c" * 64, "sealed": "bad"}]},
        ]
        for payload in invalid_payloads:
            r = self.unsafe("post", "/api/records", json=payload)
            self.assertIn(r.status_code, {400, 413})
            self.assertEqual(self.client.get("/api/records").get_json()["records"], [])
        malformed = self.unsafe("post", "/api/records", data="{", content_type="application/json")
        self.assertEqual(malformed.status_code, 400)
        non_json = self.unsafe("post", "/api/records", data="{}", content_type="text/plain")
        self.assertEqual(non_json.status_code, 400)

    def test_valid_upload_and_reupload(self):
        record = {"blind_index": "a" * 64, "sealed": "b" * 96}
        self.assertEqual(self.unsafe("post", "/api/records", json={"records": [record]}).status_code, 200)
        self.assertEqual(self.unsafe("post", "/api/records", json={"records": [record]}).status_code, 200)
        self.assertEqual(len(self.client.get("/api/records").get_json()["records"]), 1)

    def test_batch_and_total_quota_limits(self):
        record = {"blind_index": "a" * 64, "sealed": "b" * 96}
        with patch.object(server_app, "MAX_RECORDS_PER_BATCH", 0):
            self.assertEqual(self.unsafe("post", "/api/records", json={"records": [record]}).status_code, 413)
        with patch.object(server_app, "MAX_TOTAL_RECORDS", 0):
            self.assertEqual(self.unsafe("post", "/api/records", json={"records": [record]}).status_code, 409)
        self.assertEqual(self.client.get("/api/records").get_json()["records"], [])

    def test_request_body_limit_returns_json_413(self):
        old = server_app.app.config["MAX_CONTENT_LENGTH"]
        server_app.app.config["MAX_CONTENT_LENGTH"] = 64
        try:
            response = self.unsafe("post", "/api/records", data="{" + "x" * 100 + "}", content_type="application/json")
            self.assertEqual(response.status_code, 413)
            self.assertIn("error", response.get_json())
        finally:
            server_app.app.config["MAX_CONTENT_LENGTH"] = old

    def test_challenge_is_server_side_and_bound_to_session(self):
        with self.client.session_transaction() as sess:
            sess["vault_unlocked"] = True
        self.client.post("/api/passkeys/register/options", headers=self.security_headers())
        with self.raw_conn() as conn:
            row = conn.execute(text("SELECT kind,challenge,session_id_hash,consumed_at FROM webauthn_challenges")).fetchone()
            sess_hash = conn.execute(text("SELECT session_id_hash FROM server_sessions WHERE active_ceremony_id IS NOT NULL")).fetchone()[0]
        self.assertEqual(row[0], "registration")
        self.assertEqual(row[2], sess_hash)
        self.assertIsNone(row[3])

    def test_runtime_javascript_is_the_artifact_served_and_tested(self):
        html = self.client.get("/").get_data(as_text=True)
        self.assertIn('/static/app.js', html)
        runtime = self.client.get("/static/app.js").get_data(as_text=True)
        self.assertIn("const apiFetch", runtime)
        self.assertIn('id="resetPassphraseBtn"', html)
        self.assertIn("async function resetPassphrase()", runtime)
        self.assertIn("await api('/api/records', { method: 'DELETE' })", runtime)
        self.assertIn("crypto.getRandomValues", runtime)
        self.assertIn("CHAT_ATTITUDE", runtime)
        self.assertIn('id="passEntropy"', html)
        self.assertIn("function updatePassphraseEntropy()", runtime)
        self.assertIn("Lost kid, get a better passphrase", runtime)
        self.assertIn("Decent, Buddy", runtime)
        self.assertIn("Good, but you're still Cooked.", runtime)
        self.assertIn('id="transactionEditor"', html)
        self.assertIn("async function saveTransactionEdit", runtime)
        self.assertIn("const reportable", runtime)
        self.assertIn("Split amounts must be positive", runtime)
        self.assertIn("Changes are encrypted in your browser before they are saved", html)
        self.assertIn('id="fraudWatch"', html)
        self.assertIn("function detectAnomalies", runtime)
        self.assertIn("function robustZ", runtime)
        self.assertIn("history.length < 20", runtime)
        self.assertIn("A flag means statistically unusual, not confirmed fraud", html)
        self.assertIn('id="editFraudStatus"', html)
        self.assertIn("async function setFraudStatus", runtime)
        self.assertIn("marked as fraud by you", runtime)
        self.assertIn("function theilSenForecast", runtime)
        self.assertIn("function conversationalAnswer", runtime)
        self.assertIn("historical residual variability", runtime)
        self.assertIn("Project cash flow", html)
        browser_test = (Path(__file__).parent / "test_browser.py").read_text()
        self.assertIn("page.goto(base", browser_test)


class TestProductionHardening(ServerCase):
    def test_security_headers_and_cache_policies(self):
        html = self.client.get("/")
        self.assertEqual(html.headers["Cache-Control"], "no-store")
        self.assertIn("Content-Security-Policy-Report-Only", html.headers)
        self.assertNotIn("Content-Security-Policy", html.headers)
        self.assertNotIn("Strict-Transport-Security", html.headers)
        for name, value in {
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "X-Frame-Options": "DENY", "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        }.items():
            self.assertEqual(html.headers[name], value)
        static = self.client.get("/static/app.js")
        self.assertEqual(static.headers["Cache-Control"], "public, max-age=300")
        self.assertEqual(self.client.get("/api/session").headers["Cache-Control"], "no-store")
        error = self.client.post("/api/relay")
        self.assertEqual(error.headers["Cache-Control"], "no-store")

    def test_csp_source_regressions(self):
        html = (Path(__file__).parent / "static/index.html").read_text()
        js = (Path(__file__).parent / "static/app.js").read_text()
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>")
        self.assertNotRegex(html, r"\son[a-z]+\s*=")
        self.assertNotRegex(html + js, r"javascript:")
        self.assertNotRegex(html, r"<(?:script|link)[^>]+(?:src|href)=[\"']https?://")
        self.assertNotIn("style=", html + js)
        policy = server_app.CSP
        self.assertNotIn("'unsafe-inline'", policy)
        self.assertNotIn("'unsafe-eval'", policy.replace("'wasm-unsafe-eval'", ""))
        self.assertNotRegex(policy, r"(?:script-src|connect-src)[^;]*\*")

    def test_rate_limit_returns_429_and_persists_without_raw_identifiers(self):
        original = server_app.RATE_LIMITS["session"]
        server_app.RATE_LIMITS["session"] = (2, 60)
        try:
            self.assertEqual(self.client.get("/api/session").status_code, 200)
            self.assertEqual(self.client.get("/api/session").status_code, 200)
            cookie = self.client.get_cookie(server_app.COOKIE_NAME).value
            limited = self.client.get("/api/session")
            self.assertEqual(limited.status_code, 429)
            self.assertGreaterEqual(int(limited.headers["Retry-After"]), 1)
            fresh = server_app.app.test_client()
            self.assertEqual(fresh.get("/api/session").status_code, 200)
            replay = server_app.app.test_client(); replay.set_cookie(server_app.COOKIE_NAME, cookie)
            self.assertEqual(replay.get("/api/session").status_code, 429)
            raw = self.db_bytes()
            self.assertNotIn(cookie.encode(), raw)
        finally:
            server_app.RATE_LIMITS["session"] = original

    def test_expired_rate_buckets_are_cleanable(self):
        self.client.get("/api/session")
        with self._engine.begin() as conn:
            conn.execute(text("UPDATE rate_limits SET expires_at=0"))
            conn.execute(text("DELETE FROM rate_limits WHERE expires_at<:now"), {"now": int(__import__('time').time())})
        with self.raw_conn() as conn:
            self.assertEqual(conn.execute(text("SELECT COUNT(*) FROM rate_limits")).fetchone()[0], 0)

    def test_concurrent_rate_updates_are_atomic(self):
        original = server_app.RATE_LIMITS["relay"]
        server_app.RATE_LIMITS["relay"] = (3, 60)
        token = self.client.get("/api/session").get_json()["csrf_token"]
        cookie = self.client.get_cookie(server_app.COOKIE_NAME).value
        def attempt(_):
            client = server_app.app.test_client(); client.set_cookie(server_app.COOKIE_NAME, cookie)
            return client.post("/api/relay", headers={"Origin":server_app.ORIGIN,"X-CSRF-Token":token}).status_code
        try:
            with ThreadPoolExecutor(max_workers=6) as pool:
                statuses = list(pool.map(attempt, range(10)))
            self.assertLessEqual(statuses.count(200), 3)
            self.assertEqual(set(statuses), {200, 429})
        finally:
            server_app.RATE_LIMITS["relay"] = original

    def test_failed_webauthn_attempt_consumes_failure_budget(self):
        with server_app.app.app_context():
            table = models.PasskeyCredential.__table__
            server_app.db().execute(table.insert().values(identity_id=1, credential_id=b"cred", credential_public_key=b"\x01", label="Key"))
            server_app.db().commit()
        headers = self.security_headers()
        self.client.post("/api/passkeys/login/options", headers=headers)
        original = server_app.RATE_LIMITS["login_verify"]
        server_app.RATE_LIMITS["login_verify"] = (1, 600)
        try:
            first = self.client.post("/api/passkeys/login/verify", json={"credential":{"id":"missing"}}, headers=headers)
            second = self.client.post("/api/passkeys/login/verify", json={"credential":{"id":"missing"}}, headers=headers)
            self.assertEqual(first.status_code, 400)
            self.assertEqual(second.status_code, 429)
        finally:
            server_app.RATE_LIMITS["login_verify"] = original

    def test_deployment_artifacts_are_constrained(self):
        root = Path(__file__).parent
        gunicorn = (root / "deploy/gunicorn.conf.py").read_text()
        nginx = (root / "deploy/nginx-vault.conf").read_text()
        unit = (root / "deploy/vault.service").read_text()
        script = (root / "deploy/install-permissions.sh.example").read_text()
        env = (root / "deploy/vault.env.example").read_text()
        self.assertIn('bind = "unix:/run/vault/vault.sock"', gunicorn)
        self.assertNotIn("0.0.0.0", gunicorn)
        self.assertIn("workers = 1", gunicorn)
        self.assertIn("reload = False", gunicorn)
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3", nginx)
        self.assertIn("server_tokens off", nginx)
        self.assertIn("client_max_body_size 8m", nginx)
        self.assertIn("User=vault", unit); self.assertIn("Group=vault", unit)
        self.assertIn("NoNewPrivileges=true", unit); self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("UMask=0077", unit)
        # Only /run/vault (the Gunicorn socket) -- the app holds no local
        # data directory of its own now that state lives in PostgreSQL.
        self.assertEqual(unit.count("ReadWritePaths="), 1)
        self.assertIn("RestrictAddressFamilies=AF_UNIX", unit)
        self.assertNotIn("StateDirectory=", unit)
        self.assertNotIn("chmod -R", script); self.assertNotIn("chown -R", script)
        self.assertIn("REPLACE_WITH", env)
        self.assertNotRegex(env, r"VAULT_SECRET_KEY=(?!REPLACE)")
        self.assertIn("VAULT_DATABASE_URL", env)
        self.assertNotIn("VAULT_DB_PATH", env)
        source = (root / "app.py").read_text()
        self.assertRegex(source, r'if __name__ == "__main__":\s+if PRODUCTION:')

    def test_proxyfix_exactly_one_hop(self):
        captured = {}
        def downstream(environ, start_response):
            captured.update(remote=environ["REMOTE_ADDR"], scheme=environ["wsgi.url_scheme"])
            start_response("200 OK", []); return [b""]
        middleware = server_app.ProxyFix(downstream, x_for=1, x_proto=1, x_host=0)
        environ = {"REMOTE_ADDR":"127.0.0.1", "wsgi.url_scheme":"http",
                   "HTTP_X_FORWARDED_FOR":"spoofed, 198.51.100.7", "HTTP_X_FORWARDED_PROTO":"http, https"}
        middleware(environ, lambda *_: None)
        self.assertEqual(captured, {"remote":"198.51.100.7", "scheme":"https"})
        self.assertFalse(server_app.TRUST_PROXY)

    def test_production_configuration_headers_and_fail_closed(self):
        # Importing app.py doesn't itself open a database connection (the
        # SQLAlchemy engine is created lazily), so this only needs
        # VAULT_DATABASE_URL to be present, not reachable.
        code = "import app; c=app.app.test_client(); r=c.get('/'); print(r.headers.get('Content-Security-Policy','')); print(r.headers.get('Strict-Transport-Security',''))"
        env = os.environ.copy(); env.update({
            "VAULT_ENV":"production", "VAULT_AUTH_POLICY":"required",
            "VAULT_ORIGIN":"https://vault.example.com", "VAULT_RP_ID":"vault.example.com",
            "VAULT_SECRET_KEY":"production-test-secret", "VAULT_DATABASE_URL":TEST_DATABASE_URL,
            "VAULT_CSP_MODE":"enforce",
        })
        result = subprocess.run([sys.executable, "-c", code], cwd=Path(__file__).parent, env=env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("upgrade-insecure-requests", result.stdout)
        self.assertIn("max-age=31536000", result.stdout)
        bad = os.environ.copy(); bad.update({"VAULT_ENV":"production"})
        for key in ("VAULT_AUTH_POLICY","VAULT_ORIGIN","VAULT_RP_ID","VAULT_SECRET_KEY","VAULT_DATABASE_URL"):
            bad.pop(key, None)
        result = subprocess.run([sys.executable, "-c", "import app"], cwd=Path(__file__).parent, env=bad, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)


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
        with self.raw_conn() as conn:
            rows = conn.execute(text("SELECT blind_index, sealed FROM records")).fetchall()

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

    def test_bank_names_are_sealed_and_net_flows_are_derived_locally(self):
        sim, original = self.full_flow()
        stored = self.client.get("/api/records").get_json()["records"]
        recovered = [sim.open(r["sealed"]) for r in stored]
        self.assertEqual({t["bank"] for t in recovered}, {m["bank"] for m in fakebank.ACCOUNTS.values()})
        expected = {account: round(sum(-t["amount"] for t in original if t["account"] == account), 2)
                    for account in fakebank.ACCOUNTS}
        derived = {account: round(sum(-t["amount"] for t in recovered if t["account"] == account), 2)
                   for account in fakebank.ACCOUNTS}
        self.assertEqual(derived, expected)
        self.assertTrue(all(set(r) == {"id", "blind_index", "sealed"} for r in stored))

    def test_shipped_javascript_contains_no_bank_names(self):
        script = (Path(__file__).parent / "static" / "app.js").read_text(encoding="utf-8")
        for meta in fakebank.ACCOUNTS.values():
            self.assertNotIn(meta["bank"], script)

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


# ---------------------------------------------------------------- audit log


def _fake_authenticator_data(sign_count: int) -> bytes:
    """32-byte rp_id_hash + 1-byte flags (user-present only, no attested
    credential data or extensions) + 4-byte big-endian sign count -- the
    minimum 37-byte layout parse_authenticator_data accepts."""
    return b"\x00" * 32 + b"\x01" + sign_count.to_bytes(4, "big")


def _fake_authentication_credential_json(sign_count: int, credential_id: str = "cred-id") -> dict:
    import base64

    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    return {
        "id": credential_id,
        "rawId": b64(credential_id.encode()),
        "type": "public-key",
        "response": {
            "clientDataJSON": b64(b"{}"),
            "authenticatorData": b64(_fake_authenticator_data(sign_count)),
            "signature": b64(b"sig"),
        },
    }


class TestAuditLog(ServerCase):
    def headers(self):
        return self.security_headers()

    def audit_rows(self):
        with self.raw_conn() as conn:
            return conn.execute(text(
                "SELECT event_type, client_ref, credential_id, detail FROM audit_events ORDER BY id"
            )).mappings().all()

    def test_passkey_registration_is_audited(self):
        with self.client.session_transaction() as sess:
            sess["vault_unlocked"] = True
        self.client.post("/api/passkeys/register/options", headers=self.headers())
        verified = SimpleNamespace(credential_id=b"audit-cred", credential_public_key=b"pub", sign_count=0, credential_device_type="single_device", credential_backed_up=False)
        with patch.object(server_app, "verify_registration_response", return_value=verified):
            self.client.post("/api/passkeys/register/verify", json={"credential": {"response": {"transports": []}}, "label": "Laptop"}, headers=self.headers())
        rows = self.audit_rows()
        self.assertEqual([r["event_type"] for r in rows], ["PASSKEY_REGISTERED"])
        self.assertEqual(bytes(rows[0]["credential_id"]), b"audit-cred")
        self.assertEqual(rows[0]["detail"], {"label": "Laptop"})

    def test_passkey_removal_is_audited(self):
        with server_app.app.app_context():
            table = models.PasskeyCredential.__table__
            server_app.db().execute(table.insert().values(identity_id=1, credential_id=b"cred", credential_public_key=b"\x01", label="Key"))
            server_app.db().commit()
        with self.client.session_transaction() as sess:
            sess["vault_unlocked"] = True
            sess["authenticated_at"] = __import__("time").time()  # step-up freshness needs a recent passkey auth
        self.client.delete("/api/passkeys/Y3JlZA", headers=self.headers())
        rows = self.audit_rows()
        self.assertEqual([r["event_type"] for r in rows], ["PASSKEY_REMOVED"])
        self.assertEqual(bytes(rows[0]["credential_id"]), b"cred")

    def test_passkey_auth_success_and_failure_are_audited(self):
        with server_app.app.app_context():
            table = models.PasskeyCredential.__table__
            server_app.db().execute(table.insert().values(identity_id=1, credential_id=b"cred", credential_public_key=b"\x01", label="Key"))
            server_app.db().commit()
        self.client.post("/api/passkeys/login/options", headers=self.headers())
        first = self.client.post("/api/passkeys/login/verify", json={"credential": {"id": "missing"}}, headers=self.headers())
        self.assertEqual(first.status_code, 400)
        rows = self.audit_rows()
        self.assertEqual(rows, [], "an unrecognized credential id never reaches a stored row to audit against")

        self.client.post("/api/passkeys/login/options", headers=self.headers())
        payload = _fake_authentication_credential_json(sign_count=5, credential_id="Y3JlZA")
        with patch.object(server_app, "verify_authentication_response", side_effect=server_app.WebAuthnException("bad signature")):
            self.client.post("/api/passkeys/login/verify", json={"credential": payload}, headers=self.headers())
        rows = self.audit_rows()
        self.assertEqual([r["event_type"] for r in rows], ["PASSKEY_AUTH_FAILURE"])

        self.client.post("/api/passkeys/login/options", headers=self.headers())
        verified = SimpleNamespace(new_sign_count=6, credential_device_type="single_device", credential_backed_up=False)
        with patch.object(server_app, "verify_authentication_response", return_value=verified):
            self.client.post("/api/passkeys/login/verify", json={"credential": payload}, headers=self.headers())
        rows = self.audit_rows()
        self.assertEqual([r["event_type"] for r in rows], ["PASSKEY_AUTH_FAILURE", "PASSKEY_AUTH_SUCCESS"])

    def test_suspicious_counter_event_is_audited_even_when_verification_fails(self):
        with server_app.app.app_context():
            table = models.PasskeyCredential.__table__
            server_app.db().execute(table.insert().values(identity_id=1, credential_id=b"cred", credential_public_key=b"\x01", label="Key", sign_count=10))
            server_app.db().commit()
        self.client.post("/api/passkeys/login/options", headers=self.headers())
        regressed = _fake_authentication_credential_json(sign_count=3, credential_id="Y3JlZA")
        with patch.object(server_app, "verify_authentication_response", side_effect=server_app.WebAuthnException("bad")):
            self.client.post("/api/passkeys/login/verify", json={"credential": regressed}, headers=self.headers())
        rows = self.audit_rows()
        self.assertEqual([r["event_type"] for r in rows], ["SUSPICIOUS_COUNTER_EVENT", "PASSKEY_AUTH_FAILURE"])
        self.assertEqual(rows[0]["detail"], {"stored_sign_count": 10})

    def test_session_revoked_is_audited(self):
        token = self.client.get("/api/session").get_json()["csrf_token"]
        self.client.post("/api/logout", headers={"Origin": server_app.ORIGIN, "X-CSRF-Token": token})
        rows = self.audit_rows()
        self.assertEqual([r["event_type"] for r in rows], ["SESSION_REVOKED"])

    def test_passkey_protection_disabled_is_audited(self):
        with server_app.app.app_context():
            table = models.PasskeyCredential.__table__
            server_app.db().execute(table.insert().values(identity_id=1, credential_id=b"cred", credential_public_key=b"\x01", label="Key"))
            server_app.db().commit()
        with self.client.session_transaction() as sess:
            sess["vault_unlocked"] = True
            sess["authenticated_at"] = time.time()
        self.client.post("/api/passkeys/disable", json={"confirm_unlocked": True}, headers=self.headers())
        rows = self.audit_rows()
        self.assertEqual([r["event_type"] for r in rows], ["PASSKEY_PROTECTION_DISABLED"])

    def test_audit_events_contain_no_secrets(self):
        """Extends this suite's no-secrets-in-storage philosophy to the
        audit table specifically: a row documenting a registration should
        never contain the public key, challenge, or CSRF token, even
        though the public key itself is legitimately stored elsewhere
        (passkey_credentials) -- WebAuthn public keys need integrity, not
        secrecy, but the audit trail has no reason to duplicate them."""
        with self.client.session_transaction() as sess:
            sess["vault_unlocked"] = True
        self.client.post("/api/passkeys/register/options", headers=self.headers())
        verified = SimpleNamespace(credential_id=b"audit-cred-2", credential_public_key=b"super-secret-public-key-bytes", sign_count=0, credential_device_type="single_device", credential_backed_up=False)
        with patch.object(server_app, "verify_registration_response", return_value=verified):
            self.client.post("/api/passkeys/register/verify", json={"credential": {"response": {"transports": []}}, "label": "Laptop"}, headers=self.headers())
        csrf = self.client.get("/api/session").get_json()["csrf_token"]
        with self.raw_conn() as conn:
            audit_only = b"".join(
                str(dict(r)).encode() for r in conn.execute(text("SELECT * FROM audit_events")).mappings().all()
            )
        self.assertNotIn(b"super-secret-public-key-bytes", audit_only)
        self.assertNotIn(csrf.encode(), audit_only)


# ---------------------------------------------------------------- step-up auth


class TestStepUpAuthentication(ServerCase):
    """Adding another passkey, removing one, or disabling protection all
    require passkey authentication within VAULT_STEPUP_WINDOW_SECONDS --
    but only once a passkey already exists. First-time enrollment has no
    prior ceremony to be "recent" relative to, so it must stay reachable
    with vault-unlock alone."""

    def headers(self):
        return self.security_headers()

    def seed_existing_passkey(self):
        with server_app.app.app_context():
            table = models.PasskeyCredential.__table__
            server_app.db().execute(table.insert().values(identity_id=1, credential_id=b"cred", credential_public_key=b"\x01", label="Key"))
            server_app.db().commit()

    def unlock(self, authenticated_at=None):
        with self.client.session_transaction() as sess:
            sess["vault_unlocked"] = True
            if authenticated_at is not None:
                sess["authenticated_at"] = authenticated_at

    def test_first_enrollment_needs_no_step_up(self):
        self.unlock(authenticated_at=None)
        self.assertEqual(self.client.post("/api/passkeys/register/options", headers=self.headers()).status_code, 200)

    def test_adding_another_passkey_requires_recent_authentication(self):
        self.seed_existing_passkey()
        self.unlock(authenticated_at=None)
        self.assertEqual(self.client.post("/api/passkeys/register/options", headers=self.headers()).status_code, 401)

    def test_adding_another_passkey_succeeds_with_fresh_authentication(self):
        self.seed_existing_passkey()
        self.unlock(authenticated_at=time.time())
        self.assertEqual(self.client.post("/api/passkeys/register/options", headers=self.headers()).status_code, 200)

    def test_removal_rejects_stale_authentication(self):
        self.seed_existing_passkey()
        self.unlock(authenticated_at=time.time() - server_app.VAULT_STEPUP_WINDOW_SECONDS - 1)
        self.assertEqual(self.client.delete("/api/passkeys/Y3JlZA", headers=self.headers()).status_code, 401)

    def test_removal_succeeds_with_fresh_authentication(self):
        self.seed_existing_passkey()
        self.unlock(authenticated_at=time.time())
        self.assertEqual(self.client.delete("/api/passkeys/Y3JlZA", headers=self.headers()).status_code, 200)

    def test_disable_rejects_stale_authentication(self):
        self.seed_existing_passkey()
        self.unlock(authenticated_at=time.time() - server_app.VAULT_STEPUP_WINDOW_SECONDS - 1)
        response = self.client.post("/api/passkeys/disable", json={"confirm_unlocked": True}, headers=self.headers())
        self.assertEqual(response.status_code, 401)

    def test_disable_succeeds_with_fresh_authentication(self):
        self.seed_existing_passkey()
        self.unlock(authenticated_at=time.time())
        response = self.client.post("/api/passkeys/disable", json={"confirm_unlocked": True}, headers=self.headers())
        self.assertEqual(response.status_code, 200)


# ---------------------------------------------------------------- runner

REPORT = [
    ("Fake bank feed", TestFakeBank),
    ("Browser crypto", TestBrowserCrypto),
    ("Server API", TestServerAPI),
    ("Optional passkeys", TestOptionalPasskeys),
    ("Security increment", TestSecurityIncrement),
    ("Production hardening", TestProductionHardening),
    ("Privacy guarantee", TestPrivacyGuarantee),
    ("Audit log", TestAuditLog),
    ("Step-up authentication", TestStepUpAuthentication),
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
        print("  python app.py   ->   http://localhost:5000\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
