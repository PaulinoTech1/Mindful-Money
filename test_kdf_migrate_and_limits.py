"""Bug D (migrate stores kdf_version with salts) and bug E (max sealed size).

Run: VAULT_ENV=test VAULT_TEST_DATABASE_URL=... python -m pytest test_kdf_migrate_and_limits.py
"""
from __future__ import annotations

import os
import unittest

import nacl.bindings
from sqlalchemy import text

import app as server_app
from test_demo import ServerCase

SALT_A = "11" * 16
SALT_B = "22" * 16
SALT_C = "33" * 16
SALT_D = "44" * 16
LARGEST_BUCKET = 8192  # static/app.js PAD_BUCKETS[-1]


class MigrateKdfVersionTest(ServerCase):
    def identity_row(self):
        with self.raw_conn() as conn:
            self.client.get("/api/session")  # ensure identity 1 is seeded
            return conn.execute(text(
                "SELECT encode(kdf_salt_enc,'hex') AS enc, encode(kdf_salt_idx,'hex') AS idx, kdf_version "
                "FROM vault_identity WHERE id = 1")).mappings().one()

    def migrate(self, **body):
        return self.unsafe("post", "/api/kdf/salts/migrate", json=body)

    def test_fresh_vault_migrate_v3_stores_v3(self):
        before = self.identity_row()
        self.assertIsNone(before["enc"])
        self.assertEqual(before["kdf_version"], 1)  # column server_default
        r = self.migrate(salt_enc=SALT_A, salt_idx=SALT_B, kdf_version=3)
        self.assertEqual(r.status_code, 200, r.get_json())
        row = self.identity_row()
        self.assertEqual((row["enc"], row["idx"], row["kdf_version"]), (SALT_A, SALT_B, 3))
        got = self.client.get("/api/kdf/salts").get_json()
        self.assertEqual(got["kdf_version"], 3)

    def test_invalid_or_missing_version_rejected_and_nothing_changes(self):
        self.assertEqual(self.migrate(salt_enc=SALT_A, salt_idx=SALT_B, kdf_version=3).status_code, 200)
        for bad in (None, 0, 4, "3", 3.0, True, [3]):
            body = dict(salt_enc=SALT_C, salt_idx=SALT_D, force=True)
            if bad is not None:
                body["kdf_version"] = bad
            r = self.migrate(**body)
            self.assertEqual(r.status_code, 400, f"kdf_version={bad!r}")
            row = self.identity_row()
            self.assertEqual((row["enc"], row["idx"], row["kdf_version"]), (SALT_A, SALT_B, 3),
                             f"state changed after rejected kdf_version={bad!r}")

    def test_force_overwrite_changes_salts_and_version_together(self):
        self.assertEqual(self.migrate(salt_enc=SALT_A, salt_idx=SALT_B, kdf_version=3).status_code, 200)
        r = self.migrate(salt_enc=SALT_C, salt_idx=SALT_D, kdf_version=1, force=True)
        self.assertEqual(r.status_code, 200, r.get_json())
        row = self.identity_row()
        self.assertEqual((row["enc"], row["idx"], row["kdf_version"]), (SALT_C, SALT_D, 1))

    def test_refused_overwrite_changes_neither(self):
        self.assertEqual(self.migrate(salt_enc=SALT_A, salt_idx=SALT_B, kdf_version=3).status_code, 200)
        r = self.migrate(salt_enc=SALT_C, salt_idx=SALT_D, kdf_version=1)  # no force
        self.assertEqual(r.status_code, 409)
        row = self.identity_row()
        self.assertEqual((row["enc"], row["idx"], row["kdf_version"]), (SALT_A, SALT_B, 3))


class SealedSizeLimitTest(ServerCase):
    def test_limit_matches_largest_bucket_ciphertext(self):
        expected_hex = 2 * (LARGEST_BUCKET + nacl.bindings.crypto_box_SEALBYTES)
        self.assertEqual(nacl.bindings.crypto_box_SEALBYTES, 48)
        if "VAULT_MAX_SEALED_HEX_LENGTH" not in os.environ:
            self.assertEqual(server_app.MAX_SEALED_HEX_LENGTH, expected_hex)

    def test_real_max_bucket_ciphertext_accepted_one_byte_over_rejected(self):
        pk, _sk = nacl.bindings.crypto_box_keypair()
        sealed = nacl.bindings.crypto_box_seal(b"\x00" * LARGEST_BUCKET, pk).hex()
        self.assertEqual(len(sealed), server_app.MAX_SEALED_HEX_LENGTH)
        ok = self.unsafe("post", "/api/records", json={"records": [
            {"blind_index": "ab" * 32, "sealed": sealed}]})
        self.assertEqual(ok.status_code, 200, ok.get_json())
        over = self.unsafe("post", "/api/records", json={"records": [
            {"blind_index": "cd" * 32, "sealed": sealed + "00"}]})
        self.assertEqual(over.status_code, 400, over.get_json())


if __name__ == "__main__":
    unittest.main()


class BatchSizeInvariantTest(unittest.TestCase):
    """Bug G: a worst-case batch must fit under the request limit by design.

    Derivation: README "Ciphertext and resource limits".
    """

    def test_worst_case_batch_fits_request_limit(self):
        import json
        n = server_app.MAX_RECORDS_PER_BATCH
        record = {"blind_index": "a" * 64, "sealed": "b" * server_app.MAX_SEALED_HEX_LENGTH}
        body = json.dumps({"records": [record] * n}, separators=(",", ":"))
        self.assertEqual(len(body), 14 + n * 16575 - 1)
        self.assertLessEqual(len(body), server_app.MAX_REQUEST_BYTES)
        self.assertLessEqual(len(body), server_app.MAX_JSON_OBJECT_BYTES)
        # Default spacing (", " and ": ") must also fit.
        self.assertLessEqual(len(json.dumps({"records": [record] * n})), server_app.MAX_REQUEST_BYTES)

    def test_client_chunk_limits_within_server_limits(self):
        src = open(os.path.join(os.path.dirname(__file__), "static", "app.js"), encoding="utf-8").read()
        import re
        recs = int(re.search(r"const UPLOAD_MAX_RECORDS = (\d+);", src).group(1))
        mib = int(re.search(r"const UPLOAD_MAX_BYTES = (\d+) \* 1024 \* 1024;", src).group(1))
        self.assertLessEqual(recs, server_app.MAX_RECORDS_PER_BATCH)
        self.assertLess(mib * 1024 * 1024, server_app.MAX_REQUEST_BYTES)


class WorstCaseBatchAcceptedTest(ServerCase):
    def test_server_accepts_max_size_batch(self):
        n = server_app.MAX_RECORDS_PER_BATCH
        records = [{"blind_index": f"{i:064x}", "sealed": "ab" * (server_app.MAX_SEALED_HEX_LENGTH // 2)}
                   for i in range(n)]
        r = self.unsafe("post", "/api/records", json={"records": records})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True)[:200])


class UploadRateLimitTest(ServerCase):
    """Bug I: realistic editing bursts pass at the production default.

    Derivation of the default: README "Ciphertext and resource limits".
    """

    def _post_one(self, i):
        # Fetch CSRF headers once: each security_headers() call is a
        # GET /api/session, which has its own (session) budget.
        if not hasattr(self, "_headers"):
            self._headers = self.security_headers()
        record = {"blind_index": f"{i:064x}", "sealed": "ab" * 560}
        return self.client.post("/api/records", headers=self._headers,
                                json={"records": [record]}).status_code

    def _wait_for_fresh_window(self, needed_seconds):
        import time
        seconds = server_app.RATE_LIMITS["upload"][1]
        if seconds - time.time() % seconds < needed_seconds:
            time.sleep(seconds - time.time() % seconds + 0.1)

    def test_production_default_is_60_per_minute(self):
        self.assertEqual(server_app.RATE_LIMITS["upload"], (60, 60))

    def test_burst_of_30_single_edits_accepted(self):
        self._wait_for_fresh_window(20)
        statuses = [self._post_one(i) for i in range(30)]
        self.assertEqual(statuses, [200] * 30)

    def test_limit_triggers_above_default(self):
        limit = server_app.RATE_LIMITS["upload"][0]
        self._wait_for_fresh_window(25)
        statuses = [self._post_one(i) for i in range(limit + 1)]
        self.assertEqual(statuses[:limit], [200] * limit)
        self.assertEqual(statuses[limit], 429)


class KdfVersionServerDefaultTest(ServerCase):
    """R: kdf_version defaults to 1 in the database itself, as the migration
    (production) does, so raw SQL inserts behave the same on every DB."""

    def test_raw_insert_without_kdf_version_gets_1(self):
        from sqlalchemy import text as _text
        with self._engine.begin() as conn:
            conn.execute(_text("INSERT INTO vault_identity (id, user_handle, passkey_required) "
                               "VALUES (77, 'r'::bytea, false)"))
            v = conn.execute(_text("SELECT kdf_version FROM vault_identity WHERE id = 77")).scalar_one()
        self.assertEqual(v, 1)
