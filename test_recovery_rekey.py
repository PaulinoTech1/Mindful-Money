"""Bugs L, M, K: recovery blob gate and atomic vault rekey.

Run: VAULT_ENV=test VAULT_TEST_DATABASE_URL=... python -m pytest test_recovery_rekey.py
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import text

import app as server_app
import models
from test_demo import ServerCase

BLOB = "ab" * 72          # nonce + secretbox of a 32-byte seed
NEW_BLOB = "cd" * 72
SALT_E, SALT_I = "11" * 16, "22" * 16


def bi(n: int, tag: str = "a") -> str:
    return (tag * 2 + f"{n:062x}")[:64]


def sealed(n: int, tag: str = "0") -> str:
    return (f"{n:04x}" + tag * 252)[:256]


class RecoveryCase(ServerCase):
    def setUp(self):
        super().setUp()
        self.h = self.security_headers()

    def post(self, path, body=None):
        return self.client.post(path, headers=self.h, json=body if body is not None else {})

    def add_passkey(self, identity_id=1, cred=b"cred"):
        with server_app.app.app_context():
            server_app.db().execute(models.PasskeyCredential.__table__.insert().values(
                identity_id=identity_id, credential_id=cred, credential_public_key=b"\x01", label="Key"))
            server_app.db().commit()

    def set_auth_age(self, seconds):
        with self.client.session_transaction() as sess:
            sess["authenticated_at"] = time.time() - seconds

    def seed_vault(self, n=3, blob=True):
        self.assertEqual(self.post("/api/kdf/salts/generate").status_code, 200)
        recs = [{"blind_index": bi(i), "sealed": sealed(i)} for i in range(n)]
        if n:
            self.assertEqual(self.post("/api/records", {"records": recs}).status_code, 200)
        if blob:
            self.assertEqual(self.post("/api/recovery/setup", {"recovery_blob": BLOB}).status_code, 200)
        return recs

    def state(self):
        with self.raw_conn() as conn:
            recs = sorted(tuple(r) for r in conn.execute(text(
                "SELECT blind_index, sealed FROM records WHERE identity_id = 1")).all())
            ident = conn.execute(text(
                "SELECT encode(kdf_salt_enc,'hex'), encode(kdf_salt_idx,'hex'), kdf_version, "
                "encode(recovery_blob,'hex') FROM vault_identity WHERE id = 1")).one()
        return recs, tuple(ident)


class RecoveryGateTest(RecoveryCase):
    """L: the blob gate is a passkey-authenticated session with a recent assertion."""

    def test_blob_403_or_401_without_passkey_session(self):
        self.seed_vault()
        # No passkey registered at all: refused (never opened to sessions without one).
        self.assertEqual(self.client.get("/api/recovery/blob").status_code, 409)
        self.add_passkey()
        # Signed out: refused.
        self.deauthenticate()
        self.assertIn(self.client.get("/api/recovery/blob").status_code, {401, 403})
        # Signed in but the passkey assertion is older than the step-up window.
        self.authenticate()
        self.set_auth_age(server_app.VAULT_STEPUP_WINDOW_SECONDS + 5)
        self.assertEqual(self.client.get("/api/recovery/blob").status_code, 401)

    def test_blob_200_with_recent_passkey_session(self):
        self.seed_vault()
        self.add_passkey()
        r = self.client.get("/api/recovery/blob")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["recovery_blob"], BLOB)

    def test_delete_works_and_status_reflects_it(self):
        self.seed_vault()
        self.add_passkey()
        self.assertTrue(self.client.get("/api/recovery/status").get_json()["set_up"])
        self.set_auth_age(server_app.VAULT_STEPUP_WINDOW_SECONDS + 5)
        self.assertEqual(self.post("/api/recovery/delete").status_code, 401)
        self.authenticate()
        self.assertEqual(self.post("/api/recovery/delete").status_code, 200)
        self.assertFalse(self.client.get("/api/recovery/status").get_json()["set_up"])
        self.assertEqual(self.client.get("/api/recovery/blob").status_code, 404)

    def test_status_reveals_no_blob(self):
        self.seed_vault()
        body = self.client.get("/api/recovery/status").get_data(as_text=True)
        self.assertNotIn(BLOB, body)


class RekeyTest(RecoveryCase):
    """M and K: atomic rekey."""

    def setUp(self):
        super().setUp()
        self.recs = self.seed_vault(n=3)
        self.add_passkey()
        self.before = self.state()

    def begin(self):
        r = self.post("/api/vault/rekey/begin")
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()["rekey_id"]

    def stage(self, rid, rows):
        return self.post("/api/vault/rekey/records", {"rekey_id": rid, "records": rows})

    def new_rows(self, which=range(3)):
        return [{"blind_index": bi(i, "b"), "old_blind_index": bi(i), "sealed": sealed(i, "9")} for i in which]

    def commit(self, rid, **over):
        body = {"rekey_id": rid, "salt_enc": SALT_E, "salt_idx": SALT_I, "kdf_version": 3,
                "recovery_blob": NEW_BLOB, **over}
        body = {k: v for k, v in body.items() if v is not ...}
        return self.post("/api/vault/rekey/commit", body)

    def test_full_rekey_swaps_everything_atomically(self):
        rid = self.begin()
        self.assertEqual(self.stage(rid, self.new_rows([0, 1])).status_code, 200)
        self.assertEqual(self.stage(rid, self.new_rows([2])).status_code, 200)
        self.assertEqual(self.state(), self.before)  # nothing live changed before commit
        r = self.commit(rid)
        self.assertEqual(r.status_code, 200, r.get_json())
        recs, ident = self.state()
        self.assertEqual(recs, sorted((bi(i, "b"), sealed(i, "9")) for i in range(3)))
        self.assertEqual(ident, (SALT_E, SALT_I, 3, NEW_BLOB))
        with self.raw_conn() as conn:
            self.assertEqual(conn.execute(text("SELECT count(*) FROM vault_rekeys")).scalar(), 0)
            self.assertEqual(conn.execute(text("SELECT count(*) FROM vault_rekey_records")).scalar(), 0)

    def test_begin_requires_recent_passkey(self):
        self.set_auth_age(server_app.VAULT_STEPUP_WINDOW_SECONDS + 5)
        self.assertEqual(self.post("/api/vault/rekey/begin").status_code, 401)
        self.deauthenticate()
        self.assertIn(self.post("/api/vault/rekey/begin").status_code, {401, 403})

    def test_other_identity_cannot_use_rekey_id(self):
        rid = self.begin()
        with self.client.session_transaction() as sess:
            sess["identity_id"] = 2
        with server_app.app.app_context():
            server_app.db().execute(models.VaultIdentity.__table__.insert().values(
                id=2, user_handle=b"other", passkey_required=False))
            server_app.db().commit()
        self.assertEqual(self.stage(rid, self.new_rows()).status_code, 404)
        self.assertEqual(self.commit(rid).status_code, 404)

    def test_validation(self):
        rid = self.begin()
        bad = [
            {"rekey_id": rid, "records": [{"blind_index": bi(0, "b"), "sealed": sealed(0)}]},
            {"rekey_id": rid, "records": [{**self.new_rows([0])[0], "old_blind_index": "XYZ"}]},
            {"rekey_id": rid, "records": self.new_rows([0]) * 2},
            {"rekey_id": rid, "records": [{**self.new_rows([0])[0], "sealed": "ab"}]},
            {"records": self.new_rows([0])},
        ]
        for body in bad:
            self.assertEqual(self.post("/api/vault/rekey/records", body).status_code, 400, body)
        self.assertEqual(self.stage("x" * 43, self.new_rows()).status_code, 404)
        self.assertEqual(self.stage(rid, self.new_rows()).status_code, 200)
        self.assertEqual(self.stage(rid, self.new_rows([0])).status_code, 409)  # over base count
        for over in ({"salt_enc": "zz"}, {"salt_idx": SALT_E}, {"kdf_version": 4}, {"kdf_version": "3"},
                     {"kdf_version": True}, {"recovery_blob": ...}, {"recovery_blob": "abc"}):
            self.assertEqual(self.commit(rid, **over).status_code, 400, over)
        self.assertEqual(self.state(), self.before)

    def test_incomplete_or_wrong_set_leaves_old_state(self):
        rid = self.begin()
        self.stage(rid, self.new_rows([0, 1]))
        r = self.commit(rid)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.state(), self.before)
        rid = self.begin()  # replaces the earlier rekey
        rows = self.new_rows([0, 1]) + [{"blind_index": bi(2, "b"), "old_blind_index": bi(7), "sealed": sealed(2)}]
        self.stage(rid, rows)
        self.assertEqual(self.commit(rid).status_code, 409)
        self.assertEqual(self.state(), self.before)

    def test_failed_commit_rolls_back_everything(self):
        rid = self.begin()
        self.stage(rid, self.new_rows())
        # Force a failure after the delete/insert, inside the same transaction.
        real_update = server_app.update
        calls = {"n": 0}
        def failing_update(table, *a, **k):
            if table is models.VaultIdentity.__table__:
                calls["n"] += 1
                raise RuntimeError("simulated crash during commit")
            return real_update(table, *a, **k)
        server_app.update = failing_update
        try:
            server_app.app.config["PROPAGATE_EXCEPTIONS"] = False
            r = self.commit(rid)
        finally:
            server_app.update = real_update
            server_app.app.config["PROPAGATE_EXCEPTIONS"] = None
        self.assertEqual(calls["n"], 1)
        self.assertGreaterEqual(r.status_code, 500)
        self.assertEqual(self.state(), self.before)
        # The staged rekey is still usable afterwards.
        self.assertEqual(self.commit(rid).status_code, 200)

    def test_normal_upload_during_rekey_is_rejected(self):
        rid = self.begin()
        r = self.post("/api/records", {"records": [{"blind_index": bi(9), "sealed": sealed(9)}]})
        self.assertEqual(r.status_code, 409)
        self.assertEqual(self.unsafe("delete", "/api/records").status_code, 409)
        self.stage(rid, self.new_rows())
        self.assertEqual(self.commit(rid).status_code, 200)
        # Afterwards uploads work again.
        r = self.post("/api/records", {"records": [{"blind_index": bi(9, "b"), "sealed": sealed(9)}]})
        self.assertEqual(r.status_code, 200)

    def test_vault_changed_before_commit_is_detected(self):
        rid = self.begin()
        self.stage(rid, self.new_rows())
        # A write that slipped past the guard (simulated directly in SQL).
        with self._engine.begin() as conn:
            conn.execute(text("UPDATE records SET sealed = :s WHERE blind_index = :b"),
                         {"s": sealed(1, "7"), "b": bi(1)})
        changed = self.state()
        self.assertEqual(self.commit(rid).status_code, 409)
        self.assertEqual(self.state(), changed)

    def test_concurrent_upload_and_commit_never_mix(self):
        rid = self.begin()
        self.stage(rid, self.new_rows())
        cookie = self.client.get_cookie(server_app.COOKIE_NAME).value
        def upload(_):
            c = server_app.app.test_client(); c.set_cookie(server_app.COOKIE_NAME, cookie)
            return c.post("/api/records", headers=self.h,
                          json={"records": [{"blind_index": bi(8), "sealed": sealed(8)}]}).status_code
        with ThreadPoolExecutor(max_workers=4) as pool:
            ups = [pool.submit(upload, i) for i in range(4)]
            r = self.commit(rid)
            statuses = [f.result() for f in ups]
        self.assertEqual(r.status_code, 200)
        recs, _ = self.state()
        # Every upload either was refused or landed after the swap (same session).
        old_keys = {bi(i) for i in range(3)}
        self.assertFalse(old_keys & {b for b, _ in recs})
        self.assertTrue(set(statuses) <= {200, 409}, statuses)

    def test_commit_revokes_other_sessions(self):
        other = server_app.app.test_client()
        with other.session_transaction() as sess:
            sess["identity_id"] = 1; sess["authenticated_at"] = time.time()
        oh = {"Origin": server_app.ORIGIN, "X-CSRF-Token": other.get("/api/session").get_json()["csrf_token"]}
        rid = self.begin()
        self.stage(rid, self.new_rows())
        self.assertEqual(self.commit(rid).status_code, 200)
        r = other.post("/api/records", headers=oh, json={"records": [{"blind_index": bi(5), "sealed": sealed(5)}]})
        self.assertIn(r.status_code, {401, 403})
        self.assertNotIn(bi(5), {b for b, _ in self.state()[0]})

    def test_zk_commitment_carried_to_new_index(self):
        with self._engine.begin() as conn:
            conn.execute(text("UPDATE records SET commitment = :c, circuit_version = 'v1' WHERE blind_index = :b"),
                         {"c": "ee" * 32, "b": bi(0)})
        rid = self.begin()
        self.stage(rid, self.new_rows())
        self.assertEqual(self.commit(rid).status_code, 200)
        with self.raw_conn() as conn:
            row = conn.execute(text("SELECT commitment, circuit_version FROM records WHERE blind_index = :b"),
                               {"b": bi(0, "b")}).one()
        self.assertEqual(tuple(row), ("ee" * 32, "v1"))

    def test_abort_unblocks_writes_and_keeps_vault(self):
        self.begin()
        self.assertEqual(self.post("/api/vault/rekey/abort").get_json(), {"aborted": True})
        r = self.post("/api/records", {"records": [{"blind_index": bi(9), "sealed": sealed(9)}]})
        self.assertEqual(r.status_code, 200)

    def test_expired_rekey_no_longer_blocks_or_commits(self):
        rid = self.begin()
        self.stage(rid, self.new_rows())
        with self._engine.begin() as conn:
            conn.execute(text("UPDATE vault_rekeys SET expires_at = 0"))
        self.assertEqual(self.commit(rid).status_code, 404)
        self.assertEqual(self.state(), self.before)
        r = self.post("/api/records", {"records": [{"blind_index": bi(9), "sealed": sealed(9)}]})
        self.assertEqual(r.status_code, 200)

    def test_vault_without_recovery_key_must_not_send_blob(self):
        with self._engine.begin() as conn:
            conn.execute(text("UPDATE vault_identity SET recovery_blob = NULL"))
        rid = self.begin()
        self.stage(rid, self.new_rows())
        self.assertEqual(self.commit(rid).status_code, 400)
        self.assertEqual(self.commit(rid, recovery_blob=...).status_code, 200)

    def test_worst_case_rekey_chunk_fits_request_limit(self):
        n = server_app.MAX_RECORDS_PER_BATCH
        row = {"blind_index": "a" * 64, "old_blind_index": "b" * 64, "sealed": "c" * server_app.MAX_SEALED_HEX_LENGTH}
        body = json.dumps({"rekey_id": "x" * 43, "records": [row] * n}, separators=(",", ":"))
        self.assertLessEqual(len(body), server_app.MAX_REQUEST_BYTES)


class StaleRekeyAbortTest(RekeyTest):
    """P: a crashed rekey must not block writes for long, and abort must never
    interleave with a commit."""

    def test_default_ttl_is_600_seconds(self):
        self.assertEqual(server_app.REKEY_TTL_SECONDS, 600)
        self.assertEqual(self.post("/api/vault/rekey/begin").get_json()["expires_in"], 600)

    def test_abort_after_commit_is_a_no_op(self):
        rid = self.begin()
        self.stage(rid, self.new_rows())
        self.assertEqual(self.commit(rid).status_code, 200)
        after = self.state()
        self.assertEqual(self.post("/api/vault/rekey/abort").get_json(), {"aborted": False})
        self.assertEqual(self.state(), after)

    def test_abort_waits_for_an_in_progress_commit(self):
        rid = self.begin()
        self.stage(rid, self.new_rows())
        # Hold the identity row FOR UPDATE, exactly as a running commit does.
        with self._engine.connect() as locker:
            tx = locker.begin()
            locker.execute(text("SELECT id FROM vault_identity WHERE id = 1 FOR UPDATE"))
            with ThreadPoolExecutor(max_workers=1) as pool:
                fut = pool.submit(self.post, "/api/vault/rekey/abort")
                time.sleep(0.7)
                self.assertFalse(fut.done(), "abort must block while a commit holds the row lock")
                tx.rollback()
                self.assertEqual(fut.result(timeout=10).get_json(), {"aborted": True})
        self.assertEqual(self.state(), self.before)
        self.assertEqual(self.commit(rid).status_code, 404)

    def test_abort_is_scoped_to_the_callers_identity(self):
        self.begin()
        with server_app.app.app_context():
            server_app.db().execute(models.VaultIdentity.__table__.insert().values(
                id=2, user_handle=b"other", passkey_required=False))
            server_app.db().commit()
        other = server_app.app.test_client()
        with other.session_transaction() as sess:
            sess["identity_id"] = 2; sess["authenticated_at"] = time.time()
        oh = {"Origin": server_app.ORIGIN, "X-CSRF-Token": other.get("/api/session").get_json()["csrf_token"]}
        self.assertEqual(other.post("/api/vault/rekey/abort", headers=oh, json={}).get_json(), {"aborted": False})
        r = self.post("/api/records", {"records": [{"blind_index": bi(9), "sealed": sealed(9)}]})
        self.assertEqual(r.status_code, 409)


class CeremonyClobberTest(RecoveryCase):
    """F/Q: a request that did not touch the WebAuthn ceremony must not erase a
    ceremony another overlapping request on the same session started."""

    def _row(self):
        with self.raw_conn() as conn:
            return conn.execute(text("SELECT active_ceremony_id FROM server_sessions WHERE revoked_at IS NULL "
                                     "ORDER BY last_seen_at DESC LIMIT 1")).scalar_one()

    def _overlap(self, mutate):
        cookie = self.client.get_cookie(server_app.COOKIE_NAME).value
        iface = server_app.app.session_interface
        with server_app.app.test_request_context(headers={"Cookie": f"{server_app.COOKIE_NAME}={cookie}"}):
            from flask import request
            sess = iface.open_session(server_app.app, request)    # loaded: no ceremony
            with self._engine.begin() as conn:                     # overlapping request starts one
                conn.execute(text("UPDATE server_sessions SET active_ceremony_id = 'ceremony-from-B'"))
            mutate(sess)
            sess.modified = True
            iface.save_session(server_app.app, sess, server_app.app.response_class())

    def test_untouched_ceremony_is_not_clobbered(self):
        self.assertIsNone(self._row())
        self._overlap(lambda sess: sess.__setitem__("vault_unlocked", True))
        self.assertEqual(self._row(), "ceremony-from-B")

    def test_a_request_that_changes_the_ceremony_still_writes_it(self):
        self._overlap(lambda sess: sess.__setitem__("active_ceremony_id", "ceremony-from-A"))
        self.assertEqual(self._row(), "ceremony-from-A")

    def test_consuming_the_ceremony_clears_it(self):
        with self._engine.begin() as conn:
            conn.execute(text("UPDATE server_sessions SET active_ceremony_id = 'c1'"))
        self._overlap(lambda sess: sess.pop("active_ceremony_id", None) or sess.__setitem__("active_ceremony_id", None))
        self.assertIsNone(self._row())
