#!/usr/bin/env python3
"""Tests for the manual-transaction ZK proof endpoints (circuit v4).

    pytest test_zkp_server.py

Covers, against the real Flask app and a real Postgres test database:
  - key commitment enrollment: step-up gate, server-generated salt,
    one-time registration, input validation
  - challenge issuance: 409 without an enrolled commitment, 503 when the
    verifier is unavailable, commitment and salt returned from the DB
  - submission: every public input the server owns (challenge, record id,
    schema, key commitment, salt) is compared against server rows, so a
    client-supplied commitment or salt is never trusted; v2 and v3
    challenges are refused; stored ciphertext is built from proof outputs
  - availability: verifier unavailable or timed out returns 503 and refunds
    the challenge; an invalid proof spends it
  - zkp_verifier.py: fail-closed artifacts check (VK, bb, baked CRS),
    native CLI invocation, ABI order of the committed v4 artifact
Real bb verification of the committed proof fixture lives in
test_zkp_real_bb.py (no database needed; runs in CI and inside the image).
Rekey replacement of the commitment is covered in test_recovery_rekey.py.
"""

from __future__ import annotations

import json
import os
import secrets
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import insert, text

import app as server_app
import models
import zkp_verifier
from test_demo import ServerCase

VALID_FAKE_PROOF = ("00" * 31 + "01") * 2
COMMITMENT = bytes.fromhex("0c83c98feb59e793295da3c820c6ef508319104f9f57fefd1ed8c6cae14a501e")
SALT = bytes.fromhex("55aa" * 15 + "55")
ZERO_FIELD = "0x" + "0" * 64


def _fake_outputs():
    # commitment, ciphertext[8], mac: distinct canonical field values
    return [zkp_verifier.canonical_field_hex(0x100 + i) for i in range(1 + zkp_verifier.CIPHERTEXT_LEN + 1)]


def _current_session_id_hash(case):
    case.client.get("/api/session")
    cookie = case.client.get_cookie(server_app.COOKIE_NAME)
    return server_app._sid_hash(cookie.value)


def _set_vault_key(case, commitment=COMMITMENT, salt=SALT, identity_id=1):
    with case._engine.begin() as conn:
        conn.execute(text("UPDATE vault_identity SET zkp_key_commitment = :c, zkp_vault_salt = :s WHERE id = :i"),
                     {"c": commitment, "s": salt, "i": identity_id})


def _force_issue_challenge(case, **overrides):
    """Insert a challenge row directly, bypassing artifacts_available(), to
    exercise Flask's own bookkeeping independent of the verifier."""
    now = time.time()
    values = dict(
        challenge_id=secrets.token_urlsafe(16), identity_id=1,
        session_id_hash=_current_session_id_hash(case),
        challenge=secrets.token_bytes(31), record_id=secrets.token_bytes(16),
        purpose="manual_expense_create",
        circuit_version=zkp_verifier.CIRCUIT_VERSION, schema_version=zkp_verifier.SCHEMA_VERSION,
        created_at=now, expires_at=now + 300,
    )
    values.update(overrides)
    with case._engine.begin() as conn:
        conn.execute(insert(models.ZkpChallenge.__table__).values(**values))
    return values


def _public_inputs(values, commitment=COMMITMENT, salt=SALT):
    return list(zkp_verifier.expected_server_inputs(
        challenge=values["challenge"], record_id=values["record_id"],
        key_commitment=commitment, vault_salt=salt)) + _fake_outputs()


def _consumed_at(case, challenge_id):
    with case._engine.connect() as conn:
        return conn.execute(text("SELECT consumed_at FROM zkp_challenges WHERE challenge_id = :c"),
                            {"c": challenge_id}).scalar_one()


class ZkpCase(ServerCase):
    def setUp(self):
        super().setUp()
        self.h = self.security_headers()

    def post(self, path, body=None):
        return self.client.post(path, headers=self.h, json=body if body is not None else {})

    def add_passkey(self):
        with server_app.app.app_context():
            server_app.db().execute(models.PasskeyCredential.__table__.insert().values(
                identity_id=1, credential_id=b"cred", credential_public_key=b"\x01", label="Key"))
            server_app.db().commit()

    def set_auth_age(self, seconds):
        with self.client.session_transaction() as sess:
            sess["authenticated_at"] = time.time() - seconds

    def vault_key(self):
        with self._engine.connect() as conn:
            row = conn.execute(text("SELECT zkp_key_commitment, zkp_vault_salt FROM vault_identity WHERE id = 1")).one()
        return (bytes(row[0]) if row[0] is not None else None, bytes(row[1]) if row[1] is not None else None)

    def submit(self, challenge_id, **body):
        payload = {"challenge_id": challenge_id, "blind_index": "a" * 64,
                   "proof": VALID_FAKE_PROOF, "public_inputs": [ZERO_FIELD] * zkp_verifier.PUBLIC_INPUT_COUNT}
        payload.update(body)
        return self.unsafe("post", "/api/records/manual", json=payload)


class TestKeyCommitmentEnrollment(ZkpCase):
    def enroll(self, commitment=COMMITMENT.hex()):
        salt = self.post("/api/zkp/key-commitment/salt")
        self.assertEqual(salt.status_code, 200, salt.get_json())
        return salt, self.post("/api/zkp/key-commitment", {"key_commitment": commitment})

    def test_requires_a_passkey(self):
        self.assertEqual(self.post("/api/zkp/key-commitment/salt").status_code, 409)
        self.assertEqual(self.post("/api/zkp/key-commitment", {"key_commitment": COMMITMENT.hex()}).status_code, 409)
        self.assertEqual(self.vault_key(), (None, None))

    def test_requires_recent_step_up(self):
        self.add_passkey()
        self.set_auth_age(server_app.VAULT_STEPUP_WINDOW_SECONDS + 5)
        self.assertEqual(self.post("/api/zkp/key-commitment/salt").status_code, 401)
        self.assertEqual(self.post("/api/zkp/key-commitment", {"key_commitment": COMMITMENT.hex()}).status_code, 401)
        self.assertEqual(self.vault_key(), (None, None))

    def test_enrollment_stores_server_salt_and_commitment(self):
        self.add_passkey(); self.set_auth_age(1)
        salt_resp, enroll = self.enroll()
        self.assertEqual(enroll.status_code, 200, enroll.get_json())
        salt_hex = salt_resp.get_json()["vault_salt"]
        self.assertEqual(len(salt_hex), 62)
        self.assertLess(int(salt_hex, 16), zkp_verifier.BN254_SCALAR_MODULUS)
        self.assertEqual(self.vault_key(), (COMMITMENT, bytes.fromhex(salt_hex)))
        status = self.client.get("/api/zkp/key-commitment").get_json()
        self.assertEqual(status, {"registered": True, "vault_salt": salt_hex})

    def test_salt_is_random_per_request(self):
        self.add_passkey(); self.set_auth_age(1)
        a = self.post("/api/zkp/key-commitment/salt").get_json()["vault_salt"]
        b = self.post("/api/zkp/key-commitment/salt").get_json()["vault_salt"]
        self.assertNotEqual(a, b)

    def test_commitment_requires_salt_first(self):
        self.add_passkey(); self.set_auth_age(1)
        self.assertEqual(self.post("/api/zkp/key-commitment", {"key_commitment": COMMITMENT.hex()}).status_code, 409)

    def test_registered_commitment_cannot_be_overwritten_outside_rekey(self):
        self.add_passkey(); self.set_auth_age(1)
        self.enroll()
        self.assertEqual(self.post("/api/zkp/key-commitment/salt").status_code, 409)
        self.assertEqual(self.post("/api/zkp/key-commitment", {"key_commitment": "1b" * 32}).status_code, 409)
        self.assertEqual(self.vault_key()[0], COMMITMENT)

    def test_rejects_malformed_commitments(self):
        self.add_passkey(); self.set_auth_age(1)
        self.post("/api/zkp/key-commitment/salt")
        modulus_hex = f"{zkp_verifier.BN254_SCALAR_MODULUS:064x}"
        for bad in ["", "0" * 64, modulus_hex, "f" * 64, "AB" * 32, "ab" * 31, 5, None]:
            self.assertEqual(self.post("/api/zkp/key-commitment", {"key_commitment": bad}).status_code, 400, bad)
        self.assertEqual(self.post("/api/zkp/key-commitment",
                                   {"key_commitment": COMMITMENT.hex(), "vault_salt": "00"}).status_code, 400)
        self.assertEqual(self.vault_key()[0], None)

    def test_csrf_required(self):
        self.assertEqual(self.client.post("/api/zkp/key-commitment/salt", json={}).status_code, 403)
        self.assertEqual(self.client.post("/api/zkp/key-commitment", json={}).status_code, 403)


class TestZkpChallengeIssuance(ZkpCase):
    def challenge(self):
        return self.unsafe("post", "/api/zkp/challenge", json={"purpose": "manual_expense_create"})

    def test_requires_authentication(self):
        unauth = server_app.app.test_client()
        resp = unauth.post("/api/zkp/challenge", json={"purpose": "manual_expense_create"},
                           headers={"Origin": "https://testserver"})
        self.assertIn(resp.status_code, (401, 403))

    def test_rejects_unknown_purpose_and_fields(self):
        self.assertEqual(self.unsafe("post", "/api/zkp/challenge", json={"purpose": "x"}).status_code, 400)
        self.assertEqual(self.unsafe("post", "/api/zkp/challenge",
                                     json={"purpose": "manual_expense_create", "extra": 1}).status_code, 400)

    def test_fails_closed_when_verifier_unavailable(self):
        self.assertFalse(zkp_verifier.artifacts_available())
        resp = self.challenge()
        self.assertEqual(resp.status_code, 503)
        self.assertNotIn("Traceback", resp.get_data(as_text=True))

    def test_vault_without_commitment_gets_409(self):
        with patch.object(zkp_verifier, "artifacts_available", return_value=True):
            self.assertEqual(self.challenge().status_code, 409)

    def test_challenge_returns_db_commitment_and_salt_for_v4(self):
        _set_vault_key(self)
        with patch.object(zkp_verifier, "artifacts_available", return_value=True):
            resp = self.challenge()
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body["key_commitment"], COMMITMENT.hex())
        self.assertEqual(body["vault_salt"], SALT.hex())
        self.assertEqual(body["circuit_version"], "manual-transaction-v4")
        self.assertEqual(body["schema_version"], 4)


class TestZkpSubmission(ZkpCase):
    def setUp(self):
        super().setUp()
        _set_vault_key(self)

    def valid(self, values, inputs=None):
        with patch.object(zkp_verifier, "verify_proof",
                          return_value=zkp_verifier.VerificationResult(valid=True, duration_seconds=0.001)) as verify:
            resp = self.submit(values["challenge_id"], public_inputs=inputs or _public_inputs(values))
        return resp, verify

    def test_vault_without_commitment_gets_409_without_burning_challenge(self):
        _set_vault_key(self, commitment=None, salt=None)
        values = _force_issue_challenge(self)
        self.assertEqual(self.submit(values["challenge_id"], public_inputs=_public_inputs(values)).status_code, 409)
        self.assertIsNone(_consumed_at(self, values["challenge_id"]))

    def test_unknown_expired_consumed_cross_identity_rejected(self):
        self.assertEqual(self.submit("does-not-exist").status_code, 400)
        expired = _force_issue_challenge(self, expires_at=time.time() - 1)
        self.assertEqual(self.submit(expired["challenge_id"], public_inputs=_public_inputs(expired)).status_code, 400)
        used = _force_issue_challenge(self, consumed_at=time.time())
        self.assertEqual(self.submit(used["challenge_id"], public_inputs=_public_inputs(used)).status_code, 400)
        with self._engine.begin() as conn:
            conn.execute(insert(models.VaultIdentity.__table__).values(id=2, user_handle=b"tenant-two", passkey_required=False))
        other = _force_issue_challenge(self, identity_id=2)
        self.assertEqual(self.submit(other["challenge_id"], public_inputs=_public_inputs(other)).status_code, 400)

    def test_cross_session_challenge_rejected(self):
        other_client = server_app.app.test_client()
        other_client.get("/api/session")
        other_hash = server_app._sid_hash(other_client.get_cookie(server_app.COOKIE_NAME).value)
        values = _force_issue_challenge(self, session_id_hash=other_hash)
        self.assertEqual(self.submit(values["challenge_id"], public_inputs=_public_inputs(values)).status_code, 400)

    def test_each_server_owned_public_input_must_match(self):
        """challenge, record id, schema, key commitment and salt all come
        from server rows; a client-supplied value for any of them (e.g. its
        own commitment for a random key) is refused before verification."""
        for index, bad in [(0, ZERO_FIELD), (1, zkp_verifier.canonical_field_hex(7)), (2, zkp_verifier.canonical_field_hex(3)),
                           (3, zkp_verifier.canonical_field_hex(0xabc)), (4, zkp_verifier.canonical_field_hex(0xdef))]:
            values = _force_issue_challenge(self)
            inputs = _public_inputs(values)
            inputs[index] = bad
            with patch.object(zkp_verifier, "verify_proof") as verify:
                resp = self.submit(values["challenge_id"], public_inputs=inputs)
            self.assertEqual(resp.status_code, 400, index)
            verify.assert_not_called()

    def test_v2_and_v3_challenges_are_refused(self):
        for version, schema in [(zkp_verifier.CIRCUIT_VERSION_V2, 2), (zkp_verifier.CIRCUIT_VERSION_V3, 3)]:
            values = _force_issue_challenge(self, circuit_version=version, schema_version=schema)
            resp, verify = self.valid(values)
            self.assertEqual(resp.status_code, 400, version)
            verify.assert_not_called()

    def test_v2_style_body_with_sealed_and_commitment_is_refused(self):
        values = _force_issue_challenge(self)
        resp = self.submit(values["challenge_id"], public_inputs=_public_inputs(values), sealed="b" * 200, commitment="c" * 64)
        self.assertEqual(resp.status_code, 400)

    def test_wrong_public_input_count_and_malformed_proof(self):
        values = _force_issue_challenge(self)
        self.assertEqual(self.submit(values["challenge_id"], public_inputs=_public_inputs(values)[:4]).status_code, 400)
        self.assertEqual(self.submit(values["challenge_id"], proof="not hex", public_inputs=_public_inputs(values)).status_code, 400)

    def test_verifier_unavailable_returns_503_and_refunds_challenge(self):
        values = _force_issue_challenge(self)
        inputs = _public_inputs(values)
        first = self.submit(values["challenge_id"], public_inputs=inputs)
        self.assertEqual(first.status_code, 503)
        self.assertIsNone(_consumed_at(self, values["challenge_id"]))
        # Still usable once the verifier is back.
        resp, _ = self.valid(values, inputs)
        self.assertEqual(resp.status_code, 200)
        self.assertIsNotNone(_consumed_at(self, values["challenge_id"]))
        with self.raw_conn() as conn:
            self.assertEqual(conn.execute(text("SELECT count(*) FROM records")).scalar(), 1)

    def test_verifier_timeout_returns_503_and_refunds(self):
        values = _force_issue_challenge(self)
        with patch.object(zkp_verifier, "verify_proof", side_effect=zkp_verifier.CircuitArtifactsUnavailable("timed out")):
            self.assertEqual(self.submit(values["challenge_id"], public_inputs=_public_inputs(values)).status_code, 503)
        self.assertIsNone(_consumed_at(self, values["challenge_id"]))

    def test_invalid_proof_spends_the_challenge(self):
        values = _force_issue_challenge(self)
        inputs = _public_inputs(values)
        with patch.object(zkp_verifier, "verify_proof",
                          return_value=zkp_verifier.VerificationResult(valid=False, duration_seconds=0.001)):
            self.assertEqual(self.submit(values["challenge_id"], public_inputs=inputs).status_code, 400)
        self.assertIsNotNone(_consumed_at(self, values["challenge_id"]))
        resp, _ = self.valid(values, inputs)
        self.assertEqual(resp.status_code, 400)

    def test_valid_proof_stores_proven_outputs_as_record(self):
        values = _force_issue_challenge(self)
        inputs = _public_inputs(values)
        resp, verify = self.valid(values, inputs)
        self.assertEqual(resp.status_code, 200)
        verify.assert_called_once_with(bytes.fromhex(VALID_FAKE_PROOF), tuple(inputs))
        stored = self.client.get("/api/records").get_json()["records"]
        self.assertEqual(len(stored), 1)
        expected_sealed = values["record_id"].hex() + "".join(v[2:] for v in inputs[6:])
        self.assertEqual(stored[0]["sealed"], expected_sealed)
        self.assertEqual(len(expected_sealed), 2 * (16 + 32 * 9))
        self.assertEqual(stored[0]["commitment"], inputs[5][2:])
        self.assertEqual(stored[0]["circuit_version"], "manual-transaction-v4")

    def test_csrf_and_rate_limit(self):
        self.assertEqual(self.client.post("/api/records/manual", json={}).status_code, 403)
        limit, _ = server_app.RATE_LIMITS["zkp_verify"]
        values = _force_issue_challenge(self)
        statuses = [self.submit(values["challenge_id"], public_inputs=_public_inputs(values)).status_code for _ in range(limit + 2)]
        self.assertIn(429, statuses)

    def test_v2_records_remain_readable(self):
        with self._engine.begin() as conn:
            conn.execute(text("INSERT INTO records (identity_id, blind_index, sealed, bytes, stored_at, commitment, circuit_version) "
                              "VALUES (1, :b, :s, 100, current_date, :c, 'manual-transaction-v2')"),
                         {"b": "d" * 64, "s": "e" * 200, "c": "c" * 64})
        stored = self.client.get("/api/records").get_json()["records"]
        self.assertEqual(stored[0]["circuit_version"], "manual-transaction-v2")


class TestReadiness(ZkpCase):
    def test_ready_reports_zkp_without_failing(self):
        resp = self.client.get("/ready")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["zkp"], "unavailable")
        with patch.object(zkp_verifier, "artifacts_available", return_value=True):
            self.assertEqual(self.client.get("/ready").get_json()["zkp"], "available")


class TestZkpVerifierModule(ServerCase):
    def test_fails_closed_without_artifacts(self):
        with self.assertRaises(zkp_verifier.CircuitArtifactsUnavailable):
            zkp_verifier.verify_proof(bytes.fromhex(VALID_FAKE_PROOF), [ZERO_FIELD] * zkp_verifier.PUBLIC_INPUT_COUNT)

    def test_missing_crs_means_unavailable_even_with_vk_and_bb(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bb = Path(d) / "bb"; bb.write_bytes(b"x")
            with patch.object(zkp_verifier, "BB_EXECUTABLE", str(bb)), patch.object(zkp_verifier, "CRS_DIR", None):
                self.assertFalse(zkp_verifier.artifacts_available())
            crs = Path(d) / "crs"; crs.mkdir(); (crs / "bn254_g2.dat").write_bytes(b"x")
            with patch.object(zkp_verifier, "BB_EXECUTABLE", str(bb)), patch.object(zkp_verifier, "CRS_DIR", crs):
                self.assertFalse(zkp_verifier.artifacts_available())
                (crs / "bn254_g1.dat").write_bytes(b"x")
                self.assertTrue(zkp_verifier.artifacts_available())

    def test_rejects_bad_proof_and_inputs_before_artifacts(self):
        pi = [ZERO_FIELD] * zkp_verifier.PUBLIC_INPUT_COUNT
        for proof in [b"", b"x" * (zkp_verifier.MAX_PROOF_BYTES + 1)]:
            with self.assertRaises(zkp_verifier.ZkpVerificationError):
                zkp_verifier.verify_proof(proof, pi)
        proof = bytes.fromhex(VALID_FAKE_PROOF)
        for bad in [pi[:-1], ["0x1"] + pi[1:], [f"0x{zkp_verifier.BN254_SCALAR_MODULUS:064x}"] + pi[1:]]:
            with self.assertRaises(zkp_verifier.ZkpVerificationError):
                zkp_verifier.verify_proof(proof, bad)

    def test_committed_v4_artifact_abi_matches_server_order(self):
        artifact = json.loads(Path("zkp/manual_expense_v4/target/manual_expense_v4.json").read_text("utf-8"))
        public = [p["name"] for p in artifact["abi"]["parameters"] if p["visibility"] == "public"]
        self.assertEqual(public, ["challenge", "record_id_hash", "schema_version", "key_commitment", "vault_salt"])
        private = [p["name"] for p in artifact["abi"]["parameters"] if p["visibility"] == "private"]
        self.assertIn("zk_root", private)
        self.assertNotIn("enc_key", private)
        ret = artifact["abi"]["return_type"]
        self.assertEqual(ret["visibility"], "public")
        self.assertEqual(ret["abi_type"]["kind"], "tuple")
        self.assertEqual(len(public) + 1 + zkp_verifier.CIPHERTEXT_LEN + 1, zkp_verifier.PUBLIC_INPUT_COUNT)

    def test_native_cli_invocation_uses_server_vk_and_baked_crs(self):
        import tempfile
        proof = bytes.fromhex(VALID_FAKE_PROOF)
        fields = tuple([ZERO_FIELD] * zkp_verifier.PUBLIC_INPUT_COUNT)
        with tempfile.TemporaryDirectory() as d:
            vk = Path(d) / "vk"; vk.write_bytes(b"vk")
            bb = Path(d) / "bb"; bb.write_bytes(b"bb")
            crs = Path(d) / "crs"; crs.mkdir()
            for name in zkp_verifier.CRS_FILES: (crs / name).write_bytes(b"x")

            def fake_run(command, **kwargs):
                self.assertEqual(Path(command[command.index("-p") + 1]).read_bytes(), proof)
                self.assertEqual(len(Path(command[command.index("-i") + 1]).read_bytes()), 32 * zkp_verifier.PUBLIC_INPUT_COUNT)
                self.assertEqual(command[command.index("-k") + 1], str(vk))
                self.assertEqual(command[command.index("-c") + 1], str(crs))
                return SimpleNamespace(returncode=0)

            with patch.object(zkp_verifier, "VK_PATH", vk), patch.object(zkp_verifier, "BB_EXECUTABLE", str(bb)), \
                 patch.object(zkp_verifier, "CRS_DIR", crs), patch.object(zkp_verifier.subprocess, "run", side_effect=fake_run):
                self.assertTrue(zkp_verifier.verify_proof(proof, fields).valid)

    def test_timeout_is_reported_as_unavailable(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            vk = Path(d) / "vk"; vk.write_bytes(b"vk")
            bb = Path(d) / "bb"; bb.write_bytes(b"bb")
            crs = Path(d)
            for name in zkp_verifier.CRS_FILES: (crs / name).write_bytes(b"x")
            with patch.object(zkp_verifier, "VK_PATH", vk), patch.object(zkp_verifier, "BB_EXECUTABLE", str(bb)), \
                 patch.object(zkp_verifier, "CRS_DIR", crs), \
                 patch.object(zkp_verifier.subprocess, "run", side_effect=subprocess.TimeoutExpired("bb", 1)):
                with self.assertRaises(zkp_verifier.CircuitArtifactsUnavailable):
                    zkp_verifier.verify_proof(bytes.fromhex(VALID_FAKE_PROOF), [ZERO_FIELD] * zkp_verifier.PUBLIC_INPUT_COUNT)

    def test_category_ids(self):
        self.assertEqual(len(zkp_verifier.CATEGORY_IDS), 16)
        self.assertEqual(zkp_verifier.category_id_for("Salary"), (10, True))
        self.assertEqual(zkp_verifier.category_id_for(None), (0, False))


if __name__ == "__main__":
    unittest.main()
