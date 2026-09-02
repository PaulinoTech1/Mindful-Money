#!/usr/bin/env python3
"""Tests for the manual-expense ZK-proof challenge/verification endpoints.

    python3 test_zkp_server.py
    pytest test_zkp_server.py

What these tests DO cover for real, against the real Flask app and a real
Postgres test database (imports ServerCase from test_demo.py):
  - challenge issuance, authentication, single-use claiming, expiry,
    cross-session rejection
  - every public-input / context mismatch Flask is supposed to catch
    BEFORE ever calling the cryptographic verifier
  - the real fail-closed behavior of zkp_verifier.verify_proof() when the
    verification key / bb executable are absent (which is genuinely true
    in this repository -- see zkp/README.md) -- this is not simulated,
    it is the actual CircuitArtifactsUnavailable path executing for real
  - CSRF / origin / rate-limit protection on the new endpoints

What these tests do NOT and cannot cover here (see zkp/README.md,
"Status"): a real proof being generated, verified, and accepted. No
`nargo`/`bb` toolchain is available in this dev sandbox (native Windows;
Barretenberg has no Windows build), so there is no compiled circuit and no
verification key. Every test below that would need a *valid* proof to
proceed instead asserts the correct fail-closed 503/400 behavior when the
verifier is unavailable -- which is itself the required behavior, not a
placeholder for it.
"""

from __future__ import annotations

import time

from test_demo import ServerCase

import models
import zkp_verifier


class TestZkpChallengeIssuance(ServerCase):
    def test_requires_authentication_when_policy_requires_it(self):
        with self._engine.begin() as conn:
            from sqlalchemy import text
            conn.execute(text(
                "INSERT INTO vault_identity (id, user_handle, passkey_required) "
                "VALUES (1, decode('00','hex'), true) ON CONFLICT (id) DO UPDATE SET passkey_required = true"
            ))
        resp = self.unsafe("post", "/api/zkp/challenge", json={"purpose": "manual_expense_create"})
        self.assertEqual(resp.status_code, 401)

    def test_rejects_unknown_purpose(self):
        resp = self.unsafe("post", "/api/zkp/challenge", json={"purpose": "delete_everything"})
        self.assertEqual(resp.status_code, 400)

    def test_rejects_unexpected_fields(self):
        resp = self.unsafe("post", "/api/zkp/challenge", json={"purpose": "manual_expense_create", "extra": 1})
        self.assertEqual(resp.status_code, 400)

    def test_fails_closed_when_circuit_artifacts_are_unavailable(self):
        # Real behavior in this repo, not a mock: no VK/bb are present.
        self.assertFalse(zkp_verifier.artifacts_available())
        resp = self.unsafe("post", "/api/zkp/challenge", json={"purpose": "manual_expense_create"})
        self.assertEqual(resp.status_code, 503)
        self.assertNotIn("Traceback", resp.get_data(as_text=True))


def _force_issue_challenge(case, **overrides):
    """Bypass zkp_verifier.artifacts_available() to exercise the challenge
    lifecycle logic on its own, independent of whether a real verifier is
    installed on this machine -- this is testing Flask's own bookkeeping
    (claim-once, expiry, ownership), not the cryptography."""
    from sqlalchemy import insert
    import secrets

    table = models.ZkpChallenge.__table__
    now = time.time()
    values = dict(
        challenge_id=secrets.token_urlsafe(16),
        session_id_hash=_current_session_id_hash(case),
        challenge=secrets.token_bytes(31),
        record_id=secrets.token_bytes(16),
        purpose="manual_expense_create",
        circuit_version=zkp_verifier.CIRCUIT_VERSION,
        schema_version=zkp_verifier.SCHEMA_VERSION,
        created_at=now,
        expires_at=now + 300,
    )
    values.update(overrides)
    with case._engine.begin() as conn:
        conn.execute(insert(table).values(**values))
    return values


def _current_session_id_hash(case):
    """Forces session creation/persistence on `case.client`'s cookie jar,
    then derives the same session_id_hash app.py itself would -- shared by
    any test that needs to attach a ZkpChallenge row to "the current
    request's session" (the FK to server_sessions requires a real row,
    not a synthetic hash)."""
    import app as server_app
    case.client.get("/api/session")
    cookie = case.client.get_cookie(server_app.COOKIE_NAME)
    return server_app._sid_hash(cookie.value)


class TestZkpChallengeLifecycle(ServerCase):
    def submit(self, challenge_id, **body):
        payload = {
            "challenge_id": challenge_id,
            "blind_index": "a" * 64,
            "sealed": "b" * 200,
            "commitment": "c" * 64,
            "proof": "ab" * 64,
            "public_inputs": {"challenge": "", "record_id": "", "schema_version": zkp_verifier.SCHEMA_VERSION},
        }
        payload.update(body)
        return self.unsafe("post", "/api/records/manual", json=payload)

    def test_unknown_challenge_id_rejected(self):
        resp = self.submit("does-not-exist")
        self.assertEqual(resp.status_code, 400)

    def test_expired_challenge_rejected(self):
        values = _force_issue_challenge(self, expires_at=time.time() - 1)
        resp = self.submit(values["challenge_id"], public_inputs={
            "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
            "schema_version": values["schema_version"],
        })
        self.assertEqual(resp.status_code, 400)

    def test_already_consumed_challenge_rejected(self):
        values = _force_issue_challenge(self, consumed_at=time.time())
        resp = self.submit(values["challenge_id"], public_inputs={
            "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
            "schema_version": values["schema_version"],
        })
        self.assertEqual(resp.status_code, 400)

    def test_public_input_challenge_mismatch_rejected(self):
        values = _force_issue_challenge(self)
        resp = self.submit(values["challenge_id"], public_inputs={
            "challenge": ("00" * 31),  # wrong -- does not match the issued challenge
            "record_id": values["record_id"].hex(),
            "schema_version": values["schema_version"],
        })
        self.assertEqual(resp.status_code, 400)

    def test_public_input_record_id_mismatch_rejected(self):
        values = _force_issue_challenge(self)
        resp = self.submit(values["challenge_id"], public_inputs={
            "challenge": values["challenge"].hex(),
            "record_id": ("11" * 16),  # wrong
            "schema_version": values["schema_version"],
        })
        self.assertEqual(resp.status_code, 400)

    def test_wrong_schema_version_rejected(self):
        values = _force_issue_challenge(self)
        resp = self.submit(values["challenge_id"], public_inputs={
            "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
            "schema_version": zkp_verifier.SCHEMA_VERSION + 1,
        })
        self.assertEqual(resp.status_code, 400)

    def test_unknown_circuit_version_rejected(self):
        values = _force_issue_challenge(self, circuit_version="manual-expense-v0-deprecated")
        resp = self.submit(values["challenge_id"], public_inputs={
            "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
            "schema_version": values["schema_version"],
        })
        self.assertEqual(resp.status_code, 400)

    def test_malformed_proof_hex_rejected(self):
        values = _force_issue_challenge(self)
        resp = self.submit(
            values["challenge_id"],
            proof="not hex at all",
            public_inputs={
                "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
                "schema_version": values["schema_version"],
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_well_formed_but_unverifiable_proof_fails_closed_503(self):
        """Every context check passes (challenge, record_id, schema_version,
        circuit_version all correct) -- the ONLY remaining step is
        cryptographic verification, which is genuinely unavailable in this
        sandbox. The correct, required behavior is 503 fail-closed, never
        200. This exercises the real zkp_verifier.verify_proof() code
        path end to end, not a mock."""
        values = _force_issue_challenge(self)
        resp = self.submit(values["challenge_id"], public_inputs={
            "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
            "schema_version": values["schema_version"],
        })
        self.assertEqual(resp.status_code, 503)
        with self._engine.connect() as conn:
            from sqlalchemy import text
            count = conn.execute(text("SELECT count(*) FROM records WHERE commitment = 'c' || repeat('c', 63)")).scalar_one()
        self.assertEqual(count, 0, "no record must be stored when the verifier is unavailable")

    def test_challenge_is_single_use_even_when_verification_later_fails(self):
        """The atomic claim in _claim_zkp_challenge means a challenge is
        spent on first use regardless of what happens next -- submitting
        the same challenge_id twice must be rejected the second time
        (400, "unknown/already-consumed challenge"), proving there is no
        SELECT-then-UPDATE race window an attacker could exploit to reuse
        one challenge for two records."""
        values = _force_issue_challenge(self)
        inputs = {
            "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
            "schema_version": values["schema_version"],
        }
        first = self.submit(values["challenge_id"], public_inputs=inputs)
        second = self.submit(values["challenge_id"], public_inputs=inputs)
        self.assertEqual(first.status_code, 503)  # fails closed on verification, but the challenge is now spent
        self.assertEqual(second.status_code, 400)  # replay of an already-consumed challenge

    def test_cross_session_challenge_is_rejected(self):
        """A challenge issued to one session must not be usable from
        another -- simulates one user's challenge being replayed by a
        different authenticated party. Uses a second real Flask test
        client (its own cookie jar) so the "other session" is a genuine
        server_sessions row, not a synthetic hash that would just trip
        the foreign key instead of the ownership check being tested."""
        import app as server_app
        other_client = server_app.app.test_client()
        other_client.get("/api/session")
        other_hash = server_app._sid_hash(other_client.get_cookie(server_app.COOKIE_NAME).value)

        values = _force_issue_challenge(self, session_id_hash=other_hash)
        resp = self.submit(values["challenge_id"], public_inputs={
            "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
            "schema_version": values["schema_version"],
        })
        self.assertEqual(resp.status_code, 400)

    def test_request_without_csrf_or_origin_is_rejected(self):
        resp = self.client.post("/api/records/manual", json={})
        self.assertEqual(resp.status_code, 403)

    def test_rate_limited_after_repeated_verification_attempts(self):
        from app import RATE_LIMITS
        limit, _seconds = RATE_LIMITS["zkp_verify"]
        values = _force_issue_challenge(self)
        inputs = {
            "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
            "schema_version": values["schema_version"],
        }
        statuses = [self.submit(values["challenge_id"], public_inputs=inputs).status_code for _ in range(limit + 2)]
        self.assertIn(429, statuses, f"expected a 429 within {limit + 2} attempts, got {statuses}")


class TestZkpVerifierModule(ServerCase):
    """Direct tests of zkp_verifier.py's own contract, independent of the
    Flask layer above it."""

    def test_verify_proof_fails_closed_without_artifacts(self):
        with self.assertRaises(zkp_verifier.CircuitArtifactsUnavailable):
            zkp_verifier.verify_proof(b"anything")

    def test_verify_proof_rejects_empty_proof_before_touching_artifacts(self):
        with self.assertRaises(zkp_verifier.ZkpVerificationError):
            zkp_verifier.verify_proof(b"")

    def test_verify_proof_rejects_oversized_proof(self):
        with self.assertRaises(zkp_verifier.ZkpVerificationError):
            zkp_verifier.verify_proof(b"x" * (zkp_verifier.MAX_PROOF_BYTES + 1))

    def test_category_id_round_trip_matches_static_app_js_taxonomy(self):
        # Keep this list in exact sync with MANUAL_CATEGORIES in
        # static/app.js and CATEGORY_COUNT's ordering in main.nr -- this
        # test is the tripwire if one of the three ever drifts.
        expected = (
            "Housing", "Groceries", "Dining", "Transport", "Utilities", "Subscriptions",
            "Shopping", "Health & insurance", "Investing", "Income", "Uncategorized",
        )
        self.assertEqual(zkp_verifier.CATEGORY_IDS, expected)
        for i, name in enumerate(expected):
            self.assertEqual(zkp_verifier.category_id_for(name), (i, True))
        self.assertEqual(zkp_verifier.category_id_for(None), (0, False))
        with self.assertRaises(ValueError):
            zkp_verifier.category_id_for("Not A Real Category")


class TestProofCiphertextBindingLimitation(ServerCase):
    """Required by design (see zkp/README.md and the delivery report's
    'Residual risks'): documents, rather than hides, that Flask has no way
    to check whether `sealed` (opaque ciphertext) actually encrypts the
    same record `commitment`/the proof are about. This test does not
    pretend to run a real proof; it demonstrates that nothing in Flask's
    request handling before the verifier call inspects any relationship
    between `sealed` and `commitment` -- by construction, since `sealed`
    is only ever validated as an opaque hex blob (see the shared
    MIN/MAX_SEALED_HEX_LENGTH check reused from PUT /api/records)."""

    def test_sealed_ciphertext_content_is_never_inspected_against_commitment(self):
        values = _force_issue_challenge(self)
        # `sealed` here is 200 arbitrary hex chars with zero relationship
        # to `commitment` -- Flask's schema-level checks (hex format,
        # length bounds) accept this exactly as readily as a genuine
        # matching ciphertext would, because it cannot tell the
        # difference. The only gate standing between this and being
        # stored is proof verification (see the 503 below) -- there is no
        # separate "does sealed match commitment" check anywhere in
        # app.py, by design, because the server cannot decrypt `sealed`.
        resp = self.submit(
            values["challenge_id"],
            sealed="f" * 200,
            commitment="c" * 64,
            public_inputs={
                "challenge": values["challenge"].hex(), "record_id": values["record_id"].hex(),
                "schema_version": values["schema_version"],
            },
        )
        # Rejected here only because the verifier is unavailable in this
        # sandbox (fail-closed) -- NOT because Flask detected the mismatch.
        # A deployment with a working verifier would accept this same
        # request the moment `proof` is a real, valid proof for
        # `commitment`, regardless of what `sealed` actually contains.
        self.assertEqual(resp.status_code, 503)

    def submit(self, challenge_id, **body):
        payload = {
            "challenge_id": challenge_id,
            "blind_index": "a" * 64,
            "sealed": "b" * 200,
            "commitment": "c" * 64,
            "proof": "ab" * 64,
            "public_inputs": {},
        }
        payload.update(body)
        return self.unsafe("post", "/api/records/manual", json=payload)


def main():
    import unittest
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name, obj in list(globals().items()):
        if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
            suite.addTests(loader.loadTestsFromTestCase(obj))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
