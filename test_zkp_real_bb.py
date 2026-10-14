#!/usr/bin/env python3
"""Real Barretenberg verification of the committed v4 proof fixture.

No database or Flask needed. Runs where bb 5.1.0 and the baked CRS are
installed: the CI `zkp-v4` job, and inside the built image (`docker-zkp`
job, with `--network none` to prove no request-time download). Set
ZKP_REQUIRE_REAL=1 to fail instead of skip when the runtime is missing.

    python -m unittest -v test_zkp_real_bb

The fixture (tests/fixtures/zkp_v4) is an honest proof for fixed test
values produced by scripts/zkp_v4_e2e.sh.
"""
from __future__ import annotations

import os
import unittest
from pathlib import Path

import zkp_verifier

FIXTURE_DIR = Path(__file__).resolve().parent / "tests" / "fixtures" / "zkp_v4"
COMMITMENT = "0x0c83c98feb59e793295da3c820c6ef508319104f9f57fefd1ed8c6cae14a501e"


def _fixture():
    proof = (FIXTURE_DIR / "proof").read_bytes()
    raw = (FIXTURE_DIR / "public_inputs").read_bytes()
    return proof, [f"0x{raw[i:i + 32].hex()}" for i in range(0, len(raw), 32)]


class TestRealBarretenbergVerification(unittest.TestCase):
    def setUp(self):
        if not zkp_verifier.artifacts_available():
            if os.environ.get("ZKP_REQUIRE_REAL") == "1":
                self.fail("bb, the baked CRS or the v4 VK is missing")
            self.skipTest("bb and the baked CRS are not installed here")

    def test_honest_fixture_verifies(self):
        proof, inputs = _fixture()
        self.assertEqual(len(inputs), zkp_verifier.PUBLIC_INPUT_COUNT)
        self.assertEqual(inputs[3], COMMITMENT)
        self.assertTrue(zkp_verifier.verify_proof(proof, inputs).valid)

    def test_other_commitment_record_or_ciphertext_fails(self):
        """A proof for one vault's key does not verify against another
        commitment (what a random key would need), another record id, or a
        modified ciphertext output."""
        proof, inputs = _fixture()
        for index, value in [(3, 0xabc), (1, 0xdf), (7, 1)]:
            bad = list(inputs)
            bad[index] = zkp_verifier.canonical_field_hex(value)
            self.assertFalse(zkp_verifier.verify_proof(proof, bad).valid, index)


if __name__ == "__main__":
    unittest.main()
