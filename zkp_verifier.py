"""Server-side cryptographic verifier for manual-expense ZK proofs.

See zkp/README.md for the full design writeup. Trust boundary this module
enforces:

    proof bytes (from an authenticated, CSRF-checked, challenge-validated
    Flask request -- see app.py's POST /api/records/manual)
        |
        v
    this module: invoke the official `bb` CLI against a server-controlled,
    read-only, pinned verification key
        |
        v
    valid / invalid, nothing else

This module NEVER receives, computes, or has access to: plaintext expense
fields, the client-side encryption key, or any private circuit witness --
none of those ever leave the browser (see static/zkp/manual_expense_client.js).
It also never accepts a verification key from a caller; only the file at
VK_PATH (server configuration, not request data) is ever used. Accepting a
client-supplied verification key would let any prover write a circuit that
does `assert(true)`, produce its own matching key and proof, and defeat the
entire system -- see the project's delivery report, "Verification trust
anchor".

Requires the official `bb` CLI (see zkp/README.md for install instructions
-- Barretenberg has no native Windows build; this module targets a
Linux/macOS/WSL deployment host). Neither `bb` nor a compiled verification
key exist in this repository's own dev sandbox, so verify_proof() below
raises CircuitArtifactsUnavailable immediately here -- see zkp/README.md
"Status" for exactly what has and has not been executed.

CLI usage is pinned to the documented basic flow from
https://barretenberg.aztec.network/docs/getting_started/ :
    bb verify -p <proof file> -k <vk file>
That page notes Barretenberg proof files conventionally have the public
inputs prepended to the proof bytes by `bb prove`/`write_vk --write_vk`.
Whether bb.js's browser-generated proof blob (from
`backend.generateProof(witness)`, which returns a `{proof, publicInputs}`
structure per the noir_js tutorial) is byte-for-byte the same file format
native `bb verify` expects is an INTEGRATION DETAIL NOT YET VALIDATED in
this repository -- there is a real, documented history of friction between
bb.js's in-browser proof format and the native bb CLI's file format across
Barretenberg versions. Treat `_proof_file_bytes()` below as the one place
that assumption lives, and verify it for real against the pinned toolchain
version before relying on this in production.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

CIRCUIT_VERSION = "manual-expense-v1"
SCHEMA_VERSION = 1

# Must stay in exact sync with the CATEGORY_COUNT ordering in
# zkp/manual_expense/src/main.nr and MANUAL_CATEGORIES in static/app.js.
# Index in this tuple == the circuit's category_id witness value.
CATEGORY_IDS = (
    "Housing", "Groceries", "Dining", "Transport", "Utilities", "Subscriptions",
    "Shopping", "Health & insurance", "Investing", "Income", "Uncategorized",
)

BB_EXECUTABLE = os.environ.get("ZKP_BB_EXECUTABLE") or shutil.which("bb") or "bb"
VK_PATH = Path(os.environ.get("ZKP_MANUAL_EXPENSE_VK_PATH", "zkp/manual_expense/target/vk"))
VERIFY_TIMEOUT_SECONDS = float(os.environ.get("ZKP_VERIFY_TIMEOUT_SECONDS", "10"))
MAX_PROOF_BYTES = int(os.environ.get("ZKP_MAX_PROOF_BYTES", str(256 * 1024)))


class ZkpVerificationError(RuntimeError):
    """A proof was rejected, malformed, or too large. Message text is
    always safe to log or show a user -- never includes proof bytes,
    stdout/stderr from `bb`, or filesystem paths."""


class CircuitArtifactsUnavailable(RuntimeError):
    """The pinned verification key or the `bb` executable is not present
    on this host. Callers MUST fail closed exactly as for an invalid
    proof -- never treat "verifier unavailable" as "proof accepted"."""


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    duration_seconds: float


def artifacts_available() -> bool:
    """Non-raising check for a startup/health-check log line -- see
    app.py's startup logging. Does not itself imply anything about proof
    validity."""
    return VK_PATH.is_file() and (shutil.which(BB_EXECUTABLE) is not None or Path(BB_EXECUTABLE).is_file())


def _require_artifacts() -> None:
    if not VK_PATH.is_file():
        raise CircuitArtifactsUnavailable(f"verification key not found at {VK_PATH}")
    if shutil.which(BB_EXECUTABLE) is None and not Path(BB_EXECUTABLE).is_file():
        raise CircuitArtifactsUnavailable("bb executable not found")


def verify_proof(proof_bytes: bytes) -> VerificationResult:
    """Verify a manual-expense proof against the pinned verification key.

    Only answers "is this proof cryptographically valid under this
    verification key" -- it says nothing about whether the proof's public
    inputs are the ones Flask expects (challenge, record_id_hash,
    schema_version). That check happens in app.py, against the
    `public_inputs` the client submits alongside the proof, BEFORE this
    function is ever called -- see POST /api/records/manual. A proof that
    is cryptographically valid for the wrong public inputs is rejected
    there, not here.
    """
    if not isinstance(proof_bytes, (bytes, bytearray)) or not proof_bytes:
        raise ZkpVerificationError("proof is missing or empty")
    if len(proof_bytes) > MAX_PROOF_BYTES:
        raise ZkpVerificationError("proof exceeds the maximum accepted size")
    _require_artifacts()

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="zkp_verify_") as tmpdir:
        # Server-generated filename, inside a server-generated temp
        # directory -- never derived from client input.
        proof_path = Path(tmpdir) / "proof"
        proof_path.write_bytes(proof_bytes)
        try:
            result = subprocess.run(
                [BB_EXECUTABLE, "verify", "-p", str(proof_path), "-k", str(VK_PATH)],
                capture_output=True,
                timeout=VERIFY_TIMEOUT_SECONDS,
                check=False,
                cwd=tmpdir,
            )
        except subprocess.TimeoutExpired as exc:
            raise ZkpVerificationError("proof verification timed out") from exc
        except OSError as exc:
            raise CircuitArtifactsUnavailable("could not invoke the bb executable") from exc

    duration = time.monotonic() - started
    # Only the exit code is trusted (0 == valid). stdout/stderr are never
    # parsed for a decision and never forwarded to the client -- see
    # app.py's generic "Unable to validate the encrypted record." response.
    return VerificationResult(valid=result.returncode == 0, duration_seconds=duration)


def category_id_for(name: str | None) -> tuple[int, bool]:
    """(category_id, has_category) matching the circuit's witness shape,
    from the same canonical category string static/app.js's
    validateExpenseCategory already produces. Raises ValueError for
    anything not in CATEGORY_IDS -- callers must treat that as a 400, not
    silently default to "Uncategorized"."""
    if name is None:
        return 0, False
    try:
        return CATEGORY_IDS.index(name), True
    except ValueError:
        raise ValueError(f"unknown category: {name!r}") from None
