"""Server-side cryptographic verifier for manual-transaction ZK proofs.

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

This module NEVER receives, computes, or has access to: plaintext transaction
fields, the client-side encryption key, or any private circuit witness --
none of those ever leave the browser (see static/zkp/manual_expense_v4_client.js).
It also never accepts a verification key from a caller; only the file at
VK_PATH (server configuration, not request data) is ever used. Accepting a
client-supplied verification key would let any prover write a circuit that
does `assert(true)`, produce its own matching key and proof, and defeat the
entire system -- see the project's delivery report, "Verification trust
anchor".

Requires the official `bb` 5.1.0 CLI and a baked BN254 CRS directory
(`ZKP_CRS_DIR`). The Dockerfile installs both, pinned by sha256; any host
without them reports the verifier unavailable and every proof submission
fails closed with 503 (never accepted).

Barretenberg 5.1 represents an UltraHonk proof and its public inputs as
separate arrays of 32-byte big-endian BN254 field elements. The browser
returns that exact split as `{ proof, publicInputs }`; the native CLI reads
the same split from `-p` and `-i`:

    bb verify -s ultra_honk -p <proof> -i <public_inputs> -k <vk> -c <crs>

This module validates canonical field encodings, writes both files, and
never relies on a client-supplied verification key.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

# Active circuit: v4, key-bound (zkp/manual_expense_v4, docs/ZKP_BINDING.md).
# v2 records stay readable but no new v2 proofs are accepted; v3 never
# reached production and is never accepted (its key was unbound).
CIRCUIT_VERSION = "manual-transaction-v4"
SCHEMA_VERSION = 4
CIRCUIT_VERSION_V2 = "manual-transaction-v2"
CIRCUIT_VERSION_V3 = "manual-transaction-v3"
READ_ONLY_CIRCUIT_VERSIONS = (CIRCUIT_VERSION_V2,)

# Must stay in exact sync with the CATEGORY_COUNT ordering in
# zkp/manual_expense_v4/src/main.nr and MANUAL_CATEGORIES in static/app.js.
# Index in this tuple == the circuit's category_id witness value.
CATEGORY_IDS = (
    "Housing", "Groceries", "Dining", "Transport", "Utilities", "Subscriptions",
    "Shopping", "Health & insurance", "Investing", "Other (expense)",
    "Salary", "Freelance", "Investment income", "Refund", "Gift", "Other (income)",
)

_ROOT = Path(__file__).resolve().parent
BB_EXECUTABLE = os.environ.get("ZKP_BB_EXECUTABLE") or shutil.which("bb") or "bb"
_DEFAULT_VK_PATH = _ROOT / "zkp" / "manual_expense_v4" / "target" / "vk"
VK_PATH = Path(os.environ["ZKP_V4_VK_PATH"]) if os.environ.get("ZKP_V4_VK_PATH") else _DEFAULT_VK_PATH
# Baked-in BN254 CRS (see Dockerfile). Without it bb would try to download
# the CRS over plain HTTP at request time, so the verifier is reported
# unavailable unless this directory holds both files.
CRS_DIR = Path(os.environ["ZKP_CRS_DIR"]) if os.environ.get("ZKP_CRS_DIR") else None
CRS_FILES = ("bn254_g1.dat", "bn254_g2.dat")
VERIFY_TIMEOUT_SECONDS = float(os.environ.get("ZKP_VERIFY_TIMEOUT_SECONDS", "10"))
MAX_PROOF_BYTES = int(os.environ.get("ZKP_MAX_PROOF_BYTES", str(256 * 1024)))
# challenge, record_id_hash, schema_version, key_commitment, vault_salt,
# then the return tuple: commitment, ciphertext[8], mac.
SERVER_INPUT_COUNT = 5
CIPHERTEXT_LEN = 8
PUBLIC_INPUT_COUNT = SERVER_INPUT_COUNT + 1 + CIPHERTEXT_LEN + 1
FIELD_BYTES = 32
RECORD_ID_BYTES = 16
BN254_SCALAR_MODULUS = int("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 16)
_CANONICAL_FIELD_HEX = re.compile(r"0x[0-9a-f]{64}")


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


def _bb_present() -> bool:
    return shutil.which(BB_EXECUTABLE) is not None or Path(BB_EXECUTABLE).is_file()


def _crs_present() -> bool:
    return CRS_DIR is not None and all((CRS_DIR / name).is_file() for name in CRS_FILES)


def artifacts_available() -> bool:
    """Non-raising check used by /ready (non-fatal field), the challenge
    endpoint and startup logging. True only when the VK, bb and the baked
    CRS are all present, so no request ever triggers a CRS download."""
    return VK_PATH.is_file() and _bb_present() and _crs_present()


def _require_artifacts() -> None:
    if not VK_PATH.is_file():
        raise CircuitArtifactsUnavailable("verification key not found")
    if not _bb_present():
        raise CircuitArtifactsUnavailable("bb executable not found")
    if not _crs_present():
        raise CircuitArtifactsUnavailable("baked CRS not found")


def canonical_field_hex(value: int | bytes | str) -> str:
    """Return one canonical `0x`-prefixed 32-byte BN254 field encoding.

    Bytes are interpreted as a big-endian unsigned integer. Strings may
    contain hexadecimal with or without `0x`; they are parsed, range
    checked, and padded. This helper is for server-owned values only;
    request public inputs are required to already be canonical.
    """
    if isinstance(value, bytes):
        integer = int.from_bytes(value, "big")
    elif isinstance(value, int) and not isinstance(value, bool):
        integer = value
    elif isinstance(value, str):
        raw = value[2:] if value.startswith("0x") else value
        if not raw or not re.fullmatch(r"[0-9a-f]+", raw):
            raise ZkpVerificationError("invalid public input encoding")
        integer = int(raw, 16)
    else:
        raise ZkpVerificationError("invalid public input type")
    if not 0 <= integer < BN254_SCALAR_MODULUS:
        raise ZkpVerificationError("public input is outside the BN254 scalar field")
    return f"0x{integer:064x}"


def expected_server_inputs(*, challenge: bytes, record_id: bytes, key_commitment: bytes, vault_salt: bytes) -> tuple[str, ...]:
    """The first five public inputs, in Noir ABI declaration order, built
    only from server-owned rows (challenge row and vault_identity). The
    client never chooses any of them."""
    return (
        canonical_field_hex(challenge),
        canonical_field_hex(record_id),
        canonical_field_hex(SCHEMA_VERSION),
        canonical_field_hex(key_commitment),
        canonical_field_hex(vault_salt),
    )


def sealed_from_outputs(record_id: bytes, public_inputs: tuple[str, ...]) -> str:
    """Stored v4 record, built by the server from the VERIFIED proof outputs:
    record_id (16 bytes) || ciphertext (8 x 32) || mac (32), lowercase hex.
    The stored ciphertext is therefore exactly the proven one."""
    if len(record_id) != RECORD_ID_BYTES:
        raise ZkpVerificationError("invalid record id")
    outputs = public_inputs[SERVER_INPUT_COUNT + 1:]
    return record_id.hex() + "".join(value[2:] for value in outputs)


def commitment_from_outputs(public_inputs: tuple[str, ...]) -> str:
    return public_inputs[SERVER_INPUT_COUNT][2:]


def validate_public_inputs(public_inputs: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(public_inputs, (list, tuple)) or len(public_inputs) != PUBLIC_INPUT_COUNT:
        raise ZkpVerificationError("incorrect public input count")
    result = tuple(public_inputs)
    for value in result:
        if not isinstance(value, str) or _CANONICAL_FIELD_HEX.fullmatch(value) is None:
            raise ZkpVerificationError("public input is not canonical field hex")
        if int(value[2:], 16) >= BN254_SCALAR_MODULUS:
            raise ZkpVerificationError("public input is outside the BN254 scalar field")
    return result


def _validate_proof_bytes(proof_bytes: bytes) -> bytes:
    if not isinstance(proof_bytes, (bytes, bytearray)) or not proof_bytes:
        raise ZkpVerificationError("proof is missing or empty")
    if len(proof_bytes) > MAX_PROOF_BYTES:
        raise ZkpVerificationError("proof exceeds the maximum accepted size")
    if len(proof_bytes) % FIELD_BYTES:
        raise ZkpVerificationError("proof is not a sequence of field elements")
    normalized = bytes(proof_bytes)
    for offset in range(0, len(normalized), FIELD_BYTES):
        if int.from_bytes(normalized[offset:offset + FIELD_BYTES], "big") >= BN254_SCALAR_MODULUS:
            raise ZkpVerificationError("proof contains a non-canonical field element")
    return normalized


def verify_proof(proof_bytes: bytes, public_inputs: list[str] | tuple[str, ...]) -> VerificationResult:
    """Verify a manual-expense proof against the pinned verification key.

    The caller must first check that the first five inputs equal
    expected_server_inputs(). This function still validates their binary
    shape and passes the same values to the cryptographic verifier.
    """
    proof = _validate_proof_bytes(proof_bytes)
    fields = validate_public_inputs(public_inputs)
    _require_artifacts()

    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="zkp_verify_") as tmpdir:
        # Server-generated filename, inside a server-generated temp
        # directory -- never derived from client input.
        proof_path = Path(tmpdir) / "proof"
        public_inputs_path = Path(tmpdir) / "public_inputs"
        proof_path.write_bytes(proof)
        public_inputs_path.write_bytes(b"".join(bytes.fromhex(value[2:]) for value in fields))
        try:
            result = subprocess.run(
                [
                    BB_EXECUTABLE, "verify", "-s", "ultra_honk",
                    "-p", str(proof_path), "-i", str(public_inputs_path),
                    "-k", str(VK_PATH), "-c", str(CRS_DIR),
                ],
                capture_output=True,
                timeout=VERIFY_TIMEOUT_SECONDS,
                check=False,
                cwd=tmpdir,
            )
        except subprocess.TimeoutExpired as exc:
            # Not the client's fault: treat like an unavailable verifier
            # (503, challenge refunded) rather than an invalid proof.
            raise CircuitArtifactsUnavailable("proof verification timed out") from exc
        except OSError as exc:
            raise CircuitArtifactsUnavailable("could not invoke the bb executable") from exc

    duration = time.monotonic() - started
    # Only the exit code is trusted (0 == valid). stdout/stderr are never
    # parsed for a decision and never forwarded to the client -- see
    # app.py's generic "Unable to validate the encrypted record." response.
    return VerificationResult(valid=result.returncode == 0, duration_seconds=duration)


def category_id_for(name: str | None) -> tuple[int, bool]:
    """(category_id, has_category) matching the circuit's witness shape,
    using the circuit's internal labels. The two Other labels are distinct
    because their ids bind income vs expense. Raises ValueError for anything
    not in CATEGORY_IDS -- callers must fail closed rather than defaulting."""
    if name is None:
        return 0, False
    try:
        return CATEGORY_IDS.index(name), True
    except ValueError:
        raise ValueError(f"unknown category: {name!r}") from None
