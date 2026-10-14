#!/usr/bin/env python3
"""Docker build step: fetch the ZK verifier runtime, pinned by sha256.

    python fetch_zkp_runtime.py <out_dir> <v4_artifact_dir>

Produces <out_dir>/bb and <out_dir>/crs/{bn254_g1.dat,bn254_g2.dat}:
  1. bb 5.1.0 release tarball over HTTPS; tarball and binary sha256 pinned.
  2. First 2^17 points of the Aztec BN254 CRS (compressed, HTTPS range
     request) and the G2 point; both sha256 pinned.
  3. Runs `bb write_vk` on the committed v4 circuit with that CRS, which
     (a) writes the decompressed bn254_g1.dat the verifier reads, so nothing
     is downloaded at request time, and (b) proves the committed VK matches
     the committed circuit. The decompressed file is pinned too.
Any mismatch fails the image build. Only public artifacts; no secrets.
"""
from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

BB_URL = "https://github.com/AztecProtocol/barretenberg/releases/download/v5.1.0/barretenberg-amd64-linux.tar.gz"
BB_TARBALL_SHA256 = "016fa165a5c1b860386b9afa6ef49bf09bcd14246315d7c05cdeddd88349edaf"
BB_BINARY_SHA256 = "71c1858665c00db527245a17e4bd28388085939ae3c20310220f0d34a7c843d5"
CRS_G1_URL = "https://crs.aztec-labs.com/g1_compressed.dat"
CRS_G1_BYTES = 32 * (1 << 17)  # 2^17 compressed points, 4 MiB
CRS_G1_SHA256 = "fad8203ae1fd103658d4bb33b2b4cf126a28352b5de4684737cff23cc15fb94b"
CRS_G2_URL = "https://crs.aztec-labs.com/g2.dat"
CRS_G2_SHA256 = "01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f"
# Decompressed by bb write_vk for the v4 circuit (2^15 points).
CRS_G1_DECOMPRESSED_SHA256 = "50d2f4e9567be2b8e382cedfd078b96a3428a94597b7e88c4116e105d578ce77"


def fetch(url: str, expected: str, byte_range: int | None = None) -> bytes:
    if not url.startswith("https://"):
        raise SystemExit("refusing non-HTTPS download")
    req = urllib.request.Request(url, headers={"Range": f"bytes=0-{byte_range - 1}"} if byte_range else {})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
    if byte_range is not None and len(data) != byte_range:
        raise SystemExit(f"unexpected length from {url}")
    return check(data, expected, url)


def check(data: bytes, expected: str, label: str) -> bytes:
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise SystemExit(f"sha256 mismatch for {label}: {got}")
    return data


def main() -> None:
    out, artifacts = Path(sys.argv[1]), Path(sys.argv[2])
    crs = out / "crs"
    crs.mkdir(parents=True, exist_ok=True)

    tarball = fetch(BB_URL, BB_TARBALL_SHA256)
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        member = tar.getmember("bb")
        bb_bytes = check(tar.extractfile(member).read(), BB_BINARY_SHA256, "bb binary")
    bb = out / "bb"
    bb.write_bytes(bb_bytes)
    bb.chmod(0o755)

    (crs / "bn254_g1_compressed.dat").write_bytes(fetch(CRS_G1_URL, CRS_G1_SHA256, CRS_G1_BYTES))
    (crs / "bn254_g2.dat").write_bytes(fetch(CRS_G2_URL, CRS_G2_SHA256))

    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([str(bb), "write_vk", "-s", "ultra_honk", "-b", str(artifacts / "manual_expense_v4.json"),
                        "-o", tmp, "-c", str(crs)], check=True, capture_output=True)
        for name in ("vk", "vk_hash"):
            if (Path(tmp) / name).read_bytes() != (artifacts / name).read_bytes():
                raise SystemExit(f"committed {name} does not match the committed circuit")
    check((crs / "bn254_g1.dat").read_bytes(), CRS_G1_DECOMPRESSED_SHA256, "decompressed CRS")
    (crs / "bn254_g1_compressed.dat").unlink()
    (crs / "crs.lock").unlink(missing_ok=True)
    shutil.copy2(artifacts / "vk", out / "vk")
    print("zkp runtime ready: bb, CRS and VK verified")


if __name__ == "__main__":
    main()
