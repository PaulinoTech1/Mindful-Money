#!/usr/bin/env python3
"""Generate Subresource Integrity (SRI) manifest for Mindful Money static JS.

This script:
1. Computes SHA-384 hashes for all crypto-relevant JavaScript files
2. Generates an integrity manifest (static/integrity-manifest.json)
3. Updates static/index.html with integrity attributes

The manifest enables:
- Browser enforcement via SRI (defense against accidental modification,
  CDN tampering, and as an audit signal)
- CI verification that deployed JS matches the tested commit
- Out-of-band verification by users (compare served hashes to git)

LIMITATION: SRI on same-origin scripts does not stop a fully compromised
origin (attacker can modify both HTML and JS). The real protection is:
1. CI deploy verification (checks served JS matches git commit)
2. User out-of-band verification via the manifest
3. Future: signed manifest with offline key

Usage:
    python3 scripts/generate_integrity.py
    python3 scripts/generate_integrity.py --check  # verify only, no writes
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).parent.parent
STATIC = HERE / "static"
MANIFEST_PATH = STATIC / "integrity-manifest.json"

# Crypto-relevant JS files that must have integrity protection.
# Vendor files are included; they change rarely but must be pinned.
JS_FILES = [
    "vendor/libsodium-sumo.js",
    "vendor/libsodium-wrappers.js",
    "vendor/chart.umd.min.js",
    "simplefin-client.js",
    "recovery-words.js",
    "app.js",
    # Lazy-loaded ZKP v4 prover (one self-contained module, ~17 MB). Its tag
    # lives in <template id="zkpProverTemplate"> and app.js clones it in.
    "zkp/build/mm-zkp-v4.js",
]


def compute_sri(path: Path) -> str:
    """Compute SHA-384 SRI hash for a file."""
    h = hashlib.sha384()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    digest = base64.b64encode(h.digest()).decode("ascii")
    return f"sha384-{digest}"


def generate_manifest() -> dict:
    """Generate the integrity manifest."""
    manifest = {
        "version": 1,
        "generated_by": "scripts/generate_integrity.py",
        "files": {},
    }
    for rel in JS_FILES:
        path = STATIC / rel
        if not path.exists():
            print(f"WARNING: {rel} not found, skipping", file=sys.stderr)
            continue
        manifest["files"][rel] = {
            "sri": compute_sri(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    return manifest


def update_html(manifest: dict) -> None:
    """Update index.html with integrity attributes."""
    html_path = STATIC / "index.html"
    html = html_path.read_text()

    for rel, info in manifest["files"].items():
        # Match <script src="/static/REL"></script> or <script src="/static/REL">
        pattern = rf'<script src="/static/{re.escape(rel)}"([^>]*)>'
        sri = info["sri"]

        def replacer(m):
            attrs = m.group(1)
            # Drop every existing integrity and crossorigin attribute, then
            # add exactly one of each. Earlier versions kept the old
            # crossorigin and appended another, so every run added a
            # duplicate; this form is idempotent.
            attrs = re.sub(r'\s+(?:integrity|crossorigin)(?:="[^"]*")?', '', attrs)
            return f'<script src="/static/{rel}"{attrs} integrity="{sri}" crossorigin="anonymous">'

        new_html, count = re.subn(pattern, replacer, html)
        if count > 0:
            print(f"  Updated integrity for {rel}")
            html = new_html
        else:
            print(f"  WARNING: no script tag found for {rel}", file=sys.stderr)

    if html != html_path.read_text():
        html_path.write_text(html)


def check_manifest() -> bool:
    """Verify current files match the manifest. Returns True if all match."""
    if not MANIFEST_PATH.exists():
        print(f"ERROR: {MANIFEST_PATH} not found", file=sys.stderr)
        return False

    manifest = json.loads(MANIFEST_PATH.read_text())
    ok = True
    for rel, info in manifest["files"].items():
        path = STATIC / rel
        if not path.exists():
            print(f"FAIL: {rel} missing", file=sys.stderr)
            ok = False
            continue
        current = compute_sri(path)
        if current != info["sri"]:
            print(f"FAIL: {rel} hash mismatch", file=sys.stderr)
            print(f"  expected: {info['sri']}", file=sys.stderr)
            print(f"  actual:   {current}", file=sys.stderr)
            ok = False
        else:
            print(f"OK: {rel}")
    return ok


def main():
    check_only = "--check" in sys.argv

    if check_only:
        sys.exit(0 if check_manifest() else 1)

    print("Generating integrity manifest...")
    manifest = generate_manifest()

    print(f"\nWriting {MANIFEST_PATH}...")
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n")

    print("\nUpdating index.html with SRI attributes...")
    update_html(manifest)

    print("\nDone. Review the changes and commit.")
    print("\nLIMITATION REMINDER: SRI on same-origin scripts does not prevent")
    print("a compromised origin from replacing both HTML and JS. This is")
    print("defense-in-depth. Real protection requires CI deploy verification")
    print("and out-of-band manifest checks.")


if __name__ == "__main__":
    main()
