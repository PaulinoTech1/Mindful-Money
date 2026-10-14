#!/usr/bin/env python3
"""scripts/generate_integrity.py and the lazy ZKP prover bundle.

    pytest test_integrity_script.py

- Running the generator twice is idempotent (it used to append one more
  crossorigin="anonymous" to every tag per run).
- Every pinned script tag has exactly one integrity and one crossorigin.
- The committed manifest and index.html match the committed files,
  including static/zkp/build/mm-zkp-v4.js inside <template>.
- The CRS slice inlined into the bundle is the pinned one.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
from pathlib import Path

HERE = Path(__file__).parent
STATIC = HERE / "static"


def load_generator(static_dir: Path):
    spec = importlib.util.spec_from_file_location("generate_integrity", HERE / "scripts" / "generate_integrity.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.STATIC = static_dir
    mod.MANIFEST_PATH = static_dir / "integrity-manifest.json"
    return mod


def copy_static(tmp_path: Path) -> Path:
    dest = tmp_path / "static"
    gen = load_generator(STATIC)
    for rel in gen.JS_FILES + ["index.html", "integrity-manifest.json"]:
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(STATIC / rel, dest / rel)
    return dest


def script_tags(html: str):
    return re.findall(r'<script src="/static/[^"]+"[^>]*>', html)


def test_generator_is_idempotent(tmp_path):
    static = copy_static(tmp_path)
    html_path = static / "index.html"
    # Start from the historical bug: duplicated crossorigin attributes.
    html_path.write_text(html_path.read_text().replace(
        'crossorigin="anonymous"', 'crossorigin="anonymous" crossorigin="anonymous"'))
    gen = load_generator(static)
    gen.update_html(gen.generate_manifest())
    once = html_path.read_text()
    gen.update_html(gen.generate_manifest())
    gen.update_html(gen.generate_manifest())
    assert html_path.read_text() == once
    for tag in script_tags(once):
        assert tag.count("crossorigin=") == 1, tag
        assert tag.count("integrity=") == 1, tag


def test_committed_html_and_manifest_match_files():
    gen = load_generator(STATIC)
    manifest = json.loads((STATIC / "integrity-manifest.json").read_text())
    assert manifest == gen.generate_manifest(), "run python3 scripts/generate_integrity.py"
    html = (STATIC / "index.html").read_text()
    tags = script_tags(html)
    assert len(tags) == len(gen.JS_FILES)
    for rel, info in manifest["files"].items():
        tag = next(t for t in tags if f'src="/static/{rel}"' in t)
        assert f'integrity="{info["sri"]}"' in tag, rel
        assert tag.count("crossorigin=") == 1, rel


def test_prover_is_lazy_template_module():
    html = (STATIC / "index.html").read_text()
    m = re.search(r'<template id="zkpProverTemplate">(.*?)</template>', html, re.S)
    assert m, "prover template missing"
    assert 'src="/static/zkp/build/mm-zkp-v4.js" type="module"' in m.group(1)
    # Not loaded eagerly anywhere else.
    assert html.count("mm-zkp-v4.js") == 1


def test_inlined_crs_is_the_pinned_one():
    spec = importlib.util.spec_from_file_location("fetch_zkp_runtime", HERE / "scripts" / "fetch_zkp_runtime.py")
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    crs = HERE / "zkp" / "browser_crs"
    assert hashlib.sha256((crs / "g1_compressed_2p17.dat").read_bytes()).hexdigest() == runtime.CRS_G1_SHA256
    assert hashlib.sha256((crs / "g2.dat").read_bytes()).hexdigest() == runtime.CRS_G2_SHA256
