#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
circuit_dir="$repo_root/zkp/manual_expense"
client_dir="$repo_root/static/zkp"

nargo_version="$(nargo --version)"
if [[ "$nargo_version" != *"nargo version = 1.0.0-beta.26"* ]]; then
  echo "Expected nargo 1.0.0-beta.26; got: $nargo_version" >&2
  exit 1
fi

bb_version="$(bb --version)"
if [[ "$bb_version" != "5.1.0" ]]; then
  echo "Expected bb 5.1.0; got: $bb_version" >&2
  exit 1
fi

cd "$circuit_dir"
nargo test --show-output
nargo compile
bb write_vk -s ultra_honk -b target/manual_expense.json -o target
sha256sum target/manual_expense.json target/vk target/vk_hash

cd "$client_dir"
npm ci
npm run build
npm run smoke
