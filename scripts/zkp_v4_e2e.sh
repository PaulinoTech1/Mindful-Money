#!/usr/bin/env bash
# End-to-end check of the v4 key-bound circuit with the pinned toolchain.
#   1. nargo tests (honest passes; random key, wrong salt, wrong record id,
#      nonce mismatch fail).
#   2. Rebuild: compiled circuit and VK must equal the committed artifacts.
#   3. bb prove/verify: an honest proof verifies; a proof made with a random
#      key (self-consistent for that key's own commitment) is rejected when
#      checked against the REGISTERED commitment, as the server does; a
#      record_id substitution is rejected.
# Needs nargo 1.0.0-beta.26, bb 5.1.0 and a CRS directory (ZKP_CRS_DIR) that
# already holds bn254_g1_compressed.dat and bn254_g2.dat (no download).
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
dir="$repo_root/zkp/manual_expense_v4"
crs="${ZKP_CRS_DIR:?set ZKP_CRS_DIR to a directory holding the pinned CRS}"
[[ -z "${FIXTURE_OUT:-}" || "$FIXTURE_OUT" = /* ]] || FIXTURE_OUT="$PWD/$FIXTURE_OUT"
[[ "$(nargo --version)" == *"nargo version = 1.0.0-beta.26"* ]] || { echo "need nargo 1.0.0-beta.26" >&2; exit 1; }
[[ "$(bb --version)" == "5.1.0" ]] || { echo "need bb 5.1.0" >&2; exit 1; }
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cd "$dir"

nargo test
cp target/manual_expense_v4.json "$work/committed.json"; cp target/vk "$work/committed_vk"
nargo compile
cmp target/manual_expense_v4.json "$work/committed.json" || { echo "compiled circuit differs from committed artifact" >&2; exit 1; }
bb write_vk -s ultra_honk -b target/manual_expense_v4.json -o "$work" -c "$crs" >/dev/null 2>&1
cmp "$work/vk" "$work/committed_vk" || { echo "VK differs from committed vk" >&2; exit 1; }
cmp "$work/vk_hash" target/vk_hash || { echo "vk_hash differs" >&2; exit 1; }

fixture="$(nargo test print_fixture --show-output 2>&1 | grep -a -o 'FIXTURE commit=[^ ]* other_commit=[^ ]* nonce=[^ ]*')"
commit="$(sed 's/.*FIXTURE commit=\([^ ]*\).*/\1/' <<<"$fixture")"
other_commit="$(sed 's/.* other_commit=\([^ ]*\).*/\1/' <<<"$fixture")"
nonce="$(sed 's/.* nonce=\([^ ]*\)$/\1/' <<<"$fixture")"
name="[$(python3 -c "print(','.join(str(b) for b in list(b'Coffee')+[0]*114))")]"

write_prover() { # $1 file, $2 zk_root, $3 key_commitment
  cat > "$1" <<TOML
name_bytes = $name
name_length = 6
amount_cents = 4599
category_id = 1
has_category = true
commitment_blinding = "333"
zk_root = "$2"
enc_nonce = "$nonce"
challenge = "111"
record_id_hash = "222"
schema_version = 4
key_commitment = "$3"
vault_salt = "0x55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55aa55"
TOML
}
write_prover "$work/honest.toml" "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd" "$commit"
write_prover "$work/random.toml" "0x0fedcba9876543210fedcba9876543210fedcba9876543210fedcba98765" "$other_commit"

for who in honest random; do
  nargo execute -p "$work/$who.toml" "e2e_$who" >/dev/null
  mkdir -p "$work/$who"
  bb prove -s ultra_honk -b target/manual_expense_v4.json -w "target/e2e_$who.gz" -o "$work/$who" -c "$crs" >/dev/null 2>&1
  rm -f "target/e2e_$who.gz"
done

verify() { bb verify -s ultra_honk -p "$1" -i "$2" -k target/vk -c "$crs" >/dev/null 2>&1; }

# Public inputs: 0 challenge, 1 record_id_hash, 2 schema_version,
# 3 key_commitment, 4 vault_salt, 5 commitment, 6..13 ciphertext, 14 mac.
replace_field() { # $1 in, $2 out, $3 index, $4 hex value
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys
data = bytearray(open(sys.argv[1], 'rb').read()); i = int(sys.argv[3])
data[32*i:32*i+32] = int(sys.argv[4], 16).to_bytes(32, 'big')
open(sys.argv[2], 'wb').write(data)
PY
}

verify "$work/honest/proof" "$work/honest/public_inputs" && echo "PASS honest proof verifies" || { echo "FAIL honest proof rejected" >&2; exit 1; }
replace_field "$work/random/public_inputs" "$work/random_registered" 3 "$commit"
if verify "$work/random/proof" "$work/random_registered"; then echo "FAIL random-key proof verified against the registered commitment" >&2; exit 1; fi
echo "PASS random-key proof rejected against the registered commitment (bb exit nonzero)"
replace_field "$work/honest/public_inputs" "$work/honest_other_record" 1 "0xdf"
if verify "$work/honest/proof" "$work/honest_other_record"; then echo "FAIL proof accepted for another record id" >&2; exit 1; fi
echo "PASS proof rejected for a different record_id_hash (bb exit nonzero)"
if [[ -n "${FIXTURE_OUT:-}" ]]; then
  mkdir -p "$FIXTURE_OUT"
  cp "$work/honest/proof" "$FIXTURE_OUT/proof"; cp "$work/honest/public_inputs" "$FIXTURE_OUT/public_inputs"
  echo "wrote honest proof fixture to $FIXTURE_OUT"
fi
echo "zkp v4 e2e OK"
