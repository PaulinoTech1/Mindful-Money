#!/usr/bin/env python3
"""Test the v3 circuit's plaintext packing/unpacking logic.

This verifies the field arithmetic for packing name/amount/category into
field elements, without requiring Poseidon2 or nargo. The actual encryption
(Poseidon keystream) is tested separately once the circuit is compiled.
"""

FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
MAX_NAME_BYTES = 120
BYTES_PER_FIELD = 30
CIPHERTEXT_LEN = 8


def pack_plaintext(name: bytes, amount_cents: int, category_id: int, has_category: bool):
    """Pack into 8 field elements (must match main.nr)."""
    assert 1 <= len(name) <= MAX_NAME_BYTES
    assert 1 <= amount_cents <= 99999999999
    assert category_id < 16
    
    plaintext = [0] * CIPHERTEXT_LEN
    
    # Pack name: 30 bytes per field, little-endian
    name_padded = name.ljust(MAX_NAME_BYTES, b'\x00')
    for f in range(4):
        acc = 0
        mult = 1
        for b in range(BYTES_PER_FIELD):
            idx = f * BYTES_PER_FIELD + b
            acc += name_padded[idx] * mult
            mult *= 256
        plaintext[f] = acc
    
    # Pack metadata
    meta = amount_cents
    meta += category_id * (1 << 64)
    if has_category:
        meta += (1 << 128)
    meta += len(name) * (1 << 129)
    plaintext[4] = meta
    
    # Fields 5-7 are zero
    return plaintext


def unpack_plaintext(plaintext):
    """Unpack field elements to components."""
    assert len(plaintext) == CIPHERTEXT_LEN
    
    # Unpack name
    name_bytes = bytearray()
    for f in range(4):
        val = plaintext[f]
        for b in range(BYTES_PER_FIELD):
            name_bytes.append(val & 0xFF)
            val >>= 8
    name_bytes = bytes(name_bytes[:MAX_NAME_BYTES])
    
    # Unpack metadata
    meta = plaintext[4]
    amount_cents = meta & ((1 << 64) - 1)
    category_id = (meta >> 64) & ((1 << 64) - 1)
    has_category = bool((meta >> 128) & 1)
    name_length = (meta >> 129) & ((1 << 32) - 1)
    
    name = name_bytes[:name_length]
    return name, amount_cents, category_id, has_category


def test_roundtrip():
    """Test pack/unpack roundtrip."""
    test_cases = [
        (b"Coffee", 550, 2, True),
        (b"A" * 120, 99999999999, 15, True),  # max values
        (b"X", 1, 0, False),  # min values
        ("Café ☕".encode('utf-8'), 1234, 5, True),  # UTF-8
    ]
    
    for name, amount, cat, has_cat in test_cases:
        packed = pack_plaintext(name, amount, cat, has_cat)
        # Verify all fields < modulus
        for f in packed:
            assert f < FIELD_MODULUS, f"Field exceeds modulus: {f}"
        
        unpacked = unpack_plaintext(packed)
        assert unpacked[0] == name, f"Name mismatch: {unpacked[0]} != {name}"
        assert unpacked[1] == amount, f"Amount mismatch"
        assert unpacked[2] == cat, f"Category mismatch"
        assert unpacked[3] == has_cat, f"has_category mismatch"
        print(f"OK: {name[:20]}... amount={amount} cat={cat}")
    
    print("\nAll packing tests passed!")


if __name__ == "__main__":
    test_roundtrip()
