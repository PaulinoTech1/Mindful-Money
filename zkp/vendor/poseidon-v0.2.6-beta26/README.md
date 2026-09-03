# Poseidon v0.2.6 compatibility package

This package contains the `Poseidon2` implementation from
`noir-lang/poseidon` tag `v0.2.6`, reduced to the API used by this
application and adapted for Noir `v1.0.0-beta.26`.

The upstream tag does not compile unchanged under beta.26. Noir changed
`std::hash::poseidon2_permutation(state, 4)` to
`std::hash::poseidon2_permutation(state)`, and the old dynamic empty-slice
initializer is also rejected. The application only uses the static
`Poseidon2::hash` API, so this compatibility package keeps that upstream
algorithm and applies the permutation signature change. The untouched
source and license remain available in `zkp/upstream/poseidon`, pinned to
the exact v0.2.6 commit.

Do not treat this as a new cryptographic construction. Replace it with a
future upstream Poseidon release once that release is explicitly
compatible with beta.26, then regenerate the circuit artifact and VK.
