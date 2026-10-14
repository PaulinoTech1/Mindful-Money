# Browser CRS slice

Inlined into `static/zkp/build/mm-zkp-v4.js` so the browser prover never
downloads a CRS from a third party.

| File | Contents | sha256 |
| --- | --- | --- |
| `g1_compressed_2p17.dat` | First 2^17 compressed BN254 G1 points, byte-identical to the server CRS pinned as `CRS_G1_SHA256` in `scripts/fetch_zkp_runtime.py` (bb's SrsInitSrs takes compressed points in 2^17-point chunks) | `fad8203ae1fd103658d4bb33b2b4cf126a28352b5de4684737cff23cc15fb94b` |
| `g2.dat` | BN254 G2 point, identical to `CRS_G2_SHA256` | `01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f` |

`test_integrity_script.py` checks both against the pins in
`scripts/fetch_zkp_runtime.py`. This directory is outside the Docker build
context; only the built bundle ships.
