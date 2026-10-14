/* Browser entry for the lazy loaded ZKP v4 prover (static/zkp/build/).
 *
 * Built by `npm run build:browser` into ONE self-contained ES module: the
 * Barretenberg wasm, the Noir ACVM and ABI wasm, the compiled circuit and
 * the first 2^17 compressed BN254 CRS points (prefix of the sha256-pinned
 * file in scripts/fetch_zkp_runtime.py) are inlined. app.js injects it as a
 * <script type="module" integrity=...> cloned from index.html, so the SRI
 * hash pins every byte the prover runs. No workers, no network fetches,
 * no third-party CRS download.
 *
 * Exposes window.MMZkpV4 and fires the 'mm-zkp-v4-ready' event.
 */
import { Barretenberg, BackendType } from '@aztec/bb.js';
import g1 from '../../zkp/browser_crs/g1_compressed_2p17.dat?mmbytes';
import g2 from '../../zkp/browser_crs/g2.dat?mmbytes';
import {
  configureRuntime, enrollKeyCommitment, proveManualTransactionV4,
  decryptManualTransactionV4, keyCommitmentHex, deriveZkRoot, CIRCUIT_VERSION_V4,
} from './manual_expense_v4_client.js';

const CRS_POINTS = 1 << 17;

configureRuntime({
  barretenberg: async () => {
    // Single thread, main thread: no Worker scripts to load outside SRI.
    const bb = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1, skipSrsInit: true });
    await bb.srsInitSrs({ pointsBuf: g1, numPoints: CRS_POINTS, g2Point: g2 });
    return bb;
  },
});

window.MMZkpV4 = Object.freeze({
  CIRCUIT_VERSION_V4, enrollKeyCommitment, proveManualTransactionV4,
  decryptManualTransactionV4, keyCommitmentHex, deriveZkRoot,
});
window.dispatchEvent(new Event('mm-zkp-v4-ready'));
