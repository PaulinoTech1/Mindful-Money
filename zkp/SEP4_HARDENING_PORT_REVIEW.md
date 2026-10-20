# Port review: ZKP branch commit 4bd5e86d (2026-09-04)

Subject commit: `4bd5e86d` "Harden ZKP verification and professionalize demo data"
on branch `ZKP` (parent `ce6b4d86`), the branch's only commit not on `main`.
Reviewed against `main` at `6d811fb4` on 2026-10-20 by three-way comparison
(base = parent, ours = current main, theirs = the Sep 4 commit), file by file.

## Bottom line

No code from the Sep 4 commit was ported. Every code change in it belongs to
the pre-v4 ZKP architecture (the `manual_expense` circuit, root-relative Vite
WASM assets, a two-argument `api_error` world with an unadopted error-code
grammar), and `main` has since rebuilt the same ground in the v4 line:
PR #12 (merged, per-vault key commitment) and PR #13 (open, v4 UI wiring).
Applying the Sep 4 changes on top of current `main` would regress the v4
verifier paths, the current payload schema, and the current demo dataset.
This file is the ledger behind that verdict, kept so the Sep 4 work stays
auditable. The `ZKP` branch is untouched and still holds the original commit.

## Per-file ledger

| File | Sep 4 change | State on current main | Verdict |
| --- | --- | --- | --- |
| `zkp_verifier.py` | +66/-19, 6 conflict hunks: v3 paths (`zkp/manual_expense/target/vk`), `bb verify` arg order with `-c` CRS flag, health-check docstring, VK path in error message | v4: `_DEFAULT_VK_PATH` points at `zkp/manual_expense_v4`, baked CRS directory, `/ready` non-fatal semantics | Superseded by v4. Keep main. |
| `app.py` | +139/-73, 11 conflict hunks: MM_SERVER_* error codes on ZKP/passkey paths, payload set gains `sealed`/`commitment`, `/api/relay` endpoint, `_DEFAULT_ZKP_CRS_ROOT` | 456 lines of new surface where Sep 4 has 14 (health, v4 routes); `api_error(message, status)` takes two arguments and main contains zero `MM_SERVER_` codes; payload schema set by the v4 flow | Superseded / architectural. The error-code grammar was never adopted on main; porting it means changing `api_error` and every call site, a feature decision, not a port. Keep main. |
| `ERROR_CODES.md` | New file (+65): stable verbose API/client error-code grammar | Absent on main; the grammar it documents exists only in the Sep 4 commit | Not ported. Revivable as a standalone doc if the grammar is adopted later; porting it alone would document a system main does not run. |
| `static/app.js` | +153/-19, 3 conflict hunks: `error.code` plumbing, narrower income regex, v3 decrypt flow | Main added `Retry-After` handling, widened the income regex (added `bonus`), rewrote unlock/decrypt for v4 | Superseded. Keep main. |
| `static/index.html` | +8/-0, 1 hunk: adds a ZKP status card | Spot now carries the ciphertext-length callout; v4 status UI is wired in PR #13 | Superseded by PR #13's approach. Keep main. |
| `static/zkp/vite.config.js` | +19/-5, 1 hunk: keep Noir/ACVM WASM as same-origin asset files | Main's config builds the v4 library bundle; PR #13 moves to a single-file SRI-pinnable prover bundle | Superseded. Keep main. |
| `static/zkp/public/assets/barretenberg.wasm.gz`, `barretenberg-threads.wasm.gz` | New asset files for the v3 bundle | Absent on main; v4 prover is a single-file bundle (PR #13) | Superseded. Not ported. |
| `static/zkp/manual_expense_client.js` | +34/-1, clean take (file unchanged on main since parent) | Not referenced by current `static/index.html`; v4 has its own client path | Inert on current main. Not ported; available at blob `6cf667e32f` on the `ZKP` branch if ever needed. |
| `zkp/README.md` | +19/-3, clean take (unchanged on main since parent) | Both versions document the v3 `manual_expense` setup; the v4 circuit is what current code runs | Stale in both versions. Not ported; v4 documentation belongs with PR #13. |
| `test_zkp_server.py` | +28/-4, 7 conflict hunks: v3 challenge/verifier tests | Rebuilt around v4 helpers (`_set_vault_key` with commitment/salt, `PUBLIC_INPUT_COUNT`) from PR #12 | Superseded. Keep main. |
| `test_browser.py` | +14/-3, 2 hunks: demo expectations ($89.99, "Family Recreation Center") | Current demo dataset differs ($44.00, "Peloton App"); Sep 4 expectations would fail against current main | Demo drift. Keep main. |
| `test_demo.py` | +88/-3, 1 hunk: adds 60-line `TestFakeBank` class | `fakebank.py` was deleted on main | Inert on current main. Not ported. |
| `fakebank.py` | +5/-5 | Deleted on main | Not ported (no resurrection of deleted files). |
| `app.js` (repo root) | +1/-1 | Deleted on main (app lives under `static/`) | Not ported. |
| `README.md` | +3/-2, 2 hunks: "six months of transactions" demo text; adds `ERROR_CODES.md` table row | Main says twelve months (current demo); table row documents the unadopted grammar | Demo drift / tied to ERROR_CODES.md decision. Keep main. |
| `screenshots/2-dashboard.png`, `3-server-view.png`, `4-mobile.png` | Regenerated against the professionalized Sep 4 demo data | Byte-identical to the Sep 4 parent on main, but they depict the Sep 4 dataset, which current demo data no longer matches | Not ported: they would contradict the current demo. Regenerate from current data instead. |

## What would change this verdict

- Adopting the MM_SERVER_* error-code grammar as a feature (new `api_error`
  signature plus call-site pass). That is a design decision for the owner;
  `ERROR_CODES.md` and the Sep 4 call sites are the starting draft.
- Anything in PR #13's review that sends the v4 UI back toward the v3 asset
  layout would revive the vite.config and WASM asset items above.

## Provenance

Method: per-file three-way merge (`git merge-file`) of parent / current main /
Sep 4 versions; conflict census 34 hunks across 9 files (app.py 11,
test_zkp_server.py 7, zkp_verifier.py 6, static/app.js 3, README.md 2,
test_browser.py 2, static/index.html 1, vite.config.js 1, test_demo.py 1).
Prepared by Constantine at the owner's direction, 2026-10-20. No Sep 4 code
was merged, and the `ZKP` branch was not modified.
