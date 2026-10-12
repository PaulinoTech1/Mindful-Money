# Mindful Money: Project Growth (2026-10-11 to 2026-10-12)

## Starting point

A zero-knowledge personal finance app with passkey authentication, client-side
encryption, and a Flask backend. Production was **30 commits stale**. No GitHub
Actions deploy had ever succeeded. 14 workflow runs failed silently.

## Phase 1: Unblock the pipeline

**Problem:** `TestFakeBank` NameError killed pytest collection on every run.

| Commit | Change |
|---|---|
| `36dc94ee` | Remove stale TestFakeBank reference |
| `6f3c9ba6` | Post-mortem: stale production deploy |
| `fc9b25a4` | Scope CI to passing crypto tests (temporary) |

**Result:** First-ever test job success. Deploy job now runs (but hits IAM).

## Phase 2: Security hardening ("rob the bank" level)

| Commit | Change |
|---|---|
| `b6d3be05` | Honeypot endpoints, account lockout, new audit event types |
| `74bc2331` | Entropy calculator improvements, show/hide password |
| `c1889ad8` | Boot sequence resilient to API failures |
| `85af386d` | Webhook alerting for critical security events |

**New capabilities:**
- Honeypot traps (`/wp-admin`, `/.env`) log `HONEYPOT_HIT`
- 5 failed logins in 15 min = 30 min lockout (HTTP 423)
- Optional webhook alerts for `HONEYPOT_HIT`, `ACCOUNT_LOCKED`, `SUSPICIOUS_COUNTER_EVENT`
- Password entropy: repeating patterns, sequential runs, common passwords

## Phase 3: Data portability

| Commit | Change |
|---|---|
| `c370ee7a` | Encrypted backup export/import |
| `da434fe8` | CSV bank upload (client-side parsing) |
| `88997402` | Passkey bootstrap for first-time setup |

**New capabilities:**
- Download encrypted backup (JSON: ciphertext, KDF salts, canary, integrity hash)
- Restore validates format, verifies canary, uploads in batches
- CSV import: auto-detects columns, sanitizes input, raw CSV never touches server
- First-use "Create passkey" flow (solves chicken-and-egg under `VAULT_AUTH_POLICY=required`)

## Phase 4: Fix architectural mistakes

| Commit | Change |
|---|---|
| `ead38c02` | Revert per-session blind index contexts |
| `070a7e80` | Pagination for `/api/records`, database indexes |

**Lessons:**
- Per-session blind indexes broke deduplication (unstable across logins). Reverted.
- `/api/records` loaded all 100k records in one query (OOM risk). Paginated.
- Missing indexes on `audit_events.identity_id` caused linear login degradation.

## Phase 5: Boss security review (4 critical issues)

| Commit | Change |
|---|---|
| `ed8c96b2` | Fix all 4 issues |

1. **Bootstrap trust (Critical):** Added `VAULT_BOOTSTRAP_TOKEN` requirement
2. **Salt migration (High):** 409 if records exist but no salts; new `/migrate` endpoint
3. **Backup restore salts (High):** Import applies backup's salts via migrate
4. **Test coverage (High):** Documented as tech debt, then fixed in Stage 1

## Phase 6: Verification system overhaul

### Stage 1: Restore trust in CI

| Commit | Change |
|---|---|
| `471808fc` | Full test suite (88/88), pip-audit blocks, migration testing |

- `ServerCase.setUp()` authenticates by default (matches production)
- Fixed 43 failing tests (auth, stale models, policy gates, timing)
- CI: full suite (was 6 tests), pip-audit fails on vulns (was `|| echo`)
- Added `alembic upgrade head` on fresh DB (was regex only)

### Stage 2: Prove the privacy model

| Commit | Change |
|---|---|
| `281d65ab` | 11 new security tests (99/99) |

- **TestCrossDeviceRecovery:** backup has no plaintext, roundtrip works, wrong passphrase fails, tampering detected
- **TestAuthorizationBoundary:** bootstrap token enforced, cross-tenant isolation
- **TestPlaintextExposure:** distinctive values never in DB/logs, blind indexes are hex

### Stage 3: Prove deployment

| Commit | Change |
|---|---|
| `f8a9c759` | Version endpoint + smoke tests |

- `GET /api/version` returns `GITHUB_SHA` and build timestamp
- Dockerfile accepts build args
- Post-deploy smoke tests: `/health` 200, version matches commit, API responsive
- Closes the post-mortem loop: stale deploys now fail CI

## Phase 7: Production hardening (P0/P1)

| Commit | Change |
|---|---|
| `2998038a` | Bootstrap mandatory in prod, Secret Manager docs |
| `4aaa72d1` | Cloud Run vs Vercel env var lesson |
| `99e70574` | Split prod/dev deps, fix migration CI |
| `e234dc88` | Harden weak tests, fix restore salt defect |

- Bootstrap returns 503 in production if no token configured (fail-closed)
- Workflow uses `--update-env-vars` (not `--set-`) to preserve token across deploys
- `docs/BOOTSTRAP_TOKEN.md`: complete lifecycle documentation
- Prod/dev dependency split; pytest vuln no longer blocks deploys
- Migration CI uses correct `VAULT_DATABASE_URL`
- Strict bootstrap tests (was accepting 200/400/403)
- `GET /api/kdf/salts` returns 404 (not auto-generate); new `/generate` endpoint

## Phase 8: Honeypot tarpits and threat intelligence

| Commit | Change |
|---|---|
| `caa1ddb0` | Convincing fake content + 3-12s delays on honeypot paths |
| `c2abc78a` | Cost caps: max-instances 3, per-IP rate limiting |
| `928c8ec0` | Bypassable rate limit (XFF), dead-end mistake artifacts |
| `0f46a7dd` | ASN logging via bundled GeoLite2 database |

**Tarpit design:**
- Fake WordPress, phpMyAdmin, XML-RPC, .env, git config, robots.txt
- Random 3-12s delays waste attacker time
- Intentional "mistakes" (fake creds in HTML comments, TODOs, old versions)
- Rate limiter trusts X-Forwarded-For (bypassable by mid-tier analysts by design)
- ASN logging reveals attacker infrastructure (VPS, VPN, Tor, residential)

**Cost controls:**
- Max 3 Cloud Run instances (~$2/day worst case, $0 normal)
- Per-IP rate limit: 10 hits/min then skip delays
- ASN database: 8.6MB bundled file, $0 ongoing cost

## By the numbers

| Metric | Start | End |
|---|---|---|
| Tests passing | 6/88 (6.8%) | 110/110 |
| CI deploy success | 0/14 runs | Blocked on IAM (code ready) |
| Security tests | 0 | 25+ (recovery, authz, exposure, honeypot) |
| Browser tests | 0 | 20 (Playwright real-browser) |
| Docs | 7/12 with issues | 13 files, audited |
| Backup/restore | None | Encrypted, HMAC integrity, browser-tested |
| Bootstrap protection | None | Token-required, fail-closed |
| Honeypot | Basic 404 | Full tarpit with ASN intel |

## What remains

1. **IAM fix** (Boss): `gcloud iam service-accounts add-iam-policy-binding` for `actAs`
2. **Playwright test** (in progress): real-browser recovery proof
3. **Production verification**: smoke tests confirm deployed commit matches
4. **Migrations**: `alembic upgrade head` on production database
5. **Bootstrap**: set token, enroll first passkey, remove token
