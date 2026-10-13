# Cloud Run Deployment Troubleshooting

Issues encountered deploying Mindful Money to Google Cloud Run (2026-10-11).

## Secret Manager API not enabled

**Symptom:**
```
ERROR: (gcloud.secrets.create) Secret Manager API has not been used in project
[...] before or it is disabled.
```

**Fix:**
```bash
gcloud services enable secretmanager.googleapis.com
```
Wait 2-3 minutes for propagation before retrying.

## Cloud Build API not enabled

**Symptom:**
```
ERROR: (gcloud.run.deploy) INVALID_ARGUMENT: Invalid build request.
could not resolve source: ... does not have storage.objects.get access ...
```

**Fix:**
```bash
gcloud services enable cloudbuild.googleapis.com
```
If still failing after propagation, grant the Compute service account
explicit Storage Object Viewer:
```bash
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/storage.objectViewer"
```

## Service account key creation blocked

**Symptom:** GCP Console shows "Service account key creation is disabled"
with `iam.disableServiceAccountKeyCreation` organization policy.

**Cause:** Google Advanced Protection mode enforces this policy.

**Workaround:** Do not use JSON keys. Options:
1. Run `gcloud` commands directly from Cloud Shell (already authenticated)
2. Use Workload Identity Federation for CI/CD (no long-lived secrets)

## Build log not found

**Symptom:**
```
(gcloud.builds.log) NOT_FOUND: Requested entity was not found.
```

**Cause:** Build ID from a previous (cleaned up) attempt, or the build
failed before logging started.

**Fix:** Rerun the deploy and use the fresh build ID from the output URL.

## VAULT_RP_ID / VAULT_ORIGIN placeholder

The initial deploy uses `placeholder` values because the Cloud Run URL
is not known until after first deploy. After getting the URL:

```bash
gcloud run deploy mindful-money \
  --region us-central1 \
  --update-env-vars "VAULT_RP_ID=actual-host.run.app,VAULT_ORIGIN=https://actual-host.run.app"
```

WebAuthn will not work until these match the real URL.

## Private service access

Deploy without `--allow-unauthenticated`, then grant invoker access:

```bash
gcloud run services add-iam-policy-binding mindful-money \
  --region us-central1 \
  --member="user:YOUR_EMAIL@gmail.com" \
  --role="roles/run.invoker"
```

## Docker build succeeds but deploy fails

**Symptom:** `gcloud builds describe` shows the `gcr.io/cloud-builders/docker`
step as SUCCESS, but overall build status is FAILURE with empty logs.

**Cause:** The failure is in the push to Artifact Registry or the Cloud Run
deployment phase, not the Docker build itself. The Dockerfile is fine.

**Diagnosis:**
```bash
# Get the latest build ID
BUILD_ID=$(gcloud builds list --region us-central1 --limit 1 --format="value(id)")

# Check step statuses
gcloud builds describe $BUILD_ID --region us-central1 --format="json(steps[].name, steps[].status)"

# Check if the service was created despite the failure
gcloud run services list --region us-central1
```

**Common causes:**
- Artifact Registry API not enabled: `gcloud services enable artifactregistry.googleapis.com`
- Insufficient permissions for the Cloud Build service account to push images
- The `--source .` upload succeeded but the image push failed silently

## Testing the build without deploying

To isolate whether the issue is the Docker build or the Cloud Run deploy:

```bash
# Build only (no deploy) - tags the image but doesn't run it
gcloud builds submit \
  --region us-central1 \
  --tag us-central1-docker.pkg.dev/PROJECT_ID/mindful-money/test:latest \
  .
```

If this succeeds, the Dockerfile is fine and the issue is in the
deploy phase (IAM, secrets, env vars). If it fails, the issue is
in the Docker build itself.

## Manual Docker build test

If Cloud Build logs are empty, test the Dockerfile locally first
(requires Docker installed):

```bash
docker build -t mindful-money-test .
```

This catches Dockerfile syntax errors, missing files, and dependency
issues before involving GCP.

## Cloud Run cannot access Secret Manager secrets

**Symptom:** Deploy fails after Docker build succeeds. The container
cannot start because it cannot read the secrets.

**Cause:** The Cloud Run runtime service account
(`PROJECT_NUMBER-compute@developer.gserviceaccount.com`) does not have
the `secretmanager.secretAccessor` role on the secrets.

**Fix:**
```bash
PROJECT_NUMBER=$(gcloud projects describe PROJECT_ID --format="value(projectNumber)")

gcloud secrets add-iam-policy-binding mindful-money-secret \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud secrets add-iam-policy-binding neon-db-url \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

## Artifact Registry push denied

**Symptom:** `gcloud builds submit` succeeds in building but fails pushing:
```
denied: Permission 'artifactregistry.repositories.uploadArtifacts' denied
```

**Cause:** The Artifact Registry repository does not exist, or the Cloud
Build service account lacks push permission.

**Fix:**
```bash
# Create the repository
gcloud artifacts repositories create mindful-money \
  --repository-format=docker \
  --location=us-central1

# Grant Cloud Build push access
gcloud artifacts repositories add-iam-policy-binding mindful-money \
  --location=us-central1 \
  --member="serviceAccount:PROJECT_NUMBER@cloudbuild.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"
```

## `gcloud run deploy --source` fails after Docker build succeeds

**Symptom:** Multiple `gcloud run deploy --source .` attempts fail with
"Build failed" even though `gcloud builds describe` shows the Docker step
as SUCCESS. The image never appears in Artifact Registry
(`gcloud artifacts docker images list` returns 0 items).

**What was tried:**
1. Enabled Secret Manager, Cloud Build, and Artifact Registry APIs
2. Created the Artifact Registry repository `mindful-money`
3. Granted `roles/artifactregistry.writer` to the Cloud Build service account
4. Granted `roles/storage.objectViewer` to the Compute service account
5. Granted `roles/secretmanager.secretAccessor` to the Cloud Run runtime
   service account for both secrets

**Hypothesis:** The `--source .` flow uses an internal registry path that
does not match the manually created Artifact Registry repository. The
push target is opaque and not configurable, making IAM debugging difficult.

**Next try: Separate build from deploy**

Instead of the combined `--source` flow, split into two explicit steps.
This gives full control over the image tag and registry path:

```bash
# Step 1: Build and push to our known Artifact Registry path
gcloud builds submit \
  --region us-central1 \
  --tag us-central1-docker.pkg.dev/PROJECT_ID/mindful-money/app:latest \
  .

# Step 2: Deploy from the pushed image (no build involved)
gcloud run deploy mindful-money \
  --image us-central1-docker.pkg.dev/PROJECT_ID/mindful-money/app:latest \
  --region us-central1 \
  --set-env-vars "VAULT_ENV=production,..." \
  --set-secrets "VAULT_SECRET_KEY=mindful-money-secret:latest,VAULT_DATABASE_URL=neon-db-url:latest"
```

**Justification:** If Step 1 succeeds, the Dockerfile and registry
permissions are confirmed working. If Step 2 then fails, the issue is
isolated to Cloud Run configuration (env vars, secrets, IAM), not the
build pipeline. This bisects the problem instead of debugging the
opaque combined flow.

## Cloud Build uses Compute service account, not Cloud Build SA

**Symptom:** Push to Artifact Registry fails with permission denied,
even after granting `roles/artifactregistry.writer` to
`PROJECT_NUMBER@cloudbuild.gserviceaccount.com`.

**Cause:** The build log shows:
```
The service account running this build .../serviceAccounts/PROJECT_NUMBER-compute@developer.gserviceaccount.com
```
Cloud Build is using the Compute Engine default service account, not
the Cloud Build service account. The IAM grant went to the wrong identity.

**Fix:** Grant the role to the Compute service account instead:
```bash
gcloud artifacts repositories add-iam-policy-binding mindful-money \
  --location=us-central1 \
  --member="serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role="roles/artifactregistry.writer"
```

## Alembic not found after pip install in Cloud Shell

**Symptom:** `pip install alembic` succeeds but `alembic: command not found`.

**Cause:** Cloud Shell installs user packages to `~/.local/lib/python3.12/site-packages`
with binaries in `~/.local/bin`, which is not in the default PATH.

**Fix:**
```bash
export PATH="$HOME/.local/bin:$PATH"
```

Or use the module directly:
```bash
python3 -m alembic upgrade head
```

## Running migrations from Cloud Shell

**Superseded (2026-10-13).** The earlier procedure here exported the
`neon-db-url` secret, which is the POOLED runtime string; DDL needs the
UNPOOLED string (see the 2026-10-13 schema-drift entry below). The only
supported procedure is `docs/RUNBOOK.md` "Database migrations" (current
checkout, unpooled URL via `read -s`, single `postgresql+psycopg://` prefix,
`alembic current` equals `alembic heads`).

## App returns 500: Could not parse SQLAlchemy URL

**Symptom:** Cloud Run logs show:
```
sqlalchemy.exc.ArgumentError: Could not parse SQLAlchemy URL from given URL string
```
at `db.py` line 30 in `_ensure_bound()` when calling `create_engine()`.

**Cause:** The `VAULT_DATABASE_URL` secret contains an invalid value.
Common cases:
- Still has the placeholder text from initial setup
- Missing the `postgresql://` scheme prefix
- Truncated or has a trailing newline issue
- Special characters in the password not URL-encoded

**Diagnosis:** Check the secret length without printing it:
```bash
gcloud secrets versions access latest --secret=neon-db-url | wc -c
```
A valid Neon URL is 80+ characters. If it's under 50, it's the placeholder.

**Fix:** Add a new version with the real URL using `read -s` to avoid
shell history:
```bash
read -s NEON_URL
# Paste the URL when prompted (hidden input), press Enter
echo -n "$NEON_URL" | gcloud secrets versions add neon-db-url --data-file=-
unset NEON_URL
```

The Cloud Run revision uses `neon-db-url:latest`, so it picks up the new
version on the next container startup. If the app is already running,
trigger a new revision:
```bash
gcloud run deploy mindful-money \
  --image us-central1-docker.pkg.dev/PROJECT_ID/mindful-money/app:latest \
  --region us-central1
```

**Valid format:**
```
postgresql://user:password@ep-xxx-xxx.us-east-2.aws.neon.tech/dbname?sslmode=require
```
Use the pooled connection string from the Neon dashboard (contains `-pooler`
in the hostname).

## Decision: Secrets via Secret Manager, never shell history

**Context:** The Neon database URL and Flask secret key are sensitive
credentials. They needed to get into GCP Secret Manager securely.

**Options considered:**

1. **Direct `echo` in shell** (rejected)
   ```bash
   echo -n "postgresql://..." | gcloud secrets create neon-db-url --data-file=-
   ```
   The URL appears in shell history (`~/.bash_history`). Anyone with
   access to the Cloud Shell VM or its disk image could recover it.
   Rejected.

2. **`read -s` with hidden input** (acceptable fallback)
   ```bash
   read -s NEON_URL
   echo -n "$NEON_URL" | gcloud secrets versions add neon-db-url --data-file=-
   unset NEON_URL
   ```
   Input is hidden, doesn't appear in history. The variable is cleared
   after use. Acceptable but requires careful execution.

3. **GCP Console web UI** (chosen)
   Navigate to Secret Manager in the browser, click the secret,
   "New Version", paste the value. No shell involved at all.

**Decision:** Use the GCP Console web UI for initial secret creation.
The browser session is already authenticated with Advanced Protection
+ YubiKey. No credential touches the shell, its history, or any log.

**Rationale:** For a finance app, the database credential is the highest-
value secret. The extra clicks in the web UI are worth eliminating
the shell history risk entirely. The `read -s` method is documented
as a fallback for automation, but manual web UI entry is preferred
for one-time setup.

## Frontend calls removed API endpoint (ZK refactor leftover)

**Symptom:** Browser console shows:
```
/api/relay/sources:1 Failed to load resource: 404
app.js:28 Uncaught (in promise) Error: Request failed.
    at apiFetch (app.js:28:19)
    at async app.js:1488:19
```
The app stuck on "Loading cryptography..." and never proceeds.

**Cause:** The zero-knowledge refactor removed the server-side SimpleFin
relay (`/api/relay` and `/api/relay/sources`), but `static/app.js` still
called `/api/relay/sources` during boot to check if SimpleFin was available.
The 404 threw an uncaught promise rejection that halted initialization
before libsodium could finish loading.

**Fix:** Remove the call. SimpleFin is now always available client-side
(it's just JavaScript in `simplefin-client.js`). In `static/app.js`:
```javascript
// Before:
const sources = await api('/api/relay/sources'); SIMPLEFIN_AVAILABLE = sources.simplefin_available;
// After:
SIMPLEFIN_AVAILABLE = true;
```

**Lesson:** When removing server endpoints, grep the frontend for all
references. The refactor removed the Flask routes but missed the JS
caller. A pre-deploy checklist should include: "search frontend for
removed endpoint paths."

## Current deployment status (2026-10-11)

**Working:**
- Cloud Run service deployed and running
- Database migrations completed (3 migrations applied at the time; this
  count is historical. As of 2026-10-13 there are 8 revisions, head
  `f1a2b3c4d5e6`. See `docs/RUNBOOK.md` "Database migrations".)
- Secrets in Secret Manager (Flask key, Neon URL)
- WebAuthn RP_ID/ORIGIN configured for the Cloud Run URL
- Docker build pipeline functional

**Not working:**
- Frontend boot blocked by the `/api/relay/sources` 404 (fix pushed,
  awaiting redeploy)
- Browser IAM access: Cloud Run IAM incompatible with browser navigation,
  removed in favor of app-level WebAuthn

**Honest assessment:** The infrastructure is solid. The app deploys,
connects to the database, and serves pages. The remaining issue is a
frontend bug from an incomplete refactor, not an infrastructure problem.
Once the fixed `app.js` is deployed, the app should be fully functional.

## GitHub Actions WIF: service account impersonation denied

**Symptom:** GitHub Actions workflow authenticates via Workload Identity
Federation successfully, but the Docker push fails with:
```
ERROR: (gcloud.auth.docker-helper) There was a problem refreshing your
current auth tokens: ('Unable to acquire impersonated credentials',
'Permission iam.serviceAccounts.getAccessToken denied on resource
(or it may not exist).')
```

**Cause:** The Workload Identity Pool was granted `roles/run.admin`,
`roles/artifactregistry.writer`, and `roles/iam.serviceAccountUser` at
the project level. But `serviceAccountUser` is not sufficient for
Workload Identity Federation impersonation. The pool needs the
`roles/iam.workloadIdentityUser` role **on the specific service account**
being impersonated.

**Fix:**
```bash
gcloud iam service-accounts add-iam-policy-binding SERVICE_ACCOUNT_EMAIL \
  --member="principalSet://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/attribute.repository/ORG/REPO" \
  --role="roles/iam.workloadIdentityUser"
```

**Why this is easy to miss:** The GCP docs for Workload Identity
Federation emphasize the pool-level IAM grants (run.admin, etc.), but
the service-account-level `workloadIdentityUser` binding is documented
separately under "impersonation." The error message
(`getAccessToken denied`) does not name the missing role directly.

**Complete WIF setup checklist for Cloud Run deploys:**
1. Create workload identity pool
2. Create OIDC provider for `https://token.actions.githubusercontent.com`
   with attribute condition on the repo
3. Grant pool `roles/run.admin` on the project
4. Grant pool `roles/artifactregistry.writer` on the Artifact Registry repo
5. Grant pool `roles/iam.workloadIdentityUser` **on the service account**
   (this is the step most often missed)
6. Add `GCP_WORKLOAD_IDENTITY_PROVIDER` and `GCP_SERVICE_ACCOUNT` as
   GitHub Actions secrets

## GitHub Actions: gcloud uses wrong project

**Symptom:** Workflow fails at "Deploy to Cloud Run" with:
```
ERROR: (gcloud.run.deploy) PERMISSION_DENIED: Cloud Run Admin API has not
been used in project developer before or it is disabled.
```

**Cause:** The `gcloud` CLI in the GitHub Actions runner defaults to a
project named `developer` (derived from the service account credentials)
instead of the actual GCP project. The `--project` flag was missing from
the deploy command.

**Fix:** Add `--project ${{ env.PROJECT_ID }}` explicitly to all `gcloud`
commands in the workflow:
```yaml
gcloud run deploy ${{ env.SERVICE_NAME }} \
  --image "${{ env.IMAGE }}" \
  --region ${{ env.REGION }} \
  --project ${{ env.PROJECT_ID }} \
  ...
```

**Lesson:** Never rely on gcloud's default project in CI. The credential
file override (`gha-creds-*.json`) sets an unexpected default. Always
pass `--project` explicitly in automation.

## Service account cannot act as itself (iam.serviceAccounts.actAs)

**Symptom:**
```
ERROR: (gcloud.run.deploy) PERMISSION_DENIED: The service account
31393284277-compute@developer.gserviceaccount.com does not have
iam.serviceAccounts.actAs permission on itself.
```

**Root cause:** Cloud Run deploy needs the deploying service account to
impersonate the runtime service account (which is itself in this case).

**Fix:** (run from Cloud Shell)
```bash
gcloud iam service-accounts add-iam-policy-binding \
  31393284277-compute@developer.gserviceaccount.com \
  --member="serviceAccount:31393284277-compute@developer.gserviceaccount.com" \
  --role="roles/iam.serviceAccountUser" \
  --project=project-c89a7f58-b865-4112-bf8
```

Wait 2-3 minutes for IAM propagation, then re-run the workflow.

## _seed_identity NotNullViolation on passkey_required (2026-10-12)

**Symptom:** Every `/api/*` request returns 503 with
`{"error":"The request could not be completed"}`. `/health` returns 200.
Smoke tests fail on `/api/version` and `/api/passkeys/status`. No error
appears in Cloud Run logs because the `SQLAlchemyError` handler does not
log the exception.

**Root cause:** `_seed_identity()` in `db.py` inserts the bootstrap
identity row with only `id` and `user_handle`, relying on the Python-side
`default=False` for the `passkey_required` column. That default does not
fire on a Core `pg_insert` (it is an ORM-flush behavior), so PostgreSQL
receives NULL for a NOT NULL column with no server default:

```
psycopg.errors.NotNullViolation: null value in column "passkey_required"
of relation "vault_identity" violates not-null constraint
```

The rate limiter's `before_request` handler calls `db()` on every
`/api/*` request, which calls `_seed_identity()`, so a single missing
default takes down the entire API surface while `/health` (no DB touch)
stays green.

**Fix:** Set the value explicitly instead of relying on the default
(`db.py`):

```python
.values(id=1, user_handle=secrets.token_bytes(32), passkey_required=False)
```

**Lesson:** Python-side column `default=` is not a substitute for a
database `server_default` when using Core inserts (`pg_insert`,
`insert()`). Either set values explicitly on Core inserts or add a
`server_default` to the model. Silent error handlers
(`@app.errorhandler(SQLAlchemyError)` returning 503 without logging)
make this class of bug invisible in Cloud Logging; consider logging the
exception before returning the generic error.

**Update 2026-10-13:** the handler now logs a redacted `event="db_error"`
line. Status and details: `docs/HARDENING_PROPOSALS.md` P1.

**Diagnosis pattern:** reproduce the app's exact DB code path from Cloud
Shell using the Secret Manager value directly (no paste):

```bash
export VAULT_DATABASE_URL=$(gcloud secrets versions access latest --secret=neon-db-url)
python3 -c 'import os; from sqlalchemy import create_engine, inspect; e = create_engine(os.environ["VAULT_DATABASE_URL"]); print(sorted(inspect(e).get_table_names()))'
```

## /api/* 503 from schema drift; kdf_version hypothesis tested and rejected (2026-10-13)

**Symptom:** After the `_seed_identity` fix (previous entry) and a
credential rotation, `/health` returns 200 but every `/api/*` request
still returns the handled 503.

**Context (same window, separately confirmed faults):**

1. The `neon-db-url` secret held a `postgresql://` URL while the image
   ships only psycopg3, so SQLAlchemy's default psycopg2 dialect failed
   to load. Cloud Shell masked this: it has psycopg2 installed, so
   direct tests against the same secret value passed there.
2. The first rotated secret version (v4) was built with the
   `postgresql+psycopg://` prefix applied twice. SQLAlchemy parses
   `postgresql+psycopg://postgresql+psycopg://user@host/db` with
   username `postgresql+psycopg`, so Postgres rejected authentication
   and every route returned 500 (the custom session interface writes
   to the DB on the response path, `app.py` `save_session`). Diagnosed
   from the Cloud Logging traceback plus a local `make_url` parse
   check. A start-of-string prefix check did not catch the doubling;
   count occurrences instead. v5 (single prefix) fixed authentication.

**Root cause (confirmed):** schema drift. The production
`vault_identity` table has 5 columns (`id`, `user_handle`,
`passkey_required`, `created_at`, `updated_at`); `models.py` maps 10.
The migrations that add the other five were never applied to the
production database: `c4d9e3f2a1b6_add_kdf_salts` (`kdf_salt_enc`,
`kdf_salt_idx`, `kdf_version`) and `f1a2b3c4d5e6_add_recovery_blob`
(`recovery_blob`, `recovery_created_at`). Inserts name their columns
explicitly, so the seed and health paths pass. Selects built from the
model's `Table` object name every mapped column, so identity-touching
`/api/*` calls fail on the missing columns (a `SQLAlchemyError`) and
the handler returns 503.

**Hypothesis tested and rejected:** that `kdf_version` was a second
`_seed_identity` landmine of the same class as `passkey_required`
(NOT NULL, Python-only `default=1`, omitted from the Core insert).
Tested from Cloud Shell against the production database: an
`information_schema` probe of `vault_identity`, plus the app's exact
insert run as-is and with `kdf_version=1` added. Result: the column
does not exist in the production table at all; the as-is insert
succeeds, and the with-`kdf_version` variant errors with "Unconsumed
column names: kdf_version". The theory was wrong. The probe is what
killed it, and the same probe is what exposed the drift.

**Fix:** apply the outstanding migrations from a current checkout
with the unpooled connection string (DDL cannot run through the
pooler):

```bash
alembic upgrade head
```

No redeploy is required: the running code already expects the full
schema and generates SQL per request.

**Lesson:** after any migration run, verify the applied state against
the models (`alembic current` versus `alembic heads`, plus a column
probe), not just the table list. A table existing is not evidence that
its columns match the models. Drift of this kind breaks selects while
inserts keep passing, which makes the failure look like an application
bug instead of a deployment gap.

**Resolution:** Applied 2026-10-13. The 2026-10-12 upgrade had run
from a stale local checkout (local head `5ece671`, whose newest
migration was `9c1e4a7b2d10`), so it stopped five revisions short
without erroring. After `git pull`, `alembic upgrade head` applied the
five outstanding revisions in order, ending at `f1a2b3c4d5e6`.
Verified from outside: `/health`, `/api/version`, and
`/api/passkeys/status` all return 200 on the already-running
revision; no redeploy was needed.

## Two run.app hostnames; only one works for passkeys (2026-10-13)

**Symptom:** Docs and the deploy smoke test used
`mindful-money-31393284277.us-central1.run.app`, while the runbook, incident
docs and `VAULT_RP_ID` / `VAULT_ORIGIN` used
`mindful-money-k23ukkh5cq-uc.a.run.app`.

**Evidence:** `deploy.yml` sets `VAULT_RP_ID=mindful-money-k23ukkh5cq-uc.a.run.app`;
the smoke test `BASE_URL` pointed at the other host. Both hosts are Cloud
Run URLs for the same service and serve the same revision
(`docs/POST_MORTEM_STALE_DEPLOY.md` item 4).

**Root cause:** Cloud Run issues a legacy hash URL and a newer
project-number URL. Different docs were written from different consoles.

**Fix:** `k23ukkh5cq-uc` is canonical everywhere (docs and smoke tests). The
`31393284277` host is not valid for passkeys because WebAuthn binds the
credential to the RP ID; a ceremony started there fails origin checks.

**Lesson:** one hostname, defined next to `VAULT_RP_ID`, referenced everywhere.

**Status:** implemented on branch `hardening/2026-10-13` (docs and smoke-test
URL). Not production-verified. Confidence high.

## KDF v3 silent fallback to v2 (2026-10-13)

**Symptom:** none observed yet. Found by code review while the KDF v3 end to
end check was still open.

**Evidence:** `static/app.js` `deriveKeys()` caught any exception from the
v3 Argon2id call (5 ops, 256MB) and retried with v2 parameters (3 ops,
256MB), showing only a small note under the unlock box.

**Root cause:** different Argon2id parameters produce different keys. For a
vault whose stored `kdf_version` is 3, a v2 derivation cannot decrypt its
records, and anything sealed in that session would be encrypted to a second
key pair (a split-brain vault). The fallback was meant to avoid lockout on
memory-limited mobile browsers, but it trades a loud failure for silent
data inconsistency.

**Fix:** `deriveKeys()` derives with exactly the stored version. On failure
it throws `KDF_ALLOCATION_FAILED`, derives nothing, and the unlock gate
shows a clear message (nothing decrypted or saved, try a desktop browser).
v2 is used only for vaults whose stored version is 2. `kdf_version` values
other than 1, 2, 3 are rejected.

**Default-version reconciliation:** `getSalts()` used `|| 1` for
`GET /api/kdf/salts` and `|| 3` for `POST /api/kdf/salts/generate`. Both are
correct and stay: GET returns the stored NOT NULL column whose
`server_default` is 1 (rows that predate KDF versioning are v1), and generate
always writes and returns 3. They now go through the same validator.

**Rejected hypothesis:** "the two defaults are inconsistent, unify on 3."
Rejected because a v1 legacy row read with `|| 3` would derive the wrong keys,
which is the same class of bug as the fallback.

**Tests:** `tests/kdf_no_fallback.test.mjs` (node, stubbed libsodium):
v3 allocation failure throws and never attempts v2 params; v3 success uses
5 ops / 256MB; stored v2 still derives v2; unknown versions rejected. Wired
into `pr-verify.yml`.

**Status:** implemented, locally tested (node unit test). Not CI-verified,
not production-verified. The real-device end to end check (v3 unlock on iOS
Safari) is still open. Confidence high for the logic, medium for device
behavior.

**Lesson:** a crypto fallback that changes key material is never a graceful
degradation. Break loudly.

## PR browser-test: Playwright `json=` TypeError, then stale first-load flow (2026-10-13)

**Symptom:** on PR #8 the `browser-test` job failed with
`TypeError: APIRequestContext.post() got an unexpected keyword argument 'json'`
at `test_browser.py:145`. `verify` and CodeQL passed.

**Evidence:** Playwright for Python's `APIRequestContext.post()` signature
(checked against the installed 1.63.0) takes `data=`, `form=`, `multipart=`;
there is no `json=` (that is the `requests` library's spelling). A dict
passed as `data=` is serialized as JSON. The line came in with commit
`28e3c9b` (2026-10-12). The workflow installed an unpinned `playwright`.

**Unconfirmed:** whether this job failed before PR #8. The two earlier
Dependabot PRs failed at `verify`, so their `browser-test` never ran.

**Fix:** `json=` changed to `data=`; Playwright pinned to `1.63.0` in
`requirements-dev.txt` and `pr-verify.yml`.

**Second failure (open):** with the fix, the run gets past line 145
(hostile-Origin check passes locally) and then times out at
`page.fill("#pass", ...)`: `#pass` is never visible. Same result on an
unmodified `main` checkout with only the `json=` fix applied, so it is not
caused by PR #8. Cause: `28e3c9b` also made `static/app.js` show the passkey
bootstrap gate whenever `bootstrap_needed` is true, and the test starts from a
truncated database (no passkeys). Setting `VAULT_AUTH_POLICY=optional` for
the test server was tried and rejected: the bootstrap branch runs before the
policy check, so the passphrase gate stays hidden.

**Proposed next fix (not done):** enroll a passkey in the test via a
Chromium virtual authenticator (CDP `WebAuthn.enable` and
`WebAuthn.addVirtualAuthenticator`) plus a test-only `VAULT_BOOTSTRAP_TOKEN`,
then continue to the passphrase gate. `test_playwright_recovery.py` has the
same first-load assumption.

**Lesson:** pin test tooling, and run the browser suite on pushes to main
too, so a frontend flow change cannot silently strand the E2E tests.

**Status:** `json=` fix implemented and locally verified past line 145;
browser suite still failing (pre-existing). Confidence high.

### Update: passkey bootstrap in the browser tests (2026-10-13, later)

Both browser tests now enroll the first passkey through the real bootstrap
UI with a Chromium virtual authenticator (CDP `WebAuthn.enable` and
`WebAuthn.addVirtualAuthenticator`: ctap2, internal, resident key, UV) and
a test-only dummy `VAULT_BOOTSTRAP_TOKEN` set only in each test's server env.
The test asserts the page origin equals `VAULT_ORIGIN` (`localhost`).

Driving the real ceremony found two issues:

1. **App bug (fixed, affects production enrollment):** `bootstrapPasskey()`
   in `static/app.js` passed the server's JSON options straight to
   `navigator.credentials.create()`. The challenge is base64url text, so the
   browser rejects it ("The provided value is not of type ArrayBuffer").
   Every other ceremony decodes with `publicKeyOptions()`; bootstrap now does
   too. Without this fix the owner's pending first enrollment on production
   would fail. Status: implemented, locally tested (ceremony succeeds in
   headless Chromium); not production-verified. Confidence high.
2. **By-design gap (not changed):** bootstrap verify rotates the session
   without `authenticated_at` (only `login_verify` sets it), so right after
   enrollment `/api/kdf/salts` returns 401 and the gate shows "Incorrect
   vault passphrase". The tests now reload and complete a real passkey login
   before unlocking. In production the owner will see the same misleading
   message after enrolling; reloading and signing in with the passkey works.
   Proposal (needs a decision, auth-semantics change): after bootstrap, have
   the frontend run the login ceremony automatically instead of showing the
   passphrase gate. Confidence high (reproduced locally).

**Remaining failures (pre-existing, stale tests, not fixed: attempt limit):**
- `test_browser.py`: everything through unlock passes; then
  `page.wait_for_selector("#dash:not([hidden])")` times out after clicking
  "Connect demo bank" (`connect('fakebank')`).
- `test_playwright_recovery.py`: phase 1 (bootstrap, records, export) passes;
  phase 2 fails with "Backup import failed: Error: Passphrase required to
  restore backup." and phase 3's salt-mismatch expectation fails. The import
  flow now asks for a passphrase that the test does not supply.

Status: bootstrap path locally tested; both suites still red. Not
CI-verified as passing.

### Update: stale browser-test steps investigated; three app bugs found (2026-10-13, later)

Scope: test-only changes. App bugs below are documented, NOT fixed.

**Intended flow, from the code:**
- Demo bank was not removed or renamed. `#connectBtn` ("Connect demo bank")
  still calls `connect('fakebank')`, which now generates demo transactions
  client-side (`generateDemoTransactions`), seals them, uploads, and calls
  `load()`, which shows `#dash`. The test step is correct as written.
- Backup import: the unlock gate clears `#pass`, so `importBackup()` asks
  for the passphrase with `prompt()`, verifies the HMAC and canary with
  candidate keys BEFORE changing server salts, migrates salts if they differ,
  then reports with `alert()` ("Restored N records" or "Restore failed: ...").
  The "Backup salts do not match" message the old phase 3 expected no longer
  exists: cross-vault restore with the right passphrase is now intended.

**Test changes (implemented):**
- `test_playwright_recovery.py`: new `import_backup()` helper answers the
  passphrase prompt and collects the result alert. Phase 2 asserts the
  prompt happens. Phase 3 now asserts the current security property: a
  foreign backup with a WRONG passphrase is rejected with an integrity or
  wrong-passphrase error, leaves this vault's KDF salts unchanged, and
  imports nothing; with the right passphrase the restore succeeds and is
  byte-identical.
- `test_browser.py`: diagnostics only (prints `#connectNote`, console errors
  and HTTP >= 400 responses when the connect step times out). No assertion
  loosened.

**App bug A (high severity, confirmed): padding length overflows one byte.**
- Symptom: "Connect demo bank" shows `Error: Unexpected non-whitespace
  character after JSON at position 235`; `#dash` never appears.
- Evidence: stack `JSON.parse` in `open()` from `load()`. `padPlaintext()`
  in `static/app.js` stores the pad length in every pad byte of a
  `Uint8Array`, but buckets are 512 to 8192 bytes, so any pad length of 256
  or more is stored modulo 256. `unpadPlaintext()` then strips too little.
  A node round-trip of the exact functions over lengths 2 to 8192:
  1275 ok, 6916 broken.
- Impact: most newly sealed records cannot be read back. The plaintext
  prefix is intact inside the ciphertext, so data is recoverable with a
  corrected unpad (for example, strip trailing bytes after the JSON value).
  Production has no enrolled passkey yet, so no real vault data is believed
  affected. Confidence high.
- Proposed fix (not done): store the pad length in a 2-byte or 4-byte
  trailer (format version bump), with a tolerant reader for existing
  records. Zero-knowledge unaffected.

**App bug B (high, confirmed): backup restore always fails.**
- Symptom: every import alerts `Restore failed: S.crypto_verify_32 is not a
  function` (phase 2 same-vault restore, phase 3 both passphrases).
- Root cause: the loaded libsodium build does not expose
  `crypto_verify_32` at runtime. Proposed fix: use `S.memcmp` or a
  constant-time compare on the two 32-byte arrays.

**App bug C (medium, code-read, masked by B): two more restore defects.**
- `candidateSalts` omits `kdf_version`, so candidate keys are derived with
  v1 even for v3 backups; the HMAC check would then fail.
- `candidateOpen()` does not call `unpadPlaintext()`, but the canary is
  sealed with the padded `seal()`, so the canary check would throw
  "wrong passphrase". Confidence medium-high (not executed past bug B).

**Status:** test changes implemented and run locally. `test_browser.py`
fails at the demo-bank connect step (bug A). `test_playwright_recovery.py`
20/24: the 4 failures are the restore alerts (bug B) and the resulting
console error. Not CI-green. A weak spot noted, not changed: phase 2's
"every recovered transaction matches" passes because browser B shares
browser A's vault, so it does not by itself prove the import worked; the
"Restored N records" assertion does.

### Fixed: bugs A, B, C (2026-10-13, later)

All changes are client-side in `static/app.js`; the server still stores
only ciphertext, and keys never leave the browser. Zero-knowledge
unchanged.

**A. Padding format v2.** Layout of a padded plaintext of bucket size B:
`[data][0x00 fill][padLen uint32 big-endian][0x02]`. Buckets are unchanged
(512 to 8192), so length-hiding is unchanged. Max data per record drops from
8192 to 8187 bytes (5-byte trailer); larger records are rejected with
"Record too large", as before.
- Reader: tries v2 strictly (marker, length within bucket, zero fill),
  else reads legacy v1. For v1, candidate pad lengths are P with
  P mod 256 equal to the last byte and P within the trailing run (plus P=0
  for exact bucket fits). A candidate is accepted only if the remaining
  bytes are canonical JSON (valid UTF-8, parses, no surrounding whitespace,
  which is what `seal()` always wrote). Exactly one match is required;
  more than one throws "Ambiguous legacy padding". In the exhaustive test
  no legacy record was ambiguous.
- Why legacy and v2 cannot be confused: a valid v2 trailer needs the two
  high bytes of the length to be 0x00, and v1 JSON plaintext never contains
  0x00 and v1 pad runs are a single repeated byte.
- Also used by the passphrase re-encryption path (same `unpadPlaintext`).
  The ZKP v3 sealed path (`static/zkp/manual_expense_sealed_client.js`) uses
  its own Poseidon2 AEAD without bucket padding; not changed.
- Rejected approaches: (1) 2-byte length with no marker: cannot be told
  apart from legacy records reliably. (2) Fixing only the reader: writers
  would keep producing ambiguous records. (3) New bucket sizes: would change
  the length-hiding profile documented in THREAT_MODEL.
- Tests: `tests/padding.test.mjs` (in pr-verify): v2 round trip for every
  length 0 to 8187 and every bucket edge; 8188 to 8193 rejected; legacy
  records produced by the old writer verbatim read back for every JSON
  length 8 to 8192 (plus '}' and space stress cases, and pad byte equal to
  '}'); malformed input (wrong length, all zero, no JSON, dirty fill, bad
  length field, invalid UTF-8) rejected with a clear error.

**B. Restore integrity compare.** `crypto_verify_32` is not exported at
runtime by the bundled libsodium-wrappers; replaced with `S.memcmp`
(constant time). The backup's `integrity` field must be 64 lowercase hex
characters. The browser test asserts `typeof S.memcmp === 'function'`
at runtime.

**C. Restore key derivation and canary.**
- The backup's `kdf_version` is validated (`checkKdfVersion`) and passed
  to every derivation in the restore path. Backups without the field (made
  before KDF versioning) are v1. No fallback to another version.
- The canary is unpadded before parsing (it is written by `seal()`).

**Old backups:** a backup made before this fix carries v1-padded canary and
records; both read through the legacy reader, and restored records are
re-uploaded as-is and read the same way. Status: implemented, covered at
the padding level by the unit test; an end to end restore of a pre-fix
backup file was not run. Confidence medium-high.

**Verification:** node unit tests (padding, KDF no-fallback): pass.
pytest 144 passed. `test_browser.py` 119/119. `test_playwright_recovery.py`
26/26, including phase 3: a foreign backup with a wrong passphrase is
rejected with "Integrity check failed", leaves the vault's KDF salts
unchanged and imports nothing; the right passphrase restores byte-identical
records. All locally tested (Python 3.13, Postgres 17, Chromium headless
shell 1243). CI status: see PR #8. Not production-verified.

Test-only adjustments in the same round: the account dropdown assertion
compared a substring against a list (option text is "bank - type ·
label"); the console-error check now removes exactly one expected 404 from
the intended new-vault `GET /api/kdf/salts` then generate flow.

**New bugs found, NOT fixed:**
- **D (medium):** `POST /api/kdf/salts/migrate` replaces salts but not
  `kdf_version`. Restoring a backup into a vault with a different stored
  version would make the next unlock derive different keys. Client-side
  guard added: restore now refuses loudly when the vault's version differs.
  Not covered: the branch where the vault has no salts yet (404), whose
  stored version is the column default 1. Proposed fix: let migrate accept
  and store `kdf_version`. Confidence high (code read).
- **E (medium):** `MAX_SEALED_HEX_LENGTH` defaults to 16384 hex (8192
  bytes), but a record in the 8192-byte bucket seals to 8240 bytes (48 bytes
  sealed-box overhead), 16480 hex, so the server rejects it. Records of
  roughly 4091 to 8187 bytes of JSON cannot be uploaded. Proposed fix: raise
  the limit to 16480 or cap the client at the 4096 bucket. Confidence high
  (arithmetic; not exercised by a test).
- **F (low):** on a fresh vault the "Create passkey" button also fires the
  login request (409 in the console). Reported earlier.

### Fixed: bugs D and E (2026-10-13, later)

**D. Migrate now stores `kdf_version` with the salts.**
- Change (`app.py` `migrate_kdf_salts`): `kdf_version` is REQUIRED in the
  request body and must be an integer in {1, 2, 3} (type checked, so `3.0`,
  `"3"`, `true` and lists are rejected with 400). It is written in the same
  `UPDATE` as `kdf_salt_enc` / `kdf_salt_idx`, so salts and version change
  together or not at all.
- Omitted version: rejected (400). The only client caller is
  `importBackup()`, which now always sends the backup's validated version.
  A default was rejected because a wrong default is exactly bug D.
- Client: both migrate calls send `kdf_version`. The interim client guard
  (refuse restore when versions differ) was removed: with the server fix,
  restoring a v1 backup into an empty v3 vault (or the reverse) is correct,
  and the guard would have blocked it.
- Schema: none. `vault_identity.kdf_version` already exists (INTEGER NOT
  NULL, server_default 1, migration `c4d9e3f2a1b6`); no Alembic revision.
- Tests (`test_kdf_migrate_and_limits.py`): fresh vault migrate with v3
  stores v3; missing, 0, 4, "3", 3.0, true, [3] all 400 with salts and
  version unchanged; force overwrite changes salts and version together; a
  refused overwrite (409) changes neither. Browser (`test_playwright_recovery.py`):
  phase 3 now reloads the restored vault, unlocks from scratch and checks
  identical records and `kdf_version` 3; new phase 4 restores a v3 backup
  into an empty vault seeded at v1 with its own salts, reloads, unlocks and
  checks identical records and that the version moved to 3. Run against the
  previous `app.py`, phase 4 times out after the reload (records cannot be
  decrypted), so the test detects the bug.

**E. Max sealed size matches the largest bucket.**
- Computed, not assumed: largest bucket 8192 (`PAD_BUCKETS`), sealed-box
  overhead `crypto_box_SEALBYTES` = 48 (asserted via PyNaCl in the test),
  so 8240 bytes = 16480 hex. Default `VAULT_MAX_SEALED_HEX_LENGTH` raised
  from 16384 to 16480. Primary statement of the limit: README.
- Checked: `records.sealed` is `TEXT` (no length cap); `MAX_CONTENT_LENGTH`
  is 8 MiB, which covers single and batched uploads at the restore batch
  size (100 x 16480 hex is about 1.6 MB).
- Rejected: shrinking the client to the 4096 bucket (would lose the 8192
  bucket that THREAT_MODEL relies on for length hiding of large records).
- Tests: a real sealed box of an 8192-byte plaintext (exactly 16480 hex) is
  accepted; one byte more (16482 hex) is rejected with 400. Browser phase 4
  seals an 8,145-byte JSON record in the browser, uploads it, reads it back
  and decrypts it; ciphertext length is exactly 16480 hex; the plaintext
  never appears in outbound requests.

**Verification:** locally tested in a clean env (only `VAULT_ENV` and
`VAULT_TEST_DATABASE_URL` set): pytest 150 passed; node padding and KDF
tests pass; `test_browser.py` 119/119; `test_playwright_recovery.py` 36/36.
CI: see PR #8. Not production-verified. Confidence high.

**New issues found, NOT fixed:**
- **G (low):** `MAX_RECORDS_PER_BATCH` is 1000 while `MAX_REQUEST_BYTES`
  is 8 MiB; 1000 records near the max size would be about 16.5 MB, so such a
  batch is rejected with 413. Normal records are 512-bucket (about 1.1 KB
  hex) and restore batches 100, so this only affects a single connect/sync
  of hundreds of very large records.
- **H (low, flaky test):** `test_browser.py` "no horizontal overflow at
  390px" failed once locally and passed on the rerun; it waits a fixed 900 ms
  after resizing.

### Fixed: bug G; bug H test fixed, which exposed bugs I and J (2026-10-13, later)

**G. Bulk uploads cannot exceed the request limit by design.**
- Server: default `VAULT_MAX_RECORDS_PER_BATCH` lowered from 1000 to 500 so
  the worst-case batch (500 records at max sealed size) is 8,287,514 bytes,
  under the 8 MiB `MAX_REQUEST_BYTES`. The derivation is stated once, in the
  README section "Ciphertext and resource limits".
- Client (`static/app.js`): new `chunkSealedRecords` / `uploadSealedRecords`
  split every bulk upload by count (500) and by body size (6 MiB). Used by
  all four bulk paths: connect / sync (demo and SimpleFin), CSV import,
  backup restore (was fixed 100 per batch) and re-encryption (was 50).
  Single-record writes (manual entry, edit, fraud status) are unchanged.
  A single record over 6 MiB throws before any request (impossible with the
  16480 hex cap). Non-atomicity across chunks: README, same section.
- Rejected: raising `MAX_CONTENT_LENGTH` (Cloud Run caps request bodies at
  32 MiB, and a larger limit widens the memory and parsing DoS surface for
  no user benefit); chunking by count only (a count alone cannot bound bytes
  if the per-record cap changes); chunking by bytes only (would let the
  client exceed the server record count with small records).
- Tests: `test_kdf_migrate_and_limits.py` asserts the worst-case compact and
  default-spaced JSON batch at the configured limits fits
  `MAX_REQUEST_BYTES` and `MAX_JSON_OBJECT_BYTES`, that the client chunk
  limits in `app.js` are within the server limits, and that the server
  accepts a real 500 x 16480-hex batch (200). `tests/upload_chunking.test.mjs`
  (added to pr-verify) runs the real `app.js` functions: 1,200 max-size
  records upload in 4 chunks (largest 6,281,938 bytes), every request under
  the server byte and count limits, order and content preserved; 1,201 small
  records split 500/500/201.
- Integrity: manifest regenerated in the same commit; only the `app.js`
  `integrity` attribute in `index.html` was changed.

**H. 390px overflow check is now condition based.**
- The fixed 900 ms wait was replaced by `wait_for_function` until
  `innerWidth === 390` and `scrollWidth <= innerWidth + 2` (10 s timeout).
  The assertion is unchanged except that it now also fails if the viewport
  never reached 390 px (stricter, not looser).
- Result: the failure was not a timing problem. Run 5 times locally, the
  check failed in 3 runs even after 10 s. Diagnostics show bug J below.
  H is therefore NOT stable yet; the test is now correctly reporting an app
  bug instead of masking it with a sleep.

**New issues found, NOT fixed:**
- **I (medium, real users too):** the `upload` rate limit is 10 requests per
  60 s and every single-record write (manual entry, edit, rename, fraud flag)
  counts. `test_browser.py` hit 429 "Request rate limit exceeded" on the
  double-submit step in 2 of 4 fast local runs (a pre-existing flake). A user
  editing quickly will hit the same. Test-only mitigation:
  `test_browser.py` sets `VAULT_RATE_UPLOAD=100` for its server process
  (production default unchanged). Not decided: whether production should
  raise the limit or separate single-record edits from bulk uploads.
- **J (low, UI):** after the viewport shrinks to 390 px, Chart.js canvases
  sometimes keep their desktop width (`#chMerchants` 1060 px, `#chBalance`
  502 px) and cause horizontal overflow that does not settle within 10 s.
  Both charts use `responsive: true, maintainAspectRatio: false`; a likely
  cause is a chart container without a constrained width (e.g. a missing
  `min-width: 0` on a grid item) so the ResizeObserver never sees it shrink.
  Not investigated further.

**Verification:** G implemented, locally tested (clean env: pytest 153
passed; node tests 3/3 files pass; `test_playwright_recovery.py` 36/36);
CI: see PR #8; not production-verified; confidence high. H implemented and
locally tested; the check now fails intermittently because of bug J, so the
browser suite is not stable; confidence high in the diagnosis.

### Fixed: bugs J and I; hypothesis K not confirmed; new bugs L and M (2026-10-13, later)

**J. Chart overflow at 390 px: root cause and fix.**
- Evidence: at the moment of failure the chart containers were already the
  right width (`.chart` 316 px, card 354 px, `.main` 390 px), but the
  Chart.js instances for `#chBalance` and `#chMerchants` still had their
  desktop width (502 px and 1060 px) as inline canvas width. Calling
  `chart.resize()` by hand fixed it immediately, and hiding the canvases
  removed all overflow. So the CSS layout was correct (cards already have
  `min-width: 0`) and the charts had missed or misapplied a resize.
- Root cause: Chart.js 4.4.7 `resize()` does not resize while its animator
  is running; it stores the size in `_resizeBeforeDraw` and applies it on the
  next draw. `render()` recreates every chart with a 380 ms entry
  animation, so a viewport change that lands near the end of that animation
  leaves the chart at a stale width. Reproduced by calling `render()` at
  1280 px and resizing to 390 px 370 ms later: `#chCategory` stayed at
  422 px in a 316 px container.
- Fix (`static/app.js`): `animation: false` for the dashboard charts
  (`baseOpts`) and the assistant charts. With no animation the animator
  never runs and every resize is applied at once. The same reproduction
  then passed at 340, 370, 380 and 400 ms.
- Rejected: `min-width: 0` or `max-width: 100%` on containers or canvases
  (the containers were already correct; a canvas capped by CSS would be
  stretched, not re-rendered); a manual `ResizeObserver` calling
  `chart.resize()` (works around Chart.js instead of removing the race,
  and adds a second observer per chart); a longer wait in the test (the
  stale width never recovers by itself).
- Regression test: `test_browser.py` now calls `render()` and shrinks the
  viewport 370 ms later, then runs the condition-based overflow check.

**I. Upload rate limit.**
- Keyed per vault identity when signed in, per client IP (HMAC) otherwise;
  fixed 60 s window. Production default raised from 10 to 60 per minute;
  the derivation is in README "Ciphertext and resource limits".
- `uploadSealedRecords` now waits for `Retry-After` on 429 and retries the
  same chunk (max 3 times), so very large uploads cannot fail midway on
  the rate limit. Covered in `tests/upload_chunking.test.mjs`.
- The test-only `VAULT_RATE_UPLOAD=100` override in `test_browser.py` was
  removed; the suite passes at the production default.
- Tests (`test_kdf_migrate_and_limits.py`): the default is (60, 60); 30
  single-record uploads in one window are all accepted; 61 in one window
  give 60 x 200 then 429. The tests wait for a fresh window when close to
  the boundary so the fixed window cannot make them flaky.
- Rejected: per-session keying (resets by clearing cookies); exempting
  single-record writes (no abuse bound); 120 per minute (doubles the
  write bandwidth bound for no observed need).

**K. Hypothesis: re-encryption keeps the old blind index. NOT confirmed.**
- `handleRecoverVault` (the only re-encryption path) does reuse the old
  `blind_index` in code, but it can never reach the upload.
  `test_playwright_recovery.py` phase 5 runs the real flow on a vault with
  records and a real recovery key: no record is uploaded and stored rows are
  unchanged. Two earlier blockers stop it (L and M below); phase 5 stubs the
  first one test-only (serves the stored encrypted blob to the page) and the
  flow then stops at the second.
- Not fixed, because the path is unreachable and a correct fix (recompute
  blind indexes under the new key and replace old rows atomically, which
  needs a server replace endpoint since old and new indexes differ) only
  makes sense together with a design for L and M.

**New issues found, NOT fixed:**
- **L (high, recovery unusable):** `GET /api/recovery/blob` and
  `POST /api/recovery/delete` require `session["passkey_authenticated"]`,
  which nothing in `app.py` sets and which the server-side session store
  (`ServerSession` columns) cannot persist. Both always return 403
  "Passkey authentication required", so the recovery key cannot be used or
  deleted.
- **M (high, recovery unusable):** past L, `handleRecoverVault` calls
  `getSalts()` and requires a new vault, but an identity with records always
  has salts (and `/api/kdf/salts/generate` refuses when records exist), so it
  always fails with "Expected new salts for re-encryption, got existing".

**Verification:** J, I implemented and locally tested in a clean env
(pytest 156 passed; node tests pass; `test_playwright_recovery.py` 38/38;
`test_browser.py` 10 of 10 consecutive runs 119/119, at the production
upload limit);
K hypothesis killed by a locally tested browser test. CI: see PR #8. Not
production-verified. Confidence: J high (reproduced and fixed), I high, K
high.
