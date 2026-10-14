# Health Checks and Readiness Probes

## Endpoints

### `GET /health` - Liveness

Returns 200 if the Python process is running. Does NOT check the database.
Used by Cloud Run to determine if the container should be restarted.

```json
{"status": "ok"}
```

### `GET /ready` - Readiness

Returns 200 if the app can serve traffic (database is reachable).
Returns 503 if the database is unreachable.

```json
{"status": "ready", "database": "ok", "zkp": "available"}
```

`zkp` is informational and never affects the status code: `available` means
the bb binary, baked CRS and v4 verification key are present
(`zkp_verifier.artifacts_available()`); `unavailable` means proof
submissions return 503 while the rest of the app works. See
`docs/ZKP_BINDING.md` "Availability".

Used by Cloud Run to determine if the container should receive traffic.
A container that fails readiness is removed from the load balancer rotation
but not restarted.

### `GET /api/version` - Deploy verification

Returns the git commit SHA of the deployed code. Used by CI smoke tests
to detect stale deployments.

```json
{"commit": "a1b2c3d4e5f6", "built_at": "2026-10-12T00:00:00Z"}
```

## Cloud Run configuration

Cloud Run automatically configures health checks when the service is deployed.
The default settings are:

- **Liveness probe:** HTTP GET `/health` on the container port
- **Check interval:** 30 seconds
- **Timeout:** 5 seconds
- **Failure threshold:** 3 consecutive failures trigger container restart

To customize (via gcloud):

```bash
gcloud run services update mindful-money \
  --region=us-central1 \
  --project=project-c89a7f58-b865-4112-bf8 \
  # Cloud Run uses startup CPU boost by default; no custom probe config needed
  # for basic liveness. For readiness gates, use --health-check flag if available.
```

**Note:** Cloud Run's native health check support varies by generation.
Gen 2 supports explicit startup/liveness probes. If using Gen 1, the
`/health` endpoint serves as an implicit liveness signal via request success.

## CI smoke tests

The deploy workflow verifies after each deployment:

1. `/health` returns 200 (app is running)
2. `/api/version` commit matches `github.sha` (not a stale deploy)
3. `/api/passkeys/status` does not return 404/500 (API is functional)
4. **JS integrity:** Served `app.js`, `simplefin-client.js`, and
   `recovery-words.js` SHA-256 hashes match `integrity-manifest.json`
   from the deployed commit. **Fails the deploy on mismatch.**

The JS integrity check is the critical control: it detects if the
deployed JavaScript differs from what was tested, whether due to
a stale deployment, build corruption, or tampering.

## Manual verification

```bash
BASE="https://mindful-money-k23ukkh5cq-uc.a.run.app"

# Liveness
curl -s $BASE/health | python3 -m json.tool

# Readiness (checks DB)
curl -s $BASE/ready | python3 -m json.tool

# Version (verify deploy)
curl -s $BASE/api/version | python3 -m json.tool

# JS integrity (compare to git)
curl -s $BASE/static/app.js | sha256sum
# Compare to: static/integrity-manifest.json in the deployed commit
```

## Residual risk

Health checks verify the app is running and the database is reachable.
They do NOT verify:
- That the served JavaScript is the correct version (covered by CI smoke test, not by Cloud Run probes)
- That encryption is working correctly (covered by unit tests, not by probes)
- That a sophisticated attacker hasn't replaced the JS (see `docs/JS_INTEGRITY.md`)

A fully compromised origin will still return 200 on `/health`.
