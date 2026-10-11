# Hosting Decision: Google Cloud Run

**Date:** 2026-10-11
**Status:** Decided
**Decision:** Deploy Mindful Money on Google Cloud Run

## Context

Mindful Money is a zero-knowledge personal finance tracker (Flask + Postgres).
The server never sees plaintext; all encryption happens client-side.
We needed a hosting platform that runs the full Flask stack reliably.

## Options Considered

### Vercel (tried, rejected)

The project was initially deployed on Vercel. The Flask backend would not
start. Vercel's Python runtime did not create serverless functions for the
app despite multiple configuration attempts:

- `vercel.json` with `builds` config
- `vercel.json` with `functions` config
- Standard `api/` directory pattern with `api/index.py` entry point

API routes returned static HTML instead of JSON responses. The deployment
showed READY with no Python functions listed. Vercel is optimized for
JavaScript frameworks; Flask is a second-class citizen.

### Render (considered)

- Native Flask support, straightforward deployment
- Pricing: $7/mo (web) + $7/mo (Postgres) = ~$14/mo minimum viable
- Or $7/mo (web) + Neon free tier for Postgres
- Simple, but a fixed monthly cost for a low-traffic app

### Cloudflare (considered)

- Cloudflare Tunnel to self-hosted infrastructure: viable but requires
  maintaining the homelab as the compute layer
- Cloudflare Workers/Pages cannot run Python Flask
- Deferred: homelab hosting is a future option, not now

### Railway / Fly.io (considered)

- Both support Flask via Docker
- Railway: usage-based, ~$5-20/mo
- Fly.io: ~$5/mo, Docker-based
- Neither matched Cloud Run on cost for this workload

## Decision: Google Cloud Run

**Rationale:**

1. **Cost:** Free tier covers 2M requests/month, 180K vCPU-seconds, 360K
   GiB-seconds. At projected usage (~4,500 requests/month single user,
   ~450K/month at 100 users), the app stays in free tier indefinitely.
   Paid overage is $0.40/million requests beyond 2M.

2. **Full-stack:** Single container runs the Flask app serving both API
   and static frontend. No CORS issues, no split-brain sessions, no
   frontend/backend separation complexity.

3. **No sleep penalty:** Unlike Render free tier, Cloud Run scales to zero
   without a 30-second cold start penalty on every wake.

4. **Safety:** Google pauses the account when trial credits exhaust rather
   than auto-charging. Budget alerts provide additional visibility.

5. **Docker-native:** Standard Dockerfile deployment. No platform-specific
   configuration hacks.

## Architecture

```
Browser <--HTTPS--> Cloud Run (Flask + static) <--TLS--> Neon Postgres
                         |
                    GCP Secret Manager
                    (VAULT_SECRET_KEY, VAULT_DATABASE_URL)
```

- **Compute:** Cloud Run (us-central1, free tier region)
- **Database:** Neon Postgres (free tier, pooled connection)
- **Secrets:** GCP Secret Manager (no plaintext in env config)
- **Auth:** Google Advanced Protection + YubiKey for console access;
  no service account JSON keys (blocked by org policy)

## Consequences

- Vercel project `mindful-money` is deprecated for this app
- Deployment is via `gcloud run deploy --source .` from Cloud Shell
- Database migrations run via Cloud Run jobs or Cloud Shell
- Future: evaluate Cloudflare Tunnel to homelab if self-hosting is desired
