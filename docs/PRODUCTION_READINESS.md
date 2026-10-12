# Production Readiness Plan

**Date:** 2026-10-11
**Updated:** 2026-10-12
**Current status:** All P0, P1, P2, P3 items complete. Awaiting first successful deploy.
**Goal:** Production-ready for personal use with real financial data.

## Priority 0: Blockers (fix before real data) - ✅ ALL DONE

### P0.1: Health check endpoint ✅
**Status:** Complete. `GET /health` and `GET /ready` implemented.

### P0.2: Database migrations in CI/CD
**Problem:** Migrations are manual. Easy to deploy code that requires a migration that hasn't run.
**Action:**
- Add migration check to workflow (verify `alembic upgrade head --sql` succeeds)
- Document manual migration step in DEPLOYMENT_WORKFLOW.md
- Consider: run migrations as a Cloud Run job before deploy (advanced)
**Effort:** 2 hours

### P0.3: Dependency scanning
**Problem:** No Dependabot, no vulnerability scanning. `requirements.txt` uses version ranges.
**Action:**
- Enable Dependabot for Python dependencies
- Pin versions with hashes (`pip-compile --generate-hashes`)
- Add `pip-audit` to CI test job
**Effort:** 2 hours

### P0.4: SECURITY.md is a template
**Problem:** Current SECURITY.md is the GitHub default template, not specific to this project.
**Action:** Rewrite with:
- How to report vulnerabilities (email, response time)
- Supported versions (main branch only)
- Scope (what's in scope for reports)
- No bug bounty (personal project)
**Effort:** 1 hour

## Priority 1: Important (fix soon)

### P1.1: Backup verification
**Problem:** Neon has point-in-time recovery, but it's never been tested.
**Action:**
- Document Neon's backup/retention policy
- Test restore to a separate Neon branch (non-destructive)
- Document recovery procedure in INCIDENT_RESPONSE.md
**Effort:** 2 hours

### P1.2: Uptime monitoring
**Problem:** No alerts if the app goes down.
**Action:**
- Create Cloud Monitoring uptime check for the health endpoint
- Alert on 2 consecutive failures
- Free tier covers this
**Effort:** 1 hour

### P1.3: Rate limit tuning
**Problem:** Rate limits exist but haven't been validated under load.
**Action:**
- Review current limits in app.py
- Test with realistic load (10 req/sec for 60 seconds)
- Adjust if legitimate use triggers limits
**Effort:** 3 hours

### P1.4: Session security review
**Problem:** Session handling is complex (custom server_sessions table).
**Action:**
- Review session fixation, hijacking protections
- Verify `__Host-` cookie prefix is used
- Verify SameSite=Strict
- Test session revocation actually works
**Effort:** 3 hours

### P1.5: CSP verification
**Problem:** CSP is set to `enforce` but hasn't been verified in production.
**Action:**
- Check browser console for CSP violations
- Verify no inline scripts (or proper nonces)
- Document CSP policy in TRUST_BOUNDARIES.md
**Effort:** 2 hours

## Priority 2: Hardening (before public use)

### P2.1: Secrets rotation procedure
**Problem:** No documented procedure for rotating VAULT_SECRET_KEY or Neon URL.
**Action:** Document in INCIDENT_RESPONSE.md:
- How to rotate Flask secret key (invalidates sessions)
- How to rotate Neon password (update Secret Manager)
- How to rotate SimpleFin access URL (client-side, just re-enter)
**Effort:** 2 hours

### P2.2: Load testing
**Problem:** Unknown how the app behaves under load.
**Action:**
- Test: 10 concurrent users, 100 req/sec for 5 minutes
- Monitor: Cloud Run instance count, latency p99, error rate, DB connections
- Tune: Gunicorn workers/threads, Cloud Run concurrency, min/max instances
**Effort:** 4 hours

### P2.3: Frontend security
**Problem:** JavaScript delivers encryption. No integrity verification.
**Action:**
- Add Subresource Integrity (SRI) hashes for static JS
- Or: document why SRI isn't used (dynamic content)
- Verify no `eval()` or `innerHTML` with user data
- Audit npm dependencies (if any)
**Effort:** 3 hours

### P2.4: Database connection pooling
**Problem:** Unknown if connection pooling is configured correctly for Cloud Run.
**Action:**
- Review SQLAlchemy pool settings in db.py
- Verify pool size matches Cloud Run concurrency
- Monitor for connection exhaustion under load
**Effort:** 2 hours

### P2.5: Audit log retention
**Problem:** No policy for how long audit events are kept.
**Action:**
- Define retention (e.g., 1 year for security events, 90 days for others)
- Implement cleanup job (or document manual cleanup)
- Consider GDPR right-to-erasure implications
**Effort:** 2 hours

## Priority 3: Operational excellence

### P3.1: Runbook for common operations
**Problem:** Procedures are scattered across docs.
**Action:** Create `docs/RUNBOOK.md` with:
- Deploy rollback (how to revert to previous revision)
- Database migration (step-by-step)
- Secret rotation (step-by-step)
- Incident response (link to INCIDENT_RESPONSE.md)
- Scaling (how to adjust min/max instances)
**Effort:** 3 hours

### P3.2: SLOs and error budgets
**Problem:** No defined reliability targets.
**Action:** Define:
- Availability SLO: 99.5% (allows ~3.6 hours downtime/month)
- Latency SLO: p99 < 2 seconds
- Error rate SLO: < 1% of requests
- Monitor in Cloud Monitoring dashboard
**Effort:** 2 hours

### P3.3: Dependency pinning
**Problem:** `requirements.txt` uses ranges (`Flask>=3.1,<4`). Builds are not reproducible.
**Action:**
- Use `pip-compile` to generate pinned `requirements.txt`
- Pin base Docker image by digest (`python:3.12-slim@sha256:...`)
- Document update procedure
**Effort:** 2 hours

### P3.4: Multi-region (future)
**Problem:** Single region (us-central1). Regional outage = downtime.
**Action:** (Defer until needed)
- Neon supports read replicas
- Cloud Run is regional; would need multi-region setup
- For personal use, single region is acceptable with backups
**Effort:** N/A (deferred)

## Already done (strengths)

- ✅ Client-side encryption (server never sees plaintext)
- ✅ WebAuthn passkeys (no passwords)
- ✅ Tenant isolation (identity_id on all tables)
- ✅ Audit logging with incident response API
- ✅ Opt-in IP logging (privacy by default)
- ✅ Rate limiting
- ✅ CSRF protection
- ✅ Security headers
- ✅ GitHub Actions CI/CD with test gate
- ✅ Workload Identity Federation (no long-lived keys)
- ✅ Honest trust boundary documentation
- ✅ Incident response runbook (zero-cost GCP native)
- ✅ Two-tier logging (Cloud Logging + Postgres audit)

## Estimated effort

- P0 (blockers): 6 hours
- P1 (important): 13 hours
- P2 (hardening): 14 hours
- P3 (excellence): 9 hours
- **Total:** ~42 hours (~1 week of focused work)

## Recommended order

1. **This week:** P0.1 (health check), P0.3 (Dependabot), P0.4 (SECURITY.md)
2. **Next week:** P0.2 (migrations), P1.2 (uptime), P1.5 (CSP)
3. **Following:** P1.1 (backups), P1.3 (rate limits), P1.4 (sessions)
4. **When ready for real data:** P2 items
5. **Ongoing:** P3 items as time permits

## What "production-ready" means for this project

This is a personal finance app, not a SaaS product. Production-ready means:
- ✅ Can handle real financial data without loss
- ✅ Survives common failure modes (deploy errors, DB issues)
- ✅ Detectable when broken (monitoring/alerts)
- ✅ Recoverable from backups
- ✅ Honest about limitations (already done)

It does NOT mean:
- ❌ SOC 2 compliant
- ❌ Handling other users' data
- ❌ 99.99% uptime SLA
- ❌ Formal security audit (recommended but not required for personal use)
