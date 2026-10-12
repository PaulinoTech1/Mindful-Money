# Load Testing Guide

**Last updated:** 2026-10-11

## Objective

Verify the app handles realistic load without errors or excessive latency.

## Test plan

### Baseline (smoke test)
- 1 user, 10 requests, sequential
- Verify: all 200s, p99 < 500ms

### Normal load
- 10 concurrent users, 100 requests total
- Verify: < 1% errors, p99 < 2s

### Stress test
- 50 concurrent users, 500 requests total
- Monitor: Cloud Run instance count, DB connections, error rate
- Verify: graceful degradation, no crashes

## Tools

Use `hey` (simple) or `k6` (advanced):

```bash
# Install hey
go install github.com/rakyll/hey@latest

# Test health endpoint (no auth needed)
hey -n 100 -c 10 https://mindful-money-k23ukkh5cq-uc.a.run.app/health

# Test API (requires auth - use session cookie)
hey -n 100 -c 10 \
  -H "Cookie: vault_session=YOUR_SESSION" \
  https://mindful-money-k23ukkh5cq-uc.a.run.app/api/session
```

## What to monitor

In Cloud Console during the test:
1. **Cloud Run**: Instance count, request latency (p50, p99), error rate
2. **Cloud SQL/Neon**: Active connections, query latency
3. **Cloud Logging**: Error rate, rate limit hits

## Expected results

- **Health endpoint:** Should handle 100 req/sec easily (no DB, no auth)
- **API endpoints:** Depends on DB. Watch for connection pool exhaustion.
- **Current config:** 1 Gunicorn worker, 8 threads. Cloud Run concurrency default 80.

## Tuning

If p99 latency > 2s:
- Increase Cloud Run memory (default 512Mi)
- Increase Gunicorn threads
- Check DB query performance

If error rate > 1%:
- Check Cloud Logging for errors
- Verify DB connection pool isn't exhausted
- Check rate limits aren't too aggressive

## Current settings (for reference)

- Gunicorn: `--workers 1 --threads 8 --timeout 0`
- Cloud Run: default concurrency (80), default memory (512Mi)
- SQLAlchemy pool: check `db.py` for pool_size and max_overflow

## Database connection pooling

Current settings (`db.py`):
- `pool_size=5` (persistent connections)
- `max_overflow=10` (temporary extra connections)
- `pool_pre_ping=True` (verify connections before use)
- **Max total:** 15 connections per Cloud Run instance

With Gunicorn (1 worker, 8 threads), 15 connections is sufficient.
If Cloud Run scales to N instances, total DB connections = N * 15.

**Neon limits:** Check your Neon plan for max connections. If you hit limits:
- Reduce `max_overflow`
- Increase Cloud Run memory (allows more instances with fewer connections each)
- Or: use PgBouncer (not currently configured)
