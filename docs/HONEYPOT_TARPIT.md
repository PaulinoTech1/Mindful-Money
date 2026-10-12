# Honeypot Deception Design

## Core principle: perceived vulnerability, not actual vulnerability

An attacker should believe they've discovered an exploitable mistake, but
the apparent weakness must never compromise real assets, bypass real controls,
or consume disproportionate resources.

| Perceived (deception) | Actual (reality) |
|---|---|
| XFF rotation resets login attempt counter | Real rate limit uses trusted `remote_addr`, unaffected |
| Fake backup export takes 5 minutes | Each poll is a cheap JSON response, no worker blocking |
| `.env` contains production credentials | All credentials are inert, point to nothing |
| WordPress 5.8.3 has known CVEs | Static HTML, no WordPress installed |
| `robots.txt` reveals backup paths | All paths are dead ends |

## Architecture

### Deception layer (cosmetic)

These change what the attacker SEES. They are entirely fictional:

**Fake attempt counter** (`_deception_attempts_remaining`)
- Based on `X-Forwarded-For` header (spoofable by design)
- Attacker rotates XFF → counter resets → believes they bypassed a limit
- The real rate limiter is independent and unaffected

**Fake async backup** (`/backup/export` → `/backup/status`)
- POST returns 202 with job ID immediately (no `time.sleep`)
- Polling returns plausible progress percentages
- Never completes (stuck at 99%)
- Each request is cheap; the deception is interactive without blocking workers

**Fake credentials and misconfigurations**
- HTML comments with test accounts, TODOs, debug paths
- `.env` with commented-out old passwords, fake S3 buckets
- `robots.txt` disallowing tempting paths
- All lead nowhere

### Control layer (real)

These protect actual resources and cannot be bypassed:

**Rate limiter** (`_honeypot_rate_limited`)
- Keyed by HMAC of `request.remote_addr` (trusted, not spoofable)
- 30 hits/minute per client; over budget → minimal 404 responses
- Independent of XFF, cookies, or any attacker-controlled header

**Infrastructure caps**
- `--max-instances 3` (deploy workflow)
- `--concurrency 8` per instance
- Worst case bounded regardless of attack volume

**No password collection**
- Fake login forms log that an attempt occurred
- Submitted passwords are NEVER stored, logged, or transmitted
- Audit events contain path and metadata only

**Cheap robots.txt**
- No rate limit check, no delay
- Legitimate crawlers unaffected

## Why this matters

The previous design trusted `X-Forwarded-For` for the real rate limit budget.
This was an actual vulnerability: an attacker could reset the expensive delay
budget by rotating headers. The deception (fake counter) and the control
(real limit) were conflated.

The fix separates them:
- Deception operates on attacker-controlled signals (XFF)
- Controls operate on trusted signals (`remote_addr`)
- The attacker cannot distinguish which is which from outside

This follows MITRE Engage principles: shape what the adversary sees, thinks,
and does, without introducing real weaknesses.

## ASN logging

When `VAULT_IP_LOGGING=on`, honeypot hits log the attacker's ASN:

```
event="honeypot_hit" path="/wp-login.php" asn="AS15169 Google LLC"
```

Uses bundled GeoLite2-ASN database (8.6MB, free). Local file lookups,
zero per-query cost. See `geoip/ATTRIBUTION.md`.

## Monitoring

**Deception engagement metrics** (for future analysis):
- Unique XFF values per session (measures perceived bypass attempts)
- Backup job poll count (measures engagement depth)
- Path progression: robots.txt → .env → wp-login → backup/export
- Repeat visits with different XFF (sophisticated actor indicator)

**Security signals:**
- `honeypot_hit` with ASN (threat intel)
- `honeypot_credential_attempt` (active exploitation attempt, no password stored)
- `honeypot_rate_limited` (flooding, real limit engaged)
- `honeypot_backup_job_started` (deep engagement)

## Testing

`TestHoneypotTarpit` (13 tests) verifies:
- Fake content served correctly
- XFF counter resets (deception works)
- XFF rotation does NOT reset real limit (control works)
- Passwords not logged
- Backup export returns immediately (no sleep)
- Rate limiting engages on trusted IP
