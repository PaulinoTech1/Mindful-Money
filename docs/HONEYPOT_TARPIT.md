# Honeypot Tarpit Design

## Purpose

Waste attacker time, increase detection probability, and gather threat
intelligence. Every second an attacker spends in the tarpit is a second
they're not spending on real targets.

## Architecture

### Covered paths

| Path | Response | Purpose |
|------|----------|---------|
| `/wp-admin`, `/wp-login.php` | Fake WordPress login (200) | Credential stuffing target |
| `/xmlrpc.php` | Fake XML-RPC response (200) | Pingback scanner engagement |
| `/.env` | Fake secrets file (200) | Dead credential harvesting |
| `/phpmyadmin` | Fake DB admin login (200) | High-value target lure |
| `/.git/config` | Fake git config (200) | Recon dead end |
| `/robots.txt` | Disallows interesting paths (200) | Directs scanners to dead ends |
| `/backup.zip`, `/db_backup.sql` | Fake ZIP garbage (200) | Wastes download/analysis time |
| `/admin`, `/api/admin`, `/server-status` | Delay then 404 | Generic tarpit |

### Tarpit delays

Each hit incurs a random 3-12 second delay using a cryptographically secure
RNG (`secrets.randbelow`). The unpredictability prevents attackers from
timing their requests around it.

POST requests to login forms get an extra delay (simulates slow auth backend).

### Bypassable rate limiting (intentional)

The rate limiter trusts the `X-Forwarded-For` header for its throttle key.
The real authentication (`_client_log_id`) uses `request.remote_addr` and
ignores XFF.

This is deliberate tarpit design:
- **Unsophisticated scanners** hit the 10 hits/minute limit and slow down or give up
- **Mid-tier analysts** spot the XFF discrepancy, rotate headers, and bypass the limit
- **Result:** skilled attackers invest MORE time in the tarpit, which is the goal

The longer they engage with fake content, the more we learn and the less
time they spend on real targets.

### Artifacts of mistakes (intentional dead ends)

Real systems have mistakes. The tarpit includes convincing ones that all
lead nowhere:

**WordPress HTML comments:**
```html
<!-- TODO: disable WP_DEBUG before production push -->
<!-- Test account: wp_admin / TempPass123! (remove before go-live) -->
<!-- WordPress 5.8.3 | PHP 7.4.21 -->
<!-- Debug: /wp-content/debug.log (rotated daily) -->
```

**`.env` file:**
```
# TODO: rotate all keys before Q4 audit
# Old credentials (disabled 2024-03, kept for reference):
# DB_PASSWORD_OLD=Summer2023!Vault
# Backup bucket: s3://vault-backups-prod (migrating to Glacier)
```

**`robots.txt`:**
```
Disallow: /admin/
Disallow: /backup/
Disallow: /old-site/
# TODO: remove /backup-2024-01.zip before launch
```

Every thread pulls into nothing. The more convincing the mistake, the deeper
the attacker invests before realizing it's fake.

### ASN logging

When `VAULT_IP_LOGGING=on`, honeypot hits log the attacker's ASN:

```
event="honeypot_hit" path="/wp-login.php" asn="AS15169 Google LLC"
```

This reveals whether the attacker is on:
- VPS/cloud provider (likely attacker infrastructure)
- VPN/proxy service
- Tor exit node
- Residential ISP (possibly compromised device)

Uses bundled GeoLite2-ASN database (8.6MB, free). Local file lookups,
zero per-query cost. See `geoip/ATTRIBUTION.md`.

## Cost controls

Three layers prevent the tarpit from becoming an economic DoS vector:

### 1. Max instances: 3

Deploy workflow sets `--max-instances 3`. Cloud Run never spins up more
than 3 instances regardless of attack volume.

Worst case: 3 × 1 vCPU × 24h = ~$2/day if fully saturated.
Normal: scales to zero ($0).

### 2. Per-IP rate limiting

More than 10 honeypot hits in 60 seconds from one IP → skip the tarpit
delay, return immediately. Flood attackers burn through their budget then
get instant responses.

### 3. Concurrency: 8

Each instance handles max 8 concurrent requests. Absolute ceiling:
24 concurrent tarpit delays across all instances.

## Monitoring

**Log events to watch:**
- `honeypot_hit` - normal tarpit engagement
- `honeypot_credential_attempt` - attacker tried credentials on fake login
- `honeypot_env_exfiltrated` - attacker downloaded fake .env
- `honeypot_backup_download` - attacker downloaded fake backup
- `honeypot_rate_limited` - flooding attempt (investigate)

**Webhook alerts:** All `HONEYPOT_HIT` events fire webhook alerts if
`VAULT_WEBHOOK_URL` is configured. Includes ASN when available.

## Testing

`TestHoneypotTarpit` (10 tests) verifies:
- Fake content served correctly
- Audit events created
- Rate limiting works
- XFF bypass works (intentional)
- ASN lookup functions
- Trap not revealed by error codes
