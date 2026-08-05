# Vault production deployment

This is a single-node SQLite deployment for a small Vault installation. TLS,
CSP, and rate limiting reduce network and injection risk; they do not make a
compromised application origin trustworthy. A malicious deployed JavaScript
bundle can steal browser-resident passphrases and plaintext. The server still
observes ciphertext count, timing, and length. Backups contain authentication
metadata and ciphertext and remain sensitive.

## 1. Packages and identities

Examples target Debian/Ubuntu. Install Python, venv, nginx, sqlite3, and systemd
from the OS. Create non-login identities and a socket-only group:

```sh
sudo groupadd --system vault-web
sudo useradd --system --home /var/lib/vault --shell /usr/sbin/nologin vault
sudo usermod -a -G vault-web vault
sudo usermod -a -G vault-web www-data
```

The `vault` account has no password, shell, home files, sudo, capabilities, or
TLS-key access. `www-data` receives socket access only. `/var/lib/vault` is
`vault:vault` mode 0700, so nginx cannot traverse or read it even if group
memberships are misread. The socket is `vault:vault-web` mode 0660.

## 2. Install files and Python environment

Install reviewed source under `/opt/vault`, root-owned and not writable by
`vault`. Directories are 0755; Python/static files are 0644 (0444 is also
acceptable). Review and run `install-permissions.sh.example` with
`VAULT_SOURCE` set; it intentionally does not copy static recursively or create
secrets. Install those reviewed directories with explicit `install` modes.

```sh
sudo python3 -m venv /opt/vault/.venv
sudo /opt/vault/.venv/bin/pip install -r /opt/vault/requirements.txt
sudo install -d -o vault -g vault -m 0700 /var/lib/vault /var/backups/vault
```

SQLite must be able to create WAL and SHM files beside the database, so the
directory—not merely `vault.db`—is writable by `vault`. New database and backup
files should be 0600; systemd's `UMask=0077` enforces this.

## 3. Secrets and production configuration

Copy `vault.env.example` to `/etc/vault/vault.env`, replace placeholders without
putting secrets on a command line, and set `root:root` mode 0600. Never commit
that file or dump the environment to logs. Production requires HTTPS,
`VAULT_AUTH_POLICY=required`, an explicit secret/RP/origin, and an absolute
`VAULT_DB_PATH` outside `/opt/vault`. The parent must already exist, not be
world-writable, and neither it nor the database may be a symlink.

`VAULT_ORIGIN` is the exact external origin, for example
`https://vault.example.com`. `VAULT_RP_ID` is only the domain, without scheme or
port. Localhost passkeys cannot authenticate the production domain; enroll
production credentials on that domain before enforcing a migrated deployment.
There is no automatic database move. Stop the old service, create a consistent
backup, install it as `/var/lib/vault/vault.db` mode 0600, and start the new
service.

## 4. Gunicorn, systemd, and nginx

Gunicorn uses one `gthread` worker with four bounded threads. One process avoids
excessive SQLite writers; WAL and the five-second busy timeout handle short
concurrent operations. Connections are opened per request, never inherited via
preload, and closed by Flask teardown. Gunicorn binds only
`/run/vault/vault.sock`, never TCP, and logs method/path/status—not bodies or
sensitive headers—to journald.

Install `vault.service` and `nginx-vault.conf` after replacing the domain and
certificate paths. The service confines writes to `/var/lib/vault` and
`/run/vault`. `RestrictAddressFamilies=AF_UNIX` is correct for the current fake
bank. A future network bank adapter requires the reviewed addition of `AF_INET
AF_INET6`; do not silently weaken it now.

```sh
sudo install -o root -g root -m 0644 deploy/vault.service /etc/systemd/system/vault.service
sudo install -o root -g root -m 0644 deploy/nginx-vault.conf /etc/nginx/sites-available/vault
sudo ln -s /etc/nginx/sites-available/vault /etc/nginx/sites-enabled/vault
sudo systemctl daemon-reload
sudo systemctl enable --now vault
sudo nginx -t
sudo systemctl reload nginx
```

nginx redirects HTTP to HTTPS, permits TLS 1.2/1.3 only, caps bodies at 8 MiB,
replaces untrusted forwarding headers, rate-limits connections/requests, blocks
hidden/source/database paths, and proxies to the Unix socket. Flask trusts
exactly one `X-Forwarded-For`/`X-Forwarded-Proto` hop only when
`VAULT_TRUST_PROXY=1`; exposing Gunicorn directly in that mode permits spoofed
forwarding data. Origin and WebAuthn configuration always come from environment,
never Host or forwarding headers.

Provision certificates using operator-controlled DNS and OS/reverse-proxy
tooling. The example paths are Let's Encrypt placeholders; no issuance is
automated here. The TLS private key must remain unreadable by `vault`.

## 5. Enrollment, backup, upgrades, and rollback

For a new remote instance, first perform a controlled production-domain
enrollment before making the site generally reachable, then set required policy.
Optional authentication is localhost-development-only. Losing both the
passphrase and every recovery mechanism makes data unrecoverable.

Create consistent backups with SQLite's backup API while the service is stopped
or online via `.backup`; never copy only a live WAL database file:

```sh
sudo -u vault sqlite3 /var/lib/vault/vault.db ".backup '/var/backups/vault/vault-YYYYMMDD.db'"
sudo chmod 0600 /var/backups/vault/vault-YYYYMMDD.db
```

Test restoration to a separate protected directory before relying on it.
Upgrades: back up, stage root-owned source in a versioned directory, run tests,
stop Vault, switch `/opt/vault`, start and inspect logs. Rollback: stop, restore
the prior source and only restore the database when the schema change is known
incompatible; idempotent additive migrations normally require no rollback.

Review logs with `journalctl -u vault`; events intentionally omit cookies,
session IDs, CSRF tokens, challenges, credentials, ciphertext, and plaintext.
Rate limiting reduces abuse and is not authentication. SQLite is supported only
within this documented single-node, single-worker model.

## 6. Validation checklist

Run only checks actually available on the deployment host:

```sh
python test_demo.py
python test_browser.py
python -m compileall .
sudo nginx -t
systemd-analyze verify deploy/vault.service
systemd-analyze security vault.service
curl -I https://vault.example.com/
curl -I https://vault.example.com/static/app.js
curl -I http://vault.example.com/
openssl s_client -connect vault.example.com:443 -tls1
openssl s_client -connect vault.example.com:443 -tls1_1
ss -lntp
stat -c '%A %U %G %n' /run/vault/vault.sock /var/lib/vault /var/lib/vault/vault.db
sudo -u www-data test ! -r /var/lib/vault/vault.db
sudo -u vault test ! -w /opt/vault/app.py
```

Expect HTTPS HTML/API/error responses to have enforced CSP, HSTS and `no-store`;
unhashed static assets use `public, max-age=300`. Expect HTTP 301, TLS 1.0/1.1
failure, no public Gunicorn TCP listener, socket mode 0660, denial for `.env`,
`.git`, database and source URLs, and JSON 429 responses with `Retry-After`.
Complete a real production-origin WebAuthn registration/login and confirm CSP
has no browser violations. Certificate renewal belongs to nginx/OS tooling.

Further tightening could add a reviewed syscall allow-list and read-only bind
mounts. They are omitted because Python, SQLite, threading, authenticators, and
distribution-specific Gunicorn behavior need host-level tracing before such a
filter can be safely deployed.
