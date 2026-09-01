# Vault production deployment

This is a single-node deployment for a small Vault installation, with
PostgreSQL as a separate service. TLS, CSP, and rate limiting reduce network
and injection risk; they do not make a compromised application origin
trustworthy. A malicious deployed JavaScript bundle can steal browser-resident
passphrases and plaintext. The server still observes ciphertext count,
timing, and length. Backups contain authentication metadata and ciphertext
and remain sensitive.

## 1. Packages and identities

Examples target Debian/Ubuntu. Install Python, venv, nginx, and systemd from
the OS. If backups run from this host, also install `postgresql-client` for
`pg_dump`/`pg_restore`. Create non-login identities and a socket-only group:

```sh
sudo groupadd --system vault-web
sudo useradd --system --home /var/lib/vault --shell /usr/sbin/nologin vault
sudo usermod -a -G vault-web vault
sudo usermod -a -G vault-web www-data
```

The `vault` account has no password, shell, home files, sudo, capabilities, or
TLS-key access. `www-data` receives socket access only. The Gunicorn socket is
`vault:vault-web` mode 0660.

## 2. Install files and Python environment

Install reviewed source under `/opt/vault`, root-owned and not writable by
`vault`. Directories are 0755; Python/static files are 0644 (0444 is also
acceptable). Review and run `install-permissions.sh.example` with
`VAULT_SOURCE` set; it intentionally does not copy static recursively or create
secrets. Install those reviewed directories with explicit `install` modes.

```sh
sudo python3 -m venv /opt/vault/.venv
sudo /opt/vault/.venv/bin/pip install -r /opt/vault/requirements.txt
sudo install -d -o vault -g vault -m 0700 /var/backups/vault
```

The application holds no local data directory: all state lives in PostgreSQL.
`/var/backups/vault` exists only to hold `pg_dump` output (§5). New backup
files should be 0600; systemd's `UMask=0077` enforces this.

## 3. PostgreSQL: roles, database, and network exposure

Provision PostgreSQL 16+ separately (same host via a Unix socket, or a managed
service). The application must never run as a superuser and must not receive
`SUPERUSER`, `CREATEDB`, `CREATEROLE`, or `REPLICATION`. Use a separate role
for running Alembic migrations if migrations should not run with the same
privileges as the live application:

```sh
sudo -u postgres psql <<'SQL'
CREATE ROLE vault_app LOGIN PASSWORD 'REPLACE_WITH_A_LONG_RANDOM_PASSWORD';
CREATE ROLE vault_migrate LOGIN PASSWORD 'REPLACE_WITH_A_DIFFERENT_LONG_RANDOM_PASSWORD';
CREATE DATABASE vault_prod OWNER vault_migrate;
\c vault_prod
GRANT CONNECT ON DATABASE vault_prod TO vault_app;
GRANT USAGE ON SCHEMA public TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO vault_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO vault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO vault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO vault_app;
SQL
```

`vault_migrate` owns the schema and runs Alembic (`alembic upgrade head`,
§5); `vault_app` only reads/writes rows in tables that already exist. Neither
role needs `CREATEDB`/`CREATEROLE`/`SUPERUSER`.

Require SCRAM-SHA-256 authentication (`password_encryption = scram-sha-256`
in `postgresql.conf`, which also determines the hash algorithm used when
these roles' passwords are set). In `pg_hba.conf`, restrict access to exactly
the connection method actually used — for a same-host Unix socket:

```
local   vault_prod   vault_app,vault_migrate   scram-sha-256
```

**Do not bind PostgreSQL to a publicly reachable interface.** For a same-host
deployment, `postgresql.conf`'s `listen_addresses` should not include the
public interface at all — the Unix socket needs no `listen_addresses` entry.
If the application and database are genuinely on separate hosts, require TLS
(`hostssl` in `pg_hba.conf`, `sslmode=verify-full` in `VAULT_DATABASE_URL`)
and restrict the `hostssl` line to the application host's address, never
`0.0.0.0/0`.

`VAULT_DATABASE_URL` for the application (`vault.env`, §4) uses the
`vault_app` role and the same-host Unix socket by default:

```
VAULT_DATABASE_URL=postgresql+psycopg://vault_app:REPLACE_WITH_A_LONG_RANDOM_PASSWORD@/vault_prod?host=/var/run/postgresql
```

Running Alembic (`alembic upgrade head`) uses a separate, migration-only
connection string with the `vault_migrate` role — set `VAULT_DATABASE_URL` to
that role's connection string only for the duration of the migration step
(§5), never in the running service's environment.

## 4. Secrets and production configuration

Copy `vault.env.example` to `/etc/vault/vault.env`, replace placeholders without
putting secrets on a command line, and set `root:root` mode 0600. Never commit
that file or dump the environment to logs. Production requires HTTPS,
`VAULT_AUTH_POLICY=required`, an explicit secret/RP/origin, and
`VAULT_DATABASE_URL` pointing at the `vault_app` role from §3.

`VAULT_ORIGIN` is the exact external origin, for example
`https://vault.example.com`. `VAULT_RP_ID` is only the domain, without scheme or
port. Localhost passkeys cannot authenticate the production domain; enroll
production credentials on that domain before enforcing a migrated deployment.

## 5. Gunicorn, systemd, and nginx

Gunicorn uses one `gthread` worker with four bounded threads by default.
Unlike the earlier SQLite-backed version, this is no longer a single-writer
constraint — PostgreSQL handles concurrent writers itself via MVCC and
row-level locking, and `db.py`'s connection pool (`pool_size=5,
max_overflow=10` per process) already assumes more than one in-flight
request. Raising `workers` is safe and a reasonable next tuning step; this
deployment keeps the conservative default rather than sizing it against a
specific load target here. Whatever value is chosen, keep `workers × threads
× pool_size` comfortably under PostgreSQL's `max_connections`. Gunicorn binds
only `/run/vault/vault.sock`, never TCP, and logs method/path/status — not
bodies or sensitive headers — to journald.

Install `vault.service` and `nginx-vault.conf` after replacing the domain and
certificate paths. The service confines writes to `/run/vault`.
`RestrictAddressFamilies=AF_UNIX` is correct when PostgreSQL is reached over
its own Unix domain socket on the same host (the default in §3) — this is the
recommended setup for a single-node deployment and keeps the tighter sandbox.
If PostgreSQL is instead reached over TCP (a remote or managed database),
`RestrictAddressFamilies` needs the reviewed addition of `AF_INET AF_INET6`;
do not add this unless the connection string in `VAULT_DATABASE_URL` actually
requires it.

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

## 6. Enrollment, migrations, backup, upgrades, and rollback

For a new remote instance, first perform a controlled production-domain
enrollment before making the site generally reachable, then set required policy.
Optional authentication is localhost-development-only. Losing both the
passphrase and every recovery mechanism makes data unrecoverable — this
remains true regardless of the database backend.

Before starting the service for the first time (and on every upgrade that
adds a migration), apply the schema with the `vault_migrate` role from §3:

```sh
sudo -u vault VAULT_DATABASE_URL='postgresql+psycopg://vault_migrate:...@/vault_prod?host=/var/run/postgresql' \
    /opt/vault/.venv/bin/alembic -c /opt/vault/alembic.ini upgrade head
```

Back up with `pg_dump` in the custom format, which supports parallel restore
and doesn't require the service to be stopped (it reads a consistent
snapshot via a transaction):

```sh
sudo -u vault pg_dump --format=custom --file=/var/backups/vault/vault-$(date +%Y%m%d).dump \
    "postgresql://vault_migrate:...@/vault_prod?host=/var/run/postgresql"
sudo chmod 0600 /var/backups/vault/vault-*.dump
```

**Test restoration** to a separate, throwaway database before relying on any
backup — a backup that has never been restored is unverified:

```sh
sudo -u postgres createdb vault_restore_test
sudo -u vault pg_restore --dbname=vault_restore_test /var/backups/vault/vault-YYYYMMDD.dump
```

Upgrades: back up, run any new Alembic migration against a copy first if the
migration is non-trivial, stage root-owned source in a versioned directory,
run tests, stop Vault, switch `/opt/vault`, run `alembic upgrade head` against
the real database, start and inspect logs. Rollback: stop, restore the prior
source, and run `alembic downgrade <prior revision>` only when the schema
change is known incompatible with the prior code — additive migrations
normally require no schema rollback, only a code rollback.

Review logs with `journalctl -u vault`; events intentionally omit cookies,
session IDs, CSRF tokens, challenges, credentials, ciphertext, and plaintext.
Rate limiting reduces abuse and is not authentication.

## 7. Validation checklist

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
sudo -u postgres psql -c "\du" | grep vault_app   # confirm no SUPERUSER/CREATEDB/CREATEROLE/REPLICATION
sudo ss -lntp | grep 5432 || echo "postgres not listening on any TCP port"  # expect no output before the ||
sudo -u vault test ! -w /opt/vault/app.py
```

Expect HTTPS HTML/API/error responses to have enforced CSP, HSTS and `no-store`;
unhashed static assets use `public, max-age=300`. Expect HTTP 301, TLS 1.0/1.1
failure, no public Gunicorn TCP listener, socket mode 0660, no public
PostgreSQL TCP listener, denial for `.env`, `.git`, database and source URLs,
and JSON 429 responses with `Retry-After`. Complete a real production-origin
WebAuthn registration/login and confirm CSP has no browser violations.
Certificate renewal belongs to nginx/OS tooling.

Further tightening could add a reviewed syscall allow-list and read-only bind
mounts. They are omitted because Python, PostgreSQL client libraries,
threading, authenticators, and distribution-specific Gunicorn behavior need
host-level tracing before such a filter can be safely deployed.
