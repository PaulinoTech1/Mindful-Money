"""Conservative single-node Gunicorn configuration for Vault (PostgreSQL-backed).

workers=1 is a starting point, not a database-imposed limit: PostgreSQL
handles concurrent writers itself via MVCC and row-level locking, and
db.py's per-process connection pool already assumes more than one
in-flight request. Raising workers is safe; size workers * threads *
pool_size comfortably under PostgreSQL's max_connections if you do.
"""
import grp
import os
bind = "unix:/run/vault/vault.sock"
workers = 1
worker_class = "gthread"
threads = 4
timeout = 30
graceful_timeout = 30
keepalive = 5
max_requests = 1000
max_requests_jitter = 100
umask = 0o007
accesslog = "-"
errorlog = "-"
capture_output = False
reload = False
preload_app = False
worker_tmp_dir = "/run/vault"

def when_ready(_server):
    """Grant only the dedicated reverse-proxy group access to the socket."""
    socket_path = "/run/vault/vault.sock"
    os.chown(socket_path, -1, grp.getgrnam("vault-web").gr_gid)
    os.chmod(socket_path, 0o660)

# Deliberately omit access_log_format customizations that could record headers,
# cookies, query strings, or request bodies. The default logs method/path/status.
