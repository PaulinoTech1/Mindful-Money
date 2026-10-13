"""P1: the SQLAlchemyError 503 handler and /ready log loudly but redacted.

Run: VAULT_ENV=test VAULT_TEST_DATABASE_URL=... python -m pytest test_db_error_logging.py
"""
from __future__ import annotations

import logging
import os
import unittest
from unittest.mock import patch

from sqlalchemy.exc import OperationalError

import app as server_app
import db as dbmod

# Same binding as test_demo.py: real DB for session save, faked db() for the
# code under test.
dbmod.rebind(os.environ.get(
    "VAULT_TEST_DATABASE_URL",
    "postgresql+psycopg://vault:vault_dev_only_password@localhost:5432/vault_test"))

FAKE_PW = "s3cr3tPW9x"
FAKE_HOST = "ep-fake-host-123456.us-east-2.aws.neon.tech"
FAKE_URL = f"postgresql+psycopg://alice:{FAKE_PW}@{FAKE_HOST}/vaultdb"


class _FakeDriverError(Exception):
    sqlstate = "08006"


def _op_error():
    orig = _FakeDriverError(
        f'connection to server at "{FAKE_HOST}" (10.1.2.3), port 5432 failed: '
        f"could not connect using {FAKE_URL} password={FAKE_PW} user=alice\n"
        "DETAIL: second line must never be logged"
    )
    return OperationalError("SELECT secret_column FROM t WHERE x = %(x)s",
                            {"x": "bound-param-value"}, orig)


class _RaisingConn:
    def execute(self, *a, **k):
        raise _op_error()

    def commit(self):
        pass

    def rollback(self):
        pass


FORBIDDEN = [FAKE_PW, FAKE_HOST, FAKE_URL, "postgresql", "alice", "10.1.2.3",
             "bound-param-value", "secret_column", "second line"]


class DbErrorLoggingTest(unittest.TestCase):
    def setUp(self):
        self.client = server_app.app.test_client()

    def _assert_clean(self, text):
        for bad in FORBIDDEN:
            self.assertNotIn(bad, text, f"leaked {bad!r}")

    def test_api_503_logs_class_not_secrets_and_response_unchanged(self):
        with patch.object(server_app, "db", lambda: _RaisingConn()), \
             self.assertLogs("vault.security", level=logging.ERROR) as cm:
            resp = self.client.get("/api/version")
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.get_json(), {"error": "The request could not be completed"})
        logs = "\n".join(cm.output)
        self.assertIn('event="db_error"', logs)
        self.assertIn('class="OperationalError"', logs)
        self.assertIn('orig_class="_FakeDriverError"', logs)
        self.assertIn('sqlstate="08006"', logs)
        self.assertIn('path="/api/version"', logs)
        self._assert_clean(logs)

    def test_ready_logs_redacted(self):
        with patch.object(server_app, "db", lambda: _RaisingConn()), \
             self.assertLogs("vault.security", level=logging.WARNING) as cm:
            resp = self.client.get("/ready")
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.get_json(), {"status": "not_ready", "database": "error"})
        logs = "\n".join(cm.output)
        self.assertIn('event="readiness_failed"', logs)
        self.assertIn('class="OperationalError"', logs)
        self._assert_clean(logs)

    def test_redactor_unit(self):
        info = server_app._redact_db_detail(_op_error())
        self.assertEqual(info["cls"], "OperationalError")
        self.assertEqual(info["sqlstate"], "08006")
        self._assert_clean(repr(info))
        # Unique-violation DETAIL style key=value is redacted too.
        e = OperationalError("x", {}, _FakeDriverError("dup (blind_index)=(abcdef0123) exists"))
        self.assertNotIn("abcdef0123", server_app._redact_db_detail(e)["detail"])


if __name__ == "__main__":
    unittest.main()
