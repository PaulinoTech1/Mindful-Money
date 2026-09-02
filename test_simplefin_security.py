#!/usr/bin/env python3
"""Security regression tests for the SimpleFin integration.

    python3 test_simplefin_security.py
    pytest test_simplefin_security.py

Covers: SSRF/URL validation, redirect rejection, response size limits,
SimpleFin JSON schema validation, Decimal-based money parsing, and a
source-level regression guard for the stored-XSS fix in renderAccounts().
No network access and no real SimpleFin bridge are used -- DNS resolution
and the socket layer are mocked.
"""

from __future__ import annotations

import ipaddress
import unittest
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import simplefin
import simplefin_models
import simplefin_security as sfsec

STATIC = Path(__file__).parent / "static" / "app.js"


# ---------------------------------------------------------------- URL / SSRF


class TestUrlValidation(unittest.TestCase):
    def test_rejects_http(self):
        with self.assertRaises(sfsec.SimpleFinSecurityError):
            sfsec.parse_and_validate_https_url("http://example.com/accounts")

    def test_rejects_ftp_file_data_javascript_schemes(self):
        for scheme in ("ftp", "file", "gopher", "data", "javascript", "unix"):
            with self.subTest(scheme=scheme):
                with self.assertRaises(sfsec.SimpleFinSecurityError):
                    sfsec.parse_and_validate_https_url(f"{scheme}://example.com/x")

    def test_accepts_https(self):
        parts = sfsec.parse_and_validate_https_url("https://bridge.simplefin.org/simplefin/accounts")
        self.assertEqual(parts.hostname, "bridge.simplefin.org")

    def test_rejects_missing_hostname(self):
        with self.assertRaises(sfsec.SimpleFinSecurityError):
            sfsec.parse_and_validate_https_url("https:///accounts")

    def test_rejects_malformed_port(self):
        with self.assertRaises(sfsec.SimpleFinSecurityError):
            sfsec.parse_and_validate_https_url("https://example.com:notaport/accounts")

    def test_rejects_oversized_url(self):
        huge = "https://example.com/" + ("a" * sfsec.MAX_URL_LENGTH)
        with self.assertRaises(sfsec.SimpleFinSecurityError):
            sfsec.parse_and_validate_https_url(huge)

    def test_rejects_control_characters(self):
        with self.assertRaises(sfsec.SimpleFinSecurityError):
            sfsec.parse_and_validate_https_url("https://example.com/\x00/accounts")

    def test_allowlist_rejects_unlisted_host(self):
        with self.assertRaises(sfsec.SimpleFinSecurityError):
            sfsec.parse_and_validate_https_url(
                "https://evil.example.com/accounts", allowed_hosts=frozenset({"bridge.simplefin.org"}),
            )

    def test_allowlist_accepts_listed_host(self):
        parts = sfsec.parse_and_validate_https_url(
            "https://bridge.simplefin.org/accounts", allowed_hosts=frozenset({"bridge.simplefin.org"}),
        )
        self.assertEqual(parts.hostname, "bridge.simplefin.org")


class TestDnsResolutionSsrf(unittest.TestCase):
    """resolve_and_verify_public() is where private/loopback/link-local/
    metadata destinations actually get rejected, using ipaddress rather
    than a hand-maintained list of literal strings."""

    def _mock_addrinfo(self, ip: str):
        return [(2 if ":" not in ip else 10, 1, 6, "", (ip, 443))]

    def test_rejects_localhost_loopback_v4(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo("127.0.0.1")):
            with self.assertRaises(sfsec.SimpleFinSecurityError):
                sfsec.resolve_and_verify_public("localhost")

    def test_rejects_loopback_v6(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo("::1")):
            with self.assertRaises(sfsec.SimpleFinSecurityError):
                sfsec.resolve_and_verify_public("target")

    def test_rejects_cloud_metadata_address(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo("169.254.169.254")):
            with self.assertRaises(sfsec.SimpleFinSecurityError):
                sfsec.resolve_and_verify_public("target")

    def test_rejects_rfc1918_private_v4(self):
        for ip in ("10.0.0.5", "172.16.0.5", "192.168.1.5"):
            with self.subTest(ip=ip):
                with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(ip)):
                    with self.assertRaises(sfsec.SimpleFinSecurityError):
                        sfsec.resolve_and_verify_public("target")

    def test_rejects_ipv6_unique_local(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo("fd00::1")):
            with self.assertRaises(sfsec.SimpleFinSecurityError):
                sfsec.resolve_and_verify_public("target")

    def test_rejects_ipv4_mapped_ipv6_private(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo("::ffff:10.0.0.5")):
            with self.assertRaises(sfsec.SimpleFinSecurityError):
                sfsec.resolve_and_verify_public("target")

    def test_rejects_multicast_and_unspecified(self):
        for ip in ("224.0.0.1", "0.0.0.0"):
            with self.subTest(ip=ip):
                with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(ip)):
                    with self.assertRaises(sfsec.SimpleFinSecurityError):
                        sfsec.resolve_and_verify_public("target")

    def test_accepts_public_address(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo("93.184.216.34")):
            ip = sfsec.resolve_and_verify_public("target")
            self.assertEqual(ip, "93.184.216.34")

    def test_dns_failure_fails_closed(self):
        import socket as socket_mod
        with patch("socket.getaddrinfo", side_effect=socket_mod.gaierror("no such host")):
            with self.assertRaises(sfsec.SimpleFinSecurityError):
                sfsec.resolve_and_verify_public("nowhere.invalid")


# ---------------------------------------------------------------- redirects


class TestRedirectHandling(unittest.TestCase):
    def test_redirect_status_is_rejected(self):
        class FakeResponse:
            status = 302
            def read(self, *_a, **_k): return b""

        class FakeConn:
            def __init__(self, *a, **k): pass
            def request(self, *a, **k): pass
            def getresponse(self): return FakeResponse()
            def close(self): pass

        with patch("simplefin_security._PinnedHTTPSConnection", FakeConn), \
             patch.object(sfsec, "resolve_and_verify_public", return_value="93.184.216.34"):
            with self.assertRaises(sfsec.SimpleFinSecurityError):
                sfsec.fetch_no_redirect(
                    "https://example.com/accounts", headers={}, connect_timeout=1, read_timeout=1, max_bytes=1000,
                )


# ---------------------------------------------------------------- size limits


class TestResponseSizeLimit(unittest.TestCase):
    def test_oversized_body_is_rejected(self):
        class FakeResponse:
            status = 200
            def read(self, n): return b"x" * (n)  # simulate a body at/over the cap

        class FakeConn:
            def __init__(self, *a, **k): pass
            def request(self, *a, **k): pass
            def getresponse(self): return FakeResponse()
            def close(self): pass

        with patch("simplefin_security._PinnedHTTPSConnection", FakeConn), \
             patch.object(sfsec, "resolve_and_verify_public", return_value="93.184.216.34"):
            with self.assertRaises(sfsec.SimpleFinSecurityError):
                sfsec.fetch_no_redirect(
                    "https://example.com/accounts", headers={}, connect_timeout=1, read_timeout=1, max_bytes=10,
                )


# ---------------------------------------------------------------- JSON / schema


class TestAccountSetValidation(unittest.TestCase):
    def test_malformed_json_rejected(self):
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(b"{not json")

    def test_non_object_top_level_rejected(self):
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(b"[1, 2, 3]")

    def test_wrong_field_type_rejected(self):
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(b'{"accounts": "not-a-list"}')

    def test_missing_required_transaction_fields_rejected(self):
        body = b'{"accounts": [{"id": "a1", "transactions": [{"amount": "1.00"}]}]}'
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(body)

    def test_huge_amount_rejected(self):
        body = (
            b'{"accounts": [{"id": "a1", "transactions": '
            b'[{"id": "t1", "posted": 1700000000, "amount": "99999999999999999999999999"}]}]}'
        )
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(body)

    def test_non_finite_amount_rejected(self):
        body = (
            b'{"accounts": [{"id": "a1", "transactions": '
            b'[{"id": "t1", "posted": 1700000000, "amount": "Infinity"}]}]}'
        )
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(body)

    def test_non_numeric_amount_rejected(self):
        body = (
            b'{"accounts": [{"id": "a1", "transactions": '
            b'[{"id": "t1", "posted": 1700000000, "amount": "<script>alert(1)</script>"}]}]}'
        )
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(body)

    def test_absurd_timestamp_rejected(self):
        body = (
            b'{"accounts": [{"id": "a1", "transactions": '
            b'[{"id": "t1", "posted": 999999999999999, "amount": "1.00"}]}]}'
        )
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(body)

    def test_excessive_string_length_rejected(self):
        body = (
            b'{"accounts": [{"id": "a1", "name": "' + b"a" * 5000 + b'", "transactions": []}]}'
        )
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(body)

    def test_excessive_account_array_size_rejected(self):
        accounts = b",".join(b'{"id": "a%d", "transactions": []}' % i for i in range(simplefin_models.MAX_ACCOUNTS + 1))
        body = b'{"accounts": [' + accounts + b"]}"
        with self.assertRaises(simplefin_models.SchemaValidationError):
            simplefin_models.parse_account_set(body)

    def test_unknown_fields_ignored_not_trusted(self):
        body = (
            b'{"accounts": [{"id": "a1", "name": "Checking", "__proto__": "polluted", '
            b'"transactions": [{"id": "t1", "posted": 1700000000, "amount": "12.34", "unexpected_field": "x"}]}]}'
        )
        result = simplefin_models.parse_account_set(body)
        self.assertEqual(len(result.accounts), 1)
        self.assertFalse(hasattr(result.accounts[0], "__proto__"))

    def test_well_formed_response_parses(self):
        body = (
            b'{"accounts": [{"id": "a1", "name": "Checking", '
            b'"org": {"name": "Big Bank"}, "transactions": '
            b'[{"id": "t1", "posted": 1700000000, "amount": "-12.34", "payee": "Coffee Shop"}]}]}'
        )
        result = simplefin_models.parse_account_set(body)
        self.assertEqual(result.accounts[0].transactions[0].decimal_amount(), Decimal("-12.34"))

    def test_xss_payloads_survive_as_plain_text_not_stripped(self):
        payload = "<img src=x onerror=alert(1)>"
        body_obj = {
            "accounts": [{
                "id": "a1", "name": payload,
                "org": {"name": "</script><script>alert(1)</script>"},
                "transactions": [{
                    "id": "t1", "posted": 1700000000, "amount": "5.00",
                    "payee": "<script>alert(1)</script>",
                }],
            }],
        }
        import json
        result = simplefin_models.parse_account_set(json.dumps(body_obj).encode())
        # The strings are preserved verbatim as data -- not executed, not
        # HTML-stripped. Safety comes from output encoding at render time.
        self.assertEqual(result.accounts[0].name, payload)
        self.assertEqual(result.accounts[0].transactions[0].payee, "<script>alert(1)</script>")


# ---------------------------------------------------------------- normalization


class TestGenerateNormalization(unittest.TestCase):
    """generate() end-to-end against a mocked, security-validated fetch."""

    def _run_with_body(self, body: bytes, *, status=200):
        with patch.dict("os.environ", {"SIMPLEFIN_ACCESS_URL": "https://user:pass@bridge.simplefin.org/simplefin"}), \
             patch("simplefin.fetch_no_redirect", return_value=sfsec.FetchResult(status=status, body=body)):
            return simplefin.generate()

    def test_amount_sign_is_flipped_and_rounded_via_decimal(self):
        body = (
            b'{"accounts": [{"id": "a1", "name": "Checking", "transactions": '
            b'[{"id": "t1", "posted": 1700000000, "amount": "10.005"}]}]}'
        )
        rows = self._run_with_body(body)
        self.assertEqual(len(rows), 1)
        # inflow-positive -> spend-positive: sign flips.
        self.assertEqual(rows[0]["amount"], -10.0)  # ROUND_HALF_EVEN(10.005, 2dp)

    def test_403_raises_access_revoked(self):
        with patch.dict("os.environ", {"SIMPLEFIN_ACCESS_URL": "https://bridge.simplefin.org/simplefin"}), \
             patch("simplefin.fetch_no_redirect", return_value=sfsec.FetchResult(status=403, body=b"{}")):
            with self.assertRaises(simplefin.SimpleFinAccessRevoked):
                simplefin.generate()

    def test_not_configured_raises_before_any_network_call(self):
        with patch.dict("os.environ", {}, clear=False):
            import os as _os
            _os.environ.pop("SIMPLEFIN_ACCESS_URL", None)
            with self.assertRaises(simplefin.SimpleFinNotConfigured):
                simplefin.generate()

    def test_security_rejection_becomes_unavailable_not_leaked(self):
        with patch.dict("os.environ", {"SIMPLEFIN_ACCESS_URL": "https://bridge.simplefin.org/simplefin"}), \
             patch("simplefin.fetch_no_redirect", side_effect=sfsec.SimpleFinSecurityError("internal detail")):
            with self.assertRaises(simplefin.SimpleFinUnavailable) as ctx:
                simplefin.generate()
            self.assertNotIn("internal detail", str(ctx.exception))


# ---------------------------------------------------------------- credential hygiene


class TestCredentialHygiene(unittest.TestCase):
    def test_redact_url_drops_userinfo_path_query(self):
        redacted = sfsec.redact_url("https://alice:s3cr3t@bridge.simplefin.org/simplefin/accounts?start-date=123")
        self.assertNotIn("alice", redacted)
        self.assertNotIn("s3cr3t", redacted)
        self.assertNotIn("start-date", redacted)
        self.assertEqual(redacted, "https://bridge.simplefin.org")

    def test_target_and_headers_moves_credentials_to_header_not_url(self):
        url, headers = simplefin._target_and_headers("https://alice:s3cr3t@bridge.simplefin.org/simplefin", 30)
        self.assertNotIn("alice", url)
        self.assertNotIn("s3cr3t", url)
        self.assertIn("Authorization", headers)


# ---------------------------------------------------------------- frontend XSS regression guard


class TestFrontendEscaping(unittest.TestCase):
    """renderAccounts() previously interpolated SimpleFin-derived
    institution/account names into innerHTML unescaped (stored XSS). This
    is a source-level regression guard, not a DOM test, since the project
    has no browser test harness for app.js."""

    def setUp(self):
        self.source = STATIC.read_text(encoding="utf-8")

    def test_account_bank_is_escaped(self):
        self.assertIn("escapeHtml(meta.bank)", self.source)

    def test_account_label_is_escaped(self):
        self.assertIn("escapeHtml(meta.label)", self.source)

    def test_account_type_is_escaped(self):
        self.assertIn("escapeHtml(meta.type)", self.source)


def main():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name, obj in list(globals().items()):
        if isinstance(obj, type) and issubclass(obj, unittest.TestCase):
            suite.addTests(loader.loadTestsFromTestCase(obj))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
