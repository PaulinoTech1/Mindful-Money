"""SSRF/TLS-safe outbound HTTP for the SimpleFin integration.

Trust boundary this module enforces (see simplefin.py and simplefin_models.py
for the layers above and below it):

    SimpleFin bridge (untrusted external infrastructure)
        |  HTTPS, CA + hostname verified, TLS >= 1.2, no redirects followed
        v
    this module: URL/SSRF validation, DNS-rebinding-resistant connect,
                 bounded response size, bounded timeouts
        v
    simplefin.py: interprets protocol/HTTP status
        v
    simplefin_models.py: schema + semantic validation
        v
    trusted application data

SIMPLEFIN_ACCESS_URL is server-operator configuration (an environment
variable), not a value a browser client submits at request time -- this
application has no "claim a setup token" endpoint. It is nonetheless
treated as adversarial input here: a misconfigured or compromised access
URL, or a malicious/compromised upstream bridge, must not be able to make
this server reach an internal address or exfiltrate data past size/time
bounds.

Residual risk -- DNS rebinding: `resolve_and_verify_public()` re-resolves
the hostname on every call (not cached) and `_PinnedHTTPSConnection`
connects to the *exact* address that was just validated, so there is no
gap between "checked" and "connected" for a single request. What remains
unresolved at the application layer is a bridge host that is legitimately,
persistently multi-homed to both a public and an internal address and
which answers differently depending on which one is probed -- no amount of
per-request string/IP validation fully closes that without an egress
firewall in front of the process. Pair this with network-level egress
restrictions in production if the deployment threat model requires it.

TLS authenticates the remote endpoint and protects the transport. It does
not prove that the financial data returned is factually correct.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

MAX_URL_LENGTH = 4096


class SimpleFinSecurityError(RuntimeError):
    """A URL or response failed a security check. Callers must fail closed
    and must never include the offending URL or credentials in the message
    (these propagate into logs)."""


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if not ip.is_global:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return True


def parse_and_validate_https_url(url: str, *, allowed_hosts: frozenset[str] | None = None) -> SplitResult:
    """Real URL parsing (urllib.parse), not string matching. Rejects
    anything that is not an unambiguous https:// URL with a hostname."""
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        raise SimpleFinSecurityError("URL missing or too long")
    if any(ord(c) < 0x20 or ord(c) == 0x7F or c == "\x00" for c in url):
        raise SimpleFinSecurityError("URL contains control characters")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise SimpleFinSecurityError("URL could not be parsed") from exc
    if parts.scheme != "https":
        raise SimpleFinSecurityError("only https URLs are permitted")
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        # urlsplit defers port validation to the .port property, where a
        # malformed port raises -- this is the "malformed ports" / "parser
        # ambiguity" case the SSRF cheat sheet calls out explicitly.
        raise SimpleFinSecurityError("URL has a malformed port") from exc
    if not hostname:
        raise SimpleFinSecurityError("URL is missing a hostname")
    if port is not None and not (0 < port < 65536):
        raise SimpleFinSecurityError("URL has an invalid port")
    if allowed_hosts is not None and hostname.lower() not in allowed_hosts:
        raise SimpleFinSecurityError("host is not on the configured allowlist")
    return parts


def resolve_and_verify_public(hostname: str) -> str:
    """Fresh DNS resolution plus an SSRF check, performed immediately
    before use (never cached) so the validated result and the connection
    target are as close together in time as possible. Returns one public
    IP literal to connect to."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SimpleFinSecurityError("DNS resolution failed") from exc
    for _family, _type, _proto, _canon, sockaddr in infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        except ValueError:
            continue
        if _is_public_ip(ip):
            return sockaddr[0]
    raise SimpleFinSecurityError("destination does not resolve to a public address")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to a pre-validated, pre-resolved IP address while still
    performing certificate hostname verification against the original
    hostname via TLS SNI. This is what makes the SSRF check above actually
    binding: without pinning, a second DNS lookup performed at TLS-connect
    time could return a different (rebound) answer than the one that was
    validated."""

    def __init__(self, resolved_ip: str, original_hostname: str, port: int, *,
                 context: ssl.SSLContext, connect_timeout: float, read_timeout: float):
        super().__init__(original_hostname, port, timeout=connect_timeout, context=context)
        self._resolved_ip = resolved_ip
        self._read_timeout = read_timeout

    def connect(self):
        sock = socket.create_connection((self._resolved_ip, self.port), timeout=self.timeout)
        sock.settimeout(self._read_timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


@dataclass(frozen=True)
class FetchResult:
    status: int
    body: bytes


def fetch_no_redirect(
    url: str,
    *,
    headers: dict[str, str],
    connect_timeout: float,
    read_timeout: float,
    max_bytes: int,
    allowed_hosts: frozenset[str] | None = None,
) -> FetchResult:
    """GET a URL with every SSRF/TLS/redirect/size control this module
    provides. Never follows redirects -- SimpleFin does not require them,
    and blindly following one could hand Basic Auth credentials meant for
    the access URL's origin to an attacker-chosen origin instead. Fails
    closed (raises SimpleFinSecurityError) on any violation."""
    parts = parse_and_validate_https_url(url, allowed_hosts=allowed_hosts)
    hostname = parts.hostname
    port = parts.port or 443
    resolved_ip = resolve_and_verify_public(hostname)

    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"

    conn = _PinnedHTTPSConnection(
        resolved_ip, hostname, port,
        context=ctx, connect_timeout=connect_timeout, read_timeout=read_timeout,
    )
    try:
        conn.request("GET", target, headers=headers)
        response = conn.getresponse()
        if 300 <= response.status < 400:
            response.read(0)
            raise SimpleFinSecurityError("redirects are not permitted")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise SimpleFinSecurityError("response exceeded the maximum allowed size")
        return FetchResult(status=response.status, body=body)
    except ssl.SSLError as exc:
        raise SimpleFinSecurityError("TLS verification failed") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise SimpleFinSecurityError("connection timed out") from exc
    except OSError as exc:
        raise SimpleFinSecurityError("connection failed") from exc
    finally:
        conn.close()


def redact_url(url: str) -> str:
    """Best-effort redaction for the rare case a URL needs to appear in a
    diagnostic message. Keeps scheme + host only; drops userinfo, path,
    query, and fragment, any of which may carry credentials or tokens."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or "?"
        port = f":{parts.port}" if parts.port else ""
        return f"{parts.scheme or '?'}://{host}{port}"
    except ValueError:
        return "<unparsable>"
