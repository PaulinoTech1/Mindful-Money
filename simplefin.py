"""SimpleFin Protocol adapter.

Normalizes SimpleFin's /accounts response into the same transaction shape as
fakebank.generate(), so nothing downstream (categorization, the encrypted
relay, the browser) needs to know which feed produced a record.

SimpleFin's amount sign convention is inflow-positive; this app's convention
(see fakebank.py and README) is spend-positive, income-negative, so amounts
are negated on the way in.

Trust boundary (see simplefin_security.py and simplefin_models.py for the
layers this module composes):

    SimpleFin bridge (untrusted, regardless of TLS)
        -> simplefin_security.fetch_no_redirect   HTTPS/SSRF/TLS/size/time
        -> simplefin_models.parse_account_set     schema + semantic validation
        -> this module                            normalize into app's shape
        -> trusted application data

SIMPLEFIN_ACCESS_URL is server-operator configuration (an environment
variable). This application has no endpoint where a browser client submits
a raw SimpleFin setup token -- there is currently no "claim" flow. The
access URL is still handled as a secret equivalent to a password: it is
never logged, never included in an exception message, and never sent to
the browser (see _target_and_headers below and relay_sources() in app.py,
which only ever returns a boolean).
"""

from __future__ import annotations

import base64
import logging
import os
import time
from datetime import datetime, timezone
from decimal import Decimal
from urllib.parse import urlsplit, urlunsplit

from simplefin_models import SchemaValidationError, parse_account_set
from simplefin_security import FetchResult, SimpleFinSecurityError, fetch_no_redirect, redact_url

LOG = logging.getLogger("vault.security.simplefin")

SIMPLEFIN_MAX_RANGE_DAYS = 90
CONNECT_TIMEOUT = float(os.environ.get("SIMPLEFIN_CONNECT_TIMEOUT", "5"))
READ_TIMEOUT = float(os.environ.get("SIMPLEFIN_READ_TIMEOUT", "25"))
MAX_RESPONSE_BYTES = int(os.environ.get("SIMPLEFIN_MAX_RESPONSE_BYTES", str(20 * 1024 * 1024)))


class SimpleFinError(RuntimeError):
    """The SimpleFin bridge could not be reached or returned no usable data.
    Message text is always safe to log or show a user: never the access
    URL, credentials, or raw upstream response content."""


class SimpleFinNotConfigured(SimpleFinError):
    """SIMPLEFIN_ACCESS_URL is not set for this server."""


class SimpleFinAccessRevoked(SimpleFinError):
    """SimpleFin returned HTTP 403. Per the SimpleFin protocol this can
    mean the access URL was already claimed/used elsewhere and should be
    treated as potentially compromised -- app.py surfaces a warning telling
    the user to disable/recreate the connection, without echoing any
    upstream detail."""


class SimpleFinUnavailable(SimpleFinError):
    """Transient or non-conforming response: timeout, DNS failure, TLS
    failure, connection failure, oversized response, malformed JSON, or a
    response that failed schema validation. Retrying later may succeed."""


def _access_url() -> str:
    url = os.environ.get("SIMPLEFIN_ACCESS_URL")
    if not url:
        raise SimpleFinNotConfigured("SIMPLEFIN_ACCESS_URL is not set")
    return url.rstrip("/")


def _account_type(name: str) -> str:
    lowered = name.lower()
    for needle, label in (
        ("checking", "Checking"), ("savings", "Savings"), ("credit", "Credit Card"),
        ("401", "401(k)"), ("ira", "IRA"), ("brokerage", "Brokerage"), ("loan", "Loan"),
    ):
        if needle in lowered:
            return label
    return "Account"


def _target_and_headers(access_url: str, days: int) -> tuple[str, dict[str, str]]:
    parts = urlsplit(access_url)
    # Cloudflare, which fronts the SimpleFin bridge, blocks the default
    # urllib/http.client User-Agent as bot traffic and returns a bare 403.
    headers = {"Accept": "application/json", "User-Agent": "mindful-money-simplefin/1.0"}
    if parts.username is not None:
        # Credentials travel only in this header, for this one request, to
        # the one host fetch_no_redirect just validated -- never forwarded
        # across a redirect (none are ever followed) and never logged.
        credentials = base64.b64encode(f"{parts.username}:{parts.password or ''}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"
    host = parts.hostname + (f":{parts.port}" if parts.port else "")
    base = urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    start = int(time.time()) - days * 86400
    return f"{base}/accounts?start-date={start}", headers


def generate(days: int = SIMPLEFIN_MAX_RANGE_DAYS) -> list[dict]:
    """Fetch and normalize transactions for every account on the linked
    bridge. Only data that has passed both the transport-security checks
    in simplefin_security and the schema validation in simplefin_models is
    ever normalized into this application's transaction shape."""
    days = min(days, SIMPLEFIN_MAX_RANGE_DAYS)
    access_url = _access_url()
    url, headers = _target_and_headers(access_url, days)

    try:
        result: FetchResult = fetch_no_redirect(
            url, headers=headers,
            connect_timeout=CONNECT_TIMEOUT, read_timeout=READ_TIMEOUT,
            max_bytes=MAX_RESPONSE_BYTES,
        )
    except SimpleFinSecurityError as exc:
        LOG.warning('event="simplefin_security_rejected" host="%s" reason="%s"', redact_url(url), str(exc))
        raise SimpleFinUnavailable("SimpleFin could not be reached") from exc

    if result.status == 403:
        LOG.warning('event="simplefin_access_revoked" host="%s"', redact_url(url))
        raise SimpleFinAccessRevoked("SimpleFin access may have been revoked")
    if result.status == 402:
        LOG.warning('event="simplefin_payment_required" host="%s"', redact_url(url))
        raise SimpleFinUnavailable("SimpleFin reports payment is required for this connection")
    if result.status != 200:
        LOG.warning('event="simplefin_http_error" host="%s" status="%d"', redact_url(url), result.status)
        raise SimpleFinUnavailable(f"SimpleFin returned HTTP {result.status}")

    try:
        account_set = parse_account_set(result.body)
    except SchemaValidationError as exc:
        LOG.warning('event="simplefin_schema_invalid" host="%s"', redact_url(url))
        raise SimpleFinUnavailable("SimpleFin returned an unexpected response") from exc

    if not account_set.accounts and account_set.errors:
        LOG.warning('event="simplefin_accounts_errors" host="%s" count="%d"', redact_url(url), len(account_set.errors))
        raise SimpleFinUnavailable("SimpleFin reported an error for this connection")

    rows: list[dict] = []
    for account in account_set.accounts:
        account_id = account.id
        org_name = (account.org.name if account.org and account.org.name else None) or "Unknown institution"
        account_label = account.name or account_id
        account_type = _account_type(account_label)
        for txn in account.transactions:
            posted = txn.posted if txn.posted is not None else txn.transacted_at
            if posted is None:
                continue
            amount = (-txn.decimal_amount()).quantize(Decimal("0.01"))
            iso_date = datetime.fromtimestamp(posted, tz=timezone.utc).date().isoformat()
            rows.append({
                "id": f"simplefin_{account_id}_{txn.id or posted}",
                "merchant": txn.payee or txn.description or "Unknown",
                "amount": float(amount),
                "date": iso_date,
                "pending": bool(txn.pending),
                "account": account_id,
                "bank": org_name,
                "account_label": account_label,
                "account_type": account_type,
                "source": "simplefin",
            })

    rows.sort(key=lambda r: r["date"])
    return rows


if __name__ == "__main__":
    txns = generate()
    spend = sum(t["amount"] for t in txns if t["amount"] > 0)
    income = -sum(t["amount"] for t in txns if t["amount"] < 0)
    print(f"{len(txns)} transactions across {len({t['account'] for t in txns})} accounts")
    if txns:
        print(f"{txns[0]['date']} to {txns[-1]['date']}")
    print(f"income  ${income:,.2f}")
    print(f"spend   ${spend:,.2f}")
