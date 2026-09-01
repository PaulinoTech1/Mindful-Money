"""SimpleFin Protocol adapter.

Normalizes SimpleFin's /accounts response into the same transaction shape as
fakebank.generate(), so nothing downstream (categorization, the encrypted
relay, the browser) needs to know which feed produced a record.

SimpleFin's amount sign convention is inflow-positive; this app's convention
(see fakebank.py and README) is spend-positive, income-negative, so amounts
are negated on the way in.
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

SIMPLEFIN_MAX_RANGE_DAYS = 90


class SimpleFinError(RuntimeError):
    """The SimpleFin bridge could not be reached or returned no usable data."""


class SimpleFinNotConfigured(SimpleFinError):
    """SIMPLEFIN_ACCESS_URL is not set for this server."""


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


def generate(days: int = SIMPLEFIN_MAX_RANGE_DAYS) -> list[dict]:
    """Fetch and normalize transactions for every account on the linked bridge."""
    days = min(days, SIMPLEFIN_MAX_RANGE_DAYS)
    start = int(time.time()) - days * 86400
    parts = urlsplit(_access_url())
    # Cloudflare, which fronts the SimpleFin bridge, blocks the default
    # urllib User-Agent as bot traffic and returns a bare 403.
    headers = {"Accept": "application/json", "User-Agent": "mindful-money-simplefin/1.0"}
    if parts.username is not None:
        credentials = base64.b64encode(f"{parts.username}:{parts.password or ''}".encode()).decode()
        headers["Authorization"] = f"Basic {credentials}"
    host = parts.hostname + (f":{parts.port}" if parts.port else "")
    base = urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    url = f"{base}/accounts?start-date={start}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise SimpleFinError(f"SimpleFin returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise SimpleFinError(str(exc)) from exc

    accounts = payload.get("accounts") or []
    if not accounts and payload.get("errors"):
        raise SimpleFinError("; ".join(payload["errors"]))

    rows: list[dict] = []
    for account in accounts:
        account_id = str(account.get("id", ""))
        org_name = (account.get("org") or {}).get("name") or "Unknown institution"
        account_label = account.get("name") or account_id
        account_type = _account_type(account_label)
        for txn in account.get("transactions") or []:
            posted = txn.get("posted") or txn.get("transacted_at")
            if posted is None:
                continue
            try:
                amount = -float(txn["amount"])
            except (KeyError, TypeError, ValueError):
                continue
            iso_date = datetime.fromtimestamp(int(posted), tz=timezone.utc).date().isoformat()
            rows.append({
                "id": f"simplefin_{account_id}_{txn.get('id', posted)}",
                "merchant": txn.get("payee") or txn.get("description") or "Unknown",
                "amount": round(amount, 2),
                "date": iso_date,
                "pending": bool(txn.get("pending", False)),
                "account": account_id,
                "bank": org_name,
                "account_label": account_label,
                "account_type": account_type,
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
