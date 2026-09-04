"""Stand-in for the bank feed.

Generates a realistic six-month transaction history so the dashboard has
something to chart. Same output shape as aggregator._normalize(), so swapping
the real Plaid adapter back in later touches nothing downstream.

Deliberately NOT categorized here. Categorization happens on the device --
that is the whole point of the architecture, and a demo that categorizes
server-side would quietly contradict the thesis.
"""

from __future__ import annotations

import datetime as dt
import random

SEED = 20260802

# Account metadata is copied into each transaction so the browser seals it
# together with the merchant and amount. The UI has no plaintext bank-name
# lookup table to leak before the vault is unlocked.
ACCOUNTS = {
    "demo_checking": {"bank": "Scammers Inc", "label": "Everyday checking", "type": "Checking"},
    "demo_ira": {"bank": "Wells Foreclosure", "label": "Traditional IRA", "type": "IRA"},
    "demo_401k": {"bank": "DC Unc", "label": "Employer 401(k)", "type": "401(k)"},
}

# (merchant, typical amount, spread, times per week)
RECURRING_WEEKLY = [
    ("Blue Bottle Coffee", 6.25, 1.75, 4),
    ("MTA OMNY", 2.90, 0.00, 6),
    ("Trader Joe's", 78.00, 26.00, 1),
    ("Sweetgreen", 15.40, 3.20, 2),
]

OCCASIONAL = [
    ("Amazon", 42.00, 35.00, 0.9),
    ("Duane Reade", 21.50, 12.00, 0.5),
    ("Uber", 18.75, 9.00, 0.8),
    ("Whole Foods Market", 63.00, 24.00, 0.6),
    ("Lucali", 88.00, 22.00, 0.2),
    ("Rough Trade Records", 34.00, 15.00, 0.25),
    ("Citi Bike", 4.95, 0.00, 0.4),
    ("Paragon Sports", 96.00, 48.00, 0.15),
]

MONTHLY_FIXED = [
    ("Stuyvesant Town Rent", 2150.00, 1),
    ("Family Recreation Center", 89.99, 1),
    ("Con Edison", 104.00, 8),
    ("Verizon Fios", 79.99, 12),
    ("Spotify", 11.99, 4),
    ("Netflix", 15.49, 17),
    ("Equinox", 215.00, 2),
    ("State Farm Auto", 128.40, 22),
]

PAYCHECK = ("Meridian Systems Payroll", 2415.00)
IRA_CONTRIBUTION = ("IRA Contribution", 500.00)
K401_EMPLOYEE = ("401(k) Employee Deferral", 375.00)
K401_MATCH = ("401(k) Employer Match", 187.50)

# Irregular larger expenses -- the things that actually make a month tight.
IRREGULAR = [
    ("Delta Air Lines", 428.00, 140.00),
    ("Weill Cornell Physicians", 215.00, 95.00),
    ("Apple Store", 329.00, 180.00),
    ("Con Edison True-Up", 186.00, 40.00),
    ("Enterprise Rent-A-Car", 264.00, 70.00),
    ("Warby Parker", 195.00, 0.00),
]


def generate(months: int = 6) -> list[dict]:
    rng = random.Random(SEED)
    today = dt.date.today()
    # Anchor to the first of the month, else the earliest month is missing
    # its rent charge and the chart opens on a misleading spike.
    y, m = today.year, today.month - months
    while m <= 0:
        m += 12
        y -= 1
    start = dt.date(y, m, 1)
    rows: list[dict] = []
    account_counts = {account: 0 for account in ACCOUNTS}

    def add(date: dt.date, merchant: str, amount: float, account: str = "demo_checking") -> None:
        if date > today:
            return
        sequence = account_counts.setdefault(account, 0)
        # Keep the legacy checking IDs stable when adding a new recurring
        # charge. The monthly charge gets its own deterministic ID, so a
        # refresh updates old rows instead of duplicating the feed.
        if account == "demo_checking" and merchant == "Family Recreation Center":
            external_id = f"demo_family_recreation_center_{date:%Y%m}"
        else:
            external_id = f"demo_{sequence:05d}" if account == "demo_checking" else f"{account}_{sequence:05d}"
        meta = ACCOUNTS[account]
        rows.append(
            {
                "id": external_id,
                "merchant": merchant,
                "amount": round(amount, 2),
                "date": date.isoformat(),
                "pending": False,
                "account": account,
                "bank": meta["bank"],
                "account_label": meta["label"],
                "account_type": meta["type"],
                "source": "fakebank",
            }
        )
        if not (account == "demo_checking" and merchant == "Family Recreation Center"):
            account_counts[account] = sequence + 1

    day = start
    while day <= today:
        # Paycheck every other Friday.
        if day.weekday() == 4 and (day - start).days // 7 % 2 == 0:
            add(day, PAYCHECK[0], -round(PAYCHECK[1] * rng.uniform(0.98, 1.02), 2))

            # Retirement contributions are separate encrypted account feeds,
            # not checking-account expenses. They are deposits into the
            # employer plan and include a matching contribution.
            add(day, K401_EMPLOYEE[0], -K401_EMPLOYEE[1], account="demo_401k")
            add(day, K401_MATCH[0], -K401_MATCH[1], account="demo_401k")

        # One monthly contribution to the individual retirement account.
        if day.day == 15:
            add(day, IRA_CONTRIBUTION[0], -IRA_CONTRIBUTION[1], account="demo_ira")

        # Fixed monthly bills.
        for merchant, amount, dom in MONTHLY_FIXED:
            if day.day == dom:
                jitter = 1.0 if merchant.startswith(("Spotify", "Netflix", "Family Recreation Center")) else rng.uniform(0.9, 1.15)
                add(day, merchant, amount * jitter)

        # Weekly habits, weighted toward weekdays for coffee and transit.
        for merchant, amount, spread, per_week in RECURRING_WEEKLY:
            if rng.random() < per_week / 7:
                if merchant in ("Blue Bottle Coffee", "MTA OMNY") and day.weekday() >= 5:
                    continue
                add(day, merchant, max(1.0, rng.gauss(amount, spread)))

        # Occasional discretionary spending, heavier on weekends.
        weekend_boost = 1.6 if day.weekday() >= 5 else 1.0
        for merchant, amount, spread, per_week in OCCASIONAL:
            if rng.random() < (per_week * weekend_boost) / 7:
                add(day, merchant, max(1.0, rng.gauss(amount, spread)))

        # Irregular one-offs, roughly twice a month across the whole list.
        if rng.random() < 2.0 / 30:
            merchant, amount, spread = rng.choice(IRREGULAR)
            add(day, merchant, max(20.0, rng.gauss(amount, spread)))

        day += dt.timedelta(days=1)

    rows.sort(key=lambda r: r["date"])
    return rows


if __name__ == "__main__":
    txns = generate()
    spend = sum(t["amount"] for t in txns if t["amount"] > 0)
    income = -sum(t["amount"] for t in txns if t["amount"] < 0)
    print(f"{len(txns)} transactions, {txns[0]['date']} to {txns[-1]['date']}")
    print(f"income  ${income:,.2f}")
    print(f"spend   ${spend:,.2f}")
    print(f"net     ${income - spend:,.2f}")
