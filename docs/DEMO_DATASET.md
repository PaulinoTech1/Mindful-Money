# Demo dataset: the Carter household

"Connect demo bank" generates 12 months of transactions in the browser
(`generateDemoTransactions` in `static/simplefin-client.js`). The data is a
fictional household built for walkthroughs with a financial advisor. Every
row is encrypted in the browser like real data.

## Persona

Ethan (38, mechanical engineer at "Atlas Engineering") and Priya (36,
physical therapist at Novant Health) Carter live near Charlotte, NC with
Leo (4, in daycare) and Maya (8, weekly Kumon tutoring, YMCA camp in
summer). They own a home with a mortgage, have one car loan, pay their
credit card in full every month, and save on autopilot.

| Account | Institution (fictional) | What flows through it |
|---|---|---|
| Joint checking | Northbridge Bank | Both paychecks (alternating Fridays), mortgage, childcare, utilities, insurance, giving, transfers, card payment |
| Rewards Visa | Northbridge Bank | Groceries, dining, shopping, fuel, subscriptions, travel |
| Emergency fund | Northbridge Bank | $400 per month from checking |
| Ethan's 401(k) | Keystone Retirement | 6% deferral plus 3% employer match per paycheck (payroll, not via checking) |
| Priya's Roth IRA | Keystone Investments | $500 per month from checking |
| Joint brokerage | Keystone Investments | $300 per month from checking |

A $150 monthly NC 529 contribution leaves checking as a transfer.

## Calendar events

Costco membership (Jan), car repair at Firestone (Feb, $1,238.60), Ethan's
annual bonus (Mar, $4,800 net), federal tax refund (Apr, $2,340), YMCA
summer camp (Jun to Aug, Kumon pauses), beach vacation (Jul: Delta and
Marriott), back to school (Aug), holiday shopping and a year-end gift to
Habitat for Humanity (Nov, Dec). Utilities are seasonal (summer electric,
winter gas).

## Built-in talking points

- **Dining creep:** dining rises about 40% from the first quarter to the
  last (anchored to fixed dates, so refreshes do not rewrite history).
- **Unused subscription:** Peloton App, $44.00 every month, with no other
  fitness spending.
- **Idle cash:** about $2,200 per month accumulates in checking beyond the
  automated transfers.
- **Over-withholding:** a $2,340 tax refund.
- **Windfall:** the March bonus has no matching transfer out.
- **Healthy base:** card paid in full, automated saving of about 15% of
  pay, 401(k) match captured.

## Conventions

- Transfers between the household's own accounts (and 401(k) payroll
  contributions) carry `is_transfer: true`: they are excluded from income
  and spending totals but counted on the account cards.
- Childcare, tutoring and giving use the existing `Other` category with a
  tag (`childcare`, `education`, `giving`), because the category list is
  fixed by the manual-expense ZK circuit.
- Deterministic: each calendar day draws from its own seeded MT19937 stream
  (`DEMO_SEED` plus the day number), and ids are built from account, date
  and merchant, so a given date always yields the same rows and a refresh
  never duplicates them. Tested in `tests/demo_dataset.test.mjs`.
