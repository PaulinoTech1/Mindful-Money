# Vault — working prototype

A privacy-first finance tracker where the server stores your transactions and
cannot read them. Fake bank data, real cryptography, charts computed entirely
in your browser.

```bash
pip install -r requirements.txt
python3 app.py
# open http://127.0.0.1:5000
```

Set any passphrase, click **Connect demo bank**. Six months of transactions get
generated across a checking account, an IRA and a 401(k), encrypted in your
browser, and stored as ciphertext. The demo banks are Scammers Inc, Wells
Foreclose and DC Unc. The checking feed includes a fixed $423.23 monthly
Fans Only subscription charge.

No network access required. Chart.js and libsodium are vendored in
`static/vendor/` rather than loaded from a CDN — a tool that promises the
server can't read your data shouldn't hand a third party the ability to swap
out its own crypto library.

## Tests

```bash
pip install -r requirements.txt
python3 test_demo.py        # 29 tests, ~15s, no browser needed
```

Covers the fake bank feed, the crypto, the API contract, and the privacy
guarantee. `BrowserSim` in that file reproduces `static/app.js` exactly — the
same passphrase and salts produce a byte-identical seed and public key in
PyNaCl and in browser libsodium, and one test pins that public key as a
regression vector. If Python and the browser ever diverge, that test fails
first and loudly.

```bash
pip install playwright && python3 -m playwright install chromium
python3 test_browser.py             # 37 checks against the real UI
python3 test_browser.py --headed    # watch it drive the browser
```

Exercises the actual JavaScript: real Argon2id in WASM, real Chart.js
rendering, the server-view toggle, reload persistence, and mobile layout. It
samples canvas pixels to confirm charts actually drew rather than just
existing, and asserts that no merchant name appears anywhere in the server
view's DOM. Screenshots land in `screenshots/`.

Two bugs these caught, both fixed:

- The hero figure showed the current month, which on the 2nd has rent but no
  paycheck — the largest number on the page read as a $2,773 loss.
- The four-column ledger overflowed at 390px. Category is hidden on phones now.

One test was written, failed, and then deleted rather than patched: a
file-wide scan for readable English words. Hex ciphertext abuts SQLite's
binary headers, so stray bytes manufacture pseudo-words — it flagged
`bfaeddvf`, and once `came` by chance. Tightening it enough to reject those
would also reject `coffee`, which has only one letter outside a–f. It was
replaced by a column-level check that every stored value is pure hex, which
is precise and cannot flake. A test you learn to ignore is worse than no test.

## The demo, in ninety seconds

1. Unlock with any passphrase. Key derivation takes ~350ms in the browser;
   that pause is Argon2id doing its job.
2. Connect the demo bank. Watch the label: *fetching*, then **encrypting in
   your browser**, then stored.
   If the vault already has the older demo feed, use **Refresh demo accounts**
   after unlocking to add the IRA and 401(k) records without duplicating
   checking transactions.
3. Look at the dashboard — spending by category, monthly flow, running
   balance, top merchants. All computed on-device from decrypted data.
4. Click **See what the server sees.** Same page, same data, rendered from the
   actual database table: blind indexes, hex blobs, blob-size histogram.
5. Ask **Ask your vault** for a summary, monthly totals, category breakdown,
   merchant totals or net cash flow. The assistant is deterministic browser
   code over the decrypted in-memory transactions; it makes no chat request,
   calls no model or API, and sends no plaintext to the server.
6. Close it in a terminal:

```bash
grep -c "Blue Bottle" demo.db     # 0
strings demo.db | grep -v '^[0-9a-f]*$' | head
```

Verified: all 26 merchant names absent from the database file. The only
readable strings are the schema.

## Why the encryption happens in the browser

Earlier drafts sealed records server-side, which is Proton's model and is
strong — but it means plaintext passes through a worker on every sync, and you
can't honestly say "encrypted client-side."

This uses a relay instead. `POST /api/relay` fetches from the bank and returns
plaintext **in the HTTP response**, writing nothing. The browser encrypts and
uploads ciphertext. Plaintext exists only inside one request the user
personally triggered — never in a database, a queue, or a background worker.

The cost: sync happens when the app is open, not at 3am. For a finance tracker
that's an acceptable trade, and it makes the core claim literally true.

`app.py` imports no crypto library at all. It has no keys and needs none.

## What the server genuinely knows

Visible in the server view, because pretending otherwise would be dishonest:

- how many records exist
- when each was written (coarsened to the day)
- ciphertext length, which hints at merchant-name length

That last one is a real leak. Padding blobs to fixed 256-byte buckets closes
it and is about ten lines in the client. Left open deliberately so the server
view has something true to show.

It cannot recover any merchant, amount, date or category.

## Measured

| Operation | Time |
|---|---|
| Argon2id key derivation | ~350 ms |
| Encrypt 469 transactions | ~240 ms |
| Decrypt 469 transactions | ~90 ms |

Ten years of heavy usage is roughly 20 MB, so downloading the whole corpus and
computing every aggregate locally stays comfortable. No server-side query
capability is needed, which is fortunate — you couldn't build one without
weakening the encryption.

## Files

| File | Role |
|---|---|
| `static/app.js` | Key derivation, sealing, categorization, all chart math |
| `app.py` | Blob store and relay. No crypto, no keys |
| `fakebank.py` | Stand-in for the bank feed. Swap in the Plaid adapter here |
| `static/style.css` | Ledger aesthetic — Georgia's old-style figures, no webfonts |

## Demo shortcuts to remove

1. **Fixed salts** in `app.js` (`DEMO_SALT_ENC`, `DEMO_SALT_IDX`) so a reload
   re-derives the same key without a signup flow. Real builds generate random
   salts per user and store them next to the public key.
2. **No authentication.** Any browser hitting this server gets every record.
   They're unreadable without the passphrase, but record counts and timing
   leak. Add sessions.
3. **No recovery.** Forget the passphrase, lose the data. That's the honest
   consequence of the design; a real build adds a 24-word recovery phrase
   wrapping a second copy of the private key.
4. **Aggregator tokens** aren't wrapped here because there aren't any. When
   `fakebank` becomes Plaid, seal the access token under a KMS key.
5. **Flask dev server.** Obviously.

## Next

Swap `fakebank.generate()` for the Plaid adapter from the earlier pipeline
work. Nothing downstream changes — the shapes already match.
