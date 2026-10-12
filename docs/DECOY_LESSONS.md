# Lessons: Effective Decoys

What we learned building Mindful Money's deception system, from naive
honeypot to principled decoy architecture.

## Lesson 1: A decoy that creates real risk isn't a decoy

Our first tarpit trusted `X-Forwarded-For` for the rate limit budget. The
thinking: skilled attackers bypass it and invest more time. The reality:
it was an actual vulnerability. An attacker could reset the expensive delay
budget at will, turning our cost controls into suggestions.

**The rule:** If the "weakness" can affect real resource consumption, access
control, or data integrity, it's not deception. It's a bug with a philosophy.

**The fix:** Deception operates on attacker-controlled signals (XFF). Controls
operate on trusted signals (`remote_addr`). The attacker sees a bypass. The
server enforces the real limit. Neither knows about the other.

## Lesson 2: `time.sleep()` is the most expensive line of code

Our first tarpit used `time.sleep(3-12)` to waste attacker time. It worked,
but every second of attacker waiting was a second of our Cloud Run billing.
Worse, 8 concurrent sleepers could saturate a worker.

**The fix:** Simulated async operations. POST to `/backup/export` returns
202 immediately with a job ID. Polling `/backup/status` returns fake progress.
The attacker waits, polls, waits. Each request costs us microseconds. The
psychological effect (investment, anticipation) is identical.

**The rule:** Make the attacker spend *their* time, not your compute.

## Lesson 3: Don't collect what you don't need

Our first fake login forms were tempted to log submitted passwords for
"threat intel." We didn't, and the design now explicitly forbids it.

**Why:**
- Passwords may be reused on real accounts (liability if breached)
- Storing them creates a target where none existed
- The *attempt* is the signal; the *value* adds nothing
- Legal exposure varies by jurisdiction

**The rule:** Log the event, not the payload. `honeypot_credential_attempt`
with path and ASN tells you everything the password wouldn't.

## Lesson 4: Dead ends must be boring, not clever

Effective decoy artifacts look like ordinary mistakes, not puzzles:

**Good:**
- `<!-- TODO: remove debug credentials before prod -->`
- `# Old credentials (disabled 2024-03, kept for reference)`
- `Disallow: /backup/` in robots.txt
- WordPress 5.8.3 (old enough to have CVEs, common enough to be plausible)

**Bad:**
- Overly specific fake secrets (attacker verifies quickly, moves on)
- Puzzles or challenges (signals artificiality)
- Anything that references real infrastructure

**The rule:** The best decoy is one the attacker has seen a hundred times
before. Familiarity breeds confidence. Confidence breeds investment.

## Lesson 5: ASN is the highest-value cheap signal

Adding GeoLite2 ASN lookup cost $0 (bundled database, local file reads) and
transformed our telemetry from "someone hit the honeypot" to "a DigitalOcean
VPS in Frankfurt hit the honeypot three times, then a residential Comcast IP
tried the fake credentials."

**What ASN tells you:**
- Hosting provider → likely attacker infrastructure or scanner
- VPN/proxy ASN → deliberate obfuscation
- Residential ISP → possibly compromised device, different response warranted
- Same ASN across incidents → campaign tracking

**The rule:** If a signal is free and changes your triage decision, add it.

## Lesson 6: Rate limits need a visible and an invisible layer

Attackers expect rate limits. A system with no visible throttling looks
unprotected (suspicious) or broken (uninteresting). Our design:

- **Visible:** Fake attempt counter (5→4→3...) on the login page. Resets on
  XFF change. Attacker feels clever.
- **Invisible:** Real limit on trusted IP (30/min). Attacker never sees it
  until they hit it, and when they do, they get a plain 404.

**The rule:** Give them something to defeat. Make sure defeating it changes
nothing.

## Lesson 7: Measure engagement, not just hits

Counting honeypot hits tells you volume. Measuring engagement tells you
effectiveness:

- **Depth:** robots.txt → .env → wp-login → backup/export (full path = invested)
- **Persistence:** Repeat visits with different XFF (sophisticated actor)
- **Interaction:** Backup job poll count (how long they waited for nothing)
- **Bypass attempts:** Unique XFF values per session (did they find the "trick"?)

A decoy nobody interacts with is just a 404 with extra steps.

## Lesson 8: Separate the decoy from the crown jewels

Our decoy runs in the same Cloud Run service as the real app. For this
project's budget, that's acceptable because:
- Decoy endpoints never touch the database with real credentials
- Decoy responses are static or synthetic
- No production secrets are accessible from decoy code paths

**For higher-stakes deployments**, MITRE Engage recommends a separate service
with isolated service accounts, data stores, and scaling limits. The decoy
shouldn't even have credentials that *could* access production.

**The rule:** The decoy's blast radius should be zero. If compromising the
decoy code gives an attacker anything real, the architecture is wrong.

## Summary

| Do | Don't |
|---|---|
| Deceive on attacker-controlled signals | Trust attacker-controlled signals for controls |
| Simulate slow operations asynchronously | `time.sleep()` in request handlers |
| Log attempts, ASN, and metadata | Log passwords or sensitive payloads |
| Use familiar, boring mistakes | Create clever puzzles |
| Add free signals (ASN) | Skip telemetry to save effort |
| Give them a visible limit to "beat" | Leave real limits visible or absent |
| Measure engagement depth | Count hits and call it done |
| Isolate decoy from production | Share credentials or data stores |
