# Security Policy

## Supported Versions

This is a personal project. Only the `main` branch is supported.

| Version | Supported |
| ------- | --------- |
| main    | ✅        |
| others  | ❌        |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, email the maintainer directly. Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

**Response time:** Best effort. This is a personal project, not a commercial product with an SLA.

**What to expect:**
- Acknowledgment within 7 days
- Fix or mitigation plan within 30 days for critical issues
- Credit in the commit message (unless you prefer anonymity)

## Scope

**In scope:**
- Authentication bypass (WebAuthn, session management)
- Plaintext financial data exposure via the server
- Tenant isolation failures (one user seeing another's data)
- CSRF, XSS, or injection vulnerabilities
- Dependency vulnerabilities with working exploits

**Out of scope:**
- The ZKP proof gate limitations (documented in `docs/ZKP_BINDING.md`)
- The JavaScript delivery trust issue (documented in `docs/TRUST_BOUNDARIES.md`)
- SimpleFin or bank security (third-party services)
- Social engineering
- Physical access to user devices

## Security Model

See `docs/TRUST_BOUNDARIES.md` for the honest assessment of what this app
protects against and what it does not. Key points:

- The server never sees financial plaintext (client-side encryption)
- WebAuthn passkeys for authentication (no passwords)
- You must trust the JavaScript delivery pipeline
- SimpleFin and your bank can see your data (unavoidable)

## No Bug Bounty

This is a personal project with no bug bounty program. Security reports are
appreciated and will be acknowledged, but there is no monetary reward.
