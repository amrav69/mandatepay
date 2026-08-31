# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in MandatePay, please report it responsibly:

1. **Email**: Open a [GitHub Security Advisory](https://github.com/amrav69/mandatepay/security/advisories/new) (private disclosure).
2. **Include**:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fix (optional)

You will receive an acknowledgment within **48 hours** and a resolution timeline within **7 days** for critical issues.

## Security Design

MandatePay is designed with the following security properties:

- **Ed25519 signatures** — every mandate is cryptographically signed by the authority; forged or tampered mandates are rejected
- **Nonce replay protection** — each mandate nonce is stored in SQLite with a `PRIMARY KEY` constraint; replayed mandates are always rejected
- **Constant-time API key comparison** — uses `subtle::ConstantTimeEq` to prevent timing attacks
- **Tamper-evident audit chain** — every decision is chained via `SHA256(prev_hash | fields | ts)`; chain integrity is verifiable at `/v1/chain/verify`
- **Spend caps** — mandates carry a signed `max_amount_minor`; checkout amounts exceeding this are rejected regardless of API input
- **Merchant allowlist** — per-agent allowlists enforce that mandates can only be used with pre-approved merchants
- **TTL expiry** — mandates expire at a signed `expires_at` timestamp; expired mandates are rejected

## Scope

The following are **in scope** for security reports:
- Signature bypass or forgery
- Replay attack bypasses
- Authorization/authentication bypasses on protected endpoints
- SQL injection via any input field
- Timing side-channels in key comparison

The following are **out of scope**:
- Razorpay platform vulnerabilities (report to Razorpay directly)
- Denial of service via resource exhaustion (SQLite single-file limitations are a known, documented constraint)
- Social engineering
