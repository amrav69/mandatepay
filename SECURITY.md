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

- **Per-agent API keys + Ed25519 mandates (two-factor)** — `MANDATEPAY_API_KEY` is the master/admin key for `/v1/agents*` management only. Each agent holds its own per-agent key (32B base64, SHA256-hashed at rest in `agents.api_key_hash`). `POST /v1/mandates` and `POST /v1/checkout` require the per-agent key matching the body `agent_id` (401 missing/unknown, 403 mismatch); the master key does not authorize them. Rotate via `POST /v1/agents/{id}/rotate`.
- **Ed25519 signatures** — every mandate is cryptographically signed by the authority; forged or tampered mandates are rejected
- **Nonce replay protection** — each mandate nonce is stored in SQLite with a `PRIMARY KEY` constraint; first spend creates exactly one order (atomic `PENDING` reservation); an identical resubmission returns the cached order without double-spend
- **Constant-time API key comparison** — uses `subtle::ConstantTimeEq` to prevent timing attacks (master comparison hashes both sides first; per-agent verification compares hex digests in constant time)
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
