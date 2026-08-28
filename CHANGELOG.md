# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-28

### Added
- Signed payment mandates (Ed25519, `mandates.rs`) with spend caps, expiry, replay protection and merchant allowlist
- Policy engine with 9 gates (`policy.rs`): version, action, currency, cap, merchant, amount, signature, expiry, nonce
- SQLite ledger (`store.rs`): `decisions` audit trail, `nonces` replay, `orders` idempotency, `agents` per-agent caps
- Gateway seam (`gateway.rs`): `Mock` ↔ `Razorpay` test-mode (`POST /v1/orders` basic auth), `live` flag
- Axum server (`main.rs`): `POST /v1/mandates`, `POST /v1/checkout`, `GET /v1/decisions`, `GET /v1/stats`, `GET /v1/decisions/{id}`, `POST /v1/verify`, `GET /v1/chain/verify`, health and dashboard
- Constant-time API key auth (`src/auth.rs`, `subtle::ConstantTimeEq`) on write endpoints, `MANDATEPAY_API_KEY` with ephemeral fallback
- Server-side mandate cap (`MANDATEPAY_MAX_CAP`, default `100000`) and per-agent `50/min` velocity
- Tamper-evident hash chain (`SHA256(prev_hash|endpoint|decision|reason|payload|ts)`) per decision
- Nemotron 3 buyer agent (`src/bin/agent.rs`) with wallet budget guard and deterministic fallback
- Attack suite (`src/bin/eval.rs`): 10 vectors, `10/10 REJECT` + control `ALLOW`, mean `~5ms`
- Chaos harness (`src/bin/chaos.rs`): 10 concurrent checkouts on same mandate, at-most-once `1 ALLOW / 9 REJECT`
- Live dashboard (`dashboard/index.html`): liquid glass dark theme, polling `50` rows, replay viewer
- CI (`ci.yml`): `fmt --check`, `clippy -D warnings`, `cargo test`, `cargo tarpaulin` (threshold `0` → `60` planned), `cargo audit`, live attack suite + chaos + chain verify on every push

### Security
- No `unwrap` on money paths, integer `i64` paise only, `X-API-Key` or `Bearer` auth, `orders` idempotency cache

## [Unreleased]
- Per-agent merchant allowlist management API
- Structured JSON logging already via `tracing` + `tracing-subscriber`
