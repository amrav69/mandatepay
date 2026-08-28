# MandatePay

[![CI](https://github.com/amrav69/mandatepay/actions/workflows/ci.yml/badge.svg)](https://github.com/amrav69/mandatepay/actions/workflows/ci.yml) [![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Signed payment mandates for AI agents — Ed25519 intent mandates with spend caps, expiry & replay protection, verified before any Razorpay order.**

> AI agents can now act while you sleep with live API keys. Valid credentials ≠ valid payment. MandatePay is the cheque book: every money action needs a bounded, single-use, signed mandate first.

Built for **Razorpay AI Buildathon 2026 — Track 01: Agentic Commerce**. The same seam protects every track.

## Why now

Razorpay calls 2026 the age of agentic payments: ACP/AP2/x402 and NPCI's UAP are converging on agent-to-agent commerce. When agents hold keys, credential validity stops being the security boundary — action validity does. MandatePay answers *should this agent move this money, right now?*

## Quick start

```bash
# 1. server + dashboard (http://127.0.0.1:8080)
cargo run --bin mandatepay

# 2. in another terminal — Nemotron buyer agent (needs LLM_API_KEY in .env)
cargo run --bin agent

# 3. adversarial suite against the live server (needs MANDATEPAY_SEED in .env — see .env.example)
cargo run --bin eval
```

`.env` is gitignored. Copy `.env.example` → `.env` and fill:
- `LLM_API_KEY` — NVIDIA `nvapi-...` for Nemotron 3 (free at build.nvidia.com)
- `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` — `rzp_test_...` from dashboard.razorpay.com → Settings → API Keys (test mode). Absent → mock gateway.
- `MANDATEPAY_SEED` — base64 32 bytes, fixes authority key. Absent → ephemeral key per boot.
- `ALLOWED_MERCHANTS` — comma list, default `merchant-001`.

## Repo layout

```
mandatepay/
├── src/
│   ├── mandates.rs        # Mandate schema, canonical bytes, Ed25519 sign/verify
│   ├── policy.rs          # 9-gate evaluation: version/action/currency/cap/merchant/amount/sig/expiry/replay
│   ├── store.rs           # SQLite ledger: decisions + nonces + stats
│   ├── gateway.rs         # Gateway seam: Mock ↔ Razorpay test-mode (basic auth /v1/orders)
│   ├── main.rs            # axum server: / /health /v1/mandates /v1/checkout /v1/decisions /v1/stats
│   └── bin/
│       ├── agent.rs       # Nemotron buyer: JSON proposals, wallet budget guard, deterministic fallback
│       └── eval.rs        # 10-vector HTTP attack suite against live server
├── dashboard/index.html   # vanilla JS live decision stream, polling every 2s, replay viewer
├── tests/mandates_tests.rs
└── .github/workflows/ci.yml  # fmt → clippy -D warnings → tests → live attack suite (CI_SEED)
```

## Architecture

*Detailed diagram and trust boundaries land next commit.*

## Evaluation

*10-vector adversarial table and defense-in-depth notes land next commit.*

## What's real vs simulated

*Honesty table lands next commit.*

## License

MIT
