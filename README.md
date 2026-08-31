# MandatePay

<div align="center">
<img src="./mandate_card.svg" alt="MandatePay verification terminal" width="720"/>
</div>

[![CI](https://github.com/amrav69/mandatepay/actions/workflows/ci.yml/badge.svg)](https://github.com/amrav69/mandatepay/actions/workflows/ci.yml) [![Rust](https://img.shields.io/badge/rust-stable-CE422B?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org) [![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) ![Ed25519](https://img.shields.io/badge/crypto-Ed25519-00D9FF?style=flat) ![SQLite](https://img.shields.io/badge/store-SQLite-003B57?style=flat&logo=sqlite&logoColor=white) ![Razorpay](https://img.shields.io/badge/gateway-Razorpay-02042B?style=flat)

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

```
LLM (Nemotron 3 on integrate.api.nvidia.com)
 │  proposes {item, merchant_id, amount_minor, reasoning}  (JSON only)
 ▼
Agent (src/bin/agent.rs) ── wallet guard: amount ≤ AGENT_BUDGET_MINOR ──▶ POST /v1/mandates
                                                                    │
Authority (mandates.rs) ◀── Ed25519 SigningKey (MANDATEPAY_SEED) ────┘
 │  signs canonical_bytes(mandate) → 64B sig
 ▼
Mandate + signature + amount_minor ──POST /v1/checkout──▶ Policy Engine (policy.rs)
                                                         │  9 gates: version / action / currency / cap>0
                                                         │          merchant allowlist / amount>0 / amount≤cap
                                                         │          sig verifies / not expired / nonce fresh
                                                         ▼
                                                   SQLite (store.rs)
                                                   ├─ nonces (PRIMARY KEY → replay = REJECT)
                                                   └─ decisions (append-only audit trail)
                                                         │
                                          ┌────────────────┴────────────────┐
                                          ▼                                 ▼
                                    Gateway (gateway.rs)              Dashboard (dashboard/index.html)
                                    Mock  ↔  Razorpay test-mode      polls /v1/decisions + /v1/stats every 2s
                                    live:false / live:true            click row → replay payload + reason
```

**Trust boundaries — LLM proposes, determinism disposes:**

| Component | Can do | Cannot do |
|---|---|---|
| **Nemotron** | Output a JSON proposal | Touch keys, sign, or call Razorpay |
| **Agent** | Validate proposal vs wallet, request mandate, submit checkout | Exceed `AGENT_BUDGET_MINOR`, bypass policy |
| **Authority** | Sign mandates with `SigningKey` | Decide if a spend is allowed |
| **Policy Engine** | `ALLOW/REJECT` with reason | Move money |
| **Gateway** | `POST https://api.razorpay.com/v1/orders` with basic auth | Override a `REJECT` |
| **Store** | Enforce nonce uniqueness via `PRIMARY KEY` | Be bypassed — even a valid sig replays as `REJECT` |

**Gateway seam:** `Gateway::from_env()` reads `RAZORPAY_KEY_ID/SECRET`. Present → `Razorpay { basic_auth, live:true, receipt=mandate_id }`, absent → `Mock { live:false }`. Checkout code calls `gateway.create_order()` blind — the swap is one `match` arm in `src/gateway.rs:1`.

**Deterministic seed:** `MANDATEPAY_SEED` (base64 32B) fixes the authority key. Server and `cargo run --bin eval` share it, so the harness can mint *validly signed* hostile mandates — the strongest attack class. No seed → ephemeral key per boot (fine for demos, eval refuses to run).

## Evaluation

Run against a live server (`MANDATEPAY_SEED` shared, `RAZORPAY_KEY_ID` present → live test-mode):

```
======================================================================
 MANDATEPAY ATTACK SUITE — every vector must end in REJECT
======================================================================
 control: API issued a legitimate mandate in 7 ms
 control: legitimate checkout 320 ms -> ALLOW (must be ALLOW)
----------------------------------------------------------------------
 replay setup: first spend 94 ms -> ALLOW (expected ALLOW)
 attack                     vector                                        ms  decision  reason
----------------------------------------------------------------------
 forged_signature           random 64B signature on valid mandate          3  REJECT    signature does not verify against mandate authority
 tampered_mandate_field     cap raised after signing, original sig ke…    11  REJECT    signature does not verify against mandate authority
 over_cap_amount            checkout amount 10x above signed cap           3  REJECT    amount 499000 exceeds mandate cap 49900
 zero_amount                checkout for 0 paise                           2  REJECT    amount_minor must be positive
 replay                     identical checkout resubmitted                11  REJECT    nonce already consumed: possible replay
 expired_mandate            validly signed but expired window             11  REJECT    mandate expired
 non_allowlisted_merchant   validly signed mandate for unknown mercha…     3  REJECT    merchant 'merchant-999' is not allowlisted
 out_of_scope_action        signed action=payout outside governor sco…     2  REJECT    action 'payout' is outside governor scope
 unsupported_version        signed future mandate version                  3  REJECT    unsupported mandate version
 malformed_signature        signature field is not valid base64            2  REJECT    malformed signature encoding
----------------------------------------------------------------------
 attacks rejected: 10/10   mean decision latency: 5 ms
 control legitimate checkout: ALLOWED (320 ms)
 SUITE GREEN
```

Four attacks are *validly signed* hostile mandates — they prove the layers beyond the signature: expiry, allowlist, scope, and version. Mock-only runs show `~13 ms` control latency; live Razorpay adds `~300 ms` network cost — reported honestly, not hidden.

**Agent demo (real Nemotron 3 Super):**

```
[agent] model nvidia/nemotron-3-super-120b-a12b responded in 4232 ms
[agent] proposal: {"item":"wired earphones","merchant_id":"merchant-001","amount_minor":45000,...}
[agent] mandate issued: "mnd_SWaj4aIL54v1"
[agent] decision: ALLOW
[agent] gateway: razorpay-test
[agent] order: order_TV8RBWXVecmj1m
```

Visible in Razorpay Dashboard → Orders (test mode). `gateway: mock` vs `razorpay-test` is surfaced in every `POST /v1/checkout` response and in the dashboard.

## What's real vs simulated

| Real | Simulated | Not claimed |
|---|---|---|
| `mandates.rs` canonical `serde_json::to_vec` + `ed25519-dalek v3` sign/verify; `policy.rs` 9 gates; `store.rs` SQLite `PRIMARY KEY` replay; `agent.rs` live Nemotron via `integrate.api.nvidia.com` (JSON-only, budget guard + fallback); `gateway.rs` `POST https://api.razorpay.com/v1/orders` basic auth when `RAZORPAY_KEY_ID` present; `dashboard/index.html` polling `/v1/decisions` + `/v1/stats`; CI boots a server with `CI_SEED` and must get `SUITE GREEN` | Merchant catalog is synthetic (`merchant-001` allowlist, no real catalog API); orders are test-mode (`rzp_test_`); `gateway: mock` path when no keys — same response shape, `live:false`; budget/goal are env defaults | Production Razorpay deployment, Vortex access, access to Razorpay's internal risk models. This composes *with* platform fraud, not instead of it. |

Honesty is the bar — every number above is from `cargo run --bin eval` on the commit you are reading, not a screenshot from another run.

## License

MIT
