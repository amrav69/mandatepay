# Testing MandatePay

MandatePay has a comprehensive test suite covering cryptographic verification, policy evaluation, and database consistency. 

## Running Tests

To run the full test suite (40+ tests):

```bash
cargo test
```

## Test Coverage

Our tests cover the following vectors:

1. **Cryptography & Signatures**
   - Exact signature matching and rejection of mismatches
   - Rejection of tampered amounts
   - Rejection of foreign authority signatures

2. **Policy Engine (`policy.rs`)**
   - Spend caps enforced correctly
   - Merchant allowlist enforced (rejection of non-allowlisted merchants)
   - TTL expiry checks
   - Zero amount rejection

3. **Database & Persistence (`store.rs`)**
   - Replay protection (nonce uniqueness per agent)
   - Hash chain integrity verification after writes
   - Agent CRUD operations and velocity limits
   - Order caching and idempotent replay responses

4. **Integration (`app.rs` via `axum`)**
    - Complete issue and checkout workflows
    - Missing/invalid API key rejection
    - 404 vs 400 correctness
    - Metrics and logging

5. **Adversarial inputs (`adversarial_tests.rs`)**
    - Oversized body → 413 (axum `Json` 2 MiB default, pinned by test)
    - Wrong content-type → 415; truncated/empty JSON → 4xx
    - Non-numeric decision id → 400; `limit` clamped to 200

## Endpoint review (B6)

| Endpoint | Auth | DB writes | Replay | Truncated | Concurrent | Oversized | Wrong type |
|---|---|---|---|---|---|---|---|
| `POST /v1/mandates` | key | 1 ISSUED decision | N/A (mints fresh ids) | 4xx | independent, chain serializes | 413 | 415 |
| `POST /v1/checkout` | key | nonce, velocity, maybe order, 1 decision | cached ALLOW / replay REJECT | 4xx | C4+nonce atomic (B2) | 413 | 415 |
| `POST /v1/agents`, `PATCH/DELETE/GET /v1/agents/{id}` | key | agent row / velocity rows | create dup → 400 (atomic) | 4xx | atomic create/update | 413 | 415 |
| `GET /v1/decisions*`, `/v1/verify`, `/v1/chain/verify`, `/v1/stats`, `/v1/metrics`, `GET /v1/agents` | key unless `MANDATEPAY_PUBLIC_READS=1` | none | N/A (reads) | N/A | read-only | 413 (verify body) | 415 (verify) |
| `GET /health`, `GET /` | none | none | N/A | N/A | static | N/A | N/A |

## Code Coverage

We use `cargo-tarpaulin` to enforce a minimum coverage threshold of 60% on all CI builds.

```bash
cargo install cargo-tarpaulin --locked
cargo tarpaulin --fail-under 60
```
