# Testing MandatePay

MandatePay has a comprehensive test suite covering cryptographic verification, policy evaluation, and database consistency.

## Running Tests

To run the full test suite (79 tests as of this commit: 14 unit + 1 agent + 17 checkout + 11 issue + 2 fresh + 2 logging + 15 mandates + 17 store):

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
    - Complete issue and checkout workflows (per-agent keys; master cannot mint/spend)
    - Missing/invalid/wrong-agent API key rejection (401/403)
    - 404 vs 400 correctness (unknown sort/order → 400)
    - Agent CRUD, rotation, search/pagination/sort, velocity rollback, idempotency amount-mismatch
    - Metrics alias (`/v1/metrics` == `/v1/stats`) and logging boot

## Code Coverage

We use `cargo-tarpaulin` to enforce a minimum coverage threshold of 60% on all CI builds.
`tarpaulin.toml` excludes `src/bin/*`, so agent/eval/chaos harnesses are exercised via the
live CI suite (`eval` + `chaos` + chain verify), not via coverage. No tests are `#[ignore]`;
all `cargo test` cases are offline (in-memory SQLite, mock gateway).

```bash
cargo install cargo-tarpaulin --locked
cargo tarpaulin --fail-under 60
```
