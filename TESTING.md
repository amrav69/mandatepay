# Testing MandatePay

MandatePay has a comprehensive test suite covering cryptographic verification, policy evaluation, and database consistency.

## Running Tests

To run the full test suite (125 tests: 22 lib + 1 agent + 4 adversarial + 3 cancel-safety + 3 concurrency + 17 checkout + 11 issue + 3 failure-injection + 2 fresh + 2 logging + 16 mandates + 8 property + 6 stale-reclaim + 27 store):

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
    - Cancel-safety: winner-path decision recorded inside the spawned gateway
      task (disconnect still leaves exactly one audit row, deterministic `TestGate`)
    - Stale-pending reclaim: fresh blocks duplicates; stale + gateway-hit adopts
      (1 create); stale + miss reclaims via CAS (1 create); lookup error stays
      pending with 503 and 0 creates; concurrent retries single-winner;
      different-mandate same-nonce stays replay
    - Failure injection (`Failing` gateway): error/timeout/malformed leave no
      trace and stay retryable; panic maps to generic 500 with rollback

## Code Coverage

We use `cargo-tarpaulin` to enforce a minimum coverage threshold of 60% on all CI builds.
`tarpaulin.toml` excludes `src/bin/*`, so agent/eval/chaos harnesses are exercised via the
live CI suite (`eval` + `chaos` + chain verify), not via coverage. No tests are `#[ignore]`;
all `cargo test` cases are offline (in-memory SQLite, mock gateway).

```bash
cargo install cargo-tarpaulin --locked
cargo tarpaulin --fail-under 60
```
