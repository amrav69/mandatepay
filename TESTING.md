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

## Code Coverage

We use `cargo-tarpaulin` to enforce a minimum coverage threshold of 60% on all CI builds.

```bash
cargo install cargo-tarpaulin --locked
cargo tarpaulin --fail-under 60
```
