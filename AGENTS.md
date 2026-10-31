# MandatePay: instructions for coding agents

Project: Rust/Axum payments-mandate service. A human approves a bounded, cart-bound mandate with a passkey (WebAuthn, P-256); an AI agent carries the mandate but must never be able to forge it.

Layout
- crates/mandate-core: pure verification logic (intent hashing, gates, passkey.rs, registration.rs). No HTTP, no database, no I/O.
- src/: the Axum server (app.rs, store.rs on SQLite, auth.rs, mandates.rs, gateway.rs).
- Base branch for all work: v0.2. Never touch main.

Hard rules
- Only edit the files the task names. Never add dependencies unless the task says so.
- In src/ code: no unwrap, expect, panic!, unsafe, or slice indexing that can panic. Use checked arithmetic and .get().
- Security checks fail closed: any parse error or missing field means reject.
- Never weaken, delete, or edit an existing test to make it pass. If a test fails, fix the code or stop and explain.
- Keep code small and plain; document every public item.
- Never open, merge, or close pull requests, and never push to v0.2 or main. Only push the feature branch the task names.

Done means
Run and show the full output of:
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
If any fails, fix it and run all three again. Then show git diff --stat.
