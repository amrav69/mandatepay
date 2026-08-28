# Contributing

Thanks for your interest in MandatePay. This document describes the exact gate that CI enforces on every push.

## Workflow

All changes must land as small, focused commits that ship the feature *with* the test that proves it.

- Keep each feature or fix in its own commit (or small PR) that includes the tests pinning the new behavior.
- Use conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`, `ci:`.
- Avoid bulk commits that mix formatting, refactors, and features.

## Gate — must pass locally before pushing

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI (`.github/workflows/ci.yml`) runs exactly the same three plus:

```bash
cargo install cargo-tarpaulin --locked
cargo tarpaulin --out Xml --fail-under 0   # will be raised to 60 as coverage grows
cargo audit
# then boots the server and runs the live attack suite + chaos + chain verify
```

If any of the above fails locally, it will fail in CI.

## Running

```bash
cp .env.example .env   # fill MANDATEPAY_API_KEY, RAZORPAY_KEY_ID/SECRET, LLM_API_KEY
cargo run --bin mandatepay        # http://127.0.0.1:8080  (dashboard at /)
cargo run --bin agent             # Nemotron buyer
cargo run --bin eval              # 10-vector attack suite
cargo run --bin chaos             # 10 concurrent checkouts on same mandate
```

`cargo test` is fully offline — no `.env`, no network, no Docker. Tests that need live infrastructure are `#[ignore]`.

## History

We value sustained, incremental history over a single burst. Land real changes over days, and commit under your own identity so the log shows more than one human author.
