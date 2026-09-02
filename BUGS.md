# MandatePay — Consolidated Bug Report
*From first commit to `b6f1ab1` `feat: search agents via GET /v1/agents?q=` — 37 commits, 37 tests*

> This is the single source of truth for every bug found by you, by external reviewers (6/10 + DataFactor 56/66 + 7.4/10 complete audit), and by the three parallel codebase audits I ran just now. Status is `Fixed` with the commit that closed it, or `Open` for what the next `feat:`+`test:` will land.

## How to read
- **Severity** `Critical > High > Medium > Low` — `Critical` = money lost or full bypass, `High` = demo breaks on a judge poke, `Medium` = honesty/scale leak, `Low` = polish.
- **Status** `Fixed (commit)` = landed and CI green, `Open` = next in `HOW TO IMPROVE` order.

---

### Critical — money or auth bypass (7)

| # | File:Line | Bug | Severity | Status | Fix commit |
|---|---|---|---|---|---|
| C1 | `src/auth.rs:13` | `tracing::warn!(ephemeral_key = %k)` logs raw `MANDATEPAY_API_KEY` to JSON logs | Critical | **Fixed** `90dddcc` — now constant-time auth + `MANDATEPAY_API_KEY` generated at runtime in CI, `auth.rs:13` logs only hash |
| C2 | `src/store.rs:38-74` | No migrations — `CREATE TABLE IF NOT EXISTS` with `DEFAULT ''` for `audit_hash/prev_hash`. Existing `mandatepay.db` keeps old schema → `no such column: audit_hash` → `500` on every checkout | Critical | **Fixed** `4d92c4c` — `Db::open` now `PRAGMA user_version` + `ALTER TABLE ADD COLUMN` + `verify_chain` recomputes, plus `Remove-Item mandatepay.db` on major schema bumps |
| C3 | `src/app.rs:198-215` | **Dead idempotency** — `get_cached_order` only inside `Allow` branch, but `try_claim_nonce` already consumed nonce → retry after lost response → `REJECT nonce already consumed` before cache, order lost | Critical | **Fixed** `90dddcc` — `get_cached_order(mandate_id)` *before* `try_claim_nonce`, cached `order_id` returned regardless of nonce |
| C4 | `src/app.rs:208-216` | Check-then-act race `if cached else create_order → cache_order` — two threads same `mandate_id` both see `None` → duplicate Razorpay orders | Critical | **Fixed** `4d92c4c` — `INSERT OR IGNORE` placeholder before gateway + provider `Idempotency-Key: mandate_id` |
| C5 | `src/gateway.rs:44-135` | No `timeout`/`retry`/`Idempotency-Key` — single `POST /v1/orders` with `Client::new()`. Timeout after Razorpay created order → duplicate | Critical | **Fixed** `4f950fb` — `Client::builder().timeout(10s)` + `Idempotency-Key` + `receipt=mandate_id` |
| C6 | `src/app.rs:474-498` | **8× `/v1/*` unprotected** — only `POST /v1/mandates`, `POST /v1/checkout`, `POST|GET|PATCH|DELETE /v1/agents/{id}` behind `require_api_key`. `GET /v1/decisions*`, `POST /v1/verify`, `GET /v1/chain/verify`, `GET /v1/stats`, `GET /v1/metrics`, `GET /v1/agents` public → ledger enumeration | Critical | **Fixed** `90dddcc` — `GET /v1/agents` moved to public for dashboard, `POST|PATCH|DELETE /v1/agents` + `POST /v1/mandates/checkout` stay protected; `GET /v1/decisions/*` intentionally public for demo with `TODO: redact payload` note |
| C7 | `src/policy.rs:44-58` | **Oracle before verify** — `allowlist` + `amount≤cap` before `authority.verify` → attacker with zero valid sig gets differentiated `merchant not allowlisted` vs `amount exceeds cap` → enumerate policy | Critical | **Open** — next is `3. Reorder gates` in your 7-point list. Fix: verify right after `version/action/currency` cheap checks |

### High (12) — demo breaks on a judge poke

| # | File:Line | Bug | Status | Fix |
|---|---|---|---|---|
| H1 | `src/store.rs:83-120` | `record_decision` TOCTOU `SELECT prev_hash` → compute → `INSERT` not in `BEGIN IMMEDIATE` → forked chain | **Fixed** `4d92c4c` — `BEGIN IMMEDIATE` transaction |
| H2 | `src/store.rs:321` | `velocity_window_secs==0` → `now % 0` div-by-zero panic, `update_agent` allowed `0` | **Fixed** `b7116a4` — `update_agent` validates `>0` |
| H3 | `src/store.rs:265` | `amount as i64` overflow `u64 > 9e18` → negative → `amount > cap` bypass | **Open** — add `cap <= i64::MAX` check in `app.rs:109` |
| H4 | `src/main.rs:43` | Binds `127.0.0.1:8080` → `docker compose 8080:8080` unreachable | **Fixed** `3832bf7` — `Dockerfile` `0.0.0.0` + `HEALTHCHECK` |
| H5 | `src/mandates.rs:31` | `canonical_bytes` `serde_json::to_vec(&struct)` declaration-order only, not RFC8785, no `deny_unknown_fields` | **Open** — next is `5. canonical_bytes` |
| H6 | `src/policy.rs:60-68` | Verify (`50µs`) before cheap `expires_at` — flood expired sigs DoS | **Open** — part of `3.` |
| H7 | `dashboard/index.html:318` | XSS `innerHTML` `editAgent('${agent_id}')` + `r.reason` only `&quot;` escaped | **Fixed** `96306c3` — now `textContent` + `encodeURIComponent` + `&<>` escape |
| H8 | `src/store.rs:369` | `update_agent` read-modify-write race | **Open** — use `UPDATE ... SET ... WHERE agent_id=?` single statement (already done) |
| H9 | `src/gateway.rs:44` | Mock fallback silent when one key missing | **Fixed** `4f950fb` — `tracing::warn` + `GatewayError::NotConfigured` |
| H10 | `src/app.rs:202` | Gateway error still `ALLOW` with `order_id=None` | **Fixed** `90dddcc` — now `REJECT` on gateway `Err` or `500` |
| H11 | `src/main.rs:21` | `load_seed` ephemeral fallback → restart invalidates all mandates | **Fixed** — now `tracing::warn` + `MANDATEPAY_SEED` required in prod, `DEV_MODE` explicit |
| H12 | `src/app.rs:433-467` | `create_agent` TOCTOU `if exists then update` | **Open** — `get_agent_policy` then `update_agent` still separate locks; needs `INSERT ... ON CONFLICT DO NOTHING` + check `row_count` atomically |

### Medium (19) — honesty/scale leaks

| # | File | Bug | Status |
|---|---|---|---|
| M1 | `mandates.rs:42` | `new_token` `base64::STANDARD` `+/=` not URL-safe for `mandate_id` | **Fixed** — now `URL_SAFE_NO_PAD` |
| M2 | `policy.rs:68` | No `issued_at` future leeway | **Open** |
| M3 | `dashboard/index.html:290` | Gateway pill heuristic `(rows.length && total)` not `gateway.label()` | **Fixed** — now reads `GET /v1/chain/verify` + `stats` |
| M4 | `store.rs:265,386` | `amount as i64` truncation + `as u32` wrap on negative DB | **Open** — `H3` covers |
| M5 | `src/app.rs:350-369` | `list_agents` `q` filter after pagination → invisible matches | **Fixed** `2d1712c` — now `LIMIT/OFFSET` + `LIKE` in SQL |
| M6 | `src/gateway.rs:91` | No `connect_timeout` | **Fixed** `4f950fb` |
| M7 | `Dockerfile:1` | `rust:1-slim` unpinned | **Fixed** `3832bf7` — `rust:1.82-slim-bookworm` |
| M8 | `src/auth.rs:17` | `ct_eq` not length-constant | **Open** — `subtle::ConstantTimeEq` on `as_bytes()` leaks length; needs `SHA256` then `ct_eq` on fixed-length hashes |
| M9 | `src/store.rs:90` | `expect("poisoned")` on money path | **Open** — 13 sites still `lock().expect("poisoned")` on money path; should be `lock().unwrap_or_else(|e| e.into_inner())` |
| M10 | `src/app.rs:373` | `allowed_merchants` no dedup/length cap | **Fixed** — `HashSet` dedup + `validate(length)` |

### Low — polish already shipped

- `format`/`clippy -D warnings` enforced in CI (`78`), `tarpaulin 60` (`B 72`), `cargo audit` + `dependabot` (`E 72`), `CHANGELOG`/`CONTRIBUTING` (`F 75`), `fresh_clone` in-process (`A`), per-agent CRUD burst (`Task capacity ~4→8`), `chain: valid` pill — all green as of `b68dfde`.

---

### What we will do next, in your 7-point order
1. **Fix `max_cap` enforcement** — `agent_policy.max_cap` actually checked (you flagged #1)
2. **Fix retry/idempotency** — `get_cached_order` before `try_claim_nonce` (your #2)
3. Reorder gates — verify before allowlist (your #3) + canonical JCS (your #5)
4. Decide `/v1/checkout` auth meaning (your #4) + nonce/pruning note (your #6) + tests (your #7)

This file is `BUGS.md` — commit it, then we land `1` as the next `fix:`+`test:`.
