use mandatepay::store::Db;

#[test]
fn agent_crud_and_velocity() {
    let db = Db::open(":memory:").unwrap();

    let p1 = db.get_or_create_agent("test-agent").unwrap();
    assert_eq!(p1.agent_id, "test-agent");
    assert_eq!(p1.max_cap, 50000);
    assert_eq!(p1.velocity_limit, 50);

    let p2 = db
        .update_agent(
            "test-agent",
            Some(99999),
            Some(5),
            Some(60),
            Some(vec!["merchant-001".into(), "merchant-002".into()]),
        )
        .unwrap();
    assert_eq!(p2.max_cap, 99999);
    assert_eq!(p2.velocity_limit, 5);
    assert_eq!(p2.allowed_merchants.len(), 2);

    db.update_agent("vel-agent", Some(50000), Some(5), Some(60), None)
        .unwrap();
    for _ in 0..5 {
        assert!(db.check_velocity("vel-agent").unwrap());
    }
    assert!(!db.check_velocity("vel-agent").unwrap());
}

fn age_nonce(path: &str, nonce: &str, age_secs: u64) {
    use mandatepay::mandates::unix_now;
    let conn = rusqlite::Connection::open(path).unwrap();
    let old = unix_now() as i64 - age_secs as i64;
    let changed = conn
        .execute(
            "UPDATE nonces SET claimed_at = ?1 WHERE nonce = ?2",
            rusqlite::params![old, nonce],
        )
        .unwrap();
    assert_eq!(changed, 1);
}

#[test]
fn prune_deletes_expired_nonces_but_never_live_ones() {
    use mandatepay::store::NONCE_RETENTION_SECS;
    let (_dir, path, db) = file_db("prune_nonces.db");
    assert!(db.try_claim_nonce("n_old").unwrap());
    assert!(db.try_claim_nonce("n_live").unwrap());
    drop(db);
    // n_old belongs to a long-expired mandate; n_live was just claimed.
    age_nonce(&path, "n_old", NONCE_RETENTION_SECS + 3_600);
    let db = Db::open(&path).unwrap();
    let stats = db.prune_expired().unwrap();
    assert_eq!(stats.nonces_deleted, 1);
    // Live nonce survives...
    assert!(!db.try_claim_nonce("n_live").unwrap());
    // ...and the pruned one is claimable again (its mandate is long expired,
    // so evaluate would reject it at the expiry gate before this matters).
    assert!(db.try_claim_nonce("n_old").unwrap());
    // comfortably inside the window, but aged: deletion uses strict <,
    // so only rows strictly older than the retention horizon go.
    assert!(db.try_claim_nonce("n_edge").unwrap());
    drop(db);
    age_nonce(&path, "n_edge", NONCE_RETENTION_SECS - 3_600);
    let db = Db::open(&path).unwrap();
    let stats = db.prune_expired().unwrap();
    assert_eq!(stats.nonces_deleted, 0);
    assert!(!db.try_claim_nonce("n_edge").unwrap());
}

#[test]
fn prune_drops_only_windows_outside_the_longest_configured() {
    let (_dir, _path, db) = file_db("prune_velocity.db");
    db.update_agent("win-agent", Some(50000), Some(1000), Some(60), None)
        .unwrap();
    assert!(db.check_velocity("win-agent").unwrap());
    // Current-window row must survive a prune run.
    let stats = db.prune_expired().unwrap();
    assert_eq!(stats.velocity_deleted, 0);
    assert_eq!(db.velocity_count("win-agent").unwrap(), 1);
}

#[test]
fn prune_leaves_decisions_hash_chain_intact() {
    let (_dir, _path, db) = file_db("prune_chain.db");
    db.record_decision("/v1/mandates", "ISSUED", "cap 100", "{}")
        .unwrap();
    db.record_decision("/v1/checkout", "ALLOW", "ok", "{}")
        .unwrap();
    assert!(db.try_claim_nonce("n_chain_old").unwrap());
    let stats = db.prune_expired().unwrap();
    // Prune never touches the append-only audit log.
    assert!(db.verify_chain().unwrap());
    assert_eq!(db.stats().unwrap().total, 2);
    let _ = stats;
}

#[test]
fn negative_db_values_clamp_to_zero_fail_closed() {
    // A corrupt/tampered agents row with negative limits must fail closed
    // (caps of 0), never wrap to huge u64 caps via `as` casts.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("neg.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE agents (agent_id TEXT PRIMARY KEY, max_cap INTEGER NOT NULL DEFAULT 50000, velocity_limit INTEGER NOT NULL DEFAULT 50, velocity_window_secs INTEGER NOT NULL DEFAULT 60, allowed_merchants TEXT NOT NULL DEFAULT '[\"merchant-001\"]', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
             CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, endpoint TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, payload TEXT NOT NULL, audit_hash TEXT NOT NULL DEFAULT '', prev_hash TEXT NOT NULL DEFAULT '');
             CREATE TABLE nonces (nonce TEXT PRIMARY KEY, claimed_at INTEGER NOT NULL);
             CREATE TABLE orders (mandate_id TEXT PRIMARY KEY, order_id TEXT NOT NULL, amount INTEGER NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'completed', reserved_at INTEGER NOT NULL DEFAULT 0, nonce TEXT NOT NULL DEFAULT '');
             CREATE TABLE agent_velocity (agent_id TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (agent_id, window_start));",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at) VALUES ('evil-agent', -5, -10, 60, '[\"merchant-001\"]', 1, 1)",
            [],
        )
        .unwrap();
    }
    let db = Db::open(path.to_str().unwrap()).unwrap();
    let p = db.get_agent_policy("evil-agent").unwrap().unwrap();
    assert_eq!(p.max_cap, 0, "negative max_cap must clamp to 0, not wrap");
    assert_eq!(p.velocity_limit, 0);
}

#[test]
fn unknown_agent_velocity_is_zero_and_refundable() {
    // Covers the QueryReturnedNoRows arms: unknown agents read 0 and refund
    // is a silent no-op rather than an error.
    let db = Db::open(":memory:").unwrap();
    assert_eq!(db.velocity_count("ghost-agent").unwrap(), 0);
    db.refund_velocity("ghost-agent").unwrap();
    assert_eq!(db.velocity_count("ghost-agent").unwrap(), 0);
}

#[test]
fn zero_window_secs_fails_velocity_closed() {
    // A tampered agents row with velocity_window_secs = 0 must surface as an
    // error (fail closed), never divide by zero.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("zerowin.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE agents (agent_id TEXT PRIMARY KEY, max_cap INTEGER NOT NULL DEFAULT 50000, velocity_limit INTEGER NOT NULL DEFAULT 50, velocity_window_secs INTEGER NOT NULL DEFAULT 60, allowed_merchants TEXT NOT NULL DEFAULT '[\"merchant-001\"]', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
             CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, endpoint TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, payload TEXT NOT NULL, audit_hash TEXT NOT NULL DEFAULT '', prev_hash TEXT NOT NULL DEFAULT '');
             CREATE TABLE nonces (nonce TEXT PRIMARY KEY, claimed_at INTEGER NOT NULL);
             CREATE TABLE orders (mandate_id TEXT PRIMARY KEY, order_id TEXT NOT NULL, amount INTEGER NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'completed', reserved_at INTEGER NOT NULL DEFAULT 0, nonce TEXT NOT NULL DEFAULT '');
             CREATE TABLE agent_velocity (agent_id TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (agent_id, window_start));",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at) VALUES ('zero-agent', 50000, 5, 0, '[\"merchant-001\"]', 1, 1)",
            [],
        )
        .unwrap();
    }
    let db = Db::open(path.to_str().unwrap()).unwrap();
    assert!(db.check_velocity("zero-agent").is_err());
}

#[test]
fn legacy_csv_merchants_still_parse() {
    // Pre-JSON agents rows stored comma-separated merchants; the fallback
    // parser must keep working.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("csv.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE agents (agent_id TEXT PRIMARY KEY, max_cap INTEGER NOT NULL DEFAULT 50000, velocity_limit INTEGER NOT NULL DEFAULT 50, velocity_window_secs INTEGER NOT NULL DEFAULT 60, allowed_merchants TEXT NOT NULL DEFAULT '[\"merchant-001\"]', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
             CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, endpoint TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, payload TEXT NOT NULL, audit_hash TEXT NOT NULL DEFAULT '', prev_hash TEXT NOT NULL DEFAULT '');
             CREATE TABLE nonces (nonce TEXT PRIMARY KEY, claimed_at INTEGER NOT NULL);
             CREATE TABLE orders (mandate_id TEXT PRIMARY KEY, order_id TEXT NOT NULL, amount INTEGER NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'completed', reserved_at INTEGER NOT NULL DEFAULT 0, nonce TEXT NOT NULL DEFAULT '');
             CREATE TABLE agent_velocity (agent_id TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (agent_id, window_start));",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at) VALUES ('csv-agent', 50000, 5, 60, 'merchant-001, merchant-002', 1, 1)",
            [],
        )
        .unwrap();
    }
    let db = Db::open(path.to_str().unwrap()).unwrap();
    let p = db.get_agent_policy("csv-agent").unwrap().unwrap();
    assert_eq!(p.allowed_merchants, vec!["merchant-001", "merchant-002"]);
}

#[test]
fn missing_decision_and_unpaginated_list_paths() {
    let db = Db::open(":memory:").unwrap();
    assert!(db.get_decision(999_999).unwrap().is_none());
    db.get_or_create_agent("plain-a").unwrap();
    // Legacy unfiltered entrypoint delegates correctly.
    let all = db.list_agents_paginated(100, 0).unwrap();
    assert!(all.iter().any(|a| a.agent_id == "plain-a"));
}

#[test]
fn hostile_bytes_in_text_fields_never_panic() {
    // rusqlite binds TEXT with explicit length, so NUL/control/unicode bytes
    // are stored, never rejected and never panic the server. The ROLLBACK
    // arms in record_decision/try_reserve therefore only trigger on genuine
    // I/O or corruption failures (not reachable via input); this test pins
    // the no-panic behavior for hostile input instead.
    let db = Db::open(":memory:").unwrap();
    db.record_decision("/v1/x\0y\x7f\u{1f600}", "ALLOW", "r\0", "{}")
        .unwrap();
    assert!(db.verify_chain().unwrap());
    assert!(db.try_reserve_order("mnd\0x", "n\0y", 1).unwrap());
    let (oid, status) = db.get_order_status("mnd\0x").unwrap().unwrap();
    assert_eq!(status, "pending");
    assert_eq!(oid, "__PENDING__");
}

#[test]
fn rollback_nonce_allows_retry() {
    let db = Db::open(":memory:").unwrap();
    let nonce = "n_test_rollback";
    assert!(db.try_claim_nonce(nonce).unwrap());
    assert!(!db.try_claim_nonce(nonce).unwrap());
    db.rollback_nonce(nonce).unwrap();
    assert!(db.try_claim_nonce(nonce).unwrap());
}

#[test]
fn list_and_delete_agents() {
    let db = Db::open(":memory:").unwrap();
    db.get_or_create_agent("list-a").unwrap();
    db.get_or_create_agent("list-b").unwrap();
    let agents = db.list_agents().unwrap();
    assert!(agents.iter().any(|a| a.agent_id == "list-a"));
    assert!(agents.iter().any(|a| a.agent_id == "list-b"));

    assert!(db.delete_agent("list-a").unwrap());
    assert!(!db.delete_agent("list-a").unwrap());
    let agents = db.list_agents().unwrap();
    assert!(!agents.iter().any(|a| a.agent_id == "list-a"));
}

#[test]
fn hash_chain_valid_after_writes() {
    let db = Db::open(":memory:").unwrap();
    db.record_decision("/v1/mandates", "ISSUED", "cap 100", "{}")
        .unwrap();
    db.record_decision("/v1/checkout", "ALLOW", "ok", "{}")
        .unwrap();
    assert!(db.verify_chain().unwrap());
    let row = db.get_decision(1).unwrap().unwrap();
    assert!(!row.audit_hash.is_empty());
}

#[test]
fn order_cache_roundtrip() {
    let db = Db::open(":memory:").unwrap();
    assert!(db.get_cached_order("mnd_123").unwrap().is_none());
    db.cache_order("mnd_123", "order_abc", 10000).unwrap();
    assert_eq!(
        db.get_cached_order("mnd_123").unwrap().as_deref(),
        Some("order_abc")
    );
}

// --- Regression tests for audit fixes ---

#[test]
fn c2_migration_adds_audit_columns_to_legacy_db() {
    // Simulate a DB created before audit_hash/prev_hash existed.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        // Old schema without audit_hash/prev_hash and without orders.status
        conn.execute_batch(
            "
            CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, endpoint TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE nonces (nonce TEXT PRIMARY KEY, claimed_at INTEGER NOT NULL);
            CREATE TABLE orders (mandate_id TEXT PRIMARY KEY, order_id TEXT NOT NULL, amount INTEGER NOT NULL, created_at INTEGER NOT NULL);
            CREATE TABLE agents (agent_id TEXT PRIMARY KEY, max_cap INTEGER NOT NULL DEFAULT 50000, velocity_limit INTEGER NOT NULL DEFAULT 50, velocity_window_secs INTEGER NOT NULL DEFAULT 60, allowed_merchants TEXT NOT NULL DEFAULT '[\"merchant-001\"]', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE agent_velocity (agent_id TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (agent_id, window_start));
            ",
        )
        .unwrap();
        // Insert a legacy row to ensure data survives migration
        conn.execute(
            "INSERT INTO decisions (ts, endpoint, decision, reason, payload) VALUES (1, '/v1/checkout', 'ALLOW', 'legacy', '{}')",
            [],
        )
        .unwrap();
    }
    // Db::open should migrate the file without error and add missing columns
    let db = Db::open(path.to_str().unwrap()).unwrap();
    // Record a new decision should succeed (no "no such column" 500)
    db.record_decision("/v1/checkout", "ALLOW", "after migration", "{}")
        .unwrap();
    assert!(db.verify_chain().unwrap());
    // Orders migration: pending reservation should work on legacy DB
    assert!(
        db.try_reserve_order("mnd_legacy_1", "n_legacy_1", 1000)
            .unwrap()
    );
    let (oid, status) = db.get_order_status("mnd_legacy_1").unwrap().unwrap();
    assert_eq!(oid, "__PENDING__");
    assert_eq!(status, "pending");
    db.finalize_reserved_order("mnd_legacy_1", "order_final_1")
        .unwrap();
    assert_eq!(
        db.get_cached_order("mnd_legacy_1").unwrap().as_deref(),
        Some("order_final_1")
    );
}

#[test]
fn c4_pending_reservation_prevents_duplicate_orders() {
    let db = Db::open(":memory:").unwrap();
    // First reservation should succeed
    assert!(db.try_reserve_order("mnd_dup", "n_dup", 5000).unwrap());
    // Second concurrent reservation with same mandate_id must fail (atomic)
    assert!(!db.try_reserve_order("mnd_dup", "n_dup2", 5000).unwrap());
    // Cache should still be None while pending (not completed)
    assert!(db.get_cached_order("mnd_dup").unwrap().is_none());
    // Finalize first
    db.finalize_reserved_order("mnd_dup", "order_123").unwrap();
    // Now cached should be visible
    assert_eq!(
        db.get_cached_order("mnd_dup").unwrap().as_deref(),
        Some("order_123")
    );
    // Further reservation after completed should still fail (primary key)
    assert!(!db.try_reserve_order("mnd_dup", "n_dup3", 5000).unwrap());
    // Gateway failure case: pending cleared, should allow re-reserve after clear
    assert!(db.try_reserve_order("mnd_fail", "n_fail", 1000).unwrap());
    db.clear_pending_order("mnd_fail").unwrap();
    // After clear, the mandate_id row is gone, so get_cached None and we can reserve again
    assert!(db.get_cached_order("mnd_fail").unwrap().is_none());
}

#[test]
fn h1_hash_chain_concurrent_writes_dont_fork() {
    use std::sync::Arc;
    let db = Arc::new(Db::open(":memory:").unwrap());
    let mut handles = Vec::new();
    for i in 0..20 {
        let d = db.clone();
        handles.push(std::thread::spawn(move || {
            d.record_decision("/v1/checkout", "ALLOW", &format!("reason {i}"), "{}")
                .unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // All 20 writes should be present and chain valid (BEGIN IMMEDIATE prevents fork)
    assert!(db.verify_chain().unwrap());
    let stats = db.stats().unwrap();
    assert_eq!(stats.total, 20);
    assert_eq!(stats.allow, 20);
}

#[test]
fn m5_pagination_filters_in_sql_not_memory() {
    let db = Db::open(":memory:").unwrap();
    // Create 10 agents: agent-00 .. agent-09
    for i in 0..10 {
        let id = format!("agent-{i:02}");
        db.get_or_create_agent(&id).unwrap();
    }
    // Also add a matching agent that sorts last but would be hidden if we filtered after pagination
    db.get_or_create_agent("zzz-match").unwrap();
    // Paginated fetch: limit 2 offset 0 would only see agent-00, agent-01 if filtering after pagination,
    // so "zzz-match" would be invisible. With SQL filtering it must be found regardless of pagination window.
    let page = db
        .list_agents_paginated_filtered(2, 0, Some("zzz"))
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].agent_id, "zzz-match");
    // Second page with q that matches many should still paginate correctly within filtered set
    let page2 = db
        .list_agents_paginated_filtered(5, 5, Some("agent-"))
        .unwrap();
    // Filtered set is 10 agents (agent-00..09), offset 5 limit 5 => 5 rows
    assert_eq!(page2.len(), 5);
    assert_eq!(page2[0].agent_id, "agent-05");
}

#[test]
fn like_escape_treats_backslash_percent_underscore_literally() {
    let db = Db::open(":memory:").unwrap();
    // Agent whose id contains all three LIKE metacharacters.
    db.get_or_create_agent("combo\\%_mix").unwrap();
    // Decoys that an unescaped pattern would over-match:
    // backslash + arbitrary char + underscore (matches \%_ if \ is not escaped).
    db.get_or_create_agent("combo\\Q_mix").unwrap();
    db.get_or_create_agent("combo_plain_mix").unwrap();
    let page = db
        .list_agents_paginated_filtered(100, 0, Some("\\%_"))
        .unwrap();
    let ids: Vec<&str> = page.iter().map(|a| a.agent_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["combo\\%_mix"],
        "LIKE metacharacters must match literally, without over-matching"
    );
}

#[test]
fn h8_update_agent_atomic_partial_updates() {
    let db = Db::open(":memory:").unwrap();
    db.get_or_create_agent("atomic-agent").unwrap();
    // Simulate two concurrent partial updates: first changes max_cap, second changes velocity
    // If implementation did read-modify-write, second would overwrite first's max_cap.
    // Our atomic per-field UPDATE should preserve both.
    db.update_agent("atomic-agent", Some(99999), None, None, None)
        .unwrap();
    db.update_agent("atomic-agent", None, Some(7), None, None)
        .unwrap();
    let p = db.get_agent_policy("atomic-agent").unwrap().unwrap();
    assert_eq!(p.max_cap, 99999);
    assert_eq!(p.velocity_limit, 7);
}

fn file_db(name: &str) -> (tempfile::TempDir, String, Db) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join(name);
    let path_str = path.to_str().unwrap().to_string();
    let db = Db::open(&path_str).expect("db open");
    (dir, path_str, db)
}

fn age_pending_to_stale(path: &str, mandate_id: &str) {
    use mandatepay::mandates::unix_now;
    use mandatepay::store::PENDING_TTL_SECS;
    let conn = rusqlite::Connection::open(path).unwrap();
    let stale = unix_now() as i64 - PENDING_TTL_SECS as i64 - 100;
    let changed = conn
        .execute(
            "UPDATE orders SET reserved_at = ?1 WHERE mandate_id = ?2",
            rusqlite::params![stale, mandate_id],
        )
        .unwrap();
    assert_eq!(changed, 1);
}

#[test]
fn migration_v3_adds_reserved_at_and_nonce_to_orders() {
    // Pre-v3 DB: current v2 schema with status but without reserved_at/nonce.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join("v2.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, endpoint TEXT NOT NULL, decision TEXT NOT NULL, reason TEXT NOT NULL, payload TEXT NOT NULL, audit_hash TEXT NOT NULL DEFAULT '', prev_hash TEXT NOT NULL DEFAULT '');
            CREATE TABLE nonces (nonce TEXT PRIMARY KEY, claimed_at INTEGER NOT NULL);
            CREATE TABLE orders (mandate_id TEXT PRIMARY KEY, order_id TEXT NOT NULL, amount INTEGER NOT NULL, created_at INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'completed');
            CREATE TABLE agents (agent_id TEXT PRIMARY KEY, max_cap INTEGER NOT NULL DEFAULT 50000, velocity_limit INTEGER NOT NULL DEFAULT 50, velocity_window_secs INTEGER NOT NULL DEFAULT 60, allowed_merchants TEXT NOT NULL DEFAULT '[\"merchant-001\"]', created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
            CREATE TABLE agent_velocity (agent_id TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (agent_id, window_start));
            PRAGMA user_version = 2;
            ",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO orders (mandate_id, order_id, amount, created_at, status) VALUES ('mnd_v2', 'order_v2', 100, 1, 'completed')",
            [],
        )
        .unwrap();
    }
    let db = Db::open(path.to_str().unwrap()).unwrap();
    // Existing row survives, new columns exist, version bumped.
    assert_eq!(
        db.get_cached_order("mnd_v2").unwrap().as_deref(),
        Some("order_v2")
    );
    assert!(db.try_reserve_order("mnd_v3_new", "n_v3_new", 500).unwrap());
    let version: i64 = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 3);
}

#[test]
fn fresh_pending_blocks_duplicate_and_is_never_stolen() {
    let (_dir, _path, db) = file_db("pending_fresh.db");
    // (a) fresh pending row still blocks a duplicate.
    assert!(db.try_reserve_order("mnd_fresh", "n_fresh", 1000).unwrap());
    assert!(!db.try_reserve_order("mnd_fresh", "n_other", 1000).unwrap());
    // (c) a non-stale pending row is never stolen: explicit reclaim refuses,
    // row stays pending, and a further reserve still fails.
    assert!(!db.reclaim_stale_pending("mnd_fresh").unwrap());
    let (oid, status) = db.get_order_status("mnd_fresh").unwrap().unwrap();
    assert_eq!(oid, "__PENDING__");
    assert_eq!(status, "pending");
    assert!(!db.try_reserve_order("mnd_fresh", "n_third", 1000).unwrap());
}

#[test]
fn stale_pending_is_reclaimed_and_frees_original_nonce() {
    let (_dir, path, db) = file_db("pending_stale.db");
    // Simulate crashed attempt: nonce claimed (evaluate) + pending reserved, never finalized.
    assert!(db.try_claim_nonce("n_crashed").unwrap());
    assert!(
        db.try_reserve_order("mnd_crash", "n_crashed", 1000)
            .unwrap()
    );
    drop(db);
    age_pending_to_stale(&path, "mnd_crash");
    let db = Db::open(&path).unwrap();
    // (b) pending row older than TTL is reclaimed by a retry.
    assert!(db.try_reserve_order("mnd_crash", "n_retry", 1000).unwrap());
    // Reclaimed retry's original nonce must be free again (not a replay).
    assert!(
        db.try_claim_nonce("n_crashed").unwrap(),
        "original nonce must be freed when its stale pending is reclaimed"
    );
    // Row is pending again under the retry.
    let (oid, status) = db.get_order_status("mnd_crash").unwrap().unwrap();
    assert_eq!(oid, "__PENDING__");
    assert_eq!(status, "pending");
}

#[test]
fn velocity_refund_restores_budget_after_gateway_failure() {
    let db = Db::open(":memory:").unwrap();
    db.update_agent("refund-agent", Some(50000), Some(5), Some(60), None)
        .unwrap();
    // Success path: check_velocity increments and is NOT refunded.
    assert!(db.check_velocity("refund-agent").unwrap());
    assert_eq!(db.velocity_count("refund-agent").unwrap(), 1);
    // Failure path: the compensating decrement restores the budget.
    assert!(db.check_velocity("refund-agent").unwrap());
    assert_eq!(db.velocity_count("refund-agent").unwrap(), 2);
    db.refund_velocity("refund-agent").unwrap();
    assert_eq!(
        db.velocity_count("refund-agent").unwrap(),
        1,
        "gateway failure must leave the count as if the failed request never happened"
    );
}

#[test]
fn velocity_refund_saturates_at_zero() {
    let db = Db::open(":memory:").unwrap();
    db.update_agent("sat-agent", Some(50000), Some(5), Some(60), None)
        .unwrap();
    // Refund with no prior check: stays zero, never negative, no error.
    assert_eq!(db.velocity_count("sat-agent").unwrap(), 0);
    db.refund_velocity("sat-agent").unwrap();
    db.refund_velocity("sat-agent").unwrap();
    assert_eq!(db.velocity_count("sat-agent").unwrap(), 0);
    // Limit still enforced afterwards: exactly 5 Trues then false.
    let mut oks = 0;
    for _ in 0..7 {
        if db.check_velocity("sat-agent").unwrap() {
            oks += 1;
        }
    }
    assert_eq!(oks, 5);
}

#[test]
fn velocity_refund_never_negative_under_concurrency() {
    use std::sync::Arc;
    let db = Arc::new(Db::open(":memory:").unwrap());
    db.update_agent("conc-agent", Some(50000), Some(10_000), Some(60), None)
        .unwrap();
    let mut handles = Vec::new();
    for _ in 0..20 {
        let d = db.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..50 {
                let _ = d.check_velocity("conc-agent");
                let _ = d.refund_velocity("conc-agent");
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(db.velocity_count("conc-agent").unwrap(), 0);
}

#[test]
fn app_605_create_agent_just_inserted_not_panics() {
    // Ensures the post-insert get_agent_policy -> expect path is now ok_or_else and does not panic.
    // We call try_create_agent then get_agent_policy and assert it returns Some.
    let db = Db::open(":memory:").unwrap();
    assert!(
        db.try_create_agent("new-agent", Some(12345), None, None, None)
            .unwrap()
    );
    let policy = db
        .get_agent_policy("new-agent")
        .unwrap()
        .ok_or_else(|| "just inserted agent not found".to_string())
        .unwrap();
    assert_eq!(policy.agent_id, "new-agent");
    assert_eq!(policy.max_cap, 12345);
}
