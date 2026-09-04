use mandatepay::store::Db;

#[test]
fn agent_crud_and_velocity() {
    let db = Db::open(":memory:").unwrap();

    let (p1, _k1) = db.get_or_create_agent("test-agent").unwrap();
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
    assert!(db.try_reserve_order("mnd_legacy_1", 1000).unwrap());
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
    assert!(db.try_reserve_order("mnd_dup", 5000).unwrap());
    // Second concurrent reservation with same mandate_id must fail (atomic)
    assert!(!db.try_reserve_order("mnd_dup", 5000).unwrap());
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
    assert!(!db.try_reserve_order("mnd_dup", 5000).unwrap());
    // Gateway failure case: pending cleared, should allow re-reserve after clear
    assert!(db.try_reserve_order("mnd_fail", 1000).unwrap());
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
        .list_agents_paginated_filtered(2, 0, Some("zzz"), "agent_id", false)
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].agent_id, "zzz-match");
    // Second page with q that matches many should still paginate correctly within filtered set
    let page2 = db
        .list_agents_paginated_filtered(5, 5, Some("agent-"), "agent_id", false)
        .unwrap();
    // Filtered set is 10 agents (agent-00..09), offset 5 limit 5 => 5 rows
    assert_eq!(page2.len(), 5);
    assert_eq!(page2[0].agent_id, "agent-05");
}

#[test]
fn h1_sorted_pagination_reflects_global_order() {
    // H1 regression: with more rows than the page, sort must apply before
    // LIMIT/OFFSET. sort-after-paginate returned the first N by id, sorted —
    // hiding the true top rows.
    let db = Db::open(":memory:").unwrap();
    for (id, cap) in [
        ("h1-a", 1000),
        ("h1-b", 5000),
        ("h1-c", 3000),
        ("h1-d", 4000),
        ("h1-e", 2000),
    ] {
        db.try_create_agent(id, Some(cap), None, None, None)
            .unwrap();
    }
    let page = db
        .list_agents_paginated_filtered(2, 0, None, "max_cap", true)
        .unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].agent_id, "h1-b");
    assert_eq!(page[1].agent_id, "h1-d");
    let page2 = db
        .list_agents_paginated_filtered(2, 2, None, "max_cap", true)
        .unwrap();
    assert_eq!(page2.len(), 2);
    assert_eq!(page2[0].agent_id, "h1-c");
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

#[test]
fn app_605_create_agent_just_inserted_not_panics() {
    // Ensures the post-insert get_agent_policy -> expect path is now ok_or_else and does not panic.
    // We call try_create_agent then get_agent_policy and assert it returns Some.
    let db = Db::open(":memory:").unwrap();
    assert!(
        db.try_create_agent("new-agent", Some(12345), None, None, None)
            .map(|(b, _)| b)
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

#[test]
fn h3_amount_as_i64_overflow_rejected_not_wrapped() {
    let db = Db::open(":memory:").unwrap();
    // u64::MAX and i64::MAX+1 should be rejected, not silently wrapped to negative
    let overflow = i64::MAX as u64 + 1;
    let err = db.cache_order("mnd_h3", "order_h3", overflow).unwrap_err();
    assert!(format!("{err}").contains("exceeds i64::MAX"));
    let err2 = db.try_reserve_order("mnd_h3b", overflow).unwrap_err();
    assert!(format!("{err2}").contains("exceeds i64::MAX"));
    // Valid large but in-range should succeed
    let ok_val = i64::MAX as u64;
    db.cache_order("mnd_h3_ok", "order_ok", ok_val).unwrap();
    assert_eq!(
        db.get_cached_order("mnd_h3_ok").unwrap().as_deref(),
        Some("order_ok")
    );
}

#[test]
fn c3_agent_u64_to_i64_rejected_not_wrapped() {
    // C3 regression: max_cap / velocity_window_secs above i64::MAX must error
    // at the store layer (HTTP layer re-checks), never wrap negative.
    let db = Db::open(":memory:").unwrap();
    let overflow = i64::MAX as u64 + 1;
    assert!(
        db.try_create_agent("c3-max", Some(overflow), None, None, None)
            .is_err()
    );
    assert!(
        db.try_create_agent("c3-win", None, None, Some(u64::MAX), None)
            .is_err()
    );
    db.get_or_create_agent("c3-upd").unwrap();
    assert!(
        db.update_agent("c3-upd", Some(u64::MAX), None, None, None)
            .is_err()
    );
    assert!(
        db.update_agent("c3-upd", None, None, Some(overflow), None)
            .is_err()
    );
    // In-range max still accepted.
    assert!(
        db.try_create_agent("c3-ok", Some(i64::MAX as u64), None, None, None)
            .map(|(b, _)| b)
            .unwrap()
    );
}

#[test]
fn m4_u32_and_u64_bounds_checked_no_wrap() {
    // M4: as u32 / as u64 on DB values that could be out of range must error, not wrap.
    // Insert a row with velocity_limit = u32::MAX as i64 + 1 (out of range) via raw SQL, then read via get_agent_policy
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("m4.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE agents (agent_id TEXT PRIMARY KEY, max_cap INTEGER NOT NULL, velocity_limit INTEGER NOT NULL, velocity_window_secs INTEGER NOT NULL, allowed_merchants TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);",
        )
        .unwrap();
        // Insert a row with velocity_limit = 2^32 (too big for u32) and max_cap = -1 (negative for u64)
        conn.execute(
            "INSERT INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at) VALUES ('bad-agent', -5, 4294967296, -1, '[\"merchant-001\"]', 1, 1)",
            [],
        )
        .unwrap();
    }
    let db = Db::open(path.to_str().unwrap()).unwrap();
    // get_agent_policy on that row should error due to bounds check, not wrap to huge values
    let res = db.get_agent_policy("bad-agent");
    assert!(
        res.is_err(),
        "expected error for out-of-range velocity_limit/max_cap, got {res:?}"
    );
    // Also test that a valid row still works
    let db2 = Db::open(":memory:").unwrap();
    db2.get_or_create_agent("good-agent").unwrap();
    let p = db2.get_agent_policy("good-agent").unwrap().unwrap();
    assert_eq!(p.velocity_limit, 50);
}
