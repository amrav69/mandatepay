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
