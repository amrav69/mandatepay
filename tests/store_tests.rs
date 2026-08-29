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
