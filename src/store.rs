use crate::mandates::unix_now;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct DecisionRow {
    pub id: i64,
    pub ts: i64,
    pub endpoint: String,
    pub decision: String,
    pub reason: String,
    pub payload: String,
    pub audit_hash: String,
    pub prev_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LedgerStats {
    pub total: i64,
    pub allow: i64,
    pub reject: i64,
    pub issued: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    pub agent_id: String,
    pub max_cap: u64,
    pub velocity_limit: u32,
    pub velocity_window_secs: u64,
    pub allowed_merchants: Vec<String>,
}

pub struct Db(Mutex<Connection>);

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    endpoint TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload TEXT NOT NULL,
    audit_hash TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    claimed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    mandate_id TEXT PRIMARY KEY,
    order_id TEXT NOT NULL,
    amount INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    max_cap INTEGER NOT NULL DEFAULT 50000,
    velocity_limit INTEGER NOT NULL DEFAULT 50,
    velocity_window_secs INTEGER NOT NULL DEFAULT 60,
    allowed_merchants TEXT NOT NULL DEFAULT 'merchant-001',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_velocity (
    agent_id TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (agent_id, window_start)
);
";

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Db(Mutex::new(conn)))
    }

    pub fn record_decision(
        &self,
        endpoint: &str,
        decision: &str,
        reason: &str,
        payload: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.0.lock().expect("decision ledger poisoned");
        let ts = unix_now() as i64;
        let prev_hash: String = conn
            .query_row(
                "SELECT audit_hash FROM decisions ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(b"|");
        hasher.update(endpoint.as_bytes());
        hasher.update(b"|");
        hasher.update(decision.as_bytes());
        hasher.update(b"|");
        hasher.update(reason.as_bytes());
        hasher.update(b"|");
        hasher.update(payload.as_bytes());
        hasher.update(b"|");
        hasher.update(ts.to_be_bytes());
        let audit_hash = hex::encode(hasher.finalize());
        conn.execute(
            "INSERT INTO decisions (ts, endpoint, decision, reason, payload, audit_hash, prev_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ts, endpoint, decision, reason, payload, audit_hash, prev_hash
            ],
        )?;
        Ok(())
    }

    pub fn try_claim_nonce(&self, nonce: &str) -> rusqlite::Result<bool> {
        let conn = self.0.lock().expect("nonce ledger poisoned");
        let changed = conn.execute(
            "INSERT OR IGNORE INTO nonces (nonce, claimed_at) VALUES (?1, ?2)",
            params![nonce, unix_now() as i64],
        )?;
        Ok(changed > 0)
    }

    pub fn list_recent(&self, limit: i64) -> rusqlite::Result<Vec<DecisionRow>> {
        let conn = self.0.lock().expect("decision ledger poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, ts, endpoint, decision, reason, payload, audit_hash, prev_hash FROM decisions ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(DecisionRow {
                    id: row.get(0)?,
                    ts: row.get(1)?,
                    endpoint: row.get(2)?,
                    decision: row.get(3)?,
                    reason: row.get(4)?,
                    payload: row.get(5)?,
                    audit_hash: row.get(6)?,
                    prev_hash: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_decision(&self, id: i64) -> rusqlite::Result<Option<DecisionRow>> {
        let conn = self.0.lock().expect("decision ledger poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, ts, endpoint, decision, reason, payload, audit_hash, prev_hash FROM decisions WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(DecisionRow {
                id: row.get(0)?,
                ts: row.get(1)?,
                endpoint: row.get(2)?,
                decision: row.get(3)?,
                reason: row.get(4)?,
                payload: row.get(5)?,
                audit_hash: row.get(6)?,
                prev_hash: row.get(7)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn verify_chain(&self) -> rusqlite::Result<bool> {
        let conn = self.0.lock().expect("decision ledger poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, ts, endpoint, decision, reason, payload, audit_hash, prev_hash FROM decisions ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(DecisionRow {
                id: row.get(0)?,
                ts: row.get(1)?,
                endpoint: row.get(2)?,
                decision: row.get(3)?,
                reason: row.get(4)?,
                payload: row.get(5)?,
                audit_hash: row.get(6)?,
                prev_hash: row.get(7)?,
            })
        })?;
        let mut expected_prev = String::new();
        for row in rows {
            let r = row?;
            if r.prev_hash != expected_prev {
                return Ok(false);
            }
            let mut hasher = Sha256::new();
            hasher.update(r.prev_hash.as_bytes());
            hasher.update(b"|");
            hasher.update(r.endpoint.as_bytes());
            hasher.update(b"|");
            hasher.update(r.decision.as_bytes());
            hasher.update(b"|");
            hasher.update(r.reason.as_bytes());
            hasher.update(b"|");
            hasher.update(r.payload.as_bytes());
            hasher.update(b"|");
            hasher.update(r.ts.to_be_bytes());
            let calc = hex::encode(hasher.finalize());
            if calc != r.audit_hash {
                return Ok(false);
            }
            expected_prev = r.audit_hash;
        }
        Ok(true)
    }

    pub fn stats(&self) -> rusqlite::Result<LedgerStats> {
        let conn = self.0.lock().expect("decision ledger poisoned");
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM decisions", [], |r| r.get(0))?;
        let allow: i64 = conn.query_row(
            "SELECT COUNT(*) FROM decisions WHERE decision='ALLOW'",
            [],
            |r| r.get(0),
        )?;
        let reject: i64 = conn.query_row(
            "SELECT COUNT(*) FROM decisions WHERE decision='REJECT'",
            [],
            |r| r.get(0),
        )?;
        let issued: i64 = conn.query_row(
            "SELECT COUNT(*) FROM decisions WHERE decision='ISSUED'",
            [],
            |r| r.get(0),
        )?;
        Ok(LedgerStats {
            total,
            allow,
            reject,
            issued,
        })
    }

    pub fn get_cached_order(&self, mandate_id: &str) -> rusqlite::Result<Option<String>> {
        let conn = self.0.lock().expect("order cache poisoned");
        let mut stmt = conn.prepare("SELECT order_id FROM orders WHERE mandate_id = ?1")?;
        let mut rows = stmt.query(params![mandate_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn cache_order(
        &self,
        mandate_id: &str,
        order_id: &str,
        amount: u64,
    ) -> rusqlite::Result<()> {
        let conn = self.0.lock().expect("order cache poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO orders (mandate_id, order_id, amount, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![mandate_id, order_id, amount as i64, unix_now() as i64],
        )?;
        Ok(())
    }

    pub fn get_or_create_agent(&self, agent_id: &str) -> rusqlite::Result<AgentPolicy> {
        let conn = self.0.lock().expect("agent policy poisoned");
        let mut stmt = conn.prepare(
            "SELECT agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants FROM agents WHERE agent_id = ?1"
        )?;
        let mut rows = stmt.query(params![agent_id])?;
        if let Some(row) = rows.next()? {
            let merchants: String = row.get(4)?;
            Ok(AgentPolicy {
                agent_id: row.get(0)?,
                max_cap: row.get::<_, i64>(1)? as u64,
                velocity_limit: row.get::<_, i64>(2)? as u32,
                velocity_window_secs: row.get::<_, i64>(3)? as u64,
                allowed_merchants: merchants
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            })
        } else {
            let now = unix_now();
            conn.execute(
                "INSERT INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at)
                 VALUES (?1, 50000, 50, 60, 'merchant-001', ?2, ?2)",
                params![agent_id, now as i64],
            )?;
            Ok(AgentPolicy {
                agent_id: agent_id.to_string(),
                max_cap: 50000,
                velocity_limit: 50,
                velocity_window_secs: 60,
                allowed_merchants: vec!["merchant-001".to_string()],
            })
        }
    }

    pub fn check_velocity(&self, agent_id: &str) -> rusqlite::Result<bool> {
        let conn = self.0.lock().expect("velocity poisoned");
        let now = unix_now();
        conn.execute(
            "INSERT OR IGNORE INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at)
             VALUES (?1, 50000, 50, 60, 'merchant-001', ?2, ?2)",
            params![agent_id, now as i64],
        )?;
        let (velocity_limit, velocity_window_secs): (i64, i64) = conn.query_row(
            "SELECT velocity_limit, velocity_window_secs FROM agents WHERE agent_id = ?1",
            params![agent_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let window_start = now - (now % velocity_window_secs as u64);
        conn.execute(
            "INSERT INTO agent_velocity (agent_id, window_start, count) VALUES (?1, ?2, 1)
             ON CONFLICT(agent_id, window_start) DO UPDATE SET count = count + 1",
            params![agent_id, window_start as i64],
        )?;
        let count: i64 = conn.query_row(
            "SELECT count FROM agent_velocity WHERE agent_id = ?1 AND window_start = ?2",
            params![agent_id, window_start as i64],
            |r| r.get(0),
        )?;
        Ok(count <= velocity_limit)
    }

    pub fn get_agent_policy(&self, agent_id: &str) -> rusqlite::Result<Option<AgentPolicy>> {
        let conn = self.0.lock().expect("agent policy poisoned");
        let mut stmt = conn.prepare(
            "SELECT agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants FROM agents WHERE agent_id = ?1"
        )?;
        let mut rows = stmt.query(params![agent_id])?;
        if let Some(row) = rows.next()? {
            let merchants: String = row.get(4)?;
            Ok(Some(AgentPolicy {
                agent_id: row.get(0)?,
                max_cap: row.get::<_, i64>(1)? as u64,
                velocity_limit: row.get::<_, i64>(2)? as u32,
                velocity_window_secs: row.get::<_, i64>(3)? as u64,
                allowed_merchants: merchants
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            }))
        } else {
            Ok(None)
        }
    }
}
