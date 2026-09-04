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

// M4: helpers for safe i64 -> u32/u64 conversion with explicit bounds check (no silent wrap)
fn checked_u32(v: i64, col: usize, field: &str) -> rusqlite::Result<u32> {
    u32::try_from(v).map_err(|_| {
        rusqlite::Error::InvalidColumnType(col, field.into(), rusqlite::types::Type::Integer)
    })
}
fn checked_u64(v: i64, col: usize, field: &str) -> rusqlite::Result<u64> {
    if v < 0 {
        return Err(rusqlite::Error::InvalidColumnType(
            col,
            field.into(),
            rusqlite::types::Type::Integer,
        ));
    }
    Ok(v as u64)
}

/// C3: checked u64 -> i64 for DB writes. Rejects values that would wrap negative
/// instead of silently storing them (stored DoS via `as i64` wrap).
fn checked_i64(v: u64, field: &str) -> rusqlite::Result<i64> {
    i64::try_from(v)
        .map_err(|_| rusqlite::Error::InvalidParameterName(format!("{field} exceeds i64::MAX")))
}

/// C1: default allowlist for brand-new agents (per-agent value is authoritative after creation).
pub const DEFAULT_ALLOWLIST_JSON: &str = r#"["merchant-001"]"#;

/// C1: generate a fresh per-agent API key (32B base64) and its SHA256 hex hash.
/// Plaintext is returned once to the admin caller; only the hash is stored.
pub fn generate_agent_key() -> (String, String) {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let mut raw = [0u8; 32];
    getrandom::fill(&mut raw).expect("os randomness unavailable");
    let plaintext = B64.encode(raw);
    let hash = hex::encode(Sha256::digest(plaintext.as_bytes()));
    (plaintext, hash)
}

/// C1: hash a candidate plaintext the same way for constant-time comparison.
fn hash_candidate(provided: &str) -> String {
    hex::encode(Sha256::digest(provided.as_bytes()))
}

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
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'completed'
);
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    max_cap INTEGER NOT NULL DEFAULT 50000,
    velocity_limit INTEGER NOT NULL DEFAULT 50,
    velocity_window_secs INTEGER NOT NULL DEFAULT 60,
    allowed_merchants TEXT NOT NULL DEFAULT '[\"merchant-001\"]',
    api_key_hash TEXT NOT NULL DEFAULT '',
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
    fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(1)?;
            Ok(name)
        })?;
        for name in rows {
            if name? == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        // C2 migration: handle DBs created before audit_hash/prev_hash and before orders.status
        // Use both user_version and column existence for idempotency across upgrades.
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap_or(0);
        // Migration v1: audit_hash / prev_hash columns (pre-0.1.0 DBs)
        let has_audit = Self::column_exists(&conn, "decisions", "audit_hash")?;
        if !has_audit {
            conn.execute(
                "ALTER TABLE decisions ADD COLUMN audit_hash TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        let has_prev = Self::column_exists(&conn, "decisions", "prev_hash")?;
        if !has_prev {
            conn.execute(
                "ALTER TABLE decisions ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        // Migration v2: orders.status for C4 pending reservation
        let has_status = Self::column_exists(&conn, "orders", "status")?;
        if !has_status {
            conn.execute(
                "ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'",
                [],
            )?;
        }
        // Migration v3 (C1): agents.api_key_hash for per-agent keys.
        // Existing rows keep '' until rotated; operator must call
        // POST /v1/agents/:id/rotate with the master key to issue a usable key.
        let has_key_hash = Self::column_exists(&conn, "agents", "api_key_hash")?;
        if !has_key_hash {
            conn.execute(
                "ALTER TABLE agents ADD COLUMN api_key_hash TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        let legacy_unkeyed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM agents WHERE api_key_hash = ''",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if legacy_unkeyed > 0 {
            tracing::warn!(
                count = legacy_unkeyed,
                "agents table has rows without api_key_hash; rotate to issue keys"
            );
        }
        // Backfill legacy audit_hash chain if any row still has empty hash (DB upgraded from pre-chain version)
        let empty_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM decisions WHERE audit_hash = ''",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        if empty_count > 0 {
            let mut stmt = conn.prepare(
                "SELECT id, ts, endpoint, decision, reason, payload FROM decisions ORDER BY id ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?;
            let collected: Vec<(i64, i64, String, String, String, String)> =
                rows.collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            let mut prev = String::new();
            for (id, ts, endpoint, decision, reason, payload) in collected {
                let mut hasher = Sha256::new();
                hasher.update(prev.as_bytes());
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
                let hash = hex::encode(hasher.finalize());
                conn.execute(
                    "UPDATE decisions SET audit_hash = ?1, prev_hash = ?2 WHERE id = ?3",
                    params![hash, prev, id],
                )?;
                prev = hash;
            }
        }
        if version < 2 {
            conn.execute_batch("PRAGMA user_version = 2")?;
        }
        Ok(Db(Mutex::new(conn)))
    }

    pub fn record_decision(
        &self,
        endpoint: &str,
        decision: &str,
        reason: &str,
        payload: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // H1: wrap read-modify-write in BEGIN IMMEDIATE so concurrent writers serialize at SQLite level
        // and cannot fork the hash chain (read prev_hash -> compute -> insert).
        conn.execute("BEGIN IMMEDIATE", [])?;
        let result: rusqlite::Result<()> = (|| {
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
        })();
        match result {
            Ok(()) => {
                conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                if let Err(rollback_err) = conn.execute("ROLLBACK", []) {
                    tracing::error!(error = %rollback_err, "failed to rollback transaction after record_decision error");
                }
                Err(e)
            }
        }
    }

    pub fn try_claim_nonce(&self, nonce: &str) -> rusqlite::Result<bool> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let changed = conn.execute(
            "INSERT OR IGNORE INTO nonces (nonce, claimed_at) VALUES (?1, ?2)",
            params![nonce, unix_now() as i64],
        )?;
        Ok(changed > 0)
    }

    pub fn rollback_nonce(&self, nonce: &str) -> rusqlite::Result<()> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("DELETE FROM nonces WHERE nonce = ?1", params![nonce])?;
        Ok(())
    }

    pub fn list_recent(&self, limit: i64) -> rusqlite::Result<Vec<DecisionRow>> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
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
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
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
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
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
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
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
        Ok(self
            .get_cached_order_with_amount(mandate_id)?
            .map(|(oid, _)| oid))
    }

    pub fn get_cached_order_with_amount(
        &self,
        mandate_id: &str,
    ) -> rusqlite::Result<Option<(String, u64)>> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT order_id, amount FROM orders WHERE mandate_id = ?1 AND status = 'completed'",
        )?;
        let mut rows = stmt.query(params![mandate_id])?;
        if let Some(row) = rows.next()? {
            let oid: String = row.get(0)?;
            let amt: i64 = row.get(1)?;
            // amount was validated <= i64::MAX on insert, but be defensive on read
            if amt < 0 {
                return Err(rusqlite::Error::InvalidColumnType(
                    1,
                    "amount".into(),
                    rusqlite::types::Type::Integer,
                ));
            }
            Ok(Some((oid, amt as u64)))
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
        // H3: defense in depth — even though app.rs validates amount <= i64::MAX, also guard here
        if amount > i64::MAX as u64 {
            return Err(rusqlite::Error::InvalidParameterName(
                "amount exceeds i64::MAX".into(),
            ));
        }
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR IGNORE INTO orders (mandate_id, order_id, amount, created_at, status) VALUES (?1, ?2, ?3, ?4, 'completed')",
            params![mandate_id, order_id, amount as i64, unix_now() as i64],
        )?;
        Ok(())
    }

    /// C4: atomic pending reservation claimed *before* gateway call.
    /// Returns true if reservation succeeded (we own the mandate), false if another request already holds it.
    pub fn try_reserve_order(&self, mandate_id: &str, amount: u64) -> rusqlite::Result<bool> {
        if amount > i64::MAX as u64 {
            return Err(rusqlite::Error::InvalidParameterName(
                "amount exceeds i64::MAX".into(),
            ));
        }
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let changed = conn.execute(
            "INSERT OR IGNORE INTO orders (mandate_id, order_id, amount, created_at, status) VALUES (?1, '__PENDING__', ?2, ?3, 'pending')",
            params![mandate_id, amount as i64, unix_now() as i64],
        )?;
        Ok(changed > 0)
    }

    pub fn finalize_reserved_order(
        &self,
        mandate_id: &str,
        order_id: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "UPDATE orders SET order_id = ?1, status = 'completed' WHERE mandate_id = ?2 AND status = 'pending'",
            params![order_id, mandate_id],
        )?;
        Ok(())
    }

    pub fn clear_pending_order(&self, mandate_id: &str) -> rusqlite::Result<()> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "DELETE FROM orders WHERE mandate_id = ?1 AND status = 'pending'",
            params![mandate_id],
        )?;
        Ok(())
    }

    /// Returns order status for debugging; None if no row. Used in tests.
    pub fn get_order_status(&self, mandate_id: &str) -> rusqlite::Result<Option<(String, String)>> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare("SELECT order_id, status FROM orders WHERE mandate_id = ?1")?;
        let mut rows = stmt.query(params![mandate_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some((row.get(0)?, row.get(1)?)))
        } else {
            Ok(None)
        }
    }

    /// C1: first-touch create. Returns (policy, Some(plaintext_key)) only when the
    /// row was newly created or a legacy row without a key was migrated; otherwise
    /// (existing keyed row) returns (policy, None) since plaintext is unrecoverable.
    pub fn get_or_create_agent(
        &self,
        agent_id: &str,
    ) -> rusqlite::Result<(AgentPolicy, Option<String>)> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, api_key_hash FROM agents WHERE agent_id = ?1"
        )?;
        let mut rows = stmt.query(params![agent_id])?;
        if let Some(row) = rows.next()? {
            let merchants: String = row.get(4)?;
            let existing_hash: String = row.get(5)?;
            let policy = AgentPolicy {
                agent_id: row.get(0)?,
                max_cap: checked_u64(row.get::<_, i64>(1)?, 1, "max_cap")?,
                velocity_limit: checked_u32(row.get::<_, i64>(2)?, 2, "velocity_limit")?,
                velocity_window_secs: checked_u64(
                    row.get::<_, i64>(3)?,
                    3,
                    "velocity_window_secs",
                )?,
                allowed_merchants: serde_json::from_str(&merchants).unwrap_or_else(|_| {
                    merchants
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }),
            };
            drop(rows);
            drop(stmt);
            if existing_hash.is_empty() {
                let (plaintext, hash) = generate_agent_key();
                conn.execute(
                    "UPDATE agents SET api_key_hash = ?1, updated_at = ?2 WHERE agent_id = ?3",
                    params![hash, unix_now() as i64, agent_id],
                )?;
                tracing::warn!(agent_id = %agent_id, "migrated legacy agent without key; new key issued once");
                return Ok((policy, Some(plaintext)));
            }
            return Ok((policy, None));
        }
        drop(rows);
        drop(stmt);
        let now = unix_now();
        let (plaintext, hash) = generate_agent_key();
        conn.execute(
            "INSERT INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, api_key_hash, created_at, updated_at)
             VALUES (?1, 50000, 50, 60, ?2, ?3, ?4, ?4)",
            params![agent_id, DEFAULT_ALLOWLIST_JSON, hash, now as i64],
        )?;
        Ok((
            AgentPolicy {
                agent_id: agent_id.to_string(),
                max_cap: 50000,
                velocity_limit: 50,
                velocity_window_secs: 60,
                allowed_merchants: vec!["merchant-001".to_string()],
            },
            Some(plaintext),
        ))
    }

    /// C1: verify a presented per-agent key against the stored SHA256 hash.
    /// Unknown agents and empty hashes fail closed.
    pub fn verify_agent_key(&self, agent_id: &str, provided: &str) -> rusqlite::Result<bool> {
        if provided.trim().is_empty() || agent_id.trim().is_empty() {
            return Ok(false);
        }
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let stored: Option<String> = match conn.query_row(
            "SELECT api_key_hash FROM agents WHERE agent_id = ?1",
            params![agent_id.trim()],
            |r| r.get(0),
        ) {
            Ok(h) => Some(h),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e),
        };
        let Some(hash) = stored else {
            return Ok(false);
        };
        if hash.is_empty() {
            return Ok(false);
        }
        let candidate = hash_candidate(provided.trim());
        use subtle::ConstantTimeEq;
        Ok(candidate.as_bytes().ct_eq(hash.as_bytes()).into())
    }

    /// C1: rotate an agent key (master-gated at HTTP layer). Returns new plaintext once.
    pub fn rotate_agent_key(&self, agent_id: &str) -> rusqlite::Result<Option<String>> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let exists: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE agent_id = ?1)",
            params![agent_id],
            |r| r.get(0),
        )?;
        if !exists {
            return Ok(None);
        }
        let (plaintext, hash) = generate_agent_key();
        conn.execute(
            "UPDATE agents SET api_key_hash = ?1, updated_at = ?2 WHERE agent_id = ?3",
            params![hash, unix_now() as i64, agent_id],
        )?;
        Ok(Some(plaintext))
    }

    pub fn check_velocity(&self, agent_id: &str) -> rusqlite::Result<bool> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now();
        conn.execute(
            "INSERT OR IGNORE INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at)
             VALUES (?1, 50000, 50, 60, '[\"merchant-001\"]', ?2, ?2)",
            params![agent_id, now as i64],
        )?;
        let (velocity_limit, velocity_window_secs): (i64, i64) = conn.query_row(
            "SELECT velocity_limit, velocity_window_secs FROM agents WHERE agent_id = ?1",
            params![agent_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if velocity_window_secs <= 0 {
            return Err(rusqlite::Error::InvalidParameterName(
                "velocity_window_secs must be positive".to_string(),
            ));
        }
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
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants FROM agents WHERE agent_id = ?1"
        )?;
        let mut rows = stmt.query(params![agent_id])?;
        if let Some(row) = rows.next()? {
            let merchants: String = row.get(4)?;
            Ok(Some(AgentPolicy {
                agent_id: row.get(0)?,
                max_cap: checked_u64(row.get::<_, i64>(1)?, 1, "max_cap")?,
                velocity_limit: checked_u32(row.get::<_, i64>(2)?, 2, "velocity_limit")?,
                velocity_window_secs: checked_u64(
                    row.get::<_, i64>(3)?,
                    3,
                    "velocity_window_secs",
                )?,
                allowed_merchants: serde_json::from_str(&merchants).unwrap_or_else(|_| {
                    merchants
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }),
            }))
        } else {
            Ok(None)
        }
    }

    /// H8: atomic UPDATE without read-modify-write race. Only supplied fields are updated.
    pub fn update_agent(
        &self,
        agent_id: &str,
        max_cap: Option<u64>,
        velocity_limit: Option<u32>,
        velocity_window_secs: Option<u64>,
        allowed_merchants: Option<Vec<String>>,
    ) -> rusqlite::Result<AgentPolicy> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        // Ensure row exists first (atomic insert) then update only provided columns.
        let now = unix_now() as i64;
        conn.execute(
            "INSERT OR IGNORE INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at) VALUES (?1, 50000, 50, 60, '[\"merchant-001\"]', ?2, ?2)",
            params![agent_id, now],
        )?;
        // Build dynamic UPDATE with COALESCE-like behavior: update only Some values.
        // Use separate executes to keep it single atomic transaction per caller lock.
        // Each field is updated atomically inside the mutex, no read-modify-write across threads losing updates.
        if let Some(v) = max_cap {
            conn.execute(
                "UPDATE agents SET max_cap = ?1, updated_at = ?2 WHERE agent_id = ?3",
                params![checked_i64(v, "max_cap")?, unix_now() as i64, agent_id],
            )?;
        }
        if let Some(v) = velocity_limit {
            conn.execute(
                "UPDATE agents SET velocity_limit = ?1, updated_at = ?2 WHERE agent_id = ?3",
                params![v as i64, unix_now() as i64, agent_id],
            )?;
        }
        if let Some(v) = velocity_window_secs {
            conn.execute(
                "UPDATE agents SET velocity_window_secs = ?1, updated_at = ?2 WHERE agent_id = ?3",
                params![
                    checked_i64(v, "velocity_window_secs")?,
                    unix_now() as i64,
                    agent_id
                ],
            )?;
        }
        if let Some(v) = allowed_merchants {
            let merchants = serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string());
            conn.execute(
                "UPDATE agents SET allowed_merchants = ?1, updated_at = ?2 WHERE agent_id = ?3",
                params![merchants, unix_now() as i64, agent_id],
            )?;
        } else if max_cap.is_none() && velocity_limit.is_none() && velocity_window_secs.is_none() {
            // Touch updated_at even if no field changed? Not needed, but keep idempotency.
        }
        // Fetch updated row
        let mut stmt = conn.prepare(
            "SELECT agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants FROM agents WHERE agent_id = ?1",
        )?;
        let mut rows = stmt.query(params![agent_id])?;
        let row = rows.next()?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let merchants: String = row.get(4)?;
        Ok(AgentPolicy {
            agent_id: row.get(0)?,
            max_cap: checked_u64(row.get::<_, i64>(1)?, 1, "max_cap")?,
            velocity_limit: checked_u32(row.get::<_, i64>(2)?, 2, "velocity_limit")?,
            velocity_window_secs: checked_u64(row.get::<_, i64>(3)?, 3, "velocity_window_secs")?,
            allowed_merchants: serde_json::from_str(&merchants).unwrap_or_else(|_| {
                merchants
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }),
        })
    }

    /// Atomic insert for `POST /v1/agents` — returns `(inserted, plaintext_key)`.
    /// `plaintext_key` is `Some` only on insert (returned once to admin caller).
    /// Caller must map `false` to `400 already exists` without a prior `SELECT`
    /// to avoid TOCTOU.
    pub fn try_create_agent(
        &self,
        agent_id: &str,
        max_cap: Option<u64>,
        velocity_limit: Option<u32>,
        velocity_window_secs: Option<u64>,
        allowed_merchants: Option<Vec<String>>,
    ) -> rusqlite::Result<(bool, Option<String>)> {
        let max_cap_val = checked_i64(max_cap.unwrap_or(50000), "max_cap")?;
        let velocity_limit_val = velocity_limit.unwrap_or(50) as i64;
        let velocity_window_secs_val =
            checked_i64(velocity_window_secs.unwrap_or(60), "velocity_window_secs")?;
        let merchants = match allowed_merchants {
            Some(v) => serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string()),
            None => DEFAULT_ALLOWLIST_JSON.to_string(),
        };
        let (plaintext, hash) = generate_agent_key();
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now() as i64;
        let changed = conn.execute(
            "INSERT OR IGNORE INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, api_key_hash, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                agent_id,
                max_cap_val,
                velocity_limit_val,
                velocity_window_secs_val,
                merchants,
                hash,
                now
            ],
        )?;
        Ok((
            changed > 0,
            if changed > 0 { Some(plaintext) } else { None },
        ))
    }

    pub fn list_agents(&self) -> rusqlite::Result<Vec<AgentPolicy>> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants FROM agents ORDER BY agent_id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let merchants: String = row.get(4)?;
            Ok(AgentPolicy {
                agent_id: row.get(0)?,
                max_cap: checked_u64(row.get::<_, i64>(1)?, 1, "max_cap")?,
                velocity_limit: checked_u32(row.get::<_, i64>(2)?, 2, "velocity_limit")?,
                velocity_window_secs: checked_u64(
                    row.get::<_, i64>(3)?,
                    3,
                    "velocity_window_secs",
                )?,
                allowed_merchants: serde_json::from_str(&merchants).unwrap_or_else(|_| {
                    merchants
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }),
            })
        })?;
        rows.collect()
    }

    pub fn delete_agent(&self, agent_id: &str) -> rusqlite::Result<bool> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let changed = conn.execute("DELETE FROM agents WHERE agent_id = ?1", params![agent_id])?;
        conn.execute(
            "DELETE FROM agent_velocity WHERE agent_id = ?1",
            params![agent_id],
        )?;
        Ok(changed > 0)
    }

    pub fn list_agents_paginated(
        &self,
        limit: i64,
        offset: i64,
    ) -> rusqlite::Result<Vec<AgentPolicy>> {
        // M5 legacy entrypoint kept for callers without search; delegates to filtered version with empty q.
        self.list_agents_paginated_filtered(limit, offset, None)
    }

    /// M5: filter in SQL so pagination window correctly reflects matches.
    pub fn list_agents_paginated_filtered(
        &self,
        limit: i64,
        offset: i64,
        q: Option<&str>,
    ) -> rusqlite::Result<Vec<AgentPolicy>> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let filtered = q
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        if let Some(needle) = filtered {
            // Use LIKE with ESCAPE to handle % and _ safely; lowercase comparison for case-insensitive.
            let pattern = format!(
                "%{}%",
                needle
                    .to_lowercase()
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            );
            let mut stmt = conn.prepare(
                "SELECT agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants FROM agents WHERE LOWER(agent_id) LIKE ?1 ESCAPE '\\' ORDER BY agent_id ASC LIMIT ?2 OFFSET ?3",
            )?;
            let rows = stmt.query_map(params![pattern, limit, offset], |row| {
                let merchants: String = row.get(4)?;
                Ok(AgentPolicy {
                    agent_id: row.get(0)?,
                    max_cap: checked_u64(row.get::<_, i64>(1)?, 1, "max_cap")?,
                    velocity_limit: checked_u32(row.get::<_, i64>(2)?, 2, "velocity_limit")?,
                    velocity_window_secs: checked_u64(
                        row.get::<_, i64>(3)?,
                        3,
                        "velocity_window_secs",
                    )?,
                    allowed_merchants: serde_json::from_str(&merchants).unwrap_or_else(|_| {
                        merchants
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    }),
                })
            })?;
            rows.collect()
        } else {
            let mut stmt = conn.prepare(
                "SELECT agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants FROM agents ORDER BY agent_id ASC LIMIT ?1 OFFSET ?2",
            )?;
            let rows = stmt.query_map(params![limit, offset], |row| {
                let merchants: String = row.get(4)?;
                Ok(AgentPolicy {
                    agent_id: row.get(0)?,
                    max_cap: checked_u64(row.get::<_, i64>(1)?, 1, "max_cap")?,
                    velocity_limit: checked_u32(row.get::<_, i64>(2)?, 2, "velocity_limit")?,
                    velocity_window_secs: checked_u64(
                        row.get::<_, i64>(3)?,
                        3,
                        "velocity_window_secs",
                    )?,
                    allowed_merchants: serde_json::from_str(&merchants).unwrap_or_else(|_| {
                        merchants
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    }),
                })
            })?;
            rows.collect()
        }
    }
}
