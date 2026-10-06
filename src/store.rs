use crate::mandates::{unix_now, unix_now_i64};
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

/// Single SQLite connection behind one mutex. Every method locks, runs
/// synchronously, and releases before returning; no guard is ever held across
/// an `.await` (verified: no `.lock()` in async handlers — `app.rs` only
/// calls these sync methods, and the sole request-path `.await`
/// (`gateway.create_order`) sits between two separate lock acquisitions).
/// Throughput ceiling: all DB work serializes on this one mutex, so peak
/// checkout rate is bounded by single-connection SQLite latency (~ms per
/// op). That is deliberate for a demo ledger; scaling out means a pool or
/// WAL-mode readers, not a redesign of this invariant.
pub struct Db(Mutex<Connection>);

/// How long a `pending` order reservation is honored before a retry may
/// reclaim it. Must comfortably exceed the gateway timeout (10s) so a slow
/// but live attempt can never have its reservation stolen mid-flight.
pub const PENDING_TTL_SECS: u64 = 300;

/// How long a claimed nonce is retained before `prune_expired` may delete it.
///
/// SAFETY PROOF (why a pruned nonce can never enable a replay): mandates live
/// at most 86_400s after issue (the `ttl_secs` validator cap in
/// `IssueRequest`; keep in sync if that cap ever changes), and
/// `policy::evaluate` rejects issues more than 60s in the future, so for a
/// nonce claimed at time C: `expires_at <= C + 86_400 + 60`. Pruning deletes
/// only rows with `claimed_at + RETENTION < now`, i.e. `now > C + 86_460`,
/// hence `now > expires_at`. `policy::evaluate` checks expiry BEFORE the
/// nonce lookup, so any replay of the pruned mandate is rejected at the
/// expiry gate. Both sides use `unix_now`, so a clock jump affects prune and
/// evaluate consistently (a backward jump only retains more rows).
pub const NONCE_RETENTION_SECS: u64 = 86_400 + 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PruneStats {
    pub nonces_deleted: u64,
    pub velocity_deleted: u64,
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
    status TEXT NOT NULL DEFAULT 'completed',
    reserved_at INTEGER NOT NULL DEFAULT 0,
    nonce TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    max_cap INTEGER NOT NULL DEFAULT 50000,
    velocity_limit INTEGER NOT NULL DEFAULT 50,
    velocity_window_secs INTEGER NOT NULL DEFAULT 60,
    allowed_merchants TEXT NOT NULL DEFAULT '[\"merchant-001\"]',
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
        // Migration v3: orders.reserved_at + orders.nonce for stale-pending reclaim.
        // reserved_at records when the pending reservation was taken; nonce records
        // which nonce claim owns it so reclaim can free exactly that claim.
        // Existing rows default to 0/'', i.e. treated as stale and reclaimable —
        // the safe direction (unblocks) since a pre-upgrade pending could only
        // come from a crashed attempt.
        let has_reserved = Self::column_exists(&conn, "orders", "reserved_at")?;
        if !has_reserved {
            conn.execute(
                "ALTER TABLE orders ADD COLUMN reserved_at INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        let has_order_nonce = Self::column_exists(&conn, "orders", "nonce")?;
        if !has_order_nonce {
            conn.execute(
                "ALTER TABLE orders ADD COLUMN nonce TEXT NOT NULL DEFAULT ''",
                [],
            )?;
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
        if version < 3 {
            conn.execute_batch("PRAGMA user_version = 3")?;
        }
        Ok(Db(Mutex::new(conn)))
    }

    /// Append a decision to the tamper-evident hash chain. The `decisions`
    /// table is an append-only audit log: rows are NEVER pruned or deleted
    /// (not even by `prune_expired`), because `verify_chain` recomputes every
    /// link from genesis and any gap fails verification.
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
            let ts = unix_now_i64();
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
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    pub fn try_claim_nonce(&self, nonce: &str) -> rusqlite::Result<bool> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let changed = conn.execute(
            "INSERT OR IGNORE INTO nonces (nonce, claimed_at) VALUES (?1, ?2)",
            params![nonce, unix_now_i64()],
        )?;
        Ok(changed > 0)
    }

    pub fn rollback_nonce(&self, nonce: &str) -> rusqlite::Result<()> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("DELETE FROM nonces WHERE nonce = ?1", params![nonce])?;
        Ok(())
    }

    /// Delete expired nonces and dead velocity windows. See
    /// `NONCE_RETENTION_SECS` for why pruned nonces cannot enable replays.
    /// `decisions` is deliberately never touched: it is an append-only audit
    /// log and deleting rows would break `verify_chain`.
    pub fn prune_expired(&self) -> rusqlite::Result<PruneStats> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now_i64();
        let nonce_cutoff = now.saturating_sub(NONCE_RETENTION_SECS as i64);
        let nonces_deleted = conn.execute(
            "DELETE FROM nonces WHERE claimed_at < ?1",
            params![nonce_cutoff],
        )? as u64;
        // A velocity row (agent_id, window_start) can only ever match again
        // if its window_start equals a future current window, and current
        // windows are always >= now - window_secs. Deleting rows older than
        // now minus the longest *currently configured* window is therefore
        // safe. (If an operator later raises a window past this horizon, the
        // worst case is one stale window under-counting — documented, harmless
        // for a rate limiter.)
        let max_window: i64 = conn.query_row(
            "SELECT COALESCE(MAX(velocity_window_secs), 60) FROM agents",
            [],
            |r| r.get(0),
        )?;
        let velocity_cutoff = now.saturating_sub(max_window.max(1));
        let velocity_deleted = conn.execute(
            "DELETE FROM agent_velocity WHERE window_start < ?1",
            params![velocity_cutoff],
        )? as u64;
        Ok(PruneStats {
            nonces_deleted,
            velocity_deleted,
        })
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
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT order_id FROM orders WHERE mandate_id = ?1 AND status = 'completed'",
        )?;
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
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT OR IGNORE INTO orders (mandate_id, order_id, amount, created_at, status) VALUES (?1, ?2, ?3, ?4, 'completed')",
            params![mandate_id, order_id, amount as i64, unix_now_i64()],
        )?;
        Ok(())
    }

    /// C4: atomic pending reservation claimed *before* gateway call.
    /// Returns true if reservation succeeded (we own the mandate), false if another request already holds it.
    ///
    /// A `pending` row older than `PENDING_TTL_SECS` is treated as orphaned
    /// (crash between reserve and finalize/clear) and atomically reclaimed:
    /// the original attempt's nonce claim is freed and the row is retaken.
    /// Fresh pending rows are never stolen. The whole check runs inside
    /// `BEGIN IMMEDIATE` so concurrent reservers serialize.
    pub fn try_reserve_order(
        &self,
        mandate_id: &str,
        nonce: &str,
        amount: u64,
    ) -> rusqlite::Result<bool> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("BEGIN IMMEDIATE", [])?;
        let result: rusqlite::Result<bool> = (|| {
            let now = unix_now_i64();
            let changed = conn.execute(
                "INSERT OR IGNORE INTO orders (mandate_id, order_id, amount, created_at, status, reserved_at, nonce) VALUES (?1, '__PENDING__', ?2, ?3, 'pending', ?3, ?4)",
                params![mandate_id, amount as i64, now, nonce],
            )?;
            if changed > 0 {
                return Ok(true);
            }
            let (status, reserved_at, stored_nonce): (String, i64, String) = conn.query_row(
                "SELECT status, reserved_at, nonce FROM orders WHERE mandate_id = ?1",
                params![mandate_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            if status != "pending" {
                // Completed order: someone already owns this mandate_id.
                return Ok(false);
            }
            if now - reserved_at < PENDING_TTL_SECS as i64 {
                // Fresh pending: live attempt in flight, never steal.
                return Ok(false);
            }
            // Stale pending: reclaim. Free exactly the original attempt's nonce
            // claim (the retry re-claims via evaluate), then retake the row.
            // The caller's own nonce claim (made in evaluate before reserve) is
            // untouched unless it is the same value, in which case freeing it is
            // precisely what lets the retry proceed.
            if !stored_nonce.is_empty() {
                conn.execute("DELETE FROM nonces WHERE nonce = ?1", params![stored_nonce])?;
            }
            conn.execute(
                "UPDATE orders SET order_id = '__PENDING__', amount = ?1, created_at = ?2, reserved_at = ?2, nonce = ?3 WHERE mandate_id = ?4 AND status = 'pending'",
                params![amount as i64, now, nonce, mandate_id],
            )?;
            Ok(true)
        })();
        match result {
            Ok(v) => {
                conn.execute("COMMIT", [])?;
                Ok(v)
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
    }

    /// Delete a stale `pending` reservation (and free its nonce claim) without
    /// taking it over. Used before `evaluate` so a retry of a crashed attempt
    /// is not rejected as a replayed nonce. Returns true if anything was
    /// reclaimed. Fresh pending rows are never touched.
    pub fn reclaim_stale_pending(&self, mandate_id: &str) -> rusqlite::Result<bool> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute("BEGIN IMMEDIATE", [])?;
        let result: rusqlite::Result<bool> = (|| {
            let now = unix_now_i64();
            let row: Option<(String, i64, String)> = match conn.query_row(
                "SELECT status, reserved_at, nonce FROM orders WHERE mandate_id = ?1",
                params![mandate_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ) {
                Ok(v) => Some(v),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(e),
            };
            let Some((status, reserved_at, stored_nonce)) = row else {
                return Ok(false);
            };
            if status != "pending" || now - reserved_at < PENDING_TTL_SECS as i64 {
                return Ok(false);
            }
            if !stored_nonce.is_empty() {
                conn.execute("DELETE FROM nonces WHERE nonce = ?1", params![stored_nonce])?;
            }
            conn.execute(
                "DELETE FROM orders WHERE mandate_id = ?1 AND status = 'pending'",
                params![mandate_id],
            )?;
            Ok(true)
        })();
        match result {
            Ok(v) => {
                conn.execute("COMMIT", [])?;
                Ok(v)
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(e)
            }
        }
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

    pub fn get_or_create_agent(&self, agent_id: &str) -> rusqlite::Result<AgentPolicy> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut stmt = conn.prepare(
            "SELECT agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants FROM agents WHERE agent_id = ?1"
        )?;
        let mut rows = stmt.query(params![agent_id])?;
        if let Some(row) = rows.next()? {
            let merchants: String = row.get(4)?;
            Ok(AgentPolicy {
                agent_id: row.get(0)?,
                // try_from fails closed (0) on corrupt negative rows instead of
                // wrapping to huge caps via `as`.
                max_cap: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                velocity_limit: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                velocity_window_secs: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
                allowed_merchants: serde_json::from_str(&merchants).unwrap_or_else(|_| {
                    merchants
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }),
            })
        } else {
            let now = unix_now_i64();
            conn.execute(
                "INSERT INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at)
                 VALUES (?1, 50000, 50, 60, '[\"merchant-001\"]', ?2, ?2)",
                params![agent_id, now],
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
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now();
        conn.execute(
            "INSERT OR IGNORE INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at)
             VALUES (?1, 50000, 50, 60, '[\"merchant-001\"]', ?2, ?2)",
            params![agent_id, unix_now_i64()],
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

    /// Current velocity count for the agent's active window (0 if none).
    pub fn velocity_count(&self, agent_id: &str) -> rusqlite::Result<i64> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now_i64();
        let window_secs: Option<i64> = match conn.query_row(
            "SELECT velocity_window_secs FROM agents WHERE agent_id = ?1",
            params![agent_id],
            |r| r.get(0),
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e),
        };
        let Some(window_secs) = window_secs else {
            return Ok(0);
        };
        if window_secs <= 0 {
            return Ok(0);
        }
        let window_start = now - (now % window_secs);
        let count: i64 = conn
            .query_row(
                "SELECT count FROM agent_velocity WHERE agent_id = ?1 AND window_start = ?2",
                params![agent_id, window_start],
                |r| r.get(0),
            )
            .unwrap_or(0);
        Ok(count)
    }

    /// Compensating decrement for a velocity slot consumed by a request that
    /// ultimately did not place an order (e.g. gateway failure). Saturates at
    /// zero. This only ever lowers the count, so it cannot let concurrent
    /// requests exceed the limit: admission (`check_velocity`) still
    /// increments-then-compares atomically under the mutex.
    pub fn refund_velocity(&self, agent_id: &str) -> rusqlite::Result<()> {
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now_i64();
        let window_secs: i64 = match conn.query_row(
            "SELECT velocity_window_secs FROM agents WHERE agent_id = ?1",
            params![agent_id],
            |r| r.get(0),
        ) {
            Ok(v) => v,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(()),
            Err(e) => return Err(e),
        };
        if window_secs <= 0 {
            return Ok(());
        }
        let window_start = now - (now % window_secs);
        conn.execute(
            "UPDATE agent_velocity SET count = CASE WHEN count > 0 THEN count - 1 ELSE 0 END WHERE agent_id = ?1 AND window_start = ?2",
            params![agent_id, window_start],
        )?;
        Ok(())
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
                // try_from fails closed (0) on corrupt negative rows instead of
                // wrapping to huge caps via `as`.
                max_cap: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                velocity_limit: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                velocity_window_secs: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
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
        let now = unix_now_i64();
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
                params![v as i64, unix_now_i64(), agent_id],
            )?;
        }
        if let Some(v) = velocity_limit {
            conn.execute(
                "UPDATE agents SET velocity_limit = ?1, updated_at = ?2 WHERE agent_id = ?3",
                params![v as i64, unix_now_i64(), agent_id],
            )?;
        }
        if let Some(v) = velocity_window_secs {
            conn.execute(
                "UPDATE agents SET velocity_window_secs = ?1, updated_at = ?2 WHERE agent_id = ?3",
                params![v as i64, unix_now_i64(), agent_id],
            )?;
        }
        if let Some(v) = allowed_merchants {
            let merchants = serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string());
            conn.execute(
                "UPDATE agents SET allowed_merchants = ?1, updated_at = ?2 WHERE agent_id = ?3",
                params![merchants, unix_now_i64(), agent_id],
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
            // try_from fails closed (0) on corrupt negative rows.
            max_cap: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
            velocity_limit: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
            velocity_window_secs: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
            allowed_merchants: serde_json::from_str(&merchants).unwrap_or_else(|_| {
                merchants
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            }),
        })
    }

    /// Atomic insert for `POST /v1/agents` — returns `true` if a new row was inserted,
    /// `false` if the agent already existed. Caller must map `false` to `400 already exists`
    /// without a prior `SELECT` to avoid TOCTOU.
    pub fn try_create_agent(
        &self,
        agent_id: &str,
        max_cap: Option<u64>,
        velocity_limit: Option<u32>,
        velocity_window_secs: Option<u64>,
        allowed_merchants: Option<Vec<String>>,
    ) -> rusqlite::Result<bool> {
        let max_cap_val = max_cap.unwrap_or(50000) as i64;
        let velocity_limit_val = velocity_limit.unwrap_or(50) as i64;
        let velocity_window_secs_val = velocity_window_secs.unwrap_or(60) as i64;
        let merchants = match allowed_merchants {
            Some(v) => serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string()),
            None => r#"["merchant-001"]"#.to_string(),
        };
        let conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let now = unix_now_i64();
        let changed = conn.execute(
            "INSERT OR IGNORE INTO agents (agent_id, max_cap, velocity_limit, velocity_window_secs, allowed_merchants, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
            params![
                agent_id,
                max_cap_val,
                velocity_limit_val,
                velocity_window_secs_val,
                merchants,
                now
            ],
        )?;
        Ok(changed > 0)
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
                // try_from fails closed (0) on corrupt negative rows instead of
                // wrapping to huge caps via `as`.
                max_cap: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                velocity_limit: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                velocity_window_secs: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
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
    /// NOTE: the `LOWER(agent_id) LIKE ?` leading-wildcard search cannot use
    /// an index (full scan of `agents`). That is acceptable because this is
    /// only reachable from the admin/search path (`GET /v1/agents`, used by
    /// the dashboard) — never from the payment hot path (`issue`/`checkout`,
    /// which use PK lookups). Do not call this from checkout.
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
            // Use LIKE with ESCAPE '\' to handle \, % and _ safely (backslash
            // first, or the escapes themselves become wildcards); lowercase
            // comparison for case-insensitive.
            let pattern = format!(
                "%{}%",
                needle
                    .to_lowercase()
                    .replace('\\', "\\\\")
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
                    // try_from fails closed (0) on corrupt negative rows.
                    max_cap: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    velocity_limit: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    velocity_window_secs: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
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
                    // try_from fails closed (0) on corrupt negative rows.
                    max_cap: u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0),
                    velocity_limit: u32::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    velocity_window_secs: u64::try_from(row.get::<_, i64>(3)?).unwrap_or(0),
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
