use crate::mandates::unix_now;
use rusqlite::{Connection, params};
use serde::Serialize;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct DecisionRow {
    pub id: i64,
    pub ts: i64,
    pub endpoint: String,
    pub decision: String,
    pub reason: String,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LedgerStats {
    pub total: i64,
    pub allow: i64,
    pub reject: i64,
    pub issued: i64,
}

pub struct Db(Mutex<Connection>);

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    endpoint TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    claimed_at INTEGER NOT NULL
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
        conn.execute(
            "INSERT INTO decisions (ts, endpoint, decision, reason, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![unix_now() as i64, endpoint, decision, reason, payload],
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
            "SELECT id, ts, endpoint, decision, reason, payload FROM decisions ORDER BY id DESC LIMIT ?1",
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
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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
}
