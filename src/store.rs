use crate::mandates::unix_now;
use rusqlite::{params, Connection};
use std::sync::Mutex;

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
}
