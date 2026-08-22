// ferrumd's own SQLite database at /var/lib/ferrum/ferrumd.db (on @root,
// per modules/core/storage.nix's existing invariant -- this file never
// creates that directory itself, it's provisioned the same way
// /var/lib/ferrum already is for ferrum-apply's own journal).
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

// rusqlite::Connection is not Sync (it wraps interior-mutable caches), so
// it can't be shared across axum's worker threads via Arc<AppState>
// directly -- a Mutex makes that share safe. This doesn't change access
// patterns in practice: SQLite already serializes writers on a single
// connection, so callers were never getting real concurrency here anyway.
#[derive(Debug)]
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)
            .map_err(|e| anyhow::anyhow!("failed to open ferrumd database at {}: {e}", path.display()))?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                csrf_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT NOT NULL,
                attempted_at INTEGER NOT NULL,
                succeeded INTEGER NOT NULL
            );
            ",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().expect("ferrumd database mutex was poisoned by a prior panic")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_creates_all_three_tables() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        let count: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('users','sessions','login_attempts')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn open_is_idempotent_against_an_existing_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        Db::open(&path).unwrap();
        let result = Db::open(&path);
        assert!(result.is_ok(), "opening an already-initialized database must not fail: {result:?}");
    }
}
