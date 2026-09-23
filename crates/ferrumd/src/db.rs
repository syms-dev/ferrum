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
                expires_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                username TEXT NOT NULL,
                attempted_at INTEGER NOT NULL,
                succeeded INTEGER NOT NULL,
                ip TEXT NOT NULL DEFAULT ''
            );
            ",
        )?;
        // `CREATE TABLE IF NOT EXISTS` does nothing to a table that already
        // exists, so a host provisioned before these columns were added
        // would keep the old shape and fail on the first query naming one.
        Self::add_column_if_missing(&conn, "login_attempts", "ip", "TEXT NOT NULL DEFAULT ''")?;
        Self::add_column_if_missing(&conn, "sessions", "last_seen_at", "INTEGER NOT NULL DEFAULT 0")?;
        // A session that predates the idle timeout has no last_seen_at, and
        // the column default of 0 would read as "idle since 1970" -- logging
        // every existing operator out the moment they upgrade. Seeding from
        // created_at gives them the remainder of a normal idle window
        // instead, which is the honest answer to "when did we last see this
        // session?" when the answer was never recorded.
        conn.execute("UPDATE sessions SET last_seen_at = created_at WHERE last_seen_at = 0", [])?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Adds one column to an existing table, if it is not already there.
    ///
    /// SQLite has no `ADD COLUMN IF NOT EXISTS`, and the obvious shortcut --
    /// running the `ALTER` unconditionally and discarding the error -- would
    /// swallow a real failure alongside the expected "duplicate column name",
    /// which is the error suppression this project treats as a defect in its
    /// own right. Reading `PRAGMA table_info` first asks the question
    /// directly, so a genuine failure still propagates.
    ///
    /// `table`, `column` and `decl` are compile-time literals from this
    /// module, never anything off the wire; SQLite does not accept bound
    /// parameters in DDL, so they are formatted in.
    ///
    /// # Arguments
    /// * `conn` - the open connection to migrate.
    /// * `table` - the table to add to.
    /// * `column` - the column name to ensure exists.
    /// * `decl` - the column's SQL type and constraints.
    ///
    /// # Errors
    /// Any SQLite failure reading the table's shape or applying the `ALTER`.
    fn add_column_if_missing(
        conn: &Connection,
        table: &str,
        column: &str,
        decl: &str,
    ) -> anyhow::Result<()> {
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let existing: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<String>, _>>()?;
        if !existing.iter().any(|name| name == column) {
            conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"), [])?;
        }
        Ok(())
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
