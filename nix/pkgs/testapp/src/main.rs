use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    app_version: u32,
    #[arg(long, default_value = "/var/lib/ferrum-testapp/app.db")]
    db_path: String,
    #[arg(long, default_value = "127.0.0.1:8099")]
    listen: String,
}

/// Opens (creating if absent) the database at `db_path` and reconciles its
/// `user_version` against `app_version`. Returns an error -- never panics --
/// when `app_version` is older than the database's recorded schema version,
/// mirroring how a real app (e.g. Sonarr) refuses to start against a
/// database a newer release already migrated.
fn check_schema_version(db_path: &Path, app_version: u32) -> anyhow::Result<Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(db_path)?;
    let current: u32 = conn.query_row("PRAGMA user_version;", [], |row| row.get(0))?;

    if current > app_version {
        anyhow::bail!(
            "FATAL: database schema version {current} is newer than this binary supports"
        );
    }

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            text TEXT NOT NULL
        );",
    )?;

    if app_version >= 2 {
        let has_migrated_at: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('notes') WHERE name = 'migrated_at'")?
            .exists([])?;
        if !has_migrated_at {
            conn.execute_batch("ALTER TABLE notes ADD COLUMN migrated_at TEXT;")?;
        }
    }

    if current < app_version {
        conn.execute_batch(&format!("PRAGMA user_version = {app_version};"))?;
    }

    Ok(conn)
}

#[derive(Deserialize)]
struct NewNote {
    text: String,
}

#[derive(Serialize)]
struct Note {
    id: i64,
    text: String,
}

type SharedConn = Arc<Mutex<Connection>>;

async fn ping() -> StatusCode {
    StatusCode::OK
}

async fn list_notes(State(conn): State<SharedConn>) -> Json<Vec<Note>> {
    let conn = conn.lock().unwrap();
    let mut stmt = conn.prepare("SELECT id, text FROM notes ORDER BY id").unwrap();
    let notes = stmt
        .query_map([], |row| {
            Ok(Note {
                id: row.get(0)?,
                text: row.get(1)?,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    Json(notes)
}

async fn add_note(State(conn): State<SharedConn>, Json(new_note): Json<NewNote>) -> StatusCode {
    let conn = conn.lock().unwrap();
    conn.execute("INSERT INTO notes (text) VALUES (?1)", [new_note.text])
        .unwrap();
    StatusCode::NO_CONTENT
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let conn = match check_schema_version(Path::new(&args.db_path), args.app_version) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    let shared: SharedConn = Arc::new(Mutex::new(conn));

    let app = Router::new()
        .route("/ping", get(ping))
        .route("/rows", get(list_notes))
        .route("/notes", post(add_note))
        .with_state(shared);

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn v1_refuses_a_newer_schema() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("app.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch("PRAGMA user_version = 2;").unwrap();
        }
        let err = check_schema_version(&db_path, 1).unwrap_err();
        assert!(err.to_string().contains("newer than this binary supports"));
    }

    #[test]
    fn v1_accepts_a_fresh_database() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("app.db");
        check_schema_version(&db_path, 1).unwrap();
        let conn = Connection::open(&db_path).unwrap();
        let uv: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(uv, 1);
    }

    #[test]
    fn v2_migrates_a_v1_database_and_adds_migrated_at() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("app.db");
        check_schema_version(&db_path, 1).unwrap(); // simulate a prior v1 install
        check_schema_version(&db_path, 2).unwrap();
        let conn = Connection::open(&db_path).unwrap();
        let uv: i64 = conn
            .query_row("PRAGMA user_version;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(uv, 2);
        // ALTER TABLE succeeding (not erroring on a duplicate column) proves
        // the migration path is idempotent across repeated v2 starts.
        check_schema_version(&db_path, 2).unwrap();
    }
}
