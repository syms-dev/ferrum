// Local-account auth, forever -- see the plan's Global Constraints for why
// this never routes through Authelia. First-run bootstrap happens HERE,
// inside ferrumd's own startup, not via ferrum-apply -- unlike Authelia's
// own bootstrap (Phase 1.4b), which needed the privileged pre-build step
// because Authelia's user database has to exist before Authelia's own
// systemd unit starts, ferrumd's user table lives inside ferrumd's own
// already-owned database in its own already-owned state directory. No
// privilege or cross-crate coupling is needed for this.
use crate::db::Db;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const SESSION_LIFETIME_SECS: i64 = 60 * 60 * 24 * 7; // one week
const MAX_FAILURES_PER_WINDOW: i64 = 5;
const RATE_LIMIT_WINDOW_SECS: i64 = 300; // 5 minutes
const LOCKOUT_SECS: i64 = 60;

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Idempotent: does nothing if any user already exists, so a ferrumd
/// restart never resets an operator's already-changed password. Mirrors
/// ensure_first_authelia_user's exact shape (crates/ferrum-apply/src/
/// secrets.rs) -- same "generate real random value, write plaintext once
/// to a root-only 0400 file, hash the rest" pattern, just running inside
/// ferrumd's own process instead of ferrum-apply's.
pub fn ensure_first_user(db: &Db, state_dir: &Path) -> anyhow::Result<()> {
    let existing: i64 = db.conn().query_row("SELECT count(*) FROM users", [], |row| row.get(0))?;
    if existing > 0 {
        return Ok(());
    }

    let password = ferrum_secrets::random_secret_value()?;
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash bootstrap password: {e}"))?
        .to_string();

    db.conn().execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES ('admin', ?1, ?2)",
        rusqlite::params![hash, now()],
    )?;

    let setup_file = state_dir.join("ferrumd-setup-password");
    std::fs::create_dir_all(state_dir)?;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o400)
        .open(&setup_file)?;
    f.write_all(format!("{password}\n").as_bytes())?;
    Ok(())
}

pub struct LoginResult {
    pub session_token: String,
    pub csrf_token: String,
}

/// Real argon2id verification against the stored hash, with rate limiting
/// checked BEFORE the (comparatively expensive) hash verification runs --
/// a locked-out username never even reaches argon2, so a lockout can't
/// itself become a CPU-exhaustion vector.
pub fn login(db: &Db, username: &str, password: &str) -> anyhow::Result<Option<LoginResult>> {
    let window_start = now() - RATE_LIMIT_WINDOW_SECS;
    let recent_failures: i64 = db.conn().query_row(
        "SELECT count(*) FROM login_attempts WHERE username = ?1 AND succeeded = 0 AND attempted_at > ?2",
        rusqlite::params![username, window_start],
        |row| row.get(0),
    )?;
    if recent_failures >= MAX_FAILURES_PER_WINDOW {
        let last_attempt: i64 = db.conn().query_row(
            "SELECT max(attempted_at) FROM login_attempts WHERE username = ?1",
            rusqlite::params![username],
            |row| row.get(0),
        )?;
        if now() - last_attempt < LOCKOUT_SECS {
            anyhow::bail!("too many failed login attempts -- try again shortly");
        }
    }

    let row: Option<(i64, String)> = db
        .conn()
        .query_row(
            "SELECT id, password_hash FROM users WHERE username = ?1",
            rusqlite::params![username],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .ok();

    let succeeded = match &row {
        Some((_, hash)) => {
            let parsed = PasswordHash::new(hash)
                .map_err(|e| anyhow::anyhow!("stored password hash is corrupt: {e}"))?;
            Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
        }
        None => false,
    };

    db.conn().execute(
        "INSERT INTO login_attempts (username, attempted_at, succeeded) VALUES (?1, ?2, ?3)",
        rusqlite::params![username, now(), succeeded as i64],
    )?;

    if !succeeded {
        return Ok(None);
    }
    let (user_id, _) = row.expect("succeeded implies row was Some");

    let session_token = ferrum_secrets::random_secret_value()?;
    let csrf_token = ferrum_secrets::random_secret_value()?;
    db.conn().execute(
        "INSERT INTO sessions (token, user_id, csrf_token, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![session_token, user_id, csrf_token, now(), now() + SESSION_LIFETIME_SECS],
    )?;

    Ok(Some(LoginResult { session_token, csrf_token }))
}

/// Returns the session's own CSRF token if `token` is a real, unexpired
/// session -- callers use this both to authenticate a request AND to
/// validate the CSRF header on mutating requests against the SAME lookup,
/// rather than two separate queries that could disagree.
///
/// Not yet called from `main.rs`: this crate has no protected routes of
/// its own until Tasks 4/5/6 add them and build a `require_session`
/// middleware on top of it. `ferrumd` is a bin-only crate (no lib target),
/// so clippy's dead-code lint can't see that future consumption -- allowed
/// here rather than removed, since removing it would just mean re-adding
/// the same function later.
#[allow(dead_code)]
pub fn validate_session(db: &Db, token: &str) -> anyhow::Result<Option<String>> {
    db.conn()
        .query_row(
            "SELECT csrf_token FROM sessions WHERE token = ?1 AND expires_at > ?2",
            rusqlite::params![token, now()],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|e| if matches!(e, rusqlite::Error::QueryReturnedNoRows) { Ok(None) } else { Err(e.into()) })
}

pub fn logout(db: &Db, token: &str) -> anyhow::Result<()> {
    db.conn().execute("DELETE FROM sessions WHERE token = ?1", rusqlite::params![token])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn ensure_first_user_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let count_after_first: i64 = db.conn().query_row("SELECT count(*) FROM users", [], |r| r.get(0)).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let count_after_second: i64 = db.conn().query_row("SELECT count(*) FROM users", [], |r| r.get(0)).unwrap();
        assert_eq!(count_after_first, 1);
        assert_eq!(count_after_first, count_after_second, "a second call must not add a second user or reset the password");
    }

    #[test]
    fn login_succeeds_with_the_real_bootstrap_password() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let password = password.trim();
        let result = login(&db, "admin", password).unwrap();
        assert!(result.is_some(), "login with the real generated password must succeed");
    }

    #[test]
    fn login_fails_with_the_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let result = login(&db, "admin", "definitely-wrong").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn login_locks_out_after_five_failures_within_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        for _ in 0..5 {
            let _ = login(&db, "admin", "wrong").unwrap();
        }
        let result = login(&db, "admin", "wrong");
        assert!(result.is_err(), "the 6th attempt within the window must be rejected outright, not just fail auth");
    }

    #[test]
    fn validate_session_returns_none_for_an_unknown_token() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        assert_eq!(validate_session(&db, "not-a-real-token").unwrap(), None);
    }

    #[test]
    fn logout_invalidates_the_session() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let login_result = login(&db, "admin", password.trim()).unwrap().unwrap();
        assert!(validate_session(&db, &login_result.session_token).unwrap().is_some());
        logout(&db, &login_result.session_token).unwrap();
        assert_eq!(validate_session(&db, &login_result.session_token).unwrap(), None);
    }
}
