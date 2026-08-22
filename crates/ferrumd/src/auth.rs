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

/// Everything `require_session` needs about a session, from ONE lookup.
///
/// This used to be a bare `String` (the CSRF token). `POST /api/password`
/// needs the session's own user id as well -- a password change must apply
/// to the caller's own account and to nothing else -- and getting it from a
/// second query against the same token would be two lookups that could
/// disagree (a session deleted between them, a token rebound). Returning
/// both from the single row that already carries them keeps
/// "who is this?" and "is this request forged?" answered by the same read.
pub struct SessionInfo {
    pub user_id: i64,
    pub csrf_token: String,
}

/// Returns the session's own identity and CSRF token if `token` is a real,
/// unexpired session -- callers use this both to authenticate a request AND
/// to validate the CSRF header on mutating requests against the SAME
/// lookup, rather than two separate queries that could disagree.
///
/// Called from `main.rs`'s `require_session` middleware (Task 4), which
/// gates `/api/settings` behind a valid session cookie.
pub fn validate_session(db: &Db, token: &str) -> anyhow::Result<Option<SessionInfo>> {
    db.conn()
        .query_row(
            "SELECT user_id, csrf_token FROM sessions WHERE token = ?1 AND expires_at > ?2",
            rusqlite::params![token, now()],
            |row| Ok(SessionInfo { user_id: row.get(0)?, csrf_token: row.get(1)? }),
        )
        .map(Some)
        .or_else(|e| if matches!(e, rusqlite::Error::QueryReturnedNoRows) { Ok(None) } else { Err(e.into()) })
}

/// Rotates one user's own password, after really verifying the current one.
///
/// Returns `Ok(false)` -- deliberately NOT an error -- when
/// `current_password` does not verify against the stored hash, so the HTTP
/// handler can map that one case to a real `401` while a genuine database
/// or hashing failure still becomes a `500`. Collapsing the two would
/// either tell an operator who mistyped their password that the daemon is
/// broken, or tell them a broken daemon is a wrong password.
///
/// The new hash is produced exactly the way `ensure_first_user` produces
/// the bootstrap one -- a fresh `SaltString::generate(&mut OsRng)` per
/// call, `Argon2::default()` -- so a rotated password is stored in the same
/// real argon2id form `login` already verifies against, with its own new
/// salt rather than the old row's.
///
/// No length or complexity rules, on purpose: this project generates real
/// random secrets rather than gatekeeping human-chosen ones on complexity
/// theater. An EMPTY new password is still refused, because that is not a
/// weak password, it is the absence of one -- and it would leave an account
/// whose "correct" credential is the empty string.
pub fn change_password(
    db: &Db,
    user_id: i64,
    current_password: &str,
    new_password: &str,
) -> anyhow::Result<bool> {
    if new_password.is_empty() {
        anyhow::bail!("the new password must not be empty");
    }

    let stored: Option<String> = db
        .conn()
        .query_row(
            "SELECT password_hash FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |row| row.get(0),
        )
        .ok();
    // An authenticated session whose user row has vanished is not a wrong
    // password, but it is also not something to hand a 500 for: there is
    // nothing to rotate, and refusing is the only safe answer.
    let Some(stored) = stored else { return Ok(false) };

    let parsed = PasswordHash::new(&stored)
        .map_err(|e| anyhow::anyhow!("stored password hash is corrupt: {e}"))?;
    if Argon2::default()
        .verify_password(current_password.as_bytes(), &parsed)
        .is_err()
    {
        return Ok(false);
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(new_password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("failed to hash the new password: {e}"))?
        .to_string();
    db.conn().execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        rusqlite::params![hash, user_id],
    )?;
    Ok(true)
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
        assert!(validate_session(&db, "not-a-real-token").unwrap().is_none());
    }

    #[test]
    fn validate_session_returns_the_sessions_own_user_id() {
        // The half `POST /api/password` depends on: the middleware must be
        // able to say WHICH account this session belongs to, from the same
        // row it reads the CSRF token out of.
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let result = login(&db, "admin", password.trim()).unwrap().unwrap();
        let session = validate_session(&db, &result.session_token).unwrap().unwrap();
        let admin_id: i64 = db
            .conn()
            .query_row("SELECT id FROM users WHERE username = 'admin'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(session.user_id, admin_id);
        assert_eq!(session.csrf_token, result.csrf_token);
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
        assert!(validate_session(&db, &login_result.session_token).unwrap().is_none());
    }

    /// A real bootstrapped database, its real generated password, and the
    /// real user id that password belongs to.
    fn bootstrapped() -> (tempfile::TempDir, Db, String, i64) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let user_id: i64 = db
            .conn()
            .query_row("SELECT id FROM users WHERE username = 'admin'", [], |r| r.get(0))
            .unwrap();
        (dir, db, password.trim().to_string(), user_id)
    }

    fn stored_hash(db: &Db, user_id: i64) -> String {
        db.conn()
            .query_row(
                "SELECT password_hash FROM users WHERE id = ?1",
                rusqlite::params![user_id],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn change_password_refuses_a_wrong_current_password_without_erroring() {
        let (_dir, db, _password, user_id) = bootstrapped();
        let before = stored_hash(&db, user_id);
        // Ok(false), NOT Err: the handler maps this exact case to 401, and a
        // genuine database failure to 500. They must stay distinguishable.
        let result = change_password(&db, user_id, "definitely-not-the-password", "a-new-one");
        assert!(
            !result.unwrap(),
            "a wrong current password must be a refusal, not an error"
        );
        assert_eq!(
            stored_hash(&db, user_id),
            before,
            "a refused rotation must not have touched the stored hash"
        );
    }

    #[test]
    fn a_refused_rotation_leaves_the_original_password_working() {
        let (_dir, db, password, user_id) = bootstrapped();
        assert!(!change_password(&db, user_id, "wrong", "attempted-new").unwrap());
        assert!(
            login(&db, "admin", &password).unwrap().is_some(),
            "the original password must still work after a refused rotation"
        );
        assert!(
            login(&db, "admin", "attempted-new").unwrap().is_none(),
            "the password the refused call proposed must never have been set"
        );
    }

    #[test]
    fn change_password_really_rotates_the_credential_login_checks() {
        let (_dir, db, password, user_id) = bootstrapped();
        let before = stored_hash(&db, user_id);

        assert!(change_password(&db, user_id, &password, "a-real-new-password").unwrap());

        let after = stored_hash(&db, user_id);
        assert_ne!(before, after, "the stored hash must really have changed");
        assert!(
            after.starts_with("$argon2"),
            "the new credential must be stored as a real argon2 hash, got: {after}"
        );

        // The property that actually matters, asserted through the REAL
        // login path rather than by inspecting the hash: the new password
        // works and the old one does not.
        assert!(
            login(&db, "admin", "a-real-new-password").unwrap().is_some(),
            "a real login with the new password must succeed"
        );
        assert!(
            login(&db, "admin", &password).unwrap().is_none(),
            "the OLD password must stop working -- otherwise the rotation added a credential rather than replacing one"
        );
    }

    #[test]
    fn change_password_rejects_an_empty_new_password() {
        let (_dir, db, password, user_id) = bootstrapped();
        let result = change_password(&db, user_id, &password, "");
        assert!(result.is_err(), "an empty new password is the absence of a credential, not a weak one");
        assert!(
            login(&db, "admin", &password).unwrap().is_some(),
            "the rejection must have changed nothing"
        );
    }

    #[test]
    fn change_password_refuses_a_session_whose_user_no_longer_exists() {
        let (_dir, db, password, _user_id) = bootstrapped();
        // No user with id 9999 -- refuse rather than panic or 500.
        assert!(!change_password(&db, 9999, &password, "new").unwrap());
    }

    #[test]
    fn rotating_twice_really_re_salts_rather_than_reusing_the_old_salt() {
        let (_dir, db, password, user_id) = bootstrapped();
        assert!(change_password(&db, user_id, &password, "same-value").unwrap());
        let first = stored_hash(&db, user_id);
        assert!(change_password(&db, user_id, "same-value", "same-value").unwrap());
        let second = stored_hash(&db, user_id);
        assert_ne!(
            first, second,
            "the same password hashed twice must differ -- a fresh salt per rotation"
        );
        assert!(login(&db, "admin", "same-value").unwrap().is_some());
    }
}
