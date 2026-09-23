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

/// How long a session may sit unused before it stops being accepted.
///
/// The absolute lifetime above is a week, which on its own means a session
/// token lifted from a laptop stays good for a week of silence. A day of
/// actual inactivity is the ceiling instead; any request refreshes it, so an
/// operator who opens the dashboard even once a day never sees a logout, and
/// one who does not was not using the session anyway.
const IDLE_TIMEOUT_SECS: i64 = 60 * 60 * 24;
const MAX_FAILURES_PER_WINDOW: i64 = 5;
const RATE_LIMIT_WINDOW_SECS: i64 = 300; // 5 minutes
const LOCKOUT_SECS: i64 = 60;

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Deliberately synchronous and deliberately NOT wrapped in `spawn_blocking`
/// by its caller: this runs once in `main`, before the listener binds, so
/// there is no request path to block and no other task to starve. Its argon2
/// hash and `std::fs` writes are the same blocking calls that had to move off
/// the executor everywhere else -- the difference is where they run, not what
/// they do. `Db::open`, immediately above it in `main`, is startup-only for
/// the same reason.
///
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

/// What a login attempt actually was.
///
/// Three outcomes rather than `Option` plus a stringly-typed error, because
/// the handler has to map them to three different status codes and the old
/// shape made that impossible: "throttled" arrived as an `anyhow::Error`,
/// indistinguishable from a database failure, so `login_handler` answered
/// **429 with the raw error text** for both -- the wrong status for a real
/// fault, and internal detail on the one unauthenticated endpoint reachable
/// from the internet (L-03). Making the expected outcomes values leaves
/// `Err` meaning only "the daemon genuinely failed".
pub enum LoginOutcome {
    Success(LoginResult),
    /// No such user, or the password did not verify.
    BadCredentials,
    /// This source has failed too often too recently.
    Throttled,
}

impl LoginOutcome {
    /// The session this attempt produced, if it produced one.
    ///
    /// Collapses the two non-success outcomes, so a caller that only needs
    /// "did this log in?" does not have to match all three. The handler does
    /// NOT use this -- it must tell a wrong password from a throttle to pick
    /// a status code, which is the whole reason the enum exists. Which is
    /// also why it is `cfg(test)`: every production caller needs all three
    /// outcomes, so a non-test use of this would be a bug rather than a
    /// convenience.
    #[cfg(test)]
    pub fn session(self) -> Option<LoginResult> {
        match self {
            LoginOutcome::Success(result) => Some(result),
            LoginOutcome::BadCredentials | LoginOutcome::Throttled => None,
        }
    }
}

/// How far back failures are counted when deciding to throttle a source.
const PRUNE_AFTER_SECS: i64 = RATE_LIMIT_WINDOW_SECS;

/// Real argon2id verification against the stored hash, throttled PER SOURCE
/// ADDRESS rather than per username.
///
/// The username key was a remote denial of service, and the reason is worth
/// stating plainly: the throttle denied the *correct* password too, and the
/// key was a value the attacker chose. Anyone on the internet could hold the
/// sole `admin` account locked out indefinitely, at one attempt per 60s,
/// without ever knowing a credential. The lockout was the attack.
///
/// Keyed on the source address instead, an attacker can only ever throttle
/// themselves. The operator at a different address is unaffected, so the
/// remote lockout is not mitigated but gone -- there is no longer a key a
/// third party can push the operator's requests into. A *global* limit was
/// considered and rejected for the same reason in stronger form: it would
/// let one attacker lock out everybody.
///
/// The username is still recorded on every attempt. It is evidence for the
/// audit log, and no longer a gate.
///
/// The check still runs BEFORE argon2, which is the one thing worth keeping
/// from the original design: verification is deliberately expensive, so a
/// throttled source must not be able to make the daemon do it. That does
/// mean a throttled source is refused even with the right password -- but it
/// is a 60-second cooldown on the source's own address, self-clearing, and
/// unreachable by anyone else. For a single-operator appliance that is the
/// right trade: an operator who mistypes five times waits a minute, where
/// before a stranger could lock them out for as long as they cared to.
///
/// # Arguments
/// * `db` - the open database.
/// * `username` - the submitted username, recorded but never a throttle key.
/// * `password` - the submitted password.
/// * `throttle_key` - the caller's source identity, from
///   `ClientAddr::throttle_key`. Never anything the caller can choose: see
///   `client_addr.rs` for why the address behind nginx is trustworthy and
///   `X-Forwarded-For` is not.
///
/// # Errors
/// A database failure, a corrupt stored hash, or an RNG failure. Never a
/// wrong password and never a throttle -- both of those are `Ok`.
pub fn login(
    db: &Db,
    username: &str,
    password: &str,
    throttle_key: &str,
) -> anyhow::Result<LoginOutcome> {
    // Bounded here rather than by a timer: `login_attempts` is pure throttle
    // state with no value once it ages out, and before this the table grew
    // without limit on attacker-chosen usernames -- an unauthenticated remote
    // write primitive against the daemon's own disk. Pruning at the one place
    // that inserts keeps it self-limiting with nothing to schedule.
    db.conn().execute(
        "DELETE FROM login_attempts WHERE attempted_at < ?1",
        rusqlite::params![now() - PRUNE_AFTER_SECS],
    )?;

    let window_start = now() - RATE_LIMIT_WINDOW_SECS;
    let recent_failures: i64 = db.conn().query_row(
        "SELECT count(*) FROM login_attempts WHERE ip = ?1 AND succeeded = 0 AND attempted_at > ?2",
        rusqlite::params![throttle_key, window_start],
        |row| row.get(0),
    )?;
    if recent_failures >= MAX_FAILURES_PER_WINDOW {
        // `max` over an empty set is NULL, which is why this reads as an
        // Option rather than an i64: pruning can remove every row for a
        // source between the count above and this lookup.
        let last_attempt: Option<i64> = db.conn().query_row(
            "SELECT max(attempted_at) FROM login_attempts WHERE ip = ?1",
            rusqlite::params![throttle_key],
            |row| row.get(0),
        )?;
        if let Some(last_attempt) = last_attempt {
            if now() - last_attempt < LOCKOUT_SECS {
                return Ok(LoginOutcome::Throttled);
            }
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
        "INSERT INTO login_attempts (username, attempted_at, succeeded, ip) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![username, now(), succeeded as i64, throttle_key],
    )?;

    if !succeeded {
        return Ok(LoginOutcome::BadCredentials);
    }
    let (user_id, _) = row.expect("succeeded implies row was Some");

    let session_token = ferrum_secrets::random_secret_value()?;
    let csrf_token = ferrum_secrets::random_secret_value()?;
    db.conn().execute(
        "INSERT INTO sessions (token, user_id, csrf_token, created_at, expires_at, last_seen_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?4)",
        rusqlite::params![session_token, user_id, csrf_token, now(), now() + SESSION_LIFETIME_SECS],
    )?;
    // Login is the only thing that creates a session, so it is the natural
    // place to clear out the dead ones.
    prune_sessions(db)?;

    Ok(LoginOutcome::Success(LoginResult { session_token, csrf_token }))
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
    let session: Option<SessionInfo> = db
        .conn()
        .query_row(
            "SELECT user_id, csrf_token FROM sessions \
             WHERE token = ?1 AND expires_at > ?2 AND last_seen_at > ?3",
            rusqlite::params![token, now(), now() - IDLE_TIMEOUT_SECS],
            |row| Ok(SessionInfo { user_id: row.get(0)?, csrf_token: row.get(1)? }),
        )
        .map(Some)
        .or_else(|e| {
            if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                Ok(None)
            } else {
                Err(anyhow::Error::from(e))
            }
        })?;

    // Only a session that just passed the check is refreshed. Touching the
    // row first would keep an already-idle session alive forever, since
    // every rejected request would push its own deadline forward.
    if session.is_some() {
        db.conn().execute(
            "UPDATE sessions SET last_seen_at = ?1 WHERE token = ?2",
            rusqlite::params![now(), token],
        )?;
    }
    Ok(session)
}

/// Deletes sessions that are past their absolute lifetime or their idle
/// window.
///
/// Expired rows were never removed at all, so the table only ever grew --
/// one row per login, kept forever. Called from `login`, which is the only
/// thing that creates them, so the table stays bounded with nothing to
/// schedule.
///
/// # Errors
/// Any SQLite failure performing the delete.
fn prune_sessions(db: &Db) -> anyhow::Result<()> {
    db.conn().execute(
        "DELETE FROM sessions WHERE expires_at <= ?1 OR last_seen_at <= ?2",
        rusqlite::params![now(), now() - IDLE_TIMEOUT_SECS],
    )?;
    Ok(())
}

/// Resolves an authenticated user id to that user's username.
///
/// Takes the id `require_session` just authenticated, never anything off the
/// wire -- the same rule `change_password` follows, for the same reason.
///
/// `Ok(None)` means the session referenced a user row that no longer exists.
/// That is a database inconsistency rather than a normal outcome (a session
/// should not outlive its user), so it is reported distinctly instead of
/// being flattened into an empty username the UI would render as a blank.
pub fn username_for(db: &Db, user_id: i64) -> anyhow::Result<Option<String>> {
    db.conn()
        .query_row(
            "SELECT username FROM users WHERE id = ?1",
            rusqlite::params![user_id],
            |row| row.get(0),
        )
        .map(Some)
        .or_else(|e| {
            if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                Ok(None)
            } else {
                Err(e.into())
            }
        })
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
    keep_token: &str,
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
    // M-03. Changing the password is the one thing an operator does when
    // they believe their credential is compromised, and it used to
    // invalidate nothing: a stolen session survived the remedy and stayed
    // good for the rest of its week. Every OTHER session for this account
    // goes; the caller's own stays, so the operator is not logged out of the
    // tab they just used.
    db.conn().execute(
        "DELETE FROM sessions WHERE user_id = ?1 AND token != ?2",
        rusqlite::params![user_id, keep_token],
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

    /// One source address, for the tests that are not about the throttle.
    /// Real callers get this from `ClientAddr::throttle_key`.
    const TEST_CLIENT: &str = "peer:127.0.0.1";

    /// A second, different source -- the whole point of M-02 is that these
    /// two cannot affect each other.
    const OTHER_CLIENT: &str = "x-real-ip:203.0.113.7";

    /// Stands in for "the session the caller is making this request from",
    /// which `change_password` keeps while deleting the account's others.
    /// Deliberately not a token any test creates, so a test that means to
    /// keep a REAL session has to pass that session's own token.
    const KEPT_SESSION: &str = "the-callers-own-session-token";

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
        let result = login(&db, "admin", password, TEST_CLIENT).unwrap();
        assert!(
            result.session().is_some(),
            "login with the real generated password must succeed"
        );
    }

    #[test]
    fn login_fails_with_the_wrong_password() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let result = login(&db, "admin", "definitely-wrong", TEST_CLIENT).unwrap();
        assert!(result.session().is_none());
    }

    #[test]
    fn login_throttles_a_source_after_five_failures_within_the_window() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        for _ in 0..5 {
            let _ = login(&db, "admin", "wrong", TEST_CLIENT).unwrap();
        }
        // Ok(Throttled), NOT Err: the handler maps this to 429 and a real
        // database failure to 500. Collapsing them is L-03, where a database
        // error answered 429 carrying its own text.
        assert!(
            matches!(
                login(&db, "admin", "wrong", TEST_CLIENT).unwrap(),
                LoginOutcome::Throttled
            ),
            "the 6th attempt from one source within the window must be throttled outright"
        );
    }

    /// M-02's headline property, and the reason the key changed.
    ///
    /// The throttle used to be keyed on the submitted USERNAME, so any
    /// remote caller could burn five attempts against `admin` and hold the
    /// only account on the appliance locked out -- the lockout denied the
    /// correct password too, so this was a complete, unauthenticated denial
    /// of service, renewable forever at one attempt per 60s.
    ///
    /// Keyed on the source address, the attacker throttles nobody but
    /// themselves.
    #[test]
    fn one_source_cannot_lock_out_another() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let password = password.trim();

        // The attacker, from their own address, burns well past the limit
        // against the real operator's username.
        for _ in 0..20 {
            let _ = login(&db, "admin", "wrong", OTHER_CLIENT).unwrap();
        }
        assert!(
            matches!(
                login(&db, "admin", "wrong", OTHER_CLIENT).unwrap(),
                LoginOutcome::Throttled
            ),
            "the attacker must have throttled THEMSELVES"
        );

        // The operator, from a different address, logs in with the correct
        // password and is completely unaffected.
        assert!(
            login(&db, "admin", password, TEST_CLIENT).unwrap().session().is_some(),
            "a remote attacker must NOT be able to lock the operator out of their own appliance"
        );
    }

    /// The other half of M-02: `login_attempts` grew without limit on
    /// attacker-chosen usernames, so an unauthenticated caller could write
    /// to the daemon's disk indefinitely. Rows older than the window carry
    /// no throttle meaning, so they are deleted at the one place that
    /// inserts them.
    #[test]
    fn login_attempts_older_than_the_window_are_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();

        // Rows far older than the window, as a flood of distinct usernames
        // would have left behind.
        let stale = now() - PRUNE_AFTER_SECS - 3600;
        for i in 0..50 {
            db.conn()
                .execute(
                    "INSERT INTO login_attempts (username, attempted_at, succeeded, ip) \
                     VALUES (?1, ?2, 0, ?3)",
                    rusqlite::params![format!("victim-{i}"), stale, OTHER_CLIENT],
                )
                .unwrap();
        }
        let before: i64 = db
            .conn()
            .query_row("SELECT count(*) FROM login_attempts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(before, 50, "the stale rows must really have been inserted");

        let _ = login(&db, "admin", "wrong", TEST_CLIENT).unwrap();

        let remaining: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM login_attempts WHERE attempted_at = ?1",
                rusqlite::params![stale],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0, "every row older than the window must have been pruned");
    }

    /// Pruning must not quietly discard the rows the throttle is currently
    /// counting -- a prune that took everything would make the throttle
    /// unreachable, which looks identical to a working one until somebody
    /// actually attacks it.
    #[test]
    fn pruning_keeps_the_attempts_the_throttle_still_needs() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        ensure_first_user(&db, dir.path()).unwrap();
        for _ in 0..5 {
            let _ = login(&db, "admin", "wrong", TEST_CLIENT).unwrap();
        }
        let fresh: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM login_attempts WHERE ip = ?1",
                rusqlite::params![TEST_CLIENT],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(fresh, 5, "recent attempts must survive the prune");
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
        let result = login(&db, "admin", password.trim(), TEST_CLIENT).unwrap().session().unwrap();
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
        let login_result = login(&db, "admin", password.trim(), TEST_CLIENT).unwrap().session().unwrap();
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

    fn last_seen(db: &Db, token: &str) -> i64 {
        db.conn()
            .query_row(
                "SELECT last_seen_at FROM sessions WHERE token = ?1",
                rusqlite::params![token],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// M-03's headline: a password change is what an operator does when they
    /// think a session has been stolen, and it used to revoke nothing at all
    /// -- the stolen session outlived the remedy by the rest of its week.
    #[test]
    fn a_password_change_invalidates_every_other_session_but_not_the_callers() {
        let (_dir, db, password, user_id) = bootstrapped();
        let mine = login(&db, "admin", &password, TEST_CLIENT).unwrap().session().unwrap();
        let another_tab =
            login(&db, "admin", &password, TEST_CLIENT).unwrap().session().unwrap();
        let stolen = login(&db, "admin", &password, OTHER_CLIENT).unwrap().session().unwrap();
        assert!(validate_session(&db, &stolen.session_token).unwrap().is_some());

        assert!(change_password(&db, user_id, &password, "a-new-one", &mine.session_token)
            .unwrap());

        assert!(
            validate_session(&db, &mine.session_token).unwrap().is_some(),
            "the caller must not be logged out of the tab they just used"
        );
        assert!(
            validate_session(&db, &stolen.session_token).unwrap().is_none(),
            "a password change must really revoke a session taken from elsewhere"
        );
        assert!(
            validate_session(&db, &another_tab.session_token).unwrap().is_none(),
            "every other session goes -- the daemon cannot tell the operator's second tab \
             from an attacker's"
        );
    }

    /// The absolute lifetime is a week, so without an idle window a token
    /// lifted from a laptop stayed good for a week of silence.
    #[test]
    fn a_session_left_idle_past_the_timeout_stops_being_accepted() {
        let (_dir, db, password, _user_id) = bootstrapped();
        let s = login(&db, "admin", &password, TEST_CLIENT).unwrap().session().unwrap();
        assert!(validate_session(&db, &s.session_token).unwrap().is_some());

        db.conn()
            .execute(
                "UPDATE sessions SET last_seen_at = ?1 WHERE token = ?2",
                rusqlite::params![now() - IDLE_TIMEOUT_SECS - 60, s.session_token],
            )
            .unwrap();

        assert!(
            validate_session(&db, &s.session_token).unwrap().is_none(),
            "a session unused for longer than the idle window must stop being accepted"
        );
        // And prove it was the IDLE window that did it, not the absolute
        // lifetime quietly expiring -- otherwise this test would pass with no
        // idle check at all.
        let expires_at: i64 = db
            .conn()
            .query_row(
                "SELECT expires_at FROM sessions WHERE token = ?1",
                rusqlite::params![s.session_token],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            expires_at > now(),
            "the session must still be well inside its absolute lifetime, or this test is \
             measuring expiry rather than idleness"
        );
    }

    #[test]
    fn using_a_session_pushes_its_idle_deadline_forward() {
        let (_dir, db, password, _user_id) = bootstrapped();
        let s = login(&db, "admin", &password, TEST_CLIENT).unwrap().session().unwrap();
        let stale = now() - IDLE_TIMEOUT_SECS + 60; // idle, but not yet past it
        db.conn()
            .execute(
                "UPDATE sessions SET last_seen_at = ?1 WHERE token = ?2",
                rusqlite::params![stale, s.session_token],
            )
            .unwrap();

        assert!(validate_session(&db, &s.session_token).unwrap().is_some());
        assert!(
            last_seen(&db, &s.session_token) > stale,
            "a session that is actually being used must not age out underneath its operator"
        );
    }

    /// The row half of M-03: expired sessions were never deleted, so the
    /// table grew one row per login and kept them forever.
    #[test]
    fn dead_sessions_are_pruned_when_someone_logs_in() {
        let (_dir, db, password, _user_id) = bootstrapped();
        let dead = login(&db, "admin", &password, TEST_CLIENT).unwrap().session().unwrap();
        db.conn()
            .execute(
                "UPDATE sessions SET last_seen_at = ?1 WHERE token = ?2",
                rusqlite::params![now() - IDLE_TIMEOUT_SECS - 60, dead.session_token],
            )
            .unwrap();

        let live = login(&db, "admin", &password, TEST_CLIENT).unwrap().session().unwrap();

        let rows: i64 = db
            .conn()
            .query_row(
                "SELECT count(*) FROM sessions WHERE token = ?1",
                rusqlite::params![dead.session_token],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0, "the dead session's ROW must be gone, not merely rejected");
        assert!(
            validate_session(&db, &live.session_token).unwrap().is_some(),
            "pruning must not take the session that was just created with it"
        );
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
        let result = change_password(&db, user_id, "definitely-not-the-password", "a-new-one", KEPT_SESSION);
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
        assert!(!change_password(&db, user_id, "wrong", "attempted-new", KEPT_SESSION).unwrap());
        assert!(
            login(&db, "admin", &password, TEST_CLIENT).unwrap().session().is_some(),
            "the original password must still work after a refused rotation"
        );
        assert!(
            login(&db, "admin", "attempted-new", TEST_CLIENT).unwrap().session().is_none(),
            "the password the refused call proposed must never have been set"
        );
    }

    #[test]
    fn change_password_really_rotates_the_credential_login_checks() {
        let (_dir, db, password, user_id) = bootstrapped();
        let before = stored_hash(&db, user_id);

        assert!(change_password(&db, user_id, &password, "a-real-new-password", KEPT_SESSION).unwrap());

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
            login(&db, "admin", "a-real-new-password", TEST_CLIENT).unwrap().session().is_some(),
            "a real login with the new password must succeed"
        );
        assert!(
            login(&db, "admin", &password, TEST_CLIENT).unwrap().session().is_none(),
            "the OLD password must stop working -- otherwise the rotation added a credential rather than replacing one"
        );
    }

    #[test]
    fn change_password_rejects_an_empty_new_password() {
        let (_dir, db, password, user_id) = bootstrapped();
        let result = change_password(&db, user_id, &password, "", KEPT_SESSION);
        assert!(result.is_err(), "an empty new password is the absence of a credential, not a weak one");
        assert!(
            login(&db, "admin", &password, TEST_CLIENT).unwrap().session().is_some(),
            "the rejection must have changed nothing"
        );
    }

    #[test]
    fn change_password_refuses_a_session_whose_user_no_longer_exists() {
        let (_dir, db, password, _user_id) = bootstrapped();
        // No user with id 9999 -- refuse rather than panic or 500.
        assert!(!change_password(&db, 9999, &password, "new", KEPT_SESSION).unwrap());
    }

    #[test]
    fn rotating_twice_really_re_salts_rather_than_reusing_the_old_salt() {
        let (_dir, db, password, user_id) = bootstrapped();
        assert!(change_password(&db, user_id, &password, "same-value", KEPT_SESSION).unwrap());
        let first = stored_hash(&db, user_id);
        assert!(change_password(&db, user_id, "same-value", "same-value", KEPT_SESSION).unwrap());
        let second = stored_hash(&db, user_id);
        assert_ne!(
            first, second,
            "the same password hashed twice must differ -- a fresh salt per rotation"
        );
        assert!(login(&db, "admin", "same-value", TEST_CLIENT).unwrap().session().is_some());
    }
}
