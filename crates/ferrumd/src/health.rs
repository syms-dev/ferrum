// GET /api/health and GET /api/ready -- the only steady-state way to ask this
// box whether it is well.
//
// Until this module existed, the only health logic in the project was
// `wait_for_healthy` inside crates/ferrum-apply/src/apply.rs, which runs once
// per apply and then ceases to exist. There was no monitor, no dashboard tile
// and no `curl` an operator could run between applies.
//
// ============================================================================
// POINT NO WATCHDOG, NO `Restart=` POLICY AND NO FUTURE MONITORING AT
// /api/ready. EVER.
// ============================================================================
//
// This is the hazard this file is most likely to be misread into. main.rs
// already records the live failure it comes from: "a ferrumd restarted
// mid-apply by its own generation switch". An apply builds a new system
// closure and switches to it, and that switch can restart ferrumd WHILE the
// apply that started it is still running. During that window readiness is
// legitimately not `ready`. A `Restart=` policy or a systemd watchdog keyed on
// this endpoint would therefore restart ferrumd during every apply -- and
// since restarting ferrumd is itself part of what an apply does, the result is
// a restart loop that eats the apply it was meant to protect. There is
// deliberately no `WatchdogSec=` wiring anywhere in modules/core/daemon.nix
// and none should be added. Readiness is a thing to READ, never a thing to ACT
// on automatically.
//
// ## Why two endpoints
//
// Liveness and readiness are different questions, so they get different URLs.
//
//   * `GET /api/health` answers 200 as soon as the axum server is up, and is
//     DEPENDENCY-FREE: it touches no SQLite, no systemd, no catalog, no
//     filesystem. Its handler takes no arguments at all, which is the
//     structural proof of that claim rather than a promise about it. Its only
//     job is "the process is answering".
//   * `GET /api/ready` reports whether ferrumd can actually do its job, with
//     a structured body naming each dependency separately.
//
// ## Why a degraded answer is 200 and not 503
//
// Because a watcher's reflex on 503 is to restart the process, and restarting
// is the wrong move for a degraded DEPENDENCY -- restarting ferrumd does not
// repair an unreadable catalog or a system bus that is down. 503 is reserved
// here for the one state that genuinely means "cannot serve at all". Anything
// less than that is 200 with the degradation named in the body, and the README
// says in as many words that a degraded answer still returns 200, so read the
// body.
//
// ## Why there is an `applying` status, when Silo has nothing like it
//
// Silo -- see docs/competitive/silo.md -- has no explicit "starting" state,
// so its operator infers one from "liveness up, readiness 503, now go read the
// logs". ferrum does not have to infer it: `AppState.interlock` already holds
// the UUID of the job that owns the system. So an apply in flight is reported
// as its own status, carrying that job id, and a watcher can tell *mid-switch*
// from *broken* without reading anything. It is the existing interlock, read
// where it already lives -- not a second source of truth that could disagree
// with the one `POST /api/jobs` enforces.
//
// ## What readiness deliberately does NOT cover
//
// The highest-value paragraph in this file, because an undocumented health
// endpoint manufactures false confidence rather than removing it. A green
// `/api/ready` means ferrumd's own dependencies answered. It does NOT mean:
//
//   * that any catalog app is running, or serving, or reachable. Readiness
//     asks nothing at all about Sonarr, Plex, qBittorrent or any other unit.
//   * that the qBittorrent VPN kill switch is intact, or that any app's
//     network namespace is what it should be.
//   * that the media pool is mounted, that every mergerfs branch is present,
//     or that there is free space. Nothing here touches storage.
//   * that nginx, Authelia, ACME or DNS are healthy. A caller reaching this
//     endpoint through the proxy has proved more about the proxy than this
//     body does.
//   * that the catalog and settings schema are SEMANTICALLY usable. The check
//     is "readable and parseable" only; `GET /api/catalog` additionally
//     requires the catalog to be a JSON object, and readiness does not.
//   * that polkit will authorize an apply. The systemd check proves the bus
//     is reachable and that this process can authenticate to it, never that
//     `StartUnit` on `ferrum-apply@<uuid>.service` would be permitted.
//   * that the last apply succeeded, or that the running generation is good.
//   * anything about freshness. Every check here is taken live, per request,
//     and no answer in this body is a cached or last-known reading.
//
// ## What an unauthenticated caller learns, and why that is the price
//
// Both routes are outside `protected` -- they are the only `/api/` routes
// other than login, logout and sso that require no session -- because a health
// endpoint a monitor cannot reach is not a health endpoint. That makes every
// byte of this body a disclosure, so the body is a CLOSED VOCABULARY by
// construction: four status words, five fixed check names, booleans, five
// fixed reason words, and the applying job's UUID. No path, no hostname, no
// version, no generation number, no secret name, and no error string of any
// kind reaches it. `catalog::JsonDocumentFault` exists precisely so the
// catalog checks can report WHICH fault occurred without the message that
// names the file. `no_failing_check_discloses_anything_about_the_host` is the
// test that keeps it that way.
use crate::catalog::{self, JsonDocumentFault};
use crate::db::Db;
use crate::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// How long the systemd check waits before calling the bus unreachable.
///
/// Short on purpose. This bounds the work an unauthenticated caller can make
/// ferrumd do, and a system bus that needs longer than this to accept a
/// connection cannot dispatch an apply either -- so the timeout is not a
/// compromise on accuracy, it is part of the question.
const SYSTEMD_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// The overall readiness verdict. Four values, and nothing else is ever
/// serialized into the `status` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Every check passed.
    Ready,
    /// An apply, rollback or other interlock-taking job owns the system right
    /// now. Reported ahead of everything else -- see `summarize`.
    Applying,
    /// At least one dependency failed, but ferrumd can still serve. 200.
    Degraded,
    /// ferrumd's own database is unusable, so nothing it does works. 503.
    Unready,
}

impl Status {
    /// The HTTP status this verdict is served with.
    ///
    /// Three of the four are 200, and that is the design, not an oversight:
    /// only `Unready` means "cannot serve at all", which is the one meaning
    /// 503 is reserved for here. See this module's header.
    ///
    /// # Returns
    /// 503 for `Unready`, 200 otherwise.
    fn http_status(self) -> StatusCode {
        match self {
            Status::Unready => StatusCode::SERVICE_UNAVAILABLE,
            Status::Ready | Status::Applying | Status::Degraded => StatusCode::OK,
        }
    }
}

/// Why one check failed -- a fixed word, never a message.
///
/// The three `Unset`/`Unreadable`/`Unparseable` values are
/// `catalog::JsonDocumentFault`'s own distinctions, carried across by
/// `From` rather than restated, so the two vocabularies cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Reason {
    /// The environment variable naming this dependency is not set.
    Unset,
    /// It is set, and what it names could not be read.
    Unreadable,
    /// It was read, and is not valid JSON.
    Unparseable,
    /// The dependency did not answer: a dead database handle, a system bus
    /// that refused or did not reply inside the probe's deadline, or a probe
    /// that could not be run at all because the blocking task carrying it
    /// panicked. The last is lumped in deliberately -- from a monitor's side
    /// "I could not find out" and "it did not answer" are the same fact, and
    /// inventing a fourth word would imply ferrumd knew something it did not.
    Unavailable,
    /// It answered, but the answer does not identify what was asked for --
    /// today, a profile directory in which no generation is the current one.
    Unresolved,
}

impl From<JsonDocumentFault> for Reason {
    fn from(fault: JsonDocumentFault) -> Self {
        match fault {
            JsonDocumentFault::Unset => Reason::Unset,
            JsonDocumentFault::Unreadable => Reason::Unreadable,
            JsonDocumentFault::Unparseable => Reason::Unparseable,
        }
    }
}

/// One dependency's verdict: whether it answered, and if not, which fixed
/// word says why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Check {
    /// True when this dependency answered as expected.
    pub ok: bool,
    /// `None` exactly when `ok` is true.
    pub reason: Option<Reason>,
}

impl Check {
    /// A dependency that answered.
    fn passed() -> Self {
        Check { ok: true, reason: None }
    }

    /// A dependency that did not answer, and the fixed word saying why.
    ///
    /// # Arguments
    /// * `reason` - the closed-vocabulary word to report.
    fn failed(reason: Reason) -> Self {
        Check { ok: false, reason: Some(reason) }
    }
}

/// Every dependency readiness looks at, each reported on its own rather than
/// collapsed into one boolean.
///
/// Collapsing them is the thing to avoid: "not ready" with no breakdown sends
/// an operator to the logs, which is the diagnosis loop this endpoint exists
/// to shorten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Checks {
    /// ferrumd's own SQLite database really answers a query.
    pub database: Check,
    /// `$FERRUM_CATALOG` is readable and parses as JSON.
    pub catalog: Check,
    /// `$FERRUM_SETTINGS_SCHEMA` is readable and parses as JSON.
    pub settings_schema: Check,
    /// The system D-Bus connection is live.
    pub systemd: Check,
    /// `$FERRUM_PROFILES_DIR` resolves to a current generation.
    pub generation: Check,
}

/// The `GET /api/ready` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadyReport {
    /// The one-word verdict.
    pub status: Status,
    /// The UUID of the job holding the interlock, and `None` whenever
    /// `status` is not `applying`.
    pub job: Option<String>,
    /// Every dependency, individually.
    pub checks: Checks,
}

/// `GET /api/health` -- liveness. 200 as soon as the server is up.
///
/// Takes NO arguments, and that is the point rather than an accident: a
/// handler with no `State` and no extractors cannot touch the database, the
/// catalog, systemd or the filesystem even by a later careless edit, so
/// "dependency-free" is enforced by the signature instead of promised by a
/// comment. Anything that would need an argument to check belongs in
/// `ready_handler`.
///
/// # Returns
/// 200 with `{"status":"alive"}`.
pub async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "alive" })))
}

/// `GET /api/ready` -- readiness, with every dependency reported separately.
///
/// # Arguments
/// * `state` - the daemon state, read for its database handle and its
///   single-job interlock.
///
/// # Returns
/// 503 with `"status":"unready"` when the database is unusable; otherwise 200
/// with `"status"` of `ready`, `applying` or `degraded` and a `checks` object.
/// A DEGRADED ANSWER IS STILL 200 -- read the body.
pub async fn ready_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let report = probe(&state).await;
    (report.status.http_status(), Json(report))
}

/// Runs every check and assembles the report.
///
/// # Arguments
/// * `state` - the daemon state to probe.
///
/// # Returns
/// The assembled `ReadyReport`.
async fn probe(state: &Arc<AppState>) -> ReadyReport {
    // Each blocking check goes through `run_blocking` for the reason
    // main.rs's own header gives: rusqlite and std::fs block the calling
    // thread outright, and an unauthenticated endpoint is the last place to
    // hand an anonymous caller a tokio worker thread for the length of a
    // disk read.
    let owned = state.clone();
    let database = crate::run_blocking(move || check_database(&owned.db))
        .await
        .unwrap_or_else(|_| Check::failed(Reason::Unavailable));
    let documents = crate::run_blocking(|| {
        let profiles = crate::generations::profiles_dir().ok();
        (
            check_json_document("FERRUM_CATALOG"),
            check_json_document("FERRUM_SETTINGS_SCHEMA"),
            check_generation(profiles.as_deref()),
        )
    })
    .await
    .unwrap_or((
        Check::failed(Reason::Unavailable),
        Check::failed(Reason::Unavailable),
        Check::failed(Reason::Unavailable),
    ));
    let checks = Checks {
        database,
        catalog: documents.0,
        settings_schema: documents.1,
        systemd: check_systemd().await,
        generation: documents.2,
    };
    let (status, job) = summarize(&checks, interlock_holder(state));
    ReadyReport { status, job, checks }
}

/// Who holds the single-job interlock right now, without panicking on a
/// poisoned mutex.
///
/// `jobs::create_job` uses `.lock().unwrap()`, which is right there: a
/// poisoned interlock means the serialization protecting a root-privileged
/// system switch is no longer trustworthy, and refusing loudly is correct.
/// Here it is not, because this is the endpoint whose whole job is to still
/// answer when things are wrong. Recovering the value is sound rather than a
/// shortcut: what the mutex guards is a plain `Option<String>`, which a panic
/// cannot leave half-written, so the recovered value is the real one.
///
/// # Arguments
/// * `state` - the daemon state holding the interlock.
///
/// # Returns
/// The claiming job's UUID, or `None` when the interlock is free.
fn interlock_holder(state: &Arc<AppState>) -> Option<String> {
    state.interlock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

/// Decides the one-word verdict from the checks and the interlock.
///
/// Pure, and separated from `probe` on purpose: every status this endpoint
/// can report is then reachable in a test from synthesized inputs, including
/// the combinations a test machine cannot actually produce.
///
/// The precedence is the load-bearing part, and the order is deliberate:
///
///   1. **An apply in flight wins over everything.** Mid-switch is the single
///      worst moment to tell a watcher the box is broken, and during an apply
///      the generation symlink is literally being replaced while a rollback
///      can restore state directories out from under the running daemon -- so
///      a failing check here is expected rather than news. The individual
///      checks are still reported in full; only the summary word changes.
///   2. **A dead database is `unready`, not `degraded`.** It is the one
///      dependency with no partial mode: without it there is no login, no
///      session, and therefore no route that works, so it is the only state
///      that means "cannot serve at all" and the only one that earns a 503.
///   3. Any other failing check is `degraded`, and 200.
///   4. Otherwise `ready`.
///
/// # Arguments
/// * `checks` - every dependency's verdict.
/// * `holder` - the job holding the interlock, if any.
///
/// # Returns
/// The status, and the job id to report with it (`Some` only for `applying`).
fn summarize(checks: &Checks, holder: Option<String>) -> (Status, Option<String>) {
    if let Some(job) = holder {
        return (Status::Applying, Some(job));
    }
    if !checks.database.ok {
        return (Status::Unready, None);
    }
    let all_passed = checks.catalog.ok
        && checks.settings_schema.ok
        && checks.systemd.ok
        && checks.generation.ok;
    (if all_passed { Status::Ready } else { Status::Degraded }, None)
}

/// Really queries ferrumd's own database.
///
/// A real `SELECT` against a real table, not a liveness flag on the handle:
/// the question readiness is asking is whether the next login can read the
/// `users` row it needs, and only running something that reads it answers
/// that. A database file deleted, truncated, or replaced underneath a running
/// daemon keeps the handle looking fine and fails here, which is the whole
/// point.
///
/// # Arguments
/// * `db` - the database to probe.
///
/// # Returns
/// A passing check, or `Unavailable` -- the only word reported, because the
/// rusqlite error text carries the database path.
fn check_database(db: &Db) -> Check {
    let Some(conn) = db.conn_if_usable() else {
        return Check::failed(Reason::Unavailable);
    };
    match conn.query_row("SELECT count(*) FROM users", [], |row| row.get::<_, i64>(0)) {
        Ok(_) => Check::passed(),
        Err(_) => Check::failed(Reason::Unavailable),
    }
}

/// Really reads and parses the JSON document an environment variable names.
///
/// Delegates to `catalog::read_json_from_env` and keeps only the fault, so
/// this check and `GET /api/catalog` can never disagree about whether a
/// document is usable while disclosing very different amounts about it.
///
/// # Arguments
/// * `var` - the environment variable naming the document.
///
/// # Returns
/// A passing check, or one carrying `unset`, `unreadable` or `unparseable`.
fn check_json_document(var: &str) -> Check {
    match catalog::read_json_from_env(var) {
        Ok(_) => Check::passed(),
        Err(e) => Check::failed(e.fault.into()),
    }
}

/// Whether the Nix profile directory resolves to a current generation.
///
/// Takes the directory rather than reading `$FERRUM_PROFILES_DIR` itself, so
/// the caller owns the one environment read and this stays drivable from a
/// test without mutating process-wide state that other tests in this binary
/// are reading at the same time.
///
/// # Arguments
/// * `dir` - the profile directory, or `None` when the variable is unset.
///
/// # Returns
/// A passing check, or `unset`, `unreadable`, or `unresolved` -- the last
/// being the state `list_profile_generations` documents, where `system`
/// points at something that is not a generation link.
fn check_generation(dir: Option<&Path>) -> Check {
    let Some(dir) = dir else {
        return Check::failed(Reason::Unset);
    };
    match crate::generations::list_profile_generations(dir) {
        // Every error from `list_profile_generations` is a filesystem fault
        // -- an unresolvable symlink, an unreadable directory, a stat that
        // failed -- and its message names the real path, so only the word
        // crosses the boundary.
        Err(_) => Check::failed(Reason::Unreadable),
        Ok(generations) => {
            if generations.iter().any(|(_, _, current)| *current) {
                Check::passed()
            } else {
                Check::failed(Reason::Unresolved)
            }
        }
    }
}

/// Whether the system bus is live.
///
/// # Returns
/// A passing check, or `unavailable`.
async fn check_systemd() -> Check {
    if crate::dbus::system_bus_is_reachable(SYSTEMD_PROBE_TIMEOUT).await {
        Check::passed()
    } else {
        Check::failed(Reason::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every check passing, as the starting point each test below breaks one
    /// thing in. A `ready` baseline is what makes "this one change moved the
    /// verdict" a statement about the change.
    fn all_passing() -> Checks {
        Checks {
            database: Check::passed(),
            catalog: Check::passed(),
            settings_schema: Check::passed(),
            systemd: Check::passed(),
            generation: Check::passed(),
        }
    }

    #[test]
    fn everything_passing_and_nothing_applying_is_ready() {
        assert_eq!(summarize(&all_passing(), None), (Status::Ready, None));
        assert_eq!(Status::Ready.http_status(), StatusCode::OK);
    }

    /// One named way to break a single dependency inside an otherwise
    /// passing `Checks`.
    type Breaker = (&'static str, fn(&mut Checks));

    /// Each non-database dependency, broken on its own. A single `degraded`
    /// case would pass just as well if `summarize` only ever looked at one
    /// field, which is precisely the bug this spreads out to catch.
    #[test]
    fn any_single_non_database_failure_is_degraded_and_still_two_hundred() {
        let breakers: [Breaker; 4] = [
            ("catalog", |c| c.catalog = Check::failed(Reason::Unparseable)),
            ("settingsSchema", |c| c.settings_schema = Check::failed(Reason::Unset)),
            ("systemd", |c| c.systemd = Check::failed(Reason::Unavailable)),
            ("generation", |c| c.generation = Check::failed(Reason::Unresolved)),
        ];
        for (name, break_it) in breakers {
            let mut checks = all_passing();
            break_it(&mut checks);
            let (status, job) = summarize(&checks, None);
            assert_eq!(status, Status::Degraded, "a broken {name} must read as degraded");
            assert_eq!(job, None);
            assert_eq!(
                status.http_status(),
                StatusCode::OK,
                "a degraded answer must stay 200 -- a watcher's reflex on 503 is to \
                 restart, and restarting repairs no dependency ({name})"
            );
        }
    }

    #[test]
    fn a_dead_database_is_unready_and_the_only_five_hundred_and_three() {
        let mut checks = all_passing();
        checks.database = Check::failed(Reason::Unavailable);
        let (status, job) = summarize(&checks, None);
        assert_eq!(status, Status::Unready);
        assert_eq!(job, None);
        assert_eq!(status.http_status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    /// The interlock outranks every check, including the database one.
    ///
    /// Not a detail: a rollback restores state directories while ferrumd runs,
    /// so the database check CAN fail transiently mid-apply -- and answering
    /// 503 at that moment is the single most dangerous thing this endpoint
    /// could do, because it is the moment a restart policy would fire.
    #[test]
    fn an_apply_in_flight_outranks_every_failing_check() {
        let job = "11111111-2222-3333-4444-555555555555".to_string();
        let broken = Checks {
            database: Check::failed(Reason::Unavailable),
            catalog: Check::failed(Reason::Unreadable),
            settings_schema: Check::failed(Reason::Unparseable),
            systemd: Check::failed(Reason::Unavailable),
            generation: Check::failed(Reason::Unresolved),
        };
        let (status, reported) = summarize(&broken, Some(job.clone()));
        assert_eq!(status, Status::Applying);
        assert_eq!(reported, Some(job), "the applying answer must name the job that owns the system");
        assert_eq!(
            status.http_status(),
            StatusCode::OK,
            "mid-apply must never be 503: that is the one moment a restart destroys the apply"
        );
    }

    /// Only `applying` carries a job id. A leaked one on a `ready` answer
    /// would be a disclosure with no purpose.
    #[test]
    fn no_status_but_applying_reports_a_job() {
        let mut degraded = all_passing();
        degraded.systemd = Check::failed(Reason::Unavailable);
        for checks in [all_passing(), degraded] {
            assert_eq!(summarize(&checks, None).1, None);
        }
    }

    /// All four document outcomes, driven against a REAL file through the
    /// real `catalog::read_json_from_env`.
    ///
    /// The variables are private to this test rather than the real
    /// `FERRUM_CATALOG`: catalog.rs's own test mutates that one, the harness
    /// runs these threads concurrently, and a shared variable would make both
    /// tests race. Serialized into one `#[test]` for the same reason
    /// catalog.rs gives.
    #[test]
    fn a_json_document_check_reports_which_of_the_three_faults_occurred() {
        const VAR: &str = "FERRUM_HEALTH_TEST_DOCUMENT";
        let dir = tempfile::tempdir().unwrap();

        std::env::remove_var(VAR);
        assert_eq!(
            check_json_document(VAR),
            Check::failed(Reason::Unset),
            "an unset variable must be reported as unset"
        );

        let missing = dir.path().join("does-not-exist.json");
        std::env::set_var(VAR, &missing);
        assert_eq!(
            check_json_document(VAR),
            Check::failed(Reason::Unreadable),
            "a variable naming nothing must be reported as unreadable"
        );

        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{ this is not json").unwrap();
        std::env::set_var(VAR, &broken);
        assert_eq!(
            check_json_document(VAR),
            Check::failed(Reason::Unparseable),
            "invalid JSON must be reported as unparseable, not as unreadable"
        );

        let good = dir.path().join("good.json");
        std::fs::write(&good, r#"{"apps":{}}"#).unwrap();
        std::env::set_var(VAR, &good);
        assert_eq!(
            check_json_document(VAR),
            Check::passed(),
            "a real, parseable document must pass -- a check that always fails is as \
             useless as no check"
        );

        std::env::remove_var(VAR);
    }

    /// The generation check in all four of its states, against real
    /// directories and real symlinks.
    #[test]
    fn the_generation_check_separates_unset_unreadable_and_unresolved() {
        assert_eq!(
            check_generation(None),
            Check::failed(Reason::Unset),
            "no FERRUM_PROFILES_DIR must be reported as unset"
        );

        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("not-a-directory");
        assert_eq!(
            check_generation(Some(&absent)),
            Check::failed(Reason::Unreadable),
            "a profile directory that is not there must be reported as unreadable"
        );

        // `system` resolves, but to something that is not a generation link:
        // the one case list_profile_generations documents as degrading
        // `current` rather than failing outright.
        let dangling = dir.path().join("dangling");
        std::fs::create_dir(&dangling).unwrap();
        std::os::unix::fs::symlink("somewhere-else", dangling.join("system")).unwrap();
        assert_eq!(
            check_generation(Some(&dangling)),
            Check::failed(Reason::Unresolved),
            "a `system` symlink pointing at a non-generation must be reported as \
             unresolved, NOT as ready -- it is the state where rollback has no anchor"
        );

        // And the real shape: a generation link, with `system` pointing at it.
        let good = dir.path().join("profiles");
        std::fs::create_dir(&good).unwrap();
        std::fs::create_dir(good.join("system-7-link")).unwrap();
        std::os::unix::fs::symlink("system-7-link", good.join("system")).unwrap();
        assert_eq!(
            check_generation(Some(&good)),
            Check::passed(),
            "a profile directory with a resolvable current generation must pass"
        );
    }

    /// The database check against a real database, then against the same
    /// database with the table the probe reads removed.
    #[test]
    fn the_database_check_fails_only_when_the_database_really_cannot_answer() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        assert_eq!(
            check_database(&db),
            Check::passed(),
            "a real, open database must pass -- otherwise this check says nothing"
        );

        // A real fault, not a mocked one: the `users` table a login reads is
        // gone, which is what a truncated or replaced database file looks
        // like to an already-open handle.
        db.conn()
            .execute_batch("PRAGMA foreign_keys = OFF; DROP TABLE sessions; DROP TABLE users;")
            .unwrap();
        assert_eq!(
            check_database(&db),
            Check::failed(Reason::Unavailable),
            "a database that cannot answer the query a login makes must fail the check"
        );
    }

    /// The disclosure guard, and the reason this endpoint can be
    /// unauthenticated at all.
    ///
    /// It serializes a report in which EVERY check has failed -- the state
    /// with the most to say -- and asserts that the rendered document
    /// contains nothing but the closed vocabulary. The failure it is built to
    /// catch is a later edit that attaches `e.to_string()` or a `path.display()`
    /// to a reason "to make it easier to diagnose": every one of those carries
    /// filesystem detail to an anonymous caller.
    #[test]
    fn no_failing_check_discloses_anything_about_the_host() {
        let report = ReadyReport {
            status: Status::Degraded,
            job: None,
            checks: Checks {
                database: Check::failed(Reason::Unavailable),
                catalog: Check::failed(Reason::Unreadable),
                settings_schema: Check::failed(Reason::Unparseable),
                systemd: Check::failed(Reason::Unavailable),
                generation: Check::failed(Reason::Unset),
            },
        };
        let body = serde_json::to_string(&report).unwrap();

        // Every word the document is permitted to contain. A new key or a new
        // reason has to be added here deliberately, which is the review step
        // this test exists to force.
        const PERMITTED: &[&str] = &[
            "status",
            "job",
            "checks",
            "ok",
            "reason",
            "database",
            "catalog",
            "settingsSchema",
            "systemd",
            "generation",
            "ready",
            "applying",
            "degraded",
            "unready",
            "unset",
            "unreadable",
            "unparseable",
            "unavailable",
            "unresolved",
            "true",
            "false",
            "null",
        ];
        for word in body.split(|c: char| !c.is_ascii_alphanumeric()) {
            if word.is_empty() {
                continue;
            }
            assert!(
                PERMITTED.contains(&word),
                "the readiness body contains {word:?}, which is outside the closed \
                 vocabulary this unauthenticated endpoint is allowed to disclose: {body}"
            );
        }
    }

    /// And the same guard where the vocabulary is genuinely open: the job id.
    ///
    /// It is the one caller-visible value this endpoint does not control the
    /// shape of, so it is pinned separately -- a v4 UUID ferrumd generated,
    /// which names no path and is useless on its own, because every route
    /// that accepts a job id (`GET /api/jobs/:id` and its stream) is inside
    /// `protected` and answers 401 without a session.
    #[test]
    fn the_applying_answer_discloses_the_job_id_and_nothing_else() {
        let report = ReadyReport {
            status: Status::Applying,
            job: Some("0191f3c2-7e5a-4c1b-9d2e-6a7b8c9d0e1f".to_string()),
            checks: all_passing(),
        };
        let body = serde_json::to_string(&report).unwrap();
        assert!(body.contains(r#""status":"applying""#));
        assert!(body.contains(r#""job":"0191f3c2-7e5a-4c1b-9d2e-6a7b8c9d0e1f""#));
    }

    /// The systemd probe really answers "no" to a bus that is not there.
    ///
    /// The address is overridden rather than assumed absent, so the result is
    /// the same in the Nix build sandbox, in a container, and on a Linux
    /// developer machine that does have a running system bus -- the last of
    /// which would otherwise turn this into a test that passes or fails
    /// depending on who ran it. Overriding a process-wide variable is safe
    /// here only because nothing else in this binary's tests opens a D-Bus
    /// connection; the variable is restored immediately either way.
    ///
    /// Only the negative direction is provable at all: establishing a REAL
    /// system bus connection needs a running dbus-daemon, which no test
    /// environment in this repository has. The positive direction is covered
    /// by `summarize`'s own tests, which drive a passing systemd check
    /// directly. Without this test, a probe hard-wired to `true` would leave
    /// every other test in this file green.
    #[tokio::test]
    async fn the_systemd_probe_reports_a_bus_that_is_not_there_as_unreachable() {
        const ADDRESS: &str = "DBUS_SYSTEM_BUS_ADDRESS";
        let restore = std::env::var(ADDRESS).ok();
        std::env::set_var(ADDRESS, "unix:path=/nonexistent/ferrum-health-test-bus");
        let verdict = check_systemd().await;
        match restore {
            Some(previous) => std::env::set_var(ADDRESS, previous),
            None => std::env::remove_var(ADDRESS),
        }
        assert_eq!(
            verdict,
            Check::failed(Reason::Unavailable),
            "a system bus address that cannot exist must report unavailable -- if it \
             passes, the probe is not really connecting to anything"
        );
    }
}
