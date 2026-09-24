// The Job API: the daemon's actual reason to exist. POST /api/jobs writes
// a request file into /run/ferrum/requests and asks systemd (over D-Bus,
// authorized by the polkit rule in modules/core/daemon.nix) to start
// `ferrum-apply@<uuid>.service`. GET /api/jobs/:id/stream replays and then
// live-tails that job's own JSONL progress file, which ferrum-apply writes
// via crates/ferrum-apply/src/progress.rs.
//
// Note what ferrumd never does here: it never builds, never switches, never
// touches the Nix profile, and never runs anything as root. The entire
// privileged surface is the closed six-variant request enum below, which
// mirrors crates/ferrum-apply/src/request.rs exactly.
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    Json,
};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::AppState;

#[derive(Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobRequest {
    Preflight,
    Apply,
    Rollback { to: u32 },
    RestoreState,
    Gc,
    /// The read-only update check. Mirrors `request::Request::CheckUpdate`
    /// -- zero fields, so nothing an API caller supplies ever decides what
    /// the root process fetches.
    CheckUpdate,
}

fn jobs_dir() -> std::path::PathBuf {
    std::env::var("FERRUM_JOBS_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/jobs".to_string())
        .into()
}

pub fn requests_dir() -> std::path::PathBuf {
    std::env::var("FERRUM_REQUESTS_DIR")
        .unwrap_or_else(|_| "/run/ferrum/requests".to_string())
        .into()
}

/// Recovers a job's UUID from the systemd unit name carried by a real
/// `JobRemoved` signal, or `None` if this is not one of our units.
///
/// The UUID is re-parsed rather than trusted as a string: the return value
/// becomes a FILENAME under `requests_dir()` in `remove_request_file`
/// below, so anything that is not literally a UUID (a `..` component, a
/// slash, an empty instance name) must not get that far. systemd is a
/// trustworthy source here, but "the value I am about to use as a path
/// component is a UUID" is cheap to actually check and expensive to be
/// wrong about. A UUID also contains no character systemd's own instance
/// escaping would have mangled, so no unescaping step is needed.
pub fn job_uuid_from_unit(unit: &str) -> Option<String> {
    let instance = unit
        .strip_prefix("ferrum-apply@")?
        .strip_suffix(".service")?;
    Uuid::parse_str(instance).ok()?;
    Some(instance.to_string())
}

/// Deletes a finished job's request file. Best-effort by design: a failure
/// here is logged and otherwise ignored, because the file is spent input to
/// a run that has already ended and there is nothing useful the daemon
/// could do about it -- crashing (or refusing later jobs) over a stale
/// tmpfs file would be a worse outcome than the stale file itself.
///
/// Why bother at all: the request file is the thing a
/// `ferrum-apply@<uuid>.service` start actually consumes, so a request file
/// that outlives its job is a replayable privileged trigger sitting on
/// disk. The PRIMARY defence against that replay is the polkit
/// `subject.user == "ferrum"` check in modules/core/daemon.nix -- nothing
/// but ferrumd's own account can issue the start in the first place. This
/// is defence in depth underneath it: it shrinks the window in which a
/// replay would find anything to replay, rather than closing the hole on
/// its own.
///
/// The directory is passed in rather than read from the environment so the
/// tests exercise the real deletion against a real temp directory without
/// mutating process-wide environment state that the other tests in this
/// module read concurrently. Production callers hand it `requests_dir()`.
pub fn remove_request_file_in(dir: &std::path::Path, uuid: &str) {
    let path = dir.join(format!("{uuid}.json"));
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        // Already gone is the expected outcome on a re-delivered signal, not
        // a problem worth a log line.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!(
            "ferrumd: could not remove the spent request file {}: {e} -- \
             harmless to this job, but it will linger until the next reboot \
             clears /run",
            path.display()
        ),
    }
}

/// The one definition of which request kinds claim ferrumd's single-job
/// interlock, expressed over the `kind` string that actually crosses the
/// privilege boundary.
///
/// DA-7 exempts exactly one kind, the read-only `check_update`. Two
/// separate places need that answer -- `create_job_in`, deciding whether an
/// incoming POST claims it, and `interlock_holder_in`, deciding whether a
/// unit systemd reports running is holding it -- and the two disagreeing is
/// the whole shape of this defect class. They ask the same function about
/// the same string, and that string is the one written into the request
/// file by `request_body`.
///
/// An unrecognized kind claims the interlock. That is the fail-closed
/// direction: the cost of wrongly holding it is a 409 that clears when the
/// unit stops, and the cost of wrongly releasing it is two concurrent
/// `nix-env --set` plus `switch-to-configuration` runs as root.
///
/// # Arguments
/// * `kind` - the `kind` field of a request, e.g. `"apply"`.
pub fn kind_takes_interlock(kind: &str) -> bool {
    kind != "check_update"
}

/// Reads back the `kind` a dispatched job was requested with, from the
/// request file ferrumd itself wrote before starting the unit.
///
/// `None` when the file is gone, unreadable, not JSON, or has no string
/// `kind` -- every one of which is "we cannot say", and every one of which
/// callers must treat as interlock-taking rather than as a check.
///
/// This is the only durable record of a running job's kind that survives a
/// ferrumd restart: the file lives in `/run/ferrum/requests` (tmpfs), so it
/// outlives the process but not a reboot -- which is exactly the lifetime
/// wanted, because after a reboot systemd has no running units to ask about
/// either.
///
/// # Arguments
/// * `dir` - the requests directory.
/// * `uuid` - the job id, which is also the file's stem.
pub fn request_kind_in(dir: &std::path::Path, uuid: &str) -> Option<String> {
    let text = std::fs::read_to_string(dir.join(format!("{uuid}.json"))).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value.get("kind")?.as_str().map(str::to_string)
}

/// What one systemd `JobRemoved` signal means for ferrumd's state.
#[derive(Debug, PartialEq)]
pub struct JobRemovedEffects {
    /// Whether this signal releases the interlock. True only when the unit
    /// that finished is the one currently holding it.
    pub release_interlock: bool,
    /// The job whose request file is now spent, if this is one of our
    /// units at all. Independent of the interlock: every kind's file is
    /// spent when its unit's job is gone.
    pub spent_request: Option<String>,
}

/// Decides what a `JobRemoved` signal does, given who holds the interlock.
///
/// Pure, and separated from the stream loop in `main.rs` on purpose: this
/// decision used to be four inline lines inside `attach_and_watch`, which
/// no test could reach, and it went on being wrong in exactly the way an
/// untested decision does.
///
/// The rule is identity, not unit-name shape. `ferrum-apply@<uuid>.service`
/// names both an apply and a read-only check since DA-7, so "the unit is
/// one of ours" no longer implies "this is the job that claimed the
/// interlock". A check finishing -- which a DNS failure does in seconds --
/// must not clear the interlock of an apply that is still building and
/// switching, because the next `apply` or `rollback` would then be admitted
/// alongside a root-privileged system switch already in flight. It also
/// must not clear it because `create_job_in` never gave it one to clear;
/// this is the same invariant that function's conditional release states,
/// and this was the out-of-band path that undid it.
///
/// The narrowing is deliberate and has a cost worth naming: an unrelated
/// unit finishing used to be an accidental release valve for an interlock
/// whose own holder's signal went missing. That valve was the defect. The
/// remaining recovery is `reconcile_interlock`, which re-derives the truth
/// from systemd on every attach and re-attach.
///
/// # Arguments
/// * `unit` - the systemd unit name from the signal.
/// * `held` - the job currently holding the interlock, if any.
pub fn job_removed_effects(unit: &str, held: Option<&str>) -> JobRemovedEffects {
    let finished = job_uuid_from_unit(unit);
    JobRemovedEffects {
        release_interlock: held.is_some() && finished.as_deref() == held,
        spent_request: finished,
    }
}

/// Decides which job, if any, should hold the interlock, given the
/// `ferrum-apply@` units systemd reports as running right now.
///
/// This is the second half of the DA-7 regression. The seeding used to be a
/// bare bool from `dbus::ferrum_apply_job_is_running`, whose glob
/// `ferrum-apply@*.service` matches a read-only check exactly as well as an
/// apply -- so a check running when ferrumd started, or when the JobRemoved
/// stream dropped and re-attached, held the interlock that no job had
/// claimed and the next rollback was refused with 409.
///
/// Each running unit's kind is read back from its own request file rather
/// than remembered in the daemon. That is the deliberate trade-off: an
/// in-memory register of claimants is destroyed by the one event this whole
/// path exists for, a ferrumd that its own apply restarted mid-run, whereas
/// `/run/ferrum/requests` is tmpfs and survives the process. It does not
/// survive a reboot -- and it does not need to, because after a reboot
/// systemd has no running units to classify either, so both sources agree
/// on "nothing".
///
/// Only units systemd says are running are consulted, which is what makes a
/// stale request file harmless: cleanup is best-effort, so one can outlive
/// its job, but a file whose unit is not running is never looked at.
///
/// More than one claimant should be impossible, and would mean the
/// interlock had already been defeated. The lowest id wins, so the answer
/// is at least stable across re-attaches rather than alternating.
///
/// # Arguments
/// * `dir` - the requests directory, where each running job's kind is
///   recorded.
/// * `running_units` - systemd's current running `ferrum-apply@` unit names.
pub fn interlock_holder_in(dir: &std::path::Path, running_units: &[String]) -> Option<String> {
    let mut claimants: Vec<String> = running_units
        .iter()
        .filter_map(|unit| job_uuid_from_unit(unit))
        .filter(|uuid| {
            request_kind_in(dir, uuid)
                .map(|kind| kind_takes_interlock(&kind))
                .unwrap_or(true)
        })
        .collect();
    claimants.sort();
    claimants.into_iter().next()
}

/// The exact JSON `ferrum-apply run-request` parses back out of the request
/// file. Kept as an explicit match rather than a `Serialize` derive so the
/// wire format ferrumd writes across the privilege boundary is spelled out
/// literally in one place, and a future field added to `JobRequest` can't
/// silently start crossing that boundary.
fn request_body(req: &JobRequest) -> serde_json::Value {
    match req {
        JobRequest::Preflight => serde_json::json!({"kind": "preflight"}),
        JobRequest::Apply => serde_json::json!({"kind": "apply"}),
        JobRequest::Rollback { to } => serde_json::json!({"kind": "rollback", "to": to}),
        JobRequest::RestoreState => serde_json::json!({"kind": "restore_state"}),
        JobRequest::Gc => serde_json::json!({"kind": "gc"}),
        JobRequest::CheckUpdate => serde_json::json!({"kind": "check_update"}),
    }
}

/// True when this JSONL progress line is the job's terminal line. Parsed as
/// real JSON rather than substring-matched: a substring check on
/// `"complete"` would also fire on a *detail* string that merely happened
/// to contain the quoted word, ending an operator's stream early on a job
/// that was still running.
fn is_terminal_line(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("event").and_then(|e| e.as_str()).map(str::to_string))
        .map(|event| event == "complete")
        .unwrap_or(false)
}

/// ferrumd itself serializes job requests -- apply/rollback are inherently
/// exclusive operations against the same generation sequence, so this is
/// a deliberate simplification rather than relying on systemd or
/// ferrum-apply to arbitrate concurrent runs.
///
/// The flag is claimed under a SINGLE lock acquisition (check and set
/// together), not checked and then set later: two concurrent POSTs that
/// both read `false` before either wrote `true` would otherwise both be
/// admitted. It is released again if the D-Bus start itself fails, so a
/// job that never actually started can't wedge the daemon.
pub async fn create_job(
    State(state): State<Arc<AppState>>,
    axum::Extension(crate::SessionUsername(username)): axum::Extension<crate::SessionUsername>,
    axum::Extension(client): axum::Extension<crate::client_addr::ClientAddr>,
    Json(req): Json<JobRequest>,
) -> impl IntoResponse {
    create_job_in(&requests_dir(), crate::generations::profiles_dir(), state, username, client, req).await
}

/// The body of `create_job`, with both directories passed in.
///
/// Same reason `remove_request_file_in` and `list_jobs_in` exist: the tests
/// drive the real handler against real temp directories without mutating
/// process-wide environment state that the other tests in this crate read
/// concurrently. `profiles_dir` arrives as the `Result` its lookup
/// produced, because an unresolvable profile directory is not a detail to
/// paper over here -- see the rollback guard below.
async fn create_job_in(
    dir: &std::path::Path,
    profiles_dir: anyhow::Result<std::path::PathBuf>,
    state: Arc<AppState>,
    username: Option<String>,
    client: crate::client_addr::ClientAddr,
    req: JobRequest,
) -> axum::response::Response {
    let user = username.as_deref().unwrap_or(crate::UNKNOWN_USER).to_string();
    // apply and rollback are the two most consequential things this daemon
    // can be asked to do -- they change the running system and they can move
    // it backwards -- so the dispatch is recorded with WHICH kind it was and
    // which job id it became, whatever the outcome.
    let kind = request_body(&req)
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("unknown")
        .to_string();
    let audit_job = |outcome: &str, detail: &str| {
        crate::audit::record("job-dispatch", outcome, &user, &client, detail);
    };
    // M4. The rollback target is validated HERE, before anything of it
    // reaches the privilege boundary.
    //
    // It used to be validated nowhere. `create_job` wrote
    // `{"kind":"rollback","to":<u32>}` through untouched, and the only
    // check on the target anywhere in the daemon was the `rollbackable`
    // field `generations.rs` hands the UI for display -- which a caller is
    // free to ignore, and which `generations.rs`'s own header comment
    // claimed this endpoint was the authority behind. It was not.
    //
    // The specific harm is that a rollback to the CURRENT generation is not
    // a no-op. The closure does not change, so nothing is rolled back; but
    // every app's state directory is restored from the last apply's
    // snapshot and the box reboots. An operator gets the destruction
    // without the rollback.
    //
    // It fails closed: if the current generation cannot be established, the
    // one thing certain is that we cannot say the target is not it, and the
    // operation being guarded reboots the machine. Only rollback pays for
    // this lookup -- the other five kinds have no target to check.
    if let JobRequest::Rollback { to } = req {
        let target = to;
        // A directory walk plus an lstat per generation, so it goes to the
        // blocking pool rather than the executor thread -- as
        // `get_generations` does with the same read.
        let current = match profiles_dir {
            Ok(profiles) => crate::run_blocking(move || crate::generations::current_generation(&profiles)).await,
            Err(e) => Ok(Err(e)),
        };
        match current {
            Ok(Ok(Some(current))) if current == target => {
                audit_job("denied", &format!("kind={kind} to={target} is the current generation"));
                return (
                    StatusCode::BAD_REQUEST,
                    crate::generations::rollback_to_current_reason(current),
                )
                    .into_response();
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                audit_job("error", &format!("kind={kind} could not read the current generation"));
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("refusing a rollback: could not establish which generation this host is running: {e:#}"),
                )
                    .into_response();
            }
            Err(status) => return status.into_response(),
        }
    }
    // DA-7. The read-only check is the one kind exempt from the interlock,
    // and the invariant that decides it is: *a rollback must never be
    // blocked by a read-only check.* The flag has no timeout and no cancel,
    // a candidate check evaluates the whole module system twice and can
    // take minutes, and the one path that has to work on a host an update
    // just broke is the rollback a shared flag would refuse for the whole
    // of that time.
    //
    // This is a change INSIDE the critical section, not a bypass bolted
    // beside it: for every kind that does take the interlock, the check and
    // the set are still one lock acquisition, because two concurrent POSTs
    // that both found it unclaimed before either claimed it would otherwise
    // both be admitted.
    //
    // The id is minted BEFORE the claim because the claim now records it:
    // an interlock that does not know who holds it cannot be released by
    // that holder alone, and `main.rs`'s JobRemoved handler was releasing
    // it for whichever of our units finished first.
    let uuid = Uuid::new_v4().to_string();
    let takes_interlock = kind_takes_interlock(&kind);
    if takes_interlock {
        let mut held = state.interlock.lock().unwrap();
        if held.is_some() {
            audit_job("denied", &format!("kind={kind} a job is already running"));
            return (StatusCode::CONFLICT, "a job is already running").into_response();
        }
        *held = Some(uuid.clone());
    }

    let body = request_body(&req);

    // Releasing is conditional for the same reason claiming is: a failed
    // check must not clear an interlock it never claimed, which would let a
    // second apply in alongside the one still running. It is also gated on
    // still being OUR claim, so this cannot become the same out-of-band
    // clear it is guarding against.
    let release = || {
        if takes_interlock {
            let mut held = state.interlock.lock().unwrap();
            if held.as_deref() == Some(uuid.as_str()) {
                *held = None;
            }
        }
    };

    if let Err(e) = tokio::fs::create_dir_all(dir).await {
        release();
        audit_job("error", &format!("kind={kind} could not create the requests dir"));
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create requests dir: {e}"),
        )
            .into_response();
    }
    let request_path = dir.join(format!("{uuid}.json"));
    if let Err(e) = tokio::fs::write(&request_path, body.to_string()).await {
        release();
        audit_job("error", &format!("kind={kind} could not write the request file"));
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write request file: {e}"),
        )
            .into_response();
    }

    if let Err(e) = crate::dbus::start_ferrum_apply_unit(&uuid).await {
        release();
        // L6. The interlock was already released here; the request file was
        // not. It is the input a `ferrum-apply@<uuid>.service` start
        // consumes, so one left behind is a replayable privileged trigger
        // -- and nothing else would ever remove it, because `JobRemoved`
        // never fires for a unit that never started and that signal is the
        // only other path to `remove_request_file`. It survived until a
        // reboot cleared /run.
        remove_request_file_in(dir, &uuid);
        audit_job("error", &format!("kind={kind} the unit did not start"));
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    audit_job("success", &format!("kind={kind} job={uuid}"));
    (StatusCode::OK, Json(serde_json::json!({"id": uuid}))).into_response()
}

/// Replays the job's own JSONL progress file from the start, then
/// switches to live-tail via polling (a simple, real, correct baseline --
/// inotify-based tailing via the `notify` crate is a real optimization
/// worth doing, but polling every 500ms is trivially correct and good
/// enough for a human watching one job's own progress; this is a
/// deliberate simplification, not an oversight).
///
/// `id` is used only as a filename component under `jobs_dir()`, and is
/// rejected outright unless it is a real UUID -- without that check, a
/// crafted id containing `..` would let an authenticated operator stream
/// arbitrary files off the box through the daemon.
pub async fn stream_job(Path(id): Path<String>) -> impl IntoResponse {
    if Uuid::parse_str(&id).is_err() {
        return (StatusCode::BAD_REQUEST, "job id must be a UUID").into_response();
    }
    let path = jobs_dir().join(format!("{id}.jsonl"));
    let stream = async_stream::stream! {
        let mut last_len: usize = 0;
        loop {
            // `tokio::fs` rather than `spawn_blocking`: ferrumd already
            // depends on tokio with `features = ["full"]`, which enables
            // `fs`, so this adds no feature and pulls in no new code. It is
            // also the call that most needed moving -- this loop re-reads the
            // whole growing progress file every 500ms, per connected stream,
            // for the entire duration of an apply.
            let Ok(content) = tokio::fs::read_to_string(&path).await else {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            };
            // `get` rather than direct slicing: a direct `content[last_len..]`
            // panics if the offset ever lands mid-UTF-8-sequence, which would
            // take the whole daemon's task down rather than dropping one
            // stream.
            if content.len() > last_len {
                if let Some(fresh) = content.get(last_len..) {
                    for line in fresh.lines() {
                        if !line.trim().is_empty() {
                            yield Ok::<_, Infallible>(
                                Event::default().event("progress").data(line)
                            );
                        }
                    }
                    last_len = content.len();
                }
            }
            if content.lines().rev().find(|l| !l.trim().is_empty()).map(is_terminal_line).unwrap_or(false) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

/// One job, as `GET /api/jobs` reports it.
///
/// `status` is lifecycle, `result` is outcome, and they are deliberately
/// separate fields: a job that finished is `status: "complete"` with a
/// `result` of `succeeded`/`degraded`/`failed`, so a caller can render "is
/// it still going?" without having to know the outcome vocabulary, and the
/// outcome vocabulary can grow without changing what "still running" means.
#[derive(Serialize, Debug, PartialEq)]
pub struct JobSummary {
    pub id: String,
    /// `None` for a job dispatched before `ferrum-apply` learned to write a
    /// `started` line. Reported as null rather than guessed: the request
    /// file that would have said is deleted once the unit stops.
    pub kind: Option<String>,
    /// `running` (no terminal line yet), `complete`, or `unknown` (the file
    /// exists but nothing in it parses).
    pub status: &'static str,
    pub result: Option<String>,
    pub detail: Option<String>,
    pub started_at: Option<u64>,
    pub finished_at: Option<u64>,
}

/// One parsed progress line, echoed verbatim by `GET /api/jobs/:id`.
#[derive(Serialize, Debug)]
pub struct JobEvent {
    pub ts: Option<u64>,
    pub event: Option<String>,
    pub detail: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct JobDetail {
    #[serde(flatten)]
    pub summary: JobSummary,
    pub events: Vec<JobEvent>,
}

fn parse_line(line: &str) -> Option<serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(line).ok()
}

fn str_field(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(str::to_string)
}

/// Reads one job's JSONL file into a summary.
///
/// Returns `None` only when the file cannot be read at all; a file that is
/// present but unparseable is a summary with `status: "unknown"`, not an
/// omission. That distinction matters: the file's existence is real evidence
/// that a real privileged run happened, and hiding it because we cannot read
/// it would be strictly worse than showing it plainly.
pub fn summarize(id: &str, path: &std::path::Path) -> std::io::Result<Option<JobSummary>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        // Genuinely absent is `Ok(None)` -- the caller turns that into a 404,
        // or skips it in a listing. Any OTHER error is a real fault and is
        // propagated: a permission regression on the jobs directory must not
        // be indistinguishable from "this job does not exist". Same rule
        // ferrum_state::journal::list already applies (journal.rs:35-38), and
        // the same rationale Task 3 recorded for the generations endpoint --
        // an operator who cannot tell a fault from an empty result will
        // conclude their history was lost.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    Ok(Some(summarize_content(id, &content)))
}

/// Summarizes a job's progress file from content already in hand.
///
/// Split out of `summarize` for L5: `get_job_in` needs both the summary and
/// the events, and reading the file twice to get them meant the two halves
/// of one response could disagree about what was on disk. With the content
/// read once and passed to both, they cannot.
///
/// # Arguments
/// * `id` - the job's UUID, echoed into the summary.
/// * `content` - the whole progress file.
fn summarize_content(id: &str, content: &str) -> JobSummary {
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    let first = lines.first().and_then(|l| parse_line(l));
    let last = lines.last().and_then(|l| parse_line(l));

    let Some(first) = first else {
        return JobSummary {
            id: id.to_string(),
            kind: None,
            status: "unknown",
            result: None,
            detail: None,
            started_at: None,
            finished_at: None,
        };
    };

    let started_at = first.get("ts").and_then(|t| t.as_u64());
    // Only a genuine `started` line names the kind. Any other first event
    // means this job predates that line, so the kind is unknown rather than
    // whatever the first step happened to be called.
    let kind = match str_field(&first, "event").as_deref() {
        Some("started") => str_field(&first, "detail"),
        _ => None,
    };

    let terminal = last.filter(|l| str_field(l, "event").as_deref() == Some("complete"));
    let (status, result, detail, finished_at) = match terminal {
        Some(l) => {
            // `Progress::complete` writes the detail as "<result>: <detail>".
            // Split once, so a detail containing its own ": " stays intact.
            let payload = str_field(&l, "detail").unwrap_or_default();
            let (result, detail) = match payload.split_once(": ") {
                Some((r, d)) => (Some(r.to_string()), Some(d.to_string())),
                None => (Some(payload.clone()), None),
            };
            ("complete", result, detail, l.get("ts").and_then(|t| t.as_u64()))
        }
        None => ("running", None, None, None),
    };

    JobSummary { id: id.to_string(), kind, status, result, detail, started_at, finished_at }
}

/// Newest first, via the same `Reverse` idiom gc.rs already uses.
///
/// A job with no parseable `started_at` sorts LAST rather than disappearing
/// (see `summarize`'s note on not hiding real runs): `None < Some(_)`, so
/// `Reverse(None)` is the greatest key and lands at the end. Extracted from
/// the handler so that ordering -- including the None-last part, which is a
/// deliberate choice a refactor could silently invert -- is directly testable
/// without standing up a router or mutating process-wide environment.
fn sort_newest_first(summaries: &mut [JobSummary]) {
    summaries.sort_by_key(|s| std::cmp::Reverse(s.started_at));
}

#[derive(Deserialize)]
pub struct ListJobsQuery {
    limit: Option<usize>,
}

/// `GET /api/jobs?limit=N`
///
/// A missing jobs directory is an empty list, not a 500: a host that has
/// never dispatched a job is a real, valid state, and the UI's "no jobs yet"
/// is the correct rendering of it.
pub async fn list_jobs(Query(q): Query<ListJobsQuery>) -> impl IntoResponse {
    // A directory walk plus a read of every job file it lists, so it goes to
    // the blocking pool -- see main.rs's run_blocking.
    match crate::run_blocking(move || list_jobs_in(&jobs_dir(), q.limit)).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    }
}

/// The body of `list_jobs`, with the directory passed in so the tests below
/// exercise the real handler against a real temp directory without mutating
/// process-wide environment that the other tests in this module read
/// concurrently -- the same reason `remove_request_file_in` exists.
fn list_jobs_in(dir: &std::path::Path, limit: Option<usize>) -> axum::response::Response {
    let limit = limit.unwrap_or(25).clamp(1, 100);

    // Absent is an empty list; anything else is a fault and must say so.
    // `journal::list` (crates/ferrum-state/src/journal.rs:35-38) sets this
    // precedent, and Task 3 recorded the rationale: a fault rendered as an
    // empty list is indistinguishable from "this host has never run a job",
    // so an operator with real history concludes it was lost.
    if !dir.exists() {
        return Json(serde_json::json!({ "jobs": [] })).into_response();
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not read the jobs directory {}: {e}", dir.display()),
            )
                .into_response()
        }
    };

    let mut summaries: Vec<JobSummary> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        // The stem becomes the reported id, so it is re-parsed as a UUID for
        // the same reason `stream_job` re-parses its own path parameter:
        // anything that is not literally a UUID has no business being echoed
        // back as a job id.
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if Uuid::parse_str(stem).is_err() {
            continue;
        }
        match summarize(stem, &path) {
            Ok(Some(summary)) => summaries.push(summary),
            // Vanished between read_dir and read -- a benign race, not a fault.
            Ok(None) => continue,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("could not read the job file {}: {e}", path.display()),
                )
                    .into_response()
            }
        }
    }

    sort_newest_first(&mut summaries);
    summaries.truncate(limit);

    Json(serde_json::json!({ "jobs": summaries })).into_response()
}

/// `GET /api/jobs/:id`
pub async fn get_job(Path(id): Path<String>) -> impl IntoResponse {
    // Reads the job's whole progress file, so it goes to the blocking pool
    // -- see main.rs's run_blocking.
    match crate::run_blocking(move || get_job_in(&jobs_dir(), &id)).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    }
}

/// The body of `get_job`; see `list_jobs_in` for why the directory is a
/// parameter rather than read from the environment here.
fn get_job_in(dir: &std::path::Path, id: &str) -> axum::response::Response {
    // Rejected before touching the filesystem, identical to `stream_job`'s
    // guard and for the identical reason: the id becomes a path component.
    if Uuid::parse_str(id).is_err() {
        return (StatusCode::BAD_REQUEST, "job id must be a UUID").into_response();
    }
    let path = dir.join(format!("{id}.jsonl"));
    // L5. ONE read, feeding both halves of the response.
    //
    // This used to read the file twice -- `summarize` for the summary, then
    // again for the events -- and the second read ended in
    // `unwrap_or_default()`. A failure of that second read therefore became
    // `events: []` on a `200`, next to a summary saying the job started and
    // naming its kind: a document that cannot be true, reading as "the
    // progress log is empty". That is precisely the fault-as-absence
    // `summarize`'s own doc forbids, and the two reads made it reachable
    // with no permission change at all -- the file only had to stop being
    // readable between them.
    //
    // Reading once removes the window rather than narrowing it, and the
    // summary and the events can no longer disagree about what was on disk.
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (StatusCode::NOT_FOUND, "no such job").into_response()
        }
        // A permission regression on an existing job file is a fault, not a
        // 404: reporting "no such job" would send an operator hunting for a
        // job that is right there on disk.
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not read the job file {}: {e}", path.display()),
            )
                .into_response()
        }
    };

    let summary = summarize_content(id, &content);
    let events: Vec<JobEvent> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(parse_line)
        .map(|v| JobEvent {
            ts: v.get("ts").and_then(|t| t.as_u64()),
            event: str_field(&v, "event"),
            detail: str_field(&v, "detail"),
        })
        .collect();

    Json(JobDetail { summary, events }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L5. A job whose file cannot be read must never be rendered as a job
    /// that has no events.
    ///
    /// `get_job_in` read the same file twice -- once through `summarize`,
    /// once for the events -- and the second read ended in
    /// `unwrap_or_default()`. Any failure of that second read therefore
    /// produced `events: []` on a `200`, alongside a summary that says the
    /// job started and names its kind. That document is not merely
    /// incomplete, it is impossible: a job that started and emitted
    /// nothing. It reads as "the progress log is empty", and it directly
    /// contradicts the rule `summarize`'s own doc states -- a fault must
    /// not be indistinguishable from an absence, because an operator who
    /// cannot tell them apart concludes their history was lost.
    ///
    /// The two reads are what make the failure reachable without any
    /// permission change at all: the file only has to stop being readable
    /// BETWEEN them. This drives exactly that, with a thread removing and
    /// restoring the file underneath. On a single read the window does not
    /// exist -- a 200 is served from one successful read or it is not
    /// served -- so the assertion cannot fail on the fixed code rather than
    /// merely tending not to.
    #[tokio::test]
    async fn a_job_file_that_vanishes_mid_request_is_never_rendered_as_having_no_events() {
        let dir = tempfile::tempdir().unwrap();
        let id = "6e2f7795-58c7-4654-82b6-f655b065ea47";
        let path = job_file(
            dir.path(),
            id,
            &[(10, "started", "apply"), (11, "step", "building"), (12, "complete", "ok")],
        );
        let body = std::fs::read_to_string(&path).unwrap();

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let churn = {
            let (path, body, stop) = (path.clone(), body.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = std::fs::remove_file(&path);
                    let _ = std::fs::write(&path, &body);
                }
            })
        };

        let mut impossible = 0usize;
        for _ in 0..5_000 {
            let response = get_job_in(dir.path(), id);
            if response.status() != StatusCode::OK {
                continue;
            }
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let started = doc.get("kind").and_then(|k| k.as_str()).is_some();
            let no_events = doc.get("events").and_then(|e| e.as_array()).is_some_and(|e| e.is_empty());
            if started && no_events {
                impossible += 1;
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        churn.join().unwrap();

        assert_eq!(
            impossible, 0,
            "{impossible} response(s) reported a job that started and named its kind while \
             showing an empty event list -- a fault rendered as an absence, which is the one \
             thing summarize's own documentation says must never happen"
        );
    }

    /// Writes a job file whose lines are the given `(event, detail)` pairs,
    /// each with an explicit `ts`, and returns its path.
    fn job_file(dir: &std::path::Path, id: &str, lines: &[(u64, &str, &str)]) -> std::path::PathBuf {
        let path = dir.join(format!("{id}.jsonl"));
        let body: String = lines
            .iter()
            .map(|(ts, event, detail)| {
                format!("{}\n", serde_json::json!({"ts": ts, "event": event, "detail": detail}))
            })
            .collect();
        std::fs::write(&path, body).unwrap();
        path
    }

    const ID: &str = "3f1b8a7e-0c2d-4e5f-9a1b-2c3d4e5f6a7b";

    #[test]
    fn a_finished_job_reports_its_kind_result_detail_and_both_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let path = job_file(
            dir.path(),
            ID,
            &[
                (100, "started", "apply"),
                (101, "build", "building the new generation"),
                (102, "complete", "succeeded: switched to generation 7"),
            ],
        );
        let s = summarize(ID, &path).unwrap().unwrap();
        assert_eq!(s.kind.as_deref(), Some("apply"));
        assert_eq!(s.status, "complete");
        assert_eq!(s.result.as_deref(), Some("succeeded"));
        assert_eq!(s.detail.as_deref(), Some("switched to generation 7"));
        assert_eq!(s.started_at, Some(100));
        assert_eq!(s.finished_at, Some(102));
    }

    #[test]
    fn a_job_with_no_terminal_line_is_running_and_has_no_finished_at() {
        let dir = tempfile::tempdir().unwrap();
        let path = job_file(dir.path(), ID, &[(100, "started", "rollback"), (101, "snapshot", "taken")]);
        let s = summarize(ID, &path).unwrap().unwrap();
        assert_eq!(s.status, "running");
        assert_eq!(s.kind.as_deref(), Some("rollback"));
        assert_eq!(s.result, None);
        assert_eq!(s.finished_at, None);
    }

    /// A job dispatched before `ferrum-apply` learned to write a `started`
    /// line. Its kind is genuinely unknown -- the request file that would
    /// have said is deleted once the unit stops -- so it must be reported as
    /// null rather than guessed from whatever the first step happened to be.
    #[test]
    fn a_job_predating_the_started_line_reports_a_null_kind_not_the_first_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = job_file(
            dir.path(),
            ID,
            &[(100, "preflight", "checking free space"), (101, "complete", "succeeded: ok")],
        );
        let s = summarize(ID, &path).unwrap().unwrap();
        assert_eq!(s.kind, None, "the first event is not a `started` line, so the kind is unknown");
        assert_eq!(s.started_at, Some(100), "but its ts is still the job's start");
        assert_eq!(s.status, "complete");
    }

    /// `Progress::complete` writes "<result>: <detail>", and a real detail can
    /// itself contain ": " -- a health-check message, a path with a port, a
    /// nested error. Splitting on the FIRST separator keeps the rest intact;
    /// splitting on the last, or on every occurrence, would truncate it.
    #[test]
    fn a_detail_containing_its_own_separator_survives_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = job_file(
            dir.path(),
            ID,
            &[(1, "complete", "failed: unit sonarr.service is down: exit code 3")],
        );
        let s = summarize(ID, &path).unwrap().unwrap();
        assert_eq!(s.result.as_deref(), Some("failed"));
        assert_eq!(s.detail.as_deref(), Some("unit sonarr.service is down: exit code 3"));
    }

    /// Real evidence that a real privileged run happened must not be hidden
    /// just because it cannot be parsed.
    #[test]
    fn an_unparseable_job_file_is_reported_as_unknown_rather_than_omitted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{ID}.jsonl"));
        std::fs::write(&path, "this is not json at all\n").unwrap();
        let s = summarize(ID, &path).unwrap().unwrap();
        assert_eq!(s.status, "unknown");
        assert_eq!(s.kind, None);
        assert_eq!(s.started_at, None);
    }

    /// Newest first, and an unparseable job (no `started_at`) must land at
    /// the END rather than the front. Inverting this is a one-character
    /// mistake that would push every broken job to the top of the operator's
    /// list, so it is asserted rather than left to the comment.
    #[test]
    fn jobs_sort_newest_first_with_unknown_start_times_last() {
        let mk = |id: &str, started_at: Option<u64>| JobSummary {
            id: id.to_string(),
            kind: None,
            status: "complete",
            result: None,
            detail: None,
            started_at,
            finished_at: None,
        };
        let mut v = vec![mk("old", Some(10)), mk("broken", None), mk("new", Some(30)), mk("mid", Some(20))];
        sort_newest_first(&mut v);
        let order: Vec<&str> = v.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(order, vec!["new", "mid", "old", "broken"]);
    }

    /// The three handler-level cases Task 4 Step 4 names: a non-UUID filename
    /// that must be skipped, `limit` clamped at both ends, and a `..`-bearing
    /// id rejected with 400.
    ///
    /// Driven through the real handlers rather than the helpers, because the
    /// UUID guards are the security-relevant part of this task and a test of
    /// `summarize` alone cannot exercise them. Serialized into ONE test that
    /// sets `FERRUM_JOBS_DIR`, matching this module's existing note about
    /// process-wide environment: the other tests here read it concurrently.
    /// The three handler-level cases Task 4 Step 4 names: a non-UUID filename
    /// that must be skipped, `limit` clamped at both ends, and a `..`-bearing
    /// id rejected with 400.
    ///
    /// Driven through the real handler bodies rather than the helpers,
    /// because the UUID guards are the security-relevant part of this task
    /// and a test of `summarize` alone cannot exercise them. Uses the `_in`
    /// variants so it touches NO process-wide environment: an earlier version
    /// set `FERRUM_JOBS_DIR` and was genuinely flaky, because this module's
    /// own `jobs_dir()` default test calls `remove_var` concurrently.
    #[tokio::test]
    async fn handlers_skip_non_uuid_files_clamp_limit_and_reject_traversal_ids() {
        use axum::body::to_bytes;

        let dir = tempfile::tempdir().unwrap();
        job_file(dir.path(), ID, &[(10, "started", "apply"), (11, "complete", "succeeded: ok")]);
        std::fs::write(dir.path().join("not-a-uuid.jsonl"), "{\"ts\":1,\"event\":\"started\"}\n").unwrap();

        async fn read(r: axum::response::Response) -> (StatusCode, String) {
            let (parts, body) = r.into_parts();
            let bytes = to_bytes(body, usize::MAX).await.unwrap();
            (parts.status, String::from_utf8(bytes.to_vec()).unwrap())
        }

        // 1. The non-UUID filename is skipped; only the real job is listed.
        let (status, text) = read(list_jobs_in(dir.path(), None)).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let jobs = v["jobs"].as_array().unwrap();
        assert_eq!(jobs.len(), 1, "only the UUID-named file is a job: {text}");
        assert_eq!(jobs[0]["id"], ID);
        assert!(!text.contains("not-a-uuid"), "a non-UUID stem must never be echoed as an id");

        // 2. limit clamps at both ends: 0 -> 1, and a huge value -> 100.
        for (requested, at_most) in [(Some(0usize), 1usize), (Some(10_000), 100)] {
            let (status, text) = read(list_jobs_in(dir.path(), requested)).await;
            assert_eq!(status, StatusCode::OK);
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                v["jobs"].as_array().unwrap().len() <= at_most,
                "limit {requested:?} should clamp to at most {at_most}"
            );
        }

        // 3. A traversal id is rejected BEFORE any filesystem access.
        for bad in ["../../etc/shadow", "..", "not-a-uuid", ""] {
            let (status, _) = read(get_job_in(dir.path(), bad)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "id {bad:?} must be rejected as a non-UUID");
        }

        // A real UUID with no file is a 404 -- not a 400, and not a 500.
        let (status, _) = read(get_job_in(dir.path(), "11111111-2222-3333-4444-555555555555")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // And the real job is retrievable, with its events.
        let (status, text) = read(get_job_in(dir.path(), ID)).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["kind"], "apply");
        assert_eq!(v["events"].as_array().unwrap().len(), 2);
    }

    /// A fault must never be reported as absence. `summarize` returns
    /// `Ok(None)` ONLY for a genuinely missing file; any other IO error
    /// propagates, so `get_job` can answer 500 instead of a misleading 404
    /// and `list_jobs` can answer 500 instead of a silently empty list.
    ///
    /// Provoked with a directory where a file is expected, which yields a
    /// non-`NotFound` error deterministically. A permissions test would not
    /// work here: the test container runs as root and bypasses DAC, so a
    /// mode-000 file is still readable and the test would pass vacuously.
    #[test]
    fn a_read_error_that_is_not_absence_propagates_rather_than_reading_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        let as_dir = dir.path().join(format!("{ID}.jsonl"));
        std::fs::create_dir(&as_dir).unwrap();

        let err = summarize(ID, &as_dir).expect_err("a directory is not an absent job");
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "this must not be mistaken for a missing job"
        );

        // And the genuinely-absent case still reads as absent, not an error.
        assert!(summarize(ID, &dir.path().join("absent.jsonl")).unwrap().is_none());
    }

    #[test]
    fn a_missing_job_file_summarizes_to_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(summarize(ID, &dir.path().join("nope.jsonl")).unwrap().is_none());
    }

    /// A `complete` line that is not the LAST line leaves the job running --
    /// otherwise a job whose terminal line is followed by a stray write would
    /// be reported finished while its unit is still going.
    #[test]
    fn only_the_last_line_can_terminate_a_job() {
        let dir = tempfile::tempdir().unwrap();
        let path = job_file(
            dir.path(),
            ID,
            &[(1, "started", "gc"), (2, "complete", "succeeded: done"), (3, "extra", "still writing")],
        );
        assert_eq!(summarize(ID, &path).unwrap().unwrap().status, "running");
    }

    #[test]
    fn blank_lines_do_not_confuse_the_first_or_last_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{ID}.jsonl"));
        std::fs::write(
            &path,
            "\n{\"ts\":5,\"event\":\"started\",\"detail\":\"gc\"}\n\n\
             {\"ts\":6,\"event\":\"complete\",\"detail\":\"succeeded: pruned 2\"}\n\n",
        )
        .unwrap();
        let s = summarize(ID, &path).unwrap().unwrap();
        assert_eq!(s.kind.as_deref(), Some("gc"));
        assert_eq!(s.started_at, Some(5));
        assert_eq!(s.finished_at, Some(6));
    }

    #[test]
    fn every_request_kind_serializes_to_what_ferrum_apply_parses() {
        // These exact strings are what crates/ferrum-apply/src/request.rs's
        // own #[serde(tag = "kind", rename_all = "snake_case")] enum accepts;
        // its own tests assert the parse side.
        assert_eq!(request_body(&JobRequest::Preflight).to_string(), r#"{"kind":"preflight"}"#);
        assert_eq!(request_body(&JobRequest::Apply).to_string(), r#"{"kind":"apply"}"#);
        assert_eq!(
            request_body(&JobRequest::Rollback { to: 42 }).to_string(),
            r#"{"kind":"rollback","to":42}"#
        );
        assert_eq!(
            request_body(&JobRequest::RestoreState).to_string(),
            r#"{"kind":"restore_state"}"#
        );
        assert_eq!(request_body(&JobRequest::Gc).to_string(), r#"{"kind":"gc"}"#);
        // The read-only check is a bare tag and nothing else. Asserted as
        // the exact serialized bytes, because "no field crosses the
        // privilege boundary" is the whole security property of this
        // variant -- a field silently added to `JobRequest` would show up
        // here as a changed string.
        assert_eq!(
            request_body(&JobRequest::CheckUpdate).to_string(),
            r#"{"kind":"check_update"}"#
        );
    }

    #[test]
    fn job_request_deserializes_from_the_api_wire_format() {
        let parsed: JobRequest = serde_json::from_str(r#"{"kind":"rollback","to":7}"#).unwrap();
        match parsed {
            JobRequest::Rollback { to } => assert_eq!(to, 7),
            other => panic!("expected Rollback, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_job_kind_is_rejected_rather_than_defaulted() {
        assert!(serde_json::from_str::<JobRequest>(r#"{"kind":"delete_everything"}"#).is_err());
    }

    #[test]
    fn only_a_real_complete_event_terminates_the_stream() {
        assert!(is_terminal_line(r#"{"detail":"succeeded: ","event":"complete","ts":1}"#));
        assert!(!is_terminal_line(r#"{"detail":"x","event":"switch","ts":1}"#));
        // The exact case a naive substring check gets wrong: a still-running
        // step whose detail text happens to contain the quoted word.
        assert!(!is_terminal_line(
            r#"{"detail":"waiting for \"complete\" from the builder","event":"build","ts":1}"#
        ));
        assert!(!is_terminal_line("not json at all"));
        assert!(!is_terminal_line(""));
    }

    #[test]
    fn a_real_job_removed_unit_name_yields_its_uuid() {
        assert_eq!(
            job_uuid_from_unit("ferrum-apply@6e2f7795-58c7-4654-82b6-f655b065ea47.service")
                .as_deref(),
            Some("6e2f7795-58c7-4654-82b6-f655b065ea47")
        );
    }

    #[test]
    fn unrelated_units_and_non_uuid_instances_are_not_treated_as_jobs() {
        // Every JobRemoved on the box arrives at this listener, not just
        // ours -- an unrelated unit must never name a file to delete.
        assert_eq!(job_uuid_from_unit("sshd.service"), None);
        assert_eq!(job_uuid_from_unit("ferrum-apply.service"), None);
        // The path-traversal shapes specifically: these must be rejected by
        // the UUID parse, not joined onto requests_dir().
        assert_eq!(job_uuid_from_unit("ferrum-apply@...service"), None);
        assert_eq!(
            job_uuid_from_unit("ferrum-apply@../../etc/passwd.service"),
            None
        );
        assert_eq!(job_uuid_from_unit("ferrum-apply@.service"), None);
        // Right prefix, right instance, wrong suffix.
        assert_eq!(
            job_uuid_from_unit("ferrum-apply@6e2f7795-58c7-4654-82b6-f655b065ea47.timer"),
            None
        );
    }

    #[test]
    fn a_spent_request_file_is_really_deleted_and_a_missing_one_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = "6e2f7795-58c7-4654-82b6-f655b065ea47";
        let path = dir.path().join(format!("{uuid}.json"));
        std::fs::write(&path, r#"{"kind":"preflight"}"#).unwrap();
        assert!(path.exists());
        remove_request_file_in(dir.path(), uuid);
        assert!(!path.exists(), "the spent request file must really be gone");
        // Idempotent: a re-delivered JobRemoved must not panic or fail.
        remove_request_file_in(dir.path(), uuid);
    }

    /// `POST /api/jobs`, driven through the real handler.
    mod create_job {
        use super::*;

        /// A profile directory whose `system` symlink names `current`.
        ///
        /// Passed to the handler directly rather than through
        /// `FERRUM_PROFILES_DIR`, for the reason `remove_request_file_in`
        /// already records: the other tests in this crate read that
        /// variable concurrently.
        fn profiles(current: u32) -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            for generation in [current, current + 1] {
                let link = format!("system-{generation}-link");
                std::os::unix::fs::symlink("/nonexistent-store-path", dir.path().join(&link)).unwrap();
            }
            std::os::unix::fs::symlink(
                format!("system-{current}-link"),
                dir.path().join("system"),
            )
            .unwrap();
            dir
        }

        /// A stand-in for the id of an apply that is already in flight. A
        /// real UUID, because the interlock now holds a job id and every
        /// other consumer of one re-parses it.
        const RUNNING_APPLY: &str = "9e4a1f2c-7d61-4a3e-9b02-5c8f3a1d6e77";

        fn state() -> Arc<AppState> {
            let dir = tempfile::tempdir().unwrap();
            let db = crate::db::Db::open(&dir.path().join("test.db")).unwrap();
            Arc::new(AppState { db, interlock: std::sync::Mutex::new(None) })
        }

        /// Drives the real handler and hands back its status, its body, and
        /// whatever privileged request files it left behind.
        async fn dispatch(
            requests: &std::path::Path,
            profiles: anyhow::Result<std::path::PathBuf>,
            req: JobRequest,
        ) -> (StatusCode, String, Vec<String>) {
            dispatch_with(requests, profiles, state(), req).await
        }

        /// `dispatch`, with the shared state handed in so a test can drive
        /// the handler against an interlock that is ALREADY claimed, and
        /// can inspect the flag afterwards.
        async fn dispatch_with(
            requests: &std::path::Path,
            profiles: anyhow::Result<std::path::PathBuf>,
            state: Arc<AppState>,
            req: JobRequest,
        ) -> (StatusCode, String, Vec<String>) {
            let response = create_job_in(
                requests,
                profiles,
                state,
                Some("operator".to_string()),
                crate::client_addr::ClientAddr::Direct("127.0.0.1".parse().unwrap()),
                req,
            )
            .await;
            let mut written: Vec<String> = std::fs::read_dir(requests)
                .map(|entries| {
                    entries
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            written.sort();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8_lossy(&body).into_owned(), written)
        }

        /// The headline of M4.
        ///
        /// Rolling back to the generation the host is already running does
        /// not roll anything back: the closure does not change. What it
        /// DOES do is restore every app's state directory from the last
        /// apply's snapshot and reboot -- a destructive no-op, and the
        /// reason `generations.rs` marks the current generation
        /// `rollbackable: false`. That guard lived only in a display field
        /// the UI is free to ignore; `create_job` wrote the target through
        /// unchecked.
        ///
        /// The assertion is on the request file, not just the status,
        /// because the request file IS the privileged trigger: once it
        /// exists and the unit is started, the decision has crossed the
        /// privilege boundary and ferrumd has no say left.
        #[tokio::test]
        async fn a_rollback_to_the_current_generation_never_becomes_a_request() {
            let requests = tempfile::tempdir().unwrap();
            let profiles = profiles(7);
            let (status, _body, written) = dispatch(
                requests.path(),
                Ok(profiles.path().to_path_buf()),
                JobRequest::Rollback { to: 7 },
            )
            .await;
            assert!(
                written.is_empty(),
                "no privileged rollback request may reach /run/ferrum/requests for the \
                 generation the host is already running -- it would restore every app's \
                 state directory and reboot without changing the closure. Found: {written:?}"
            );
            assert_eq!(status, StatusCode::BAD_REQUEST, "it must be refused outright");
        }

        /// The guard on the guard: a real rollback must still get through.
        ///
        /// There is no system bus in the test environment, so the dispatch
        /// fails at `start_ferrum_apply_unit` and answers 500. That is the
        /// point -- it got as far as trying, which a refused request never
        /// does.
        #[tokio::test]
        async fn a_rollback_to_a_different_generation_is_not_refused() {
            let requests = tempfile::tempdir().unwrap();
            let profiles = profiles(7);
            let (status, _body, _written) = dispatch(
                requests.path(),
                Ok(profiles.path().to_path_buf()),
                JobRequest::Rollback { to: 8 },
            )
            .await;
            assert_ne!(
                status,
                StatusCode::BAD_REQUEST,
                "a rollback to a generation the host is NOT running must reach the dispatch"
            );
        }

        /// L6. A dispatch that never started must not leave its request
        /// file behind.
        ///
        /// The request file IS the privileged trigger: it is the input a
        /// `ferrum-apply@<uuid>.service` start consumes. When the D-Bus
        /// start failed, `create_job` released the interlock and returned
        /// 500 -- but left the file sitting in /run/ferrum/requests, where
        /// nothing would ever remove it. `JobRemoved` never fires for a
        /// unit that never started, so the cleanup in `attach_and_watch`
        /// does not reach it, and the file survives until a reboot clears
        /// /run.
        ///
        /// It is the same class of leftover `remove_request_file`'s own
        /// documentation exists for, arriving by the one path that
        /// documentation did not cover, and the same defence-in-depth
        /// argument applies: polkit's `subject.user == "ferrum"` check is
        /// the primary control, and shrinking the window in which a replay
        /// finds anything to replay is what this adds underneath it.
        #[tokio::test]
        async fn a_dispatch_that_never_started_leaves_no_replayable_request_file() {
            let requests = tempfile::tempdir().unwrap();
            // Preflight, so the rollback guard is not what refuses it: this
            // has to get all the way to the D-Bus start and fail THERE,
            // which it does because the test environment has no system bus.
            let (status, _body, written) =
                dispatch(requests.path(), Err(anyhow::anyhow!("unused")), JobRequest::Preflight).await;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "the dispatch must really have failed at the unit start"
            );
            assert!(
                written.is_empty(),
                "a request file for a job that never started is a replayable privileged                  trigger with nothing left to clean it up. Found: {written:?}"
            );
        }

        /// Fail closed. If the current generation cannot be established,
        /// the one thing that is certain is that we cannot say the target
        /// is not it -- and the operation being guarded reboots the box.
        #[tokio::test]
        async fn a_rollback_is_refused_when_the_current_generation_cannot_be_read() {
            let requests = tempfile::tempdir().unwrap();
            let (status, body, written) = dispatch(
                requests.path(),
                Err(anyhow::anyhow!("FERRUM_PROFILES_DIR not set")),
                JobRequest::Rollback { to: 7 },
            )
            .await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(
                body.contains("FERRUM_PROFILES_DIR"),
                "the refusal must name what it could not read: {body}"
            );
            assert!(written.is_empty(), "found: {written:?}");
        }

        /// DA-7, asserted rather than commented.
        ///
        /// The invariant: *a rollback must never be blocked by a read-only
        /// check.* The interlock has no timeout and no cancel, and a
        /// candidate check can take minutes -- so if the check claimed it,
        /// the one path that has to work on a host an update just broke is
        /// exactly the path a shared interlock would block.
        ///
        /// Both halves are asserted together, because either alone is
        /// vacuous: an exemption that also exempted `Apply` would pass a
        /// test that only looked at `CheckUpdate`.
        #[tokio::test]
        async fn a_read_only_check_is_not_blocked_by_a_running_job_but_an_apply_still_is() {
            let requests = tempfile::tempdir().unwrap();
            let shared = state();
            *shared.interlock.lock().unwrap() = Some(RUNNING_APPLY.to_string());

            let (status, body, _) = dispatch_with(
                requests.path(),
                Err(anyhow::anyhow!("unused")),
                shared.clone(),
                JobRequest::CheckUpdate,
            )
            .await;
            assert_ne!(
                status,
                StatusCode::CONFLICT,
                "a read-only check must not be refused because another job holds the \
                 interlock -- it would make a rollback unreachable on a broken host: {body}"
            );
            // It got as far as the D-Bus start, which there is no system bus
            // for here. That is the proof it reached the dispatch.
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

            let (status, body, _) = dispatch_with(
                requests.path(),
                Err(anyhow::anyhow!("unused")),
                shared.clone(),
                JobRequest::Apply,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "apply changes the running system and must still serialize: {body}"
            );

            // And the check neither claimed nor released someone else's
            // claim: the interlock is exactly as it was found, still naming
            // the apply -- not merely still held by somebody.
            assert_eq!(
                shared.interlock.lock().unwrap().as_deref(),
                Some(RUNNING_APPLY),
                "the check must leave the running job's own interlock alone"
            );
        }

        /// The other half of the exemption: a check on an idle host must
        /// not leave the interlock claimed behind it, or the first check
        /// would wedge every later apply.
        #[tokio::test]
        async fn a_read_only_check_never_claims_the_interlock_on_an_idle_host() {
            let requests = tempfile::tempdir().unwrap();
            let shared = state();
            let _ = dispatch_with(
                requests.path(),
                Err(anyhow::anyhow!("unused")),
                shared.clone(),
                JobRequest::CheckUpdate,
            )
            .await;
            assert_eq!(
                shared.interlock.lock().unwrap().as_deref(),
                None,
                "a read-only check must leave the interlock unclaimed"
            );

            // The consequence rather than a re-read of the state we just
            // looked at: an apply dispatched afterwards must not find the
            // interlock held. That is what "left it unclaimed" actually
            // means, and it is what would break if the check claimed and
            // never released.
            let (status, body, _) = dispatch_with(
                requests.path(),
                Err(anyhow::anyhow!("unused")),
                shared.clone(),
                JobRequest::Apply,
            )
            .await;
            assert_ne!(
                status,
                StatusCode::CONFLICT,
                "a preceding read-only check must not have wedged the interlock: {body}"
            );
        }

        /// The guard is scoped to rollback and must not cost the other
        /// five kinds a profile-directory lookup they have no use for.
        #[tokio::test]
        async fn the_other_job_kinds_do_not_need_a_readable_profile_directory() {
            let requests = tempfile::tempdir().unwrap();
            let (status, body, _written) = dispatch(
                requests.path(),
                Err(anyhow::anyhow!("FERRUM_PROFILES_DIR not set")),
                JobRequest::Preflight,
            )
            .await;
            assert_ne!(status, StatusCode::BAD_REQUEST);
            // It still fails at the dispatch -- there is no system bus here
            // -- but it must not fail for a directory it never reads.
            assert!(
                !body.contains("FERRUM_PROFILES_DIR"),
                "a preflight must not be refused for a profile directory it never reads: {body}"
            );
        }

        /// Defect 2, driven to the outcome DA-7 exists to prevent.
        ///
        /// `dbus::ferrum_apply_job_is_running` globs
        /// `ferrum-apply@*.service`, which since DA-7 matches a read-only
        /// check as readily as an apply. So a check that happened to be
        /// running when ferrumd started -- or when the JobRemoved stream
        /// dropped and re-attached, which `supervise_job_watch` makes an
        /// ordinary event -- seeded the interlock with no job having
        /// claimed it, and the next rollback was refused with 409. On a
        /// host an update has just broken, that rollback is the one
        /// operation that has to work.
        ///
        /// Both halves are asserted together because either alone is
        /// vacuous: seeding that never held anything would pass a test that
        /// only looked at the check.
        #[tokio::test]
        async fn a_check_running_at_startup_still_admits_a_rollback_but_a_running_apply_refuses_it() {
            let requests = tempfile::tempdir().unwrap();
            let profiles = profiles(7);
            let check = "b0f4c211-59ad-4f0e-8c37-2e6d5a9f1b84";
            let apply = "c7a1e3d8-46b2-4ff1-9d05-8a2c7b6e4f10";
            std::fs::write(
                requests.path().join(format!("{check}.json")),
                r#"{"kind":"check_update"}"#,
            )
            .unwrap();
            std::fs::write(
                requests.path().join(format!("{apply}.json")),
                r#"{"kind":"apply"}"#,
            )
            .unwrap();

            // What `attach_and_watch` resolves from systemd's answer, and
            // then what `reconcile_interlock` does with it.
            let holder = interlock_holder_in(
                requests.path(),
                &[format!("ferrum-apply@{check}.service")],
            );
            assert_eq!(
                holder, None,
                "a read-only check is not a claimant, so reconciliation must not seed the \
                 interlock from one"
            );
            let shared = state();
            *shared.interlock.lock().unwrap() = holder;

            let (status, body, _) = dispatch_with(
                requests.path(),
                Ok(profiles.path().to_path_buf()),
                shared.clone(),
                JobRequest::Rollback { to: 6 },
            )
            .await;
            assert_ne!(
                status,
                StatusCode::CONFLICT,
                "a rollback must never be refused because a read-only check happens to be \
                 running -- that is verbatim the outcome DA-7 exists to prevent: {body}"
            );
            // There is no system bus here, so it fails at the dispatch. That
            // is the proof it got as far as trying, which a 409 never does.
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

            // The positive control: an APPLY running at startup must still
            // seed the interlock, and the same rollback must then be
            // refused. Without this the assertion above would also pass a
            // reconciliation that had simply stopped seeding anything.
            let holder = interlock_holder_in(
                requests.path(),
                &[format!("ferrum-apply@{apply}.service")],
            );
            assert_eq!(
                holder.as_deref(),
                Some(apply),
                "an apply systemd reports running must seed the interlock, and the interlock \
                 must name it"
            );
            let restarted = state();
            *restarted.interlock.lock().unwrap() = holder;

            let (status, body, _) = dispatch_with(
                requests.path(),
                Ok(profiles.path().to_path_buf()),
                restarted.clone(),
                JobRequest::Rollback { to: 6 },
            )
            .await;
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "a rollback alongside an apply that is still switching the system is the \
                 concurrency the interlock exists to refuse: {body}"
            );
        }
    }

    /// The two decisions `main.rs` used to make inline, where no test could
    /// reach them. Both defects lived in exactly those lines.
    mod interlock {
        use super::*;

        const APPLY: &str = "3c8d5a72-1e94-4b60-8f21-7d4e0a9c6b35";
        const CHECK: &str = "f1927b04-8ca6-4d3f-91e7-0b52d8a37c6e";

        fn unit(uuid: &str) -> String {
            format!("ferrum-apply@{uuid}.service")
        }

        /// A requests directory holding exactly the `(uuid, kind)` pairs
        /// given, written in the same shape `request_body` writes.
        fn requests_holding(entries: &[(&str, &str)]) -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            for (uuid, kind) in entries {
                std::fs::write(
                    dir.path().join(format!("{uuid}.json")),
                    serde_json::json!({ "kind": kind }).to_string(),
                )
                .unwrap();
            }
            dir
        }

        /// `kind_takes_interlock` is asked about the string `request_body`
        /// actually writes, so this walks every variant and derives the
        /// string the same way the handler does rather than restating it.
        /// A seventh kind added without a decision here would fail this.
        #[test]
        fn every_kind_but_the_read_only_check_claims_the_interlock() {
            let cases = [
                (JobRequest::Preflight, true),
                (JobRequest::Apply, true),
                (JobRequest::Rollback { to: 3 }, true),
                (JobRequest::RestoreState, true),
                (JobRequest::Gc, true),
                (JobRequest::CheckUpdate, false),
            ];
            for (req, claims) in cases {
                let kind = request_body(&req)
                    .get("kind")
                    .and_then(|k| k.as_str())
                    .expect("every request kind must serialize a kind string")
                    .to_string();
                assert_eq!(
                    kind_takes_interlock(&kind),
                    claims,
                    "kind={kind} must {} the interlock",
                    if claims { "claim" } else { "be exempt from" }
                );
            }
        }

        #[test]
        fn a_recorded_kind_is_read_back_and_anything_unreadable_is_no_answer() {
            let dir = requests_holding(&[(APPLY, "apply"), (CHECK, "check_update")]);
            assert_eq!(request_kind_in(dir.path(), APPLY).as_deref(), Some("apply"));
            assert_eq!(
                request_kind_in(dir.path(), CHECK).as_deref(),
                Some("check_update")
            );

            // Absent, not JSON, and JSON without a string kind are all "we
            // cannot say" rather than a kind.
            assert_eq!(
                request_kind_in(dir.path(), "00000000-0000-4000-8000-000000000000"),
                None
            );
            std::fs::write(dir.path().join("broken.json"), "not json at all").unwrap();
            assert_eq!(request_kind_in(dir.path(), "broken"), None);
            std::fs::write(dir.path().join("kindless.json"), r#"{"to":7}"#).unwrap();
            assert_eq!(request_kind_in(dir.path(), "kindless"), None);
        }

        /// Defect 1. The unit name carries only a UUID, so nothing in it
        /// says whether the job that just ended was a check or an apply --
        /// and a check that fails on DNS ends in seconds while an apply is
        /// still building and switching. Releasing on unit-name shape
        /// rather than on identity handed the next `apply` or `rollback` a
        /// free pass alongside a root-privileged system switch already in
        /// flight.
        ///
        /// The holder's own completion is asserted in the same test as the
        /// positive control: a rule that never released anything would
        /// satisfy the first half and wedge the daemon permanently.
        #[test]
        fn only_the_interlock_holders_own_completion_releases_it() {
            let held = Some(APPLY);

            let other = job_removed_effects(&unit(CHECK), held);
            assert!(
                !other.release_interlock,
                "a read-only check finishing must not release the interlock of an apply that \
                 is still running -- it would admit a second root system switch alongside it"
            );

            let own = job_removed_effects(&unit(APPLY), held);
            assert!(
                own.release_interlock,
                "the holder's own completion is the one thing that must release it; without \
                 this the interlock has no timeout and no cancel and would wedge the daemon"
            );

            // An unclaimed interlock stays unclaimed rather than being
            // "released" into some other state.
            assert!(!job_removed_effects(&unit(APPLY), None).release_interlock);
            assert!(!job_removed_effects("sshd.service", held).release_interlock);
        }

        /// The request file is spent for every kind, and that is decided
        /// separately from the interlock. A check's file is just as
        /// replayable a privileged trigger as an apply's.
        #[test]
        fn every_kinds_completion_marks_its_own_request_file_spent() {
            assert_eq!(
                job_removed_effects(&unit(CHECK), Some(APPLY)).spent_request.as_deref(),
                Some(CHECK),
                "a check's file is spent even though its completion releases nothing"
            );
            assert_eq!(
                job_removed_effects(&unit(APPLY), Some(APPLY)).spent_request.as_deref(),
                Some(APPLY)
            );
            // Still gated on a real UUID, and still nothing for a unit that
            // is not ours: the value names a file to delete.
            assert_eq!(job_removed_effects("sshd.service", None).spent_request, None);
            assert_eq!(
                job_removed_effects("ferrum-apply@../../etc/passwd.service", None).spent_request,
                None
            );
        }

        #[test]
        fn a_running_check_is_not_a_claimant_but_a_running_apply_is() {
            let dir = requests_holding(&[(APPLY, "apply"), (CHECK, "check_update")]);

            assert_eq!(
                interlock_holder_in(dir.path(), &[unit(CHECK)]),
                None,
                "a read-only check running is not a job holding the interlock"
            );
            assert_eq!(
                interlock_holder_in(dir.path(), &[unit(APPLY)]).as_deref(),
                Some(APPLY),
                "an apply running is"
            );
            // A check running beside an apply must not hide the apply.
            assert_eq!(
                interlock_holder_in(dir.path(), &[unit(CHECK), unit(APPLY)]).as_deref(),
                Some(APPLY)
            );
            assert_eq!(interlock_holder_in(dir.path(), &[]), None);
        }

        /// Fail-closed. A running unit whose kind cannot be established --
        /// its request file already deleted, unreadable, or written by an
        /// older ferrumd -- is treated as claiming the interlock.
        ///
        /// The cost of guessing "check" wrongly is two concurrent
        /// `nix-env --set` and `switch-to-configuration` runs as root. The
        /// cost of guessing "apply" wrongly is a 409 that lasts only as
        /// long as the unit does, because the next reconciliation re-derives
        /// the answer from systemd rather than from this state.
        #[test]
        fn a_running_unit_of_unknown_kind_claims_the_interlock() {
            let dir = requests_holding(&[(CHECK, "check_update")]);
            let unknown = "8b3c1d59-2f74-4e08-a916-6d0e5b7c3a21";

            assert_eq!(
                interlock_holder_in(dir.path(), &[unit(unknown)]).as_deref(),
                Some(unknown),
                "a running unit we cannot classify must be treated as interlock-taking"
            );
            // The control that keeps that from being "everything claims it":
            // a unit we CAN classify as a check still does not.
            assert_eq!(interlock_holder_in(dir.path(), &[unit(CHECK)]), None);
        }
    }

    #[test]
    fn jobs_and_requests_dirs_fall_back_to_the_real_deployed_defaults() {
        std::env::remove_var("FERRUM_JOBS_DIR");
        std::env::remove_var("FERRUM_REQUESTS_DIR");
        assert_eq!(jobs_dir(), std::path::PathBuf::from("/var/lib/ferrum/jobs"));
        assert_eq!(requests_dir(), std::path::PathBuf::from("/run/ferrum/requests"));
    }
}
