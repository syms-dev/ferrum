// The Job API: the daemon's actual reason to exist. POST /api/jobs writes
// a request file into /run/ferrum/requests and asks systemd (over D-Bus,
// authorized by the polkit rule in modules/core/daemon.nix) to start
// `ferrum-apply@<uuid>.service`. GET /api/jobs/:id/stream replays and then
// live-tails that job's own JSONL progress file, which ferrum-apply writes
// via crates/ferrum-apply/src/progress.rs.
//
// Note what ferrumd never does here: it never builds, never switches, never
// touches the Nix profile, and never runs anything as root. The entire
// privileged surface is the closed five-variant request enum below, which
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
}

fn jobs_dir() -> std::path::PathBuf {
    std::env::var("FERRUM_JOBS_DIR")
        .unwrap_or_else(|_| "/var/lib/ferrum/jobs".to_string())
        .into()
}

fn requests_dir() -> std::path::PathBuf {
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
pub fn remove_request_file(uuid: &str) {
    remove_request_file_in(&requests_dir(), uuid)
}

/// The body of `remove_request_file`, with the directory passed in so the
/// tests below exercise the real deletion against a real temp directory
/// without mutating process-wide environment state that the other tests in
/// this module read concurrently.
fn remove_request_file_in(dir: &std::path::Path, uuid: &str) {
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
    Json(req): Json<JobRequest>,
) -> impl IntoResponse {
    {
        let mut running = state.job_running.lock().unwrap();
        if *running {
            return (StatusCode::CONFLICT, "a job is already running").into_response();
        }
        *running = true;
    }

    let uuid = Uuid::new_v4().to_string();
    let body = request_body(&req);

    let release = || {
        *state.job_running.lock().unwrap() = false;
    };

    let dir = requests_dir();
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        release();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create requests dir: {e}"),
        )
            .into_response();
    }
    let request_path = dir.join(format!("{uuid}.json"));
    if let Err(e) = tokio::fs::write(&request_path, body.to_string()).await {
        release();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to write request file: {e}"),
        )
            .into_response();
    }

    if let Err(e) = crate::dbus::start_ferrum_apply_unit(&uuid).await {
        release();
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

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
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    let first = lines.first().and_then(|l| parse_line(l));
    let last = lines.last().and_then(|l| parse_line(l));

    let Some(first) = first else {
        return Ok(Some(JobSummary {
            id: id.to_string(),
            kind: None,
            status: "unknown",
            result: None,
            detail: None,
            started_at: None,
            finished_at: None,
        }));
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

    Ok(Some(JobSummary { id: id.to_string(), kind, status, result, detail, started_at, finished_at }))
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
    // Reads the job's whole progress file twice (summarize, then events), so
    // it goes to the blocking pool -- see main.rs's run_blocking.
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
    let summary = match summarize(id, &path) {
        Ok(Some(s)) => s,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such job").into_response(),
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

    let events = std::fs::read_to_string(&path)
        .map(|c| {
            c.lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(parse_line)
                .map(|v| JobEvent {
                    ts: v.get("ts").and_then(|t| t.as_u64()),
                    event: str_field(&v, "event"),
                    detail: str_field(&v, "detail"),
                })
                .collect()
        })
        .unwrap_or_default();

    Json(JobDetail { summary, events }).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn jobs_and_requests_dirs_fall_back_to_the_real_deployed_defaults() {
        std::env::remove_var("FERRUM_JOBS_DIR");
        std::env::remove_var("FERRUM_REQUESTS_DIR");
        assert_eq!(jobs_dir(), std::path::PathBuf::from("/var/lib/ferrum/jobs"));
        assert_eq!(requests_dir(), std::path::PathBuf::from("/run/ferrum/requests"));
    }
}
