// GET /api/updates -- serves the update-check report ferrum-apply wrote.
//
// R3's second acceptance criterion is the whole shape of this file: the
// evaluation that answers "what would an update change?" runs inside
// privileged `ferrum-apply`, dispatched as an ordinary job, because ferrumd
// must never shell out to `nix` (that would put the whole Nix closure on the
// unprivileged daemon's PATH -- the same reasoning generations.rs already
// records for not calling `nix-env --list-generations`). ferrumd's entire
// part is to hand the UI the document that run produced.
//
// The document is served as an opaque `serde_json::Value`, exactly as
// catalog.rs serves `$FERRUM_CATALOG`, and deliberately NOT modelled as Rust
// structs. The producer (ferrum-apply's check_update job) is the one place
// the report's shape is written down; a mirror here would be a second place,
// and a second place is a place to drift. A field added on the producing side
// reaches the UI with no change to this file at all.
//
// The one thing ferrumd does decide is the envelope: whether a report exists,
// which run it came from, and whether the report directory could be read at
// all. Those three are ferrumd's own answers, so they are typed here.
use axum::{extract::Query, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// The producer writes `<job-id>.update-check.json` beside that job's own
/// `<job-id>.jsonl` progress file, and `latest.update-check.json` for a run
/// with no job id (a bare CLI invocation over SSH).
const REPORT_SUFFIX: &str = ".update-check.json";

/// The stem the producer uses when a run has no job id. It is not a job id,
/// so a report found under it is reported with `jobId: null` rather than the
/// literal string, which the UI would otherwise hand straight back to
/// `GET /api/jobs/:id` and get a 400 for.
const OFF_JOB_STEM: &str = "latest";

/// Where update-check reports live.
///
/// `FERRUM_UPDATE_REPORT_DIR` first so the reports can be moved off the jobs
/// directory later without touching either side; `FERRUM_JOBS_DIR` second
/// because that is where the producer puts them today, beside each job's own
/// progress file; the same `/var/lib/ferrum/jobs` default `jobs.rs::jobs_dir`
/// already carries, so the two cannot disagree about where a job's artefacts
/// are when neither variable is set.
///
/// # Returns
/// The directory to read reports from. Never fails: every step has a default.
fn report_dir() -> PathBuf {
    resolve_report_dir(
        std::env::var("FERRUM_UPDATE_REPORT_DIR").ok(),
        std::env::var("FERRUM_JOBS_DIR").ok(),
    )
}

/// The fallback chain itself, with the environment already read.
///
/// Split out so it can be tested without `set_var`/`remove_var`: this binary's
/// tests share one process, and `jobs.rs`'s
/// `handlers_skip_non_uuid_files_clamp_limit_and_reject_traversal_ids`
/// records a real flake caused by exactly that collision -- an earlier
/// version of it set `FERRUM_JOBS_DIR` while that module's own `jobs_dir()`
/// default test called `remove_var` concurrently. A pure function has no
/// such hazard.
///
/// # Arguments
/// * `update_var` - `FERRUM_UPDATE_REPORT_DIR`, if set.
/// * `jobs_var` - `FERRUM_JOBS_DIR`, if set.
///
/// # Returns
/// The first of the two that is set, or `/var/lib/ferrum/jobs`.
fn resolve_report_dir(update_var: Option<String>, jobs_var: Option<String>) -> PathBuf {
    update_var
        .or(jobs_var)
        .unwrap_or_else(|| "/var/lib/ferrum/jobs".to_string())
        .into()
}

/// `GET /api/updates` query string.
///
/// `job` is optional: absent means "the most recent check on this host",
/// which is what the Updates view wants on first paint; present means "the
/// report that specific check produced", which is what it wants immediately
/// after streaming a `check_update` job to completion.
#[derive(Deserialize)]
pub struct UpdatesQuery {
    pub job: Option<String>,
}

/// One report read off disk, with the run it came from.
struct FoundReport {
    /// `None` for the off-job `latest.update-check.json`.
    job_id: Option<String>,
    document: Value,
}

/// Reads one report file, separating "not there" from "there and broken".
///
/// # Arguments
/// * `path` - the report file to read.
///
/// # Returns
/// `Ok(None)` when the file genuinely does not exist, `Ok(Some(document))`
/// when it parses.
///
/// # Errors
/// A string naming the real path for any OTHER read error (a permission
/// regression on the jobs directory, most plausibly) and for JSON that does
/// not parse. Neither is flattened into `Ok(None)`: a fault reported as an
/// absence renders in the UI as "this host has never been checked", which is
/// a statement about the host rather than about ferrumd, and sends an
/// operator looking in the wrong place. `jobs.rs::summarize` draws the same
/// line for the same reason.
fn read_report(path: &Path) -> Result<Option<Value>, String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!("could not read the update report at {}: {e}", path.display()))
        }
    };
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|e| format!("the update report at {} is not valid JSON: {e}", path.display()))
}

/// The job id a report file name carries, if it is a report file at all.
///
/// # Arguments
/// * `name` - one directory entry's file name.
///
/// # Returns
/// `Some(None)` for the off-job `latest.update-check.json`, `Some(Some(id))`
/// for a job's own report, and `None` for anything else in the directory --
/// which is every `<job-id>.jsonl` progress file, so the two artefact kinds
/// sharing one directory can never be confused for each other.
fn report_job_id(name: &str) -> Option<Option<String>> {
    let stem = name.strip_suffix(REPORT_SUFFIX)?;
    if stem == OFF_JOB_STEM {
        return Some(None);
    }
    Some(Some(stem.to_string()))
}

/// Finds the most recent report in `dir`.
///
/// Newest by the file's own mtime, with the file name as a tie-break so two
/// reports written inside one filesystem timestamp tick still produce a
/// stable answer rather than whichever `read_dir` happened to yield last.
///
/// Scanning is not an optimisation gone wrong: it is the only correct answer
/// to "the most recent check". The producer writes `latest.update-check.json`
/// only for an off-job run, so after a UI-driven check that file may not
/// exist at all, and reading it alone would report a host as never-checked
/// immediately after it was checked.
///
/// # Arguments
/// * `dir` - the report directory.
///
/// # Returns
/// `Ok(None)` when the directory holds no report, INCLUDING when the
/// directory itself does not exist -- a host that has never run a check has
/// never had the directory created, and that is the never-checked state, not
/// a fault.
///
/// # Errors
/// A string naming the real path when the directory exists but cannot be
/// listed, when an entry's metadata cannot be read for any reason other than
/// the entry having vanished mid-scan, or when the winning file cannot be
/// read or parsed.
///
/// # Known limitation
/// "Most recent" means the newest mtime, so a host clock that steps BACKWARDS
/// between two checks -- NTP correcting a fast clock -- makes the newer report
/// look older, and this serves the previous one. Accepted rather than fixed:
/// the alternative is trusting the document's own `checkedAt`, which would
/// make ferrumd parse a document it deliberately treats as opaque, and buy
/// nothing against a clock that was wrong when `checkedAt` was written either.
/// What keeps it from being silent is the UI rendering `checkedAt`, so a stale
/// answer is at least visibly stale.
fn newest_report(dir: &Path) -> Result<Option<FoundReport>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!("could not read the update report directory {}: {e}", dir.display()))
        }
    };

    let mut best: Option<(std::time::SystemTime, String)> = None;
    for entry in entries {
        let entry = entry.map_err(|e| {
            format!("could not read the update report directory {}: {e}", dir.display())
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if report_job_id(&name).is_none() {
            continue;
        }
        let modified = match entry.metadata().and_then(|m| m.modified()) {
            Ok(modified) => modified,
            // Deleted between read_dir and stat -- a benign race, the same
            // one jobs.rs::list_jobs_in treats as a skip rather than a fault.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(format!(
                    "could not read the update report {}: {e}",
                    dir.join(&name).display()
                ))
            }
        };
        if best.as_ref().is_none_or(|(t, n)| (modified, &name) > (*t, n)) {
            best = Some((modified, name));
        }
    }

    let Some((_, name)) = best else {
        return Ok(None);
    };
    let path = dir.join(&name);
    match read_report(&path)? {
        Some(document) => Ok(Some(FoundReport {
            job_id: report_job_id(&name).expect("the name matched the suffix above"),
            document,
        })),
        // It was in the listing a moment ago and is gone now. Reporting the
        // host as never-checked would be a guess; saying what happened is not.
        None => Err(format!("the update report at {} vanished while being read", path.display())),
    }
}

/// The 200 body for a report that was found.
///
/// # Arguments
/// * `found` - the report and the run it came from.
///
/// # Returns
/// `{"status":"report","jobId":<id or null>,"report":<the producer's whole
/// document, verbatim>}`.
fn report_body(found: FoundReport) -> Value {
    serde_json::json!({
        "status": "report",
        "jobId": found.job_id,
        "report": found.document,
    })
}

/// The 200 body for a host on which no check has ever run.
///
/// An explicit, successful state rather than a 404 or an empty body: the UI
/// must be able to tell "never checked" from "checked, and up to date" from
/// "the check failed", and only the first of those is ferrumd's to answer.
/// A 404 would make it indistinguishable from a wrong URL, and an empty
/// body from a broken daemon.
fn never_checked_body() -> Value {
    serde_json::json!({ "status": "never-checked", "jobId": null, "report": null })
}

/// The body of `get_updates`; the directory is a parameter rather than read
/// from the environment here so tests drive real fixtures, the same split
/// `jobs.rs::get_job_in` already uses.
///
/// # Arguments
/// * `dir` - the report directory.
/// * `job` - the `?job=` value, if the caller sent one.
///
/// # Returns
/// The real response: 200 with a report, 200 never-checked, 400 for a `job`
/// that is not a UUID, 404 for a UUID with no report, or 500 naming the path
/// for any read or parse fault.
fn updates_response_in(dir: &Path, job: Option<&str>) -> axum::response::Response {
    let Some(id) = job else {
        return match newest_report(dir) {
            Ok(Some(found)) => (StatusCode::OK, Json(report_body(found))).into_response(),
            Ok(None) => (StatusCode::OK, Json(never_checked_body())).into_response(),
            Err(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        };
    };

    // Rejected before touching the filesystem, identical to
    // `jobs.rs::get_job_in`'s guard and for the identical reason: the id
    // becomes a path component, and without this a crafted value containing
    // `..` would let an authenticated operator read arbitrary files off the
    // box through the daemon.
    if Uuid::parse_str(id).is_err() {
        return (StatusCode::BAD_REQUEST, "job id must be a UUID").into_response();
    }
    let path = dir.join(format!("{id}{REPORT_SUFFIX}"));
    match read_report(&path) {
        Ok(Some(document)) => {
            let found = FoundReport { job_id: Some(id.to_string()), document };
            (StatusCode::OK, Json(report_body(found))).into_response()
        }
        // Named a specific run and that run produced no report -- it is
        // still running, or it failed before writing one. Deliberately NOT
        // the never-checked state: the caller asked about one run, and
        // answering about the host would be answering a different question.
        Ok(None) => (
            StatusCode::NOT_FOUND,
            format!("no update report for job {id}; the check may still be running or may have failed"),
        )
            .into_response(),
        Err(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
    }
}

/// `GET /api/updates` -- the most recent update check, or one run's own.
///
/// Read-only and session-gated. No CSRF token: it is a GET, and
/// `require_session` checks the token on mutating methods only.
///
/// # Arguments
/// * `query` - `?job=<uuid>` to fetch one run's report; omitted for the most
///   recent report on this host.
///
/// # Returns
/// * `200` `{"status":"report","jobId":<uuid|null>,"report":{...}}` -- the
///   producer's document verbatim under `report`.
/// * `200` `{"status":"never-checked","jobId":null,"report":null}` -- no
///   check has ever run here.
/// * `400` `job id must be a UUID` -- a `?job=` value that is not a UUID.
/// * `404` -- a UUID with no report on disk.
/// * `500` -- the report directory or file could not be read, or the report
///   is not valid JSON. The message names the real path.
///
/// Re-read from disk on every request, never cached, for the reason
/// catalog.rs records: a ferrumd left running across a generation switch must
/// not serve an answer its own host has moved past.
pub async fn get_updates(Query(query): Query<UpdatesQuery>) -> impl IntoResponse {
    // A directory listing and a file read per request, so it goes to the
    // blocking pool -- see main.rs's run_blocking.
    let dir = report_dir();
    match crate::run_blocking(move || updates_response_in(&dir, query.job.as_deref())).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A_JOB: &str = "11111111-2222-3333-4444-555555555555";
    const ANOTHER_JOB: &str = "99999999-8888-7777-6666-555555555555";

    /// A report document in the producer's real shape, trimmed to the fields
    /// an assertion below actually reads. It is written and read as opaque
    /// JSON, so the fields it does not carry are exactly as irrelevant to
    /// ferrumd as the ones it does -- which is the property being tested.
    fn a_report(state: &str) -> String {
        serde_json::json!({
            "schemaVersion": 1,
            "checkedAt": 1758700000u64,
            "candidate": { "state": state, "inputName": "ferrum" },
            "apps": [{ "id": "plex", "enabled": true, "state": "up-to-date" }],
            "warnings": []
        })
        .to_string()
    }

    /// Writes a report and stamps it with an explicit mtime.
    ///
    /// The mtime is set rather than inherited from the clock: "newest wins"
    /// is the behaviour under test, and a fixture that depended on two
    /// consecutive writes landing in different filesystem timestamp ticks
    /// would be asserting something about the ambient filesystem instead.
    fn write_report(dir: &Path, stem: &str, body: &str, age_secs: u64) {
        let path = dir.join(format!("{stem}{REPORT_SUFFIX}"));
        std::fs::write(&path, body).unwrap();
        let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + age_secs);
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(when).unwrap();
    }

    /// The real status and the real body of a real response.
    ///
    /// Everything below asserts on this rather than on the values fed in:
    /// the contract the UI lane is blocked on is what comes OUT of the
    /// handler, and a test that checked its inputs would agree with any
    /// implementation at all.
    async fn parts(response: axum::response::Response) -> (StatusCode, String) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn json_parts(response: axum::response::Response) -> (StatusCode, Value) {
        let (status, body) = parts(response).await;
        let value = serde_json::from_str(&body)
            .unwrap_or_else(|e| panic!("the response body must be JSON ({e}): {body}"));
        (status, value)
    }

    /// A host on which no check has ever run answers 200 with an explicit
    /// never-checked state -- not 404, not an empty body, not a 500. The UI
    /// has to distinguish this from "checked and up to date", and it can
    /// only do that if ferrumd says which one it is.
    #[tokio::test]
    async fn a_host_that_was_never_checked_is_an_explicit_success() {
        let dir = tempfile::tempdir().unwrap();
        let (status, body) = json_parts(updates_response_in(dir.path(), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "never-checked");
        assert_eq!(body["report"], Value::Null);
        assert_eq!(body["jobId"], Value::Null);
    }

    /// And so does a report directory that does not exist yet, which is the
    /// state of every host before its first privileged job ever ran.
    #[tokio::test]
    async fn a_report_directory_that_does_not_exist_is_never_checked_not_a_fault() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("never-created");
        let (status, body) = json_parts(updates_response_in(&absent, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "never-checked");
    }

    /// A directory holding only job progress files -- which is every host
    /// that has applied but never checked -- is still never-checked. This is
    /// the anti-vacuity guard for the test above: without it, a scan that
    /// matched nothing at all would pass both.
    #[tokio::test]
    async fn progress_files_are_not_mistaken_for_reports() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(format!("{A_JOB}.jsonl")), "{\"event\":\"started\"}\n")
            .unwrap();
        let (status, body) = json_parts(updates_response_in(dir.path(), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "never-checked");

        // ...and the same directory with a real report in it answers
        // differently, which proves the scan can see one at all.
        write_report(dir.path(), A_JOB, &a_report("update-available"), 0);
        let (status, body) = json_parts(updates_response_in(dir.path(), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "report");
    }

    /// The producer's document is served through verbatim, and the run it
    /// came from is named.
    #[tokio::test]
    async fn a_present_report_is_served_whole_with_its_job_id() {
        let dir = tempfile::tempdir().unwrap();
        write_report(dir.path(), A_JOB, &a_report("update-available"), 0);

        let (status, body) = json_parts(updates_response_in(dir.path(), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "report");
        assert_eq!(body["jobId"], A_JOB);
        assert_eq!(body["report"]["schemaVersion"], 1);
        assert_eq!(body["report"]["checkedAt"], 1758700000u64);
        assert_eq!(body["report"]["candidate"]["state"], "update-available");
        assert_eq!(body["report"]["apps"][0]["id"], "plex");
    }

    /// An off-job run's report is served with `jobId: null` -- the UI must
    /// not be handed the string "latest" and try to stream it as a job.
    #[tokio::test]
    async fn an_off_job_report_reports_no_job_id() {
        let dir = tempfile::tempdir().unwrap();
        write_report(dir.path(), OFF_JOB_STEM, &a_report("up-to-date"), 0);

        let (status, body) = json_parts(updates_response_in(dir.path(), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "report");
        assert_eq!(body["jobId"], Value::Null);
        assert_eq!(body["report"]["candidate"]["state"], "up-to-date");
    }

    /// With several reports on disk, the newest wins -- including when the
    /// newest is a job's own and the stale one is the off-job `latest`,
    /// which is precisely the state a UI-driven check leaves behind.
    #[tokio::test]
    async fn the_most_recent_report_wins() {
        let dir = tempfile::tempdir().unwrap();
        write_report(dir.path(), OFF_JOB_STEM, &a_report("not-checked"), 0);
        write_report(dir.path(), ANOTHER_JOB, &a_report("up-to-date"), 10);
        write_report(dir.path(), A_JOB, &a_report("update-available"), 20);

        let (status, body) = json_parts(updates_response_in(dir.path(), None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["jobId"], A_JOB);
        assert_eq!(body["report"]["candidate"]["state"], "update-available");
    }

    /// A specific run's report is addressable, and is not confused with the
    /// most recent one.
    #[tokio::test]
    async fn a_specific_job_gets_its_own_report() {
        let dir = tempfile::tempdir().unwrap();
        write_report(dir.path(), ANOTHER_JOB, &a_report("up-to-date"), 0);
        write_report(dir.path(), A_JOB, &a_report("update-available"), 20);

        let (status, body) = json_parts(updates_response_in(dir.path(), Some(ANOTHER_JOB))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["jobId"], ANOTHER_JOB);
        assert_eq!(
            body["report"]["candidate"]["state"], "up-to-date",
            "?job= must serve the named run's report, not the newest one"
        );
    }

    /// A real job that produced no report is a 404 naming the job -- not the
    /// never-checked state, which would be an answer about the host rather
    /// than about the run the caller asked about.
    #[tokio::test]
    async fn a_job_with_no_report_is_a_404_not_never_checked() {
        let dir = tempfile::tempdir().unwrap();
        write_report(dir.path(), OFF_JOB_STEM, &a_report("up-to-date"), 0);

        let (status, body) = parts(updates_response_in(dir.path(), Some(A_JOB))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains(A_JOB), "the 404 must name the job it could not find: {body}");
        assert!(!body.contains("never-checked"), "a missing run is not a never-checked host");
    }

    /// The id becomes a path component, so anything that is not a UUID is
    /// refused before the filesystem is touched.
    #[tokio::test]
    async fn a_traversing_job_id_is_refused_before_any_read() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret.update-check.json");
        std::fs::write(&secret, a_report("update-available")).unwrap();

        for id in ["../secret", "secret", "..", "not-a-uuid"] {
            let (status, body) = parts(updates_response_in(dir.path(), Some(id))).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "id {id:?} was not refused");
            assert!(body.contains("must be a UUID"), "got: {body}");
        }
    }

    /// A report that cannot be parsed is a fault, reported as one. Flattening
    /// it into never-checked would tell an operator their host has never been
    /// checked when in fact the answer is sitting on disk, unreadable.
    #[tokio::test]
    async fn a_malformed_report_is_a_fault_not_an_absence() {
        let dir = tempfile::tempdir().unwrap();
        write_report(dir.path(), A_JOB, "{ this is not json", 0);

        let (status, body) = parts(updates_response_in(dir.path(), None)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("not valid JSON"), "got: {body}");
        assert!(body.contains(A_JOB), "the fault must name the real file: {body}");

        // The same file asked for by job id, so neither path can quietly
        // degrade to an absence.
        let (status, body) = parts(updates_response_in(dir.path(), Some(A_JOB))).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("not valid JSON"), "got: {body}");
    }

    /// A report that cannot be read at all is a fault too, and a 404 would
    /// be a lie: the name is right there on disk.
    ///
    /// The unreadable file is a DIRECTORY wearing a report's name, not a
    /// chmod-000 file. Mode bits do not restrain root, and this suite runs
    /// as root under `nix build` and as an ordinary user on a dev box -- a
    /// permission fixture would therefore prove the fault path in one of
    /// those and quietly prove nothing in the other. `EISDIR` is the same
    /// "present but unreadable" branch and it is the same for every user.
    #[tokio::test]
    async fn an_unreadable_report_is_a_fault_not_a_404() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("{A_JOB}{REPORT_SUFFIX}"));
        std::fs::create_dir(&path).unwrap();
        assert!(
            std::fs::read_to_string(&path).is_err(),
            "the fixture must really be unreadable, or this test proves nothing"
        );

        let (status, body) = parts(updates_response_in(dir.path(), Some(A_JOB))).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("could not read"), "got: {body}");
        assert!(body.contains(A_JOB), "the fault must name the real file: {body}");

        // And the same file reached through the most-recent path, so neither
        // route can quietly degrade a fault into never-checked.
        let (status, body) = parts(updates_response_in(dir.path(), None)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("could not read"), "got: {body}");
    }

    /// An unlistable report directory is a fault, not a never-checked host --
    /// the same distinction, one level up, and proved the same
    /// privilege-independent way: `ENOTDIR` rather than a mode bit.
    #[tokio::test]
    async fn an_unlistable_report_directory_is_a_fault() {
        let parent = tempfile::tempdir().unwrap();
        let not_a_dir = parent.path().join("reports");
        std::fs::write(&not_a_dir, "this is a file, not a directory").unwrap();
        assert!(
            std::fs::read_dir(&not_a_dir).is_err(),
            "the fixture must really be unlistable, or this test proves nothing"
        );

        let (status, body) = parts(updates_response_in(&not_a_dir, None)).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("could not read the update report directory"), "got: {body}");
        assert!(body.contains("reports"), "the fault must name the real path: {body}");
    }

    /// The file-name recogniser the scan depends on, exercised directly.
    ///
    /// Every assertion the scan feeds is about which file WINS, so a
    /// recogniser that matched nothing would leave several of the tests
    /// above asserting the never-checked state and passing. This is the
    /// positive control for it.
    #[test]
    fn the_report_recogniser_reads_both_spellings_and_nothing_else() {
        assert_eq!(report_job_id("latest.update-check.json"), Some(None));
        assert_eq!(report_job_id(&format!("{A_JOB}.update-check.json")), Some(Some(A_JOB.into())));
        for other in [
            "11111111-2222-3333-4444-555555555555.jsonl",
            "update-check.json",
            "latest.update-check.json.tmp",
            "notes.json",
        ] {
            assert_eq!(report_job_id(other), None, "{other} must not be read as a report");
        }
    }

    /// The report directory prefers its own variable, falls back to the jobs
    /// directory the producer really writes into, and otherwise defaults to
    /// the same path `jobs.rs::jobs_dir` defaults to -- so with neither
    /// variable set the two cannot disagree about where a job's artefacts are.
    #[test]
    fn report_dir_resolution() {
        let both = resolve_report_dir(Some("/srv/reports".into()), Some("/srv/jobs".into()));
        assert_eq!(both, PathBuf::from("/srv/reports"));

        let jobs_only = resolve_report_dir(None, Some("/srv/jobs".into()));
        assert_eq!(jobs_only, PathBuf::from("/srv/jobs"));

        let neither = resolve_report_dir(None, None);
        assert_eq!(neither, PathBuf::from("/var/lib/ferrum/jobs"));
    }
}
