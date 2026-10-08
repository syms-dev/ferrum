// GET /api/parity -- serves the parity status report `ferrum-apply` wrote.
//
// WHY THIS IS NOT PART OF /api/health OR /api/ready. health.rs's own header
// is explicit that readiness "does NOT mean... that the media pool is
// mounted, that every mergerfs branch is present, or that there is free
// space" -- "Nothing here touches storage" -- and those two routes are
// deliberately the only unauthenticated /api/ surface besides login, logout
// and sso. Parity status is operator-facing detail: file counts, mount
// points, a last-sync timestamp. Folding it into a monitor-robot liveness
// signal would both stretch those routes past their stated design and
// publish the shape of someone's storage to anyone who can reach the port.
// So this is a new route, inside the authenticated group.
//
// WHY ferrumd DOES NOT COMPUTE IT. `snapraid diff` opens every data disk
// and the parity file directly, as root. ferrumd is unprivileged, and the
// invariant that it never shells out to a privileged tool is the same one
// generations.rs records for `nix-env` and updates.rs for `nix`. The
// document is produced by `ferrum-apply parity-status`, dispatched as an
// ordinary job; ferrumd's entire part is to hand the UI what that run wrote.
//
// The document is served as an opaque `serde_json::Value`, exactly as
// updates.rs serves its own and catalog.rs serves $FERRUM_CATALOG. The
// producer (crates/ferrum-apply/src/parity.rs) is the one place the report's
// shape is written down; a mirror here would be a second place, and a second
// place is a place to drift.
//
// This deliberately mirrors updates.rs rather than factoring a shared
// scanner out of it. The two envelopes differ -- updates.rs answers a
// `?job=` query this route has no analogue for -- and generalising a
// well-tested file to save twenty lines here would put the update path's
// behaviour at risk for no gain to either.
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// The producer writes `<job-id>.parity-status.json` beside that job's own
/// `<job-id>.jsonl` progress file, and `latest.parity-status.json` for a run
/// with no job id (a bare CLI invocation over SSH).
const REPORT_SUFFIX: &str = ".parity-status.json";

/// The stem the producer uses when a run has no job id. Not a job id, so a
/// report found under it is reported with `jobId: null`.
const OFF_JOB_STEM: &str = "latest";

/// Where parity reports live.
///
/// `FERRUM_PARITY_REPORT_DIR` first so the reports can be moved off the jobs
/// directory later without touching either side; `FERRUM_JOBS_DIR` second
/// because that is where the producer puts them today. The same defaults and
/// the same order the producer itself uses, so the two cannot disagree.
///
/// # Returns
/// The directory to read reports from. Never fails: every step has a default.
fn report_dir() -> PathBuf {
    resolve_report_dir(
        std::env::var("FERRUM_PARITY_REPORT_DIR").ok(),
        std::env::var("FERRUM_JOBS_DIR").ok(),
    )
}

/// The fallback chain with the environment already read.
///
/// Split out so it can be tested without `set_var`/`remove_var`: this
/// binary's tests share one process, and updates.rs records a real flake
/// caused by exactly that collision.
///
/// # Arguments
/// * `parity_var` - `FERRUM_PARITY_REPORT_DIR`, if set.
/// * `jobs_var` - `FERRUM_JOBS_DIR`, if set.
///
/// # Returns
/// The first of the two that is set, or `/var/lib/ferrum/jobs`.
fn resolve_report_dir(parity_var: Option<String>, jobs_var: Option<String>) -> PathBuf {
    parity_var
        .or(jobs_var)
        .unwrap_or_else(|| "/var/lib/ferrum/jobs".to_string())
        .into()
}

/// The job id a report file name carries, if it is a report file at all.
///
/// # Arguments
/// * `name` - one directory entry's file name.
///
/// # Returns
/// `Some(None)` for the off-job report, `Some(Some(id))` for a job's own,
/// and `None` for anything else in the directory -- which is every
/// `<job-id>.jsonl` progress file and every update report, so three artefact
/// kinds sharing one directory can never be confused for each other.
fn report_job_id(name: &str) -> Option<Option<String>> {
    let stem = name.strip_suffix(REPORT_SUFFIX)?;
    if stem == OFF_JOB_STEM {
        return Some(None);
    }
    Some(Some(stem.to_string()))
}

/// Finds the most recent parity report in `dir`.
///
/// Newest by the file's own mtime, with the file name as a tie-break so two
/// reports written inside one filesystem timestamp tick still produce a
/// stable answer rather than whichever `read_dir` happened to yield last.
///
/// # Arguments
/// * `dir` - the report directory.
///
/// # Returns
/// `Ok(None)` when the directory holds no parity report, INCLUDING when the
/// directory itself does not exist -- a host that has never run the check
/// has never had it created, and that is the not-yet-checked state rather
/// than a fault.
///
/// # Errors
/// A string naming the real path when the directory exists but cannot be
/// listed, or the winning file cannot be read or parsed. Neither is
/// flattened into `Ok(None)`: a fault reported as an absence renders as a
/// statement about the host rather than about ferrumd, and sends an operator
/// looking in the wrong place.
fn newest_report(dir: &Path) -> Result<Option<(Option<String>, Value)>, String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(format!(
                "could not read the parity report directory {}: {e}",
                dir.display()
            ))
        }
    };

    let mut best: Option<(std::time::SystemTime, String)> = None;
    for entry in entries {
        let entry = entry.map_err(|e| {
            format!("could not read the parity report directory {}: {e}", dir.display())
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if report_job_id(&name).is_none() {
            continue;
        }
        let modified = match entry.metadata().and_then(|m| m.modified()) {
            Ok(modified) => modified,
            // Deleted between read_dir and stat -- the same benign race
            // jobs.rs and updates.rs both treat as a skip.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(format!(
                    "could not read the parity report {}: {e}",
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
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        // It was in the listing a moment ago and is gone now. Reporting the
        // host as unchecked would be a guess; saying what happened is not.
        Err(e) => {
            return Err(format!(
                "the parity report at {} could not be read: {e}",
                path.display()
            ))
        }
    };
    let document: Value = serde_json::from_str(&raw).map_err(|e| {
        format!("the parity report at {} is not valid JSON: {e}", path.display())
    })?;
    Ok(Some((
        report_job_id(&name).expect("the name matched the suffix above"),
        document,
    )))
}

/// The 200 body for a host on which the parity check has never run.
///
/// An explicit, successful state rather than a 404 or an empty body, and the
/// requirement names the reason: the UI must be able to tell "never checked"
/// from "checked, and current" from "the check failed". A 404 would be
/// indistinguishable from a wrong URL, and an empty body from a broken
/// daemon.
///
/// Note what this state is NOT: it is not "parity is not configured". That
/// is a fact about the host, which only the privileged producer can
/// establish, and it arrives as `state: "not-configured"` INSIDE a report.
/// This state means only that no report exists yet.
fn never_checked_body() -> Value {
    serde_json::json!({ "status": "never-checked", "jobId": null, "report": null })
}

/// The body of [`get_parity`]; the directory is a parameter rather than read
/// from the environment so tests drive real fixtures -- the same split
/// `jobs.rs::get_job_in` and `updates.rs` already use.
///
/// # Arguments
/// * `dir` - the report directory.
///
/// # Returns
/// 200 with the newest report, 200 never-checked, or 500 naming the path for
/// any read or parse fault.
fn parity_response_in(dir: &Path) -> axum::response::Response {
    match newest_report(dir) {
        Ok(Some((job_id, document))) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "report",
                "jobId": job_id,
                "report": document,
            })),
        )
            .into_response(),
        Ok(None) => (StatusCode::OK, Json(never_checked_body())).into_response(),
        Err(message) => (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
    }
}

/// `GET /api/parity` -- the newest parity status report this host produced.
///
/// Authenticated: it is behind `require_session` in `build_router`, with
/// every other `/api/` route except health, ready, login, logout and sso.
///
/// # Returns
/// * `200` `{"status":"report","jobId":<id|null>,"report":{...}}` -- the
///   producer's whole document, verbatim.
/// * `200` `{"status":"never-checked","jobId":null,"report":null}` -- no
///   parity check has run on this host yet.
/// * `500` with a message naming the path when the report directory or the
///   report itself cannot be read.
pub async fn get_parity() -> impl IntoResponse {
    parity_response_in(&report_dir())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_of(resp: axum::response::Response) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    const REPORT: &str = r#"{"schemaVersion":1,"state":"in-sync","generatedAt":100,
        "lastSync":{"finishedAt":90,"result":"success"},"elapsedSeconds":10,
        "unprotected":{"equal":3,"added":0,"removed":0,"updated":0,"moved":0,"copied":0,"restored":0},
        "unprotectedUnavailable":null,"unprotectedBytesUnavailable":"x",
        "parityDisks":[{"path":"/mnt/p/snapraid.parity","present":true}],"limitation":"y"}"#;

    /// A missing directory is "nothing has run yet", with a 200 and a named
    /// status -- never a 404, which the UI could not tell from a wrong URL.
    #[tokio::test]
    async fn a_host_that_has_never_checked_gets_a_named_state_not_a_404() {
        let dir = tempfile::tempdir().unwrap();
        let (status, body) =
            body_of(parity_response_in(&dir.path().join("absent"))).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"never-checked\""), "{body}");
        assert!(body.contains("\"report\":null"), "{body}");
    }

    /// An empty directory is the same state. Without this the assertion
    /// above would pass against an implementation that only handled the
    /// missing-directory case.
    #[tokio::test]
    async fn an_empty_report_directory_is_also_never_checked() {
        let dir = tempfile::tempdir().unwrap();
        let (status, body) = body_of(parity_response_in(dir.path())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"never-checked\""), "{body}");
    }

    /// A progress file is not a report, and neither is an UPDATE report
    /// sitting in the same directory. Three artefact kinds share it.
    #[tokio::test]
    async fn only_parity_reports_are_treated_as_parity_reports() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "11111111-1111-4111-8111-111111111111.jsonl", "{}");
        write(dir.path(), "latest.update-check.json", "{}");
        let (status, body) = body_of(parity_response_in(dir.path())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"never-checked\""), "{body}");
    }

    /// The producer's document is served verbatim, with the run it came from.
    #[tokio::test]
    async fn a_jobs_report_is_served_with_its_job_id() {
        let dir = tempfile::tempdir().unwrap();
        let id = "22222222-2222-4222-8222-222222222222";
        write(dir.path(), &format!("{id}.parity-status.json"), REPORT);
        let (status, body) = body_of(parity_response_in(dir.path())).await;
        assert_eq!(status, StatusCode::OK);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "report");
        assert_eq!(v["jobId"], id);
        assert_eq!(v["report"]["state"], "in-sync");
        assert_eq!(v["report"]["lastSync"]["finishedAt"], 90);
        assert_eq!(v["report"]["elapsedSeconds"], 10);
    }

    /// An off-job run reports a null job id rather than the literal stem,
    /// which the UI would otherwise hand back to GET /api/jobs/:id.
    #[tokio::test]
    async fn an_off_job_report_reports_a_null_job_id() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "latest.parity-status.json", REPORT);
        let (_, body) = body_of(parity_response_in(dir.path())).await;
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["status"], "report");
        assert!(v["jobId"].is_null(), "{body}");
    }

    /// Corrupt JSON is a 500 naming the path, not a never-checked 200. A
    /// fault reported as an absence is a statement about the host rather
    /// than about ferrumd.
    #[tokio::test]
    async fn an_unreadable_report_is_a_fault_not_an_absence() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "latest.parity-status.json", "{not json");
        let (status, body) = body_of(parity_response_in(dir.path())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("not valid JSON"), "{body}");
        assert!(body.contains("latest.parity-status.json"), "{body}");
    }

    #[test]
    fn the_report_directory_falls_back_the_same_way_the_producer_does() {
        assert_eq!(
            resolve_report_dir(Some("/a".into()), Some("/b".into())),
            PathBuf::from("/a")
        );
        assert_eq!(resolve_report_dir(None, Some("/b".into())), PathBuf::from("/b"));
        assert_eq!(resolve_report_dir(None, None), PathBuf::from("/var/lib/ferrum/jobs"));
    }
}
