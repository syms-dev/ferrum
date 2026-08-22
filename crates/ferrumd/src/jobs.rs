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
    extract::{Path, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    Json,
};
use serde::Deserialize;
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
    if let Err(e) = std::fs::create_dir_all(&dir) {
        release();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to create requests dir: {e}"),
        )
            .into_response();
    }
    let request_path = dir.join(format!("{uuid}.json"));
    if let Err(e) = std::fs::write(&request_path, body.to_string()) {
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
            let Ok(content) = std::fs::read_to_string(&path) else {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn jobs_and_requests_dirs_fall_back_to_the_real_deployed_defaults() {
        std::env::remove_var("FERRUM_JOBS_DIR");
        std::env::remove_var("FERRUM_REQUESTS_DIR");
        assert_eq!(jobs_dir(), std::path::PathBuf::from("/var/lib/ferrum/jobs"));
        assert_eq!(requests_dir(), std::path::PathBuf::from("/run/ferrum/requests"));
    }
}
