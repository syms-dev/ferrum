// A tiny, real JSONL progress writer -- one line per meaningful step,
// flushed immediately so a concurrently-tailing ferrumd sees each line
// as it's written, not batched. Only used when FERRUM_JOB_ID is set
// (i.e. this run was dispatched via `run-request`, not invoked by hand
// over SSH) -- a bare `ferrum-apply apply` run over SSH has no job id and
// no ferrumd tailing it, so it stays silent on this front exactly as it
// always has.
//
// FERRUM_JOB_ID is set on the real `ferrum-apply@%i.service` template unit
// (modules/core/daemon.nix) from systemd's own `%i` instance-name
// substitution, so it is always exactly the UUID ferrumd's own D-Bus
// StartUnit call used -- ferrumd's SSE handler tails
// $FERRUM_JOBS_DIR/<that uuid>.jsonl.
use std::io::Write;

pub struct Progress {
    file: Option<std::fs::File>,
}

impl Progress {
    pub fn open() -> Self {
        let job_id = std::env::var("FERRUM_JOB_ID").ok().filter(|id| !id.is_empty());
        let file = job_id.and_then(|id| {
            let dir = std::env::var("FERRUM_JOBS_DIR")
                .unwrap_or_else(|_| "/var/lib/ferrum/jobs".to_string());
            std::fs::create_dir_all(&dir).ok()?;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(format!("{dir}/{id}.jsonl"))
                .ok()
        });
        Self { file }
    }

    pub fn event(&mut self, event: &str, detail: &str) {
        if let Some(f) = &mut self.file {
            let line = serde_json::json!({
                "ts": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                "event": event,
                "detail": detail,
            });
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
        }
    }

    /// The terminal line for a job. ferrumd's SSE handler closes the stream
    /// when it sees a line containing `"complete"`, so exactly one of these
    /// must be written per dispatched job -- see the dispatch table in
    /// main.rs for which layer owns the `complete` line for each request
    /// kind.
    pub fn complete(&mut self, result: &str, detail: &str) {
        self.event("complete", &format!("{result}: {detail}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests mutate process-wide environment, so they're serialized
    /// into a single #[test] rather than racing each other across the test
    /// harness's threads.
    #[test]
    fn writes_jsonl_only_when_a_job_id_is_set() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("FERRUM_JOBS_DIR", dir.path());

        // No FERRUM_JOB_ID: silent, and no file created at all.
        std::env::remove_var("FERRUM_JOB_ID");
        let mut p = Progress::open();
        p.event("preflight", "should not be written");
        p.complete("succeeded", "nor this");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "a run with no job id must write nothing at all"
        );

        // With a job id: a real JSONL file, one object per line.
        std::env::set_var("FERRUM_JOB_ID", "test-job");
        let mut p = Progress::open();
        p.event("preflight", "checking free space");
        p.complete("succeeded", "all good");
        let raw = std::fs::read_to_string(dir.path().join("test-job.jsonl")).unwrap();
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2, "expected exactly two lines, got: {raw}");

        let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["event"], "preflight");
        assert_eq!(first["detail"], "checking free space");
        assert!(first["ts"].as_u64().unwrap() > 0);

        let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["event"], "complete");
        assert_eq!(second["detail"], "succeeded: all good");

        std::env::remove_var("FERRUM_JOB_ID");
        std::env::remove_var("FERRUM_JOBS_DIR");
    }

    #[test]
    fn appends_rather_than_truncating_an_existing_job_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("append-job.jsonl"), "{\"event\":\"pre-existing\"}\n").unwrap();

        // Open the file directly rather than through the env-var path, so
        // this test never races the env-mutating test above.
        let mut p = Progress {
            file: Some(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dir.path().join("append-job.jsonl"))
                    .unwrap(),
            ),
        };
        p.event("switch", "activating");
        let raw = std::fs::read_to_string(dir.path().join("append-job.jsonl")).unwrap();
        assert!(raw.contains("pre-existing"), "the existing content must survive: {raw}");
        assert!(raw.contains("switch"));
    }
}
