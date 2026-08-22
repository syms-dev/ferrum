// The JSON request file format ferrumd (Phase 1.5a Task 6) writes and
// `ferrum-apply run-request` reads. Deliberately a small, closed enum --
// this is the entire privileged surface a compromised ferrumd could ever
// reach, so it must never grow a variant that accepts arbitrary shell/Nix
// content. Every variant maps onto a subcommand that already exists and
// is already tested; this file adds no new privileged LOGIC, only a new
// entry point onto it.
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    Preflight,
    Apply,
    Rollback { to: u32 },
    RestoreState,
    Gc,
}

pub fn read_request(path: &Path) -> anyhow::Result<Request> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("failed to read request file {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse request file {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apply_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, r#"{"kind":"apply"}"#).unwrap();
        assert!(matches!(read_request(&path).unwrap(), Request::Apply));
    }

    #[test]
    fn parses_rollback_request_with_target_generation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, r#"{"kind":"rollback","to":42}"#).unwrap();
        match read_request(&path).unwrap() {
            Request::Rollback { to } => assert_eq!(to, 42),
            other => panic!("expected Rollback, got {other:?}"),
        }
    }

    #[test]
    fn rejects_an_unknown_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, r#"{"kind":"delete_everything"}"#).unwrap();
        assert!(read_request(&path).is_err(), "an unknown request kind must be rejected, never silently ignored");
    }

    #[test]
    fn rejects_malformed_json_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, "not json at all").unwrap();
        assert!(read_request(&path).is_err());
    }
}
