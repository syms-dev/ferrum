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
    /// The read-only update check. Zero fields, deliberately: this is the
    /// one kind that reaches the network, and any field would be content
    /// ferrumd (or whoever compromised it) chose for a root process to
    /// fetch. What is checked comes from the operator's own root-owned
    /// /etc/ferrum/flake.nix, which ferrumd cannot write.
    CheckUpdate,
}

impl Request {
    /// The request's own kind string, exactly as it appears in the request
    /// file's `kind` field.
    ///
    /// Derived from the parsed variant rather than re-read out of the raw
    /// JSON text: the file has already been through serde by the time
    /// anything wants this, so re-parsing it would introduce a second,
    /// weaker reader of the same bytes that could disagree with the first.
    /// These strings must stay in lockstep with the `rename_all =
    /// "snake_case"` tag above -- they are what `GET /api/jobs` reports as a
    /// job's `kind`, and the UI renders them.
    pub fn kind(&self) -> &'static str {
        match self {
            Request::Preflight => "preflight",
            Request::Apply => "apply",
            Request::Rollback { .. } => "rollback",
            Request::RestoreState => "restore_state",
            Request::Gc => "gc",
            Request::CheckUpdate => "check_update",
        }
    }
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

    /// These strings are what `GET /api/jobs` reports as a job's `kind` and
    /// what the UI renders, so they must match the `rename_all =
    /// "snake_case"` tag exactly. Asserted against the real serde round-trip
    /// rather than hand-written literals, so renaming a variant without
    /// updating `kind()` fails here instead of silently changing the API.
    #[test]
    fn kind_matches_the_tag_serde_actually_parses() {
        let dir = tempfile::tempdir().unwrap();
        for (json, expected) in [
            (r#"{"kind":"preflight"}"#, "preflight"),
            (r#"{"kind":"apply"}"#, "apply"),
            (r#"{"kind":"rollback","to":3}"#, "rollback"),
            (r#"{"kind":"restore_state"}"#, "restore_state"),
            (r#"{"kind":"gc"}"#, "gc"),
            (r#"{"kind":"check_update"}"#, "check_update"),
        ] {
            let path = dir.path().join("req.json");
            std::fs::write(&path, json).unwrap();
            let req = read_request(&path).unwrap();
            assert_eq!(req.kind(), expected, "kind() disagrees with the parsed tag for {json}");
            // And the reported kind really is the tag from the file, not a
            // label invented alongside it.
            let tag: serde_json::Value = serde_json::from_str(json).unwrap();
            assert_eq!(req.kind(), tag["kind"].as_str().unwrap());
        }
    }

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

    /// The read-only check carries no fields at all, deliberately: it is
    /// the one request kind that reaches the network, and a field would be
    /// operator- or attacker-supplied content deciding what a root process
    /// fetches. The repo and ref come from the operator's own root-owned
    /// flake.nix instead, which ferrumd cannot write.
    #[test]
    fn check_update_carries_no_fields_and_ignores_any_that_are_injected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, r#"{"kind":"check_update"}"#).unwrap();
        assert!(matches!(read_request(&path).unwrap(), Request::CheckUpdate));

        // An extra field on the wire changes nothing about what runs: the
        // variant has nowhere to put it.
        std::fs::write(
            &path,
            r#"{"kind":"check_update","flakeRef":"https://evil.example/repo"}"#,
        )
        .unwrap();
        assert!(matches!(read_request(&path).unwrap(), Request::CheckUpdate));
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
