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
    /// The ordinary rebuild.
    ///
    /// `accept_pin_change` is the one field on this enum that is neither a
    /// generation number nor absent, and it is worth being precise about why
    /// it is not the "arbitrary content" this file's header forbids: it is
    /// compared for EQUALITY against the revision `/etc/ferrum/flake.lock`
    /// already names, and used for nothing else (`pin_gate::decide`). It
    /// cannot choose a repository, a reference, or a revision to fetch --
    /// a value that matches nothing simply leaves the gate closed. What it
    /// carries is the operator's acknowledgement that this rebuild also
    /// moves the host to a different ferrum revision (R8), which has to
    /// name that revision or it would survive the revision changing under
    /// it.
    ///
    /// `#[serde(default)]` so `{"kind":"apply"}` -- what every ferrumd
    /// before this wrote, and what the common case still writes -- keeps
    /// parsing.
    ///
    /// `accept_no_way_in` is the second field of the same kind and obeys
    /// the same rule: it is compared for EQUALITY against the token
    /// `way_in::decide` would issue for the lockout it actually found
    /// (`console-locked+ssh-disabled` and the like), and used for nothing
    /// else. It cannot name a route, a port, a user or a file -- a value
    /// that matches nothing simply leaves the gate closed. What it carries
    /// is the operator's acknowledgement that the generation this apply
    /// would produce has no way back in, named specifically enough that an
    /// acknowledgement of one lockout cannot pass a different one.
    Apply {
        #[serde(default)]
        accept_pin_change: Option<String>,
        #[serde(default)]
        accept_no_way_in: Option<String>,
    },
    Rollback { to: u32 },
    RestoreState,
    Gc,
    /// The read-only update check. Zero fields, deliberately: this is the
    /// one kind that reaches the network, and any field would be content
    /// ferrumd (or whoever compromised it) chose for a root process to
    /// fetch. What is checked comes from the operator's own root-owned
    /// /etc/ferrum/flake.nix, which ferrumd cannot write.
    CheckUpdate,
    /// The update commit: advance the pin, then apply. Zero fields, for the
    /// same reason `CheckUpdate` has none and with more at stake -- this is
    /// the one kind that WRITES /etc/ferrum/flake.lock and then builds and
    /// switches the host as root. The repository, the ref, and therefore
    /// the candidate are all computed by ferrum-apply from the operator's
    /// own root-owned /etc/ferrum/flake.nix, which ferrumd cannot write.
    /// A `Update { flakeRef }` shape -- the rejected one -- would have made
    /// the request file a way to choose what a root process builds.
    Update,
    /// "The update this host is running is good." Clears every
    /// `update_pre_image` mark in the journal, returning the snapshots an
    /// update held back from `gc` to ordinary retention.
    ///
    /// Zero fields, and that is a design choice rather than an accident of
    /// this one being simple: a per-snapshot form would put a snapshot NAME
    /// -- which becomes a path component on the privileged side -- into the
    /// request file, for no gain. Confirming means "what I am running now
    /// is fine", which says nothing that distinguishes one held-back
    /// snapshot from another.
    ConfirmUpdate,
    /// Run a parity sync now. Zero fields, and that is the same rule every
    /// other variant here follows: it names no disk, no path and no
    /// schedule. What gets synced is decided entirely by
    /// `/etc/snapraid.conf`, which the host's own Nix evaluation wrote and
    /// ferrumd cannot touch. A `ParitySync { disks }` shape -- the rejected
    /// one -- would have made the request file a way to choose what a root
    /// process reads and what it overwrites.
    ParitySync,
    /// The read-only parity status check. Zero fields, for the same reason,
    /// and it writes nothing to the array at all: `systemctl is-active` and
    /// `snapraid diff`, then one report document beside the job's own
    /// progress file.
    ParityStatus,
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
            Request::Apply { .. } => "apply",
            Request::Rollback { .. } => "rollback",
            Request::RestoreState => "restore_state",
            Request::Gc => "gc",
            Request::CheckUpdate => "check_update",
            Request::Update => "update",
            Request::ConfirmUpdate => "confirm_update",
            Request::ParitySync => "parity_sync",
            Request::ParityStatus => "parity_status",
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
            (r#"{"kind":"update"}"#, "update"),
            (r#"{"kind":"confirm_update"}"#, "confirm_update"),
            (r#"{"kind":"parity_sync"}"#, "parity_sync"),
            (r#"{"kind":"parity_status"}"#, "parity_status"),
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

    /// The fieldless form -- what every ferrumd before R8 wrote, and what
    /// an ordinary apply still writes -- parses, and parses as "nothing
    /// acknowledged" rather than failing on the absent field.
    #[test]
    fn parses_apply_request() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, r#"{"kind":"apply"}"#).unwrap();
        match read_request(&path).unwrap() {
            Request::Apply { accept_pin_change, accept_no_way_in } => {
                assert_eq!(accept_pin_change, None);
                assert_eq!(accept_no_way_in, None);
            }
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    /// And the acknowledged form carries the revision through verbatim --
    /// the half without which the test above would pass against a variant
    /// that dropped the field on the floor.
    #[test]
    fn parses_an_apply_that_acknowledges_a_pin_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(
            &path,
            r#"{"kind":"apply","accept_pin_change":"2222222222222222222222222222222222222222"}"#,
        )
        .unwrap();
        match read_request(&path).unwrap() {
            Request::Apply { accept_pin_change, .. } => {
                assert_eq!(accept_pin_change.as_deref(), Some("2".repeat(40).as_str()));
            }
            other => panic!("expected Apply, got {other:?}"),
        }
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

    /// The commit kind carries no fields either, and the injected-field
    /// case matters more here than it does for the check: this is the
    /// variant that writes flake.lock and then builds and switches as root.
    /// An extra field on the wire must be provably inert -- the variant has
    /// nowhere to put one, which is why the whole candidate resolution
    /// happens inside ferrum-apply from root-owned inputs.
    #[test]
    fn update_carries_no_fields_and_ignores_any_that_are_injected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("req.json");
        std::fs::write(&path, r#"{"kind":"update"}"#).unwrap();
        assert!(matches!(read_request(&path).unwrap(), Request::Update));

        for injected in [
            r#"{"kind":"update","flakeRef":"github:attacker/evil"}"#,
            r#"{"kind":"update","rev":"deadbeef"}"#,
            r#"{"kind":"update","to":3}"#,
            r#"{"kind":"update","flake_lock":"/tmp/mine.lock"}"#,
        ] {
            std::fs::write(&path, injected).unwrap();
            let req = read_request(&path).unwrap();
            assert!(
                matches!(req, Request::Update),
                "an injected field must not change which variant runs: {injected}"
            );
            assert_eq!(req.kind(), "update");
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
