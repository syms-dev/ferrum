// Reading the resolved `ferrum` pin out of a host's own flake.lock, so an
// apply can record what it built from (R8's first criterion).
//
// Separate from `update_candidate::parse_locked`, which answers a different
// question and answers it strictly: that one is the update CHECK's reader,
// it needs `lastModified` to order a candidate, and it returns a named error
// the operator is shown when the lock cannot be read. This one feeds a
// journal entry on the apply path, where there is no operator looking and
// no decision resting on the answer yet -- so every unreadable shape is
// `None` ("pin unknown"), never an error, because failing an apply over a
// bookkeeping field would be a far worse outcome than a generation whose
// provenance is unrecorded. R8's own edge cases say the same thing about
// the absence: it is an artifact, not a disagreement.
//
// Two readers rather than one because merging them would have to give one
// of those two call sites the other's failure behaviour.
use ferrum_state::journal::Pin;
use std::path::Path;

/// Pick one input's locked `rev` and `narHash` out of a `flake.lock`
/// document.
///
/// Resolves through `nodes.root.inputs.<name>` rather than assuming the node
/// is keyed by the input's own name -- Nix renames a node when two inputs
/// would collide, and reading the wrong node would record some other
/// repository's revision as this host's.
///
/// # Arguments
/// * `text` - the contents of a `flake.lock`.
/// * `name` - the input name, normally `ferrum`.
///
/// # Returns
/// The pin, or `None` when the document is not JSON, does not pin that
/// input, resolves it to a node that is not there, or records it without
/// BOTH a revision and a NAR hash. A half-known pin is recorded as unknown:
/// `Pin`'s two fields are a pair, and half of an identity is not a weaker
/// identity, it is a different claim.
pub fn parse(text: &str, name: &str) -> Option<Pin> {
    let doc: serde_json::Value = serde_json::from_str(text).ok()?;
    // `.as_str()` and not `.get(0)`: an input resolved through `follows`
    // appears here as an ARRAY naming a path, and following it would be a
    // second resolution rule this reader does not need -- ferrum is a
    // top-level input on every host template.
    let node_key = doc
        .pointer(&format!("/nodes/root/inputs/{name}"))?
        .as_str()?;
    let locked = doc.pointer(&format!("/nodes/{node_key}/locked"))?;
    Some(Pin {
        rev: locked.get("rev")?.as_str()?.to_string(),
        nar_hash: locked.get("narHash")?.as_str()?.to_string(),
    })
}

/// Read one input's pin from a `flake.lock` on disk.
///
/// # Arguments
/// * `flake_lock` - normally `/etc/ferrum/flake.lock`.
/// * `name` - the input name, normally `ferrum`.
///
/// # Returns
/// The pin, or `None` when the file cannot be read or `parse` cannot read
/// it. Never an error: see this module's header.
pub fn read(flake_lock: &Path, name: &str) -> Option<Pin> {
    parse(&std::fs::read_to_string(flake_lock).ok()?, name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A lock in the shape Nix really writes, with the `ferrum` input
    /// resolved through a node whose KEY differs from the input's name --
    /// the collision-renaming case a naive `nodes.ferrum` lookup gets
    /// silently wrong.
    const LOCK: &str = r#"{
      "nodes": {
        "root":     { "inputs": { "ferrum": "ferrum_2", "nixpkgs": "nixpkgs" } },
        "ferrum_2": { "locked": { "lastModified": 1785627969,
                                  "narHash": "sha256-FERRUM=",
                                  "owner": "owner", "repo": "ferrum",
                                  "rev": "1111111111111111111111111111111111111111",
                                  "type": "github" } },
        "ferrum":   { "locked": { "narHash": "sha256-WRONG=",
                                  "rev": "9999999999999999999999999999999999999999" } },
        "nixpkgs":  { "locked": { "narHash": "sha256-NIXPKGS=",
                                  "rev": "2222222222222222222222222222222222222222" } }
      },
      "root": "root", "version": 7
    }"#;

    #[test]
    fn reads_the_rev_and_narhash_through_the_root_inputs_mapping() {
        let pin = parse(LOCK, "ferrum").expect("the lock pins ferrum");
        assert_eq!(pin.rev, "1".repeat(40));
        assert_eq!(pin.nar_hash, "sha256-FERRUM=");
    }

    /// The anti-vacuity half of the test above: the same document contains a
    /// node literally keyed `ferrum` carrying a different revision, and a
    /// reader that took the name as the key would return THAT and still
    /// look green. It must not.
    #[test]
    fn a_node_keyed_by_the_input_name_is_not_the_one_read() {
        let pin = parse(LOCK, "ferrum").unwrap();
        assert_ne!(pin.rev, "9".repeat(40), "resolved the node by name instead of through root.inputs");
        assert_ne!(pin.nar_hash, "sha256-WRONG=");
    }

    /// And it reads the input it was ASKED about, not whichever one happens
    /// to be first -- without this, every assertion above would hold for a
    /// reader hard-wired to one input.
    #[test]
    fn reads_the_input_it_was_asked_about() {
        let pin = parse(LOCK, "nixpkgs").unwrap();
        assert_eq!(pin.rev, "2".repeat(40));
    }

    #[test]
    fn an_input_the_lock_does_not_pin_is_unknown_not_an_error() {
        assert!(parse(LOCK, "no-such-input").is_none());
    }

    /// Every shape that cannot yield a WHOLE pin reads as unknown. The
    /// half-pin rows are the point: recording a rev with no NAR hash would
    /// put a partial identity in the journal that later code would compare
    /// against a complete one.
    #[test]
    fn every_unreadable_or_partial_shape_is_unknown() {
        for (label, text) in [
            ("not json", "}{"),
            ("no nodes", r#"{"version":7}"#),
            (
                "input resolved to a node that is absent",
                r#"{"nodes":{"root":{"inputs":{"ferrum":"gone"}}}}"#,
            ),
            (
                "a follows array rather than a node name",
                r#"{"nodes":{"root":{"inputs":{"ferrum":["nixpkgs","ferrum"]}},
                    "nixpkgs":{"locked":{"rev":"r","narHash":"h"}}}}"#,
            ),
            (
                "locked with no rev",
                r#"{"nodes":{"root":{"inputs":{"ferrum":"f"}},
                    "f":{"locked":{"narHash":"sha256-X="}}}}"#,
            ),
            (
                "locked with no narHash",
                r#"{"nodes":{"root":{"inputs":{"ferrum":"f"}},
                    "f":{"locked":{"rev":"abc"}}}}"#,
            ),
            (
                "a node with no locked entry at all",
                r#"{"nodes":{"root":{"inputs":{"ferrum":"f"}},"f":{"original":{}}}}"#,
            ),
        ] {
            assert!(parse(text, "ferrum").is_none(), "{label} must read as unknown");
        }
    }

    #[test]
    fn a_missing_file_is_unknown_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(&dir.path().join("flake.lock"), "ferrum").is_none());
    }

    #[test]
    fn reads_a_real_file_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flake.lock");
        std::fs::write(&path, LOCK).unwrap();
        assert_eq!(read(&path, "ferrum").unwrap().rev, "1".repeat(40));
    }
}
