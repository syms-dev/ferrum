//! The snapshot journal: one entry per apply, recording what was running
//! before the switch and what pin the switch built from.
//!
//! An entry is the rollback story's only durable record. `snapshot`,
//! `generation` and `toplevel` describe the PRE-image the apply quiesced
//! and snapshotted; `built_pin` describes the closure that replaced it.
//! Both belong here because an entry is a record of one apply EVENT, and
//! the moment that apply reads `/etc/ferrum/flake.lock` is the only moment
//! the pin is knowable at all.
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The resolved `ferrum` flake input one apply built from, as
/// `/etc/ferrum/flake.lock` recorded it.
///
/// Two fields and no more: the revision answers "which ferrum is this", and
/// the NAR hash answers "and was it the same tree", which is the pair
/// `flake.lock` itself stores and the pair an operator can check against a
/// remote without trusting this host.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// `nodes.<ferrum>.locked.rev` -- the exact commit.
    pub rev: String,
    /// `nodes.<ferrum>.locked.narHash` -- the content hash of the tree that
    /// commit resolved to.
    pub nar_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JournalEntry {
    pub snapshot: String,
    pub generation: u32,
    /// The toplevel store path that `generation` was ACTUALLY running (read
    /// from `/run/current-system` at snapshot time) -- not the newly-built
    /// toplevel being switched to.
    pub toplevel: String,
    pub taken_at: String,
    pub quiesced: bool,
    /// The pin the apply that wrote this entry BUILT FROM -- so the pin of
    /// the generation this apply produced (`generation + 1`), not of
    /// `generation`.
    ///
    /// That asymmetry against the three fields above is deliberate and is
    /// the only honest option. The pin a given generation was built from is
    /// knowable exactly once: while the apply that produced it is running.
    /// By the time that generation is itself snapshotted and left behind,
    /// `/etc/ferrum/flake.lock` may have been advanced by an update, so
    /// reading it then and calling it `generation`'s pin would be false in
    /// precisely the case the field exists for (R8: rollback does not revert
    /// the pin). Recording what this apply actually built from is a fact;
    /// attributing it to the pre-image would be a guess.
    ///
    /// `None` means "pin unknown", which is what every entry written before
    /// this field existed deserialises to -- the host's real journal predates
    /// it, and an entry that failed to parse would take the whole Generations
    /// view down. Absence is an artifact of age, never a disagreement.
    ///
    /// `#[serde(default)]` is stated rather than relied on implicitly: serde
    /// already treats a missing `Option` as `None`, so this adds nothing
    /// today -- it is here so the tolerance survives the field one day
    /// ceasing to be an `Option`, which is the edit that would otherwise
    /// brick an existing host's Generations view silently.
    #[serde(default)]
    pub built_pin: Option<Pin>,
}

pub fn snapshot_name(unix_ts: u64, generation: u32) -> String {
    format!("{unix_ts}-gen{generation}")
}

pub fn write(journal_dir: &Path, entry: &JournalEntry) -> anyhow::Result<()> {
    std::fs::create_dir_all(journal_dir)?;
    let path = journal_dir.join(format!("{}.json", entry.snapshot));
    let tmp_path = journal_dir.join(format!("{}.json.tmp", entry.snapshot));
    std::fs::write(&tmp_path, serde_json::to_string_pretty(entry)?)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

pub fn read(journal_dir: &Path, snapshot: &str) -> anyhow::Result<JournalEntry> {
    let path = journal_dir.join(format!("{snapshot}.json"));
    let content = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("no journal entry for {snapshot}: {e}"))?;
    Ok(serde_json::from_str(&content)?)
}

pub fn list(journal_dir: &Path) -> anyhow::Result<Vec<JournalEntry>> {
    if !journal_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for f in std::fs::read_dir(journal_dir)? {
        let f = f?;
        if f.path().extension().and_then(|e| e.to_str()) == Some("json") {
            let content = std::fs::read_to_string(f.path())?;
            entries.push(serde_json::from_str(&content)?);
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_back_identically() {
        let dir = tempfile::tempdir().unwrap();
        let entry = JournalEntry {
            snapshot: "1770000000-gen42".to_string(),
            generation: 42,
            toplevel: "/nix/store/abc-nixos-system-test".to_string(),
            taken_at: "2026-08-20T00:00:00Z".to_string(),
            quiesced: true,
            built_pin: None,
        };
        write(dir.path(), &entry).unwrap();
        let read_back = read(dir.path(), "1770000000-gen42").unwrap();
        assert_eq!(read_back.generation, 42);
        assert_eq!(read_back.toplevel, "/nix/store/abc-nixos-system-test");
        assert!(read_back.quiesced);
    }

    #[test]
    fn reading_a_missing_entry_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path(), "does-not-exist").is_err());
    }

    /// The host's live journal predates `built_pin`. Every one of those
    /// entries must still parse, because `list` propagates the FIRST parse
    /// error and the Generations view is built from its result -- one
    /// unreadable entry would blank the whole screen, rollback controls
    /// included, on exactly the host this field was added for.
    ///
    /// Written as the literal five-field JSON a pre-field apply produced,
    /// not as a serialisation of today's struct with the field set to
    /// `None`: a round trip never omits the key, so it would pass against a
    /// struct that REQUIRES it. This fails there -- confirmed by making the
    /// field required (`deserialize_with = "Option::deserialize"`), which
    /// turns this one test red with `missing field built_pin` and leaves
    /// the rest of the module green.
    #[test]
    fn an_entry_written_before_this_field_existed_still_parses_as_pin_unknown() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("1770000000-gen7.json"),
            r#"{"snapshot":"1770000000-gen7","generation":7,
                "toplevel":"/nix/store/old-nixos-system","taken_at":"1770000000",
                "quiesced":true}"#,
        )
        .unwrap();

        let entry = read(dir.path(), "1770000000-gen7").unwrap();
        assert_eq!(entry.generation, 7);
        assert!(entry.built_pin.is_none(), "an absent pin reads as unknown, never as an error");

        // And through the path the Generations view actually uses, where a
        // single failure takes every other entry down with it.
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].built_pin.is_none());
    }

    /// The other half. Without it the test above would pass identically if
    /// `built_pin` were never written or read at all.
    #[test]
    fn a_recorded_pin_round_trips_under_its_own_field_names() {
        let dir = tempfile::tempdir().unwrap();
        let entry = JournalEntry {
            snapshot: "1770000001-gen8".to_string(),
            generation: 8,
            toplevel: "/nix/store/abc-nixos-system-test".to_string(),
            taken_at: "1770000001".to_string(),
            quiesced: true,
            built_pin: Some(Pin {
                rev: "a".repeat(40),
                nar_hash: "sha256-ZZZ=".to_string(),
            }),
        };
        write(dir.path(), &entry).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("1770000001-gen8.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(doc["built_pin"]["rev"], "a".repeat(40));
        assert_eq!(doc["built_pin"]["nar_hash"], "sha256-ZZZ=");

        let read_back = read(dir.path(), "1770000001-gen8").unwrap();
        assert_eq!(read_back.built_pin, entry.built_pin);
    }

    /// An apply that recorded no pin writes the key as an explicit `null`
    /// rather than omitting it, so "this apply could not read the lock" is
    /// visible in the file and in `GET /api/generations` instead of being
    /// indistinguishable from an entry written by an older ferrum.
    #[test]
    fn an_unknown_pin_is_written_as_an_explicit_null() {
        let dir = tempfile::tempdir().unwrap();
        write(
            dir.path(),
            &JournalEntry {
                snapshot: "1770000002-gen9".to_string(),
                generation: 9,
                toplevel: "/nix/store/x".to_string(),
                taken_at: "1770000002".to_string(),
                quiesced: true,
                built_pin: None,
            },
        )
        .unwrap();
        let raw = std::fs::read_to_string(dir.path().join("1770000002-gen9.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert!(
            doc.as_object().unwrap().contains_key("built_pin"),
            "the key is present even when unknown, got: {raw}"
        );
        assert!(doc["built_pin"].is_null());
    }

    #[test]
    fn snapshot_name_embeds_timestamp_and_generation() {
        let name = snapshot_name(1770000000, 42);
        assert_eq!(name, "1770000000-gen42");
    }
}
