//! The snapshot journal: one entry per apply, recording what was running
//! before the switch and what pin the switch built from.
//!
//! An entry is the rollback story's only durable record. `snapshot`,
//! `generation` and `toplevel` describe the PRE-image the apply quiesced
//! and snapshotted; `built_pin` and `built_toplevel` describe the closure
//! that replaced it, and `update_pre_image` says whether the pre-image is
//! an update's way back. All of them belong here because an entry is a
//! record of one apply EVENT, and the moment that apply reads
//! `/etc/ferrum/flake.lock` is the only moment the pin is knowable at all.
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
    /// The toplevel store path the apply that wrote this entry BUILT -- so
    /// the toplevel of the generation this apply produced, matching
    /// `built_pin`'s subject rather than `toplevel`'s.
    ///
    /// This field is what makes `built_pin` usable. `built_pin` describes a
    /// generation the entry does not name: the entry's `generation` is the
    /// PRE-image, and the number the apply went on to create is not knowable
    /// at the moment the entry is written, nor recoverable later from the
    /// numbers alone -- an apply made after a rollback produces
    /// `max + 1`, not `generation + 1`. The store path is recoverable,
    /// because `/run/current-system` and every `system-<N>-link` resolve to
    /// exactly the path `nix build` printed. So "which pin was generation N
    /// built from" is answered by matching N's own store path against this
    /// field (`generations::built_pin_of`), with no timestamp heuristics and
    /// no assumption about how generation numbers advance.
    ///
    /// `None` is "unknown", for the same reasons and with the same tolerance
    /// as `built_pin` above: every entry written before this field existed
    /// deserialises to it, and absence is an artifact of age, never a
    /// disagreement.
    #[serde(default)]
    pub built_toplevel: Option<String>,
    /// Set when this entry's snapshot is the PRE-image of an update -- the
    /// state of the host immediately before its ferrum pin was advanced.
    ///
    /// It exists for exactly one consumer, `gc::plan`, which protects a
    /// marked snapshot from retention pruning so that "an update is never a
    /// one-way door" survives longer than the ten applies
    /// `FERRUM_KEEP_GENERATIONS` otherwise allows. The mark is cleared by
    /// the operator confirming the update is good (`ferrum-apply
    /// confirm-update`), which is what keeps the protected set bounded and
    /// endable rather than a retention rule that silently grows forever.
    ///
    /// A plain `bool` rather than an `Option<bool>`: absent means false,
    /// which is the correct reading for every entry written before this
    /// field existed -- an old entry is not an unconfirmed update, it is an
    /// ordinary apply.
    #[serde(default)]
    pub update_pre_image: bool,
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

/// Clear every `update_pre_image` mark in the journal.
///
/// This is what "the operator confirms the update is good" does: the
/// snapshots an update held back from `gc` go back to ordinary retention.
/// It is deliberately a sweep rather than a per-snapshot operation --
/// confirming means "what I am running now is fine", which says nothing
/// that distinguishes one held-back snapshot from another, and a
/// per-snapshot form would need a snapshot name to cross the privilege
/// boundary for no gain.
///
/// # Arguments
/// * `journal_dir` - ferrum's snapshot journal.
///
/// # Returns
/// How many entries were cleared. Zero is an ordinary, successful outcome:
/// nothing was being held back.
///
/// # Errors
/// Any failure reading the directory, parsing an entry, or rewriting one.
/// A partial sweep is possible and harmless -- an entry still marked is
/// still protected, which is the safe direction -- so this stops at the
/// first failure rather than pressing on against a sick filesystem.
pub fn clear_update_marks(journal_dir: &Path) -> anyhow::Result<usize> {
    let mut cleared = 0;
    for mut entry in list(journal_dir)? {
        if !entry.update_pre_image {
            continue;
        }
        entry.update_pre_image = false;
        write(journal_dir, &entry)?;
        cleared += 1;
    }
    Ok(cleared)
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
            built_toplevel: None,
            update_pre_image: false,
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
        assert!(
            entry.built_toplevel.is_none(),
            "an absent built toplevel reads as unknown, which is what keeps this generation out \
             of the apply gate entirely"
        );
        assert!(
            !entry.update_pre_image,
            "an entry written before the mark existed is an ordinary apply, never an \
             unconfirmed update holding a snapshot back from gc"
        );

        // And through the path the Generations view actually uses, where a
        // single failure takes every other entry down with it.
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert!(listed[0].built_pin.is_none());
        assert!(listed[0].built_toplevel.is_none());
        assert!(!listed[0].update_pre_image);
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
            built_toplevel: Some("/nix/store/new-nixos-system".to_string()),
            update_pre_image: true,
        };
        write(dir.path(), &entry).unwrap();

        let raw = std::fs::read_to_string(dir.path().join("1770000001-gen8.json")).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(doc["built_pin"]["rev"], "a".repeat(40));
        assert_eq!(doc["built_pin"]["nar_hash"], "sha256-ZZZ=");
        assert_eq!(doc["built_toplevel"], "/nix/store/new-nixos-system");
        assert_eq!(doc["update_pre_image"], true);

        let read_back = read(dir.path(), "1770000001-gen8").unwrap();
        assert_eq!(read_back.built_pin, entry.built_pin);
        assert_eq!(read_back.built_toplevel, entry.built_toplevel);
        assert!(read_back.update_pre_image);
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
                built_toplevel: None,
                update_pre_image: false,
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

    /// Confirming an update clears exactly the marks, and nothing else
    /// about the entries it rewrites.
    #[test]
    fn confirming_clears_every_mark_and_touches_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let marked = JournalEntry {
            update_pre_image: true,
            built_pin: Some(Pin { rev: "a".repeat(40), nar_hash: "sha256-A=".into() }),
            built_toplevel: Some("/nix/store/new".into()),
            ..plain("1000-gen1", 1)
        };
        write(dir.path(), &marked).unwrap();
        write(dir.path(), &plain("2000-gen2", 2)).unwrap();

        assert_eq!(clear_update_marks(dir.path()).unwrap(), 1, "only the marked entry is rewritten");

        let after = read(dir.path(), "1000-gen1").unwrap();
        assert!(!after.update_pre_image, "the mark is gone");
        // The rest of the entry is the rollback story's only durable
        // record; a sweep that reset it would quietly make the generation
        // unrollbackable and its pin unknown.
        assert_eq!(after.snapshot, marked.snapshot);
        assert_eq!(after.generation, marked.generation);
        assert_eq!(after.toplevel, marked.toplevel);
        assert_eq!(after.taken_at, marked.taken_at);
        assert!(after.quiesced);
        assert_eq!(after.built_pin, marked.built_pin);
        assert_eq!(after.built_toplevel, marked.built_toplevel);

        // Idempotent, and an already-clear journal is a success, not an
        // error: the operator may confirm twice, and a host that never
        // updated has nothing to clear.
        assert_eq!(clear_update_marks(dir.path()).unwrap(), 0);
        assert_eq!(list(dir.path()).unwrap().len(), 2, "no entry is lost by the sweep");
    }

    /// A journal directory that does not exist is "nothing to clear", for
    /// the same reason `list` treats it as an empty journal: a host that
    /// has never applied is not a fault.
    #[test]
    fn confirming_on_a_host_with_no_journal_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(clear_update_marks(&dir.path().join("never-created")).unwrap(), 0);
    }

    /// A five-field entry with a given snapshot name and generation.
    fn plain(snapshot: &str, generation: u32) -> JournalEntry {
        JournalEntry {
            snapshot: snapshot.to_string(),
            generation,
            toplevel: "/nix/store/old".to_string(),
            taken_at: "1000".to_string(),
            quiesced: true,
            built_pin: None,
            built_toplevel: None,
            update_pre_image: false,
        }
    }

    #[test]
    fn snapshot_name_embeds_timestamp_and_generation() {
        let name = snapshot_name(1770000000, 42);
        assert_eq!(name, "1770000000-gen42");
    }
}
