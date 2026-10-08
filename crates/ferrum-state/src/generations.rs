//! The generation list, correlated against the snapshot journal.
//!
//! Two jobs, and the second is newer than the first. `parse_nix_env_list`
//! and `correlate` answer "which generations exist and which of them have a
//! snapshot to roll back to". `built_pin_of` answers "which ferrum revision
//! was THIS generation built from", which is the question R8's apply gate
//! and rollback notice both rest on.
use crate::journal::{JournalEntry, Pin};

#[derive(Debug)]
pub struct GenerationInfo {
    pub generation: u32,
    /// Reported by `GET /api/generations`. `rollback::prepare()` needs only
    /// `generation`/`snapshot` to validate a single target and constructs
    /// this with placeholders for these two, so a caller building a
    /// `GenerationInfo` by hand rather than via `correlate` should not rely
    /// on them.
    pub date: String,
    pub current: bool,
    pub snapshot: Option<JournalEntry>,
}

/// Parses `nix-env -p /nix/var/nix/profiles/system --list-generations`
/// output. Validated against real output (Phase 1.0 probe 0.5):
/// "   1   2026-08-19 23:37:29   \n   3   2026-08-20 00:02:36   (current)\n"
pub fn parse_nix_env_list(output: &str) -> Vec<(u32, String, bool)> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            if line.trim().is_empty() {
                return None;
            }
            let current = line.trim_end().ends_with("(current)");
            let line = line.trim_end().trim_end_matches("(current)").trim_end();
            let mut parts = line.split_whitespace();
            let generation: u32 = parts.next()?.parse().ok()?;
            let date = parts.next()?;
            let time = parts.next()?;
            Some((generation, format!("{date} {time}"), current))
        })
        .collect()
}

/// Extracts the unix-timestamp prefix from a snapshot name like
/// "1770000000-gen42", for comparing which of several snapshots for the
/// same generation number is the most recent. Shared with
/// `rollback::prepare`, which picks the latest snapshot for a single target
/// generation the same way `correlate` does for every generation.
pub fn snapshot_ts(snapshot: &str) -> u64 {
    snapshot
        .split('-')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub fn correlate(
    generations: Vec<(u32, String, bool)>,
    journal_entries: Vec<JournalEntry>,
) -> Vec<GenerationInfo> {
    generations
        .into_iter()
        .map(|(generation, date, current)| {
            let snapshot = journal_entries
                .iter()
                .filter(|e| e.generation == generation)
                .max_by_key(|e| snapshot_ts(&e.snapshot))
                .cloned();
            GenerationInfo {
                generation,
                date,
                current,
                snapshot,
            }
        })
        .collect()
}

/// The `ferrum` pin a generation running `toplevel` was built from.
///
/// Journal entries record `built_pin` against `built_toplevel` -- the store
/// path the apply that wrote the entry produced -- and never against a
/// generation NUMBER, because the number was not knowable when the entry was
/// written and cannot be reconstructed afterwards (an apply made after a
/// rollback creates `max + 1`, not `generation + 1`). The store path is the
/// join that works: `/run/current-system` and every `system-<N>-link`
/// resolve to exactly the path `nix build` printed.
///
/// # Arguments
/// * `toplevel` - the generation's own store path, with no trailing slash,
///   exactly as the symlink resolves it.
/// * `entries` - the whole journal.
///
/// # Returns
/// The pin, or `None` when no entry claims that toplevel (an entry written
/// before `built_toplevel` existed, a generation applied outside
/// `ferrum-apply`, or a pruned entry) or when the claiming entry recorded no
/// pin. `None` is "pin unknown", never "the pins disagree": every caller
/// treats it as a reason NOT to act, which is what keeps a generation
/// predating these fields from gating anything.
///
/// Two entries claiming one toplevel is possible -- the same closure can be
/// built twice -- and the latest wins, ranked by the same `snapshot_ts` key
/// `correlate` and `rollback::prepare` already rank by.
pub fn built_pin_of(toplevel: &str, entries: &[JournalEntry]) -> Option<Pin> {
    entries
        .iter()
        .filter(|e| e.built_toplevel.as_deref() == Some(toplevel))
        .max_by_key(|e| snapshot_ts(&e.snapshot))
        .and_then(|e| e.built_pin.clone())
}

pub fn is_rollbackable(info: &GenerationInfo) -> Result<(), String> {
    if info.snapshot.is_none() {
        return Err(format!(
            "generation {} has no state snapshot -- it was either applied outside ferrum-apply, or its snapshot was pruned",
            info.generation
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalEntry;

    const SAMPLE_OUTPUT: &str = "\
   1   2026-08-19 23:37:29
   2   2026-08-19 23:58:13
   3   2026-08-20 00:02:36   (current)
";

    #[test]
    fn parses_nix_env_list_generations_output() {
        let parsed = parse_nix_env_list(SAMPLE_OUTPUT);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0], (1, "2026-08-19 23:37:29".to_string(), false));
        assert_eq!(parsed[2], (3, "2026-08-20 00:02:36".to_string(), true));
    }

    fn entry(snapshot: &str, generation: u32) -> JournalEntry {
        JournalEntry {
            snapshot: snapshot.to_string(),
            generation,
            toplevel: "/nix/store/x".to_string(),
            taken_at: "2026-08-20T00:00:00Z".to_string(),
            quiesced: true,
            built_pin: None,
            built_toplevel: None,
            update_pre_image: false,
        }
    }

    #[test]
    fn correlates_the_latest_snapshot_when_a_generation_number_repeats() {
        let generations = vec![(1, "d1".to_string(), false)];
        let journal_entries = vec![
            entry("1000-gen1", 1),
            entry("2000-gen1", 1), // a later snapshot for the same generation number
        ];
        let infos = correlate(generations, journal_entries);
        assert_eq!(infos[0].snapshot.as_ref().unwrap().snapshot, "2000-gen1");
    }

    #[test]
    fn generation_with_no_snapshot_is_not_rollbackable() {
        let info = GenerationInfo {
            generation: 5,
            date: "d".to_string(),
            current: false,
            snapshot: None,
        };
        assert!(is_rollbackable(&info).is_err());
    }

    /// A journal entry built from `pin_rev`, claiming `built_toplevel` as
    /// the closure it produced.
    fn built(snapshot: &str, generation: u32, built_toplevel: &str, pin_rev: &str) -> JournalEntry {
        JournalEntry {
            built_toplevel: Some(built_toplevel.to_string()),
            built_pin: Some(Pin {
                rev: pin_rev.to_string(),
                nar_hash: format!("sha256-{pin_rev}="),
            }),
            ..entry(snapshot, generation)
        }
    }

    #[test]
    fn a_generations_pin_is_found_by_the_toplevel_the_apply_recorded() {
        let entries = vec![
            built("1000-gen1", 1, "/nix/store/two", "bbb"),
            built("2000-gen2", 2, "/nix/store/three", "ccc"),
        ];
        assert_eq!(built_pin_of("/nix/store/two", &entries).unwrap().rev, "bbb");
        assert_eq!(built_pin_of("/nix/store/three", &entries).unwrap().rev, "ccc");
    }

    /// The anti-vacuity half: the lookup must be keyed on `built_toplevel`
    /// and not on `toplevel`, which is the PRE-image's path and therefore
    /// names a DIFFERENT generation's closure. Keyed on the wrong field,
    /// every pin would be attributed one generation too early -- which is
    /// precisely the off-by-one that would make the apply gate fire on a
    /// host whose pins agree.
    #[test]
    fn the_pre_image_toplevel_is_not_what_the_lookup_matches() {
        let entries = vec![JournalEntry {
            toplevel: "/nix/store/one".to_string(),
            ..built("1000-gen1", 1, "/nix/store/two", "bbb")
        }];
        assert!(
            built_pin_of("/nix/store/one", &entries).is_none(),
            "matching the pre-image's toplevel would attribute the built pin to the generation \
             the apply replaced"
        );
        assert!(built_pin_of("/nix/store/two", &entries).is_some());
    }

    /// Every shape that cannot yield a pin is "unknown", which is the state
    /// no caller is allowed to gate on.
    #[test]
    fn an_unrecorded_or_unmatched_toplevel_is_unknown() {
        let aged = entry("1000-gen1", 1); // predates both fields
        let no_pin = JournalEntry {
            built_toplevel: Some("/nix/store/two".to_string()),
            built_pin: None, // the apply ran but could not read the lock
            ..entry("2000-gen2", 2)
        };
        let entries = vec![aged, no_pin];

        assert!(built_pin_of("/nix/store/x", &entries).is_none(), "the pre-image path of an aged entry");
        assert!(built_pin_of("/nix/store/two", &entries).is_none(), "claimed, but with no pin recorded");
        assert!(built_pin_of("/nix/store/absent", &entries).is_none(), "claimed by nothing");
        assert!(built_pin_of("/nix/store/two", &[]).is_none(), "an empty journal");
    }

    /// One closure built twice: the later apply's pin is the one that
    /// describes what is running now.
    #[test]
    fn the_latest_entry_wins_when_one_toplevel_was_built_twice() {
        let entries = vec![
            built("1000-gen1", 1, "/nix/store/same", "old"),
            built("9000-gen4", 4, "/nix/store/same", "new"),
        ];
        assert_eq!(built_pin_of("/nix/store/same", &entries).unwrap().rev, "new");
    }

    #[test]
    fn generation_with_a_snapshot_is_rollbackable() {
        let info = GenerationInfo {
            generation: 1,
            date: "d".to_string(),
            current: false,
            snapshot: Some(entry("1000-gen1", 1)),
        };
        assert!(is_rollbackable(&info).is_ok());
    }
}
