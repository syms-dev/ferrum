// Task 7 (rollback) is the first real consumer of this module.

use crate::journal::JournalEntry;

#[derive(Debug)]
pub struct GenerationInfo {
    pub generation: u32,
    // Populated for shape-consistency with correlate()'s output (used when
    // listing all generations, e.g. a future ferrumd-facing API), but
    // rollback::prepare() only needs `generation`/`snapshot` to validate a
    // single target -- it constructs this with placeholder values for the
    // other two, so they're genuinely unread until a real list-generations
    // consumer exists.
    #[allow(dead_code)]
    pub date: String,
    #[allow(dead_code)]
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
/// same generation number is the most recent.
fn snapshot_ts(snapshot: &str) -> u64 {
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
