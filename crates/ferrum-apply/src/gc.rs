// Snapshot retention: prunes application-state snapshots that are older
// than the `ferrum.storage.keepGenerations` most recent ones.
//
// Why this has to exist: every `ferrum-apply apply` takes a read-only btrfs
// snapshot of @state and journals it (apply.rs step 4). Nothing ever
// removed one, and `ferrum.storage.keepGenerations` -- a real, documented,
// operator-settable option, present in settings-schema.json -- had no
// consumer anywhere in the tree. A long-lived host therefore accumulated
// one snapshot per apply forever.
//
// That is not merely untidy. btrfs snapshots pin the extents they
// reference, so an *arr SQLite database that is rewritten in place keeps
// every historical version of every rewritten extent alive for as long as
// any snapshot referencing it survives. This is the concrete mechanism
// behind design known-risk 3 ("btrfs CoW under a SQLite-heavy workload...
// usage grows faster than 'snapshots are free' intuition suggests"), and
// it is the failure an operator hits months in, with a full disk and no
// obvious cause.
use ferrum_state::journal::{self, JournalEntry};
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

/// What a GC run would do, or did. Returned rather than printed so the
/// caller owns presentation and `plan` stays unit-testable without a real
/// btrfs filesystem underneath it.
// Deliberately only Debug: JournalEntry itself derives no PartialEq, and
// adding one just to compare whole plans in tests would widen a shipped,
// shared type for a test's convenience. The tests below compare snapshot
// names, which is what actually matters about a plan anyway.
#[derive(Debug)]
pub struct GcPlan {
    /// Snapshots to delete, oldest first.
    pub prune: Vec<JournalEntry>,
    /// Snapshots to keep, newest first.
    pub keep: Vec<JournalEntry>,
}

/// Decides which snapshots to prune, given the journal and a retention
/// count. Pure: no filesystem access beyond what the caller already read,
/// so the policy is testable on its own.
///
/// Two rules, and the second is the one that matters:
///
/// 1. Keep the `keep_generations` newest snapshots, ranked by the timestamp
///    embedded in the snapshot name (`<unix_ts>-gen<N>`), which is what
///    `generations::snapshot_ts` already parses and what `correlate` already
///    ranks by. Ranking by name rather than by the journal file's own mtime
///    keeps this agreeing with every other consumer of the same data.
///
/// 2. **Never prune the snapshot belonging to the currently-running
///    generation**, even if it falls outside the retention window. That
///    snapshot is the one a rollback FROM a bad future apply would restore,
///    and on a host that has been rebooted into an older generation it can
///    easily be older than `keep_generations` newer ones. Pruning it would
///    silently remove the operator's way back, which is the single worst
///    thing this file could do.
pub fn plan(entries: Vec<JournalEntry>, keep_generations: usize, current_generation: u32) -> GcPlan {
    let mut sorted = entries;
    // Newest first. `snapshot_ts` is the shared parser -- see rule 1.
    sorted.sort_by_key(|e| std::cmp::Reverse(ferrum_state::generations::snapshot_ts(&e.snapshot)));

    // A retention count of 0 would mean "keep nothing", which combined with
    // rule 2 still keeps the current generation's snapshot. Treated as the
    // operator genuinely asking for maximum pruning rather than rejected:
    // the interlock that makes it safe is rule 2, not a floor on this number.
    let mut keep = Vec::new();
    let mut prune = Vec::new();
    let mut protected: HashSet<String> = HashSet::new();

    // Rule 2 first, so the current generation's snapshot is protected
    // regardless of where it lands in the ranking. Only its NEWEST snapshot
    // is protected -- a generation applied more than once has several, and
    // only the latest is what a rollback would actually select (see
    // rollback::prepare's own max_by_key on the same key).
    if let Some(current) = sorted.iter().find(|e| e.generation == current_generation) {
        protected.insert(current.snapshot.clone());
    }

    for entry in sorted {
        if keep.len() < keep_generations || protected.contains(&entry.snapshot) {
            keep.push(entry);
        } else {
            prune.push(entry);
        }
    }

    // Oldest first, so a partially-failing run deletes the least useful
    // snapshots before whatever stops it.
    prune.reverse();
    GcPlan { prune, keep }
}

/// Really deletes one snapshot subvolume and its journal entry, in that
/// order.
///
/// Order is load-bearing. The journal entry is what makes a snapshot
/// *findable* -- `rollback::prepare` reads the journal, then checks the
/// subvolume still exists and refuses with a clear message if it does not.
/// So a crash between the two steps leaves a journal entry pointing at a
/// missing snapshot, which is an already-handled, already-tested condition
/// that fails loudly and safely. The reverse order would leave an orphaned
/// subvolume consuming disk with nothing referencing it -- invisible to
/// every tool here and to the operator.
fn delete_one(snapshot_dir: &Path, journal_dir: &Path, entry: &JournalEntry) -> anyhow::Result<()> {
    let path = snapshot_dir.join(&entry.snapshot);
    if path.exists() {
        let output = Command::new("btrfs")
            .args(["subvolume", "delete"])
            .arg(&path)
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "failed to delete snapshot subvolume {}: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    // Best-effort: a snapshot whose subvolume is already gone should still
    // lose its journal entry, which is precisely the state a previous
    // interrupted run leaves behind. Not finding the file is success.
    let journal_file = journal_dir.join(format!("{}.json", entry.snapshot));
    match std::fs::remove_file(&journal_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!(
            "deleted snapshot {} but could not remove its journal entry {}: {e}",
            entry.snapshot,
            journal_file.display()
        )),
    }
}

/// Runs a real GC pass. Returns the number of snapshots actually pruned.
pub fn run(
    snapshot_dir: &Path,
    journal_dir: &Path,
    keep_generations: usize,
    current_generation: u32,
    progress: &mut crate::progress::Progress,
) -> anyhow::Result<usize> {
    let entries = journal::list(journal_dir)?;
    let total = entries.len();
    let plan = plan(entries, keep_generations, current_generation);

    progress.event(
        "gc_plan",
        &format!(
            "{total} snapshots journalled; keeping {}, pruning {}",
            plan.keep.len(),
            plan.prune.len()
        ),
    );

    let mut pruned = 0;
    for entry in &plan.prune {
        progress.event("gc_prune", &entry.snapshot);
        // A single failure aborts the run rather than continuing: the most
        // likely cause is the filesystem itself being unhappy (a subvolume
        // still busy, a read-only mount), and grinding through every
        // remaining snapshot against a sick filesystem turns one clear
        // error into dozens.
        delete_one(snapshot_dir, journal_dir, entry)?;
        pruned += 1;
    }
    Ok(pruned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: u64, generation: u32) -> JournalEntry {
        JournalEntry {
            snapshot: format!("{ts}-gen{generation}"),
            generation,
            toplevel: "/nix/store/whatever".to_string(),
            taken_at: "2026-09-15 12:00:00".to_string(),
            quiesced: true,
        }
    }

    #[test]
    fn keeps_the_n_newest_and_prunes_the_rest() {
        let entries = vec![entry(100, 1), entry(200, 2), entry(300, 3), entry(400, 4)];
        // current = 4, which is also the newest, so rule 2 protects nothing extra.
        let plan = plan(entries, 2, 4);
        assert_eq!(plan.keep.len(), 2);
        assert_eq!(plan.prune.len(), 2);
        // Newest kept.
        assert_eq!(plan.keep[0].snapshot, "400-gen4");
        assert_eq!(plan.keep[1].snapshot, "300-gen3");
        // Pruned oldest-first.
        assert_eq!(plan.prune[0].snapshot, "100-gen1");
        assert_eq!(plan.prune[1].snapshot, "200-gen2");
    }

    #[test]
    fn never_prunes_the_running_generations_snapshot_even_when_it_is_old() {
        // The operator rebooted back into generation 1 and has since applied
        // three times. Generation 1's snapshot is the OLDEST, and a naive
        // "keep the 2 newest" would delete the only way back.
        let entries = vec![entry(100, 1), entry(200, 2), entry(300, 3), entry(400, 4)];
        let plan = plan(entries, 2, 1);
        let pruned: Vec<_> = plan.prune.iter().map(|e| e.snapshot.as_str()).collect();
        assert!(
            !pruned.contains(&"100-gen1"),
            "the running generation's snapshot must never be pruned, got {pruned:?}"
        );
        assert!(plan.keep.iter().any(|e| e.snapshot == "100-gen1"));
    }

    #[test]
    fn a_zero_retention_count_still_protects_the_running_generation() {
        let entries = vec![entry(100, 1), entry(200, 2)];
        let plan = plan(entries, 0, 1);
        assert_eq!(plan.keep.len(), 1);
        assert_eq!(plan.keep[0].snapshot, "100-gen1");
        assert_eq!(plan.prune.len(), 1);
        assert_eq!(plan.prune[0].snapshot, "200-gen2");
    }

    #[test]
    fn protects_only_the_newest_snapshot_of_a_repeated_generation() {
        // Generation 2 was applied twice. Only the later snapshot is what
        // rollback would select, so only it needs protecting.
        let entries = vec![entry(100, 2), entry(500, 2), entry(200, 3)];
        let plan = plan(entries, 0, 2);
        let kept: Vec<_> = plan.keep.iter().map(|e| e.snapshot.as_str()).collect();
        assert_eq!(kept, vec!["500-gen2"]);
        assert_eq!(plan.prune.len(), 2);
    }

    #[test]
    fn keeping_more_than_exist_prunes_nothing() {
        let entries = vec![entry(100, 1), entry(200, 2)];
        let plan = plan(entries, 10, 2);
        assert!(plan.prune.is_empty());
        assert_eq!(plan.keep.len(), 2);
    }

    #[test]
    fn an_empty_journal_is_not_an_error() {
        let plan = plan(Vec::new(), 3, 1);
        assert!(plan.prune.is_empty());
        assert!(plan.keep.is_empty());
    }

    #[test]
    fn deleting_an_already_missing_subvolume_still_removes_the_journal_entry() {
        // Exactly the state a previously-interrupted gc run leaves behind.
        // No btrfs is available here, and none is needed: the subvolume path
        // does not exist, so delete_one must skip the btrfs call entirely
        // and go straight to the journal entry.
        let dir = tempfile::tempdir().unwrap();
        let snapshot_dir = dir.path().join("snapshots");
        let journal_dir = dir.path().join("journal");
        std::fs::create_dir_all(&snapshot_dir).unwrap();
        std::fs::create_dir_all(&journal_dir).unwrap();

        let e = entry(100, 1);
        journal::write(&journal_dir, &e).unwrap();
        let journal_file = journal_dir.join(format!("{}.json", e.snapshot));
        assert!(journal_file.exists());

        delete_one(&snapshot_dir, &journal_dir, &e).unwrap();
        assert!(
            !journal_file.exists(),
            "the journal entry must be removed even when its subvolume is already gone"
        );
    }
}
