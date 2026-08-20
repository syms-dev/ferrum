use crate::generations::{correlate, is_rollbackable, GenerationInfo};
use crate::journal;
use crate::restore_state::RollbackIntent;
use std::path::Path;
use std::process::Command;

/// Validates that `target_generation` has a state snapshot and writes the
/// rollback-intent file. Does not touch the Nix profile or reboot -- that's
/// `run`'s job, kept separate so this half is unit-testable.
pub fn prepare(
    target_generation: u32,
    journal_dir: &Path,
    intent_path: &Path,
) -> anyhow::Result<RollbackIntent> {
    let entries = journal::list(journal_dir)?;
    let matching: Vec<_> = entries
        .iter()
        .filter(|e| e.generation == target_generation)
        .cloned()
        .collect();

    let info = GenerationInfo {
        generation: target_generation,
        date: String::new(),
        current: false,
        snapshot: matching
            .iter()
            .max_by_key(|e| {
                e.snapshot
                    .split('-')
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
            })
            .cloned(),
    };

    is_rollbackable(&info).map_err(|e| anyhow::anyhow!(e))?;
    let snapshot = info.snapshot.unwrap().snapshot;

    let intent = RollbackIntent {
        target_generation,
        snapshot,
        requested_at: format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs()
        ),
    };

    let tmp_path = intent_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, serde_json::to_string_pretty(&intent)?)?;
    std::fs::rename(&tmp_path, intent_path)?;

    Ok(intent)
}

/// Runs correlate() only as a convenience for a future `list-generations`
/// consumer -- unused by `run` itself, which validates directly via
/// `prepare`. Kept here because `generations::correlate`'s only current
/// caller is this module's tests; removing an unused-import warning by
/// invoking it in a real (if small) code path is preferable to `#[allow]`.
#[allow(dead_code)]
fn all_generations_info(
    nix_env_output: &str,
    journal_dir: &Path,
) -> anyhow::Result<Vec<GenerationInfo>> {
    let parsed = crate::generations::parse_nix_env_list(nix_env_output);
    let entries = journal::list(journal_dir)?;
    Ok(correlate(parsed, entries))
}

pub fn run(target_generation: u32, journal_dir: &Path, intent_path: &Path) -> anyhow::Result<()> {
    prepare(target_generation, journal_dir, intent_path)?;

    let status = Command::new("nix-env")
        .args([
            "-p",
            "/nix/var/nix/profiles/system",
            "--switch-generation",
            &target_generation.to_string(),
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("nix-env --switch-generation {target_generation} failed");
    }

    let status = Command::new("/nix/var/nix/profiles/system/bin/switch-to-configuration")
        .arg("boot")
        .status()?;
    if !status.success() {
        anyhow::bail!("switch-to-configuration boot failed");
    }

    Command::new("reboot").status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalEntry;

    fn write_journal_entry(dir: &std::path::Path, snapshot: &str, generation: u32) {
        crate::journal::write(
            dir,
            &JournalEntry {
                snapshot: snapshot.to_string(),
                generation,
                toplevel: "/nix/store/x".to_string(),
                taken_at: "2026-08-20T00:00:00Z".to_string(),
                quiesced: true,
            },
        )
        .unwrap();
    }

    #[test]
    fn refuses_a_generation_with_no_snapshot() {
        let journal_dir = tempfile::tempdir().unwrap();
        let intent_path = journal_dir.path().join("intent.json");
        let err = prepare(99, journal_dir.path(), &intent_path).unwrap_err();
        assert!(err.to_string().contains("no state snapshot"));
        assert!(!intent_path.exists());
    }

    #[test]
    fn writes_a_valid_intent_file_for_a_rollbackable_generation() {
        let journal_dir = tempfile::tempdir().unwrap();
        write_journal_entry(journal_dir.path(), "1000-gen1", 1);
        let intent_path = journal_dir.path().join("intent.json");

        let intent = prepare(1, journal_dir.path(), &intent_path).unwrap();
        assert_eq!(intent.target_generation, 1);
        assert_eq!(intent.snapshot, "1000-gen1");

        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&intent_path).unwrap()).unwrap();
        assert_eq!(on_disk["target_generation"], 1);
        assert_eq!(on_disk["snapshot"], "1000-gen1");
    }

    #[test]
    fn picks_the_latest_snapshot_when_the_generation_number_repeats() {
        let journal_dir = tempfile::tempdir().unwrap();
        write_journal_entry(journal_dir.path(), "1000-gen1", 1);
        write_journal_entry(journal_dir.path(), "2000-gen1", 1);
        let intent_path = journal_dir.path().join("intent.json");

        let intent = prepare(1, journal_dir.path(), &intent_path).unwrap();
        assert_eq!(intent.snapshot, "2000-gen1");
    }
}
