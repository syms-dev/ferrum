use ferrum_state::generations::{is_rollbackable, snapshot_ts, GenerationInfo};
use ferrum_state::journal;
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
    snapshot_dir: &Path,
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
            .max_by_key(|e| snapshot_ts(&e.snapshot))
            .cloned(),
    };

    is_rollbackable(&info).map_err(|e| anyhow::anyhow!(e))?;
    let snapshot = info.snapshot.unwrap().snapshot;

    // The journal entry surviving doesn't guarantee the snapshot subvolume
    // it points at still exists on disk (it may have been pruned manually,
    // or later by `gc`). Check before committing to a reboot that
    // ferrum-state-restore.service cannot complete -- this is deliberately
    // a plain existence check, not a "is this really a valid btrfs
    // subvolume" check (see preflight::check_is_subvolume for that class).
    let snapshot_path = snapshot_dir.join(&snapshot);
    if !snapshot_path.exists() {
        anyhow::bail!(
            "generation {target_generation}'s snapshot {snapshot:?} is recorded in the \
             journal but no longer exists at {}",
            snapshot_path.display()
        );
    }

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

/// Purely additive instrumentation wrapper around `run_inner`, mirroring
/// `apply::run`: writes the terminal `complete` progress line on both the
/// success and error paths, so a job's progress file always ends in one.
/// Note the success path only ever reaches `complete` if `reboot` returns
/// without the machine going down first -- a rollback that reboots
/// promptly ends its progress stream by the unit (and machine) going away,
/// which is exactly what an operator watching it should see.
pub fn run(
    target_generation: u32,
    journal_dir: &Path,
    intent_path: &Path,
    snapshot_dir: &Path,
) -> anyhow::Result<()> {
    let mut progress = crate::progress::Progress::open();
    let outcome = run_inner(
        target_generation,
        journal_dir,
        intent_path,
        snapshot_dir,
        &mut progress,
    );
    match &outcome {
        Ok(()) => progress.complete("succeeded", &format!("rebooting into generation {target_generation}")),
        Err(e) => progress.complete("failed", &e.to_string()),
    }
    outcome
}

fn run_inner(
    target_generation: u32,
    journal_dir: &Path,
    intent_path: &Path,
    snapshot_dir: &Path,
    progress: &mut crate::progress::Progress,
) -> anyhow::Result<()> {
    progress.event(
        "validate",
        &format!("checking generation {target_generation} has a usable state snapshot"),
    );
    prepare(target_generation, journal_dir, intent_path, snapshot_dir)?;
    progress.event("write-intent", "rollback intent written");

    progress.event("switch-generation", "pointing the system profile at the target generation");
    let status = Command::new("nix-env")
        .args([
            "-p",
            "/nix/var/nix/profiles/system",
            "--switch-generation",
            &target_generation.to_string(),
        ])
        .status()?;
    if !status.success() {
        // A rollback attempt that never touched the Nix profile must leave
        // no trace -- otherwise a stale intent file triggers a surprise
        // state restore on some later, unrelated boot.
        let _ = std::fs::remove_file(intent_path);
        anyhow::bail!("nix-env --switch-generation {target_generation} failed");
    }

    let status = Command::new("/nix/var/nix/profiles/system/bin/switch-to-configuration")
        .arg("boot")
        .status()?;
    if !status.success() {
        let _ = std::fs::remove_file(intent_path);
        anyhow::bail!("switch-to-configuration boot failed");
    }

    progress.event("reboot", "scheduling the reboot into the target generation");
    request_reboot("reboot")
}

/// Asks the machine to reboot, and refuses to call a non-zero exit a
/// reboot.
///
/// `Command::status()?` propagates only a failure to SPAWN; a process that
/// ran and exited non-zero comes back as `Ok(status)`. Discarding that
/// status made a failed `reboot` indistinguishable from a successful one,
/// and `run` then wrote "succeeded -- rebooting into generation N" about a
/// machine that had not moved. The two steps above already check
/// `status.success()` for exactly this reason; this one did not.
///
/// The intent file is deliberately KEPT on failure, which is the opposite
/// of what the two steps above do. They remove it because they failed
/// before the boot configuration was committed, so a surviving intent would
/// "trigger a surprise state restore on some later, unrelated boot". Here
/// `switch-to-configuration boot` has already succeeded -- generation N is
/// armed and the next boot goes there whatever this process does -- so
/// removing the intent would leave the machine booting the target
/// generation with the CURRENT state, which is the mismatch the intent file
/// exists to prevent. Keeping it is correct; saying nothing was not.
///
/// # Arguments
/// * `program` - the reboot binary to run. Parameterised only so the
///   failure path can be exercised against a real process with a real exit
///   code.
///
/// # Errors
/// When the reboot cannot be spawned, or exits non-zero. The message says
/// the machine is still up and that the target generation is nonetheless
/// armed, because the operator's next action differs completely from the
/// other two failure paths: there, nothing happened; here, the rollback
/// will complete on the next boot by any cause.
fn request_reboot(program: &str) -> anyhow::Result<()> {
    let status = Command::new(program).status()?;
    if !status.success() {
        anyhow::bail!(
            "the machine did not reboot: {program} exited with {}. The \
             target generation is already armed and the rollback intent is \
             still in place, so the rollback WILL complete on the next \
             boot -- reboot deliberately rather than leaving it to happen \
             unannounced.",
            status
                .code()
                .map(|c| format!("status {c}"))
                .unwrap_or_else(|| "a signal".to_string())
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_state::journal::JournalEntry;

    fn write_journal_entry(dir: &std::path::Path, snapshot: &str, generation: u32) {
        ferrum_state::journal::write(
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

    /// A `reboot` that exits non-zero is not a reboot.
    ///
    /// `Command::status()?` propagates only a failure to SPAWN. A non-zero
    /// exit came back as `Ok(status)` and was discarded, so `run_inner`
    /// returned `Ok(())` and `run` wrote "succeeded -- rebooting into
    /// generation N" about a machine that had not moved.
    /// Writes an executable `/bin/sh` script that exits with `code`, and
    /// returns its path.
    ///
    /// NOT `/bin/false` and `/bin/true`, which is what these tests used
    /// first. Those exist on a developer's machine and on CI's runner, and
    /// do NOT exist inside a Nix build sandbox -- so `cargo test` was green
    /// everywhere a human looked while the `cargo-test-ferrum-apply` and
    /// `workspace-tests` flake checks failed with ENOENT. A test fixture
    /// that depends on the ambient filesystem is a test that passes for a
    /// reason unrelated to the code. `/bin/sh` is one of the few paths Nix
    /// guarantees inside the sandbox, so the script is portable where the
    /// coreutils binaries are not.
    fn script_exiting(dir: &std::path::Path, name: &str, code: u8) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\nexit {code}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn a_reboot_that_fails_is_not_reported_as_a_reboot() {
        let dir = tempfile::tempdir().unwrap();
        let failing = script_exiting(dir.path(), "reboot-fails", 1);
        let err = request_reboot(&failing).unwrap_err().to_string();
        assert!(
            err.contains("did not reboot"),
            "the operator has to be told the machine is still up: {err}"
        );
        assert!(
            err.contains("armed"),
            "and that the target generation is already committed for the \
             next boot: {err}"
        );
    }

    /// The success path still succeeds, so the check above cannot be
    /// satisfied by refusing everything.
    #[test]
    fn a_reboot_that_is_accepted_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let accepting = script_exiting(dir.path(), "reboot-ok", 0);
        request_reboot(&accepting).unwrap();
    }

    /// A `reboot` binary that is not there at all is a spawn failure, and
    /// must not be mistaken for a clean reboot either.
    #[test]
    fn a_reboot_that_cannot_be_spawned_is_an_error() {
        assert!(request_reboot("/nonexistent/reboot").is_err());
    }

    #[test]
    fn refuses_a_generation_with_no_snapshot() {
        let journal_dir = tempfile::tempdir().unwrap();
        let intent_path = journal_dir.path().join("intent.json");
        // No snapshot_dir contents needed -- this fails earlier, on
        // is_rollbackable, before ever checking the snapshot dir.
        let snapshot_dir = tempfile::tempdir().unwrap();
        let err = prepare(99, journal_dir.path(), &intent_path, snapshot_dir.path()).unwrap_err();
        assert!(err.to_string().contains("no state snapshot"));
        assert!(!intent_path.exists());
    }

    #[test]
    fn writes_a_valid_intent_file_for_a_rollbackable_generation() {
        let journal_dir = tempfile::tempdir().unwrap();
        write_journal_entry(journal_dir.path(), "1000-gen1", 1);
        let intent_path = journal_dir.path().join("intent.json");
        let snapshot_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(snapshot_dir.path().join("1000-gen1")).unwrap();

        let intent = prepare(1, journal_dir.path(), &intent_path, snapshot_dir.path()).unwrap();
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
        let snapshot_dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(snapshot_dir.path().join("1000-gen1")).unwrap();
        std::fs::create_dir_all(snapshot_dir.path().join("2000-gen1")).unwrap();

        let intent = prepare(1, journal_dir.path(), &intent_path, snapshot_dir.path()).unwrap();
        assert_eq!(intent.snapshot, "2000-gen1");
    }

    #[test]
    fn refuses_when_the_journal_entry_exists_but_the_snapshot_directory_is_gone() {
        let journal_dir = tempfile::tempdir().unwrap();
        write_journal_entry(journal_dir.path(), "1000-gen1", 1);
        let intent_path = journal_dir.path().join("intent.json");
        // Deliberately does NOT create snapshot_dir/1000-gen1 -- the
        // journal entry is recorded but the snapshot itself is gone.
        let snapshot_dir = tempfile::tempdir().unwrap();

        let err = prepare(1, journal_dir.path(), &intent_path, snapshot_dir.path()).unwrap_err();
        assert!(err.to_string().contains("no longer exists"));
        assert!(!intent_path.exists());
    }
}
