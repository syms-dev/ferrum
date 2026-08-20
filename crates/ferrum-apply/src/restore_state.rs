use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Serialize, Deserialize, Debug)]
pub struct RollbackIntent {
    pub target_generation: u32,
    pub snapshot: String,
    pub requested_at: String,
}

/// Returns Ok(None) if no rollback is pending (the common case, every
/// ordinary boot) -- this is not an error, it's the expected state. Any I/O
/// error other than "file genuinely doesn't exist" (e.g. permission denied)
/// is surfaced as an error rather than silently treated as "no intent".
pub fn read_intent(path: &Path) -> anyhow::Result<Option<RollbackIntent>> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(serde_json::from_str(&content)?))
}

pub struct StorageConfig {
    pub intent_path: PathBuf,
    pub result_path: PathBuf,
    pub failure_marker_path: PathBuf,
}

/// Writes the boot-time failure marker that `ferrum-apps.target`'s
/// ConditionPathExists uses to hold managed apps down. Lives on durable
/// storage (`@root`, NOT the snapshotted `@state` subvolume) specifically so
/// that a failed restore stays flagged across a later, unrelated reboot --
/// tmpfs would silently disarm the interlock on the very next boot, even one
/// with no rollback pending. Always creates the marker's parent directory
/// first -- this runs very early in boot and its parent directory is not
/// guaranteed to exist yet, so a plain `fs::write` would silently fail
/// (ENOENT) and leave the interlock fail-OPEN. Safe to call at any point,
/// including before anything else has touched disk.
fn write_failure_marker(path: &Path, reason: &str) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(path, reason) {
        eprintln!(
            "ferrum-apply restore-state: FAILED TO WRITE FAILURE MARKER at {}: {e} -- \
             apps may start despite an incomplete or failed restore",
            path.display()
        );
    }
}

/// `intent.snapshot` is a cross-task contract with Task 7's `rollback`
/// command and is used to build a path under `snapshots_dir`. Reject
/// anything that isn't a single plain path component: an absolute path
/// would discard `snapshots_dir` entirely, and `..` would let it escape.
fn validate_snapshot_name(snapshot: &str) -> anyhow::Result<()> {
    let mut components = Path::new(snapshot).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(_)), None) => Ok(()),
        _ => anyhow::bail!(
            "intent.snapshot must be a single plain path component, got {snapshot:?}"
        ),
    }
}

/// Performs the validated snapshot-and-rename swap (Phase 1.0 probe 0.2)
/// against the top-level btrfs volume mounted at `scratch_mount`.
fn perform_swap(scratch_mount: &Path, snapshot: &str) -> anyhow::Result<PathBuf> {
    validate_snapshot_name(snapshot)?;

    let snapshots_dir = scratch_mount.join("@snapshots");
    let live_state = scratch_mount.join("@state");
    let trash_dir = scratch_mount.join("trash");
    std::fs::create_dir_all(&trash_dir)?;

    let restoring = scratch_mount.join("@state.restoring");
    // Best-effort cleanup: a previous attempt may have snapshotted
    // successfully but failed before the rename, leaving this behind. Clear
    // it so this attempt's snapshot doesn't fail with "already exists".
    // Ignore errors -- if it doesn't exist, there's nothing to clean up.
    let _ = Command::new("btrfs")
        .args(["subvolume", "delete"])
        .arg(&restoring)
        .status();

    let status = Command::new("btrfs")
        .args(["subvolume", "snapshot"])
        .arg(snapshots_dir.join(snapshot))
        .arg(&restoring)
        .status()?;
    if !status.success() {
        anyhow::bail!("btrfs subvolume snapshot failed while materializing a writable copy");
    }

    let displaced = trash_dir.join(format!(
        "@state.replaced.{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    ));
    std::fs::rename(&live_state, &displaced)?;
    std::fs::rename(&restoring, &live_state)?;
    Ok(displaced)
}

/// Mounts the top-level btrfs volume and performs the swap. Separated from
/// `run` so the empty-root-device case is just another failure inside the
/// normal fail-closed flow, not a special case checked before the marker is
/// written.
fn attempt_restore(root_device: &str, snapshot: &str, target_generation: u32) -> anyhow::Result<()> {
    if root_device.is_empty() {
        anyhow::bail!(
            "FERRUM_ROOT_DEVICE is not set (or resolved empty) -- cannot mount the \
             top-level btrfs volume to perform the restore"
        );
    }

    // rollback::prepare writes the intent before `nix-env --switch-generation`
    // runs, so it's possible in principle for what actually booted to differ
    // from what the intent expected -- a bug in the switch step, or manual
    // operator intervention. Check before touching any state: swapping in a
    // snapshot for a generation that isn't the one running would be wrong no
    // matter how cheaply it failed.
    let (actual_generation, _) = crate::apply::current_generation()?;
    if actual_generation != target_generation {
        anyhow::bail!(
            "intent targets generation {target_generation} but generation {actual_generation} \
             is what's currently running -- refusing to restore state for a generation that \
             isn't booted"
        );
    }

    let scratch_mount = PathBuf::from("/run/ferrum/btrfs");
    std::fs::create_dir_all(&scratch_mount)?;
    let mount_status = Command::new("mount")
        .args(["-t", "btrfs", "-o", "subvolid=5,noatime", root_device])
        .arg(&scratch_mount)
        .status()?;
    if !mount_status.success() {
        anyhow::bail!("failed to mount the top-level btrfs volume for the state swap");
    }

    let swap_result = perform_swap(&scratch_mount, snapshot);

    let _ = Command::new("umount").arg(&scratch_mount).status();

    swap_result?;
    Ok(())
}

/// Never returns an error to its caller -- a failed restore must not fail
/// the boot. Failure is signaled by writing `storage.failure_marker_path`,
/// which `ferrum-apps.target`'s `ConditionPathExists` uses to hold managed
/// apps down.
///
/// Fail-closed by construction: as soon as a valid rollback intent is
/// confirmed (the only case where anything risky is about to happen), the
/// failure marker is written immediately, *before* the mount/snapshot/
/// rename sequence is attempted at all, and it is removed only after that
/// sequence is confirmed to have fully succeeded. This means any abnormal
/// termination from that point on -- a panic, SIGKILL, timeout, OOM, or the
/// process simply never finishing -- leaves the marker in place, which is
/// the safe default. Ordinary boots (no intent) never write it at all.
pub fn run(root_device: &str, storage: &StorageConfig) {
    let intent = match read_intent(&storage.intent_path) {
        Ok(None) => return, // ordinary boot, nothing to do
        Ok(Some(intent)) => intent,
        Err(e) => {
            eprintln!("ferrum-apply restore-state: malformed intent file: {e}");
            write_failure_marker(
                &storage.failure_marker_path,
                &format!("malformed rollback intent file: {e}"),
            );
            return;
        }
    };

    // Assume failure until proven otherwise -- this is the actual safety
    // net. Everything below can panic, be killed, or time out without
    // making this interlock any less safe.
    write_failure_marker(
        &storage.failure_marker_path,
        "restore in progress or did not complete",
    );

    let result = attempt_restore(root_device, &intent.snapshot, intent.target_generation);

    match &result {
        Ok(()) => {
            let _ = std::fs::write(
                &storage.result_path,
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "generation": intent.target_generation,
                    "restoredFrom": intent.snapshot,
                }))
                .unwrap(),
            );
            // Only remove the marker once everything else about a
            // successful restore has been recorded -- this is the one
            // place the interlock is allowed to open back up.
            if let Err(e) = std::fs::remove_file(&storage.failure_marker_path) {
                eprintln!(
                    "ferrum-apply restore-state: restore succeeded but failed to remove the \
                     failure marker at {}: {e} -- apps will stay blocked until this is \
                     cleared manually",
                    storage.failure_marker_path.display()
                );
            }
            // The intent is only ever removed on confirmed success, matching
            // the malformed-intent path above (which never removes it
            // either). A FAILED restore deliberately leaves the intent in
            // place: the failure marker already holds apps down regardless,
            // so there's no safety reason to make a failure one-shot, and
            // every reason not to -- a transient failure (a flaky mount, a
            // brief resource contention) can self-heal on a later boot
            // instead of silently never retrying.
            if let Err(e) = std::fs::remove_file(&storage.intent_path) {
                eprintln!(
                    "ferrum-apply restore-state: restore succeeded but failed to remove the \
                     rollback intent file {}: {e} -- this same intent will re-trigger the same \
                     restore attempt (a no-op re-establishing the same already-correct state) \
                     on the next boot; safe, but worth fixing so it stops repeating",
                    storage.intent_path.display()
                );
            }
        }
        Err(e) => {
            eprintln!("ferrum-apply restore-state: {e}");
            // Already in place from above; rewrite it with the real reason.
            write_failure_marker(&storage.failure_marker_path, &e.to_string());
            let _ = std::fs::write(
                &storage.result_path,
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": false,
                    "error": e.to_string(),
                }))
                .unwrap(),
            );
            // Intent stays -- see the success branch's comment above for why.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_well_formed_intent_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollback-intent.json");
        std::fs::write(
            &path,
            r#"{"target_generation": 1, "snapshot": "1000-gen1", "requested_at": "2026-08-20T00:00:00Z"}"#,
        )
        .unwrap();
        let intent = read_intent(&path).unwrap().unwrap();
        assert_eq!(intent.target_generation, 1);
        assert_eq!(intent.snapshot, "1000-gen1");
    }

    #[test]
    fn missing_intent_file_means_ordinary_boot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert!(read_intent(&path).unwrap().is_none());
    }

    #[test]
    fn malformed_intent_file_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rollback-intent.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(read_intent(&path).is_err());
    }

    #[test]
    fn validate_snapshot_name_accepts_a_plain_component() {
        assert!(validate_snapshot_name("1000-gen1").is_ok());
    }

    #[test]
    fn validate_snapshot_name_rejects_absolute_paths() {
        assert!(validate_snapshot_name("/etc/passwd").is_err());
    }

    #[test]
    fn validate_snapshot_name_rejects_path_traversal() {
        assert!(validate_snapshot_name("../../etc/passwd").is_err());
        assert!(validate_snapshot_name("foo/../../bar").is_err());
    }

    #[test]
    fn validate_snapshot_name_rejects_empty_and_dot() {
        assert!(validate_snapshot_name("").is_err());
        assert!(validate_snapshot_name(".").is_err());
        assert!(validate_snapshot_name("..").is_err());
    }

    /// The single most safety-critical property in this module: a malformed
    /// intent must leave the failure marker in place, so
    /// `ferrum-apps.target`'s `ConditionPathExists` holds apps down.
    #[test]
    fn malformed_intent_leaves_the_failure_marker_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let storage = StorageConfig {
            intent_path: dir.path().join("var/rollback-intent.json"),
            result_path: dir.path().join("var/rollback-result.json"),
            failure_marker_path: dir.path().join("run/ferrum/state-restore-failed"),
        };
        std::fs::create_dir_all(storage.intent_path.parent().unwrap()).unwrap();
        std::fs::write(&storage.intent_path, "not json").unwrap();

        // The marker's parent (run/ferrum) deliberately does NOT exist yet,
        // reproducing the exact condition that caused Critical #1: nothing
        // else has created /run/ferrum by this point in boot.
        assert!(!storage.failure_marker_path.parent().unwrap().exists());

        run("", &storage);

        assert!(
            storage.failure_marker_path.exists(),
            "failure marker must exist after a malformed intent"
        );
    }

    /// A valid-but-unactionable intent (e.g. no root device resolvable,
    /// reproducing Critical #2's underlying condition of a null device)
    /// must also leave the marker in place. The intent itself is left in
    /// place too (not removed) -- a failed restore retries on the next
    /// boot instead of being one-shot, so a transient failure can self-heal
    /// without an operator having to re-trigger the rollback by hand.
    #[test]
    fn failed_restore_leaves_marker_and_intent_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let storage = StorageConfig {
            intent_path: dir.path().join("var/rollback-intent.json"),
            result_path: dir.path().join("var/rollback-result.json"),
            failure_marker_path: dir.path().join("run/ferrum/state-restore-failed"),
        };
        std::fs::create_dir_all(storage.intent_path.parent().unwrap()).unwrap();
        std::fs::write(
            &storage.intent_path,
            r#"{"target_generation": 1, "snapshot": "1000-gen1", "requested_at": "2026-08-20T00:00:00Z"}"#,
        )
        .unwrap();

        // Empty root device: attempt_restore fails immediately without
        // touching a real filesystem, exercising the fail-closed path with
        // no btrfs/mount available in this sandbox.
        run("", &storage);

        assert!(
            storage.failure_marker_path.exists(),
            "failure marker must exist after a failed restore"
        );
        assert!(
            storage.intent_path.exists(),
            "intent file must stay in place after a failed restore, so it retries on the next boot"
        );
    }

    #[test]
    fn missing_intent_writes_no_marker() {
        let dir = tempfile::tempdir().unwrap();
        let storage = StorageConfig {
            intent_path: dir.path().join("var/rollback-intent.json"),
            result_path: dir.path().join("var/rollback-result.json"),
            failure_marker_path: dir.path().join("run/ferrum/state-restore-failed"),
        };

        run("", &storage);

        assert!(!storage.failure_marker_path.exists());
    }
}
