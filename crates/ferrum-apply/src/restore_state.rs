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

/// `FERRUM_ROOT_DEVICE` becomes an argv entry of `mount`, run as root from
/// a `DefaultDependencies = false` unit ordered before `local-fs.target`.
/// Reject anything that cannot be a device path.
///
/// The leading `-` is the whole finding. Until this existed the only guard
/// was `is_empty()`, so a value starting with `-` was not passed to `mount`
/// as a device at all -- `mount` parses it as an option, and `-o` takes the
/// NEXT argv entry as its argument, which here is the scratch mount point.
/// One environment value therefore rewrote the shape of a privileged
/// early-boot command. Requiring an absolute path covers that and every
/// other non-device value in one rule, which beats a denylist of leading
/// `-`: `dev/sda1` is not a device either.
///
/// This is `validate_snapshot_name`'s sibling. That one guards the other
/// externally-supplied component of the same operation, and the two
/// together are the whole of what `restore-state` accepts from outside.
///
/// Nothing is taken away from a working host:
/// `modules/core/state-restore.nix` asserts at evaluation time that
/// `fileSystems.<stateDir>.device` resolves to "a concrete block device",
/// and refuses to build otherwise.
///
/// # Arguments
/// * `root_device` - the value of `FERRUM_ROOT_DEVICE`, possibly empty
///   when NixOS omitted the variable.
///
/// # Errors
/// An `anyhow::Error` naming `FERRUM_ROOT_DEVICE` when the value is empty,
/// is not an absolute path, or carries a NUL or a newline.
fn validate_root_device(root_device: &str) -> anyhow::Result<()> {
    if root_device.is_empty() {
        anyhow::bail!(
            "FERRUM_ROOT_DEVICE is not set (or resolved empty) -- cannot mount the \
             top-level btrfs volume to perform the restore"
        );
    }
    if !root_device.starts_with('/') {
        anyhow::bail!(
            "FERRUM_ROOT_DEVICE must be an absolute device path, got {root_device:?} -- \
             a value that is not a path reaches mount as an option rather than a device"
        );
    }
    if root_device.contains('\0') || root_device.contains('\n') {
        anyhow::bail!(
            "FERRUM_ROOT_DEVICE must not contain a NUL or a newline, got {root_device:?}"
        );
    }
    Ok(())
}

/// Performs the validated snapshot-and-rename swap (Phase 1.0 probe 0.2)
/// against the top-level btrfs volume mounted at `scratch_mount`.
///
/// The swap is two renames, and a crash between them used to be permanently
/// unrecoverable. `rename(@state -> trash/@state.replaced.<ts>)` succeeds,
/// then `rename(@state.restoring -> @state)` never runs: the host is left
/// with NO `@state` and the restored copy still under its working name. The
/// next boot's retry then deleted `@state.restoring` -- the only copy of
/// the restored state -- re-snapshotted, and failed at the first rename
/// with ENOENT because `@state` was not there. Every boot after that did
/// the same, so apps stayed held down by the failure marker forever, and
/// `run`'s claim that a transient failure "can self-heal on a later boot"
/// was false for exactly this state.
///
/// That window is real on this unit. It runs early in boot with
/// `DefaultDependencies = false`, so a SIGKILL on unit timeout, or power
/// loss during an operator-initiated reboot, land squarely in it.
///
/// So the retry now asks which interruption it is looking at before doing
/// anything destructive:
///
/// * `@state` absent AND `@state.restoring` present -- the first rename
///   completed and the second did not. FINISH it: the second rename is all
///   that is left, and `@state.restoring` is a complete snapshot because
///   the first rename only runs after the snapshot succeeded.
/// * anything else -- start over, which is what the old code always did.
///
/// `renameat2(RENAME_EXCHANGE)` would close the window rather than recover
/// from it, but there is no binding for it in this workspace's dependency
/// set and adding one is not worth it: detection needs no syscall the std
/// library does not already expose, and it also recovers hosts already
/// stuck in this state, which an atomic exchange would not.
///
/// # Arguments
/// * `scratch_mount` - the top-level btrfs volume (`subvolid=5`).
/// * `snapshot` - the snapshot directory name under `@snapshots`.
///
/// # Errors
/// When the snapshot name is invalid, the btrfs snapshot fails, or either
/// rename fails.
fn perform_swap(scratch_mount: &Path, snapshot: &str) -> anyhow::Result<()> {
    validate_snapshot_name(snapshot)?;

    let snapshots_dir = scratch_mount.join("@snapshots");
    let live_state = scratch_mount.join("@state");
    let trash_dir = scratch_mount.join("trash");
    std::fs::create_dir_all(&trash_dir)?;

    let restoring = scratch_mount.join("@state.restoring");

    // Before the destructive cleanup below: is this a swap that was
    // interrupted between its two renames? If so the only thing missing is
    // the second one. Restarting from here cannot work -- there is no
    // @state left to displace -- and the cleanup would destroy the restored
    // copy on the way to finding that out.
    if !live_state.exists() && restoring.exists() {
        std::fs::rename(&restoring, &live_state)?;
        return Ok(());
    }

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
    Ok(())
}

/// Mounts the top-level btrfs volume and performs the swap. Separated from
/// `run` so the empty-root-device case is just another failure inside the
/// normal fail-closed flow, not a special case checked before the marker is
/// written.
fn attempt_restore(root_device: &str, snapshot: &str, target_generation: u32) -> anyhow::Result<()> {
    validate_root_device(root_device)?;

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
            //
            // That claim used to be false for one state, and it was the
            // state most likely to occur: a crash between `perform_swap`'s
            // two renames left no `@state`, and every retry then failed
            // identically forever. `perform_swap` now detects that case and
            // finishes the interrupted swap, so retrying is genuinely
            // capable of healing it rather than only of repeating.
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

    /// The exact on-disk state a crash between the two renames leaves.
    ///
    /// `perform_swap` renames `@state` into `trash/` and then renames
    /// `@state.restoring` into its place. A crash in between -- a SIGKILL
    /// on unit timeout, or power loss during an operator-initiated reboot,
    /// both realistic for a `DefaultDependencies = false` early-boot unit --
    /// leaves the host with NO `@state` and the restored copy still sitting
    /// at `@state.restoring`.
    ///
    /// Before this was handled, the next boot deleted `@state.restoring`
    /// (the only copy of the restored state), re-snapshotted, and then
    /// failed at `rename(@state -> trash/...)` with ENOENT, because
    /// `@state` was not there. Every subsequent boot did the same, so apps
    /// stayed held down by the failure marker forever.
    ///
    /// The setup below is filesystem state, not btrfs state, so what this
    /// executes is the recovery decision and the rename that completes the
    /// swap -- not a real crash. That is the point: the recovery path
    /// touches no btrfs subcommand at all, which is why it can be asserted
    /// here with real renames on real directories.
    #[test]
    fn an_interrupted_swap_is_finished_rather_than_restarted() {
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path();
        std::fs::create_dir_all(mount.join("@snapshots/1000-gen1")).unwrap();
        // The first rename completed: the old state is already in trash.
        std::fs::create_dir_all(mount.join("trash/@state.replaced.1000")).unwrap();
        // The second never ran: the restored copy is still under its
        // working name, and @state does not exist.
        std::fs::create_dir_all(mount.join("@state.restoring")).unwrap();
        std::fs::write(mount.join("@state.restoring/marker"), b"restored").unwrap();
        assert!(!mount.join("@state").exists());

        perform_swap(mount, "1000-gen1").unwrap();

        assert!(
            mount.join("@state").exists(),
            "the interrupted swap must be completed, not started over"
        );
        assert_eq!(
            std::fs::read(mount.join("@state/marker")).unwrap(),
            b"restored",
            "and it must be the RESTORED copy that lands at @state"
        );
        assert!(
            !mount.join("@state.restoring").exists(),
            "the working name is consumed by the rename"
        );
    }

    /// The recovery must key on `@state` being ABSENT, not merely on
    /// `@state.restoring` being present.
    ///
    /// A leftover `@state.restoring` beside a live `@state` is the other
    /// interruption -- a crash after the snapshot and before the first
    /// rename -- and that one genuinely must be restarted, because
    /// `@state.restoring` may be a half-written snapshot. Treating it as a
    /// finished swap would discard the live state for an incomplete copy.
    #[test]
    fn a_leftover_restoring_beside_a_live_state_is_not_treated_as_finished() {
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path();
        std::fs::create_dir_all(mount.join("@snapshots/1000-gen1")).unwrap();
        std::fs::create_dir_all(mount.join("@state")).unwrap();
        std::fs::write(mount.join("@state/marker"), b"live").unwrap();
        std::fs::create_dir_all(mount.join("@state.restoring")).unwrap();

        // No btrfs here, so the restart fails at the snapshot step -- which
        // is the proof that it took the restart path at all rather than
        // quietly "completing" a swap that had not reached its first
        // rename.
        assert!(perform_swap(mount, "1000-gen1").is_err());
        assert_eq!(
            std::fs::read(mount.join("@state/marker")).unwrap(),
            b"live",
            "the live state must still be there"
        );
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

    /// R2/SEC3. `FERRUM_ROOT_DEVICE` is interpolated straight into
    /// `mount`'s argv, as root, from a `DefaultDependencies = false` unit
    /// ordered before `local-fs.target` -- about as early and as privileged
    /// as code on this host gets. The only guard was `is_empty()`, so a
    /// value beginning with `-` is not a device at all: `mount` parses it
    /// as an option, and `-o` in particular takes the NEXT argv entry as
    /// its argument, which here is the scratch mount point. That silently
    /// reshapes the whole command.
    ///
    /// Asserted through `attempt_restore` rather than the validator alone,
    /// because the property is about ORDER: the refusal has to land before
    /// anything else is attempted, exactly as the `is_empty()` check did.
    /// `modules/core/state-restore.nix`'s own assertions already require
    /// `fileSystems.<stateDir>.device` to be "a concrete block device", so
    /// requiring an absolute path takes nothing away that a working host
    /// has.
    #[test]
    fn a_root_device_that_is_really_an_option_never_reaches_mount() {
        for bad in ["-o", "--bind", "-o subvolid=5", "", "dev/sda1", "/dev/sda\n-o"] {
            let err = attempt_restore(bad, "1000-gen1", 1).unwrap_err();
            let message = format!("{err:#}");
            assert!(
                message.contains("FERRUM_ROOT_DEVICE"),
                "root device {bad:?} was not refused as a device -- it failed later, \
                 with: {message}"
            );
        }
    }

    #[test]
    fn a_real_block_device_path_is_still_accepted() {
        for good in [
            "/dev/sda1",
            "/dev/nvme0n1p2",
            "/dev/disk/by-uuid/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9",
            "/dev/mapper/cryptroot",
        ] {
            validate_root_device(good)
                .unwrap_or_else(|e| panic!("rejected a real device path {good:?}: {e}"));
        }
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
