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
/// ordinary boot) -- this is not an error, it's the expected state.
pub fn read_intent(path: &Path) -> anyhow::Result<Option<RollbackIntent>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    Ok(Some(serde_json::from_str(&content)?))
}

pub struct StorageConfig {
    pub intent_path: PathBuf,
    pub result_path: PathBuf,
    pub failure_marker_path: PathBuf,
}

/// Performs the validated snapshot-and-rename swap (Phase 1.0 probe 0.2)
/// against the top-level btrfs volume mounted at `scratch_mount`.
fn perform_swap(scratch_mount: &Path, snapshot: &str) -> anyhow::Result<PathBuf> {
    let snapshots_dir = scratch_mount.join("@snapshots");
    let live_state = scratch_mount.join("@state");
    let trash_dir = scratch_mount.join("trash");
    std::fs::create_dir_all(&trash_dir)?;

    let restoring = scratch_mount.join("@state.restoring");
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

/// Never returns an error to its caller -- a failed restore must not fail
/// the boot. Failure is signaled by writing failure_marker_path, which
/// ferrum-apps.target's ConditionPathExists uses to hold managed apps down.
pub fn run(root_device: &str, storage: &StorageConfig) {
    let intent = match read_intent(&storage.intent_path) {
        Ok(None) => return, // ordinary boot, nothing to do
        Ok(Some(intent)) => intent,
        Err(e) => {
            eprintln!("ferrum-apply restore-state: malformed intent file: {e}");
            let _ = std::fs::write(&storage.failure_marker_path, e.to_string());
            let _ = std::fs::remove_file(&storage.intent_path);
            return;
        }
    };

    let result = (|| -> anyhow::Result<()> {
        let scratch_mount = PathBuf::from("/run/ferrum/btrfs");
        std::fs::create_dir_all(&scratch_mount)?;
        let mount_status = Command::new("mount")
            .args(["-t", "btrfs", "-o", "subvolid=5,noatime", root_device])
            .arg(&scratch_mount)
            .status()?;
        if !mount_status.success() {
            anyhow::bail!("failed to mount the top-level btrfs volume for the state swap");
        }

        let swap_result = perform_swap(&scratch_mount, &intent.snapshot);

        let _ = Command::new("umount").arg(&scratch_mount).status();

        swap_result?;
        Ok(())
    })();

    match result {
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
        }
        Err(e) => {
            eprintln!("ferrum-apply restore-state: {e}");
            let _ = std::fs::write(&storage.failure_marker_path, e.to_string());
            let _ = std::fs::write(
                &storage.result_path,
                serde_json::to_string_pretty(&serde_json::json!({
                    "ok": false,
                    "error": e.to_string(),
                }))
                .unwrap(),
            );
        }
    }

    let _ = std::fs::remove_file(&storage.intent_path);
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
}
