use crate::journal::{self, JournalEntry};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq)]
pub enum ApplyResult {
    Succeeded,
    Degraded(String),
    Failed(String),
}

/// Turns switch-to-configuration's exit code plus a post-switch health
/// summary into a classification. See Global Constraints in the plan for
/// what each exit code means: 0 = ok, 2 = activation script failed,
/// 4 = one or more units failed to start/restart.
fn classify(switch_exit_code: i32, all_units_active: bool) -> ApplyResult {
    match switch_exit_code {
        0 if all_units_active => ApplyResult::Succeeded,
        0 => ApplyResult::Degraded(
            "one or more managed units failed to become active".to_string(),
        ),
        2 => ApplyResult::Degraded("activation script failed (exit 2)".to_string()),
        4 => ApplyResult::Degraded(
            "one or more units failed to start or restart (exit 4)".to_string(),
        ),
        other => ApplyResult::Degraded(format!("switch-to-configuration exited {other}")),
    }
}

fn run_ok(cmd: &mut Command) -> anyhow::Result<()> {
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("command failed: {cmd:?}");
    }
    Ok(())
}

fn current_generation() -> anyhow::Result<u32> {
    let target = std::fs::read_link("/nix/var/nix/profiles/system")?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("unexpected profile link target: {target:?}"))?;
    // profile links look like "system-<N>-link"
    let n: u32 = name
        .strip_prefix("system-")
        .and_then(|s| s.strip_suffix("-link"))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("could not parse generation number from {name}"))?;
    Ok(n)
}

fn all_managed_units_active() -> anyhow::Result<bool> {
    let output = Command::new("systemctl")
        .args(["is-active", "ferrum-apps.target"])
        .output()?;
    Ok(output.status.success())
}

pub struct StorageConfig {
    pub state_dir: std::path::PathBuf,
    pub snapshot_dir: std::path::PathBuf,
    pub journal_dir: std::path::PathBuf,
    pub min_free_gib: u64,
}

pub fn run(flake_ref: &str, storage: &StorageConfig) -> anyhow::Result<ApplyResult> {
    // 1. Build (apps still running -- the slow part).
    let build_output = Command::new("nix")
        .args(["build", "--no-link", "--print-out-paths", flake_ref])
        .output()?;
    if !build_output.status.success() {
        return Ok(ApplyResult::Failed(format!(
            "nix build failed: {}",
            String::from_utf8_lossy(&build_output.stderr)
        )));
    }
    let toplevel = String::from_utf8(build_output.stdout)?.trim().to_string();

    let current = current_generation()?;
    if Path::new(&toplevel) == std::fs::read_link("/run/current-system")? {
        return Ok(ApplyResult::Succeeded); // nothing changed
    }

    // 2. Preflight, before touching anything.
    crate::preflight::run(&storage.state_dir, &storage.snapshot_dir, storage.min_free_gib)
        .map_err(|e| anyhow::anyhow!("preflight failed, nothing changed: {e}"))?;

    let generation = current;

    // 3. Stop managed apps -- downtime starts here.
    run_ok(Command::new("systemctl").args(["stop", "ferrum-apps.target"]))?;

    // 4. Snapshot @state.
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let snapshot_name = journal::snapshot_name(ts, generation);
    let snapshot_path = storage.snapshot_dir.join(&snapshot_name);
    run_ok(
        Command::new("btrfs")
            .args(["subvolume", "snapshot", "-r"])
            .arg(&storage.state_dir)
            .arg(&snapshot_path),
    )?;

    let entry = JournalEntry {
        snapshot: snapshot_name.clone(),
        generation,
        toplevel: toplevel.clone(),
        taken_at: chrono_taken_at(),
        quiesced: true,
    };
    journal::write(&storage.journal_dir, &entry)?;

    // 5. Set the profile to the new generation.
    run_ok(
        Command::new("nix-env")
            .args(["-p", "/nix/var/nix/profiles/system", "--set"])
            .arg(&toplevel),
    )?;

    // 6. Activate.
    let switch_status = Command::new(format!("{toplevel}/bin/switch-to-configuration"))
        .arg("switch")
        .status()?;
    let switch_exit_code = switch_status.code().unwrap_or(-1);

    // 7. Restart managed apps -- REQUIRED: switch-to-configuration only
    // restarts units whose closure changed, so anything we stopped in step 3
    // that DIDN'T change would otherwise stay down.
    run_ok(Command::new("systemctl").args(["start", "ferrum-apps.target"]))?;

    let healthy = all_managed_units_active()?;
    Ok(classify(switch_exit_code, healthy))
}

fn chrono_taken_at() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // A minimal RFC3339-ish timestamp without pulling in the `chrono` crate
    // for one call site; precision to the second is enough for a journal.
    format!("{}", now.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_0_with_all_units_active_is_succeeded() {
        assert_eq!(
            classify(0, true),
            ApplyResult::Succeeded
        );
    }

    #[test]
    fn exit_0_with_a_unit_down_is_degraded() {
        assert_eq!(
            classify(0, false),
            ApplyResult::Degraded("one or more managed units failed to become active".to_string())
        );
    }

    #[test]
    fn exit_2_is_degraded_activation() {
        assert_eq!(
            classify(2, true),
            ApplyResult::Degraded("activation script failed (exit 2)".to_string())
        );
    }

    #[test]
    fn exit_4_is_degraded_units() {
        assert_eq!(
            classify(4, true),
            ApplyResult::Degraded("one or more units failed to start or restart (exit 4)".to_string())
        );
    }
}
