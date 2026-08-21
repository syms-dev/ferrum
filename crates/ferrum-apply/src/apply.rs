use crate::journal::{self, JournalEntry};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
        anyhow::bail!("command failed ({status}): {cmd:?}");
    }
    Ok(())
}

/// Finds the generation number and store path that are *actually* running,
/// by scanning `/nix/var/nix/profiles/system-*-link` for the entry whose
/// target matches `/run/current-system`. We deliberately don't trust
/// `/nix/var/nix/profiles/system`'s own pointer: if a prior apply partially
/// failed (e.g. `nix-env --set` ran but the switch itself never completed),
/// the profile can point at a generation that was never actually activated.
/// `/run/current-system` is the source of truth for what's running, but it's
/// a plain symlink to a store path -- it doesn't encode a generation number
/// itself, hence the scan.
pub(crate) fn current_generation() -> anyhow::Result<(u32, PathBuf)> {
    let running_target = std::fs::read_link("/run/current-system")
        .map_err(|e| anyhow::anyhow!("failed to read /run/current-system: {e}"))?;

    let profiles_dir = Path::new("/nix/var/nix/profiles");
    for entry in std::fs::read_dir(profiles_dir)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Some(n) = name
            .strip_prefix("system-")
            .and_then(|s| s.strip_suffix("-link"))
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if std::fs::read_link(entry.path())? == running_target {
            return Ok((n, running_target));
        }
    }
    anyhow::bail!(
        "no profile generation under {} matches the running system ({}); /run/current-system may point at an unactivated generation",
        profiles_dir.display(),
        running_target.display()
    )
}

/// Checks that every unit `ferrum-apps.target` pulls in is actually active,
/// not just the target itself. Apps are wired up with `wantedBy`/`partOf`
/// (see modules/apps/*/service.nix), not `Requires=`/`BindsTo=`, so a failed
/// app does NOT make `systemctl is-active ferrum-apps.target` report
/// inactive -- checking the target alone would make a fully-dead system
/// after a switch still look healthy.
fn all_managed_units_active() -> anyhow::Result<bool> {
    let list_output = Command::new("systemctl")
        .args([
            "list-dependencies",
            "--plain",
            "--no-legend",
            "ferrum-apps.target",
        ])
        .output()?;
    if !list_output.status.success() {
        anyhow::bail!(
            "failed to list ferrum-apps.target's dependencies: {}",
            String::from_utf8_lossy(&list_output.stderr)
        );
    }
    let units: Vec<String> = String::from_utf8_lossy(&list_output.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    for unit in &units {
        let status = Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .status()?;
        if !status.success() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Polls `check` until it reports healthy or `timeout` elapses, sleeping
/// `poll_interval` between attempts. A slow-starting app (Sonarr can take
/// tens of seconds to become genuinely usable) checked exactly once,
/// immediately after `systemctl start` returns, would be misclassified as
/// Degraded far more often than the app is actually unhealthy --
/// `systemctl start` returns as soon as jobs complete, which for a simple
/// service is the moment the process is forked, not when it's actually up.
fn wait_for_healthy_with<F: FnMut() -> anyhow::Result<bool>>(
    timeout: Duration,
    poll_interval: Duration,
    mut check: F,
) -> anyhow::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if check()? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        std::thread::sleep(poll_interval);
    }
}

fn wait_for_healthy(timeout: Duration) -> anyhow::Result<bool> {
    wait_for_healthy_with(timeout, Duration::from_millis(500), all_managed_units_active)
}

pub struct StorageConfig {
    pub state_dir: std::path::PathBuf,
    pub snapshot_dir: std::path::PathBuf,
    pub journal_dir: std::path::PathBuf,
    pub min_free_gib: u64,
    pub failure_marker_path: std::path::PathBuf,
    pub health_check_timeout: Duration,
    pub secrets_dir: PathBuf,
    pub servarr_apps: Vec<String>,
    pub host_key_pub: PathBuf,
}

pub fn run(flake_ref: &str, storage: &StorageConfig) -> anyhow::Result<ApplyResult> {
    // 0. Ensure every enabled servarr app has its API-key secret, BEFORE
    // build -- their environmentFiles reference the decrypted path
    // statically, and sops.validateSopsFiles (on by default) checks the
    // .sops file exists at Nix EVAL time, which happens inside the build
    // step right after this. ensure_all only reads storage.host_key_pub
    // (and shells out to ssh-to-age/sops) when something is actually
    // missing, so a host with every key already generated -- or with no
    // servarr apps enabled at all -- never depends on the host key here.
    let servarr_refs: Vec<&str> = storage.servarr_apps.iter().map(String::as_str).collect();
    crate::secrets::ensure_all(&storage.secrets_dir, &storage.host_key_pub, &servarr_refs)?;

    // 1. Build (apps still running -- the slow part).
    //
    // --impure is required, not optional: sops.secrets.<name>.sopsFile
    // (constructed from ferrum.secretsDir, e.g. /etc/ferrum/secrets/...)
    // is genuine Nix path-typed data referencing a location outside any
    // flake's own hermetic source tree (the code constructing it lives in
    // ferrum's own flake, fetched as an input to /etc/ferrum's flake --
    // paths across that boundary are never accessible under Nix's default
    // pure evaluation, confirmed for real on ferrum-dev: the identical
    // eval fails with "access to absolute path ... is forbidden in pure
    // evaluation mode" without --impure, and succeeds cleanly with it).
    //
    // Note this disables the purity sandbox for the WHOLE build, not just
    // this one path -- any other impure builtin (currentTime, getEnv, an
    // arbitrary absolute-path read introduced elsewhere in the module
    // tree) would now silently succeed here instead of failing fast.
    // checks.eval-example-hosts (the CI-facing check) never runs with
    // --impure, so it stays a real guard against accidental impurity
    // everywhere except this one specific, already-audited case.
    let build_output = Command::new("nix")
        .args(["build", "--impure", "--no-link", "--print-out-paths", flake_ref])
        .output()?;
    if !build_output.status.success() {
        return Ok(ApplyResult::Failed(format!(
            "nix build failed: {}",
            String::from_utf8_lossy(&build_output.stderr)
        )));
    }
    let toplevel = String::from_utf8(build_output.stdout)?.trim().to_string();

    let (current, running_toplevel) = current_generation()?;
    if Path::new(&toplevel) == running_toplevel {
        // Nothing to switch. But a *prior* apply may have left the system
        // degraded (e.g. an app crashed after activation) -- report real
        // health instead of a bare, potentially-false "succeeded".
        return Ok(classify(0, wait_for_healthy(storage.health_check_timeout)?));
    }

    // 2. Preflight, before touching anything.
    crate::preflight::run(
        &storage.state_dir,
        &storage.snapshot_dir,
        storage.min_free_gib,
        &storage.failure_marker_path,
    )
    .map_err(|e| anyhow::anyhow!("preflight failed, nothing changed: {e}"))?;

    // 3. Stop managed apps -- downtime starts here.
    run_ok(Command::new("systemctl").args(["stop", "ferrum-apps.target"]))?;

    // Everything between the stop above and the restart below MUST leave
    // apps restarted no matter how it fails -- snapshot, journal write,
    // nix-env --set, and the switch itself are all fallible, and a bare `?`
    // on any of them would return out of `run` early and leave
    // ferrum-apps.target stopped forever. So the fallible sequence is
    // isolated in a closure whose error we inspect AFTER the unconditional
    // restart below, not before.
    let inner = || -> anyhow::Result<i32> {
        // 4. Snapshot @state.
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let snapshot_name = journal::snapshot_name(ts, current);
        let snapshot_path = storage.snapshot_dir.join(&snapshot_name);
        run_ok(
            Command::new("btrfs")
                .args(["subvolume", "snapshot", "-r"])
                .arg(&storage.state_dir)
                .arg(&snapshot_path),
        )?;

        let entry = JournalEntry {
            snapshot: snapshot_name.clone(),
            generation: current,
            toplevel: running_toplevel.display().to_string(),
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
        Ok(switch_status.code().unwrap_or(-1))
    };

    let inner_result = inner();

    // 7. Restart managed apps -- REQUIRED and UNCONDITIONAL: switch-to-configuration
    // only restarts units whose closure changed, so anything we stopped in
    // step 3 that DIDN'T change would otherwise stay down. This must run
    // regardless of whether `inner` above succeeded, which is why we don't
    // propagate its error until after this line. If systemctl itself can't
    // be reached, that's a distinct, real problem worth surfacing loudly via
    // `?` rather than swallowing.
    run_ok(Command::new("systemctl").args(["start", "ferrum-apps.target"]))?;

    let switch_exit_code = inner_result.map_err(|e| {
        anyhow::anyhow!("apply failed mid-sequence (apps have been restarted): {e}")
    })?;

    let healthy = wait_for_healthy(storage.health_check_timeout)?;
    Ok(classify(switch_exit_code, healthy))
}

/// Unix-seconds-as-a-string, e.g. "1770000000". Not RFC3339 -- deliberately
/// avoids pulling in the `chrono` crate for one call site, and this format
/// is what Task 8's VM test fixture expects, so keep it as-is.
fn chrono_taken_at() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{}", now.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_0_with_all_units_active_is_succeeded() {
        assert_eq!(classify(0, true), ApplyResult::Succeeded);
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

    #[test]
    fn negative_exit_code_is_degraded_with_code_shown() {
        assert_eq!(
            classify(-1, true),
            ApplyResult::Degraded("switch-to-configuration exited -1".to_string())
        );
    }

    #[test]
    fn wait_for_healthy_returns_true_immediately_when_already_healthy() {
        let mut calls = 0;
        let result = wait_for_healthy_with(Duration::from_secs(10), Duration::from_millis(1), || {
            calls += 1;
            Ok(true)
        });
        assert_eq!(result.unwrap(), true);
        assert_eq!(calls, 1, "must not poll again once healthy");
    }

    #[test]
    fn wait_for_healthy_polls_until_healthy_within_the_timeout() {
        let mut calls_remaining_unhealthy = 2;
        let result = wait_for_healthy_with(Duration::from_secs(10), Duration::from_millis(1), || {
            if calls_remaining_unhealthy > 0 {
                calls_remaining_unhealthy -= 1;
                Ok(false)
            } else {
                Ok(true)
            }
        });
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn wait_for_healthy_gives_up_and_returns_false_after_the_timeout() {
        let result = wait_for_healthy_with(Duration::from_millis(20), Duration::from_millis(5), || {
            Ok(false)
        });
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn wait_for_healthy_propagates_a_check_error_immediately() {
        let result: anyhow::Result<bool> =
            wait_for_healthy_with(Duration::from_secs(10), Duration::from_millis(1), || {
                anyhow::bail!("systemctl unreachable")
            });
        assert!(result.is_err());
    }
}
