use ferrum_state::journal::{self, JournalEntry};
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
/// Turns the switch's exit code and the post-settle health into a verdict.
///
/// Exit 4 means "a unit failed to start or restart" AT THE MOMENT THE
/// SWITCH FINISHED, which is not the same as a unit that is broken. A
/// service with Restart=on-failure that exits non-zero once and succeeds
/// on its next attempt is reported as failed by switch-to-configuration
/// and is perfectly healthy thirty seconds later.
///
/// ferrum-reconcile does exactly that on every apply: it races the apps it
/// registers, exits 1 when they are not listening yet, and succeeds on the
/// retry. Five consecutive applies on a working host reported
/// "apply degraded" about a service that had already fixed itself -- and a
/// warning that is usually wrong is how a real one gets ignored.
///
/// So exit 4 defers to the health check, which polls until the units
/// settle. A unit that is still not active when that times out is a real
/// failure and is still reported.
///
/// # Arguments
/// * `switch_exit_code` - what switch-to-configuration returned.
/// * `all_units_active` - whether the managed units are active AFTER the
///   settle window, not at the instant the switch returned.
fn classify(switch_exit_code: i32, all_units_active: bool) -> ApplyResult {
    match switch_exit_code {
        0 if all_units_active => ApplyResult::Succeeded,
        0 => ApplyResult::Degraded(
            "one or more managed units failed to become active".to_string(),
        ),
        // The activation SCRIPT failing is not a restart race -- nothing
        // retries it, so this stays immediate.
        2 => ApplyResult::Degraded("activation script failed (exit 2)".to_string()),
        4 if all_units_active => ApplyResult::Succeeded,
        4 => ApplyResult::Degraded(
            "one or more units failed to start or restart, and were still not \
             active after the health-check window (exit 4)"
                .to_string(),
        ),
        other => ApplyResult::Degraded(format!("switch-to-configuration exited {other}")),
    }
}

/// Folds the DNS reconcile step's outcome into the switch's own verdict
/// (decision D-08).
///
/// DNS runs as a step inside this binary rather than as its own systemd unit
/// precisely so its failures arrive here with a per-record breakdown intact,
/// instead of being absorbed by `all_managed_units_active()`'s single
/// boolean. A record that could not be created is a published app that
/// nobody can reach, which is the failure R1 exists to fix -- so it degrades
/// the apply even when the switch and the health check were both clean.
///
/// # Arguments
/// * `base` - the verdict `classify` produced from the switch.
/// * `dns` - `None` when there is nothing to report, or the breakdown.
///
/// # Returns
/// `base` unchanged when DNS is clean. Otherwise `Degraded`, with the DNS
/// reason appended to any reason `base` already carried -- a failing switch
/// and a failing DNS reconcile are two facts and the operator needs both.
/// `Failed` is left alone: an apply that never got as far as switching is
/// not degraded *by DNS*, and relabelling it would hide the real cause.
fn fold_dns_outcome(base: ApplyResult, dns: Option<String>) -> ApplyResult {
    let Some(reason) = dns else {
        return base;
    };
    match base {
        ApplyResult::Succeeded => ApplyResult::Degraded(reason),
        ApplyResult::Degraded(existing) => ApplyResult::Degraded(format!("{existing}; {reason}")),
        ApplyResult::Failed(existing) => ApplyResult::Failed(existing),
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
    pub auth_enabled: bool,
    pub authelia_state_dir: PathBuf,
    pub admin_email: String,
    pub sabnzbd_state_dir: Option<PathBuf>,
    pub sabnzbd_port: u16,
}

/// Names the `ApplyResult` variant without its payload, for the terminal
/// progress line. Deliberately not `Debug`: the payload can be a whole
/// nix-build stderr dump, and the `complete` line carries the detail
/// separately.
fn result_name(result: &ApplyResult) -> &'static str {
    match result {
        ApplyResult::Succeeded => "succeeded",
        ApplyResult::Degraded(_) => "degraded",
        ApplyResult::Failed(_) => "failed",
    }
}

fn result_detail(result: &ApplyResult) -> String {
    match result {
        ApplyResult::Succeeded => String::new(),
        ApplyResult::Degraded(reason) | ApplyResult::Failed(reason) => reason.clone(),
    }
}

/// Purely additive instrumentation wrapper: runs the real `run_inner`
/// below and writes the terminal `complete` progress line for it,
/// including on the error path (an early `?` inside `run_inner` would
/// otherwise leave a job's progress file with no terminal line at all, and
/// ferrumd's SSE handler would tail it forever).
pub fn run(flake_ref: &str, storage: &StorageConfig) -> anyhow::Result<ApplyResult> {
    let mut progress = crate::progress::Progress::open();
    let outcome = run_inner(flake_ref, storage, &mut progress);
    match &outcome {
        Ok(result) => progress.complete(result_name(result), &result_detail(result)),
        Err(e) => progress.complete("error", &e.to_string()),
    }
    outcome
}

fn run_inner(
    flake_ref: &str,
    storage: &StorageConfig,
    progress: &mut crate::progress::Progress,
) -> anyhow::Result<ApplyResult> {
    // 0. Ensure every enabled servarr app has its API-key secret, and (if
    // auth is enabled) Authelia's own required secrets and first user,
    // BEFORE build -- same reasoning as the servarr keys: sops.validateSopsFiles
    // checks file existence at Nix EVAL time, inside the build step right
    // after this.
    progress.event("secrets", "ensuring generated secrets exist");
    let servarr_refs: Vec<&str> = storage.servarr_apps.iter().map(String::as_str).collect();
    crate::secrets::ensure_all(&storage.secrets_dir, &storage.host_key_pub, &servarr_refs)?;
    if storage.auth_enabled {
        crate::secrets::ensure_authelia_secrets(&storage.secrets_dir, &storage.host_key_pub)?;
        crate::secrets::ensure_first_authelia_user(&storage.authelia_state_dir, &storage.admin_email)?;
    }
    if let Some(sabnzbd_state_dir) = &storage.sabnzbd_state_dir {
        crate::secrets::ensure_sabnzbd_apikey(
            sabnzbd_state_dir,
            &storage.secrets_dir,
            &storage.host_key_pub,
            storage.sabnzbd_port,
        )?;
    }

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
    progress.event("build", "building the new system closure");
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
        progress.event("health-check", "already on the target closure; checking health only");
        let healthy = classify(0, wait_for_healthy(storage.health_check_timeout)?);
        // DNS is reconciled here too, and that is load-bearing rather than
        // symmetric: an apply whose records failed (a refused token, an
        // unreachable API) leaves the closure unchanged, so the operator's
        // retry after fixing the credential lands on exactly this path. If
        // it skipped reconciliation there would be no way to converge
        // without an unrelated configuration change.
        let dns = crate::dns_reconcile::reconcile_for_apply(&toplevel, progress);
        return Ok(fold_dns_outcome(healthy, dns));
    }

    // 2. Preflight, before touching anything.
    progress.event("preflight", "checking free space and snapshot subvolumes");
    crate::preflight::run(
        &storage.state_dir,
        &storage.snapshot_dir,
        storage.min_free_gib,
        &storage.failure_marker_path,
    )
    .map_err(|e| anyhow::anyhow!("preflight failed, nothing changed: {e}"))?;

    // 3. Stop managed apps -- downtime starts here.
    progress.event("stop-apps", "stopping ferrum-apps.target (downtime starts)");
    run_ok(Command::new("systemctl").args(["stop", "ferrum-apps.target"]))?;

    // Everything between the stop above and the restart below MUST leave
    // apps restarted no matter how it fails -- snapshot, journal write,
    // nix-env --set, and the switch itself are all fallible, and a bare `?`
    // on any of them would return out of `run` early and leave
    // ferrum-apps.target stopped forever. So the fallible sequence is
    // isolated in a closure whose error we inspect AFTER the unconditional
    // restart below, not before.
    let mut inner = || -> anyhow::Result<i32> {
        // 4. Snapshot @state.
        progress.event("snapshot", "snapshotting @state");
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
        progress.event("set-profile", "pointing the system profile at the new closure");
        run_ok(
            Command::new("nix-env")
                .args(["-p", "/nix/var/nix/profiles/system", "--set"])
                .arg(&toplevel),
        )?;

        // 6. Activate.
        progress.event("switch", "running switch-to-configuration switch");
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
    progress.event("start-apps", "restarting ferrum-apps.target");
    run_ok(Command::new("systemctl").args(["start", "ferrum-apps.target"]))?;

    let switch_exit_code = inner_result.map_err(|e| {
        anyhow::anyhow!("apply failed mid-sequence (apps have been restarted): {e}")
    })?;

    progress.event("health-check", "waiting for every managed unit to become active");
    let healthy = wait_for_healthy(storage.health_check_timeout)?;

    // 8. Reconcile the DNS records the new closure publishes (R1, D-08).
    // After the switch, so the document read is the one this generation
    // activated; after the health check, so a host that cannot serve its
    // apps is not also told its records are wrong. Deliberately not `?`:
    // Cloudflare being unreachable must degrade the verdict, never turn a
    // completed switch into an apply error.
    let dns = crate::dns_reconcile::reconcile_for_apply(&toplevel, progress);
    Ok(fold_dns_outcome(classify(switch_exit_code, healthy), dns))
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

    /// Exit 4 with everything healthy AFTER the settle window is a
    /// success, not a degradation.
    ///
    /// switch-to-configuration reports exit 4 for a unit that failed at
    /// the instant it finished. ferrum-reconcile does that on every apply
    /// -- it races the apps it registers, exits 1, and succeeds on the
    /// retry seconds later. Five consecutive applies on a healthy host
    /// said "apply degraded" about a service that had already fixed
    /// itself.
    ///
    /// Mutation check: return Degraded for exit 4 regardless and this
    /// fails.
    #[test]
    fn exit_4_that_settles_is_not_degraded() {
        assert_eq!(classify(4, true), ApplyResult::Succeeded);
    }

    /// ...but a unit still down after the window is a real failure, and
    /// the message says the window was given.
    #[test]
    fn exit_4_that_does_not_settle_is_still_degraded() {
        let ApplyResult::Degraded(reason) = classify(4, false) else {
            panic!("a unit that never came up must be reported");
        };
        assert!(reason.contains("still not active"), "{reason}");
        assert!(reason.contains("exit 4"), "{reason}");
    }

    /// An activation SCRIPT failure is not a restart race -- nothing
    /// retries it -- so it must not be softened by the same rule.
    #[test]
    fn exit_2_is_never_softened_by_the_settle_check() {
        assert!(matches!(classify(2, true), ApplyResult::Degraded(_)));
    }

    #[test]
    fn negative_exit_code_is_degraded_with_code_shown() {
        assert_eq!(
            classify(-1, true),
            ApplyResult::Degraded("switch-to-configuration exited -1".to_string())
        );
    }

    /// D-08. A switch and a health check that both passed do not make the
    /// apply a success if the records nobody can reach were never created --
    /// that is precisely the shape of the incident R1 exists to fix.
    ///
    /// Mutation check: return `base` unchanged whatever `dns` says and this
    /// fails.
    #[test]
    fn a_clean_switch_with_a_failed_record_is_degraded_not_succeeded() {
        assert_eq!(
            fold_dns_outcome(
                ApplyResult::Succeeded,
                Some("1 of 2 DNS record(s) could not be reconciled: auth.example.com (create): refused".to_string()),
            ),
            ApplyResult::Degraded(
                "1 of 2 DNS record(s) could not be reconciled: auth.example.com (create): refused"
                    .to_string()
            )
        );
    }

    #[test]
    fn a_clean_reconcile_leaves_the_switchs_own_verdict_alone() {
        assert_eq!(
            fold_dns_outcome(ApplyResult::Succeeded, None),
            ApplyResult::Succeeded
        );
        assert_eq!(
            fold_dns_outcome(ApplyResult::Degraded("a unit is down".to_string()), None),
            ApplyResult::Degraded("a unit is down".to_string())
        );
    }

    /// Two failures are two facts. Collapsing them would leave whichever one
    /// the operator did not see unfixed.
    #[test]
    fn a_degraded_switch_and_a_failed_record_report_both_causes() {
        let ApplyResult::Degraded(reason) = fold_dns_outcome(
            ApplyResult::Degraded("a unit is down".to_string()),
            Some("auth.example.com (create): refused".to_string()),
        ) else {
            panic!("two failures must still be a degradation");
        };
        assert!(reason.contains("a unit is down"), "{reason}");
        assert!(reason.contains("auth.example.com"), "{reason}");
    }

    /// A build that never switched is not degraded *by DNS*; relabelling it
    /// would bury the real cause.
    #[test]
    fn a_failed_apply_keeps_its_own_cause() {
        assert_eq!(
            fold_dns_outcome(
                ApplyResult::Failed("nix build failed".to_string()),
                Some("auth.example.com (create): refused".to_string()),
            ),
            ApplyResult::Failed("nix build failed".to_string())
        );
    }

    #[test]
    fn wait_for_healthy_returns_true_immediately_when_already_healthy() {
        let mut calls = 0;
        let result = wait_for_healthy_with(Duration::from_secs(10), Duration::from_millis(1), || {
            calls += 1;
            Ok(true)
        });
        assert!(result.unwrap());
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
        assert!(result.unwrap());
    }

    #[test]
    fn wait_for_healthy_gives_up_and_returns_false_after_the_timeout() {
        let result = wait_for_healthy_with(Duration::from_millis(20), Duration::from_millis(5), || {
            Ok(false)
        });
        assert!(!result.unwrap());
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
