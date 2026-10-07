// SnapRAID parity: the privileged half, and the only place a snapraid
// command is ever run from.
//
// WHY IT IS HERE AND NOT IN ferrumd. `snapraid sync` reads every data disk
// and rewrites a parity file spanning all of them; `snapraid status` opens
// the same raw paths. Those are root operations over the operator's whole
// library, and ferrumd is deliberately unprivileged -- the same invariant
// generations.rs records for not shelling out to `nix-env`, and the one the
// updates work restated for `nix`. ferrumd's entire part in parity is to
// serve the document a run of this code produced.
//
// The split inside this file is the testable/untestable one. Everything that
// DECIDES something -- whether parity is configured, what a unit's state
// means -- is a pure function over strings, exercised by the tests at the
// bottom. The only impure part is the `CommandRunner` call, which is the
// same seam update_check.rs already uses so that neither needs a second one.
use std::path::{Path, PathBuf};

use crate::update_check::CommandRunner;

/// The systemd unit nixpkgs' `services.snapraid` generates for a sync, and
/// the one `modules/core/parity.nix` re-times.
///
/// Starting THIS rather than running `snapraid sync` directly is deliberate
/// reuse: the generated unit already carries `ProtectSystem = "strict"`, a
/// `ReadWritePaths` list computed from the configured disks, a capability
/// bounding set of `CAP_DAC_OVERRIDE` (plus `CAP_FOWNER` for the pre-sync
/// touch), and the idle I/O class ferrum adds. A direct invocation would run
/// with none of that, and would be a second answer to "what may a sync
/// touch" free to drift from the first.
pub const SYNC_UNIT: &str = "snapraid-sync.service";

/// Where nixpkgs' `services.snapraid` renders its configuration.
///
/// Its existence is ferrum's "is parity configured on this host" predicate,
/// and that is a deliberate choice of signal: the file is written if and
/// only if `services.snapraid.enable` is on, so it cannot disagree with the
/// units. Reading `ferrum.storage.parity.enable` out of settings.json would
/// be a second authority, and the one that is NOT what systemd acted on.
pub const SNAPRAID_CONF: &str = "/etc/snapraid.conf";

/// What a manual sync request turned into.
///
/// `NotConfigured` is a distinct value from `Failed` on purpose. "There is
/// no parity on this host" and "parity exists and the sync broke" are
/// different facts about the library, and collapsing them is the same
/// defect the update check's `CheckFailed`/`UpToDate` split exists to
/// prevent -- an unreachable check must never read like a clean result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcome {
    /// `/etc/snapraid.conf` does not exist, so no sync can be started.
    NotConfigured,
    /// systemd accepted the job and the unit ran to completion successfully.
    Completed,
    /// systemd could not be reached at all (binary missing, no D-Bus).
    Unreachable(String),
    /// The unit ran and failed, or systemd refused the job.
    Failed(String),
}

impl SyncOutcome {
    /// The process exit code this outcome should produce.
    ///
    /// # Returns
    /// `0` only for [`SyncOutcome::Completed`]. Every other variant is a
    /// non-zero code so that a caller which checks nothing but `$?` -- a
    /// shell script, a systemd `ExecStart`, the job runner -- still sees a
    /// failure rather than silence.
    pub fn exit_code(&self) -> i32 {
        match self {
            SyncOutcome::Completed => 0,
            SyncOutcome::NotConfigured => 2,
            SyncOutcome::Unreachable(_) => 3,
            SyncOutcome::Failed(_) => 1,
        }
    }

    /// A single line naming what happened, for stdout and the progress log.
    ///
    /// # Returns
    /// Human-readable text. Never contains a path outside the two constants
    /// above, so it is safe to log.
    pub fn summary(&self) -> String {
        match self {
            SyncOutcome::Completed => "parity sync completed".to_string(),
            SyncOutcome::NotConfigured => format!(
                "parity is not configured on this host ({SNAPRAID_CONF} does not exist), \
                 so there is nothing to sync. Set ferrum.storage.parity.enable and name a \
                 parity disk first."
            ),
            SyncOutcome::Unreachable(e) => {
                format!("could not ask systemd to start {SYNC_UNIT}: {e}")
            }
            SyncOutcome::Failed(e) => format!("{SYNC_UNIT} did not complete: {e}"),
        }
    }
}

/// Is parity configured on this host?
///
/// # Arguments
/// * `conf` - the path to check, normally [`SNAPRAID_CONF`]. Taken as an
///   argument rather than read from the constant so the tests can exercise
///   both answers without touching `/etc`.
///
/// # Returns
/// `true` when the generated snapraid configuration exists.
pub fn is_configured(conf: &Path) -> bool {
    conf.exists()
}

/// Starts a sync by hand, whatever the timer is doing.
///
/// R3's manual trigger. Independent of `systemd.timers.snapraid-sync` by
/// construction: `systemctl start` acts on the SERVICE, which exists
/// whenever parity is configured, while the timer is what
/// `ferrum.storage.parity.sync.enable` turns off. An operator who runs
/// fully manually therefore has exactly this, and it behaves identically to
/// the scheduled path because it starts the same unit.
///
/// `--wait` so that the exit code of this process reflects the sync rather
/// than only the request to start it. A fire-and-forget start would report
/// success for a sync that failed thirty seconds later, which is the
/// frozen-gauge failure this feature exists to avoid reproducing.
///
/// A second concurrent start is not a failure here: systemd's own job
/// handling collapses it onto the running job for a `Type=oneshot` unit, so
/// `--wait` simply returns when that one finishes.
///
/// # Arguments
/// * `conf` - the snapraid configuration path to test for existence.
/// * `runner` - the command seam; [`crate::update_check::RealRunner`] in
///   production.
///
/// # Returns
/// The outcome, which the caller turns into an exit code and a log line.
pub fn start_sync(conf: &Path, runner: &dyn CommandRunner) -> SyncOutcome {
    if !is_configured(conf) {
        return SyncOutcome::NotConfigured;
    }
    let args = vec![
        "start".to_string(),
        "--wait".to_string(),
        SYNC_UNIT.to_string(),
    ];
    match runner.run("systemctl", &args) {
        Err(e) => SyncOutcome::Unreachable(e),
        Ok(out) if out.success => SyncOutcome::Completed,
        Ok(out) => {
            let detail = if out.stderr.trim().is_empty() {
                out.stdout.trim().to_string()
            } else {
                out.stderr.trim().to_string()
            };
            SyncOutcome::Failed(if detail.is_empty() {
                "systemctl reported a failure with no message".to_string()
            } else {
                detail
            })
        }
    }
}

/// The snapraid configuration path this host should use.
///
/// `FERRUM_SNAPRAID_CONF` first so a test host (or a VM test) can point at a
/// fixture without `/etc` being writable; [`SNAPRAID_CONF`] otherwise.
///
/// # Returns
/// The path to read. Never fails: the fallback is a constant.
pub fn conf_path() -> PathBuf {
    std::env::var("FERRUM_SNAPRAID_CONF")
        .unwrap_or_else(|_| SNAPRAID_CONF.to_string())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_check::CommandOutput;
    use std::cell::RefCell;

    /// Records what it was asked to run and replies with a scripted result.
    struct FakeRunner {
        reply: Result<CommandOutput, String>,
        calls: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl FakeRunner {
        fn ok() -> Self {
            Self::with(Ok(CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }))
        }
        fn with(reply: Result<CommandOutput, String>) -> Self {
            Self { reply, calls: RefCell::new(Vec::new()) }
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String> {
            self.calls
                .borrow_mut()
                .push((program.to_string(), args.to_vec()));
            match &self.reply {
                Ok(o) => Ok(o.clone()),
                Err(e) => Err(e.clone()),
            }
        }
    }

    fn existing_conf() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("snapraid.conf");
        std::fs::write(&p, "data d0 /mnt/a\n").unwrap();
        (dir, p)
    }

    /// A host with no parity must say so, and must not spawn anything.
    ///
    /// The "must not spawn" half is the load-bearing one: without it this
    /// passes identically on an implementation that runs systemctl first and
    /// interprets the failure as "not configured", which would report the
    /// same word for a broken systemd.
    #[test]
    fn a_host_without_parity_reports_not_configured_and_runs_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let runner = FakeRunner::ok();
        let outcome = start_sync(&dir.path().join("absent.conf"), &runner);
        assert_eq!(outcome, SyncOutcome::NotConfigured);
        assert!(runner.calls.borrow().is_empty(), "it spawned something");
        assert_ne!(outcome.exit_code(), 0);
    }

    /// The manual trigger starts the SERVICE, not the timer -- which is what
    /// makes it work on a host where the timer is disabled.
    #[test]
    fn the_manual_trigger_starts_the_service_and_waits_for_it() {
        let (_d, conf) = existing_conf();
        let runner = FakeRunner::ok();
        assert_eq!(start_sync(&conf, &runner), SyncOutcome::Completed);

        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "systemctl");
        assert_eq!(
            calls[0].1,
            vec!["start".to_string(), "--wait".to_string(), SYNC_UNIT.to_string()],
        );
        assert!(
            !calls[0].1.iter().any(|a| a.ends_with(".timer")),
            "the manual trigger must not depend on the timer: {:?}",
            calls[0].1
        );
    }

    /// A unit that ran and failed is distinguishable from a systemd that
    /// could not be reached at all, and both from "no parity here".
    #[test]
    fn every_failure_mode_is_its_own_outcome_and_its_own_exit_code() {
        let (_d, conf) = existing_conf();

        let failed = start_sync(
            &conf,
            &FakeRunner::with(Ok(CommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "Job for snapraid-sync.service failed".into(),
            })),
        );
        assert!(matches!(failed, SyncOutcome::Failed(_)));
        assert!(failed.summary().contains("did not complete"));

        let unreachable = start_sync(
            &conf,
            &FakeRunner::with(Err("failed to run systemctl: No such file".into())),
        );
        assert!(matches!(unreachable, SyncOutcome::Unreachable(_)));

        let codes = [
            SyncOutcome::Completed.exit_code(),
            SyncOutcome::NotConfigured.exit_code(),
            SyncOutcome::Unreachable(String::new()).exit_code(),
            SyncOutcome::Failed(String::new()).exit_code(),
        ];
        assert_eq!(codes[0], 0);
        let mut distinct = codes.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            codes.len(),
            "two outcomes share an exit code, so a caller cannot tell them apart: {codes:?}"
        );
    }

    /// A failure with nothing on either stream still produces a message.
    /// Silence here would read, in the journal, as a sync that said nothing.
    #[test]
    fn a_silent_failure_still_says_something() {
        let (_d, conf) = existing_conf();
        let outcome = start_sync(
            &conf,
            &FakeRunner::with(Ok(CommandOutput {
                success: false,
                stdout: "   ".into(),
                stderr: String::new(),
            })),
        );
        match outcome {
            SyncOutcome::Failed(d) => assert!(!d.is_empty()),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn the_conf_path_is_overridable_for_tests_and_defaults_to_etc() {
        assert_eq!(SNAPRAID_CONF, "/etc/snapraid.conf");
        let (_d, conf) = existing_conf();
        assert!(is_configured(&conf));
        assert!(!is_configured(Path::new("/nonexistent/snapraid.conf")));
    }
}
