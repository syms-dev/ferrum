//! Where this install got to, so a failure after the disk is gone is
//! recoverable (spec R7).
//!
//! Most installers treat the destructive step as the last step. This one
//! cannot: disko runs, then the system is built and switched, then the host
//! boots, then stage 2 enables the apps. Several of those can fail with the
//! target's previous OS already destroyed, and re-running from the top
//! would repartition a disk that is already correct.
//!
//! The phase that matters most is `Installing`. The wipe happens *inside*
//! the `nixos-anywhere` invocation, before it returns, so a crash between
//! those two moments would otherwise leave the disk gone with the record
//! still reading `PreflightPassed` -- an unrecorded destructive action,
//! which is precisely the boundary this file exists to protect.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Phase {
    /// The host repository exists and is committed.
    Generated,
    /// Tier 1 preflight passed. Nothing on the target has been touched.
    PreflightPassed,
    /// `nixos-anywhere` has been STARTED. The disk may already be gone.
    Installing,
    /// `nixos-anywhere` returned successfully.
    Installed,
    /// Stage 2 applied: apps and auth are enabled on the host.
    Stage2Applied,
    /// Post-install verification passed.
    Verified,
}

impl Phase {
    /// Whether reaching this phase means the target's disk may already have
    /// been written to. Everything from `Installing` onward is past the
    /// point of no return.
    pub fn is_destructive(self) -> bool {
        self >= Phase::Installing
    }

    pub fn describe(self) -> &'static str {
        match self {
            Phase::Generated => "host repository generated",
            Phase::PreflightPassed => "preflight passed, target untouched",
            Phase::Installing => "install STARTED -- the disk may already be erased",
            Phase::Installed => "installed and booted",
            Phase::Stage2Applied => "apps and authentication enabled",
            Phase::Verified => "verified",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallState {
    pub phase: Phase,
    pub target: String,
    pub hostname: String,
    /// The by-id path of the disk that was approved for erasure. Recorded
    /// so a resume can tell it is continuing the same install and not a
    /// different one against the same directory.
    pub approved_disk: String,
}

fn path_in(dir: &Path) -> PathBuf {
    dir.join("install-state.json")
}

/// Reads the recorded state, if any.
///
/// # Errors
/// A malformed file is an error, never a silent "start from scratch": the
/// safe reading of an unreadable record is that something already happened.
pub fn read(dir: &Path) -> anyhow::Result<Option<InstallState>> {
    let p = path_in(dir);
    if !p.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&p)?;
    let state: InstallState = serde_json::from_str(&body).map_err(|e| {
        anyhow::anyhow!(
            "{} exists but cannot be read ({e}). Refusing to guess how far a \
             previous install got -- inspect it by hand, or pass --fresh if \
             you are certain the target can be repartitioned.",
            p.display()
        )
    })?;
    Ok(Some(state))
}

/// Records a phase transition atomically.
///
/// Temp file, then rename. A partially written record of a destructive
/// action is worse than no record: the next run reads it, and half a
/// filename's worth of JSON parses as nothing at all.
///
/// # Errors
/// Any filesystem failure.
pub fn write(dir: &Path, state: &InstallState) -> anyhow::Result<()> {
    let p = path_in(dir);
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(state)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

/// Removes the record, for `--fresh`.
///
/// # Errors
/// Any filesystem failure other than the file already being absent.
pub fn clear(dir: &Path) -> anyhow::Result<()> {
    let p = path_in(dir);
    match std::fs::remove_file(&p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// What a run should do given what it found.
#[derive(Debug, PartialEq, Eq)]
pub enum Resume {
    /// No prior state: run everything.
    Fresh,
    /// Continue from after `phase`.
    ContinueAfter(Phase),
    /// A human has to look at this first.
    Conflict(String),
}

/// Decides how to proceed.
///
/// `--fresh` is always explicit and never implied by a stale directory:
/// an implied restart is an implied repartition.
///
/// # Errors
/// None; a problem is returned as `Resume::Conflict` so the caller can
/// print it with the rest of the context.
pub fn plan(prior: Option<&InstallState>, target: &str, fresh: bool) -> Resume {
    let Some(prior) = prior else {
        return Resume::Fresh;
    };
    if fresh {
        return Resume::Fresh;
    }
    if prior.target != target {
        return Resume::Conflict(format!(
            "this directory holds an install of {} that reached '{}', but you \
             named {}. Use a different directory, or --fresh to discard that \
             record.",
            prior.target,
            prior.phase.describe(),
            target
        ));
    }
    if prior.phase == Phase::Verified {
        return Resume::Conflict(format!(
            "{} is already installed and verified. Use --fresh to reinstall it \
             from scratch, which WILL erase {} again.",
            prior.target, prior.approved_disk
        ));
    }
    Resume::ContinueAfter(prior.phase)
}

/// Whether the disk confirmation must be asked again.
///
/// It must not be asked on a resume past `Installing`: the named disk is
/// already gone, so re-confirming protects nothing and only trains the
/// operator to retype a serial without reading it.
pub fn needs_disk_confirmation(resume: &Resume) -> bool {
    match resume {
        Resume::Fresh => true,
        Resume::Conflict(_) => false,
        Resume::ContinueAfter(p) => !p.is_destructive(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(phase: Phase) -> InstallState {
        InstallState {
            phase,
            target: "root@saltbox".into(),
            hostname: "saltbox".into(),
            approved_disk: "/dev/disk/by-id/ata-OS_1".into(),
        }
    }

    #[test]
    fn nothing_recorded_means_a_fresh_run() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read(dir.path()).unwrap().is_none());
        assert_eq!(plan(None, "root@saltbox", false), Resume::Fresh);
    }

    #[test]
    fn a_phase_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &state(Phase::Installed)).unwrap();
        assert_eq!(read(dir.path()).unwrap().unwrap().phase, Phase::Installed);
    }

    /// No `.tmp` may survive a successful write, or the next run sees two
    /// files and no way to tell which is current.
    #[test]
    fn writes_leave_no_temporary_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), &state(Phase::Installing)).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    /// An unreadable record must not be read as "nothing happened". The
    /// safe reading is that something did.
    #[test]
    fn a_corrupt_record_refuses_rather_than_restarting() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("install-state.json"), "{ truncated").unwrap();
        let err = read(dir.path()).unwrap_err().to_string();
        assert!(err.contains("Refusing to guess"), "{err}");
        assert!(err.contains("--fresh"), "the escape hatch must be named: {err}");
    }

    #[test]
    fn a_resume_continues_from_where_it_stopped() {
        assert_eq!(
            plan(Some(&state(Phase::PreflightPassed)), "root@saltbox", false),
            Resume::ContinueAfter(Phase::PreflightPassed)
        );
    }

    /// The property this whole file exists for: after the wipe has STARTED,
    /// a resume must not ask for the serial again.
    #[test]
    fn a_resume_past_the_wipe_does_not_re_ask_for_the_serial() {
        for phase in [Phase::Installing, Phase::Installed, Phase::Stage2Applied] {
            let r = plan(Some(&state(phase)), "root@saltbox", false);
            assert!(
                !needs_disk_confirmation(&r),
                "{phase:?} must not re-confirm: the disk is already gone"
            );
        }
    }

    /// ...but before it, nothing was touched, so it must.
    #[test]
    fn a_resume_before_the_wipe_does_re_ask() {
        for phase in [Phase::Generated, Phase::PreflightPassed] {
            let r = plan(Some(&state(phase)), "root@saltbox", false);
            assert!(needs_disk_confirmation(&r), "{phase:?} touched nothing");
        }
    }

    #[test]
    fn installing_is_the_first_destructive_phase() {
        assert!(!Phase::Generated.is_destructive());
        assert!(!Phase::PreflightPassed.is_destructive());
        assert!(Phase::Installing.is_destructive());
        assert!(Phase::Installed.is_destructive());
    }

    /// A stale directory must never imply a restart -- an implied restart
    /// is an implied repartition.
    #[test]
    fn fresh_is_explicit_and_never_implied() {
        let prior = state(Phase::Installed);
        assert_eq!(plan(Some(&prior), "root@saltbox", true), Resume::Fresh);
        assert_eq!(
            plan(Some(&prior), "root@saltbox", false),
            Resume::ContinueAfter(Phase::Installed),
            "without --fresh this must resume, never restart"
        );
    }

    #[test]
    fn a_different_target_in_the_same_directory_is_a_conflict() {
        let r = plan(Some(&state(Phase::Installed)), "root@other", false);
        match r {
            Resume::Conflict(m) => {
                assert!(m.contains("root@saltbox") && m.contains("root@other"), "{m}");
                assert!(m.contains("--fresh"), "{m}");
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    /// Re-running against a finished install must not quietly reinstall it.
    #[test]
    fn a_finished_install_refuses_to_run_again_by_accident() {
        let r = plan(Some(&state(Phase::Verified)), "root@saltbox", false);
        match r {
            Resume::Conflict(m) => {
                assert!(m.contains("already installed"), "{m}");
                assert!(m.contains("WILL erase"), "the cost must be explicit: {m}");
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn clearing_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        clear(dir.path()).unwrap();
        write(dir.path(), &state(Phase::Generated)).unwrap();
        clear(dir.path()).unwrap();
        assert!(read(dir.path()).unwrap().is_none());
    }
}
