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
    /// `nixos-anywhere` returned successfully. The disk is written and the
    /// host will boot, but NOTHING after that has happened yet -- in
    /// particular the real `hardware-configuration.nix` has not been
    /// transferred. Do not read this as "finished".
    Installed,
    /// The host came back on SSH and its real `hardware-configuration.nix`
    /// is in place.
    ///
    /// This phase exists because of a defect it is the whole fix for.
    /// `Installed` used to be written BEFORE `wait_for_ssh` and the
    /// transfer, both of which lived inside the same `reached < Installed`
    /// block. A run interrupted in that window -- or one whose
    /// `wait_for_ssh` timed out -- recorded `Installed`, and the next run
    /// evaluated `Installed < Installed == false` and skipped the transfer
    /// FOREVER. The staged placeholder (`{ ... }: { }`, a valid empty
    /// module) then stayed as the host's real hardware configuration, so
    /// the install reported success with no `availableKernelModules` and
    /// no microcode. Splitting the phases is what makes the transfer
    /// resumable; recording `Installed` still happens immediately after
    /// `nixos-anywhere` so a resume can never repartition a live disk.
    HardwareConfigured,
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
            // NOT "and booted": this is recorded the instant nixos-anywhere
            // returns, which is before wait_for_ssh has proved anything.
            Phase::Installed => "installed -- not yet confirmed booted",
            Phase::HardwareConfigured => "booted, with its real hardware configuration in place",
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
    /// What the operator consented to publish without authentication, as
    /// the exact sorted app list they were shown when they typed R9 A2's
    /// phrase -- **not a bare boolean**.
    ///
    /// A boolean here was a genuine authorization bypass, and worth
    /// recording why. It lived in `install-state.json`, in the same
    /// operator-writable bind mount as everything else, and it was
    /// unscoped: consent given for `[sonarr]` in one run silently covered
    /// `[sonarr, qbittorrent, sabnzbd]` after an edit to
    /// `settings.stage2.json` between runs -- a file the installer itself
    /// tells the operator is theirs. No forgery required. And forging it
    /// was trivial anyway.
    ///
    /// The list makes consent checkable rather than merely present: the
    /// guard recomputes the open-app set and compares, so consent covers
    /// only what was actually on screen.
    ///
    /// Still recorded here rather than in `settings.stage2.json` because
    /// Nix evaluates that file against the module schema and an
    /// installer-private key would be an unknown option.
    #[serde(default)]
    pub unauthenticated_accepted_for: Vec<String>,
}

/// The installer's own progress record, inside the operator's host
/// directory. Named in the conflict message, so operators are told the
/// exact file to edit rather than a description of it.
pub const STATE_FILE: &str = "install-state.json";

fn path_in(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE)
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
        // A target that changed AFTER the disk was written is not an
        // operator mistake -- it is the normal case, and the old advice
        // here was actively destructive.
        //
        // The install sets the machine's hostname, so it requests a new
        // DHCP lease and comes back on a different address. That happened
        // on the very first real install: saltbox -> ferrum, .46 -> .50.
        // The operator then names the new address, and this said "use
        // --fresh to discard that record" -- which would re-run the
        // destructive step and erase a host that had just installed
        // correctly. The one suggestion offered was the one action that
        // loses the work.
        if prior.phase.is_destructive() {
            return Resume::Conflict(format!(
                "this directory holds an install of {} that reached '{}', and \
                 you named {}.\n\n\
                 If this is the SAME machine on a new address -- which is \
                 normal, because the install changes the hostname and so the \
                 DHCP lease -- update the \"target\" field in \
                 {STATE_FILE} to {} and re-run WITHOUT --fresh. It will pick \
                 up where it left off.\n\n\
                 DO NOT use --fresh to get past this. {} is already \
                 installed; --fresh would erase {} again and start over.",
                prior.target,
                prior.phase.describe(),
                target,
                target,
                prior.target,
                prior.approved_disk
            ));
        }
        return Resume::Conflict(format!(
            "this directory holds an install of {} that reached '{}', but you \
             named {}. Nothing has been erased yet, so --fresh is safe here \
             if you meant to start over; otherwise use a different directory.",
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

/// The phase this run may treat as already reached.
///
/// `None` means "validate everything again". A run that collected answers
/// also regenerated the repository, so the previous run's recorded phase
/// describes content that no longer exists -- and carrying it forward
/// skipped Tier 1 entirely when resuming from exactly `PreflightPassed`,
/// because `PreflightPassed < PreflightPassed` is false.
///
/// Kept beside `needs_disk_confirmation` because the two answer the same
/// question from opposite ends: that one decides whether this run ASKS,
/// this one decides whether what a previous run proved still applies.
pub fn effective_reached(resume: &Resume) -> Option<Phase> {
    match resume {
        Resume::Fresh | Resume::Conflict(_) => None,
        Resume::ContinueAfter(p) if needs_disk_confirmation(resume) => {
            // Re-asked, so re-generated, so nothing is carried forward.
            let _ = p;
            None
        }
        Resume::ContinueAfter(p) => Some(*p),
    }
}

#[cfg(test)]
mod tests {
    /// The IP changing after an install is NORMAL -- the install sets the
    /// hostname, so the machine requests a new DHCP lease and comes back
    /// on a different address. It happened on the first real install
    /// (saltbox -> ferrum, .46 -> .50).
    ///
    /// The advice for that situation must never be --fresh, which would
    /// re-run the destructive step and erase a host that just installed
    /// correctly.
    ///
    /// Mutation check: collapse the two branches back into one message
    /// and this fails.
    #[test]
    fn a_target_that_moved_after_the_wipe_is_never_told_to_use_fresh() {
        for phase in [
            Phase::Installing,
            Phase::Installed,
            Phase::HardwareConfigured,
            Phase::Stage2Applied,
        ] {
            let r = plan(Some(&state(phase)), "root@192.168.2.50", false);
            let Resume::Conflict(msg) = r else {
                panic!("{phase:?}: a different target must not silently continue");
            };
            assert!(
                msg.contains("DO NOT use --fresh"),
                "{phase:?} is past the wipe, so --fresh would erase a live host: {msg}"
            );
            // It must name the file to edit and the safe route.
            assert!(msg.contains(STATE_FILE), "{phase:?}: {msg}");
            assert!(msg.contains("WITHOUT --fresh"), "{phase:?}: {msg}");
            // ...and the new address, so it can be copied.
            assert!(msg.contains("root@192.168.2.50"), "{phase:?}: {msg}");
        }

        // BEFORE the wipe there is nothing to lose, so --fresh is fine and
        // the message may say so.
        for phase in [Phase::Generated, Phase::PreflightPassed] {
            let r = plan(Some(&state(phase)), "root@192.168.2.50", false);
            let Resume::Conflict(msg) = r else {
                panic!("{phase:?}")
            };
            assert!(!msg.contains("DO NOT use --fresh"), "{phase:?}: {msg}");
            assert!(
                msg.contains("Nothing has been erased yet"),
                "{phase:?}: {msg}"
            );
        }
    }

    use super::*;

    fn state(phase: Phase) -> InstallState {
        InstallState {
            phase,
            target: "root@saltbox".into(),
            hostname: "saltbox".into(),
            approved_disk: "/dev/disk/by-id/ata-OS_1".into(),
            unauthenticated_accepted_for: Vec::new(),
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
        assert!(
            err.contains("--fresh"),
            "the escape hatch must be named: {err}"
        );
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
        for phase in [
            Phase::Installing,
            Phase::Installed,
            Phase::HardwareConfigured,
            Phase::Stage2Applied,
        ] {
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

    /// The defect this closes: resuming from `PreflightPassed` re-ran the
    /// interactive flow and regenerated the repository, then skipped Tier 1
    /// because the recorded phase said it had already passed -- for content
    /// that no longer existed. Same shape as the resume that skipped the
    /// authentication backstop.
    /// The regression test for the defect `HardwareConfigured` exists for.
    ///
    /// `Installed` used to be the phase recorded before `wait_for_ssh` and
    /// the hardware-config transfer, all inside one `reached < Installed`
    /// block. A run interrupted in that window recorded `Installed`, and
    /// the next run's `Installed < Installed` was false, so it skipped the
    /// transfer permanently and the host kept the placeholder hardware
    /// configuration -- while reporting success.
    ///
    /// Mutation check: collapse `HardwareConfigured` back into `Installed`
    /// (make them the same phase) and this fails.
    #[test]
    fn a_run_interrupted_after_install_still_has_the_transfer_left_to_do() {
        assert!(
            Phase::Installed < Phase::HardwareConfigured,
            "a state recorded at Installed MUST still be behind the transfer \
             gate, or an interrupted run never transfers the real \
             hardware-configuration.nix and the placeholder becomes the \
             installed host's real hardware config"
        );
        // ...and the transfer still happens before stage 2, which needs a
        // host that evaluates.
        assert!(Phase::HardwareConfigured < Phase::Stage2Applied);
        // The destructive boundary is unmoved: the new phase is past it,
        // so a resume from it can never repartition.
        assert!(Phase::HardwareConfigured.is_destructive());
    }

    /// `Installed` is recorded before anything has proved the host booted,
    /// so its description must not claim it did.
    #[test]
    fn the_installed_phase_does_not_claim_a_boot_it_has_not_seen() {
        // "and booted" was the exact old claim, and it was false: this
        // phase is recorded before wait_for_ssh runs.
        assert!(!Phase::Installed.describe().contains("and booted"));
        assert!(Phase::Installed.describe().contains("not yet confirmed"));
        // The phase that IS recorded after the host answered may say so.
        assert!(Phase::HardwareConfigured.describe().contains("booted"));
    }

    #[test]
    fn a_resume_that_re_asks_carries_no_phase_forward() {
        for phase in [Phase::Generated, Phase::PreflightPassed] {
            let r = plan(Some(&state(phase)), "root@saltbox", false);
            assert!(needs_disk_confirmation(&r), "{phase:?} re-asks");
            assert_eq!(
                effective_reached(&r),
                None,
                "{phase:?}: this run regenerated the repository, so the previous \
                 run's phase is not evidence about this one"
            );
        }
    }

    /// ...but a resume PAST the wipe did not re-ask and did not
    /// regenerate, so its recorded progress still stands.
    #[test]
    fn a_resume_past_the_wipe_keeps_its_progress() {
        for phase in [
            Phase::Installing,
            Phase::Installed,
            Phase::HardwareConfigured,
            Phase::Stage2Applied,
        ] {
            let r = plan(Some(&state(phase)), "root@saltbox", false);
            assert_eq!(effective_reached(&r), Some(phase), "{phase:?}");
        }
    }

    #[test]
    fn a_fresh_run_carries_nothing_forward() {
        assert_eq!(effective_reached(&Resume::Fresh), None);
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
                assert!(
                    m.contains("root@saltbox") && m.contains("root@other"),
                    "{m}"
                );
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

    /// An older record without the field must still load -- and must read
    /// as "no consent given", never as consent.
    #[test]
    fn a_record_without_the_consent_flag_reads_as_no_consent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("install-state.json"),
            r#"{"phase":"Installed","target":"root@h","hostname":"h","approved_disk":"/d"}"#,
        )
        .unwrap();
        let st = read(dir.path()).unwrap().unwrap();
        assert!(
            st.unauthenticated_accepted_for.is_empty(),
            "absence must never mean consent"
        );
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
