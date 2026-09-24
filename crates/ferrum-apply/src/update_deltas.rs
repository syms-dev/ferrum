// Per-app version deltas: what each enabled app's version would become
// under the candidate revision.
//
// The evaluation is of the host's FULLY RESOLVED configuration with the
// ferrum input overridden -- not of a catalog lookup. That distinction is
// the whole of R1's `custom/` edge case: an operator who pinned
// `services.sonarr.package = pkgs.sonarr_3;` in /etc/ferrum/custom/ has an
// app the pin change does not move, and a catalog-only lookup would flag it
// as changing when it does not. Evaluating the real configuration gets that
// right for free, because `custom/` is already part of what is being
// evaluated.
//
// One `nix eval` per app, and the argv is the control. `--override-input`
// takes the exact revision the candidate resolution already showed the
// operator (DA-1), `--no-write-lock-file` is what Spike B proved leaves
// /etc/ferrum/flake.lock byte-identical, and there is no `--impure` and no
// `nix build` anywhere -- the candidate's own code is evaluated, never
// executed.
//
// A per-app failure stays a per-app failure. When a package is removed or
// renamed upstream its row carries the evaluator's own stderr and every
// other row still reports normally, because R1 requires a loud, specific,
// attributable failure rather than a dropped row or a collapsed report.
use crate::update_check::{is_safe_app_id, AppReport, AppState, CandidateState, CommandRunner};

/// The argv that evaluates one attribute of the resolved configuration
/// against a candidate revision of one input.
///
/// # Arguments
/// * `input_name` - the flake input to override, `ferrum`.
/// * `candidate_flakeref` - that input pinned at the exact candidate rev.
/// * `flake_dir` - the host flake directory, e.g. `/etc/ferrum`.
/// * `attr` - the attribute to read, already fully qualified.
pub fn candidate_eval_argv(
    input_name: &str,
    candidate_flakeref: &str,
    flake_dir: &str,
    attr: &str,
) -> Vec<String> {
    vec![
        "eval".to_string(),
        "--json".to_string(),
        // Spike B: with this flag, `nix eval --override-input` leaves the
        // lock file byte-identical. It is the reason this is a read-only
        // preview at all rather than a disguised `nix flake lock`.
        "--no-write-lock-file".to_string(),
        "--override-input".to_string(),
        input_name.to_string(),
        candidate_flakeref.to_string(),
        format!("{flake_dir}#{attr}"),
    ]
}

/// Fill in every enabled app's candidate version and final state.
///
/// Rows that already failed their current-version evaluation are left
/// alone: they have no `current` to compare against, and re-reporting the
/// same app twice under two different failures would be noise.
///
/// # Arguments
/// * `runner` - the subprocess seam.
/// * `rows` - the app rows, mutated in place.
/// * `input_name` / `candidate_flakeref` / `flake_dir` / `config_attr` -
///   as for `candidate_eval_argv`.
/// * `candidate_short_rev` - used only in operator-facing text.
pub fn apply_candidate_versions(
    runner: &dyn CommandRunner,
    rows: &mut [AppReport],
    input_name: &str,
    candidate_flakeref: &str,
    flake_dir: &str,
    config_attr: &str,
    candidate_short_rev: &str,
) {
    for row in rows.iter_mut() {
        if !row.enabled || row.state == AppState::EvaluationFailed {
            continue;
        }
        let Some(current) = row.current_version.clone() else {
            continue;
        };
        if !is_safe_app_id(&row.id) {
            continue;
        }
        let attr = format!("{config_attr}.services.{}.package.version", row.id);
        let argv = candidate_eval_argv(input_name, candidate_flakeref, flake_dir, &attr);
        match runner.run("nix", &argv) {
            Err(e) => {
                row.state = AppState::EvaluationFailed;
                row.reason = Some(format!(
                    "could not be evaluated against candidate {candidate_short_rev}"
                ));
                row.error = Some(e);
            }
            Ok(out) if !out.success => {
                // The package was removed or renamed upstream, or the
                // module tree changed shape. The evaluator's own words are
                // the only useful thing to say, and they are what an
                // operator needs to decide whether to take this update.
                row.state = AppState::EvaluationFailed;
                row.reason = Some(format!(
                    "could not be evaluated against candidate {candidate_short_rev}"
                ));
                row.error = Some(out.stderr.trim().to_string());
            }
            Ok(out) => match serde_json::from_str::<serde_json::Value>(out.stdout.trim())
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
            {
                Some(candidate) => {
                    row.state = if candidate == current {
                        AppState::UpToDate
                    } else {
                        AppState::UpdateAvailable
                    };
                    row.candidate_version = Some(candidate);
                }
                None => {
                    row.state = AppState::EvaluationFailed;
                    row.reason = Some(format!(
                        "could not be evaluated against candidate {candidate_short_rev}"
                    ));
                    row.error = Some(format!(
                        "{attr} did not evaluate to a version string under the candidate"
                    ));
                }
            },
        }
    }
}

/// Mark every enabled app when there is no delta to compute.
///
/// The three cases are genuinely different and are not collapsed.
///
/// `UpToDate`: the candidate resolved to the revision this host already
/// runs, so the evaluation would be identical by construction and the apps
/// really are up to date. The row says so with the inference named, rather
/// than presenting it as a measurement.
///
/// `NotNewer`: a candidate WAS resolved, it simply is not newer. Saying
/// "no candidate revision was resolved" here would be a plainly false
/// sentence inside the one report whose entire premise is honesty.
///
/// `CheckFailed`: nothing was resolved and nothing is known.
///
/// Neither of the last two may read as "up to date".
///
/// # Arguments
/// * `rows` - the app rows, mutated in place.
/// * `candidate` - the resolved candidate state. `UpdateAvailable` never
///   reaches here; it goes to `apply_candidate_versions` instead.
///
/// # Returns
/// Nothing; `rows` is updated in place.
pub fn mark_no_delta(rows: &mut [AppReport], candidate: CandidateState) {
    let (state, reason) = match candidate {
        CandidateState::UpToDate => (
            AppState::UpToDate,
            "this host already runs the revision its ferrum input tracks, so nothing about \
             this app would change",
        ),
        CandidateState::NotNewer => (
            AppState::NotChecked,
            "the revision this host's ferrum input tracks is not newer than what it already \
             runs, so no update was evaluated -- this is not a statement that this app is up \
             to date",
        ),
        // UpdateAvailable cannot reach here, and treating it as "nothing
        // known" is the safe way to be wrong if it ever did.
        CandidateState::CheckFailed | CandidateState::UpdateAvailable => (
            AppState::NotChecked,
            "no candidate revision was resolved, so what this app would become is unknown -- \
             this is not a statement that it is up to date",
        ),
    };
    for row in rows.iter_mut() {
        if !row.enabled || row.state == AppState::EvaluationFailed {
            continue;
        }
        row.state = state;
        if state == AppState::UpToDate {
            row.candidate_version = row.current_version.clone();
        }
        row.reason = Some(reason.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_check::testing::{fail, ok, read_only_defects, FakeRunner};

    const CANDIDATE: &str = "2222222222222222222222222222222222222222";

    fn rows() -> Vec<AppReport> {
        vec![
            AppReport {
                id: "sonarr".to_string(),
                enabled: true,
                state: AppState::NotChecked,
                current_version: Some("4.0.18.2971".to_string()),
                candidate_version: None,
                reason: None,
                error: None,
            },
            AppReport {
                id: "jellyfin".to_string(),
                enabled: true,
                state: AppState::NotChecked,
                current_version: Some("10.11.10".to_string()),
                candidate_version: None,
                reason: None,
                error: None,
            },
            AppReport {
                id: "plex".to_string(),
                enabled: false,
                state: AppState::Excluded,
                current_version: None,
                candidate_version: None,
                reason: Some("disabled".to_string()),
                error: None,
            },
        ]
    }

    fn flakeref() -> String {
        format!(
            "{}syms-dev/ferrum/{CANDIDATE}",
            crate::update_candidate::GITHUB_SCHEME
        )
    }

    fn run(runner: &FakeRunner, rows: &mut [AppReport]) {
        apply_candidate_versions(
            runner,
            rows,
            "ferrum",
            &flakeref(),
            "/etc/ferrum",
            "nixosConfigurations.saltbox.config",
            "2222222",
        );
    }

    /// The argv IS the control here: this is the one place a candidate's
    /// own code is evaluated by a root process, so what is passed and what
    /// is not are both asserted, on the vector actually built.
    #[test]
    fn the_candidate_is_evaluated_read_only_against_the_exact_resolved_revision() {
        let mut r = rows();
        let runner = FakeRunner::new(vec![("package.version", ok("\"4.0.19.1\""))]);
        run(&runner, &mut r);

        let argvs = runner.argvs();
        assert_eq!(argvs.len(), 2, "one evaluation per ENABLED app: {argvs:?}");
        assert_eq!(
            argvs[0],
            vec![
                "eval".to_string(),
                "--json".to_string(),
                "--no-write-lock-file".to_string(),
                "--override-input".to_string(),
                "ferrum".to_string(),
                flakeref(),
                "/etc/ferrum#nixosConfigurations.saltbox.config.services.sonarr.package.version"
                    .to_string(),
            ]
        );
        for argv in &argvs {
            assert!(
                read_only_defects(argv).is_empty(),
                "{argv:?} -> {:?}",
                read_only_defects(argv)
            );
            assert!(
                argv.iter().any(|a| a.ends_with(CANDIDATE)),
                "the EXACT revision the operator was shown must be what is evaluated: {argv:?}"
            );
        }
        // The control on the control: the same scan really fires, both on a
        // forbidden flag and on the missing flag that is the whole guarantee.
        let impure = [
            "eval".to_string(),
            "--impure".to_string(),
            "--no-write-lock-file".to_string(),
        ];
        assert_eq!(read_only_defects(&impure), vec!["--impure is present".to_string()]);
        let unlocked = ["eval".to_string(), "--json".to_string()];
        assert_eq!(
            read_only_defects(&unlocked),
            vec!["--no-write-lock-file is missing".to_string()]
        );
    }

    /// R1: current -> candidate, for every enabled app.
    #[test]
    fn an_app_whose_version_moves_reports_both_ends_of_the_delta() {
        let mut r = rows();
        let runner = FakeRunner::new(vec![
            ("services.sonarr", ok("\"4.0.19.1\"")),
            ("services.jellyfin", ok("\"10.11.10\"")),
        ]);
        run(&runner, &mut r);

        let sonarr = r.iter().find(|a| a.id == "sonarr").unwrap();
        assert_eq!(sonarr.state, AppState::UpdateAvailable);
        assert_eq!(sonarr.current_version.as_deref(), Some("4.0.18.2971"));
        assert_eq!(sonarr.candidate_version.as_deref(), Some("4.0.19.1"));

        // R1's `custom/` edge case: an app the pin change does not move is
        // reported unaffected, because the fully resolved configuration --
        // which already includes custom/ -- is what was evaluated.
        let jellyfin = r.iter().find(|a| a.id == "jellyfin").unwrap();
        assert_eq!(jellyfin.state, AppState::UpToDate);
        assert_eq!(jellyfin.candidate_version.as_deref(), Some("10.11.10"));
    }

    /// R1: a package removed or renamed upstream is a loud, specific,
    /// per-app row carrying the evaluator's own text -- never a dropped row
    /// and never a generic "preview failed".
    #[test]
    fn an_app_that_vanished_upstream_keeps_its_row_and_the_evaluators_own_words() {
        let mut r = rows();
        let runner = FakeRunner::new(vec![
            (
                "services.sonarr",
                fail("error: attribute 'sonarr' missing\n       at /nix/store/abc/services.nix:9:5"),
            ),
            ("services.jellyfin", ok("\"10.12.0\"")),
        ]);
        run(&runner, &mut r);

        assert_eq!(r.len(), 3, "no row may be dropped");
        let sonarr = r.iter().find(|a| a.id == "sonarr").unwrap();
        assert_eq!(sonarr.state, AppState::EvaluationFailed);
        let error = sonarr.error.as_deref().unwrap();
        assert!(error.contains("attribute 'sonarr' missing"), "{error}");
        assert!(error.contains("services.nix:9:5"), "the location must survive too: {error}");
        assert!(!error.contains("preview failed"), "{error}");

        // One app's failure must not take the others down with it.
        let jellyfin = r.iter().find(|a| a.id == "jellyfin").unwrap();
        assert_eq!(jellyfin.state, AppState::UpdateAvailable);
        assert_eq!(jellyfin.candidate_version.as_deref(), Some("10.12.0"));
    }

    /// A disabled app is not evaluated at all -- there is nothing running
    /// to compare against, and evaluating it would invent a delta.
    #[test]
    fn a_disabled_app_is_never_evaluated_against_the_candidate() {
        let mut r = rows();
        let runner = FakeRunner::new(vec![("package.version", ok("\"9.9.9\""))]);
        run(&runner, &mut r);
        assert!(
            !runner.argvs().iter().any(|a| a.iter().any(|x| x.contains("services.plex"))),
            "{:?}",
            runner.argvs()
        );
        let plex = r.iter().find(|a| a.id == "plex").unwrap();
        assert_eq!(plex.state, AppState::Excluded);
        assert!(plex.candidate_version.is_none());
    }

    /// An app whose CURRENT version could not be read has no delta to
    /// compute, and must not be re-reported under a second failure.
    #[test]
    fn an_app_that_already_failed_its_current_evaluation_is_left_alone() {
        let mut r = rows();
        r[0].state = AppState::EvaluationFailed;
        r[0].current_version = None;
        r[0].error = Some("the original failure".to_string());
        let runner = FakeRunner::new(vec![("package.version", ok("\"1.0\""))]);
        run(&runner, &mut r);
        assert_eq!(r[0].error.as_deref(), Some("the original failure"));
        assert!(!runner.argvs().iter().any(|a| a.iter().any(|x| x.contains("services.sonarr"))));
    }

    /// The pin being unchanged is a real answer about the apps: the same
    /// inputs evaluate to the same versions. The row says so, and names the
    /// inference rather than presenting it as a measurement.
    #[test]
    fn an_unchanged_pin_makes_every_enabled_app_up_to_date_with_the_reason_named() {
        let mut r = rows();
        mark_no_delta(&mut r, CandidateState::UpToDate);
        for app in r.iter().filter(|a| a.enabled) {
            assert_eq!(app.state, AppState::UpToDate, "{}", app.id);
            assert_eq!(app.candidate_version, app.current_version, "{}", app.id);
            assert!(app.reason.as_deref().unwrap().contains("already runs the revision"));
        }
        // The disabled row keeps its own exclusion reason untouched.
        assert_eq!(r.iter().find(|a| a.id == "plex").unwrap().state, AppState::Excluded);
    }

    /// The case this whole design exists to keep honest: nothing known must
    /// never read as "up to date" -- and each not-known case must describe
    /// itself truthfully rather than borrowing another case's sentence.
    #[test]
    fn every_unknown_case_is_explicitly_unknown_and_says_what_actually_happened() {
        for (candidate, must_say, must_not_say) in [
            (
                CandidateState::CheckFailed,
                "no candidate revision was resolved",
                "not newer",
            ),
            (
                CandidateState::NotNewer,
                "is not newer than what it already runs",
                "no candidate revision was resolved",
            ),
        ] {
            let mut r = rows();
            mark_no_delta(&mut r, candidate);
            for app in r.iter().filter(|a| a.enabled) {
                assert_eq!(app.state, AppState::NotChecked, "{candidate:?} {}", app.id);
                assert!(app.candidate_version.is_none(), "{candidate:?} {}", app.id);
                let reason = app.reason.as_deref().unwrap();
                assert!(
                    reason.contains("is not a statement that"),
                    "{candidate:?}: {reason}"
                );
                assert!(reason.contains(must_say), "{candidate:?}: {reason}");
                assert!(
                    !reason.contains(must_not_say),
                    "{candidate:?} must not borrow the other case's words: {reason}"
                );
            }
        }
        // The control: the same helper really does produce up-to-date rows
        // on the one branch that earns them, so "never up to date" above is
        // a property of those branches and not of the helper.
        let mut other = rows();
        mark_no_delta(&mut other, CandidateState::UpToDate);
        assert_eq!(other[0].state, AppState::UpToDate);
    }
}
