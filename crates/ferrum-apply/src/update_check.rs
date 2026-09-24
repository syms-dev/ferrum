// The read-only update check: what this host runs today, what it would
// become, and neither of the two files that decide it touched.
//
// This is the `CheckUpdate` request kind -- the one privileged capability
// that is defined by what it must NOT do. It shells out to `nix eval` and
// `git ls-remote` as root, and it must leave
// /etc/ferrum/flake.nix and /etc/ferrum/flake.lock byte-identical: an
// update check that advanced a pin would move the host without anyone
// asking, and the operator's review step would be reviewing a decision
// already taken.
//
// Two different mechanisms, and it is worth being precise about which does
// what. PREVENTION is the argv -- `--no-write-lock-file` on every `nix
// eval`, on the current side as much as the candidate side, because
// evaluating a local-path flake is enough on its own to rewrite its lock.
// `ReadOnlyGuard` is the TRIPWIRE: it re-reads both files afterwards and
// fails the job if they moved. It cannot undo a write, so it is what
// catches a prevention that was wrong, not the guarantee itself. The tests
// use it as a proof; production uses it as an alarm.
//
// The scope of that claim, stated exactly. "Read-only" here means
// /etc/ferrum/flake.nix and /etc/ferrum/flake.lock are byte-identical
// afterwards, and the guard measures precisely those two files. It does
// NOT mean nothing is written anywhere: evaluating the candidate populates
// the Nix store, and pure evaluation still permits import-from-derivation
// and fixed-output fetches, so the candidate's own code is evaluated as
// root before the operator has reviewed anything. Store writes and
// evaluation-time resource use are outside both the prevention and the
// tripwire. That is a real residual, named here rather than implied away.
//
// Everything that decides an argv or shapes the report is a pure function
// over an injected `CommandRunner`, because there is no `nix`, no `git` and
// no network in this repo's test environment -- the only way these
// decisions can be tested at all is to make the subprocess a seam. That is
// the same convention `list_jobs_in`/`create_job_in` already use for
// directories.
//
// Cost, stated rather than hidden: one `nix eval` per enabled app per side
// (what it runs now, and what it would become). Each is a full module-system
// evaluation. This is the cost DA-6 tracks in the Phase 1.6 spec as an
// unmeasured Low, and per-app evaluation is what buys the per-app failure
// attribution R1 requires ("a loud, specific, per-app failure ... not a
// silently dropped row"). A single batched evaluation would be cheaper and
// would lose exactly that.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The document version of the report below. ferrumd and the UI read this
/// file across a generation switch, so the shape is versioned rather than
/// implicitly assumed to match the reader's binary.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// Captured stdout/stderr/status of one subprocess.
///
/// `stderr` is kept verbatim and reaches the report unmodified: R3 requires
/// the evaluator's own text, never a generic "preview failed".
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// True when the process exited zero.
    pub success: bool,
    /// Captured standard output, normally the `--json` answer.
    pub stdout: String,
    /// Captured standard error, kept byte-for-byte so it can reach the
    /// report unmodified.
    pub stderr: String,
}

/// The subprocess seam.
///
/// Implemented for real by `RealRunner`; implemented by the tests with a
/// recorder that captures every argv and answers from a canned table, so
/// the argv this module builds is asserted as data rather than inferred
/// from the variables fed into it.
pub trait CommandRunner {
    /// Run `program` with `args`, capturing its output.
    ///
    /// Returns `Err` only when the process could not be spawned at all
    /// (binary missing, permission denied); a process that ran and failed
    /// is `Ok` with `success == false`.
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String>;
}

/// The production `CommandRunner`: a real `std::process::Command`.
pub struct RealRunner;

impl CommandRunner for RealRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("failed to run {program}: {e}"))?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// How the candidate side of the check turned out.
///
/// `CheckFailed` is deliberately a distinct value from `UpToDate`: "we
/// could not look" and "we looked and there is nothing" are different
/// facts, and collapsing them is exactly the failure R1's unreachable-check
/// edge case forbids. `OrderUnknown` is the third of those facts -- "we
/// looked, we found something, and we cannot tell you whether it is newer"
/// -- which is distinct again from both. Every code path that reaches this
/// report has already resolved to exactly one of these five.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateState {
    /// A candidate was resolved and it is the revision this host already runs.
    UpToDate,
    /// A candidate was resolved and it is not newer than the installed one.
    NotNewer,
    /// A newer candidate was resolved; `rev` names it exactly.
    UpdateAvailable,
    /// A candidate was resolved and differs from the installed revision,
    /// but ferrum could not establish that it is NEWER. Distinct from
    /// `NotNewer`, which is a positive finding, and from `CheckFailed`,
    /// which means no candidate was resolved at all. `lastModified` and
    /// `currentLastModified` carry whatever the ordering attempt did learn,
    /// so the operator can judge instead of being told.
    OrderUnknown,
    /// The check could not be performed; `error` carries the real text.
    CheckFailed,
}

/// Where the candidate revision came from and what it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateReport {
    pub state: CandidateState,
    /// The flake input name in the host's own `flake.nix`, e.g. `ferrum`.
    pub input_name: Option<String>,
    /// The input's URL exactly as the host's `flake.nix` spells it.
    pub input_url: Option<String>,
    /// The ref that was queried (a branch, a tag, or `HEAD`).
    pub reference: Option<String>,
    /// The resolved candidate revision, full 40-hex. DA-1 makes this the
    /// control that replaces signature verification: the operator sees the
    /// exact commit and can refuse it.
    pub rev: Option<String>,
    /// The revision the running host's `flake.lock` pins today.
    pub current_rev: Option<String>,
    /// The candidate revision's own `lastModified`, when the ordering
    /// attempt got that far. Self-reported commit metadata, which is
    /// exactly why it is shown rather than merely acted on.
    pub last_modified: Option<i64>,
    /// The installed revision's `lastModified`, as this host's own
    /// `flake.lock` records it.
    pub current_last_modified: Option<i64>,
    /// The real error text when `state` is `CheckFailed` or
    /// `OrderUnknown` -- what could not be done, in the words of whatever
    /// could not do it.
    pub error: Option<String>,
}

/// How one catalog app came out of the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppState {
    /// Enabled, current version known, candidate side not resolved.
    NotChecked,
    /// Enabled, and the candidate would not change its version.
    UpToDate,
    /// Enabled, and the candidate would change its version.
    UpdateAvailable,
    /// Disabled in the resolved configuration; `reason` says why it is out.
    Excluded,
    /// The evaluation for this app failed; `error` carries the evaluator's
    /// own stderr.
    EvaluationFailed,
}

/// One catalog app's row. Every catalog app gets exactly one of these --
/// there is no path that drops a row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppReport {
    pub id: String,
    pub enabled: bool,
    pub state: AppState,
    pub current_version: Option<String>,
    pub candidate_version: Option<String>,
    /// Why this row is not a version delta, in operator-facing words.
    pub reason: Option<String>,
    /// The evaluator's own text when `state` is `EvaluationFailed`.
    pub error: Option<String>,
}

/// ferrum's own release version, current and candidate.
///
/// With Open Question 1 resolved as "track a curated release ref", ferrum's
/// release version on a host IS the revision its `flake.lock` pins for the
/// `ferrum` input -- there is no separate version string to read, and the
/// catalog's `ferrumVersion` is the HOST flake's own revision, not this
/// one. The short form is the seven-character prefix the rest of the
/// codebase already displays (`self.shortRev`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FerrumReport {
    pub current_version: Option<String>,
    pub current_rev: Option<String>,
    pub candidate_version: Option<String>,
    pub candidate_rev: Option<String>,
}

/// The settings-schema migration pending on this host, folded into the same
/// report so R3's "one unified what's-changing review" holds.
///
/// Deliberately does NOT claim the migration is *new*: the write-back step
/// that would record "the operator has seen this" is not implemented, so
/// there is no way to know, and R3's edge case forbids implying otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaMigrationReport {
    pub current_version: Option<i64>,
    pub target_version: Option<i64>,
    pub pending: bool,
    /// Set when the on-disk schema version is ahead of the module tree --
    /// the same monotonicity warning `preview-migration` already prints.
    pub note: Option<String>,
    pub error: Option<String>,
}

/// The whole read-only check, as one document.
///
/// One document, not a per-app flag: nixpkgs pins one package set for the
/// whole host, so R1 requires a single pending-update event carrying every
/// affected app's delta. The shape is what enforces that -- there is
/// nowhere to put a per-app "update available" flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateReport {
    pub schema_version: u32,
    pub checked_at: u64,
    pub candidate: CandidateReport,
    pub ferrum: FerrumReport,
    pub apps: Vec<AppReport>,
    /// Set when the catalog app set itself could not be evaluated, which is
    /// the one failure that would otherwise present as "no apps".
    pub apps_error: Option<String>,
    pub schema_migration: SchemaMigrationReport,
    pub warnings: Vec<String>,
}

/// Everything the check reads, passed in rather than resolved inside, so
/// the tests drive the real builder against real temp files.
pub struct CheckInputs<'a> {
    /// The flake directory, e.g. `/etc/ferrum`.
    pub flake_dir: &'a str,
    /// The configuration attribute path up to and including `.config`,
    /// e.g. `nixosConfigurations.saltbox.config`.
    pub config_attr: &'a str,
    pub settings_path: &'a Path,
    /// The host's own root-owned `flake.nix` -- where the repository and
    /// ref to check come from, and one of the two files the read-only
    /// guarantee is measured against.
    pub flake_nix: &'a Path,
    /// The host's own `flake.lock` -- what revision it runs today.
    pub flake_lock: &'a Path,
    pub now: u64,
}

/// Byte-for-byte proof that the check wrote nothing to the two files the
/// privilege boundary exists to protect.
///
/// Compares whole contents rather than a digest: there is no hashing
/// dependency in this crate, the files are a few kilobytes, and identical
/// bytes is a stronger claim than an identical digest anyway.
pub struct ReadOnlyGuard {
    watched: Vec<(PathBuf, Option<Vec<u8>>)>,
}

impl ReadOnlyGuard {
    /// Snapshot the current contents of every watched path.
    ///
    /// A path that does not exist is recorded as absent, and must still be
    /// absent afterwards -- creating `flake.lock` where there was none is
    /// as much a write as rewriting one.
    ///
    /// # Arguments
    /// * `paths` - the files that must not move.
    ///
    /// # Returns
    /// A guard holding their contents at this moment.
    pub fn capture(paths: &[&Path]) -> Self {
        Self {
            watched: paths
                .iter()
                .map(|p| (p.to_path_buf(), std::fs::read(p).ok()))
                .collect(),
        }
    }

    /// Re-read every watched path and return one message per file that
    /// changed. An empty vector is the read-only guarantee holding.
    ///
    /// # Returns
    /// One operator-facing message per file whose bytes, or whose
    /// existence, differ from the capture.
    pub fn violations(&self) -> Vec<String> {
        self.watched
            .iter()
            .filter_map(|(path, before)| {
                let after = std::fs::read(path).ok();
                if &after == before {
                    None
                } else {
                    Some(format!(
                        "the update check modified {} -- it must be strictly read-only",
                        path.display()
                    ))
                }
            })
            .collect()
    }
}

/// Splits `FERRUM_FLAKE_REF` into the flake directory and the configuration
/// attribute path ending at `.config`.
///
/// The deployed value is
/// `/etc/ferrum#nixosConfigurations.<hostname>.config.system.build.toplevel`
/// (`modules/core/overlays.nix`'s `defaultFlakeRef`), so the configuration
/// attribute is that with the `.system.build.toplevel` suffix removed. It
/// is derived from the same variable `run_apply` reads rather than
/// rebuilt from the hostname, for the reason `run_preview_migration`'s
/// header already gives: a second, independently-configured path can drift
/// from the real deployment target, and this one cannot.
///
/// # Arguments
/// * `flake_ref` - `$FERRUM_FLAKE_REF`, or this crate's compiled-in default.
///
/// # Returns
/// `(flake_dir, config_attr)`.
pub fn split_flake_ref(flake_ref: &str) -> (String, String) {
    let (dir, attr) = match flake_ref.split_once('#') {
        Some((d, a)) => (d, a),
        None => (flake_ref, "nixosConfigurations.default"),
    };
    let attr = attr.trim_end_matches('.');
    let config_attr = if let Some(base) = attr.strip_suffix(".system.build.toplevel") {
        base.to_string()
    } else if attr.ends_with(".config") {
        attr.to_string()
    } else {
        format!("{attr}.config")
    };
    (dir.to_string(), config_attr)
}

/// True for an app id this module is willing to interpolate into a Nix
/// attribute path.
///
/// The ids come from evaluating the host's own configuration, so they are
/// already trusted -- but they become argv text handed to a root-privileged
/// `nix eval`, and "the value I am about to splice into an attribute path
/// is a plain identifier" is cheap to check and expensive to be wrong
/// about. Same reasoning as `job_uuid_from_unit`'s UUID re-parse in
/// ferrumd.
///
/// # Arguments
/// * `id` - a catalog app id, as the resolved configuration named it.
///
/// # Returns
/// True for a lowercase identifier of letters, digits and hyphens starting
/// with a letter; false for everything else.
pub fn is_safe_app_id(id: &str) -> bool {
    !id.is_empty()
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// The argv for evaluating one attribute of the resolved configuration.
///
/// `--no-write-lock-file` is the flag that makes this read-only, and it is
/// needed on THIS side even though the input is the host's own flake and
/// nothing is being overridden. `nix eval` against a local-path flake locks
/// it, and writes `flake.lock` whenever the lock on disk does not already
/// satisfy `flake.nix`. That is reachable on exactly the path DA-1
/// preserves: an operator hand-edits `ferrum.url` to a new revision and
/// runs a check before applying. Without this flag the check would advance
/// the on-disk pin, as root, with nobody having asked -- the harm this
/// module's header exists to rule out. `ReadOnlyGuard` would report it
/// afterwards; it cannot undo it, so prevention has to live here.
///
/// `--json` so the answer is parseable. No `--impure`: unlike
/// `apply.rs`'s `nix build`, nothing here needs the purity sandbox
/// disabled.
///
/// # Arguments
/// * `flake_dir` - the host flake directory, e.g. `/etc/ferrum`.
/// * `attr` - the attribute path to read, already fully qualified.
///
/// # Returns
/// The arguments for `nix`, without the program name.
pub fn eval_argv(flake_dir: &str, attr: &str) -> Vec<String> {
    vec![
        "eval".to_string(),
        "--json".to_string(),
        "--no-write-lock-file".to_string(),
        format!("{flake_dir}#{attr}"),
    ]
}

/// Evaluate one attribute and hand back its raw JSON stdout, or the
/// evaluator's own stderr.
fn eval_json(
    runner: &dyn CommandRunner,
    flake_dir: &str,
    attr: &str,
) -> Result<serde_json::Value, String> {
    let argv = eval_argv(flake_dir, attr);
    let out = runner.run("nix", &argv)?;
    if !out.success {
        return Err(out.stderr.trim().to_string());
    }
    serde_json::from_str(out.stdout.trim())
        .map_err(|e| format!("nix eval returned output this check could not parse: {e}"))
}

/// The catalog app set as the resolved configuration sees it: every app id
/// the module tree knows about, and whether this host enables it.
///
/// Read from `config.ferrum.apps` rather than from `settings.json`'s keys,
/// because an app absent from `settings.json` is still a catalog app that
/// must get a row -- and because R1 requires the *resolved* configuration
/// as the source of truth, which is what `custom/` overrides participate
/// in.
fn evaluate_app_set(
    runner: &dyn CommandRunner,
    flake_dir: &str,
    config_attr: &str,
) -> Result<Vec<(String, bool)>, String> {
    let value = eval_json(runner, flake_dir, &format!("{config_attr}.ferrum.apps"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "config.ferrum.apps did not evaluate to an attribute set".to_string())?;
    let mut apps: Vec<(String, bool)> = object
        .iter()
        .map(|(id, cfg)| {
            (
                id.clone(),
                cfg.get("enable").and_then(|e| e.as_bool()).unwrap_or(false),
            )
        })
        .collect();
    apps.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(apps)
}

/// The operator-facing reason a disabled app carries no version delta.
///
/// R1's disabled-app edge case requires the text to say it, rather than the
/// row staying silent or disappearing.
pub const DISABLED_REASON: &str =
    "disabled on this host, so there is no running version to compare against -- \
     it will come up on the new package set if you enable it after updating";

/// Build one app's row from its current-version evaluation.
///
/// # Arguments
/// * `id` - the catalog app id.
/// * `enabled` - whether the resolved configuration enables it.
/// * `current` - the evaluation result, or the evaluator's own error text.
pub fn app_row(id: &str, enabled: bool, current: Result<String, String>) -> AppReport {
    if !enabled {
        return AppReport {
            id: id.to_string(),
            enabled: false,
            state: AppState::Excluded,
            current_version: None,
            candidate_version: None,
            reason: Some(DISABLED_REASON.to_string()),
            error: None,
        };
    }
    match current {
        Ok(version) => AppReport {
            id: id.to_string(),
            enabled: true,
            state: AppState::NotChecked,
            current_version: Some(version),
            candidate_version: None,
            reason: None,
            error: None,
        },
        Err(e) => AppReport {
            id: id.to_string(),
            enabled: true,
            state: AppState::EvaluationFailed,
            current_version: None,
            candidate_version: None,
            reason: None,
            error: Some(e),
        },
    }
}

/// Compare the on-disk schema version with the module tree's, without
/// claiming a pending migration is new.
///
/// Applies `preview-migration`'s existing monotonicity discipline: a target
/// below the current version is a warning, never "would migrate".
///
/// # Arguments
/// * `current` - `schemaVersion` from the host's own settings.json, or
///   `None` when it could not be read.
/// * `target` - the module tree's `config.ferrum.schemaVersion`, or the
///   evaluator's own error text.
///
/// # Returns
/// The migration block of the report. A failure becomes `error` inside it
/// rather than an `Err`, because the rest of the report is still valid.
pub fn schema_migration_report(
    current: Option<i64>,
    target: Result<i64, String>,
) -> SchemaMigrationReport {
    match (current, target) {
        (Some(current), Ok(target)) => SchemaMigrationReport {
            current_version: Some(current),
            target_version: Some(target),
            pending: target > current,
            note: if target < current {
                Some(format!(
                    "this host's settings.json (schemaVersion {current}) is newer than the \
                     module tree it is built from (schemaVersion {target}) -- no migration \
                     will run"
                ))
            } else {
                None
            },
            error: None,
        },
        (current, Ok(target)) => SchemaMigrationReport {
            current_version: current,
            target_version: Some(target),
            pending: false,
            note: None,
            error: Some(
                "could not read this host's current settings.json schemaVersion".to_string(),
            ),
        },
        (current, Err(e)) => SchemaMigrationReport {
            current_version: current,
            target_version: None,
            pending: false,
            note: None,
            error: Some(e),
        },
    }
}

/// Read `schemaVersion` out of the host's settings.json.
///
/// Absent or unreadable is `None` rather than a default, so
/// `schema_migration_report` can say so instead of comparing against an
/// invented 1.
fn current_schema_version(settings_path: &Path) -> Option<i64> {
    let raw = std::fs::read_to_string(settings_path).ok()?;
    serde_json::from_str::<serde_json::Value>(&raw)
        .ok()?
        .get("schemaVersion")
        .and_then(|v| v.as_i64())
}

/// Run the whole read-only check and shape its report.
///
/// Every subprocess goes through `runner`, and every path comes from
/// `inputs`, so this function -- including the argv it builds and the JSON
/// it emits -- is exercised end to end by the tests below with no `nix`, no
/// `git` and no network.
///
/// # Returns
/// The report. Failures become states and error text inside it rather than
/// an `Err`: a check that could not reach the network still has to report
/// every enabled app's current version, and "could not check" is a
/// first-class outcome, not an exception.
pub fn build_report(inputs: &CheckInputs, runner: &dyn CommandRunner) -> UpdateReport {
    let mut warnings: Vec<String> = Vec::new();

    let (apps, apps_error) =
        match evaluate_app_set(runner, inputs.flake_dir, inputs.config_attr) {
            Ok(apps) => (apps, None),
            Err(e) => (Vec::new(), Some(e)),
        };

    let mut rows: Vec<AppReport> = apps
        .iter()
        .map(|(id, enabled)| {
            if !enabled {
                return app_row(id, false, Ok(String::new()));
            }
            if !is_safe_app_id(id) {
                return app_row(
                    id,
                    true,
                    Err(format!(
                        "refusing to evaluate an app id that is not a plain identifier: {id:?}"
                    )),
                );
            }
            let attr = format!("{}.services.{id}.package.version", inputs.config_attr);
            let current = eval_json(runner, inputs.flake_dir, &attr).and_then(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{attr} did not evaluate to a version string"))
            });
            app_row(id, true, current)
        })
        .collect();

    let target = eval_json(
        runner,
        inputs.flake_dir,
        &format!("{}.ferrum.schemaVersion", inputs.config_attr),
    )
    .and_then(|v| {
        v.as_i64()
            .ok_or_else(|| "config.ferrum.schemaVersion did not evaluate to a number".to_string())
    });
    let schema_migration =
        schema_migration_report(current_schema_version(inputs.settings_path), target);

    let outcome =
        crate::update_candidate::resolve(runner, inputs.flake_nix, inputs.flake_lock, inputs.now);
    warnings.extend(outcome.warnings.clone());
    let candidate = outcome.report.clone();
    // ferrum's release version on a host IS the revision its flake.lock
    // pins, so both halves of R1's "current vs candidate" come straight out
    // of the resolution rather than from a second, drift-prone lookup.
    let ferrum = FerrumReport {
        current_version: candidate.current_rev.as_deref().map(crate::update_candidate::short_rev),
        current_rev: candidate.current_rev.clone(),
        candidate_version: candidate.rev.as_deref().map(crate::update_candidate::short_rev),
        candidate_rev: candidate.rev.clone(),
    };

    // The candidate deltas, only where there is a candidate to compare
    // against. Every other case goes through `mark_no_delta`, which keeps
    // "nothing is known" and "nothing would change" distinguishable --
    // inferring the second from the first is exactly what R1 forbids.
    match (&outcome.input, candidate.state, candidate.rev.as_deref()) {
        (Some(input), CandidateState::UpdateAvailable, Some(rev)) => {
            crate::update_deltas::apply_candidate_versions(
                runner,
                &mut rows,
                &input.name,
                &input.flakeref_for_rev(rev),
                inputs.flake_dir,
                inputs.config_attr,
                &crate::update_candidate::short_rev(rev),
            );
        }
        _ => crate::update_deltas::mark_no_delta(&mut rows, candidate.state),
    }

    if let Some(e) = &apps_error {
        warnings.push(format!(
            "no app could be reported: the catalog app set itself did not evaluate: {e}"
        ));
    }

    UpdateReport {
        schema_version: REPORT_SCHEMA_VERSION,
        checked_at: inputs.now,
        candidate,
        ferrum,
        apps: rows,
        apps_error,
        schema_migration,
        warnings,
    }
}

/// The directory the report document is written to.
///
/// Defaults to `FERRUM_JOBS_DIR` -- the one directory both this
/// root-privileged binary and the unprivileged daemon already share
/// (`modules/core/daemon.nix` sets it on both units), which is what lets
/// ferrumd serve the result without ever running `nix` itself.
/// `FERRUM_UPDATE_REPORT_DIR` overrides it, following the same
/// env-var-overridable convention every other path in this crate uses so
/// the behaviour is testable.
///
/// # Returns
/// The directory the report document is published in.
pub fn report_dir() -> PathBuf {
    std::env::var("FERRUM_UPDATE_REPORT_DIR")
        .or_else(|_| std::env::var("FERRUM_JOBS_DIR"))
        .unwrap_or_else(|_| "/var/lib/ferrum/jobs".to_string())
        .into()
}

/// The report document's filename for a given job id.
///
/// Sits beside that job's own `<id>.jsonl` progress file, so ferrumd finds
/// it by the id it already holds and no second identifier has to be kept in
/// sync. `latest.update-check.json` is the fallback for a run with no job
/// id (a bare `ferrum-apply check-update` over SSH).
///
/// # Arguments
/// * `job_id` - `$FERRUM_JOB_ID`, when this run was dispatched by ferrumd.
///
/// # Returns
/// The filename, without a directory.
pub fn report_file_name(job_id: Option<&str>) -> String {
    match job_id.filter(|id| !id.is_empty()) {
        Some(id) => format!("{id}.update-check.json"),
        None => "latest.update-check.json".to_string(),
    }
}

/// Write the report where ferrumd can read it, readable by the `ferrum`
/// group.
///
/// Written to a temporary file and renamed, so a reader that arrives
/// mid-write sees either the previous document or the complete new one,
/// never a truncated one. The temporary name carries this process's pid:
/// a dispatched job's report is uuid-named and cannot collide, but two
/// operators running `ferrum-apply check-update` over SSH at once would
/// otherwise share one `latest.update-check.json.tmp` and one could publish
/// the other's half-written bytes -- defeating the very discipline the
/// rename exists for.
///
/// # Arguments
/// * `dir` - the report directory, created if absent.
/// * `file_name` - from `report_file_name`.
/// * `report` - the document to publish.
///
/// # Returns
/// The path the report was published at.
///
/// # Errors
/// Any I/O failure creating the directory, writing, setting the mode, or
/// renaming, and a serialization failure as `InvalidData`.
pub fn write_report(dir: &Path, file_name: &str, report: &UpdateReport) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let final_path = dir.join(file_name);
    let temp_path = dir.join(format!("{file_name}.{}.tmp", std::process::id()));
    let body = serde_json::to_string(report)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&temp_path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // ferrumd runs as an unprivileged user and this file is written by
        // root; without an explicit mode a restrictive umask would leave
        // the daemon unable to read the answer it asked for. 0644 is not
        // world-readable in practice: the directory is 0750 ferrum:ferrum
        // (modules/core/daemon.nix), so the reachable audience is root and
        // the ferrum group.
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&temp_path, &final_path)?;
    Ok(final_path)
}

/// One line of operator-facing summary, for the job's terminal progress
/// event.
///
/// # Arguments
/// * `report` - the finished report.
///
/// # Returns
/// A single line naming the candidate outcome and the app counts. It never
/// says "up to date" for a state that is not `UpToDate`.
pub fn summary_line(report: &UpdateReport) -> String {
    let enabled = report.apps.iter().filter(|a| a.enabled).count();
    let excluded = report.apps.len() - enabled;
    let candidate = match report.candidate.state {
        CandidateState::UpToDate => "up to date".to_string(),
        CandidateState::NotNewer => "the tracked ref is not newer than this host".to_string(),
        CandidateState::UpdateAvailable => match &report.candidate.rev {
            Some(rev) => format!("update available: {rev}"),
            None => "update available".to_string(),
        },
        CandidateState::OrderUnknown => format!(
            "a candidate was found but could not be shown to be newer: {}",
            report.candidate.error.as_deref().unwrap_or("unknown reason")
        ),
        CandidateState::CheckFailed => format!(
            "could not check for updates: {}",
            report.candidate.error.as_deref().unwrap_or("unknown error")
        ),
    };
    format!("{candidate}; {enabled} enabled app(s), {excluded} excluded")
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::cell::RefCell;

    /// A `CommandRunner` that records every argv it is handed and answers
    /// from a canned table keyed on a substring of the joined argv.
    ///
    /// The recording is the point: these tests assert the argv that was
    /// actually built, not the variables fed into the builder.
    pub struct FakeRunner {
        pub calls: RefCell<Vec<(String, Vec<String>)>>,
        pub answers: Vec<(String, CommandOutput)>,
    }

    impl FakeRunner {
        pub fn new(answers: Vec<(&str, CommandOutput)>) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                answers: answers
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            }
        }

        pub fn argvs(&self) -> Vec<Vec<String>> {
            self.calls.borrow().iter().map(|(_, a)| a.clone()).collect()
        }

        pub fn programs(&self) -> Vec<String> {
            self.calls.borrow().iter().map(|(p, _)| p.clone()).collect()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String> {
            self.calls
                .borrow_mut()
                .push((program.to_string(), args.to_vec()));
            let joined = args.join(" ");
            for (needle, out) in &self.answers {
                if joined.contains(needle.as_str()) {
                    return Ok(out.clone());
                }
            }
            Err(format!("FakeRunner has no answer for: {program} {joined}"))
        }
    }

    /// Everything wrong one argv can be: a forbidden flag present, or the
    /// flag that delivers the read-only guarantee absent.
    ///
    /// A free function rather than assertions inline, so the very same scan
    /// can be pointed at a deliberately-broken argv below. That is what
    /// makes the clean result a finding instead of a scan that never fires.
    pub fn read_only_defects(argv: &[String]) -> Vec<String> {
        let mut defects = Vec::new();
        for forbidden in [
            "--impure",
            "--recreate-lock-file",
            "--update-input",
            "--commit-lock-file",
        ] {
            if argv.iter().any(|a| a == forbidden) {
                defects.push(format!("{forbidden} is present"));
            }
        }
        if argv.iter().any(|a| a == "build" || a == "lock" || a == "nix-env") {
            defects.push("a mutating subcommand is present".to_string());
        }
        // The presence half, and the one an absence-only scan could never
        // have caught: `nix eval` against a local-path flake writes
        // flake.lock whenever the existing lock does not already satisfy
        // flake.nix. Omitting this flag is not "no flag either way", it is
        // an opt-in to a root-privileged write.
        if argv.first().is_some_and(|a| a == "eval")
            && !argv.iter().any(|a| a == "--no-write-lock-file")
        {
            defects.push("--no-write-lock-file is missing".to_string());
        }
        defects
    }

    pub fn ok(stdout: &str) -> CommandOutput {
        CommandOutput {
            success: true,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    pub fn fail(stderr: &str) -> CommandOutput {
        CommandOutput {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    /// The deployed `FERRUM_FLAKE_REF` names the configuration after the
    /// HOST, not `default` -- `modules/core/overlays.nix`'s own comment
    /// records that ferrum-apply's `default` fallback failed outright on
    /// the first real ferrum host. Deriving the configuration attribute
    /// from the same variable is what keeps this check pointed at the same
    /// configuration an apply would build.
    #[test]
    fn the_configuration_attribute_comes_from_the_real_deployed_flake_ref() {
        let (dir, attr) = split_flake_ref(
            "/etc/ferrum#nixosConfigurations.saltbox.config.system.build.toplevel",
        );
        assert_eq!(dir, "/etc/ferrum");
        assert_eq!(attr, "nixosConfigurations.saltbox.config");
    }

    #[test]
    fn a_flake_ref_without_the_toplevel_suffix_still_resolves_to_a_config_attribute() {
        assert_eq!(
            split_flake_ref("/etc/ferrum#nixosConfigurations.box.config").1,
            "nixosConfigurations.box.config"
        );
        assert_eq!(
            split_flake_ref("/etc/ferrum#nixosConfigurations.box").1,
            "nixosConfigurations.box.config"
        );
        assert_eq!(
            split_flake_ref("/etc/ferrum").1,
            "nixosConfigurations.default.config"
        );
    }

    /// An app id becomes argv text for a root-privileged `nix eval`, so the
    /// matcher has to actually reject something. Both halves are asserted:
    /// a rejecting matcher that also rejects every real id would be
    /// vacuously "safe" and would report every app as failed.
    #[test]
    fn the_app_id_guard_accepts_every_real_catalog_id_and_rejects_attribute_injection() {
        for id in ["sonarr", "radarr", "prowlarr", "jellyfin", "plex", "sabnzbd", "qbittorrent"] {
            assert!(is_safe_app_id(id), "{id} is a real catalog id and must be accepted");
        }
        for id in ["", "Sonarr", "son arr", "sonarr.package", "\"a\" or builtins", "../x", "-x"] {
            assert!(!is_safe_app_id(id), "{id:?} must not reach a nix attribute path");
        }
    }

    const INSTALLED_REV: &str = "1111111111111111111111111111111111111111";
    const CANDIDATE_REV: &str = "2222222222222222222222222222222222222222";

    fn inputs<'a>(
        settings: &'a std::path::Path,
        flake_nix: &'a std::path::Path,
        flake_lock: &'a std::path::Path,
    ) -> CheckInputs<'a> {
        CheckInputs {
            flake_dir: "/etc/ferrum",
            config_attr: "nixosConfigurations.saltbox.config",
            settings_path: settings,
            flake_nix,
            flake_lock,
            now: 1_758_700_000,
        }
    }

    /// The seven-app host, three of them disabled.
    fn app_set_json() -> &'static str {
        r#"{"jellyfin":{"enable":true},"plex":{"enable":false},"prowlarr":{"enable":false},
            "qbittorrent":{"enable":false},"radarr":{"enable":true},"sabnzbd":{"enable":true},
            "sonarr":{"enable":true}}"#
    }

    fn standard_runner() -> FakeRunner {
        FakeRunner::new(vec![
            ("ferrum.apps", ok(app_set_json())),
            ("ferrum.schemaVersion", ok("2")),
            ("services.jellyfin.package.version", ok("\"10.11.10\"")),
            ("services.radarr.package.version", ok("\"6.2.1.10461\"")),
            ("services.sabnzbd.package.version", ok("\"4.5.5\"")),
            ("services.sonarr.package.version", ok("\"4.0.18.2971\"")),
            ("ls-remote", ok(&format!("{CANDIDATE_REV}\tHEAD\n"))),
            (
                "flake metadata",
                ok(&serde_json::json!({"lastModified": 200, "revision": CANDIDATE_REV}).to_string()),
            ),
        ])
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        settings: PathBuf,
        flake_nix: PathBuf,
        flake_lock: PathBuf,
    }

    fn fixture(schema_version: i64) -> Fixture {
        fixture_with_url(
            schema_version,
            &format!("{}syms-dev/ferrum", crate::update_candidate::GITHUB_SCHEME),
        )
    }

    /// The same host, with the `ferrum` input spelled however the caller
    /// needs -- the credential tests need a URL carrying userinfo.
    fn fixture_with_url(schema_version: i64, ferrum_url: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let settings = dir.path().join("settings.json");
        std::fs::write(
            &settings,
            format!(r#"{{"schemaVersion":{schema_version},"apps":{{}}}}"#),
        )
        .unwrap();
        let flake_nix = dir.path().join("flake.nix");
        std::fs::write(&flake_nix, format!("{{\n  inputs.ferrum.url = \"{ferrum_url}\";\n}}\n"))
            .unwrap();
        let flake_lock = dir.path().join("flake.lock");
        std::fs::write(
            &flake_lock,
            serde_json::json!({
                "nodes": {
                    "root": {"inputs": {"ferrum": "ferrum"}},
                    "ferrum": {"locked": {"rev": INSTALLED_REV, "lastModified": 100}}
                },
                "version": 7
            })
            .to_string(),
        )
        .unwrap();
        Fixture { _dir: dir, settings, flake_nix, flake_lock }
    }

    fn report_for(runner: &FakeRunner, f: &Fixture) -> UpdateReport {
        build_report(&inputs(&f.settings, &f.flake_nix, &f.flake_lock), runner)
    }

    /// R1: every enabled app appears exactly once with its current version,
    /// sourced from the resolved configuration.
    #[test]
    fn every_enabled_app_gets_exactly_one_row_carrying_its_current_version() {
        let f = fixture(1);
        let runner = standard_runner();
        let report = report_for(&runner, &f);

        let enabled: Vec<&AppReport> = report.apps.iter().filter(|a| a.enabled).collect();
        assert_eq!(
            enabled.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["jellyfin", "radarr", "sabnzbd", "sonarr"]
        );
        for app in &enabled {
            assert!(app.current_version.is_some(), "{} has no current version", app.id);
            assert!(
                matches!(app.state, AppState::UpToDate | AppState::UpdateAvailable),
                "{} must carry a real delta state, got {:?}",
                app.id,
                app.state
            );
        }
        assert_eq!(
            enabled
                .iter()
                .find(|a| a.id == "sonarr")
                .unwrap()
                .current_version
                .as_deref(),
            Some("4.0.18.2971")
        );
    }

    /// R1's disabled-app edge case: excluded, but never silently dropped,
    /// and the row says why in words an operator reads.
    #[test]
    fn every_disabled_app_gets_exactly_one_row_saying_why_it_is_excluded() {
        let f = fixture(1);
        let runner = standard_runner();
        let report = report_for(&runner, &f);

        let excluded: Vec<&AppReport> = report.apps.iter().filter(|a| !a.enabled).collect();
        assert_eq!(
            excluded.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            vec!["plex", "prowlarr", "qbittorrent"]
        );
        for app in &excluded {
            assert_eq!(app.state, AppState::Excluded, "{}", app.id);
            let reason = app.reason.as_deref().unwrap_or("");
            assert!(
                reason.contains("no running version to compare against"),
                "{} must say why it is out, got: {reason:?}",
                app.id
            );
            assert!(app.current_version.is_none());
        }
        // Exactly once each, and every catalog app present: 4 enabled + 3
        // excluded is the whole set the evaluation returned.
        assert_eq!(report.apps.len(), 7);
        let mut ids: Vec<&str> = report.apps.iter().map(|a| a.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 7, "an app id appeared more than once");
    }

    /// The argv itself is the control: a root-privileged `nix eval` must
    /// never be handed `--impure`, and must always be told not to write a
    /// lock file. Asserted on the vector actually built.
    #[test]
    fn the_evaluator_is_invoked_read_only_with_no_impure_flag() {
        let f = fixture(1);
        let runner = standard_runner();
        let _ = report_for(&runner, &f);

        let argvs = runner.argvs();
        assert!(!argvs.is_empty(), "the check ran no command at all");
        for (program, argv) in runner.programs().iter().zip(&argvs) {
            assert!(
                program == "nix" || program == "git",
                "no other binary may be invoked by the check: {program} {argv:?}"
            );
            // The whole set of subcommands the check is allowed to reach.
            let sub = argv.join(" ");
            assert!(
                argv[0] == "eval" || argv[0] == "ls-remote" || sub.starts_with("flake metadata"),
                "an unexpected subcommand reached the check: {argv:?}"
            );
            assert!(
                read_only_defects(argv).is_empty(),
                "{argv:?} -> {:?}",
                read_only_defects(argv)
            );
        }
        assert!(
            argvs
                .iter()
                .any(|a| a.contains(&"/etc/ferrum#nixosConfigurations.saltbox.config.services.sonarr.package.version".to_string())),
            "the per-app attribute must be built from the deployed flake ref: {argvs:?}"
        );
        // The control on the control: the SAME scan really does fire, on
        // both a forbidden flag and a missing required one.
        let impure = ["eval".to_string(), "--impure".to_string(), "--no-write-lock-file".to_string()];
        assert_eq!(read_only_defects(&impure), vec!["--impure is present".to_string()]);
        let unlocked = ["eval".to_string(), "--json".to_string()];
        assert_eq!(
            read_only_defects(&unlocked),
            vec!["--no-write-lock-file is missing".to_string()]
        );
    }

    /// R1: an app whose evaluation fails is a loud row carrying the
    /// evaluator's own text -- never a dropped row, never a generic message.
    #[test]
    fn an_app_whose_evaluation_fails_keeps_its_row_and_the_evaluators_own_text() {
        let f = fixture(1);
        let mut answers = vec![
            ("ferrum.apps", ok(app_set_json())),
            ("ferrum.schemaVersion", ok("2")),
            (
                "services.sonarr.package.version",
                fail("error: attribute 'sonarr' missing, at /nix/store/xyz/services.nix:12:3"),
            ),
        ];
        answers.push(("package.version", ok("\"1.0\"")));
        answers.push(("ls-remote", ok(&format!("{CANDIDATE_REV}\tHEAD\n"))));
        answers.push((
            "flake metadata",
            ok(&serde_json::json!({"lastModified": 200, "revision": CANDIDATE_REV}).to_string()),
        ));
        let runner = FakeRunner::new(answers);
        let report = report_for(&runner, &f);

        let sonarr = report.apps.iter().find(|a| a.id == "sonarr").unwrap();
        assert_eq!(sonarr.state, AppState::EvaluationFailed);
        assert!(
            sonarr.error.as_deref().unwrap().contains("attribute 'sonarr' missing"),
            "the evaluator's own text must survive: {:?}",
            sonarr.error
        );
        // And the other apps are unaffected -- one app's failure must not
        // take the report down with it.
        assert_eq!(report.apps.len(), 7);
        assert_eq!(
            report.apps.iter().find(|a| a.id == "radarr").unwrap().state,
            AppState::UpToDate
        );
    }

    /// The one failure that would otherwise present as "this host has no
    /// apps".
    #[test]
    fn a_failed_app_set_evaluation_is_loud_rather_than_an_empty_app_list() {
        let f = fixture(1);
        let runner = FakeRunner::new(vec![
            ("ferrum.apps", fail("error: flake 'path:/etc/ferrum' does not provide it")),
            ("ferrum.schemaVersion", ok("1")),
        ]);
        let report = report_for(&runner, &f);
        assert!(report.apps.is_empty());
        assert!(report.apps_error.as_deref().unwrap().contains("does not provide"));
        assert!(
            report.warnings.iter().any(|w| w.contains("no app could be reported")),
            "{:?}",
            report.warnings
        );
    }

    /// R3: the settings-schema migration is in the SAME report, not a
    /// separate check.
    #[test]
    fn a_pending_schema_migration_rides_in_the_same_report() {
        let f = fixture(1);
        let runner = standard_runner();
        let report = report_for(&runner, &f);
        assert_eq!(report.schema_migration.current_version, Some(1));
        assert_eq!(report.schema_migration.target_version, Some(2));
        assert!(report.schema_migration.pending);
        assert!(report.schema_migration.note.is_none());
    }

    /// `preview-migration`'s monotonicity discipline, applied here: a
    /// target below the current version warns and is never "pending".
    #[test]
    fn a_module_tree_behind_the_on_disk_settings_warns_instead_of_claiming_a_migration() {
        let r = schema_migration_report(Some(4), Ok(2));
        assert!(!r.pending);
        assert!(r.note.as_deref().unwrap().contains("no migration will run"));
        assert!(schema_migration_report(Some(2), Ok(2)).note.is_none());
        assert!(!schema_migration_report(Some(2), Ok(2)).pending);
    }

    #[test]
    fn an_unevaluable_schema_version_carries_the_evaluators_text_and_is_not_pending() {
        let r = schema_migration_report(Some(1), Err("error: infinite recursion".to_string()));
        assert!(!r.pending);
        assert_eq!(r.target_version, None);
        assert!(r.error.as_deref().unwrap().contains("infinite recursion"));
    }

    /// The whole reason the candidate states are distinct values. A check
    /// that could not reach the candidate must not be readable as "up to
    /// date" by anything -- including a consumer that only looks at the
    /// serialized text, or at the one-line summary.
    #[test]
    fn a_report_whose_candidate_could_not_be_resolved_never_says_up_to_date() {
        let f = fixture(1);
        // Everything local answers; only the remote conversation fails.
        let runner = FakeRunner::new(vec![
            ("ferrum.apps", ok(app_set_json())),
            ("ferrum.schemaVersion", ok("2")),
            ("package.version", ok("\"1.0\"")),
            ("ls-remote", fail("fatal: Could not resolve host")),
        ]);
        let report = report_for(&runner, &f);
        assert_eq!(report.candidate.state, CandidateState::CheckFailed);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains(r#""state":"check-failed""#), "{json}");
        assert!(!json.contains("up-to-date"), "{json}");
        assert!(!summary_line(&report).contains("up to date"), "{}", summary_line(&report));
        assert!(
            summary_line(&report).contains("could not check for updates"),
            "{}",
            summary_line(&report)
        );
        // Anti-vacuity: the same assertions really can find "up-to-date"
        // when it is genuinely there.
        let mut up = report.clone();
        up.candidate.state = CandidateState::UpToDate;
        let json = serde_json::to_string(&up).unwrap();
        assert!(json.contains("up-to-date"), "{json}");
        assert!(summary_line(&up).contains("up to date"));
    }

    /// R1: ferrum's own version rides in the same report as the app rows,
    /// not as a separate check -- and both halves come from the one
    /// resolution, so they can never disagree with the candidate block.
    #[test]
    fn ferrums_own_current_and_candidate_version_ride_in_the_same_report() {
        let f = fixture(1);
        let runner = standard_runner();
        let report = report_for(&runner, &f);
        assert_eq!(report.candidate.state, CandidateState::UpdateAvailable);
        assert_eq!(report.ferrum.current_rev.as_deref(), Some(INSTALLED_REV));
        assert_eq!(report.ferrum.candidate_rev.as_deref(), Some(CANDIDATE_REV));
        assert_eq!(report.ferrum.current_version.as_deref(), Some("1111111"));
        assert_eq!(report.ferrum.candidate_version.as_deref(), Some("2222222"));
        assert_eq!(report.candidate.rev.as_deref(), report.ferrum.candidate_rev.as_deref());
    }

    /// The frozen wire contract. Two other lanes read this document, so the
    /// key set is pinned the way `/api/generations`'s is.
    #[test]
    fn the_report_document_has_exactly_the_keys_the_daemon_and_ui_were_promised() {
        let f = fixture(1);
        let runner = standard_runner();
        let report = report_for(&runner, &f);
        let value = serde_json::to_value(&report).unwrap();

        let mut top: Vec<&str> = value.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        top.sort_unstable();
        assert_eq!(
            top,
            vec![
                "apps", "appsError", "candidate", "checkedAt", "ferrum", "schemaMigration",
                "schemaVersion", "warnings"
            ]
        );

        let mut app: Vec<&str> = value["apps"][0].as_object().unwrap().keys().map(|s| s.as_str()).collect();
        app.sort_unstable();
        assert_eq!(
            app,
            vec!["candidateVersion", "currentVersion", "enabled", "error", "id", "reason", "state"]
        );

        let mut cand: Vec<&str> = value["candidate"].as_object().unwrap().keys().map(|s| s.as_str()).collect();
        cand.sort_unstable();
        assert_eq!(
            cand,
            vec![
                "currentLastModified", "currentRev", "error", "inputName", "inputUrl",
                "lastModified", "reference", "rev", "state"
            ]
        );

        let mut ferrum: Vec<&str> = value["ferrum"].as_object().unwrap().keys().map(|s| s.as_str()).collect();
        ferrum.sort_unstable();
        assert_eq!(
            ferrum,
            vec!["candidateRev", "candidateVersion", "currentRev", "currentVersion"]
        );

        let mut mig: Vec<&str> = value["schemaMigration"].as_object().unwrap().keys().map(|s| s.as_str()).collect();
        mig.sort_unstable();
        assert_eq!(mig, vec!["currentVersion", "error", "note", "pending", "targetVersion"]);

        assert_eq!(value["schemaVersion"], REPORT_SCHEMA_VERSION);
        assert_eq!(value["checkedAt"], 1_758_700_000u64);
    }

    /// R1/R3's read-only guarantee, proved rather than asserted: the two
    /// files the privilege boundary exists to protect are byte-identical
    /// across a whole check.
    ///
    /// Anti-vacuity: the same guard is then shown to really notice a write,
    /// so a guard that could never fire cannot pass this test.
    #[test]
    fn a_whole_check_leaves_flake_nix_and_flake_lock_byte_identical() {
        let f = fixture(1);
        let guard = ReadOnlyGuard::capture(&[&f.flake_nix, &f.flake_lock]);
        let runner = standard_runner();
        let _ = report_for(&runner, &f);
        assert!(
            guard.violations().is_empty(),
            "the check wrote to the operator's root-owned flake files: {:?}",
            guard.violations()
        );

        std::fs::write(&f.flake_lock, "{\"nodes\":{},\"version\":7,\"x\":1}\n").unwrap();
        let violations = guard.violations();
        assert_eq!(violations.len(), 1, "the guard must really notice a write: {violations:?}");
        assert!(violations[0].contains("flake.lock"));
    }

    /// A `flake.lock` that did not exist and now does is a write too.
    #[test]
    fn the_read_only_guard_notices_a_file_that_was_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flake.lock");
        let guard = ReadOnlyGuard::capture(&[&path]);
        assert!(guard.violations().is_empty());
        std::fs::write(&path, "{}").unwrap();
        assert_eq!(guard.violations().len(), 1);
    }

    #[test]
    fn the_report_file_sits_beside_the_jobs_own_progress_file() {
        assert_eq!(
            report_file_name(Some("6e2f7795-58c7-4654-82b6-f655b065ea47")),
            "6e2f7795-58c7-4654-82b6-f655b065ea47.update-check.json"
        );
        assert_eq!(report_file_name(None), "latest.update-check.json");
        assert_eq!(report_file_name(Some("")), "latest.update-check.json");
    }

    /// The report has to be readable by an unprivileged daemon, and must
    /// never be observable half-written.
    #[test]
    fn the_report_is_written_world_readable_and_only_appears_complete() {
        let f = fixture(1);
        let runner = standard_runner();
        let report = report_for(&runner, &f);
        let dir = tempfile::tempdir().unwrap();
        let path = write_report(dir.path(), "job.update-check.json", &report).unwrap();

        let round_tripped: UpdateReport =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(round_tripped, report, "the written document must be the report itself");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "ferrumd runs unprivileged and must be able to read it");
        }
        // The temporary file must not survive the rename.
        let leftovers: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "found: {leftovers:?}");
    }

    /// M2, at the sinks that actually leave this process: the published
    /// report document (written 0644 and served by an unprivileged
    /// daemon), the one-line summary that becomes the job's progress
    /// event, and every argv a root-privileged subprocess is handed.
    ///
    /// The operator put that token at the trust level of a root-only file;
    /// none of these three are at that level.
    #[test]
    fn a_credentialled_ferrum_input_reaches_no_report_no_summary_and_no_argv() {
        const TOKEN: &str = "ghp-S3CRET-cafebabe";
        let url = format!("git+https://ferrumbot:{TOKEN}@code.example/ferrum.git?ref=main");
        let f = fixture_with_url(1, &url);
        // Positive control: the credential really is in the file the check
        // reads, so the absences below are findings and not a broken match.
        let on_disk = std::fs::read_to_string(&f.flake_nix).unwrap();
        assert!(on_disk.contains(TOKEN), "the fixture carries no credential: {on_disk}");

        let runner = standard_runner();
        let report = report_for(&runner, &f);

        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(TOKEN), "the published report carries the credential: {json}");
        assert!(!json.contains("ferrumbot"), "the published report carries the account: {json}");
        let summary = summary_line(&report);
        assert!(!summary.contains(TOKEN), "the progress summary carries the credential: {summary}");
        let argvs = runner.argvs();
        assert!(!argvs.is_empty(), "the check ran no command at all");
        for argv in &argvs {
            let joined = argv.join(" ");
            assert!(!joined.contains(TOKEN), "a root-privileged argv carries it: {joined}");
        }

        // And the same again on the failure path, where the error text is
        // built from the remote's own words.
        let stderr = format!("fatal: could not read Username for '{url}'");
        let runner = FakeRunner::new(vec![
            ("ferrum.apps", ok(app_set_json())),
            ("ferrum.schemaVersion", ok("2")),
            ("package.version", ok("\"1.0\"")),
            ("ls-remote", fail(&stderr)),
        ]);
        let report = report_for(&runner, &f);
        assert_eq!(report.candidate.state, CandidateState::CheckFailed);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains(TOKEN), "the failed-check report carries the credential: {json}");
        let summary = summary_line(&report);
        assert!(!summary.contains(TOKEN), "the failed-check summary carries it: {summary}");
    }
}
