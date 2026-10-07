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

/// The last-sync record path this host should use.
///
/// `FERRUM_PARITY_LAST_SYNC` first for the same reason [`conf_path`] takes
/// an override: a VM test needs to point at a fixture.
///
/// # Returns
/// The path to read. Never fails: the fallback is a constant.
pub fn last_sync_path() -> PathBuf {
    std::env::var("FERRUM_PARITY_LAST_SYNC")
        .unwrap_or_else(|_| LAST_SYNC_FILE.to_string())
        .into()
}

/// Seconds since the Unix epoch, now.
///
/// # Returns
/// The current time, or `0` if the system clock is before the epoch -- which
/// only makes `elapsedSeconds` saturate at zero rather than panicking.
pub fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// R4: staleness. The figure PMS structurally cannot give a reader, because
// PMS is documentation and does not run on the box.
// ---------------------------------------------------------------------------

/// Where `modules/core/parity.nix` records the result of each completed sync.
///
/// WHY FERRUM RECORDS THIS AT ALL, rather than asking snapraid. `snapraid
/// status` does not report a wall-clock last-sync time: it reports "days ago
/// of the last scrub/sync" as a histogram and a sentence ("The oldest block
/// was scrubbed N days ago, the median N, the newest N"), at DAY resolution
/// and about blocks rather than about a run. Confirmed against snapraid 12.4
/// by running it on a freshly-synced array. A dashboard that said "last
/// synced 0 days ago" would be exactly the frozen gauge this requirement
/// exists to prevent, so the timestamp comes from the one place that knows
/// it exactly: an `ExecStopPost` on the sync unit, which systemd runs
/// whether the sync succeeded or failed.
pub const LAST_SYNC_FILE: &str = "/var/lib/ferrum/parity/last-sync";

/// The schema version of the document this module writes.
///
/// Carried in the document itself so a ferrumd that is newer or older than
/// the `ferrum-apply` which produced a report can say so, rather than
/// silently misreading fields.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// The sentence that travels with every healthy parity report (R6).
///
/// It is a constant rather than UI copy because the requirement is that
/// EVERY surface reporting a protected state carries it -- a string each
/// surface wrote for itself would be free to drift, and the one that drifted
/// would be the one an operator read before trusting parity with something
/// it cannot do. The word "backup" is deliberately absent: parity is not one,
/// and naming it even to deny it is how the association gets made.
pub const LIMITATION: &str =
    "Parity protects against a single local disk failing. It does not undo a \
     deletion, it does not survive a corruption that was synced before anyone \
     noticed, and it does not survive ransomware, fire or theft -- the parity \
     disk is in the same machine.";

/// What ferrum can say about parity on this host right now.
///
/// Every one of these is a distinct, NAMED fact rather than something a
/// caller infers from a bare timestamp, which is the whole point of the
/// requirement: "it says protected" must never be able to mean something
/// different from "it is protected right now". In particular
/// [`ParityState::NotConfigured`], [`ParityState::NeverSynced`],
/// [`ParityState::LastSyncFailed`] and [`ParityState::Unknown`] are four
/// different things, and collapsing any pair of them would let a check that
/// could not run read like a clean result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ParityState {
    /// No parity on this host. Not an error, and not a 404: an explicit
    /// answer, so the UI can offer to set it up rather than showing nothing.
    NotConfigured,
    /// Parity is configured and a sync is running right now.
    Syncing,
    /// Configured, but ferrum has no record of a sync ever completing.
    NeverSynced,
    /// The last recorded sync did not succeed. Distinct from
    /// [`ParityState::NeverSynced`] and from [`ParityState::Stale`]: a failed
    /// run is a thing to act on, an old successful one is a thing to watch.
    LastSyncFailed,
    /// A parity disk is missing from this host. Sharper than stale, and
    /// deliberately separate: a dead parity disk protects nothing no matter
    /// how recent the last sync was.
    ParityDiskMissing,
    /// Synced, and nothing has changed since.
    InSync,
    /// Synced, but files have changed since -- those files are unprotected.
    Stale,
    /// Parity is configured and ferrum could not find out. Never reported as
    /// any of the above.
    Unknown,
}

/// The counts `snapraid diff` reports, in FILES.
///
/// Files, not bytes, and that is a limitation of the tool rather than a
/// choice: `snapraid diff` prints a fixed block of seven counts and no size
/// figure anywhere. Measured against snapraid 12.4. The spec asked for "an
/// approximate count/size"; the count is available and the size is not, so
/// the size is reported as unavailable with a reason instead of being
/// invented from file counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DiffCounts {
    pub equal: u64,
    pub added: u64,
    pub removed: u64,
    pub updated: u64,
    pub moved: u64,
    pub copied: u64,
    pub restored: u64,
}

impl DiffCounts {
    /// How many files are not covered by the last sync.
    ///
    /// `moved` and `copied` are excluded on purpose: snapraid resolves both
    /// against data it already holds, so neither is unprotected content.
    ///
    /// # Returns
    /// The count of added, removed and updated files.
    pub fn unprotected_files(&self) -> u64 {
        self.added + self.removed + self.updated
    }
}

/// The record `modules/core/parity.nix`'s `ExecStopPost` writes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LastSync {
    /// Seconds since the Unix epoch. Epoch seconds rather than a formatted
    /// timestamp because that is this workspace's existing idiom
    /// (`address_history`, `update_check`) and needs no new dependency.
    #[serde(rename = "finishedAt")]
    pub finished_at: u64,
    /// systemd's own `$SERVICE_RESULT` for the run: `success`, `exit-code`,
    /// `signal`, `timeout`, and so on. Kept verbatim rather than mapped to a
    /// boolean, so the report can say WHY.
    pub result: String,
}

impl LastSync {
    /// Did this run succeed?
    ///
    /// # Returns
    /// `true` only for systemd's `success` result.
    pub fn succeeded(&self) -> bool {
        self.result == "success"
    }
}

/// The whole document `GET /api/parity` serves.
///
/// Every derived number travels in the same object as the timestamp and the
/// state it was computed from -- there is no separately-fetchable "elapsed"
/// or "files changed", by construction. That is the requirement, and it is
/// enforced by this type having no sub-struct a caller could request alone.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParityReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub state: ParityState,
    /// When this document was produced. Always present: a report with no
    /// generation time is a frozen gauge waiting to happen.
    #[serde(rename = "generatedAt")]
    pub generated_at: u64,
    /// The last recorded sync, or `None` when there has never been one.
    #[serde(rename = "lastSync")]
    pub last_sync: Option<LastSync>,
    /// Seconds between the last sync finishing and this document. `None`
    /// exactly when `last_sync` is `None`.
    #[serde(rename = "elapsedSeconds")]
    pub elapsed_seconds: Option<u64>,
    /// What has changed since the last sync, or `None` when it could not be
    /// determined -- in which case `unprotectedUnavailable` says why.
    pub unprotected: Option<DiffCounts>,
    #[serde(rename = "unprotectedUnavailable")]
    pub unprotected_unavailable: Option<String>,
    /// Why no byte figure is reported. Always present and always the same
    /// sentence: a field that was sometimes absent would read, to a UI, as
    /// "sometimes there IS a byte figure".
    #[serde(rename = "unprotectedBytesUnavailable")]
    pub unprotected_bytes_unavailable: String,
    /// Each configured parity disk and whether its mount point is there.
    #[serde(rename = "parityDisks")]
    pub parity_disks: Vec<ParityDisk>,
    /// R6, carried in the document so every surface renders the same words.
    pub limitation: String,
}

/// One configured parity disk, and whether it is actually present.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParityDisk {
    /// The parity FILE's path, exactly as `/etc/snapraid.conf` names it.
    pub path: String,
    /// Whether the directory that file lives in exists. A `nofail` mount
    /// that did not come up leaves an empty mount point behind, so this is
    /// checked against the parity file's own directory rather than against
    /// the file, which does not exist before the first sync either.
    pub present: bool,
}

/// The sentence that explains the missing byte figure, everywhere.
const BYTES_UNAVAILABLE: &str =
    "snapraid reports changes as file counts only; it has no byte figure, so none \
     is shown rather than estimated.";

/// Parses the fixed count block `snapraid diff` prints.
///
/// The block looks like this and has been stable for many releases:
///
/// ```text
///        1 equal
///        2 added
///        1 removed
/// ```
///
/// # Arguments
/// * `stdout` - the captured standard output of `snapraid diff`.
///
/// # Returns
/// The counts, or `None` when the output contains none of the expected
/// labels -- which is "we could not read it", never a zeroed struct. A
/// zeroed default here would render as "nothing has changed", which is the
/// exact inversion this requirement forbids.
pub fn parse_diff(stdout: &str) -> Option<DiffCounts> {
    let mut counts = DiffCounts::default();
    let mut seen = false;
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let (Some(n), Some(label), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let Ok(n) = n.parse::<u64>() else { continue };
        let slot = match label {
            "equal" => &mut counts.equal,
            "added" => &mut counts.added,
            "removed" => &mut counts.removed,
            "updated" => &mut counts.updated,
            "moved" => &mut counts.moved,
            "copied" => &mut counts.copied,
            "restored" => &mut counts.restored,
            _ => continue,
        };
        *slot = n;
        seen = true;
    }
    if seen {
        Some(counts)
    } else {
        None
    }
}

/// Reads the last-sync record `ExecStopPost` wrote.
///
/// The file is two lines -- epoch seconds, then systemd's `$SERVICE_RESULT`
/// -- written to a temporary name and renamed into place, so a reader never
/// sees half of one.
///
/// # Arguments
/// * `path` - normally [`LAST_SYNC_FILE`].
///
/// # Returns
/// The record, or `None` when the file is absent or unreadable as that
/// shape. Unreadable is deliberately the same answer as absent here: both
/// mean "ferrum has no record of a completed sync", and the state machine
/// below turns that into `NeverSynced` rather than into a success.
pub fn read_last_sync(path: &Path) -> Option<LastSync> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut lines = text.lines();
    let finished_at = lines.next()?.trim().parse::<u64>().ok()?;
    let result = lines.next()?.trim().to_string();
    if result.is_empty() {
        return None;
    }
    Some(LastSync { finished_at, result })
}

/// Pulls the parity file paths out of a generated `/etc/snapraid.conf`.
///
/// Read from the FILE rather than from `settings.json`, for the same reason
/// [`SNAPRAID_CONF`]'s own documentation gives: the file is what snapraid
/// acted on, and a second reader of the settings document could disagree
/// with it after an edit that has not been applied.
///
/// # Arguments
/// * `conf` - the contents of `/etc/snapraid.conf`.
///
/// # Returns
/// Every `parity` / `N-parity` path, in file order.
pub fn parity_paths(conf: &str) -> Vec<String> {
    conf.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let keyword = parts.next()?;
            let is_parity = keyword == "parity"
                || (keyword.ends_with("-parity")
                    && keyword
                        .trim_end_matches("-parity")
                        .parse::<u8>()
                        .is_ok());
            if is_parity {
                parts.next().map(str::to_string)
            } else {
                None
            }
        })
        .collect()
}

/// Everything the report needs that this module cannot compute itself.
pub struct StatusInputs<'a> {
    /// The generated snapraid configuration path.
    pub conf: &'a Path,
    /// Where `ExecStopPost` records completed syncs.
    pub last_sync_file: &'a Path,
    /// Seconds since the Unix epoch, now.
    pub now: u64,
}

/// Builds the parity status document.
///
/// Runs exactly two subprocesses and only when they can mean something:
/// `systemctl is-active` (is a sync running right now?) and `snapraid diff`
/// (what has changed since the last one?). A host with no parity runs
/// neither, which is what makes `NotConfigured` an answer rather than an
/// inference from a failure.
///
/// LIVE QUERY RATHER THAN A MARKER for "is it running", and that choice is
/// what answers the spec's "host rebooted mid-sync" edge case exactly: a
/// unit is not active after a reboot, so the state resolves to a terminal
/// one on its own, with no timeout heuristic and no marker that could stick
/// at "in progress" forever.
///
/// # Arguments
/// * `inputs` - paths and the current time.
/// * `runner` - the command seam.
///
/// # Returns
/// The document. Never fails: every way of not knowing is a named state.
pub fn build_report(inputs: &StatusInputs, runner: &dyn CommandRunner) -> ParityReport {
    let base = |state: ParityState| ParityReport {
        schema_version: REPORT_SCHEMA_VERSION,
        state,
        generated_at: inputs.now,
        last_sync: None,
        elapsed_seconds: None,
        unprotected: None,
        unprotected_unavailable: None,
        unprotected_bytes_unavailable: BYTES_UNAVAILABLE.to_string(),
        parity_disks: Vec::new(),
        limitation: LIMITATION.to_string(),
    };

    let Ok(conf_text) = std::fs::read_to_string(inputs.conf) else {
        return base(ParityState::NotConfigured);
    };

    let parity_disks: Vec<ParityDisk> = parity_paths(&conf_text)
        .into_iter()
        .map(|path| {
            // The DIRECTORY, not the file: before the first sync the parity
            // file does not exist on a perfectly healthy disk, so testing for
            // it would report every fresh install as a dead parity disk.
            let present = Path::new(&path).parent().is_some_and(Path::is_dir);
            ParityDisk { path, present }
        })
        .collect();

    let last_sync = read_last_sync(inputs.last_sync_file);
    let elapsed_seconds = last_sync
        .as_ref()
        .map(|s| inputs.now.saturating_sub(s.finished_at));

    let running = matches!(
        runner.run("systemctl", &["is-active".into(), SYNC_UNIT.into()]),
        Ok(ref out) if matches!(out.stdout.trim(), "active" | "activating" | "reloading")
    );

    let (unprotected, unprotected_unavailable) = if running {
        // Deliberately not run during a sync: the array is being rewritten
        // underneath it, so any answer would be about a moment that has
        // already passed.
        (
            None,
            Some("a sync is running, so what has changed is not yet settled".to_string()),
        )
    } else {
        match runner.run("snapraid", &["-c".into(), conf_path_arg(inputs.conf), "diff".into()]) {
            Err(e) => (None, Some(e)),
            // `snapraid diff` exits 2 when there ARE differences and 0 when
            // there are none -- confirmed against 12.4 -- so a non-zero exit
            // is not on its own a failure and the counts are parsed either
            // way. What decides is whether the count block is there at all.
            Ok(out) => match parse_diff(&out.stdout) {
                Some(c) => (Some(c), None),
                None => (
                    None,
                    Some(if out.stderr.trim().is_empty() {
                        "snapraid diff produced no recognisable summary".to_string()
                    } else {
                        out.stderr.trim().to_string()
                    }),
                ),
            },
        }
    };

    // Order matters and is the requirement's own ordering of severity. A
    // missing parity disk outranks everything below it: a dead parity disk
    // protects nothing however recent the last sync was.
    let state = if parity_disks.iter().any(|d| !d.present) {
        ParityState::ParityDiskMissing
    } else if running {
        ParityState::Syncing
    } else {
        match (&last_sync, unprotected) {
            (None, _) => ParityState::NeverSynced,
            (Some(s), _) if !s.succeeded() => ParityState::LastSyncFailed,
            (Some(_), None) => ParityState::Unknown,
            (Some(_), Some(c)) if c.unprotected_files() == 0 => ParityState::InSync,
            (Some(_), Some(_)) => ParityState::Stale,
        }
    };

    ParityReport {
        state,
        last_sync,
        elapsed_seconds,
        unprotected,
        unprotected_unavailable,
        parity_disks,
        ..base(state)
    }
}

/// The `-c` argument for a snapraid invocation.
fn conf_path_arg(conf: &Path) -> String {
    conf.to_string_lossy().into_owned()
}

/// The report document's filename for a given job id.
///
/// Sits beside that job's own `<id>.jsonl` progress file, exactly as
/// `update_check::report_file_name` does and for the same reason: ferrumd
/// finds it by the id it already holds, so no second identifier has to be
/// kept in step.
///
/// # Arguments
/// * `job_id` - `$FERRUM_JOB_ID`, when this run was dispatched by ferrumd.
///
/// # Returns
/// The filename to publish at.
pub fn report_file_name(job_id: Option<&str>) -> String {
    match job_id.filter(|id| !id.is_empty()) {
        Some(id) => format!("{id}.parity-status.json"),
        None => "latest.parity-status.json".to_string(),
    }
}

/// Where parity reports are published.
///
/// `FERRUM_PARITY_REPORT_DIR` first so the reports can be moved off the jobs
/// directory later without touching either side, `FERRUM_JOBS_DIR` second
/// because that is where they go today, and the same
/// `/var/lib/ferrum/jobs` default both other readers carry so none of the
/// three can disagree about where a job's artefacts are.
///
/// # Returns
/// The directory to write to. Never fails: every step has a default.
pub fn report_dir() -> PathBuf {
    std::env::var("FERRUM_PARITY_REPORT_DIR")
        .or_else(|_| std::env::var("FERRUM_JOBS_DIR"))
        .unwrap_or_else(|_| "/var/lib/ferrum/jobs".to_string())
        .into()
}

/// Writes the report where ferrumd can read it, readable by the `ferrum`
/// group.
///
/// Written to a pid-suffixed temporary name and renamed, so a reader that
/// arrives mid-write sees the previous complete document or the new complete
/// one, never a truncated one. Identical discipline to
/// `update_check::write_report`, including the reason for the pid: two
/// operators running this by hand at once would otherwise share one
/// `latest.parity-status.json.tmp`.
///
/// # Arguments
/// * `dir` - the report directory, created if absent.
/// * `file_name` - from [`report_file_name`].
/// * `report` - the document to publish.
///
/// # Returns
/// The path the report was published at.
///
/// # Errors
/// Any I/O failure creating the directory, writing, setting the mode or
/// renaming, and a serialization failure as `InvalidData`.
pub fn write_report(
    dir: &Path,
    file_name: &str,
    report: &ParityReport,
) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let final_path = dir.join(file_name);
    let temp_path = dir.join(format!("{file_name}.{}.tmp", std::process::id()));
    let body = serde_json::to_string(report)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&temp_path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Written by root, read by the unprivileged daemon. 0644 is not
        // world-readable in practice: the directory is 0750 ferrum:ferrum
        // (modules/core/daemon.nix).
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&temp_path, &final_path)?;
    Ok(final_path)
}

/// One operator-facing line naming the state and the figure behind it.
///
/// Never says a healthy word for an unhealthy state, and never reports a
/// count without the state it belongs to.
///
/// # Arguments
/// * `report` - the finished document.
///
/// # Returns
/// A single line, safe to log.
pub fn summary_line(report: &ParityReport) -> String {
    let age = match report.elapsed_seconds {
        Some(s) => format!("last sync {}h ago", s / 3600),
        None => "no sync recorded".to_string(),
    };
    match report.state {
        ParityState::NotConfigured => "parity is not configured on this host".to_string(),
        ParityState::Syncing => "a parity sync is running".to_string(),
        ParityState::NeverSynced => {
            "parity is configured but has never completed a sync, so nothing is protected yet"
                .to_string()
        }
        ParityState::LastSyncFailed => {
            let why = report
                .last_sync
                .as_ref()
                .map(|s| s.result.clone())
                .unwrap_or_else(|| "unknown".to_string());
            format!("the last parity sync did not succeed ({why}); {age}")
        }
        ParityState::ParityDiskMissing => {
            let missing: Vec<&str> = report
                .parity_disks
                .iter()
                .filter(|d| !d.present)
                .map(|d| d.path.as_str())
                .collect();
            format!(
                "a parity disk is missing ({}), so parity cannot protect anything; {age}",
                missing.join(", ")
            )
        }
        ParityState::InSync => format!("parity is current; {age}"),
        ParityState::Stale => {
            let n = report
                .unprotected
                .map(|c| c.unprotected_files())
                .unwrap_or(0);
            format!("{n} file(s) have changed since the last parity sync and are unprotected; {age}")
        }
        ParityState::Unknown => {
            let why = report
                .unprotected_unavailable
                .clone()
                .unwrap_or_else(|| "no reason recorded".to_string());
            format!("parity status could not be determined: {why}; {age}")
        }
    }
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

    // -------------------------------------------------------------------
    // R4: staleness
    // -------------------------------------------------------------------

    /// Real `snapraid diff` output, captured verbatim from snapraid 12.4
    /// running against four loop-mounted ext4 disks in the same four-disk
    /// shape ferrum generates. A hand-written approximation here would make
    /// every assertion below a test of the approximation.
    const REAL_DIFF_WITH_CHANGES: &str = "\
Loading state from /tmp/sr/c2/snapraid.content...
Comparing...
update media/tv/show-s01e01.mkv
add media/tv/show-s01e02.mkv
add media/movies/film2.mkv
remove media/movies/film.mkv

       1 equal
       2 added
       1 removed
       1 updated
       0 moved
       0 copied
       0 restored
There are differences!
";

    /// The same command on a clean array -- captured from the same run.
    const REAL_DIFF_CLEAN: &str = "\
Loading state from /tmp/sr/c2/snapraid.content...
Comparing...

       3 equal
       0 added
       0 removed
       0 updated
       0 moved
       0 copied
       0 restored
No differences
";

    struct ScriptedRunner {
        responses: RefCell<Vec<(String, Result<CommandOutput, String>)>>,
        calls: RefCell<Vec<String>>,
    }

    impl ScriptedRunner {
        /// `active` is what `systemctl is-active` prints; `diff` is the
        /// `snapraid diff` reply, or `None` to make the spawn itself fail.
        fn new(active: &str, diff: Option<&str>) -> Self {
            let mut responses = vec![(
                "systemctl".to_string(),
                Ok(CommandOutput {
                    success: active == "active",
                    stdout: format!("{active}\n"),
                    stderr: String::new(),
                }),
            )];
            responses.push((
                "snapraid".to_string(),
                match diff {
                    Some(d) => Ok(CommandOutput {
                        success: false,
                        stdout: d.to_string(),
                        stderr: String::new(),
                    }),
                    None => Err("failed to run snapraid: No such file".to_string()),
                },
            ));
            Self { responses: RefCell::new(responses), calls: RefCell::new(Vec::new()) }
        }
    }

    impl CommandRunner for ScriptedRunner {
        fn run(&self, program: &str, _args: &[String]) -> Result<CommandOutput, String> {
            self.calls.borrow_mut().push(program.to_string());
            let responses = self.responses.borrow();
            let found = responses.iter().find(|(p, _)| p == program);
            match found {
                Some((_, Ok(o))) => Ok(o.clone()),
                Some((_, Err(e))) => Err(e.clone()),
                None => Err(format!("unscripted program {program}")),
            }
        }
    }

    /// A configured host with a parity disk directory and (optionally) a
    /// recorded last sync.
    fn fixture(last_sync: Option<(&str, &str)>) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let parity_dir = dir.path().join("parity");
        std::fs::create_dir_all(&parity_dir).unwrap();
        let conf = dir.path().join("snapraid.conf");
        std::fs::write(
            &conf,
            format!(
                "data d0 /mnt/a\ndata d1 /mnt/b\nparity {}/snapraid.parity\n\
                 content /var/lib/ferrum/snapraid/snapraid.content\nexclude /torrents/\n",
                parity_dir.display()
            ),
        )
        .unwrap();
        let last = dir.path().join("last-sync");
        if let Some((at, result)) = last_sync {
            std::fs::write(&last, format!("{at}\n{result}\n")).unwrap();
        }
        (dir, conf, last)
    }

    fn report(
        conf: &Path,
        last: &Path,
        now: u64,
        runner: &dyn CommandRunner,
    ) -> ParityReport {
        build_report(&StatusInputs { conf, last_sync_file: last, now }, runner)
    }

    /// The counts come out of real snapraid output, and an output with no
    /// count block is "we could not read it" rather than a zeroed struct.
    ///
    /// The second half is the load-bearing one: `DiffCounts::default()` would
    /// render as "nothing has changed", which is the exact inversion this
    /// requirement forbids.
    #[test]
    fn the_diff_block_parses_and_an_unreadable_one_is_not_zero() {
        let c = parse_diff(REAL_DIFF_WITH_CHANGES).expect("real output parses");
        assert_eq!(
            c,
            DiffCounts {
                equal: 1,
                added: 2,
                removed: 1,
                updated: 1,
                moved: 0,
                copied: 0,
                restored: 0
            }
        );
        assert_eq!(c.unprotected_files(), 4);

        let clean = parse_diff(REAL_DIFF_CLEAN).expect("real output parses");
        assert_eq!(clean.unprotected_files(), 0);
        assert_eq!(clean.equal, 3);

        assert!(parse_diff("snapraid: command not found").is_none());
        assert!(parse_diff("").is_none());
    }

    /// `moved` and `copied` are not unprotected content: snapraid resolves
    /// both against data it already holds.
    #[test]
    fn moved_and_copied_files_are_not_counted_as_unprotected() {
        let c = DiffCounts { moved: 9, copied: 9, ..Default::default() };
        assert_eq!(c.unprotected_files(), 0);
    }

    /// A host with no parity says so explicitly, and runs nothing at all.
    #[test]
    fn an_unconfigured_host_is_its_own_state_and_spawns_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let runner = ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN));
        let r = report(
            &dir.path().join("absent.conf"),
            &dir.path().join("absent"),
            1000,
            &runner,
        );
        assert_eq!(r.state, ParityState::NotConfigured);
        assert!(runner.calls.borrow().is_empty());
        assert!(r.last_sync.is_none());
        assert!(r.elapsed_seconds.is_none());
    }

    /// Configured, never synced -- distinct from both "in sync" and "failed".
    #[test]
    fn a_configured_host_with_no_recorded_sync_is_never_synced() {
        let (_d, conf, last) = fixture(None);
        let r = report(
            &conf,
            &last,
            1000,
            &ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN)),
        );
        assert_eq!(r.state, ParityState::NeverSynced);
        assert!(r.last_sync.is_none());
        assert!(
            r.elapsed_seconds.is_none(),
            "an elapsed time with no timestamp to compute it from"
        );
    }

    /// A clean array with a successful sync behind it, and the elapsed time
    /// travelling in the same object as the timestamp it came from.
    #[test]
    fn a_synced_unchanged_array_is_in_sync_with_a_real_elapsed_time() {
        let (_d, conf, last) = fixture(Some(("1000", "success")));
        let r = report(
            &conf,
            &last,
            4600,
            &ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN)),
        );
        assert_eq!(r.state, ParityState::InSync);
        assert_eq!(r.last_sync.as_ref().unwrap().finished_at, 1000);
        assert_eq!(r.elapsed_seconds, Some(3600));
        assert_eq!(r.unprotected.unwrap().unprotected_files(), 0);
    }

    /// Changes since the last sync make the array stale, with the figure.
    #[test]
    fn changed_files_since_the_last_sync_make_the_array_stale() {
        let (_d, conf, last) = fixture(Some(("1000", "success")));
        let r = report(
            &conf,
            &last,
            2000,
            &ScriptedRunner::new("inactive", Some(REAL_DIFF_WITH_CHANGES)),
        );
        assert_eq!(r.state, ParityState::Stale);
        assert_eq!(r.unprotected.unwrap().unprotected_files(), 4);
        assert_eq!(r.elapsed_seconds, Some(1000));
    }

    /// A sync that failed is its own state, never "stale" and never
    /// "never synced", and the report keeps systemd's own word for why.
    #[test]
    fn a_failed_sync_is_distinguishable_from_stale_and_from_never_synced() {
        let (_d, conf, last) = fixture(Some(("1000", "exit-code")));
        let r = report(
            &conf,
            &last,
            2000,
            &ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN)),
        );
        assert_eq!(r.state, ParityState::LastSyncFailed);
        assert_eq!(r.last_sync.as_ref().unwrap().result, "exit-code");
        assert!(!r.last_sync.as_ref().unwrap().succeeded());
    }

    /// A sync in progress is a live query, so a host that rebooted mid-sync
    /// resolves to a terminal state rather than sticking at "in progress".
    #[test]
    fn a_running_sync_is_reported_live_and_does_not_outlive_the_unit() {
        let (_d, conf, last) = fixture(Some(("1000", "success")));

        let running = report(
            &conf,
            &last,
            2000,
            &ScriptedRunner::new("activating", Some(REAL_DIFF_CLEAN)),
        );
        assert_eq!(running.state, ParityState::Syncing);
        assert!(
            running.unprotected.is_none() && running.unprotected_unavailable.is_some(),
            "a figure measured mid-rewrite is about a moment that has passed"
        );

        // The same fixture, with the unit no longer active -- which is what a
        // reboot leaves behind. Nothing is sticky.
        let after = report(
            &conf,
            &last,
            2000,
            &ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN)),
        );
        assert_ne!(after.state, ParityState::Syncing);
    }

    /// A missing parity disk outranks staleness: a dead parity disk protects
    /// nothing however recent the last sync was.
    #[test]
    fn a_missing_parity_disk_outranks_a_recent_successful_sync() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("snapraid.conf");
        std::fs::write(
            &conf,
            "data d0 /mnt/a\nparity /definitely/not/here/snapraid.parity\n",
        )
        .unwrap();
        let last = dir.path().join("last-sync");
        std::fs::write(&last, "1990\nsuccess\n").unwrap();

        let r = report(
            &conf,
            &last,
            2000,
            &ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN)),
        );
        assert_eq!(r.state, ParityState::ParityDiskMissing);
        assert_eq!(r.parity_disks.len(), 1);
        assert!(!r.parity_disks[0].present);
    }

    /// A parity disk whose file does not exist YET is healthy -- the file is
    /// created by the first sync. Without this, every fresh install would
    /// report a dead parity disk.
    #[test]
    fn a_parity_disk_with_no_parity_file_yet_is_still_present() {
        let (_d, conf, last) = fixture(None);
        let r = report(
            &conf,
            &last,
            2000,
            &ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN)),
        );
        assert!(r.parity_disks[0].present);
        assert_eq!(r.state, ParityState::NeverSynced);
    }

    /// snapraid not answering is `Unknown` with a reason -- never `InSync`.
    #[test]
    fn a_check_that_could_not_run_never_reads_as_a_clean_result() {
        let (_d, conf, last) = fixture(Some(("1000", "success")));
        let r = report(&conf, &last, 2000, &ScriptedRunner::new("inactive", None));
        assert_eq!(r.state, ParityState::Unknown);
        assert!(r.unprotected.is_none());
        assert!(r
            .unprotected_unavailable
            .as_deref()
            .is_some_and(|s| s.contains("snapraid")));
    }

    /// The parity file paths are read out of the generated configuration,
    /// including the numbered forms for multi-parity hosts.
    #[test]
    fn every_parity_level_is_read_out_of_the_generated_config() {
        let conf = "data d0 /mnt/a\n\
                    parity /mnt/p0/snapraid.parity\n\
                    2-parity /mnt/p1/snapraid.2-parity\n\
                    content /var/lib/ferrum/snapraid/snapraid.content\n\
                    exclude /torrents/\n";
        assert_eq!(
            parity_paths(conf),
            vec![
                "/mnt/p0/snapraid.parity".to_string(),
                "/mnt/p1/snapraid.2-parity".to_string()
            ]
        );
        // `content` and `data` lines are not parity lines, and nothing that
        // merely ends in "-parity" without a level number is either.
        assert!(parity_paths("content /x\ndata d0 /y\nx-parity /z\n").is_empty());
    }

    /// A truncated or half-written record is "no record", never a success.
    #[test]
    fn a_malformed_last_sync_record_is_treated_as_no_record() {
        let dir = tempfile::tempdir().unwrap();
        for body in ["", "notanumber\nsuccess\n", "1000\n", "1000\n\n"] {
            let p = dir.path().join("ls");
            std::fs::write(&p, body).unwrap();
            assert!(read_last_sync(&p).is_none(), "accepted {body:?}");
        }
        let p = dir.path().join("ls");
        std::fs::write(&p, "1000\nsuccess\n").unwrap();
        assert_eq!(
            read_last_sync(&p),
            Some(LastSync { finished_at: 1000, result: "success".into() })
        );
    }

    /// R6. Every report carries the limitation, and no report anywhere uses
    /// the word "backup" to describe parity.
    #[test]
    fn every_report_states_the_limitation_and_never_says_backup() {
        let (_d, conf, last) = fixture(Some(("1000", "success")));
        let states = [
            report(&conf, &last, 2000, &ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN))),
            report(&conf, &last, 2000, &ScriptedRunner::new("activating", Some(REAL_DIFF_CLEAN))),
            report(&conf, &last, 2000, &ScriptedRunner::new("inactive", None)),
            report(
                &conf,
                &last,
                2000,
                &ScriptedRunner::new("inactive", Some(REAL_DIFF_WITH_CHANGES)),
            ),
        ];
        for r in &states {
            assert_eq!(r.limitation, LIMITATION);
            assert!(r.limitation.contains("single local disk"));
            let body = serde_json::to_string(r).unwrap().to_lowercase();
            assert!(
                !body.contains("backup"),
                "a parity report used the word 'backup': {body}"
            );
        }
    }

    /// No derived number is ever returned without the thing it was derived
    /// from, in the same object.
    #[test]
    fn no_derived_number_travels_without_its_timestamp() {
        let (_d, conf, last) = fixture(Some(("1000", "success")));
        for runner in [
            ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN)),
            ScriptedRunner::new("activating", Some(REAL_DIFF_CLEAN)),
            ScriptedRunner::new("inactive", None),
        ] {
            let r = report(&conf, &last, 9000, &runner);
            assert_eq!(
                r.elapsed_seconds.is_some(),
                r.last_sync.is_some(),
                "elapsed and lastSync must appear and disappear together: {r:?}"
            );
            assert!(r.generated_at > 0, "a report with no generation time");
            assert_eq!(
                r.unprotected.is_none(),
                r.unprotected_unavailable.is_some(),
                "either the figure or the reason it is missing, never neither \
                 and never both: {r:?}"
            );
        }
    }

    /// The byte figure is absent and the reason is ALWAYS carried, so a UI
    /// can never read a missing explanation as "there is a figure here".
    #[test]
    fn the_absent_byte_figure_always_carries_its_reason() {
        let (_d, conf, last) = fixture(Some(("1000", "success")));
        let r = report(&conf, &last, 2000, &ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN)));
        assert!(r.unprotected_bytes_unavailable.contains("file counts only"));
        let dir = tempfile::tempdir().unwrap();
        let none = report(
            &dir.path().join("absent.conf"),
            &dir.path().join("absent"),
            2000,
            &ScriptedRunner::new("inactive", Some(REAL_DIFF_CLEAN)),
        );
        assert_eq!(
            none.unprotected_bytes_unavailable, r.unprotected_bytes_unavailable,
            "the explanation must not depend on the state"
        );
    }

    /// Every state the module can produce is reachable, and they are all
    /// distinct on the wire. A state nothing can reach is a branch the UI
    /// renders and an operator never sees.
    #[test]
    fn every_state_serializes_to_its_own_distinct_wire_name() {
        let all = [
            ParityState::NotConfigured,
            ParityState::Syncing,
            ParityState::NeverSynced,
            ParityState::LastSyncFailed,
            ParityState::ParityDiskMissing,
            ParityState::InSync,
            ParityState::Stale,
            ParityState::Unknown,
        ];
        let mut names: Vec<String> = all
            .iter()
            .map(|s| serde_json::to_string(s).unwrap())
            .collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(before, names.len(), "two states share a wire name: {names:?}");
        assert!(names.contains(&"\"in-sync\"".to_string()), "{names:?}");
    }
}
