// Advancing the host's pin: the only writer in the update feature, and the
// whole of R2's privileged boundary.
//
// What this module may touch, and nothing else: /etc/ferrum/flake.lock.
// `flake.nix` is the file the security thesis protects -- it is where the
// repository and the ref come from, it is root-owned, ferrumd cannot write
// it, and the Technical Architect's resolution of Open Question 1 is that a
// pin advance never rewrites it. That is enforced here rather than promised:
// its bytes are captured before the advance and compared afterwards, and a
// difference restores the lock and fails the job.
//
// Where the mechanism came from. `nix flake lock --update-input ferrum` is a
// first-class Nix command whose entire job is this operation; the rejected
// alternative was root-privileged source-text mutation of a human-authored
// .nix file with no Nix-native atomicity. The compromised-ferrumd invariant
// holds either way -- what matters is that the mutated file is root-owned,
// not which root-owned file it is -- so this was a tooling-fit decision, and
// is recorded as one.
//
// The three controls that replace signature verification (DA-1), all of them
// enforced HERE rather than at discovery, because discovery and apply
// resolve independently and minutes apart:
//
//   * monotonicity -- a candidate that is not strictly newer than what this
//     host runs is refused by the Update job itself;
//   * repo identity -- an advance that moves the ferrum input to a different
//     host/owner/repo is refused. Advancing a ref and being pointed at a
//     different repository are different operations and only the first is an
//     update;
//   * the exact revision -- what the lock ends up pinning must be the
//     revision this job just resolved and reported. `nix` re-resolves the
//     ref itself, so without this a push landing mid-job would apply a
//     revision nobody ever saw.
//
// And the failure discipline: every refusal above, and every subprocess
// failure, restores flake.lock byte-for-byte through a temp-file-and-rename
// (the discipline `ferrum_state::journal::write` already uses), so a check
// that dies mid-fetch leaves the host exactly as it found it. A partial
// advance is the one outcome with no good recovery -- it is drift that looks
// like a decision.
//
// Every subprocess goes through the injected `CommandRunner` seam for the
// reason `update_check` already does: there is no `nix`, no `git` and no
// network in this repo's test environment, so a seam is the only way these
// decisions are testable at all.
use crate::update_candidate::{short_rev, FERRUM_INPUT};
use crate::update_check::{CommandRunner, ReadOnlyGuard};
use ferrum_state::journal::Pin;
use std::path::Path;

/// The argv that asks git whether the operator's flake directory has
/// uncommitted work.
///
/// `--porcelain` because its output is a stable, parseable contract rather
/// than the human format, and `-C` rather than a working directory on the
/// runner because the seam deliberately has no cwd: one less piece of
/// ambient state deciding what a root subprocess reads.
///
/// # Arguments
/// * `flake_dir` - the host's flake directory, normally `/etc/ferrum`.
///
/// # Returns
/// The arguments for `git`, without the program name.
pub fn dirty_argv(flake_dir: &str) -> Vec<String> {
    vec![
        "-C".to_string(),
        flake_dir.to_string(),
        "status".to_string(),
        "--porcelain".to_string(),
    ]
}

/// The paths `git status --porcelain` reported as changed.
///
/// Each line is `XY <path>`, with the two status columns in the first two
/// characters; a rename carries ` -> ` and both sides are reported, because
/// an operator looking for what to commit wants to see both.
///
/// # Arguments
/// * `stdout` - git's own output.
///
/// # Returns
/// One entry per reported path, in git's order. Empty means a clean tree.
pub fn dirty_paths(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|l| l.len() > 3)
        .map(|l| l[3..].trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// The argv that advances one input's pin, rewriting only `flake.lock`.
///
/// The flake directory is a positional argument rather than a working
/// directory for the same reason it is in `dirty_argv`. No
/// `--commit-lock-file`: that tree belongs to the operator and this process
/// does not make commits on their behalf.
///
/// # Arguments
/// * `flake_dir` - the host's flake directory, normally `/etc/ferrum`.
/// * `input` - the input to advance, normally `ferrum`.
///
/// # Returns
/// The arguments for `nix`, without the program name.
pub fn advance_argv(flake_dir: &str, input: &str) -> Vec<String> {
    vec![
        "flake".to_string(),
        "lock".to_string(),
        flake_dir.to_string(),
        "--update-input".to_string(),
        input.to_string(),
    ]
}

/// The fields of a locked node that name WHERE the code comes from, as
/// opposed to which commit of it is pinned.
///
/// `rev`, `narHash`, `lastModified` and `revCount` are what an update is
/// allowed to move. Everything below must be identical before and after.
/// `ref` is deliberately absent: it lives in `flake.nix`, which this module
/// proves byte-identical anyway, and Nix may legitimately fill in a default
/// branch name that was previously implicit -- refusing on that would block
/// real updates to enforce something already enforced elsewhere.
const IDENTITY_FIELDS: &[&str] = &["type", "owner", "repo", "url", "host", "dir"];

/// Where a locked input's code comes from, as a comparable string.
///
/// # Arguments
/// * `text` - the contents of a `flake.lock`.
/// * `name` - the input name, normally `ferrum`.
///
/// # Returns
/// A canonical rendering of `IDENTITY_FIELDS`, or `None` when the lock does
/// not resolve that input -- which the caller treats as a refusal, not as a
/// match.
pub fn repo_identity(text: &str, name: &str) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_str(text).ok()?;
    let node_key = doc
        .pointer(&format!("/nodes/root/inputs/{name}"))?
        .as_str()?;
    let locked = doc.pointer(&format!("/nodes/{node_key}/locked"))?;
    let mut parts: Vec<String> = Vec::new();
    for field in IDENTITY_FIELDS {
        if let Some(v) = locked.get(*field).and_then(|v| v.as_str()) {
            parts.push(format!("{field}={v}"));
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join(" "))
}

/// Restore `flake.lock` to bytes captured before the advance.
///
/// Temp file plus rename, in the lock's own directory so the rename is
/// within one filesystem and therefore atomic -- a restore that itself tore
/// would be strictly worse than the partial advance it is undoing.
///
/// # Arguments
/// * `flake_lock` - the file to restore.
/// * `bytes` - its contents before anything ran.
///
/// # Returns
/// Nothing on success.
///
/// # Errors
/// The io error, as text, when the temp write or the rename failed. The
/// caller surfaces it beside the failure that triggered the restore: a lock
/// that could be neither advanced nor restored is the one state an operator
/// must be told about explicitly.
pub fn restore(flake_lock: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = flake_lock.with_extension("lock.ferrum-restore");
    std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, flake_lock).map_err(|e| format!("{}: {e}", flake_lock.display()))
}

/// What one successful pin advance moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advanced {
    /// What the lock pinned before, or `None` when it pinned nothing
    /// readable -- which `advance` refuses, so this is `Some` in practice
    /// and exists so the caller can report both ends.
    pub from: Option<Pin>,
    /// What the lock pins now.
    pub to: Pin,
    /// The lock's exact bytes before the advance.
    ///
    /// Carried out so the caller can undo the advance when the apply that
    /// follows it never produced a generation. An advanced-but-unapplied
    /// lock is the drift R8 exists to prevent: the host would silently pick
    /// the rejected revision up on the next unrelated settings apply. Bytes
    /// rather than a re-serialised document, so the undo is exact.
    pub previous_lock: Vec<u8>,
}

/// Compose a refusal: restore the lock, then report why, naming a failed
/// restore as well when there was one.
fn refuse(flake_lock: &Path, before: &[u8], why: String) -> String {
    match restore(flake_lock, before) {
        Ok(()) => format!("{why} -- flake.lock is unchanged"),
        Err(e) => format!(
            "{why}. WORSE: flake.lock could not be restored either ({e}), so this host's pin \
             may now differ from the one its running generation was built from. Check \
             `git -C <flake dir> diff flake.lock` before applying anything"
        ),
    }
}

/// Refuse to advance when the operator's flake directory has uncommitted
/// work.
///
/// `/etc/ferrum` is required to be a git repository with every file tracked
/// (`examples/hosts/template/flake.nix`), so a machine-written `flake.lock`
/// leaves it dirty -- and a later `git checkout` there silently reverts the
/// pin, after which the next ordinary settings apply downgrades every
/// package on the host with no preview and no confirmation. Refusing on an
/// already-dirty tree keeps that one machine-written line distinguishable
/// from the operator's own. This does not commit on their behalf: that tree
/// is theirs.
///
/// # Arguments
/// * `runner` - the subprocess seam.
/// * `flake_dir` - the host's flake directory.
///
/// # Returns
/// Nothing when the tree is clean.
///
/// # Errors
/// An operator-facing message naming the files, or naming why git could not
/// be asked -- an unanswerable question is a refusal here, never a pass.
pub fn require_clean_tree(runner: &dyn CommandRunner, flake_dir: &str) -> Result<(), String> {
    let out = runner
        .run("git", &dirty_argv(flake_dir))
        .map_err(|e| format!("could not check whether {flake_dir} has uncommitted changes: {e}"))?;
    if !out.success {
        return Err(format!(
            "could not check whether {flake_dir} has uncommitted changes: {}",
            out.stderr.trim()
        ));
    }
    let paths = dirty_paths(&out.stdout);
    if paths.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{flake_dir} has uncommitted changes, so ferrum will not write flake.lock into it -- a \
         later `git checkout` there would silently revert the pin. Commit or discard these \
         first: {}",
        paths.join(", ")
    ))
}

/// Advance the `ferrum` pin to exactly one already-resolved revision.
///
/// Writes `flake.lock` and nothing else. Every failure, including every
/// refusal below, leaves `flake.lock` byte-for-byte as it was.
///
/// # Arguments
/// * `runner` - the subprocess seam.
/// * `flake_dir` - the host's flake directory, normally `/etc/ferrum`.
/// * `flake_nix` - the file that must not move.
/// * `flake_lock` - the file this advances.
/// * `expected_rev` - the revision the caller resolved and reported to the
///   operator. The advance is refused unless the lock ends up pinning
///   exactly this.
///
/// # Returns
/// The pin before and after.
///
/// # Errors
/// An operator-facing message when the lock could not be read, when `nix`
/// failed (carrying its own stderr, never a generic "update failed"), when
/// `flake.nix` moved, when the resulting lock is unreadable, when the repo
/// identity changed, or when the resolved revision is not the expected one.
pub fn advance(
    runner: &dyn CommandRunner,
    flake_dir: &str,
    flake_nix: &Path,
    flake_lock: &Path,
    expected_rev: &str,
) -> Result<Advanced, String> {
    let before_bytes = std::fs::read(flake_lock)
        .map_err(|e| format!("could not read {}: {e}", flake_lock.display()))?;
    let before_text = String::from_utf8_lossy(&before_bytes).into_owned();
    let before_pin = crate::pin::parse(&before_text, FERRUM_INPUT);
    let before_identity = repo_identity(&before_text, FERRUM_INPUT).ok_or_else(|| {
        format!(
            "{} does not pin a readable `{FERRUM_INPUT}` input, so there is nothing to advance \
             and nothing to compare an advance against",
            flake_lock.display()
        )
    })?;

    // Captured before the subprocess and read after it: the window this
    // covers is the whole advance.
    let guard = ReadOnlyGuard::capture(&[flake_nix]);

    let out = runner
        .run("nix", &advance_argv(flake_dir, FERRUM_INPUT))
        .map_err(|e| refuse(flake_lock, &before_bytes, format!("could not run nix: {e}")))?;
    if !out.success {
        return Err(refuse(
            flake_lock,
            &before_bytes,
            format!("could not advance the pin: {}", out.stderr.trim()),
        ));
    }

    // Checked first, and ahead of anything about the revision: a run that
    // rewrote flake.nix has broken the boundary this whole feature is built
    // on, and that is worth saying before anything about which commit it
    // landed on.
    let violations = guard.violations();
    if !violations.is_empty() {
        return Err(refuse(
            flake_lock,
            &before_bytes,
            format!(
                "advancing the pin modified {} -- it must never be written. ({})",
                flake_nix.display(),
                violations.join("; ")
            ),
        ));
    }

    let after_text = match std::fs::read_to_string(flake_lock) {
        Ok(t) => t,
        Err(e) => {
            return Err(refuse(
                flake_lock,
                &before_bytes,
                format!("could not read {} back after advancing it: {e}", flake_lock.display()),
            ))
        }
    };

    let after_identity = match repo_identity(&after_text, FERRUM_INPUT) {
        Some(i) => i,
        None => {
            return Err(refuse(
                flake_lock,
                &before_bytes,
                format!(
                    "{} no longer pins a readable `{FERRUM_INPUT}` input after the advance",
                    flake_lock.display()
                ),
            ))
        }
    };
    if after_identity != before_identity {
        return Err(refuse(
            flake_lock,
            &before_bytes,
            format!(
                "refusing this update: it would repoint the `{FERRUM_INPUT}` input from \
                 [{before_identity}] to [{after_identity}]. Advancing a ref and being pointed \
                 at a different repository are different operations, and only the first is an \
                 update"
            ),
        ));
    }

    let after_pin = match crate::pin::parse(&after_text, FERRUM_INPUT) {
        Some(p) => p,
        None => {
            return Err(refuse(
                flake_lock,
                &before_bytes,
                format!(
                    "{} records no revision and NAR hash for `{FERRUM_INPUT}` after the \
                     advance, so what this host would build is unidentifiable",
                    flake_lock.display()
                ),
            ))
        }
    };
    if after_pin.rev != expected_rev {
        return Err(refuse(
            flake_lock,
            &before_bytes,
            format!(
                "refusing this update: it resolved to {} but the candidate you were shown was \
                 {}. The tracked reference moved while this ran -- check for updates again and \
                 review the new revision",
                short_rev(&after_pin.rev),
                short_rev(expected_rev)
            ),
        ));
    }

    Ok(Advanced { from: before_pin, to: after_pin, previous_lock: before_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_check::testing::{fail, ok, FakeRunner};

    const REV_OLD: &str = "1111111111111111111111111111111111111111";
    const REV_NEW: &str = "2222222222222222222222222222222222222222";

    /// A lock in the shape Nix writes, pinning `ferrum` at `rev` through a
    /// node whose key is not the input's name.
    fn lock(rev: &str, owner: &str) -> String {
        format!(
            r#"{{"nodes":{{
                 "root":{{"inputs":{{"ferrum":"ferrum_2"}}}},
                 "ferrum_2":{{"locked":{{"type":"github","owner":"{owner}","repo":"ferrum",
                     "rev":"{rev}","narHash":"sha256-{rev}=","lastModified":1}}}}
               }},"root":"root","version":7}}"#
        )
    }

    /// A flake directory on disk: flake.nix, flake.lock, and the bytes of
    /// each so a test can assert they did or did not move.
    struct Host {
        _dir: tempfile::TempDir,
        flake_dir: String,
        flake_nix: std::path::PathBuf,
        flake_lock: std::path::PathBuf,
        nix_bytes: Vec<u8>,
        lock_bytes: Vec<u8>,
    }

    fn host() -> Host {
        let dir = tempfile::tempdir().unwrap();
        let flake_nix = dir.path().join("flake.nix");
        let flake_lock = dir.path().join("flake.lock");
        let nix_text = "{ inputs.ferrum.url = \"github:owner/ferrum/release\"; }\n";
        std::fs::write(&flake_nix, nix_text).unwrap();
        std::fs::write(&flake_lock, lock(REV_OLD, "owner")).unwrap();
        Host {
            flake_dir: dir.path().display().to_string(),
            nix_bytes: std::fs::read(&flake_nix).unwrap(),
            lock_bytes: std::fs::read(&flake_lock).unwrap(),
            flake_nix,
            flake_lock,
            _dir: dir,
        }
    }

    impl Host {
        /// A runner whose `nix flake lock` writes the lock this test wants,
        /// the way the real command would.
        fn runner_writing(&self, new_lock: String) -> WritingRunner {
            WritingRunner {
                lock_path: self.flake_lock.clone(),
                new_lock: Some(new_lock),
                nix_path: None,
                new_nix: None,
                calls: std::cell::RefCell::new(Vec::new()),
                succeed: true,
            }
        }

        fn flake_nix_moved(&self) -> bool {
            std::fs::read(&self.flake_nix).unwrap() != self.nix_bytes
        }

        fn flake_lock_moved(&self) -> bool {
            std::fs::read(&self.flake_lock).unwrap() != self.lock_bytes
        }
    }

    /// A `CommandRunner` that has the side effect the real `nix flake lock`
    /// has: it rewrites the lock. The canned-answer `FakeRunner` cannot
    /// model this module at all, because every assertion here is about what
    /// happened to files afterwards.
    struct WritingRunner {
        lock_path: std::path::PathBuf,
        new_lock: Option<String>,
        nix_path: Option<std::path::PathBuf>,
        new_nix: Option<String>,
        calls: std::cell::RefCell<Vec<Vec<String>>>,
        succeed: bool,
    }

    impl CommandRunner for WritingRunner {
        fn run(
            &self,
            _program: &str,
            args: &[String],
        ) -> Result<crate::update_check::CommandOutput, String> {
            self.calls.borrow_mut().push(args.to_vec());
            if let Some(text) = &self.new_lock {
                std::fs::write(&self.lock_path, text).unwrap();
            }
            if let (Some(p), Some(text)) = (&self.nix_path, &self.new_nix) {
                std::fs::write(p, text).unwrap();
            }
            Ok(if self.succeed {
                ok("")
            } else {
                fail("error: unable to download 'https://github.com/...': Couldn't connect")
            })
        }
    }

    #[test]
    fn the_advance_argv_updates_exactly_one_input_and_commits_nothing() {
        let argv = advance_argv("/etc/ferrum", "ferrum");
        assert_eq!(
            argv,
            vec!["flake", "lock", "/etc/ferrum", "--update-input", "ferrum"]
        );
        assert!(
            !argv.iter().any(|a| a == "--commit-lock-file"),
            "that tree belongs to the operator"
        );
        assert!(
            !argv.iter().any(|a| a == "--recreate-lock-file"),
            "every other input must stay exactly where it is"
        );
    }

    #[test]
    fn a_successful_advance_moves_the_lock_and_never_the_flake() {
        let h = host();
        let runner = h.runner_writing(lock(REV_NEW, "owner"));
        let moved = advance(&runner, &h.flake_dir, &h.flake_nix, &h.flake_lock, REV_NEW).unwrap();

        assert_eq!(moved.from.unwrap().rev, REV_OLD);
        assert_eq!(moved.to.rev, REV_NEW);
        assert_eq!(moved.previous_lock, h.lock_bytes, "the undo bytes are the real pre-image");
        assert!(h.flake_lock_moved(), "the lock is the file an update writes");
        assert!(!h.flake_nix_moved(), "flake.nix is byte-identical after every path this adds");
        assert_eq!(
            runner.calls.borrow().len(),
            1,
            "one subprocess: the advance itself"
        );
    }

    /// R2's edge case: a resolution that dies partway must leave the lock
    /// byte-for-byte untouched. The runner here writes a HALF-advanced lock
    /// and then reports failure, which is exactly what a network drop
    /// mid-fetch looks like from this side.
    #[test]
    fn a_failed_advance_restores_the_lock_byte_for_byte() {
        let h = host();
        let runner = WritingRunner {
            lock_path: h.flake_lock.clone(),
            new_lock: Some("{ half written".to_string()),
            nix_path: None,
            new_nix: None,
            calls: std::cell::RefCell::new(Vec::new()),
            succeed: false,
        };
        let err =
            advance(&runner, &h.flake_dir, &h.flake_nix, &h.flake_lock, REV_NEW).unwrap_err();

        assert!(err.contains("Couldn't connect"), "nix's own words reach the operator: {err}");
        assert!(err.contains("unchanged"), "and the operator is told the lock is intact: {err}");
        assert!(!h.flake_lock_moved(), "flake.lock must be byte-for-byte as it was");
        assert!(!h.flake_nix_moved());
    }

    /// The tripwire, not the prevention: nothing here can stop `nix` from
    /// writing flake.nix, so the guarantee is that such a run FAILS and is
    /// undone rather than being reported as an ordinary update.
    #[test]
    fn an_advance_that_touched_the_flake_is_refused_and_undone() {
        let h = host();
        let runner = WritingRunner {
            lock_path: h.flake_lock.clone(),
            new_lock: Some(lock(REV_NEW, "owner")),
            nix_path: Some(h.flake_nix.clone()),
            new_nix: Some("{ inputs.ferrum.url = \"github:attacker/ferrum\"; }\n".to_string()),
            calls: std::cell::RefCell::new(Vec::new()),
            succeed: true,
        };
        let err =
            advance(&runner, &h.flake_dir, &h.flake_nix, &h.flake_lock, REV_NEW).unwrap_err();
        assert!(err.contains("must never be written"), "got: {err}");
        assert!(!h.flake_lock_moved(), "the advance is undone");
    }

    /// DA-1: repo identity may never change through an update.
    #[test]
    fn an_advance_that_repoints_the_input_at_another_repository_is_refused() {
        let h = host();
        let runner = h.runner_writing(lock(REV_NEW, "somebody-else"));
        let err =
            advance(&runner, &h.flake_dir, &h.flake_nix, &h.flake_lock, REV_NEW).unwrap_err();
        assert!(err.contains("different repository"), "got: {err}");
        assert!(err.contains("owner=somebody-else"), "both ends are named: {err}");
        assert!(!h.flake_lock_moved());
    }

    /// DA-1: an Update that applies a revision the operator was never shown
    /// is a defect. `nix` re-resolves the ref itself, so this is the case
    /// where a push lands between the resolve and the advance.
    #[test]
    fn an_advance_that_landed_on_a_different_revision_is_refused() {
        let h = host();
        let landed = "3333333333333333333333333333333333333333";
        let runner = h.runner_writing(lock(landed, "owner"));
        let err =
            advance(&runner, &h.flake_dir, &h.flake_nix, &h.flake_lock, REV_NEW).unwrap_err();
        assert!(err.contains("3333333"), "the revision it landed on is named: {err}");
        assert!(err.contains("2222222"), "and the one that was reviewed: {err}");
        assert!(!h.flake_lock_moved());
    }

    /// Anti-vacuity for the four refusals above: with the SAME runner shape
    /// and the same host, an advance that satisfies every rule succeeds. A
    /// module that refused everything would pass each refusal test alone.
    #[test]
    fn the_refusals_are_not_a_blanket_refusal() {
        let h = host();
        let runner = h.runner_writing(lock(REV_NEW, "owner"));
        assert!(advance(&runner, &h.flake_dir, &h.flake_nix, &h.flake_lock, REV_NEW).is_ok());
    }

    #[test]
    fn a_lock_that_pins_no_ferrum_input_is_refused_before_anything_runs() {
        let h = host();
        std::fs::write(&h.flake_lock, r#"{"nodes":{"root":{"inputs":{}}},"version":7}"#).unwrap();
        let runner = h.runner_writing(lock(REV_NEW, "owner"));
        let err =
            advance(&runner, &h.flake_dir, &h.flake_nix, &h.flake_lock, REV_NEW).unwrap_err();
        assert!(err.contains("nothing to advance"), "got: {err}");
        assert!(
            runner.calls.borrow().is_empty(),
            "nothing privileged runs before the lock is understood"
        );
    }

    #[test]
    fn the_dirty_check_asks_git_about_the_right_directory() {
        assert_eq!(
            dirty_argv("/etc/ferrum"),
            vec!["-C", "/etc/ferrum", "status", "--porcelain"]
        );
    }

    #[test]
    fn a_clean_tree_passes_and_a_dirty_one_names_its_files() {
        let clean = FakeRunner::new(vec![("status", ok(""))]);
        assert!(require_clean_tree(&clean, "/etc/ferrum").is_ok());

        let dirty = FakeRunner::new(vec![(
            "status",
            ok(" M flake.lock\n?? notes.txt\n M settings.json\n"),
        )]);
        let err = require_clean_tree(&dirty, "/etc/ferrum").unwrap_err();
        assert!(err.contains("flake.lock"), "got: {err}");
        assert!(err.contains("notes.txt"), "got: {err}");
        assert!(err.contains("settings.json"), "got: {err}");
    }

    /// A question that could not be asked is a refusal. Treating an
    /// unanswerable `git status` as "clean" is how the one guard against a
    /// silently-reverted pin stops guarding.
    #[test]
    fn a_git_that_could_not_answer_is_a_refusal_not_a_pass() {
        let broken = FakeRunner::new(vec![("status", fail("fatal: not a git repository"))]);
        let err = require_clean_tree(&broken, "/etc/ferrum").unwrap_err();
        assert!(err.contains("not a git repository"), "git's own words: {err}");

        // And a git that could not be spawned at all.
        let missing = FakeRunner::new(vec![]);
        assert!(require_clean_tree(&missing, "/etc/ferrum").is_err());
    }

    #[test]
    fn porcelain_lines_are_read_as_paths_including_renames() {
        assert_eq!(dirty_paths(""), Vec::<String>::new());
        assert_eq!(
            dirty_paths("?? a.txt\n M b/c.nix\nR  old -> new\n"),
            vec!["a.txt", "b/c.nix", "old -> new"]
        );
    }

    #[test]
    fn repo_identity_ignores_the_fields_an_update_is_allowed_to_move() {
        let a = repo_identity(&lock(REV_OLD, "owner"), "ferrum").unwrap();
        let b = repo_identity(&lock(REV_NEW, "owner"), "ferrum").unwrap();
        assert_eq!(a, b, "a new revision of the same repo is the same identity");
        let c = repo_identity(&lock(REV_NEW, "someone"), "ferrum").unwrap();
        assert_ne!(b, c, "a different owner is a different identity");
        assert!(repo_identity("not json", "ferrum").is_none());
        assert!(repo_identity(r#"{"nodes":{"root":{"inputs":{}}}}"#, "ferrum").is_none());
    }
}
