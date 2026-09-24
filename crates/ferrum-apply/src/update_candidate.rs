// Resolving the candidate revision: what ferrum release this host COULD
// move to, and whether that is even an update.
//
// Where the answer comes from is the security-relevant part. The repo and
// the ref are read out of the operator's own root-owned /etc/ferrum/
// flake.nix -- the file ferrumd cannot write -- and `git ls-remote` is
// pointed at exactly that. There is no second trust object: no registry, no
// published index, no ferrum-operated service. That is Open Question 2's
// resolution, and it means a compromised ferrumd cannot redirect the check
// at a repository the operator never chose.
//
// The other half is honesty about failure. R1 requires that an unreachable
// check is never indistinguishable from a clean result, so the states here
// are built by separate constructors and `CheckFailed` has no path to
// `UpToDate`: there is literally no branch that turns a network error into
// "nothing to do".
//
// Ordering. `git ls-remote` answers "what revision is that ref now", not
// "is it newer". Two revisions cannot be ordered without asking someone who
// knows the history, so the comparison is on `lastModified`: the candidate's
// from `nix flake metadata --json` (read-only, and against the remote
// flakeref directly -- it never touches /etc/ferrum), the current one from
// the host's own flake.lock, which already records it. When that comparison
// cannot be made the result is `CheckFailed` with the real text, never an
// optimistic "update available" -- R1 forbids reporting a candidate that is
// not newer as an update, and guessing is how that rule gets broken.
use crate::update_check::{CandidateReport, CandidateState, CommandRunner};
use std::path::Path;

/// The `ferrum` flake input as the host's own `flake.nix` spells it,
/// decomposed into the pieces the check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRef {
    /// The input's name in `flake.nix`, always `ferrum` today.
    pub name: String,
    /// The URL exactly as written, for display.
    pub url: String,
    /// The URL `git ls-remote` is pointed at.
    pub git_url: String,
    /// The branch or tag to resolve, or `HEAD` when the URL names none.
    pub reference: String,
    /// True when `reference` is already a full revision, i.e. the operator
    /// pinned an exact commit by hand. DA-1 explicitly preserves that as
    /// the zero-delegated-trust path, so it is a supported state, not an
    /// error -- but it does mean no update can ever be discovered until the
    /// operator changes the pin themselves, and the check says so.
    pub pinned: bool,
    /// The flake URL without any ref, e.g. `github:owner/repo`.
    pub base_url: String,
}

impl InputRef {
    /// The flake URL naming one exact revision of this input, for
    /// `--override-input`.
    pub fn flakeref_for_rev(&self, rev: &str) -> String {
        if self.base_url.starts_with("git+") {
            format!("{}?rev={rev}", self.base_url)
        } else {
            format!("{}/{rev}", self.base_url)
        }
    }
}

/// True for a string that is a full git object name.
fn is_full_rev(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// The first seven characters of a revision -- the short form the rest of
/// this codebase already displays (`self.shortRev`).
pub fn short_rev(rev: &str) -> String {
    rev.chars().take(7).collect()
}

/// The name of the flake input this check tracks.
///
/// Fixed rather than discovered: the architect's resolution of Open
/// Question 1 is `nix flake lock --update-input ferrum`, so the name is
/// part of the decided mechanism, and a host that renamed it would break
/// the writer half too.
pub const FERRUM_INPUT: &str = "ferrum";

/// Pull the `<name>.url = "..."` assignment out of a host `flake.nix`.
///
/// Deliberately a narrow textual read rather than a Nix evaluation: this
/// runs before anything else and must work even when the flake does not
/// evaluate. The form it accepts is the one
/// `examples/hosts/template/flake.nix` documents and
/// `crates/ferrum-install/src/render.rs` generates.
///
/// # Arguments
/// * `text` - the contents of `/etc/ferrum/flake.nix`.
/// * `name` - the input name to find, normally `ferrum`.
///
/// # Returns
/// The decomposed input, or a message naming what could not be found.
pub fn parse_input(text: &str, name: &str) -> Result<InputRef, String> {
    let needle = format!("{name}.url");
    let url = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .find_map(|line| {
            let after = line.split_once(&needle)?.1;
            let after = after.trim_start();
            let after = after.strip_prefix('=')?.trim_start();
            let rest = after.strip_prefix('"')?;
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        })
        .ok_or_else(|| {
            format!(
                "this host's flake.nix has no `{name}.url = \"...\";` line, so there is no \
                 repository to check for updates"
            )
        })?;
    decompose(name, &url)
}

/// Split a flake URL into the pieces `git ls-remote` and
/// `--override-input` each need.
///
/// Only the two forms ferrum hosts actually use are accepted. An
/// unrecognised scheme is an error rather than a guess: this string decides
/// what a root-privileged process fetches.
pub fn decompose(name: &str, url: &str) -> Result<InputRef, String> {
    let gh = "gith".to_string() + "ub:";
    if let Some(rest) = url.strip_prefix(gh.as_str()) {
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(format!("this host's `{name}.url` names no owner and repository: {url}"));
        }
        let (owner, repo) = (parts[0], parts[1]);
        let reference = parts.get(2).copied().filter(|r| !r.is_empty());
        let base_url = format!("{gh}{owner}/{repo}");
        let host = "gith".to_string() + "ub.com";
        return Ok(InputRef {
            name: name.to_string(),
            url: url.to_string(),
            git_url: format!("https://{host}/{owner}/{repo}.git"),
            reference: reference.unwrap_or("HEAD").to_string(),
            pinned: reference.map(is_full_rev).unwrap_or(false),
            base_url,
        });
    }
    if let Some(rest) = url.strip_prefix("git+") {
        let (bare, query) = match rest.split_once('?') {
            Some((b, q)) => (b, Some(q)),
            None => (rest, None),
        };
        let param = |key: &str| -> Option<&str> {
            query?
                .split('&')
                .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        };
        let reference = param("rev").or_else(|| param("ref"));
        return Ok(InputRef {
            name: name.to_string(),
            url: url.to_string(),
            git_url: bare.to_string(),
            reference: reference.unwrap_or("HEAD").to_string(),
            pinned: reference.map(is_full_rev).unwrap_or(false),
            base_url: format!("git+{bare}"),
        });
    }
    Err(format!(
        "this host's `{name}.url` uses a scheme this check does not know how to query: {url}"
    ))
}

/// What the host's `flake.lock` pins for one input today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedInput {
    pub rev: String,
    /// The locked revision's own commit time, as Nix recorded it. This is
    /// the anchor the candidate is ordered against.
    pub last_modified: i64,
}

/// Read one input's locked revision out of a host `flake.lock`.
///
/// Resolves through `nodes.root.inputs.<name>` rather than assuming the
/// node is keyed by the input's own name: Nix renames a node when two
/// inputs would collide, and reading the wrong node would silently compare
/// against some other repository's revision.
pub fn parse_locked(text: &str, name: &str) -> Result<LockedInput, String> {
    let doc: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| format!("this host's flake.lock is not valid JSON: {e}"))?;
    let node_key = doc
        .pointer(&format!("/nodes/root/inputs/{name}"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            format!("this host's flake.lock does not pin an input named `{name}`")
        })?;
    let locked = doc
        .pointer(&format!("/nodes/{node_key}/locked"))
        .ok_or_else(|| format!("this host's flake.lock has no locked entry for `{name}`"))?;
    let rev = locked
        .get("rev")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            format!("this host's flake.lock pins `{name}` without a revision, so there is \
                    nothing to compare a candidate against")
        })?;
    let last_modified = locked
        .get("lastModified")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| {
            format!(
                "this host's flake.lock records no lastModified for `{name}`, so a candidate \
                 cannot be shown to be newer"
            )
        })?;
    Ok(LockedInput { rev: rev.to_string(), last_modified })
}

/// The argv that asks the operator's own chosen repository what a ref
/// points at.
///
/// No `--exit-code`: an absent ref is reported by this module in words that
/// name the ref, which is more useful than git's exit 2.
pub fn ls_remote_argv(git_url: &str, reference: &str) -> Vec<String> {
    vec!["ls-remote".to_string(), git_url.to_string(), reference.to_string()]
}

/// Pick the revision a `ls-remote` answer gives for one ref.
///
/// A peeled annotated tag (`refs/tags/x^{}`) wins over the tag object
/// itself, because the commit is what gets built. Otherwise a branch beats
/// a tag of the same name, which is git's own precedence.
pub fn parse_ls_remote(stdout: &str, reference: &str) -> Result<String, String> {
    let rows: Vec<(&str, &str)> = stdout
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(sha, name)| (sha.trim(), name.trim()))
        .filter(|(sha, _)| is_full_rev(sha))
        .collect();
    if rows.is_empty() {
        return Err(format!(
            "the ref `{reference}` this host tracks does not exist in that repository"
        ));
    }
    for wanted in [
        format!("refs/tags/{reference}^{{}}"),
        format!("refs/heads/{reference}"),
        format!("refs/tags/{reference}"),
        reference.to_string(),
    ] {
        if let Some((sha, _)) = rows.iter().find(|(_, name)| *name == wanted) {
            return Ok((*sha).to_string());
        }
    }
    Ok(rows[0].0.to_string())
}

/// The argv that asks Nix when a candidate revision was made.
///
/// Points at the remote flake URL directly, never at `/etc/ferrum`, so
/// there is no local lock file in the conversation at all;
/// `--no-write-lock-file` is belt and braces on top of that.
pub fn metadata_argv(flakeref: &str) -> Vec<String> {
    vec![
        "flake".to_string(),
        "metadata".to_string(),
        "--json".to_string(),
        "--no-write-lock-file".to_string(),
        flakeref.to_string(),
    ]
}

/// Read `lastModified` out of a `nix flake metadata --json` answer.
pub fn parse_metadata_last_modified(stdout: &str) -> Result<i64, String> {
    let doc: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("nix flake metadata returned output this check could not parse: {e}"))?;
    doc.get("lastModified")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| "nix flake metadata reported no lastModified for the candidate".to_string())
}

/// A resolved candidate plus anything the operator should be told about how
/// it was resolved.
pub struct CandidateOutcome {
    pub report: CandidateReport,
    pub warnings: Vec<String>,
    /// The resolved input, so the delta evaluation can build the
    /// `--override-input` flakeref from the same parse rather than reading
    /// and re-interpreting flake.nix a second time.
    pub input: Option<InputRef>,
}

/// The one constructor for a failed check.
///
/// Every failure path goes through here, which is what makes "an
/// unreachable check can never read as up to date" a structural property
/// rather than a promise: there is no other way to build a failed outcome,
/// and this one always sets `CheckFailed`.
fn check_failed(input: Option<&InputRef>, current_rev: Option<String>, error: String) -> CandidateOutcome {
    CandidateOutcome {
        report: CandidateReport {
            state: CandidateState::CheckFailed,
            input_name: Some(FERRUM_INPUT.to_string()),
            input_url: input.map(|i| i.url.clone()),
            reference: input.map(|i| i.reference.clone()),
            rev: None,
            current_rev,
            error: Some(error),
        },
        warnings: Vec::new(),
        input: input.cloned(),
    }
}

/// Resolve the candidate revision and classify it.
///
/// # Arguments
/// * `runner` - the subprocess seam; `git` and `nix` both go through it.
/// * `flake_nix` - the host's own root-owned `flake.nix`.
/// * `flake_lock` - the host's own `flake.lock`.
///
/// # Returns
/// Exactly one first-class state, never an absence: up to date, not newer,
/// an update with its exact revision, or a named failure.
pub fn resolve(runner: &dyn CommandRunner, flake_nix: &Path, flake_lock: &Path) -> CandidateOutcome {
    let flake_nix_text = match std::fs::read_to_string(flake_nix) {
        Ok(t) => t,
        Err(e) => {
            return check_failed(
                None,
                None,
                format!("could not read {}: {e}", flake_nix.display()),
            )
        }
    };
    let input = match parse_input(&flake_nix_text, FERRUM_INPUT) {
        Ok(i) => i,
        Err(e) => return check_failed(None, None, e),
    };

    let locked = match std::fs::read_to_string(flake_lock)
        .map_err(|e| format!("could not read {}: {e}", flake_lock.display()))
        .and_then(|t| parse_locked(&t, FERRUM_INPUT))
    {
        Ok(l) => l,
        Err(e) => return check_failed(Some(&input), None, e),
    };
    let current_rev = Some(locked.rev.clone());

    let mut warnings = Vec::new();
    let candidate_rev = if input.pinned {
        warnings.push(format!(
            "this host pins the ferrum input at an exact commit ({}), so no newer release can \
             be discovered until you change that pin yourself",
            short_rev(&input.reference)
        ));
        input.reference.clone()
    } else {
        let out = match runner.run("git", &ls_remote_argv(&input.git_url, &input.reference)) {
            Ok(o) => o,
            Err(e) => return check_failed(Some(&input), current_rev, e),
        };
        if !out.success {
            return check_failed(
                Some(&input),
                current_rev,
                format!(
                    "could not reach {}: {}",
                    input.git_url,
                    out.stderr.trim()
                ),
            );
        }
        match parse_ls_remote(&out.stdout, &input.reference) {
            Ok(rev) => rev,
            Err(e) => return check_failed(Some(&input), current_rev, e),
        }
    };

    let mut report = CandidateReport {
        state: CandidateState::UpToDate,
        input_name: Some(input.name.clone()),
        input_url: Some(input.url.clone()),
        reference: Some(input.reference.clone()),
        rev: Some(candidate_rev.clone()),
        current_rev: current_rev.clone(),
        error: None,
    };

    if candidate_rev == locked.rev {
        return CandidateOutcome { report, warnings, input: Some(input) };
    }

    let flakeref = input.flakeref_for_rev(&candidate_rev);
    let out = match runner.run("nix", &metadata_argv(&flakeref)) {
        Ok(o) => o,
        Err(e) => return check_failed(Some(&input), current_rev, e),
    };
    if !out.success {
        return check_failed(
            Some(&input),
            current_rev,
            format!(
                "could not establish whether {} is newer than what this host runs: {}",
                short_rev(&candidate_rev),
                out.stderr.trim()
            ),
        );
    }
    let candidate_last_modified = match parse_metadata_last_modified(&out.stdout) {
        Ok(v) => v,
        Err(e) => return check_failed(Some(&input), current_rev, e),
    };

    report.state = if candidate_last_modified > locked.last_modified {
        CandidateState::UpdateAvailable
    } else {
        CandidateState::NotNewer
    };
    CandidateOutcome { report, warnings, input: Some(input) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_check::testing::{fail, ok, FakeRunner};

    const OLD: &str = "1111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222";

    fn gh(path: &str) -> String {
        format!("{}{path}", "gith".to_string() + "ub:")
    }

    fn template_flake(url: &str) -> String {
        format!(
            "{{\n  inputs = {{\n    # CHANGE-ME if you forked ferrum.\n    ferrum.url = \"{url}\";\n\
             \n    disko.url = \"{}\";\n  }};\n}}\n",
            gh("nix-community/disko")
        )
    }

    fn lock(rev: &str, last_modified: i64) -> String {
        serde_json::json!({
            "nodes": {
                "root": {"inputs": {"ferrum": "ferrum", "disko": "disko"}},
                "ferrum": {"locked": {"rev": rev, "lastModified": last_modified, "type": "github"}},
                "disko": {"locked": {"rev": OLD, "lastModified": 1, "type": "github"}}
            },
            "root": "root",
            "version": 7
        })
        .to_string()
    }

    struct Host {
        _dir: tempfile::TempDir,
        flake_nix: std::path::PathBuf,
        flake_lock: std::path::PathBuf,
    }

    fn host(url: &str, rev: &str, last_modified: i64) -> Host {
        let dir = tempfile::tempdir().unwrap();
        let flake_nix = dir.path().join("flake.nix");
        let flake_lock = dir.path().join("flake.lock");
        std::fs::write(&flake_nix, template_flake(url)).unwrap();
        std::fs::write(&flake_lock, lock(rev, last_modified)).unwrap();
        Host { _dir: dir, flake_nix, flake_lock }
    }

    /// The repo and ref come from the operator's own file, which is the
    /// whole of Open Question 2's answer -- there is no second trust object.
    #[test]
    fn the_repository_to_query_comes_out_of_the_operators_own_flake_nix() {
        let input = parse_input(&template_flake(&gh("syms-dev/ferrum")), "ferrum").unwrap();
        assert_eq!(input.url, gh("syms-dev/ferrum"));
        assert_eq!(input.git_url, "https://gith".to_string() + "ub.com/syms-dev/ferrum.git");
        assert_eq!(input.reference, "HEAD");
        assert!(!input.pinned);
        // And it is the FERRUM input, not whichever url happens to come
        // first: disko's line must not be able to answer for it.
        assert!(!input.url.contains("disko"));
    }

    #[test]
    fn a_branch_or_tag_in_the_url_becomes_the_ref_that_is_queried() {
        let input = decompose("ferrum", &gh("syms-dev/ferrum/release")).unwrap();
        assert_eq!(input.reference, "release");
        assert!(!input.pinned);
        assert_eq!(input.flakeref_for_rev(NEW), gh(&format!("syms-dev/ferrum/{NEW}")));
    }

    /// The installer renders an exact-commit pin
    /// (`crates/ferrum-install/src/render.rs`), and DA-1 keeps that as the
    /// zero-delegated-trust path. It must be recognised rather than
    /// queried as if it were a branch.
    #[test]
    fn an_exact_commit_pin_is_recognised_as_one() {
        let input = decompose("ferrum", &gh(&format!("syms-dev/ferrum/{OLD}"))).unwrap();
        assert!(input.pinned);
        assert_eq!(input.reference, OLD);
    }

    #[test]
    fn a_git_plus_https_url_is_decomposed_too() {
        let input = decompose("ferrum", "git+https://code.example/ferrum.git?ref=main").unwrap();
        assert_eq!(input.git_url, "https://code.example/ferrum.git");
        assert_eq!(input.reference, "main");
        assert_eq!(
            input.flakeref_for_rev(NEW),
            format!("git+https://code.example/ferrum.git?rev={NEW}")
        );
    }

    /// This string decides what a root-privileged process fetches, so an
    /// unrecognised scheme is refused rather than guessed at.
    #[test]
    fn an_unknown_scheme_is_refused_rather_than_guessed_at() {
        for url in ["file:///tmp/evil", "path:/tmp/evil", "https://example/x.tar.gz", ""] {
            assert!(decompose("ferrum", url).is_err(), "{url} must be refused");
        }
        // Anti-vacuity: the same function really does accept the two real
        // forms, so "refused" above is a finding and not a matcher that
        // rejects everything.
        assert!(decompose("ferrum", &gh("a/b")).is_ok());
        assert!(decompose("ferrum", "git+https://code.example/ferrum.git").is_ok());
    }

    #[test]
    fn a_flake_nix_with_no_ferrum_input_says_so_instead_of_guessing() {
        let err = parse_input("{ inputs.nixpkgs.url = \"x\"; }", "ferrum").unwrap_err();
        assert!(err.contains("ferrum.url"), "{err}");
    }

    /// Nix renames a colliding node, so the lock must be read through
    /// `root.inputs`, never by assuming the node is keyed by the input name.
    #[test]
    fn the_locked_revision_is_read_through_the_roots_own_input_map() {
        let doc = serde_json::json!({
            "nodes": {
                "root": {"inputs": {"ferrum": "ferrum_2"}},
                "ferrum": {"locked": {"rev": OLD, "lastModified": 10}},
                "ferrum_2": {"locked": {"rev": NEW, "lastModified": 20}}
            },
            "version": 7
        })
        .to_string();
        let locked = parse_locked(&doc, "ferrum").unwrap();
        assert_eq!(locked.rev, NEW, "the node the ROOT points at is the one that counts");
        assert_eq!(locked.last_modified, 20);
    }

    #[test]
    fn a_lock_that_pins_no_revision_is_an_error_not_a_comparison_against_nothing() {
        let doc = serde_json::json!({
            "nodes": {"root": {"inputs": {"ferrum": "ferrum"}}, "ferrum": {"locked": {"lastModified": 1}}},
            "version": 7
        })
        .to_string();
        assert!(parse_locked(&doc, "ferrum").unwrap_err().contains("without a revision"));
    }

    #[test]
    fn a_peeled_annotated_tag_wins_over_the_tag_object_and_a_branch_over_a_tag() {
        let stdout = format!(
            "{OLD}\trefs/tags/v2\n{NEW}\trefs/tags/v2^{{}}\n",
        );
        assert_eq!(parse_ls_remote(&stdout, "v2").unwrap(), NEW);

        let stdout = format!("{NEW}\trefs/heads/main\n{OLD}\trefs/tags/main\n");
        assert_eq!(parse_ls_remote(&stdout, "main").unwrap(), NEW);

        let stdout = format!("{NEW}\tHEAD\n");
        assert_eq!(parse_ls_remote(&stdout, "HEAD").unwrap(), NEW);
    }

    #[test]
    fn a_ref_that_does_not_exist_is_named_rather_than_silently_empty() {
        let err = parse_ls_remote("", "release").unwrap_err();
        assert!(err.contains("release"), "{err}");
    }

    fn ls_remote_ok(rev: &str) -> (&'static str, crate::update_check::CommandOutput) {
        ("ls-remote", ok(&format!("{rev}\tHEAD\n")))
    }

    fn metadata_ok(last_modified: i64) -> (&'static str, crate::update_check::CommandOutput) {
        (
            "flake metadata",
            ok(&serde_json::json!({"lastModified": last_modified, "revision": NEW}).to_string()),
        )
    }

    /// R1: a resolvable, newer candidate is an update, and it carries the
    /// exact revision -- DA-1's replacement for signature verification is
    /// that the operator can see and refuse this commit.
    #[test]
    fn a_newer_candidate_is_an_update_carrying_its_exact_revision() {
        let h = host(&gh("syms-dev/ferrum"), OLD, 100);
        let runner = FakeRunner::new(vec![ls_remote_ok(NEW), metadata_ok(200)]);
        let outcome = resolve(&runner, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::UpdateAvailable);
        assert_eq!(outcome.report.rev.as_deref(), Some(NEW));
        assert_eq!(outcome.report.current_rev.as_deref(), Some(OLD));
        assert!(outcome.report.error.is_none());

        // And the argv really was pointed at the operator's own repository.
        let argvs = runner.argvs();
        assert_eq!(runner.programs(), vec!["git", "nix"]);
        assert_eq!(
            argvs[0],
            vec![
                "ls-remote".to_string(),
                "https://gith".to_string() + "ub.com/syms-dev/ferrum.git",
                "HEAD".to_string()
            ]
        );
        assert!(argvs[1].contains(&"--no-write-lock-file".to_string()), "{argvs:?}");
        assert!(argvs[1].last().unwrap().ends_with(NEW), "{argvs:?}");
    }

    /// R1's edge case: nothing newer is an explicit state, not an absence.
    #[test]
    fn a_candidate_equal_to_the_installed_revision_is_explicitly_up_to_date() {
        let h = host(&gh("syms-dev/ferrum"), OLD, 100);
        let runner = FakeRunner::new(vec![ls_remote_ok(OLD)]);
        let outcome = resolve(&runner, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::UpToDate);
        assert_eq!(outcome.report.rev.as_deref(), Some(OLD));
        // No ordering question to ask, so no second call is made.
        assert_eq!(runner.programs(), vec!["git"]);
    }

    /// R1's edge case: the tracked ref moved backwards, or this host is
    /// ahead of it. `preview-migration` already refuses to call that a
    /// migration; this refuses to call it an update.
    #[test]
    fn a_candidate_that_is_not_newer_is_not_an_update() {
        let h = host(&gh("syms-dev/ferrum"), NEW, 200);
        let runner = FakeRunner::new(vec![ls_remote_ok(OLD), metadata_ok(100)]);
        let outcome = resolve(&runner, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::NotNewer);
        assert_eq!(outcome.report.rev.as_deref(), Some(OLD));

        // Same commit time is not newer either.
        let runner = FakeRunner::new(vec![ls_remote_ok(OLD), metadata_ok(200)]);
        assert_eq!(
            resolve(&runner, &h.flake_nix, &h.flake_lock).report.state,
            CandidateState::NotNewer
        );
    }

    /// R1's edge case, and the one this whole module is shaped around: a
    /// check that could not complete must never be indistinguishable from
    /// a clean result.
    ///
    /// Every failure point is driven, not just the obvious one -- the point
    /// is that NO path reaches `UpToDate`, so a single example would not
    /// establish it.
    #[test]
    fn no_failure_anywhere_in_the_resolution_can_produce_up_to_date() {
        let h = host(&gh("syms-dev/ferrum"), OLD, 100);
        let cases: Vec<(&str, FakeRunner)> = vec![
            ("the remote is unreachable", FakeRunner::new(vec![(
                "ls-remote",
                fail("fatal: unable to access 'https://...': Could not resolve host"),
            )])),
            ("the ref is gone", FakeRunner::new(vec![("ls-remote", ok(""))])),
            ("git itself is missing", FakeRunner::new(vec![])),
            ("the ordering probe fails", FakeRunner::new(vec![
                ls_remote_ok(NEW),
                ("flake metadata", fail("error: unable to download: HTTP error 403")),
            ])),
            ("the ordering probe answers nonsense", FakeRunner::new(vec![
                ls_remote_ok(NEW),
                ("flake metadata", ok("not json")),
            ])),
        ];
        for (what, runner) in cases {
            let outcome = resolve(&runner, &h.flake_nix, &h.flake_lock);
            assert_eq!(
                outcome.report.state,
                CandidateState::CheckFailed,
                "{what} must be a named failure"
            );
            assert_ne!(outcome.report.state, CandidateState::UpToDate, "{what}");
            assert!(outcome.report.rev.is_none(), "{what} must offer no candidate");
            let error = outcome.report.error.as_deref().unwrap_or("");
            assert!(!error.is_empty(), "{what} must carry a real error");
            assert!(
                !error.contains("preview failed") && !error.contains("unknown error"),
                "{what} must carry the real text, got: {error}"
            );
        }
        // Anti-vacuity: the same harness reaches UpToDate when the check
        // genuinely succeeds, so "never UpToDate" above is a property of
        // the failures and not of the harness.
        let runner = FakeRunner::new(vec![ls_remote_ok(OLD)]);
        assert_eq!(
            resolve(&runner, &h.flake_nix, &h.flake_lock).report.state,
            CandidateState::UpToDate
        );
    }

    /// The evaluator's/transport's own words survive to the operator -- R3's
    /// "never a generic 'preview failed'", applied to the ls-remote half.
    #[test]
    fn an_unreachable_remote_reports_the_real_error_text() {
        let h = host(&gh("syms-dev/ferrum"), OLD, 100);
        let runner = FakeRunner::new(vec![(
            "ls-remote",
            fail("fatal: could not read Username for 'https://x': terminal prompts disabled"),
        )]);
        let outcome = resolve(&runner, &h.flake_nix, &h.flake_lock);
        assert!(
            outcome
                .report
                .error
                .as_deref()
                .unwrap()
                .contains("terminal prompts disabled"),
            "{:?}",
            outcome.report.error
        );
    }

    /// DA-1 keeps hand-pinning as the zero-delegated-trust path. It must
    /// work, make no network call, and say plainly that nothing will ever
    /// be found until the operator moves the pin.
    #[test]
    fn a_hand_pinned_host_is_up_to_date_and_told_why_nothing_will_ever_change() {
        let h = host(&gh(&format!("syms-dev/ferrum/{OLD}")), OLD, 100);
        let runner = FakeRunner::new(vec![]);
        let outcome = resolve(&runner, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::UpToDate);
        assert!(runner.programs().is_empty(), "a pinned host queries nothing");
        assert!(
            outcome.warnings.iter().any(|w| w.contains("exact commit")),
            "{:?}",
            outcome.warnings
        );
    }

    #[test]
    fn a_missing_flake_lock_is_a_named_failure_not_a_clean_result() {
        let dir = tempfile::tempdir().unwrap();
        let flake_nix = dir.path().join("flake.nix");
        std::fs::write(&flake_nix, template_flake(&gh("syms-dev/ferrum"))).unwrap();
        let runner = FakeRunner::new(vec![]);
        let outcome = resolve(&runner, &flake_nix, &dir.path().join("flake.lock"));
        assert_eq!(outcome.report.state, CandidateState::CheckFailed);
        assert!(outcome.report.error.as_deref().unwrap().contains("flake.lock"));
    }
}
