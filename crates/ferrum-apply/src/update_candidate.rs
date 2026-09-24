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
// Credentials. That same file is the only place a `git+` URL's
// `user:password@` can come from, and it is root-only -- while everything
// this module produces is not: the report document is served by an
// unprivileged daemon, an argv is readable out of /proc by any local user,
// and a remote's stderr is quoted into the report verbatim. So the userinfo
// is stripped once, at the parse, before any field or error string exists
// that could carry it. Stripping at the sinks instead would be a list that
// has to stay complete forever; stripping at the source is a property of
// the type. The cost is stated in the warning `resolve` emits: a private
// repository has to be reachable through git's own credential
// configuration, because this check will not hand a secret to a subprocess.
//
// Ordering. `git ls-remote` answers "what revision is that ref now", not
// "is it newer". Two revisions cannot be ordered without asking someone who
// knows the history, so the comparison is on `lastModified`: the candidate's
// from `nix flake metadata --json` (read-only, and against the remote
// flakeref directly -- it never touches /etc/ferrum), the current one from
// the host's own flake.lock, which already records it.
//
// Both sides of that comparison are commit metadata, chosen by whoever
// authored the commit, and no ancestry is ever established -- establishing
// it needs history, which needs a fetch, which this check does not do. So
// the ordering is a useful signal and not a proof, and the module says so
// rather than implying otherwise: when it cannot be made, the result is
// `OrderUnknown` carrying both timestamps and both revisions for the
// operator to judge, never an optimistic "update available" and never a
// silent "not newer". R1 forbids reporting a candidate that is not newer
// as an update, and it equally forbids an undecidable check being
// indistinguishable from a clean one.
use crate::update_check::{CandidateReport, CandidateState, CommandRunner};
use std::path::Path;

/// The `ferrum` flake input as the host's own `flake.nix` spells it,
/// decomposed into the pieces the check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRef {
    /// The input's name in `flake.nix`, always `ferrum` today.
    pub name: String,
    /// The URL as written, minus any `user[:password]@` -- this is a
    /// published field, so it carries no credential.
    pub url: String,
    /// The URL `git ls-remote` is pointed at, minus any userinfo.
    pub git_url: String,
    /// The branch or tag to resolve, or `HEAD` when the URL names none.
    pub reference: String,
    /// True when `reference` is already a full revision, i.e. the operator
    /// pinned an exact commit by hand. DA-1 explicitly preserves that as
    /// the zero-delegated-trust path, so it is a supported state, not an
    /// error -- but it does mean no update can ever be discovered until the
    /// operator changes the pin themselves, and the check says so.
    pub pinned: bool,
    /// The flake URL without any ref, e.g. `github:owner/repo`, minus any
    /// userinfo and minus the query.
    pub base_url: String,
    /// Every query parameter that is not the ref -- `dir=`, `submodules=`
    /// and so on. These decide what is evaluated, so they are carried
    /// rather than dropped when the flakeref is rebuilt at an exact
    /// revision.
    pub extra_params: Vec<String>,
    /// True when the URL in `flake.nix` carried `user[:password]@` that
    /// this parse removed. The operator is told, because it changes what
    /// the check can reach.
    pub credentials_redacted: bool,
}

impl InputRef {
    /// The flake URL naming one exact revision of this input, for
    /// `--override-input`.
    ///
    /// # Arguments
    /// * `rev` - the revision to pin, normally the resolved candidate.
    ///
    /// # Returns
    /// A flake URL Nix will resolve to exactly that revision, carrying
    /// every parameter the operator pinned except the ref this revision
    /// supersedes.
    pub fn flakeref_for_rev(&self, rev: &str) -> String {
        let mut params = self.extra_params.clone();
        if self.base_url.starts_with("git+") {
            params.push(format!("rev={rev}"));
            return format!("{}?{}", self.base_url, params.join("&"));
        }
        let pinned = format!("{}/{rev}", self.base_url);
        if params.is_empty() {
            pinned
        } else {
            format!("{pinned}?{}", params.join("&"))
        }
    }
}

/// True for a string that is a full git object name.
fn is_full_rev(s: &str) -> bool {
    s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// The first seven characters of a revision -- the short form the rest of
/// this codebase already displays (`self.shortRev`).
///
/// # Arguments
/// * `rev` - a full revision, or anything shorter.
///
/// # Returns
/// At most the first seven characters; a shorter input is returned whole.
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
/// The decomposed input.
///
/// # Errors
/// When no `<name>.url = "...";` line is present, or its URL uses a scheme
/// this check cannot query.
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

/// The flake-URL scheme a ferrum host's `ferrum` input normally uses.
pub const GITHUB_SCHEME: &str = "github:";

/// The host `GITHUB_SCHEME` resolves to for `git ls-remote`.
pub const GITHUB_HOST: &str = "github.com";

/// Remove `user[:password]@` from a URL's authority.
///
/// The boundary that keeps a root-only credential out of everything this
/// module publishes. RFC 3986's own rule is used rather than a guess: the
/// authority runs to the first `/`, `?` or `#`, and userinfo runs to the
/// LAST `@` inside it -- a password containing `@` or `:` therefore does
/// not shorten the cut, which a first-`@` reading would get wrong.
///
/// One transport is treated differently. Over ssh the login name is not a
/// secret: it is how the transport selects an account, and `git@` is what
/// every ssh forge expects. Removing it would break the remote while
/// protecting nothing, so for ssh the user is kept and only a password
/// beside it -- which means nothing to ssh -- is dropped.
///
/// # Arguments
/// * `url` - a URL, with or without userinfo.
///
/// # Returns
/// The URL unchanged when it carries no userinfo, and without it otherwise.
pub fn redact_userinfo(url: &str) -> String {
    // Both spellings of a scheme: `git+https://host/..` and the opaque
    // `github:owner/repo`. The second cannot carry a real credential, but a
    // mistyped one still ends up in an error string, and this is the only
    // place that can stop it.
    let split = url
        .split_once("://")
        .map(|(scheme, rest)| (format!("{scheme}://"), rest))
        .or_else(|| {
            url.split_once(':')
                .map(|(scheme, rest)| (format!("{scheme}:"), rest))
        });
    let Some((scheme, rest)) = split else {
        return url.to_string();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let keep_user = transport_keeps_user(scheme.trim_end_matches(&['/', ':'][..]));
    format!("{scheme}{}{tail}", sanitize_authority(authority, keep_user))
}

/// True for a transport whose login name is part of addressing rather than
/// a secret.
///
/// # Arguments
/// * `scheme` - a scheme with no trailing separator, possibly compound
///   (`git+ssh`).
///
/// # Returns
/// True for ssh in any spelling, false otherwise.
fn transport_keeps_user(scheme: &str) -> bool {
    scheme
        .rsplit('+')
        .next()
        .is_some_and(|t| t.eq_ignore_ascii_case("ssh"))
}

/// The authority with its userinfo removed, or reduced to a login name.
///
/// # Arguments
/// * `authority` - the part of a URL between the scheme and the path.
/// * `keep_user` - keep the login name and drop only the password, for a
///   transport where the name is addressing rather than a secret.
///
/// # Returns
/// The host and port, optionally still prefixed by `user@`; the whole of
/// `authority` when it carries no userinfo.
fn sanitize_authority(authority: &str, keep_user: bool) -> String {
    let Some(at) = authority.rfind('@') else {
        return authority.to_string();
    };
    let (userinfo, host) = (&authority[..at], &authority[at + 1..]);
    let user = userinfo.split(':').next().unwrap_or("");
    if keep_user && !user.is_empty() {
        format!("{user}@{host}")
    } else {
        host.to_string()
    }
}

/// The same removal, applied to every URL inside a free-text string.
///
/// For the one string in this module that is not built here: a
/// subprocess's stderr, which the report republishes verbatim so the
/// operator sees the real failure. `git` composes
/// `Authentication failed for '<url>'` from the URL *after* credential
/// filling, so root's own netrc or credential helper can put a secret in
/// that line even though this module hands `git` a clean URL. The report
/// is read at a lower trust level than root's credential store, so the
/// line is cleaned on the way in.
///
/// # Arguments
/// * `text` - arbitrary text, typically a subprocess's stderr.
///
/// # Returns
/// The same text with the userinfo removed from every `scheme://` URL it
/// contains.
pub fn redact_urls_in(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        // An authority ends at the path, the query, the fragment, or at
        // whatever punctuation the surrounding prose put after it.
        let end = tail
            .find(|c: char| c.is_whitespace() || "/?#'\"`,;)".contains(c))
            .unwrap_or(tail.len());
        let (authority, after) = tail.split_at(end);
        // The scheme is the run of scheme characters immediately before
        // the `://` just consumed, so an ssh URL quoted inside prose is
        // treated the same way as one this module parsed itself.
        let before = &head[..head.len() - 3];
        let scheme_at = before
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-'))
            .map_or(0, |i| i + 1);
        out.push_str(&sanitize_authority(authority, transport_keeps_user(&before[scheme_at..])));
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Refuse an input whose argv slots `git` would read as options.
///
/// Both the repository and the ref become bare argv elements of a
/// root-privileged `git ls-remote`, and `--upload-pack=<cmd>` in either
/// slot makes git run `<cmd>`. `ls_remote_argv` already places the
/// repository after `--`; this refuses the form outright as well, which is
/// the same discipline `is_safe_app_id` applies for the same reason.
///
/// # Arguments
/// * `input` - the freshly decomposed input.
///
/// # Returns
/// The input unchanged when both slots are values rather than options.
///
/// # Errors
/// When the repository or the ref begins with `-`.
/// The transports `git+` may name.
///
/// Nothing that comes back from the fetch is signed, so the transport is
/// the whole of the trust chain. Plaintext `http` lets a network attacker
/// choose both the revision and the metadata that would make it look
/// newer, and there is no second control that would catch it. `file` is
/// kept because a local path cannot be rewritten in flight and is how this
/// is tested against a real repository.
const GIT_TRANSPORTS: [&str; 3] = ["https", "ssh", "file"];

fn refuse_option_like(input: InputRef) -> Result<InputRef, String> {
    // The repository slot is additionally constrained by `GIT_TRANSPORTS`,
    // which no `-` can satisfy; the ref slot is the one this reaches today.
    for (slot, value) in [("repository", &input.git_url), ("ref", &input.reference)] {
        if value.starts_with('-') {
            return Err(format!(
                "this host's `{}.url` gives a {slot} that begins with `-` ({value}), which git \
                 would read as an option rather than a value",
                input.name
            ));
        }
    }
    Ok(input)
}

/// Split a flake URL into the pieces `git ls-remote` and
/// `--override-input` each need.
///
/// Only the two forms ferrum hosts actually use are accepted. An
/// unrecognised scheme is an error rather than a guess: this string decides
/// what a root-privileged process fetches.
///
/// Any `user[:password]@` is removed first, so neither the returned input
/// nor any error text below can carry it -- and neither, therefore, can
/// anything built from them.
///
/// # Arguments
/// * `name` - the input's name, used only in the error text.
/// * `url` - the URL exactly as the host's `flake.nix` spells it.
///
/// # Returns
/// The decomposed input.
///
/// # Errors
/// When the URL names no owner and repository, or uses a scheme this check
/// cannot query.
pub fn decompose(name: &str, url: &str) -> Result<InputRef, String> {
    let safe = redact_userinfo(url);
    let credentials_redacted = safe != url;
    let url = safe.as_str();

    // The query is split off once, for both forms. Everything in it that
    // is not the ref survives into `extra_params`, because a parameter
    // like `dir=` decides WHICH flake inside the repository is evaluated:
    // dropping it would point a root-privileged `nix` at something the
    // operator never pinned.
    let (bare_url, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };
    let params: Vec<&str> = query
        .map(|q| q.split('&').filter(|kv| !kv.is_empty()).collect())
        .unwrap_or_default();
    let param = |key: &str| -> Option<&str> {
        params
            .iter()
            .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
    };
    let extra_params: Vec<String> = params
        .iter()
        .filter(|kv| !kv.starts_with("rev=") && !kv.starts_with("ref="))
        .map(|kv| (*kv).to_string())
        .collect();
    let query_reference = param("rev").or_else(|| param("ref"));

    if let Some(rest) = bare_url.strip_prefix(GITHUB_SCHEME) {
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() < 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(format!("this host's `{name}.url` names no owner and repository: {url}"));
        }
        let (owner, repo) = (parts[0], parts[1]);
        let reference = parts
            .get(2)
            .copied()
            .filter(|r| !r.is_empty())
            .or(query_reference);
        let base_url = format!("{GITHUB_SCHEME}{owner}/{repo}");
        return refuse_option_like(InputRef {
            name: name.to_string(),
            url: url.to_string(),
            git_url: format!("https://{GITHUB_HOST}/{owner}/{repo}.git"),
            reference: reference.unwrap_or("HEAD").to_string(),
            pinned: reference.map(is_full_rev).unwrap_or(false),
            base_url,
            extra_params,
            credentials_redacted,
        });
    }
    if let Some(bare) = bare_url.strip_prefix("git+") {
        let transport = bare.split_once("://").map(|(t, _)| t).unwrap_or("");
        if !GIT_TRANSPORTS.contains(&transport) {
            return Err(format!(
                "this host's `{name}.url` names the transport `{transport}://`, which this check \
                 will not fetch over: nothing it returns is signed, so a transport that can be \
                 rewritten in flight would let someone else choose both the revision and the \
                 metadata that makes it look newer. Use one of: {}",
                GIT_TRANSPORTS
                    .iter()
                    .map(|t| format!("{t}://"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        return refuse_option_like(InputRef {
            name: name.to_string(),
            url: url.to_string(),
            git_url: bare.to_string(),
            reference: query_reference.unwrap_or("HEAD").to_string(),
            pinned: query_reference.map(is_full_rev).unwrap_or(false),
            base_url: format!("git+{bare}"),
            extra_params,
            credentials_redacted,
        });
    }
    Err(format!(
        "this host's `{name}.url` uses a scheme this check does not know how to query: {url}"
    ))
}

/// What the host's `flake.lock` pins for one input today.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedInput {
    /// The full revision `flake.lock` pins, and the thing a candidate is
    /// compared against for equality.
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
///
/// # Arguments
/// * `text` - the contents of `/etc/ferrum/flake.lock`.
/// * `name` - the input name, normally `ferrum`.
///
/// # Returns
/// The pinned revision and its commit time.
///
/// # Errors
/// When the lock is not JSON, does not pin that input, or pins it without a
/// revision or without a `lastModified` -- each of which leaves nothing to
/// compare a candidate against.
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
///
/// `--` separates the options from the repository, so a repository that
/// looks like an option is handled as a pathname rather than parsed as one
/// -- git reports `strange pathname ... blocked` instead of honouring, say,
/// `--upload-pack`. `decompose` already refuses that form; this is the
/// second lock, and the one that holds for a form nobody anticipated.
///
/// # Arguments
/// * `git_url` - the repository, from the operator's own `flake.nix`.
/// * `reference` - the branch or tag to resolve, or `HEAD`.
///
/// # Returns
/// The arguments for `git`, without the program name.
pub fn ls_remote_argv(git_url: &str, reference: &str) -> Vec<String> {
    vec![
        "ls-remote".to_string(),
        "--".to_string(),
        git_url.to_string(),
        reference.to_string(),
    ]
}

/// Pick the revision a `ls-remote` answer gives for one ref.
///
/// A peeled annotated tag (`refs/tags/x^{}`) wins over the tag object
/// itself, because the commit is what gets built. Otherwise a branch beats
/// a tag of the same name, which is git's own precedence.
///
/// Nothing else counts. `git ls-remote <url> main` also answers with any
/// ref whose tail is `main` -- `refs/heads/feature/main` among them -- so
/// taking the first row would let a ref the operator never named decide
/// what a root-privileged process fetches. An answer that matches none of
/// the four forms is the ref not existing, and is reported as such.
///
/// # Arguments
/// * `stdout` - the raw `git ls-remote` output.
/// * `reference` - the ref that was asked for, used for precedence and for
///   the error text.
///
/// # Returns
/// The revision that ref points at.
///
/// # Errors
/// When the output names no revision at all, i.e. the ref does not exist in
/// that repository.
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
    Err(format!(
        "the ref `{reference}` this host tracks does not exist in that repository -- the refs \
         it answered with match no branch, tag or exact name of that ref"
    ))
}

/// The argv that asks Nix when a candidate revision was made.
///
/// Points at the remote flake URL directly, never at `/etc/ferrum`, so
/// there is no local lock file in the conversation at all;
/// `--no-write-lock-file` is belt and braces on top of that.
///
/// # Arguments
/// * `flakeref` - the candidate input pinned at an exact revision.
///
/// # Returns
/// The arguments for `nix`, without the program name.
pub fn metadata_argv(flakeref: &str) -> Vec<String> {
    vec![
        "flake".to_string(),
        "metadata".to_string(),
        "--json".to_string(),
        "--no-write-lock-file".to_string(),
        flakeref.to_string(),
    ]
}

/// Read `lastModified` out of a `nix flake metadata --json` answer, having
/// first checked the answer is about the revision that was asked for.
///
/// The timestamp is the whole basis for calling a candidate newer, so a
/// timestamp belonging to some other revision would silently decide an
/// update. Nix reports the revision it actually resolved, so the two are
/// compared, and an answer that names NO revision is refused for the same
/// reason a mismatched one is: it cannot be shown to describe the
/// candidate. Both route to `OrderUnknown` -- a candidate was resolved, so
/// the check did not fail; only the ordering is unavailable.
///
/// # Arguments
/// * `stdout` - the raw `nix flake metadata --json` output.
/// * `expected_rev` - the revision `git ls-remote` resolved.
///
/// # Returns
/// The candidate revision's `lastModified`.
///
/// # Errors
/// When the output is unparseable, names no revision, carries no
/// `lastModified`, or describes a different revision than the one that was
/// asked about.
pub fn parse_metadata_last_modified(stdout: &str, expected_rev: &str) -> Result<i64, String> {
    let doc: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("nix flake metadata returned output this check could not parse: {e}"))?;
    let reported = doc
        .get("revision")
        .or_else(|| doc.pointer("/locked/rev"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            "nix flake metadata named no revision, so its timestamp cannot be shown to describe \
             the candidate this check asked about"
                .to_string()
        })?;
    if reported != expected_rev {
        return Err(format!(
            "nix flake metadata answered about revision {} when this check asked about \
             {} -- refusing to order two revisions using a third one's timestamp",
            short_rev(reported),
            short_rev(expected_rev)
        ));
    }
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
/// Every path that resolved NO candidate goes through here, and this one
/// always sets `CheckFailed`; a path that resolved a candidate but could
/// not order it goes through `order_unknown` instead. Between them there
/// is no way to build an outcome that reads as up to date from a failure,
/// which is what makes that a structural property rather than a promise.
fn check_failed(
    input: Option<&InputRef>,
    locked: Option<&LockedInput>,
    error: String,
) -> CandidateOutcome {
    CandidateOutcome {
        report: CandidateReport {
            state: CandidateState::CheckFailed,
            input_name: Some(FERRUM_INPUT.to_string()),
            input_url: input.map(|i| i.url.clone()),
            reference: input.map(|i| i.reference.clone()),
            rev: None,
            current_rev: locked.map(|l| l.rev.clone()),
            last_modified: None,
            current_last_modified: locked.map(|l| l.last_modified),
            error: Some(error),
        },
        warnings: Vec::new(),
        input: input.cloned(),
    }
}

/// The one constructor for "a candidate was resolved, but it could not be
/// shown to be newer".
///
/// Separate from `check_failed` for the same structural reason that one
/// exists: a check that resolved a candidate did not fail, and a state
/// that cannot be reached by accident is worth more than a promise not to
/// set it. Both timestamps travel with it, because the operator is being
/// asked to judge something this module could not.
fn order_unknown(
    input: &InputRef,
    locked: &LockedInput,
    candidate_rev: &str,
    candidate_last_modified: Option<i64>,
    error: String,
    warnings: Vec<String>,
) -> CandidateOutcome {
    CandidateOutcome {
        report: CandidateReport {
            state: CandidateState::OrderUnknown,
            input_name: Some(FERRUM_INPUT.to_string()),
            input_url: Some(input.url.clone()),
            reference: Some(input.reference.clone()),
            rev: Some(candidate_rev.to_string()),
            current_rev: Some(locked.rev.clone()),
            last_modified: candidate_last_modified,
            current_last_modified: Some(locked.last_modified),
            error: Some(error),
        },
        warnings,
        input: Some(input.clone()),
    }
}

/// Resolve the candidate revision and classify it.
///
/// # Arguments
/// * `runner` - the subprocess seam; `git` and `nix` both go through it.
/// * `flake_nix` - the host's own root-owned `flake.nix`.
/// * `flake_lock` - the host's own `flake.lock`.
/// * `now` - the host clock, as seconds since the epoch. Only the ordering
///   uses it, and only to notice that the installed revision claims to have
///   been made in the future.
///
/// # Returns
/// Exactly one first-class state, never an absence: up to date, not newer,
/// an update with its exact revision, or a named failure.
///
/// # Errors
/// None -- a failure is a reported state, not an `Err`. A check that could
/// not reach the network still owes the operator every other fact it has.
pub fn resolve(
    runner: &dyn CommandRunner,
    flake_nix: &Path,
    flake_lock: &Path,
    now: u64,
) -> CandidateOutcome {
    let flake_nix_text = match std::fs::read_to_string(flake_nix) {
        Ok(t) => t,
        Err(e) => {
            return check_failed(None, None, format!("could not read {}: {e}", flake_nix.display()))
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

    let mut warnings = Vec::new();
    if input.credentials_redacted {
        // Said out loud because it changes what the check can reach: the
        // operator's next question, when a private fork stops resolving,
        // is why. The credential itself is not repeated here -- this text
        // is published in the same report the stripping exists to protect.
        warnings.push(format!(
            "this host's `{}.url` embeds a username or password; the update check neither uses \
             nor publishes it, so a private repository has to be reachable through git's own \
             credential configuration for root",
            input.name
        ));
    }
    let candidate_rev = if input.pinned {
        // Only when the pin is what this host is actually built from. An
        // operator who has just edited flake.nix forward is in a genuinely
        // different position: there IS something newer waiting, and telling
        // them nothing can ever be discovered would be false at the exact
        // moment it matters.
        if input.reference == locked.rev {
            warnings.push(format!(
                "this host pins the ferrum input at an exact commit ({}), so no newer release \
                 can be discovered until you change that pin yourself",
                short_rev(&input.reference)
            ));
        }
        input.reference.clone()
    } else {
        let out = match runner.run("git", &ls_remote_argv(&input.git_url, &input.reference)) {
            Ok(o) => o,
            Err(e) => return check_failed(Some(&input), Some(&locked), e),
        };
        if !out.success {
            return check_failed(
                Some(&input),
                Some(&locked),
                format!(
                    "could not reach {}: {}",
                    input.git_url,
                    redact_urls_in(out.stderr.trim())
                ),
            );
        }
        match parse_ls_remote(&out.stdout, &input.reference) {
            Ok(rev) => rev,
            Err(e) => return check_failed(Some(&input), Some(&locked), e),
        }
    };

    let mut report = CandidateReport {
        state: CandidateState::UpToDate,
        input_name: Some(input.name.clone()),
        input_url: Some(input.url.clone()),
        reference: Some(input.reference.clone()),
        rev: Some(candidate_rev.clone()),
        current_rev: Some(locked.rev.clone()),
        last_modified: None,
        current_last_modified: Some(locked.last_modified),
        error: None,
    };

    if candidate_rev == locked.rev {
        return CandidateOutcome { report, warnings, input: Some(input) };
    }

    let flakeref = input.flakeref_for_rev(&candidate_rev);
    let out = match runner.run("nix", &metadata_argv(&flakeref)) {
        Ok(o) => o,
        Err(e) => return order_unknown(&input, &locked, &candidate_rev, None, e, warnings),
    };
    if !out.success {
        return order_unknown(
            &input,
            &locked,
            &candidate_rev,
            None,
            format!(
                "could not establish whether {} is newer than what this host runs: {}",
                short_rev(&candidate_rev),
                redact_urls_in(out.stderr.trim())
            ),
            warnings,
        );
    }
    let candidate_last_modified = match parse_metadata_last_modified(&out.stdout, &candidate_rev) {
        Ok(v) => v,
        Err(e) => return order_unknown(&input, &locked, &candidate_rev, None, e, warnings),
    };
    report.last_modified = Some(candidate_last_modified);

    // The silent-forever case, and the only one here that needs no
    // attacker at all: if the installed revision claims a commit time in
    // the future, every genuine later release compares as older and this
    // host reports "nothing to do" for good. R1 forbids exactly that, so
    // an anchor the clock contradicts orders nothing and says why.
    if locked.last_modified > now as i64 {
        let said = format!(
            "this host's flake.lock records the revision it runs as made at {} (epoch seconds), \
             which is later than this host's clock reads now ({now}); the candidate {} reports \
             {}. Nothing can be ordered against an anchor from the future, so this check will \
             not say whether that candidate is newer until the two agree",
            locked.last_modified,
            short_rev(&candidate_rev),
            candidate_last_modified
        );
        warnings.push(said.clone());
        return order_unknown(
            &input,
            &locked,
            &candidate_rev,
            Some(candidate_last_modified),
            said,
            warnings,
        );
    }

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

    /// A fixed host clock for the tests. Every fixture's timestamps sit
    /// far below it, so only the tests that mean to exercise clock skew do.
    const NOW: u64 = 1_700_000_000;

    /// `resolve` at `NOW`; the clock is only interesting to the two tests
    /// that set out to move it.
    fn resolve_at(
        runner: &dyn CommandRunner,
        flake_nix: &std::path::Path,
        flake_lock: &std::path::Path,
    ) -> CandidateOutcome {
        resolve(runner, flake_nix, flake_lock, NOW)
    }

    const OLD: &str = "1111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222";

    fn gh(path: &str) -> String {
        format!("{GITHUB_SCHEME}{path}")
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
        assert_eq!(input.git_url, format!("https://{GITHUB_HOST}/syms-dev/ferrum.git"));
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

    /// A metadata answer that is about the revision it was asked about --
    /// the honest case. `rev` is threaded through rather than hardcoded so
    /// a test cannot accidentally pass by describing the wrong commit.
    fn metadata_ok_for(
        rev: &str,
        last_modified: i64,
    ) -> (&'static str, crate::update_check::CommandOutput) {
        (
            "flake metadata",
            ok(&serde_json::json!({"lastModified": last_modified, "revision": rev}).to_string()),
        )
    }

    /// R1: a resolvable, newer candidate is an update, and it carries the
    /// exact revision -- DA-1's replacement for signature verification is
    /// that the operator can see and refuse this commit.
    #[test]
    fn a_newer_candidate_is_an_update_carrying_its_exact_revision() {
        let h = host(&gh("syms-dev/ferrum"), OLD, 100);
        let runner = FakeRunner::new(vec![ls_remote_ok(NEW), metadata_ok_for(NEW, 200)]);
        let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
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
                "--".to_string(),
                format!("https://{GITHUB_HOST}/syms-dev/ferrum.git"),
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
        let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
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
        let runner = FakeRunner::new(vec![ls_remote_ok(OLD), metadata_ok_for(OLD, 100)]);
        let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::NotNewer);
        assert_eq!(outcome.report.rev.as_deref(), Some(OLD));

        // Same commit time is not newer either.
        let runner = FakeRunner::new(vec![ls_remote_ok(OLD), metadata_ok_for(OLD, 200)]);
        assert_eq!(
            resolve_at(&runner, &h.flake_nix, &h.flake_lock).report.state,
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
        let cases: Vec<(&str, CandidateState, FakeRunner)> = vec![
            ("the remote is unreachable", CandidateState::CheckFailed, FakeRunner::new(vec![(
                "ls-remote",
                fail("fatal: unable to access 'https://...': Could not resolve host"),
            )])),
            ("the ref is gone", CandidateState::CheckFailed, FakeRunner::new(vec![("ls-remote", ok(""))])),
            ("git itself is missing", CandidateState::CheckFailed, FakeRunner::new(vec![])),
            ("the ordering probe fails", CandidateState::OrderUnknown, FakeRunner::new(vec![
                ls_remote_ok(NEW),
                ("flake metadata", fail("error: unable to download: HTTP error 403")),
            ])),
            ("the ordering probe answers nonsense", CandidateState::OrderUnknown, FakeRunner::new(vec![
                ls_remote_ok(NEW),
                ("flake metadata", ok("not json")),
            ])),
        ];
        for (what, expected, runner) in cases {
            let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
            assert_eq!(outcome.report.state, expected, "{what} must be a named non-clean state");
            // The whole point: not one of the three states an operator
            // would read as "there is nothing to do here".
            for clean in [
                CandidateState::UpToDate,
                CandidateState::NotNewer,
                CandidateState::UpdateAvailable,
            ] {
                assert_ne!(outcome.report.state, clean, "{what}");
            }
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
            resolve_at(&runner, &h.flake_nix, &h.flake_lock).report.state,
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
        let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
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
        let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::UpToDate);
        assert!(runner.programs().is_empty(), "a pinned host queries nothing");
        assert!(
            outcome.warnings.iter().any(|w| w.contains("exact commit")),
            "{:?}",
            outcome.warnings
        );
    }

    /// The other half of hand-pinning, and the one the warning gets wrong
    /// if it fires on `pinned` alone: the operator has ALREADY edited
    /// flake.nix forward and has not applied yet. There genuinely is
    /// something newer waiting, so telling them nothing can ever be
    /// discovered would be false at the exact moment it matters.
    #[test]
    fn a_pin_edited_ahead_of_the_lock_is_an_update_with_no_nothing_will_change_warning() {
        let h = host(&gh(&format!("syms-dev/ferrum/{NEW}")), OLD, 100);
        let runner = FakeRunner::new(vec![metadata_ok_for(NEW, 200)]);
        let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::UpdateAvailable);
        assert_eq!(outcome.report.rev.as_deref(), Some(NEW));
        assert_eq!(outcome.report.current_rev.as_deref(), Some(OLD));
        assert!(
            !outcome.warnings.iter().any(|w| w.contains("exact commit")),
            "there IS something newer here: {:?}",
            outcome.warnings
        );
        // Still no ls-remote: a pinned ref needs no resolving either way.
        assert_eq!(runner.programs(), vec!["nix"]);
    }

    /// The timestamp is the whole basis for calling a candidate newer, so
    /// one belonging to a different revision would silently decide an
    /// update. It fails closed instead.
    #[test]
    fn a_metadata_answer_about_a_different_revision_is_refused() {
        let h = host(&gh("syms-dev/ferrum"), OLD, 100);
        // ls-remote resolved NEW; the metadata answer describes some third
        // commit and claims it is much newer.
        let third = "3333333333333333333333333333333333333333";
        let runner = FakeRunner::new(vec![ls_remote_ok(NEW), metadata_ok_for(third, 9_999)]);
        let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::OrderUnknown);
        let error = outcome.report.error.as_deref().unwrap();
        assert!(error.contains("3333333") && error.contains("2222222"), "{error}");

        // The control: the SAME parse accepts an answer about the right
        // revision, so "refused" above is about the mismatch and not about
        // the parser refusing everything.
        let runner = FakeRunner::new(vec![ls_remote_ok(NEW), metadata_ok_for(NEW, 200)]);
        assert_eq!(
            resolve_at(&runner, &h.flake_nix, &h.flake_lock).report.state,
            CandidateState::UpdateAvailable
        );
    }

    /// An answer that names no revision cannot be shown to be about the
    /// candidate, so its timestamp cannot order anything. Accepting it at
    /// face value -- which this check used to do -- meant an unrelated
    /// flake's timestamp could decide an update.
    #[test]
    fn metadata_that_names_no_revision_cannot_order_and_says_so() {
        let doc = serde_json::json!({"lastModified": 200}).to_string();
        let err = parse_metadata_last_modified(&doc, NEW).unwrap_err();
        assert!(err.contains("revision"), "{err}");

        // The control: an answer that DOES name the right revision still
        // orders, so this is about the missing field and not a parser that
        // refuses everything.
        let doc = serde_json::json!({"lastModified": 200, "revision": NEW}).to_string();
        assert_eq!(parse_metadata_last_modified(&doc, NEW).unwrap(), 200);
    }

    #[test]
    fn a_missing_flake_lock_is_a_named_failure_not_a_clean_result() {
        let dir = tempfile::tempdir().unwrap();
        let flake_nix = dir.path().join("flake.nix");
        std::fs::write(&flake_nix, template_flake(&gh("syms-dev/ferrum"))).unwrap();
        let runner = FakeRunner::new(vec![]);
        let outcome = resolve_at(&runner, &flake_nix, &dir.path().join("flake.lock"));
        assert_eq!(outcome.report.state, CandidateState::CheckFailed);
        assert!(outcome.report.error.as_deref().unwrap().contains("flake.lock"));
    }

    // ---- M2 / L1: what the operator's own flake.nix must not republish ----

    /// The credential a `git+` URL can carry, and the account name beside
    /// it. Both are the operator's, and both live at the trust level of a
    /// root-only file.
    const TOKEN: &str = "ghp-S3CRET-cafebabe";
    const ACCOUNT: &str = "ferrumbot";

    /// The URL an operator with a private fork writes.
    fn credentialled_url() -> String {
        format!("git+https://{ACCOUNT}:{TOKEN}@code.example/ferrum.git?ref=main")
    }

    /// The one matcher every absence assertion below goes through, so that
    /// a matcher which could never fire would fail the positive controls
    /// rather than quietly reporting everything clean.
    fn leaks(haystack: &str) -> bool {
        haystack.contains(TOKEN) || haystack.contains(ACCOUNT)
    }

    /// The positive control on the matcher itself: it fires on the string
    /// the operator actually wrote. Every `!leaks(..)` below is only worth
    /// something because this passes.
    #[test]
    fn the_credential_matcher_fires_on_the_url_the_operator_actually_wrote() {
        assert!(leaks(&credentialled_url()), "the matcher cannot find a credential that IS there");
        assert!(leaks(&format!("fatal: could not read Username for {}", credentialled_url())));
        assert!(!leaks("git+https://code.example/ferrum.git?ref=main"), "and it does not fire on a clean URL");
    }

    /// M2: userinfo is stripped where the URL is parsed, so no field of the
    /// parsed input can carry it onward -- not the display URL, not the
    /// argv the root-privileged fetch is built from, not the flakeref.
    #[test]
    fn no_field_of_a_parsed_input_carries_the_operators_credentials() {
        let input = decompose("ferrum", &credentialled_url()).unwrap();
        for (field, value) in [
            ("url", input.url.clone()),
            ("git_url", input.git_url.clone()),
            ("base_url", input.base_url.clone()),
            ("reference", input.reference.clone()),
            ("flakeref_for_rev", input.flakeref_for_rev(NEW)),
        ] {
            assert!(!leaks(&value), "{field} still carries the operator's credential: {value}");
        }
        // And it still names the same repository and ref -- redaction that
        // lost the repository would be a different bug.
        assert_eq!(input.git_url, "https://code.example/ferrum.git");
        assert_eq!(input.base_url, "git+https://code.example/ferrum.git");
        assert_eq!(input.reference, "main");
    }

    /// M2, end to end through the resolver: the report document, the
    /// warnings, and every argv a root-privileged process is handed.
    #[test]
    fn a_credentialled_input_publishes_no_credential_into_the_report_or_any_argv() {
        let h = host(&credentialled_url(), OLD, 100);
        // The positive control at the other end: the credential really is
        // in the file this check reads.
        assert!(
            leaks(&std::fs::read_to_string(&h.flake_nix).unwrap()),
            "the fixture does not actually contain a credential"
        );

        let runner = FakeRunner::new(vec![
            ("ls-remote", ok(&format!("{NEW}\trefs/heads/main\n"))),
            metadata_ok_for(NEW, 200),
        ]);
        let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::UpdateAvailable);

        let json = serde_json::to_string(&outcome.report).unwrap();
        assert!(!leaks(&json), "the published report carries the credential: {json}");
        for argv in runner.argvs() {
            let joined = argv.join(" ");
            assert!(!leaks(&joined), "a root-privileged argv carries the credential: {joined}");
        }
        for w in &outcome.warnings {
            assert!(!leaks(w), "a warning carries the credential: {w}");
        }
    }

    /// M2's failure paths, which is where an error string would otherwise
    /// carry the URL verbatim: an unreachable remote, an unusable metadata
    /// answer, and a scheme this check refuses outright.
    #[test]
    fn no_failure_path_puts_the_credential_into_the_reports_error_text() {
        let h = host(&credentialled_url(), OLD, 100);

        let unreachable = FakeRunner::new(vec![(
            "ls-remote",
            fail(&format!("fatal: could not read Username for {}", credentialled_url())),
        )]);
        let outcome = resolve_at(&unreachable, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::CheckFailed);
        let json = serde_json::to_string(&outcome.report).unwrap();
        assert!(!leaks(&json), "the unreachable-remote report leaks: {json}");

        let bad_metadata = FakeRunner::new(vec![
            ("ls-remote", ok(&format!("{NEW}\trefs/heads/main\n"))),
            ("flake metadata", fail(&format!("error: unable to fetch {}", credentialled_url()))),
        ]);
        let outcome = resolve_at(&bad_metadata, &h.flake_nix, &h.flake_lock);
        assert_eq!(outcome.report.state, CandidateState::OrderUnknown);
        let json = serde_json::to_string(&outcome.report).unwrap();
        assert!(!leaks(&json), "the metadata-failure report leaks: {json}");

        // A scheme the check refuses still has to refuse it without
        // quoting the credential back.
        let err = decompose("ferrum", &format!("ftp://{ACCOUNT}:{TOKEN}@code.example/x")).unwrap_err();
        assert!(!leaks(&err), "the unknown-scheme error leaks: {err}");
        let err = decompose("ferrum", &format!("{GITHUB_SCHEME}{ACCOUNT}:{TOKEN}@x")).unwrap_err();
        assert!(!leaks(&err), "the malformed-github error leaks: {err}");
    }

    /// The credential-less forms are what almost every host actually has,
    /// and redaction must not touch them.
    #[test]
    fn a_url_with_no_credentials_is_carried_through_exactly_as_written() {
        let input = decompose("ferrum", "git+https://code.example/ferrum.git?ref=main").unwrap();
        assert_eq!(input.url, "git+https://code.example/ferrum.git?ref=main");
        assert_eq!(input.git_url, "https://code.example/ferrum.git");
        assert_eq!(input.base_url, "git+https://code.example/ferrum.git");
        assert_eq!(input.reference, "main");

        let input = decompose("ferrum", &gh("syms-dev/ferrum/release")).unwrap();
        assert_eq!(input.url, gh("syms-dev/ferrum/release"));
        assert_eq!(input.git_url, format!("https://{GITHUB_HOST}/syms-dev/ferrum.git"));
        assert_eq!(input.reference, "release");
    }

    /// Userinfo with no password at all, and a password built from the
    /// characters that break a first-`@`/first-`:` reading of a URL.
    #[test]
    fn userinfo_is_stripped_whether_or_not_it_has_a_password_and_whatever_it_contains() {
        let input = decompose("ferrum", &format!("git+https://{ACCOUNT}@code.example/ferrum.git")).unwrap();
        assert_eq!(input.git_url, "https://code.example/ferrum.git");
        assert!(!leaks(&input.url), "{}", input.url);

        // A password holding `@`, `:` and a percent-encoded `/`: the last
        // `@` before the path is the boundary, not the first.
        let awkward = format!("git+https://{ACCOUNT}:p@ss:w%2Frd@code.example/ferrum.git?ref=main");
        let input = decompose("ferrum", &awkward).unwrap();
        assert_eq!(input.git_url, "https://code.example/ferrum.git");
        assert_eq!(input.reference, "main");
        for value in [input.url.clone(), input.git_url.clone(), input.base_url.clone()] {
            assert!(!value.contains("p@ss"), "a fragment of the password survived: {value}");
            assert!(!leaks(&value), "{value}");
        }
    }

    /// L1: both argv slots are operator text handed to a root-privileged
    /// `git`, so a value that would be read as an option is refused at the
    /// parse, and the repository argument is additionally placed after
    /// `--`. Defence in depth: `/etc/ferrum/flake.nix` is root-owned and
    /// ferrumd cannot write it, so this closes a form, not a live hole.
    #[test]
    fn a_value_that_git_would_read_as_an_option_never_becomes_one() {
        for url in [
            "git+--upload-pack=/bin/false",
            "git+https://code.example/x.git?ref=--upload-pack=/bin/false",
            &gh("syms-dev/ferrum/-upload-pack=/bin/false"),
            "git+-o=x",
        ] {
            assert!(decompose("ferrum", url).is_err(), "{url} must be refused");
        }
        // Anti-vacuity: the same guard accepts every ordinary form, so the
        // refusals above are about the leading dash and not a matcher that
        // rejects everything.
        assert!(decompose("ferrum", &gh("syms-dev/ferrum")).is_ok());
        assert!(decompose("ferrum", &gh("syms-dev/ferrum/release")).is_ok());
        assert!(decompose("ferrum", "git+https://code.example/ferrum.git?ref=main").is_ok());

        // And the repository argument sits behind `--`, which makes `git`
        // treat an option-looking repository as a pathname even if some
        // form got past the guard above.
        assert_eq!(
            ls_remote_argv("https://code.example/x.git", "main"),
            vec!["ls-remote", "--", "https://code.example/x.git", "main"]
        );
    }

    // ---- C: the three transport and resolution defects ----

    /// Nothing that comes back is signed, so the transport IS the trust
    /// chain: on plaintext http a network attacker picks both the revision
    /// and the metadata that would make it look newer.
    #[test]
    fn a_transport_that_can_be_rewritten_in_flight_is_refused() {
        let err = decompose("ferrum", "git+http://code.example/ferrum.git").unwrap_err();
        assert!(err.contains("http://"), "the error must name the transport: {err}");

        // Anti-vacuity: the transports that cannot be rewritten in flight
        // are all accepted, so the refusal above is about `http` and not a
        // guard that rejects every `git+` form.
        for url in [
            "git+https://code.example/ferrum.git",
            "git+ssh://git@code.example/ferrum.git",
            "git+file:///srv/ferrum",
        ] {
            assert!(decompose("ferrum", url).is_ok(), "{url} must be accepted");
        }
    }

    /// An ssh login name is not a secret -- it is how the transport picks
    /// an account, and `git@` is what every ssh forge expects. Stripping it
    /// would break the remote while protecting nothing. A password in an
    /// ssh URL means nothing to ssh and is still dropped.
    #[test]
    fn an_ssh_login_name_survives_but_a_password_beside_it_does_not() {
        let input = decompose("ferrum", "git+ssh://git@code.example/ferrum.git").unwrap();
        assert_eq!(input.git_url, "ssh://git@code.example/ferrum.git");
        assert!(!input.credentials_redacted, "nothing was redacted, so nothing should be claimed");

        let input = decompose("ferrum", "git+ssh://git:hunter2@code.example/ferrum.git").unwrap();
        assert_eq!(input.git_url, "ssh://git@code.example/ferrum.git");
        assert!(input.credentials_redacted);
        for value in [input.url.clone(), input.git_url.clone(), input.base_url.clone()] {
            assert!(!value.contains("hunter2"), "the password survived: {value}");
        }
    }

    /// `git ls-remote <url> main` matches any ref whose tail is `main`, so
    /// falling through to the first row let a ref the operator never named
    /// decide what a root-privileged process fetches.
    #[test]
    fn a_ref_the_operator_did_not_name_cannot_decide_the_revision() {
        let stdout = format!("{NEW}\trefs/heads/feature/main\n");
        let err = parse_ls_remote(&stdout, "main").unwrap_err();
        assert!(err.contains("main"), "the error must name the ref that was asked for: {err}");

        // Anti-vacuity: every form that IS an exact match still resolves.
        assert_eq!(parse_ls_remote(&format!("{NEW}\trefs/heads/main\n"), "main").unwrap(), NEW);
        assert_eq!(parse_ls_remote(&format!("{NEW}\trefs/tags/main\n"), "main").unwrap(), NEW);
        assert_eq!(parse_ls_remote(&format!("{NEW}\tHEAD\n"), "HEAD").unwrap(), NEW);
    }

    /// `dir=` decides WHICH FLAKE inside the repository is evaluated, and
    /// the rebuilt flakeref is what a root-privileged `nix` is pointed at.
    /// Dropping it meant evaluating something the operator never pinned.
    #[test]
    fn a_subdirectory_pin_survives_into_what_nix_is_asked_to_fetch() {
        let input = decompose("ferrum", "git+https://code.example/ferrum.git?dir=nix&ref=main").unwrap();
        assert_eq!(input.reference, "main");
        let flakeref = input.flakeref_for_rev(NEW);
        assert!(flakeref.contains("dir=nix"), "the pinned subdirectory was dropped: {flakeref}");
        assert!(flakeref.contains(&format!("rev={NEW}")), "{flakeref}");
        // The ref is superseded by the exact revision, not carried beside it.
        assert!(!flakeref.contains("ref=main"), "{flakeref}");

        // And a URL with no parameters is rebuilt exactly as before.
        let plain = decompose("ferrum", "git+https://code.example/ferrum.git").unwrap();
        assert_eq!(
            plain.flakeref_for_rev(NEW),
            format!("git+https://code.example/ferrum.git?rev={NEW}")
        );
    }

    // ---- A: ordering that does not claim more than it knows ----

    /// The wire value the UI reads. Asserted on the serialization, not on
    /// the variant name, because the vocabulary is the contract.
    #[test]
    fn the_undecidable_ordering_state_has_the_wire_value_the_ui_reads() {
        assert_eq!(
            serde_json::to_string(&CandidateState::OrderUnknown).unwrap(),
            "\"order-unknown\""
        );
    }

    /// R1's silent-forever case, and the only one here reachable with no
    /// attacker at all: one commit carrying a future timestamp becomes the
    /// anchor, and every genuine later release then reports "not newer"
    /// for good. A silent false "you are current" is precisely what R1
    /// forbids, so it is loud and it names both numbers.
    #[test]
    fn an_installed_timestamp_from_the_future_is_loud_rather_than_silently_not_newer() {
        let future = NOW as i64 + 86_400;
        let h = host(&gh("syms-dev/ferrum"), OLD, future);
        let runner = FakeRunner::new(vec![ls_remote_ok(NEW), metadata_ok_for(NEW, NOW as i64)]);
        let outcome = resolve(&runner, &h.flake_nix, &h.flake_lock, NOW);

        assert_eq!(outcome.report.state, CandidateState::OrderUnknown);
        assert_eq!(outcome.report.rev.as_deref(), Some(NEW), "the candidate is still reported");
        let warned = outcome.warnings.join(" | ");
        assert!(warned.contains(&future.to_string()), "both timestamps must be named: {warned}");
        assert!(warned.contains(&NOW.to_string()), "both timestamps must be named: {warned}");

        // The control: the same fixture with a sane installed timestamp
        // orders normally, so this is about the future date and not about
        // the ordering having been disabled.
        let h = host(&gh("syms-dev/ferrum"), OLD, 100);
        let runner = FakeRunner::new(vec![ls_remote_ok(NEW), metadata_ok_for(NEW, 200)]);
        assert_eq!(
            resolve(&runner, &h.flake_nix, &h.flake_lock, NOW).report.state,
            CandidateState::UpdateAvailable
        );
    }

    /// Every way the ordering probe can fail to answer. None of them may
    /// become `UpdateAvailable` (an unproven update) or `NotNewer` (a
    /// silent "nothing to do"), and each keeps the candidate it did
    /// resolve plus the real text.
    #[test]
    fn an_ordering_probe_that_cannot_answer_is_order_unknown_not_an_update() {
        let h = host(&gh("syms-dev/ferrum"), OLD, 100);
        let third = "3333333333333333333333333333333333333333";
        let cases: Vec<(&str, FakeRunner)> = vec![
            (
                "the probe itself failed",
                FakeRunner::new(vec![
                    ls_remote_ok(NEW),
                    ("flake metadata", fail("error: unable to fetch")),
                ]),
            ),
            (
                "the answer carried no lastModified",
                FakeRunner::new(vec![
                    ls_remote_ok(NEW),
                    ("flake metadata", ok(&serde_json::json!({"revision": NEW}).to_string())),
                ]),
            ),
            (
                "the answer named no revision at all",
                FakeRunner::new(vec![
                    ls_remote_ok(NEW),
                    ("flake metadata", ok(&serde_json::json!({"lastModified": 200}).to_string())),
                ]),
            ),
            (
                "the answer was about a different revision",
                FakeRunner::new(vec![ls_remote_ok(NEW), metadata_ok_for(third, 9_999)]),
            ),
        ];
        for (label, runner) in cases {
            let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);
            assert_eq!(outcome.report.state, CandidateState::OrderUnknown, "{label}");
            assert_eq!(outcome.report.rev.as_deref(), Some(NEW), "{label}: candidate still reported");
            assert!(outcome.report.error.is_some(), "{label}: the real text must survive");
        }

        // Anti-vacuity: a usable answer still orders, so `OrderUnknown`
        // above is a finding rather than the only state left reachable.
        let runner = FakeRunner::new(vec![ls_remote_ok(NEW), metadata_ok_for(NEW, 200)]);
        assert_eq!(
            resolve_at(&runner, &h.flake_nix, &h.flake_lock).report.state,
            CandidateState::UpdateAvailable
        );
    }

    /// The ordering rests on self-reported commit metadata, so the report
    /// shows the operator the numbers it used rather than only the verdict
    /// it drew from them.
    #[test]
    fn the_report_carries_both_timestamps_and_both_revisions() {
        let h = host(&gh("syms-dev/ferrum"), OLD, 100);
        let runner = FakeRunner::new(vec![ls_remote_ok(NEW), metadata_ok_for(NEW, 200)]);
        let outcome = resolve_at(&runner, &h.flake_nix, &h.flake_lock);

        assert_eq!(outcome.report.current_last_modified, Some(100));
        assert_eq!(outcome.report.last_modified, Some(200));
        assert_eq!(outcome.report.current_rev.as_deref(), Some(OLD));
        assert_eq!(outcome.report.rev.as_deref(), Some(NEW));

        let json = serde_json::to_string(&outcome.report).unwrap();
        assert!(json.contains("\"lastModified\":200"), "{json}");
        assert!(json.contains("\"currentLastModified\":100"), "{json}");
    }
}
