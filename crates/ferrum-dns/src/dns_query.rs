//! The post-apply check: does the record ferrum just wrote actually resolve,
//! asked of the servers the world will ask?
//!
//! This is the check the parent incident is about. `auth.thesyms.ca` did not
//! resolve after an install that reported success, and nothing in ferrum ever
//! looked. Writing a record to Cloudflare proves Cloudflare accepted the
//! write; it does not prove the name answers.
//!
//! **Why the query goes to the zone's own nameservers (D-07).** A recursive
//! resolver -- the host's `/etc/resolv.conf` one, or a public one -- can hold
//! a *negative* cache entry for a name that was looked up before the record
//! existed, for as long as the zone's SOA minimum. Asking it would report a
//! freshly created record as absent and turn a healthy apply into a false
//! alarm. [`crate::Zone::nameservers`] is carried on the zone by
//! `resolve_zone` precisely so this module has the authoritative servers
//! without a second lookup.
//!
//! **Why this shells out to `dig` (decision D-10).** The alternative was a
//! hand-rolled DNS-over-UDP client, which would put a wire-format parser --
//! name-compression pointers, label loops, truncation, transaction-id
//! validation -- inside a root-privileged binary reading bytes from an
//! untrusted network peer. Nothing in this file parses DNS wire format.
//! `dig +short` prints plain ASCII, one target per line, and that is all
//! that is read here. It is also the house idiom: `ferrum-apply` already
//! shells out to `systemctl`, `nix`, `btrfs` and `sops` the same way, with
//! an argv vector and never a shell string.
//!
//! It also removes a circularity the hand-rolled design never noticed:
//! `Zone.nameservers` are *hostnames*, so a socket-level implementation
//! would have to resolve them first -- through the very recursive resolver
//! D-07 exists to bypass. `dig @ns1.cloudflare.com` lets `dig` resolve the
//! `@server` itself, which is safe because that lookup is for a long-TTL,
//! operationally stable NS hostname rather than the record under test.
//!
//! **"Could not check" is not "your DNS is wrong."** These are different
//! answers to an operator and this module never conflates them. The
//! distinction rests on `dig`'s exit code, which was verified by real
//! invocation against this repository's pinned nixpkgs
//! (`bind-9.20.23`, `pkgs.dnsutils`) rather than assumed:
//!
//! | What happened | `dig +short` exit | stdout | Verdict |
//! |---|---|---|---|
//! | Server answered, record present | 0 | the target | [`Verification::Matched`] |
//! | Server answered, no such record | 0 | empty | [`Verification::Mismatch`] |
//! | Server answered with something else | 0 | the other target | [`Verification::Mismatch`] |
//! | Timed out / connection refused | 9 | `;; no servers could be reached` | [`Verification::CouldNotCheck`] |
//!
//! The last row is why the exit code is read before the output is: under
//! `+short`, `dig` writes those `;;` diagnostic lines to **stdout**, so a
//! parser that trusted stdout alone would read "no servers could be reached"
//! as an answer. Lines beginning with `;` are discarded for the same reason.

use std::net::Ipv4Addr;
use std::process::Command;
use std::time::Duration;

use crate::RecordTarget;

/// Attempts a verification makes before it gives up.
///
/// Cloudflare's own edge is usually consistent within a second or two, but
/// "usually" is not a guarantee, and the cost of being wrong here is telling
/// an operator their DNS is broken when it merely had not propagated yet.
const DEFAULT_ATTEMPTS: u32 = 4;

/// Pause between attempts. Four attempts two seconds apart bounds the whole
/// check at roughly six seconds of waiting, which is what the developer
/// documentation means by "a few attempts over a handful of seconds" -- an
/// apply holds the operator's terminal while this runs.
const DEFAULT_DELAY: Duration = Duration::from_secs(2);

/// How long one `dig` invocation may wait for one server.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest a fully qualified DNS name may be, per RFC 1035.
const MAX_NAME_LEN: usize = 253;

/// One authoritative server to ask.
///
/// `port` exists so the test suite can point the real `dig` at a fake
/// nameserver bound to an ephemeral loopback port. Production callers leave
/// it `None`, which means port 53.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nameserver {
    /// The server's hostname or address, as Cloudflare reported it.
    pub host: String,
    /// A non-default port, or `None` for 53.
    pub port: Option<u16>,
}

impl Nameserver {
    /// A nameserver on the default DNS port.
    ///
    /// # Arguments
    /// * `host` - hostname or address, e.g. `amber.ns.cloudflare.com`.
    #[must_use]
    pub fn new(host: &str) -> Self {
        Nameserver {
            host: host.to_string(),
            port: None,
        }
    }

    /// How this server is named in an operator-facing reason string.
    fn label(&self) -> String {
        match self.port {
            Some(port) => format!("{}#{port}", self.host),
            None => self.host.clone(),
        }
    }
}

/// How hard a verification tries before it reports a verdict.
///
/// Public, and not merely a set of constants, because the caller that folds
/// this into `ApplyResult` is the one holding the operator's terminal: an
/// apply wants the bounded default, while a scheduled updater could
/// reasonably wait longer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollPolicy {
    /// Attempts before giving up. Zero is treated as one.
    pub attempts: u32,
    /// Pause between attempts.
    pub delay: Duration,
    /// How long one query waits for one server.
    pub timeout: Duration,
}

impl Default for PollPolicy {
    /// The bounded poll an apply uses.
    fn default() -> Self {
        PollPolicy {
            attempts: DEFAULT_ATTEMPTS,
            delay: DEFAULT_DELAY,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// What a verification established about one name.
///
/// Three variants rather than a `bool`, deliberately. The frozen seam in the
/// R1 developer documentation named this `Result<bool, std::io::Error>`, and
/// that shape cannot express the distinction decision D-10 makes mandatory:
/// a `false` would mean both "the record is wrong" and "a nameserver was
/// unreachable", and the caller would have to guess which sentence to show
/// the operator. Telling someone their DNS is broken when a server merely
/// timed out is the specific failure this type exists to prevent. Both
/// non-matching variants still fold into `ApplyResult::Degraded` per D-08;
/// only the reason string differs, which is the whole point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// Every nameserver asked returned exactly the expected target.
    Matched,
    /// At least one nameserver answered, and its answer was not the expected
    /// target. This is a real DNS problem.
    Mismatch {
        /// What to tell the operator, naming the servers and what they said.
        reason: String,
    },
    /// No nameserver produced a usable answer, so the record's state is
    /// unknown. This is *not* a statement that the record is wrong.
    CouldNotCheck {
        /// What to tell the operator, naming why the check did not complete.
        reason: String,
    },
}

impl Verification {
    /// Whether the record was confirmed present and correct.
    #[must_use]
    pub fn is_matched(&self) -> bool {
        matches!(self, Verification::Matched)
    }

    /// The operator-facing explanation, or `None` when nothing is wrong.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Verification::Matched => None,
            Verification::Mismatch { reason } | Verification::CouldNotCheck { reason } => {
                Some(reason)
            }
        }
    }
}

impl std::fmt::Display for Verification {
    /// Renders the verdict as the sentence an apply appends to its reason.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verification::Matched => f.write_str("resolves as expected"),
            Verification::Mismatch { reason } => {
                write!(f, "does not resolve as expected: {reason}")
            }
            Verification::CouldNotCheck { reason } => write!(f, "could not be checked: {reason}"),
        }
    }
}

/// What one `dig` invocation established about one server.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ServerAnswer {
    /// The server answered. The targets are the lines `dig +short` printed,
    /// which is empty when the name exists with no record of that type.
    Answered(Vec<String>),
    /// The query never completed, and this is why.
    Unanswered(String),
}

/// Asks every authoritative nameserver whether `name` points where ferrum
/// intended, retrying within `policy` before reporting a mismatch.
///
/// # Arguments
/// * `servers` - the zone's own authoritative nameservers. Empty is itself
///   an answer: nothing can be checked.
/// * `name` - the fully qualified record name, e.g. `auth.example.com`.
/// * `expected` - the target ferrum wrote. Its variant also decides the
///   record type queried: an `A` lookup on a `CNAME` would return the
///   address the alias resolves to, not the alias, and would compare
///   unequal for the wrong reason.
/// * `policy` - how many attempts, how far apart, and how long each waits.
///
/// # Returns
/// [`Verification::Matched`] when every server answered with the expected
/// target; [`Verification::Mismatch`] when a server answered with something
/// else; [`Verification::CouldNotCheck`] when no server answered, or when
/// the arguments could not be passed to `dig` safely.
///
/// # Errors
/// None: an unreachable server, a missing `dig`, and a refused argument are
/// all [`Verification::CouldNotCheck`] rather than a `Result::Err`, because
/// every one of them is the same thing to the caller -- a record whose state
/// is unknown -- and folding them into the verdict keeps that decision here
/// rather than at each call site.
#[must_use]
pub fn verify(
    servers: &[Nameserver],
    name: &str,
    expected: &RecordTarget,
    policy: &PollPolicy,
) -> Verification {
    if servers.is_empty() {
        return Verification::CouldNotCheck {
            reason: format!("no authoritative nameserver is known for {name}"),
        };
    }
    if !is_safe_argument(name) {
        return Verification::CouldNotCheck {
            reason: format!("{name} is not a name that can be looked up"),
        };
    }

    let attempts = policy.attempts.max(1);
    let mut verdict = Verification::CouldNotCheck {
        reason: format!("no attempt to look up {name} completed"),
    };

    for attempt in 1..=attempts {
        verdict = attempt_once(servers, name, expected, policy);
        if verdict.is_matched() {
            return verdict;
        }
        // A newly written record is frequently not visible on the first ask,
        // so a single miss is not evidence of anything. Sleeping after the
        // last attempt would only delay the verdict.
        if attempt < attempts {
            std::thread::sleep(policy.delay);
        }
    }

    verdict
}

/// One round: ask every server once and classify the results together.
fn attempt_once(
    servers: &[Nameserver],
    name: &str,
    expected: &RecordTarget,
    policy: &PollPolicy,
) -> Verification {
    let mut matched: Vec<String> = Vec::new();
    let mut wrong: Vec<String> = Vec::new();
    let mut unreachable: Vec<String> = Vec::new();

    for server in servers {
        match ask(server, name, expected.record_type(), policy.timeout) {
            ServerAnswer::Answered(targets) => {
                if targets.iter().any(|t| matches(t, expected)) {
                    matched.push(server.label());
                } else if targets.is_empty() {
                    wrong.push(format!(
                        "{} has no {} record",
                        server.label(),
                        expected.record_type()
                    ));
                } else {
                    wrong.push(format!("{} returns {}", server.label(), targets.join(", ")));
                }
            }
            ServerAnswer::Unanswered(reason) => {
                unreachable.push(format!("{}: {reason}", server.label()));
            }
        }
    }

    if wrong.is_empty() && unreachable.is_empty() {
        return Verification::Matched;
    }

    // A server that answered with the wrong thing is evidence the record is
    // wrong, and outranks an unreachable sibling: the operator has something
    // to fix either way, and the mismatch is the actionable half.
    if !wrong.is_empty() {
        let mut reason = format!("{name} should be {expected}, but {}", wrong.join("; "));
        if !unreachable.is_empty() {
            reason.push_str(&format!(" (and {} did not answer)", unreachable.join("; ")));
        }
        return Verification::Mismatch { reason };
    }

    // Everything that answered was correct, but not every nameserver did --
    // so the record is not confirmed, and saying it is wrong would be false.
    let mut reason = format!("{} did not answer", unreachable.join("; "));
    if !matched.is_empty() {
        reason.push_str(&format!(" ({} answered correctly)", matched.join(", ")));
    }
    Verification::CouldNotCheck { reason }
}

/// Runs one `dig +short` against one server.
///
/// # Arguments
/// * `server` - the nameserver to ask.
/// * `name` - the already-validated record name.
/// * `record_type` - `A` or `CNAME`.
/// * `timeout` - how long `dig` waits for a reply.
///
/// # Returns
/// [`ServerAnswer::Answered`] with the targets `dig` printed, or
/// [`ServerAnswer::Unanswered`] with the reason the query did not complete.
fn ask(server: &Nameserver, name: &str, record_type: &str, timeout: Duration) -> ServerAnswer {
    if !is_safe_argument(&server.host) {
        return ServerAnswer::Unanswered(format!("{} is not a usable server name", server.host));
    }

    // An argv vector, never a shell string, matching the idiom at
    // crates/ferrum-apply/src/apply.rs:110. Nothing here is interpolated
    // into a command line, and nothing sensitive is passed at all: `dig`'s
    // arguments are visible to every user on the host via `ps`, and a
    // hostname is the only thing this needs.
    let mut command = Command::new("dig");
    command.arg("+short");
    // One try per invocation: the retry budget lives in `verify`, where it
    // can also report what happened between attempts.
    command.arg("+tries=1");
    command.arg(format!("+timeout={}", timeout.as_secs().max(1)));
    command.arg(format!("@{}", server.host));
    if let Some(port) = server.port {
        command.args(["-p", &port.to_string()]);
    }
    command.args([name, record_type]);

    match command.output() {
        // Exit 0 means the query completed, whatever the answer was --
        // including a completed query with no matching record, which is a
        // real mismatch rather than a failed check.
        Ok(output) if output.status.success() => {
            ServerAnswer::Answered(parse_short(&String::from_utf8_lossy(&output.stdout)))
        }
        // A nonzero exit (conventionally 9, "no servers could be reached")
        // means no reply arrived. Verified against bind-9.20.23 on this
        // repository's pinned nixpkgs: both a timeout and a refused
        // connection exit 9, while an answered-but-empty query exits 0.
        Ok(output) => ServerAnswer::Unanswered(format!(
            "dig exited {}",
            output
                .status
                .code()
                .map_or_else(|| "on a signal".to_string(), |c| c.to_string())
        )),
        Err(error) => ServerAnswer::Unanswered(format!("could not run dig: {error}")),
    }
}

/// Reads `dig +short` output into the targets it reported.
///
/// # Arguments
/// * `stdout` - the raw output.
///
/// # Returns
/// One entry per answer line, trimmed. Blank lines and `dig`'s own `;;`
/// diagnostics are dropped: under `+short` those diagnostics are written to
/// **stdout**, not stderr, so `;; no servers could be reached` would
/// otherwise be read as a target.
fn parse_short(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with(';'))
        .map(ToString::to_string)
        .collect()
}

/// Whether one line of `dig` output is the target ferrum wrote.
///
/// # Arguments
/// * `observed` - one answer line.
/// * `expected` - the intended target.
///
/// # Returns
/// `true` on a match. An `A` target is compared as a parsed address, so
/// `203.0.113.7` and a differently formatted equivalent cannot disagree; a
/// `CNAME` is compared case-insensitively with the root label's trailing dot
/// removed, because `dig` prints `host.example.net.` while Cloudflare and
/// ferrum's own configuration both hold `host.example.net`.
fn matches(observed: &str, expected: &RecordTarget) -> bool {
    match expected {
        RecordTarget::A(address) => observed.parse::<Ipv4Addr>().is_ok_and(|a| a == *address),
        RecordTarget::Cname(host) => normalize_name(observed) == normalize_name(host),
    }
}

/// Lowercases a name and drops the root label's trailing dot.
fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether a value may be handed to `dig` as an argument.
///
/// # Arguments
/// * `value` - a record name or a server hostname.
///
/// # Returns
/// `true` only for a plain DNS name: ASCII letters, digits, `.`, `-` and
/// `_`, not starting with a character `dig` reads as an option or a server
/// selector. This is not defence against a hostile operator -- the values
/// come from ferrum's own configuration and from Cloudflare -- but a name
/// that arrived malformed should be refused as unlookupable rather than
/// silently reinterpreted by `dig` as a flag.
fn is_safe_argument(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_LEN
        && !value.starts_with('-')
        && !value.starts_with('+')
        && !value.starts_with('@')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeNameserver, NsBehaviour};

    const HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

    /// A policy that makes the retry loop cheap: the tests below assert on
    /// the verdict, not on how long it waited for it.
    fn fast() -> PollPolicy {
        PollPolicy {
            attempts: 2,
            delay: Duration::from_millis(10),
            timeout: Duration::from_secs(1),
        }
    }

    fn loopback(fake: &FakeNameserver) -> Vec<Nameserver> {
        vec![Nameserver {
            host: "127.0.0.1".to_string(),
            port: Some(fake.port()),
        }]
    }

    #[test]
    fn a_record_that_resolves_to_the_written_address_matches() {
        let fake = FakeNameserver::start(NsBehaviour::answer(&["203.0.113.7"]));

        let verdict = verify(
            &loopback(&fake),
            "auth.example.com",
            &RecordTarget::A(HOST),
            &fast(),
        );

        assert_eq!(verdict, Verification::Matched, "{verdict}");
        assert!(
            fake.queries() >= 1,
            "the real dig must actually have been run against the fake"
        );
    }

    #[test]
    fn a_record_pointing_somewhere_else_is_a_mismatch_not_an_unreachable_server() {
        let fake = FakeNameserver::start(NsBehaviour::answer(&["198.51.100.4"]));

        let verdict = verify(
            &loopback(&fake),
            "auth.example.com",
            &RecordTarget::A(HOST),
            &fast(),
        );

        let reason = match &verdict {
            Verification::Mismatch { reason } => reason.clone(),
            other => panic!("expected a mismatch, got {other:?}"),
        };
        assert!(reason.contains("198.51.100.4"), "{reason}");
        assert!(reason.contains("203.0.113.7"), "{reason}");
    }

    #[test]
    fn an_answered_query_with_no_record_is_a_mismatch_because_the_server_did_reply() {
        let fake = FakeNameserver::start(NsBehaviour::Empty);

        let verdict = verify(
            &loopback(&fake),
            "auth.example.com",
            &RecordTarget::A(HOST),
            &fast(),
        );

        let reason = match &verdict {
            Verification::Mismatch { reason } => reason.clone(),
            other => panic!("expected a mismatch, got {other:?}"),
        };
        assert!(
            reason.contains("has no A record"),
            "an absent record is the failure R1 exists to catch: {reason}"
        );
    }

    #[test]
    fn a_server_that_never_replies_is_could_not_check_and_never_says_the_record_is_wrong() {
        let fake = FakeNameserver::start(NsBehaviour::Silent);

        let verdict = verify(
            &loopback(&fake),
            "auth.example.com",
            &RecordTarget::A(HOST),
            &fast(),
        );

        let reason = match &verdict {
            Verification::CouldNotCheck { reason } => reason.clone(),
            other => panic!("an unreachable server must not be reported as a mismatch: {other:?}"),
        };
        assert!(reason.contains("did not answer"), "{reason}");
        assert!(
            !reason.contains("should be"),
            "the wording reserved for a real mismatch must not leak here: {reason}"
        );
    }

    #[test]
    fn nothing_listening_at_all_is_also_could_not_check() {
        // A port nothing is bound to: the connection is refused rather than
        // timing out, which is a different path through dig and must land on
        // the same verdict.
        let servers = vec![Nameserver {
            host: "127.0.0.1".to_string(),
            port: Some(1),
        }];

        let verdict = verify(
            &servers,
            "auth.example.com",
            &RecordTarget::A(HOST),
            &fast(),
        );

        assert!(
            matches!(verdict, Verification::CouldNotCheck { .. }),
            "{verdict:?}"
        );
    }

    #[test]
    fn a_cname_is_queried_as_a_cname_and_compared_without_the_root_dot() {
        let fake = FakeNameserver::start(NsBehaviour::answer(&["Host.Example.Net"]));

        let verdict = verify(
            &loopback(&fake),
            "plex.example.com",
            &RecordTarget::Cname("host.example.net".to_string()),
            &fast(),
        );

        assert_eq!(
            verdict,
            Verification::Matched,
            "dig prints a CNAME with a trailing root dot, and DNS names are \
             case-insensitive: {verdict}"
        );
        assert_eq!(
            fake.last_query_type(),
            Some("CNAME".to_string()),
            "an A lookup on a CNAME returns the address it resolves to, which \
             would compare unequal for the wrong reason"
        );
    }

    #[test]
    fn a_name_with_no_known_nameserver_cannot_be_checked() {
        let verdict = verify(&[], "auth.example.com", &RecordTarget::A(HOST), &fast());

        match verdict {
            Verification::CouldNotCheck { reason } => {
                assert!(reason.contains("auth.example.com"), "{reason}");
            }
            other => panic!("expected could-not-check, got {other:?}"),
        }
    }

    #[test]
    fn a_name_that_would_be_read_by_dig_as_a_flag_is_refused_rather_than_passed() {
        let fake = FakeNameserver::start(NsBehaviour::answer(&["203.0.113.7"]));

        for hostile in ["+nssearch", "-f/etc/shadow", "name with space", ""] {
            let verdict = verify(&loopback(&fake), hostile, &RecordTarget::A(HOST), &fast());
            assert!(
                matches!(verdict, Verification::CouldNotCheck { .. }),
                "{hostile:?} reached dig: {verdict:?}"
            );
        }
        assert_eq!(
            fake.queries(),
            0,
            "no refused argument may result in a query at all"
        );
    }

    #[test]
    fn digs_own_diagnostics_are_never_read_as_an_answer() {
        // dig writes these to stdout under +short, which is exactly how a
        // naive parser reports an unreachable server as a resolved target.
        let parsed = parse_short(
            ";; communications error to 127.0.0.1#53: timed out\n\
             ;; no servers could be reached\n",
        );
        assert!(parsed.is_empty(), "{parsed:?}");

        assert_eq!(
            parse_short("203.0.113.7\n\n  198.51.100.4  \n"),
            vec!["203.0.113.7".to_string(), "198.51.100.4".to_string()]
        );
    }

    #[test]
    fn the_retry_budget_is_bounded_and_really_retries() {
        let fake = FakeNameserver::start(NsBehaviour::Empty);
        let policy = PollPolicy {
            attempts: 3,
            delay: Duration::from_millis(5),
            timeout: Duration::from_secs(1),
        };

        let verdict = verify(
            &loopback(&fake),
            "auth.example.com",
            &RecordTarget::A(HOST),
            &policy,
        );

        assert!(
            matches!(verdict, Verification::Mismatch { .. }),
            "{verdict:?}"
        );
        assert_eq!(
            fake.queries(),
            3,
            "a record that is merely slow to propagate must get more than one ask"
        );
    }

    #[test]
    fn a_verdict_renders_as_the_sentence_an_apply_appends_to_its_reason() {
        assert_eq!(Verification::Matched.to_string(), "resolves as expected");
        assert_eq!(Verification::Matched.reason(), None);

        let mismatch = Verification::Mismatch {
            reason: "ns1 returns 198.51.100.4".to_string(),
        };
        assert!(mismatch
            .to_string()
            .contains("does not resolve as expected"));
        assert_eq!(mismatch.reason(), Some("ns1 returns 198.51.100.4"));

        let unknown = Verification::CouldNotCheck {
            reason: "ns1 did not answer".to_string(),
        };
        assert!(unknown.to_string().contains("could not be checked"));
        assert!(!unknown.is_matched());
    }

    #[test]
    fn a_nameserver_on_the_default_port_is_named_without_one() {
        assert_eq!(
            Nameserver::new("ns1.example.net").label(),
            "ns1.example.net"
        );
        assert_eq!(
            Nameserver {
                host: "127.0.0.1".to_string(),
                port: Some(5353)
            }
            .label(),
            "127.0.0.1#5353"
        );
    }

    #[test]
    fn the_default_policy_is_bounded_to_a_handful_of_seconds() {
        let policy = PollPolicy::default();
        let worst_case = policy.delay * (policy.attempts - 1) + policy.timeout * policy.attempts;
        assert!(
            worst_case <= Duration::from_secs(30),
            "an apply holds the operator's terminal while this runs: {worst_case:?}"
        );
    }
}
