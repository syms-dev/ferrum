//! Finding out what this host's public IPv4 address actually is -- and
//! refusing to guess when the answer is not unanimous.
//!
//! **Why this exists.** `ferrum.proxy.dns.ddnsUpdater` shipped as a timer
//! that re-published `ferrum.proxy.dns.staticAddress` on a schedule. Three
//! comments in `modules/proxy/dns.nix` described it as re-checking the
//! host's real public address; none of them was true, and nothing anywhere
//! in `crates/` queried a public address at all. The owner's address moved
//! from `184.148.39.165` to `142.180.179.64`, seven records kept pointing at
//! the old one, every published app became unreachable from outside, and the
//! host reported itself healthy throughout. This module is the lookup that
//! was missing.
//!
//! **Address discovery is a trust decision, not a lookup.** This is the
//! whole design, and it is why the code below is longer than
//! `GET https://.../ip`. A stale record leaves the operator's apps
//! unreachable. A *wrong* record republishes every one of their hostnames --
//! `plex.`, `sonarr.`, `auth.` -- at somebody else's server, with valid
//! certificates ferrum obtained itself. That is strictly worse, so every
//! rule here resolves ties towards publishing nothing:
//!
//! 1. **At least two distinct operators must answer** ([`MIN_OPERATORS`]).
//!    One endpoint is one party's opinion, and a party that is wrong (or
//!    compromised, or merely behind a transparent proxy) is then ferrum's
//!    only witness.
//! 2. **Every source that answered must agree.** Not a majority -- a
//!    majority means acting while a witness contradicts you, which is the
//!    exact circumstance in which the stake is highest. Disagreement is a
//!    [`DiscoveryError::Disagreement`] and nothing is published.
//! 3. **The agreed address must be publishable.** A private, loopback,
//!    link-local, shared-CGNAT, documentation or otherwise reserved address
//!    is refused outright ([`unpublishable_reason`]): a record pointing at
//!    `10.0.0.5` is not a degraded record, it is a record that can only ever
//!    be wrong.
//! 4. **Failure is failure.** Every error path returns `Err`. There is no
//!    "could not tell, so assume nothing changed" branch, because an
//!    unreachable check that reads like a clean result is the shape of the
//!    defect this whole requirement exists to close.
//!
//! **Why these three sources.** They have to be genuinely independent --
//! two endpoints run by one company is one source wearing two hats -- and
//! they have to be reachable with no account, no key and no new dependency.
//!
//! * `cloudflare` (`https://one.one.one.one/cdn-cgi/trace`). Defensible as
//!   *one* of them precisely because ferrum already trusts Cloudflare with
//!   the zone: a Cloudflare that lies here could simply have written the
//!   wrong record instead. It cannot be the only one, for the same reason.
//! * `amazon` (`https://checkip.amazonaws.com`). A different company, a
//!   different network, a different failure domain, and a plain-text body
//!   that has been stable for well over a decade.
//! * `ipify` (`https://api.ipify.org`). A third party again, and the
//!   tie-breaker that lets one of the other two be down without stopping
//!   the updater.
//!
//! **The honest caveat about that third one,** recorded rather than
//! glossed: ipify is a small service and may itself sit behind a CDN, so its
//! answer could in principle be Cloudflare's answer wearing a second hat.
//! That is exactly why the quorum counts **distinct operators that answered**
//! and demands **unanimity among all of them**, rather than a majority of
//! endpoints. Two endpoints that silently share an upstream can agree with
//! each other; they cannot make a third, genuinely separate network agree
//! with a wrong answer.
//!
//! **What ferrum still cannot know, and says so instead of pretending.**
//! These services report the address a TCP connection *left* from. That the
//! address is correct does not mean inbound traffic to it reaches this host:
//! a carrier-grade NAT or a router with no port forward produces a perfectly
//! correct record in front of an unreachable server. Detecting that would
//! mean enumerating local interfaces, which `modules/proxy/dns.nix`
//! deliberately forbids the updater unit from doing (no `AF_NETLINK`), and
//! would still not answer the port-forwarding question. So the caller
//! discloses the limit when the published address changes rather than
//! inventing a reachability verdict.
//!
//! **IPv6 is out of scope**, and that is `staticAddress`'s own standing
//! contract: ferrum publishes no `AAAA` record, so there is nothing for a
//! discovered IPv6 address to be written into.
//!
//! **No test here reaches the real internet.** [`Source`] carries a plain
//! URL, so the suite points the same code at
//! [`crate::testing::FakeCloudflare`] -- which serves arbitrary bodies via
//! [`crate::testing::CannedResponse::raw`] -- exactly as every Cloudflare
//! test already does. The Nix sandbox that runs `workspace-tests` has no
//! network at all, so a real call could not succeed even by accident.

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

/// How many *distinct operators* must answer before any address is
/// believed.
///
/// Two, not one: a single witness that is wrong is indistinguishable from a
/// single witness that is right. Not three, because the updater then stops
/// working whenever any one service has an outage, and a dynamic-DNS
/// updater that is down is the stale record it exists to prevent.
pub const MIN_OPERATORS: usize = 2;

/// How long to wait for a TCP connection to an address-echo service.
///
/// Shorter than [`crate::client`]'s Cloudflare timeouts on purpose: this
/// runs before any write, three times, and an unresponsive echo service must
/// not hold an apply open. The whole discovery budget is bounded by
/// `sources.len() * (CONNECT_TIMEOUT + READ_TIMEOUT)`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for an echo service to answer once connected.
const READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How a source's response body carries the address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// The entire body is the address, modulo surrounding whitespace.
    PlainText,
    /// Cloudflare's `/cdn-cgi/trace` document: `key=value` lines, one of
    /// which is `ip=<address>`.
    CloudflareTrace,
}

/// One place that will report the address a connection arrived from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Who runs it. The quorum counts distinct values of *this*, not of
    /// `url`, so two endpoints at one company can never satisfy
    /// [`MIN_OPERATORS`] between them.
    pub operator: String,
    /// The URL to fetch. A plain `String` rather than a constant because it
    /// is the test seam: the suite points it at a local fake.
    pub url: String,
    /// How to read the body.
    pub format: Format,
}

impl Source {
    /// Describes one source.
    ///
    /// # Arguments
    /// * `operator` - the party that runs it, used for the quorum and in
    ///   every message an operator reads.
    /// * `url` - the endpoint to fetch.
    /// * `format` - how the address is carried in the body.
    #[must_use]
    pub fn new(operator: &str, url: &str, format: Format) -> Self {
        Self {
            operator: operator.to_string(),
            url: url.to_string(),
            format,
        }
    }
}

/// The three sources ferrum ships with, in the order they are queried.
///
/// Deliberately not a NixOS option. Making the source list configurable
/// would invite a host to be pointed at one endpoint, or at three run by the
/// same party, which quietly deletes the independence the whole design rests
/// on. If a source has to change, it changes here, in review, with the
/// reasoning in this file's header.
///
/// # Returns
/// Three [`Source`]s run by three different parties.
#[must_use]
pub fn default_sources() -> Vec<Source> {
    vec![
        Source::new(
            "cloudflare",
            "https://one.one.one.one/cdn-cgi/trace",
            Format::CloudflareTrace,
        ),
        Source::new(
            "amazon",
            "https://checkip.amazonaws.com",
            Format::PlainText,
        ),
        Source::new("ipify", "https://api.ipify.org", Format::PlainText),
    ]
}

/// An address at least [`MIN_OPERATORS`] independent parties agreed on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovered {
    /// The address every source that answered reported.
    pub address: Ipv4Addr,
    /// The operators that answered, in query order. Named in the journal so
    /// "two of three agreed" is a fact an operator can check rather than a
    /// claim they have to take on faith.
    pub agreed_by: Vec<String>,
    /// `operator: why` for every source that did not answer. Empty on an
    /// ordinary run. Carried rather than dropped because a quorum that has
    /// been limping on two of three sources for a month is one outage away
    /// from stopping, and nothing else would ever say so.
    pub unreachable: Vec<String>,
}

impl fmt::Display for Discovered {
    /// The one-line journal form: the address, who agreed, and who did not
    /// answer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (agreed by {})", self.address, self.agreed_by.join(", "))?;
        if !self.unreachable.is_empty() {
            write!(f, "; no answer from {}", self.unreachable.join(", "))?;
        }
        Ok(())
    }
}

/// Why no address could be published.
///
/// The split between [`DiscoveryError::NotEnoughOperators`] and the other
/// two is load-bearing and reaches the operator as a different exit code:
/// the first means *ferrum could not find out*, the other two mean *ferrum
/// found out and does not believe it*. Those call for different actions --
/// check the host's connectivity, versus look at what is answering for this
/// connection -- and collapsing them into one failure sends the operator to
/// the wrong place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// Fewer than [`MIN_OPERATORS`] distinct operators answered at all.
    NotEnoughOperators {
        /// The operators that did answer, with the address each gave.
        answered: Vec<(String, Ipv4Addr)>,
        /// `operator: why` for every source that failed.
        failures: Vec<String>,
    },
    /// Two or more sources answered, and they did not all say the same
    /// thing.
    Disagreement {
        /// Every answer received, operator by operator.
        answers: Vec<(String, Ipv4Addr)>,
    },
    /// The sources agreed, on an address no DNS record may point at.
    NotPublishable {
        /// What they agreed on.
        address: Ipv4Addr,
        /// Which reserved range it falls in, in words.
        reason: String,
        /// Who agreed on it.
        agreed_by: Vec<String>,
    },
}

impl DiscoveryError {
    /// Whether ferrum *refused* an answer rather than failing to get one.
    ///
    /// # Returns
    /// `true` for [`DiscoveryError::Disagreement`] and
    /// [`DiscoveryError::NotPublishable`] -- the two cases where discovery
    /// completed and its result was rejected on purpose.
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            DiscoveryError::Disagreement { .. } | DiscoveryError::NotPublishable { .. }
        )
    }
}

impl fmt::Display for DiscoveryError {
    /// Renders the failure with every address and operator named, so the
    /// journal line is enough to act on without re-running anything.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::NotEnoughOperators { answered, failures } => write!(
                f,
                "this host's public address could not be established: {} of the {} independent \
                 sources answered ({} are required). Answers: {}. Failures: {}",
                answered.len(),
                answered.len() + failures.len(),
                MIN_OPERATORS,
                render_answers(answered),
                if failures.is_empty() {
                    "none".to_string()
                } else {
                    failures.join("; ")
                }
            ),
            DiscoveryError::Disagreement { answers } => write!(
                f,
                "this host's public address is disputed, so nothing was published: {}. \
                 Publishing one of these would point every hostname ferrum manages at a \
                 server that may not be this one, which is worse than leaving the records \
                 stale -- so ferrum left them alone",
                render_answers(answers)
            ),
            DiscoveryError::NotPublishable {
                address,
                reason,
                agreed_by,
            } => write!(
                f,
                "{} agreed this host's public address is {address}, which is {reason} and can \
                 never be reached from the internet. Nothing was published: a record pointing \
                 there is not a stale record, it is one that cannot ever be right",
                agreed_by.join(", ")
            ),
        }
    }
}

/// Renders `operator=address` pairs for a message.
fn render_answers(answers: &[(String, Ipv4Addr)]) -> String {
    answers
        .iter()
        .map(|(who, addr)| format!("{who} said {addr}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Asks every source and returns the address they agree on.
///
/// # Arguments
/// * `sources` - the endpoints to ask. Production passes
///   [`default_sources`]; tests pass fakes.
///
/// # Returns
/// The agreed address with the operators that produced it.
///
/// # Errors
/// [`DiscoveryError`] when fewer than [`MIN_OPERATORS`] distinct operators
/// answered, when the answers disagree, or when the agreed address is not
/// one a public record may point at. There is deliberately no success value
/// that means "could not tell": see this module's header.
pub fn discover(sources: &[Source]) -> Result<Discovered, DiscoveryError> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(READ_TIMEOUT)
        .build();

    let mut answers: Vec<(String, Ipv4Addr)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    for source in sources {
        match fetch(&agent, source) {
            Ok(address) => answers.push((source.operator.clone(), address)),
            Err(why) => failures.push(format!("{}: {why}", source.operator)),
        }
    }

    // Distinct OPERATORS, never distinct responses: the whole point of the
    // quorum is that two endpoints run by the same party cannot vouch for
    // each other.
    let operators: BTreeSet<&str> = answers.iter().map(|(who, _)| who.as_str()).collect();
    if operators.len() < MIN_OPERATORS {
        return Err(DiscoveryError::NotEnoughOperators { answered: answers, failures });
    }

    let distinct: BTreeSet<Ipv4Addr> = answers.iter().map(|(_, addr)| *addr).collect();
    if distinct.len() > 1 {
        return Err(DiscoveryError::Disagreement { answers });
    }

    let address = *distinct.iter().next().expect("the quorum guarantees one");
    let agreed_by: Vec<String> = answers.into_iter().map(|(who, _)| who).collect();
    if let Some(reason) = unpublishable_reason(address) {
        return Err(DiscoveryError::NotPublishable {
            address,
            reason: reason.to_string(),
            agreed_by,
        });
    }

    Ok(Discovered {
        address,
        agreed_by,
        unreachable: failures,
    })
}

/// Fetches one source and extracts the address from its body.
///
/// # Arguments
/// * `agent` - the shared `ureq` agent carrying the timeouts.
/// * `source` - which endpoint, and how to read it.
///
/// # Errors
/// A sentence naming what went wrong, for the `operator: why` list. The
/// body is never quoted beyond its first line: these endpoints are
/// third-party and a failure mode that pastes an arbitrary response into
/// ferrum's journal is a log-injection surface for nothing in return.
fn fetch(agent: &ureq::Agent, source: &Source) -> Result<Ipv4Addr, String> {
    let response = agent
        .get(&source.url)
        .call()
        .map_err(|e| format!("{} did not answer ({e})", source.url))?;
    let body = response
        .into_string()
        .map_err(|e| format!("{} answered but the body could not be read ({e})", source.url))?;
    parse(&body, source.format)
        .ok_or_else(|| format!("{} answered with no usable IPv4 address", source.url))
}

/// Pulls an IPv4 address out of a response body.
///
/// # Arguments
/// * `body` - the response, verbatim.
/// * `format` - how the address is carried.
///
/// # Returns
/// The address, or `None` when the body does not carry one in that shape.
#[must_use]
pub fn parse(body: &str, format: Format) -> Option<Ipv4Addr> {
    match format {
        Format::PlainText => body.trim().parse().ok(),
        // Scanned line by line rather than by substring: `warp=off` and
        // `sni=plaintext` both contain `ip=`, and a substring search finds
        // the wrong one on a document whose field order is not ferrum's to
        // rely on.
        Format::CloudflareTrace => body
            .lines()
            .find_map(|line| line.trim().strip_prefix("ip="))
            .and_then(|value| value.trim().parse().ok()),
    }
}

/// Why this address may never appear in a public `A` record, if it may not.
///
/// Hand-written rather than `Ipv4Addr::is_global`, which is still unstable,
/// and deliberately not a new dependency: the ranges are a closed, published
/// list and the whole function is a `match`.
///
/// # Arguments
/// * `addr` - the address every source agreed on.
///
/// # Returns
/// `None` when the address is a globally routable unicast address, otherwise
/// the range it falls in, phrased for an operator.
#[must_use]
pub fn unpublishable_reason(addr: Ipv4Addr) -> Option<&'static str> {
    let [a, b, c, _] = addr.octets();
    if addr.is_unspecified() {
        return Some("the unspecified address 0.0.0.0");
    }
    if addr.is_broadcast() {
        return Some("the broadcast address");
    }
    if addr.is_loopback() {
        return Some("a loopback address (127.0.0.0/8)");
    }
    if addr.is_private() {
        return Some("a private address (RFC 1918) -- something between this host and the \
                     internet is answering instead of the internet");
    }
    if addr.is_link_local() {
        return Some("a link-local address (169.254.0.0/16), which means no address was \
                     configured at all");
    }
    // RFC 6598 shared address space: the carrier side of a carrier-grade
    // NAT. Reported by an echo service, it means the connection never left
    // the ISP's own network, so the address is useless as a record target --
    // separate from the CGNAT case the caller *does* publish, which is a
    // real public address in front of a NAT ferrum cannot see through.
    if a == 100 && (64..128).contains(&b) {
        return Some("carrier-grade NAT shared address space (100.64.0.0/10), so this \
                     connection never left your ISP's own network");
    }
    if a == 192 && b == 0 && c == 0 {
        return Some("IETF protocol assignments (192.0.0.0/24)");
    }
    if addr.is_documentation() {
        return Some("a documentation-only address (RFC 5737), which is never routed");
    }
    if a == 198 && (b == 18 || b == 19) {
        return Some("benchmarking address space (198.18.0.0/15), which is never routed");
    }
    if addr.is_multicast() {
        return Some("a multicast address (224.0.0.0/4)");
    }
    if a >= 240 {
        return Some("reserved address space (240.0.0.0/4), which is never routed");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{CannedResponse, FakeCloudflare, Route};

    /// The address the owner's host actually moved to. Used throughout so a
    /// fixture that accidentally publishes a documentation address cannot
    /// pass: 203.0.113.x is itself refused by `unpublishable_reason`.
    const REAL: Ipv4Addr = Ipv4Addr::new(142, 180, 179, 64);

    /// One fake HTTP server standing in for one operator. Each test starts
    /// its own per operator, so two "sources" are never the same socket --
    /// the independence the quorum asserts is real in the fixture too.
    fn echo(operator: &str, body: &str) -> (FakeCloudflare, Source) {
        let fake = FakeCloudflare::start();
        fake.script(Route::get("/ip"), CannedResponse::raw(200, body));
        let source = Source::new(operator, &format!("{}/ip", fake.base_url()), Format::PlainText);
        (fake, source)
    }

    /// A source whose server is already stopped, so the connection fails.
    fn dead(operator: &str) -> Source {
        let fake = FakeCloudflare::start();
        let url = format!("{}/ip", fake.base_url());
        drop(fake);
        Source::new(operator, &url, Format::PlainText)
    }

    #[test]
    fn two_agreeing_operators_are_enough() {
        let (_a, one) = echo("alpha", "142.180.179.64\n");
        let (_b, two) = echo("beta", "142.180.179.64");
        let found = discover(&[one, two]).expect("two agreeing operators is a quorum");
        assert_eq!(found.address, REAL);
        assert_eq!(found.agreed_by, vec!["alpha", "beta"]);
        assert!(found.unreachable.is_empty(), "{found:?}");
    }

    #[test]
    fn one_operator_alone_is_never_enough() {
        let (_a, one) = echo("alpha", "142.180.179.64");
        let err = discover(&[one]).expect_err("a single witness must not be believed");
        assert!(
            matches!(err, DiscoveryError::NotEnoughOperators { .. }),
            "{err:?}"
        );
        assert!(!err.is_refusal(), "a missing quorum is a failure to find out");
    }

    /// Two endpoints, one party. The quorum counts operators precisely so
    /// this cannot pass.
    #[test]
    fn two_endpoints_at_one_operator_are_one_source_wearing_two_hats() {
        let (_a, one) = echo("cloudflare", "142.180.179.64");
        let (_b, two) = echo("cloudflare", "142.180.179.64");
        let err = discover(&[one, two]).expect_err("one party cannot vouch for itself");
        assert!(
            matches!(err, DiscoveryError::NotEnoughOperators { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_third_source_being_down_does_not_stop_a_real_quorum() {
        let (_a, one) = echo("alpha", "142.180.179.64");
        let (_b, two) = echo("beta", "142.180.179.64");
        let found = discover(&[one, two, dead("gamma")]).expect("two of three is a quorum");
        assert_eq!(found.address, REAL);
        assert_eq!(found.unreachable.len(), 1, "{found:?}");
        assert!(found.unreachable[0].starts_with("gamma: "), "{found:?}");
    }

    #[test]
    fn disagreement_publishes_nothing_and_names_every_answer() {
        let (_a, one) = echo("alpha", "142.180.179.64");
        let (_b, two) = echo("beta", "184.148.39.165");
        let err = discover(&[one, two]).expect_err("a disputed address must not be published");
        assert!(err.is_refusal(), "{err:?}");
        let rendered = err.to_string();
        assert!(rendered.contains("142.180.179.64"), "{rendered}");
        assert!(rendered.contains("184.148.39.165"), "{rendered}");
    }

    /// A majority would publish here. Unanimity does not, and that is the
    /// deliberate difference.
    #[test]
    fn a_dissenting_third_source_still_stops_the_publish() {
        let (_a, one) = echo("alpha", "142.180.179.64");
        let (_b, two) = echo("beta", "142.180.179.64");
        let (_c, three) = echo("gamma", "198.51.100.4");
        let err = discover(&[one, two, three]).expect_err("two out of three is not unanimous");
        assert!(matches!(err, DiscoveryError::Disagreement { .. }), "{err:?}");
    }

    #[test]
    fn a_private_address_is_refused_rather_than_published() {
        let (_a, one) = echo("alpha", "192.168.1.20");
        let (_b, two) = echo("beta", "192.168.1.20");
        let err = discover(&[one, two]).expect_err("an RFC 1918 address is never a record target");
        assert!(err.is_refusal(), "{err:?}");
        assert!(err.to_string().contains("192.168.1.20"), "{err}");
    }

    #[test]
    fn every_reserved_range_is_refused_and_a_real_address_is_not() {
        for (addr, what) in [
            ("0.0.0.0", "unspecified"),
            ("127.0.0.1", "loopback"),
            ("10.1.2.3", "rfc1918 a"),
            ("172.16.0.1", "rfc1918 b"),
            ("192.168.0.1", "rfc1918 c"),
            ("169.254.1.1", "link-local"),
            ("100.64.0.1", "cgnat shared"),
            ("100.127.255.254", "cgnat shared top"),
            ("192.0.0.1", "protocol assignments"),
            ("192.0.2.1", "documentation"),
            ("198.51.100.1", "documentation"),
            ("203.0.113.1", "documentation"),
            ("198.18.0.1", "benchmarking"),
            ("224.0.0.1", "multicast"),
            ("240.0.0.1", "reserved"),
            ("255.255.255.255", "broadcast"),
        ] {
            let parsed: Ipv4Addr = addr.parse().unwrap();
            assert!(
                unpublishable_reason(parsed).is_some(),
                "{addr} ({what}) must never be published"
            );
        }
        for addr in ["142.180.179.64", "184.148.39.165", "1.1.1.1", "100.63.255.255", "100.128.0.1"] {
            let parsed: Ipv4Addr = addr.parse().unwrap();
            assert!(
                unpublishable_reason(parsed).is_none(),
                "{addr} is a real routable address and must be publishable"
            );
        }
    }

    #[test]
    fn a_cloudflare_trace_body_yields_the_ip_line_and_not_a_lookalike() {
        let body = "fl=123abc\nh=one.one.one.one\nip=142.180.179.64\nts=1\nsni=plaintext\nwarp=off\n";
        assert_eq!(parse(body, Format::CloudflareTrace), Some(REAL));
        // `sni=` and `warp=` both contain no address; a substring search for
        // "ip=" would also have matched nothing here, so the real guard is
        // that a document with a lookalike key first still resolves the real
        // one.
        let shuffled = "gateway=off\nsomeip=9.9.9.9\nip=142.180.179.64\n";
        assert_eq!(parse(shuffled, Format::CloudflareTrace), Some(REAL));
    }

    #[test]
    fn a_body_that_is_not_an_address_is_a_failure_not_a_default() {
        assert_eq!(parse("<html>go away</html>", Format::PlainText), None);
        assert_eq!(parse("", Format::PlainText), None);
        assert_eq!(parse("2a07:b944::2:2", Format::PlainText), None);
        assert_eq!(parse("fl=1\nh=x\n", Format::CloudflareTrace), None);
    }

    /// The shipped list is the design decision this module's header argues
    /// for. A future edit that collapses it to one party, or to one
    /// endpoint, has to fail here rather than quietly in production.
    #[test]
    fn the_shipped_sources_are_three_distinct_operators_over_https() {
        let sources = default_sources();
        assert!(sources.len() > MIN_OPERATORS, "{sources:?}");
        let operators: BTreeSet<&str> = sources.iter().map(|s| s.operator.as_str()).collect();
        assert_eq!(operators.len(), sources.len(), "{sources:?}");
        for source in &sources {
            assert!(source.url.starts_with("https://"), "{source:?}");
        }
    }
}
