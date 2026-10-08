//! Finding the target's own public IPv4 address (spec R1 A8).
//!
//! A8 requires the A record to be written from an address "detected at
//! install time and shown for confirmation, never guessed silently". This
//! module is the detection half; [`crate::answers::decide_dns`] is the
//! confirmation half.
//!
//! **Detection has to run on the target, and that is the whole difficulty.**
//! `ferrum-install` executes on the *operator's own machine* and reaches the
//! target over SSH -- `crate::preconditions::find_ssh_auth` and every remote
//! command in this binary are built on that assumption. So an address this
//! process discovered by asking "what is my public address" would be the
//! operator's laptop's: on a VPN, behind a corporate NAT, or simply on a
//! different connection, that is a confidently wrong answer that looks
//! exactly like a right one. Everything here therefore goes through a runner
//! the caller supplies, and production supplies `collect::run` -- the same
//! SSH path every other target-side check already uses.
//!
//! **A detected address is still not a verified one.** Carrier-grade NAT, a
//! transparent proxy, or an egress gateway can each yield an address that
//! inbound traffic never arrives at. That residual is why the result is
//! *classified* rather than merely returned: the prompt can then say which
//! of those cases it is looking at instead of echoing four octets and
//! hoping. It is also why nothing here writes a record -- the operator sees
//! the candidate first, always.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The command run **on the target** to discover its public address.
///
/// It asks `api.ipify.org`, which answers with one address in plain text and
/// no JSON to parse, and which publishes no `AAAA` record -- belt and braces
/// alongside `-4` for the IPv4-only scope decision (finding UF-18).
///
/// Three further properties are deliberate:
///
/// * `-4` on both branches forces the request itself over IPv4, so a
///   dual-stack host reports the address an `A` record can actually carry
///   rather than its IPv6 one.
/// * `curl` first, `wget` as a fallback, because this runs against a rescue
///   or installer environment whose tool set ferrum does not control.
/// * Neither present exits **0 with no output**, which [`classify`] turns
///   into a stated failure (decision D-11b: an empty input fails loudly, it
///   never degrades into a silent default). Exiting non-zero here would be
///   indistinguishable from a network fault and would lose that distinction.
///
/// No operator-supplied value is interpolated, so there is nothing to quote,
/// and no credential appears in it -- it is safe in the target's `ps`.
pub const DETECT_COMMAND: &str = concat!(
    "if command -v curl >/dev/null 2>&1; then ",
    "curl -4 -fsS --max-time 8 https://api.ipify.org",
    "; elif command -v wget >/dev/null 2>&1; then ",
    "wget -q -4 -T 8 -O - https://api.ipify.org",
    "; fi"
);

/// Why an address that parsed cannot be reached from the internet.
///
/// Finer-grained than a boolean because each case has a different fix, and
/// the operator can only act on the one they are actually in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routability {
    /// Reachable from outside this network, as far as its shape can say.
    Public,
    /// `100.64.0.0/10` -- the ISP handed out no real address. The one case
    /// where a correct-looking answer genuinely cannot work.
    CarrierGradeNat,
    /// RFC 1918: a LAN address, almost always the host's own interface
    /// rather than its egress.
    Private,
    /// `127.0.0.0/8` -- the echo was answered by the host itself.
    Loopback,
    /// `169.254.0.0/16` -- no DHCP lease.
    LinkLocal,
    /// Unspecified, broadcast or multicast: not an endpoint at all.
    Reserved,
}

/// Classifies an IPv4 address by whether the internet can reach it.
///
/// The single implementation of this judgement in the crate;
/// `answers::is_reachable_from_outside` is a thin `== Public` over it, so a
/// detected address and a typed one can never be judged by two different
/// rules.
///
/// # Arguments
/// * `addr` - the address to classify.
///
/// # Returns
/// The one category it falls into.
pub fn routability(addr: &Ipv4Addr) -> Routability {
    let [first, second, ..] = addr.octets();
    if addr.is_loopback() {
        Routability::Loopback
    } else if addr.is_link_local() {
        Routability::LinkLocal
    } else if addr.is_private() {
        Routability::Private
    } else if first == 100 && (64..=127).contains(&second) {
        Routability::CarrierGradeNat
    } else if addr.is_unspecified() || addr.is_broadcast() || addr.is_multicast() {
        Routability::Reserved
    } else {
        Routability::Public
    }
}

/// What detection found, classified so the prompt can explain itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detected {
    /// A public IPv4 address. The only variant that may pre-fill a prompt.
    Public(Ipv4Addr),
    /// An IPv4 address the internet cannot reach.
    Unroutable {
        /// What the target reported.
        address: Ipv4Addr,
        /// Which non-public category it falls into.
        why: Routability,
    },
    /// An IPv6 answer. Never an `A` record, by decision (finding UF-18).
    Ipv6(Ipv6Addr),
    /// Bytes that are not an address -- a captive portal's HTML, an error
    /// page, a proxy's interstitial.
    Unparseable {
        /// The first 60 characters of what came back.
        sample: String,
    },
    /// The command succeeded and said nothing: neither `curl` nor `wget` is
    /// on the target. D-11b's case, and the reason it is a variant of its
    /// own rather than an `Unparseable("")`.
    Empty,
    /// The command itself failed -- no route, DNS down, SSH trouble.
    Failed {
        /// The runner's own words, context chain included.
        reason: String,
    },
}

impl Detected {
    /// The address that may be offered as a prompt default.
    ///
    /// `Some` for [`Detected::Public`] and nothing else. A CGNAT, private or
    /// IPv6 answer is reported and then *asked about*, never pre-filled:
    /// pre-filling is how a wrong address gets accepted by an operator
    /// pressing enter, which is precisely A8's failure mode.
    ///
    /// # Returns
    /// The candidate, or `None` when the operator must type one.
    pub fn candidate(&self) -> Option<Ipv4Addr> {
        match self {
            Detected::Public(addr) => Some(*addr),
            _ => None,
        }
    }

    /// One or more lines describing the result to the operator.
    ///
    /// Every variant says what was found *and* what it means for the record,
    /// because "100.64.1.5" on its own reads as a success to anyone who does
    /// not already know what `100.64/10` is.
    ///
    /// # Returns
    /// The text to print. Never empty -- silence is the thing A8 forbids.
    pub fn summary(&self) -> String {
        match self {
            Detected::Public(addr) => format!(
                "  Detected on the target: {addr}\n  \
                 The target itself made this request, not this machine, so a VPN \
                 or a\n  different network here cannot have skewed it. It is shown \
                 rather than\n  simply used because a transparent proxy or an egress \
                 gateway can still\n  report an address inbound traffic never arrives \
                 at."
            ),
            Detected::Unroutable {
                address,
                why: Routability::CarrierGradeNat,
            } => format!(
                "  Detected on the target: {address}\n  \
                 That is a carrier-grade NAT address: your ISP has not given this \
                 line a\n  real address. It is not an address anything outside this \
                 network can reach,\n  and no A record can fix that. ferrum will not \
                 use it for you: either answer\n  'cname' and point at a name \
                 something else keeps current, or give the\n  address you have \
                 arranged to reach this server on."
            ),
            Detected::Unroutable { address, why } => format!(
                "  Detected on the target: {address}\n  \
                 That is {}. It is not an address anything outside this network can \
                 reach\n  -- the target reported its own interface rather than its \
                 egress. ferrum will\n  not use it for you. Give this server's public \
                 IPv4 address.",
                match why {
                    Routability::Private => "a private LAN address",
                    Routability::Loopback => "a loopback address",
                    Routability::LinkLocal => "a link-local address (no DHCP lease)",
                    _ => "a reserved address",
                }
            ),
            Detected::Ipv6(addr) => format!(
                "  Detected on the target: {addr}\n  \
                 That is an IPv6 address, and ferrum publishes A and CNAME records \
                 and no\n  AAAA record at all -- a deliberate scope decision (finding \
                 UF-18), not a\n  gap in this check. It will not be written into an A \
                 record. Give this\n  server's public IPv4 address."
            ),
            Detected::Unparseable { sample } => format!(
                "  Detection ran on the target and got back {sample:?}, which is not \
                 an\n  address. A captive portal or a filtering proxy answers like \
                 this. Nothing\n  has been assumed from it."
            ),
            Detected::Empty => String::from(
                "  Detection ran on the target and produced nothing: neither curl nor \
                 wget\n  is present there. That is a missing tool, not a missing \
                 address, and\n  ferrum will not turn it into a blank record.",
            ),
            Detected::Failed { reason } => format!(
                "  Detection could not run on the target: {reason}\n  \
                 Nothing has been assumed from that. The install continues; only the \
                 way\n  this one answer is obtained changes."
            ),
        }
    }
}

/// Classifies the raw bytes the detection command produced.
///
/// Separated from [`detect`] so the whole judgement is testable without a
/// runner, and so the same classification applies however the bytes arrived.
///
/// # Arguments
/// * `raw` - the command's stdout, untrimmed.
///
/// # Returns
/// The classification. An empty or whitespace-only `raw` is
/// [`Detected::Empty`], never a default address.
pub fn classify(raw: &str) -> Detected {
    let value = raw.trim();
    if value.is_empty() {
        return Detected::Empty;
    }
    if let Ok(v4) = value.parse::<Ipv4Addr>() {
        return match routability(&v4) {
            Routability::Public => Detected::Public(v4),
            why => Detected::Unroutable { address: v4, why },
        };
    }
    if let Ok(v6) = value.parse::<Ipv6Addr>() {
        return Detected::Ipv6(v6);
    }
    // Truncated: a captive portal returns a whole HTML page, and pasting it
    // into the operator's terminal buries the question it is attached to.
    let mut sample: String = value.chars().take(60).collect();
    if value.chars().count() > 60 {
        sample.push('\u{2026}');
    }
    Detected::Unparseable { sample }
}

/// Runs detection through a caller-supplied runner and classifies the result.
///
/// The runner is the seam that keeps this testable: production passes a
/// closure over `collect::run` against the real target, and the suite passes
/// a fake. The Nix sandbox that runs the workspace tests has no network at
/// all, so a test that reached a real echo service would fail CI by
/// construction -- and would be measuring ipify's uptime rather than this.
///
/// # Arguments
/// * `run` - executes a command **on the target** and returns its stdout.
///
/// # Returns
/// The classification. Never an error: a failure to detect is an outcome the
/// prompt handles by asking, not a reason to abandon an install.
pub fn detect(run: impl FnOnce(&str) -> anyhow::Result<String>) -> Detected {
    match run(DETECT_COMMAND) {
        Ok(out) => classify(&out),
        // `{e:#}` keeps anyhow's context chain, which for an SSH failure is
        // ssh's own stderr -- better words than a wrapper would write.
        Err(e) => Detected::Failed {
            reason: format!("{e:#}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runner that returns canned bytes. No socket is opened anywhere in
    /// this module's tests.
    fn runner_yielding(out: &str) -> impl FnOnce(&str) -> anyhow::Result<String> + '_ {
        move |_command| Ok(out.to_string())
    }

    /// A8's central claim: the address comes from the target.
    ///
    /// Mutation check: drop `-4` from `DETECT_COMMAND` and the IPv4-only
    /// assertion fails; drop the `wget` branch and the fallback assertion
    /// fails.
    #[test]
    fn detection_runs_on_the_target_over_ipv4_only() {
        let mut seen = String::new();
        let got = detect(|command| {
            seen = command.to_string();
            Ok("203.0.113.10".into())
        });
        assert_eq!(got, Detected::Public("203.0.113.10".parse().unwrap()));
        assert!(
            seen.contains("curl -4") && seen.contains("wget -q -4"),
            "the request must be forced over IPv4 on both paths, or a \
             dual-stack host reports an address no A record can carry: {seen}"
        );
        assert!(
            seen.contains("command -v wget"),
            "a rescue environment without curl must still get an answer: {seen}"
        );
        assert!(
            !seen.contains('\''),
            "nothing operator-supplied is interpolated, so nothing needs \
             quoting -- if that changed, quote it: {seen}"
        );
    }

    /// UF-18. An IPv6 answer must never become an A record's value.
    ///
    /// Mutation check: make `classify` fall through to `Unparseable` for
    /// IPv6, or have `candidate()` return something for it, and this fails.
    #[test]
    fn an_ipv6_answer_is_named_as_such_and_never_offered() {
        for v6 in ["2001:db8::1", "fe80::1", "::1"] {
            let got = classify(v6);
            assert!(matches!(got, Detected::Ipv6(_)), "{v6}: {got:?}");
            assert_eq!(got.candidate(), None, "{v6} must not pre-fill a prompt");
            assert!(got.summary().contains("UF-18"), "{v6}: {}", got.summary());
            assert!(got.summary().contains("AAAA"), "{v6}: {}", got.summary());
        }
    }

    /// A8 / R1-S5's vocabulary. CGNAT is reported, named, and not used.
    ///
    /// Mutation check: let `candidate()` return the address for any parsed
    /// IPv4 and this fails.
    #[test]
    fn a_carrier_grade_nat_address_is_reported_never_used() {
        let got = classify("100.64.1.5");
        assert_eq!(
            got,
            Detected::Unroutable {
                address: "100.64.1.5".parse().unwrap(),
                why: Routability::CarrierGradeNat,
            }
        );
        assert_eq!(
            got.candidate(),
            None,
            "a CGNAT address must never pre-fill the prompt: pressing enter \
             would publish every app at an address nothing outside can reach"
        );
        let said = got.summary();
        assert!(said.contains("100.64.1.5"), "{said}");
        assert!(said.contains("carrier-grade NAT"), "{said}");
        assert!(
            said.contains("outside this network can reach"),
            "R1-S5's own wording, not a second vocabulary: {said}"
        );
    }

    /// Every private shape the target can report about itself.
    #[test]
    fn an_interface_address_is_classified_by_why_not_merely_rejected() {
        for (raw, why) in [
            ("192.168.1.10", Routability::Private),
            ("10.0.0.1", Routability::Private),
            ("172.16.0.1", Routability::Private),
            ("127.0.0.1", Routability::Loopback),
            ("169.254.1.1", Routability::LinkLocal),
            ("0.0.0.0", Routability::Reserved),
            ("255.255.255.255", Routability::Reserved),
            ("224.0.0.1", Routability::Reserved),
        ] {
            assert_eq!(routability(&raw.parse().unwrap()), why, "{raw}");
            let got = classify(raw);
            assert_eq!(got.candidate(), None, "{raw} must not pre-fill");
            assert!(!got.summary().is_empty(), "{raw} must say something");
        }
        for public in ["203.0.113.10", "8.8.8.8", "100.128.0.1", "99.255.255.255"] {
            assert_eq!(
                routability(&public.parse().unwrap()),
                Routability::Public,
                "{public}"
            );
        }
    }

    /// D-11(b). An empty answer is a stated failure, never a blank address.
    ///
    /// The owner lost a live attempt to exactly this shape: an empty value
    /// produced empty output that read as "unsupported".
    ///
    /// Mutation check: return a default address for empty input and both
    /// assertions fail.
    #[test]
    fn nothing_at_all_is_a_stated_failure_not_a_default() {
        for blank in ["", "   ", "\n", "\r\n  \t"] {
            let got = classify(blank);
            assert_eq!(got, Detected::Empty, "{blank:?}");
            assert_eq!(
                got.candidate(),
                None,
                "{blank:?} must not produce an address of any kind"
            );
            assert!(
                got.summary().contains("neither curl nor wget"),
                "the operator must learn it was a missing tool: {}",
                got.summary()
            );
        }
    }

    /// A captive portal's HTML is shown, truncated, and assumed nothing from.
    #[test]
    fn bytes_that_are_not_an_address_are_shown_truncated() {
        let got = classify("  <html>not your address</html>  ");
        assert_eq!(
            got,
            Detected::Unparseable {
                sample: "<html>not your address</html>".into()
            }
        );
        assert_eq!(got.candidate(), None);

        let long = classify(&"x".repeat(500));
        let Detected::Unparseable { sample } = long else {
            panic!("expected Unparseable, got {long:?}");
        };
        assert_eq!(
            sample.chars().count(),
            61,
            "a whole error page must not bury the question it is attached to"
        );
        assert!(sample.ends_with('\u{2026}'));
    }

    /// A runner failure is an outcome, not an aborted install.
    ///
    /// Mutation check: make `detect` propagate the error instead and the
    /// install loses its fallback-to-asking path entirely.
    #[test]
    fn a_failed_run_carries_its_reason_and_offers_nothing() {
        let got = detect(|_| anyhow::bail!("ssh root@10.0.0.9 failed: no route to host"));
        let Detected::Failed { reason } = &got else {
            panic!("expected Failed, got {got:?}");
        };
        assert!(reason.contains("no route to host"), "{reason}");
        assert_eq!(got.candidate(), None);
        assert!(got.summary().contains("Nothing has been assumed"));
    }

    /// Trimming is this module's job, not the caller's: ssh returns the echo
    /// service's trailing newline.
    #[test]
    fn surrounding_whitespace_from_ssh_is_not_part_of_the_address() {
        assert_eq!(
            detect(runner_yielding("203.0.113.10\n")),
            Detected::Public("203.0.113.10".parse().unwrap())
        );
    }

    /// The command and the endpoint this module documents must not drift.
    #[test]
    fn the_command_asks_the_endpoint_this_module_documents() {
        assert_eq!(
            DETECT_COMMAND.matches("https://api.ipify.org").count(),
            2,
            "both the curl and the wget branch must ask the same endpoint: \
             {DETECT_COMMAND}"
        );
    }
}
