//! What the installer checks on the finished machine, and what it tells the
//! operator (spec R6 A3-A8, R9 A4).
//!
//! The design doc's postmortem of the first real install found ten defects,
//! six invisible to the VM suite, and its conclusion was that *a test that
//! never acts like a human never finds what a human hits*. Three of those
//! six were found by typing a bare command at a shell. So the checks below
//! deliberately use the operator's own interface -- `ferrum-apply` resolved
//! from `PATH`, a `curl` against the real hostname -- rather than a store
//! path or an internal query.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

use crate::answers::{DnsDecision, RecordTarget};
use crate::inventory::Device;

/// One thing asserted on the finished host.
pub struct Check {
    pub what: &'static str,
    pub command: String,
    /// Substring the output must contain for the check to pass.
    pub expect: String,
}

/// The ownership `modules/core/bootstrap.nix` documents and `ferrumd`
/// depends on.
pub fn ownership_checks() -> Vec<Check> {
    vec![
        Check {
            what: "settings.json is writable by ferrumd",
            command: "stat -c '%U:%G %a' /etc/ferrum/settings.json".into(),
            expect: "root:ferrum 664".into(),
        },
        Check {
            what: "the secrets directory belongs to ferrumd",
            command: "stat -c '%U:%G %a' /etc/ferrum/secrets".into(),
            expect: "ferrum:ferrum 750".into(),
        },
        Check {
            what: "custom/ is never writable by ferrumd",
            command: "stat -c '%U:%G %a' /etc/ferrum/custom".into(),
            expect: "root:root 755".into(),
        },
        // The last line of defence for the defect that made this check
        // necessary. The installer writes a stand-in
        // hardware-configuration.nix so Tier 1 can evaluate before
        // anything is destroyed, and `{ ... }: { }` is a valid empty
        // module -- so a host that ends up with the stand-in boots, runs,
        // and passes every other check here while having NO initrd kernel
        // modules and no microcode. The transfer step refuses to send it;
        // this proves it did not arrive by some other route.
        Check {
            what: "the host has a real hardware configuration, not the stand-in",
            // `expect` is matched with `contains`, so a COUNT is the wrong
            // shape here: "0" is a substring of "10" and "100", and the
            // check would pass on a file full of sentinels. Emit a word
            // instead, and build the pattern from the one constant.
            // Three outcomes, not two. `grep -q ... && echo STANDIN || echo
            // REAL` prints REAL when the file is ABSENT, which is the one
            // state that must never pass -- the flake imports this file
            // unconditionally, so a missing one is a host that cannot
            // evaluate at all. The count form this replaced failed closed
            // on absence by accident; this does it on purpose.
            command: hardware_config_command("/etc/ferrum/hardware-configuration.nix"),
            expect: "REAL".into(),
        },
    ]
}

/// Builds the shell command behind the hardware-configuration check.
///
/// Split out so its THREE outcomes can be executed in a test. They were
/// not pinned: reverting this to the two-outcome form -- which prints
/// REAL for a file that does not exist -- passed the entire suite. The fix
/// was live and nothing held it, which is the third time that has happened
/// in this feature.
///
/// # Arguments
/// * `path` - the file to inspect on the target.
///
/// # Returns
/// A command printing exactly one of `REAL`, `STANDIN` or `MISSING`. None
/// is a substring of another, because `Check::expect` is matched with
/// `contains`.
pub fn hardware_config_command(path: &str) -> String {
    format!(
        "test -f {path} && {{ grep -q '{s}' {path} && echo STANDIN || echo REAL; }} || echo MISSING",
        s = crate::render::HARDWARE_CONFIG_SENTINEL
    )
}

/// The service and operator-interface checks.
///
/// `command -v ferrum-apply` is the important one and is not a formality:
/// on the first real install `ferrum-apply` existed only as a store path
/// inside a unit's `ExecStart`, so it was "command not found" at a shell.
/// Nothing that invokes it by store path or through systemd can catch that.
pub fn service_checks() -> Vec<Check> {
    vec![
        Check {
            what: "ferrumd is running",
            command: "systemctl is-active ferrumd".into(),
            expect: "active".into(),
        },
        Check {
            what: "ferrum-apply resolves as a bare command",
            command: "command -v ferrum-apply".into(),
            expect: "ferrum-apply".into(),
        },
    ]
}

/// Asserts Authelia is really in front of the apps.
///
/// `modules/proxy/nginx.nix` emits
/// `error_page 401 =302 https://auth.<domain>/?rd=$target_url`, so an
/// unauthenticated request returns a redirect. One line and one round trip,
/// and it is the earliest signal that would catch an app published with no
/// login at all.
///
/// The control plane is asserted alongside them, and separately from them.
/// `crate::sso::apps_left_open` cannot see it -- ferrumd is not a catalog
/// app -- which is the defect this phase has now found in four modules in
/// a row, including in `unauthenticated_checks` directly below. Its vhost
/// exists because the proxy does, not because any app was selected, so the
/// predicate is `crate::sso::daemon_published` and the assertion is the
/// same one a gated app gets.
///
/// # Arguments
/// * `domain` - `ferrum.proxy.baseDomain`.
/// * `apps` - the published catalog apps.
/// * `sso_enabled` - whether Authelia is in front of anything at all.
///
/// # Returns
/// One check per gated surface, or none when SSO was declined -- in which
/// case [`unauthenticated_checks`] owns the inverted assertion.
pub fn auth_checks(domain: &str, apps: &[String], sso_enabled: bool) -> Vec<Check> {
    if !sso_enabled {
        return Vec::new();
    }
    let url = |host: String| {
        // Quoted at the sink even though `domain` is allowlist-validated on
        // the way in: the validator is three modules away from here.
        format!(
            "curl -sS -o /dev/null -w '%{{http_code}}' {}",
            crate::collect::sh_quote(&host)
        )
    };
    let mut checks = vec![Check {
        what: "the authentication host answers",
        command: url(format!("https://auth.{domain}/")),
        expect: "200".into(),
    }];
    if crate::sso::daemon_published(Some(domain)) {
        checks.push(Check {
            what: "the ferrum dashboard redirects to authentication",
            command: url(format!("https://{}.{domain}/", crate::dns::DAEMON_SUBDOMAIN)),
            expect: "302".into(),
        });
    }
    for app in crate::sso::apps_left_open(apps) {
        checks.push(Check {
            what: "the app redirects to authentication",
            command: url(format!("https://{app}.{domain}/")),
            expect: "302".into(),
        });
    }
    checks
}

/// R9 A4's other half: when the operator **declined** SSO, the assertion
/// inverts. A published app with no authentication in front of it must
/// answer directly, and a redirect to an auth host would mean something
/// other than what they asked for is happening.
///
/// Returning no checks at all for the decline path -- as an earlier version
/// did -- meant the one configuration the operator had to type a phrase to
/// reach was the only one verified by nothing.
///
/// **The same sentence was true one surface further in, and the docstring
/// above was describing it without noticing.** This mapped over
/// `crate::sso::apps_left_open` alone, and ferrumd is not a catalog app, so
/// the control plane -- the one thing on this host that writes secrets,
/// rewrites `settings.json` and applies generations -- was the single
/// published surface the declined-SSO path left open AND never verified.
/// `crate::sso::daemon_published` is the predicate `sso.rs`,
/// `preflight.rs` and `dns.rs` already consult for it; consulting it here
/// too is what makes all four agree.
///
/// # Arguments
/// * `domain` - `ferrum.proxy.baseDomain`.
/// * `apps` - the published catalog apps.
///
/// # Returns
/// One check per surface left open, each asserting a direct answer rather
/// than a redirect.
pub fn unauthenticated_checks(domain: &str, apps: &[String]) -> Vec<Check> {
    let answers_directly = |host: String| Check {
        what: "the app answers directly, as the operator accepted",
        command: format!(
            "curl -sS -o /dev/null -w '%{{http_code}}' {}",
            crate::collect::sh_quote(&format!("https://{host}/"))
        ),
        expect: "200".into(),
    };

    let mut checks: Vec<Check> = Vec::new();
    if crate::sso::daemon_published(Some(domain)) {
        checks.push(Check {
            what: "the ferrum dashboard answers directly, as the operator accepted",
            ..answers_directly(format!("{}.{domain}", crate::dns::DAEMON_SUBDOMAIN))
        });
    }
    checks.extend(
        crate::sso::apps_left_open(apps)
            .into_iter()
            .map(|app| answers_directly(format!("{app}.{domain}"))),
    );
    checks
}

/// Asserts every data disk the operator kept is still mounted with the
/// filesystem the inventory recorded.
///
/// A data disk that failed to mount should be a loud failure now, not a
/// missing directory discovered weeks later when a library looks empty.
pub fn data_disk_checks(kept: &[&Device]) -> Vec<Check> {
    kept.iter()
        .filter_map(|d| {
            let by_id = d.by_id.as_deref()?;
            let fstype = d.children.iter().find_map(|c| c.fstype.as_deref())?;
            Some(Check {
                what: "a kept data disk is mounted",
                // Quoted like every other remote interpolation. On a resume
                // this value comes from a plain deserialize of
                // install-inventory.json, which sits in the operator's
                // writable bind mount -- so "it came from lsblk" is not
                // true on every path that reaches here.
                command: format!(
                    "findmnt -no FSTYPE --source {}",
                    crate::collect::sh_quote(by_id)
                ),
                expect: fstype.to_string(),
            })
        })
        .collect()
}

/// R1 A8's reachability proof: is the address ferrum published the address
/// the internet actually delivers to this host?
///
/// **This is the one check in this binary that must not run over SSH, and
/// that is the entire point of it.** `auth_checks` and
/// `unauthenticated_checks` above are `curl`s executed *on the target*, and
/// a host asking itself whether it is reachable proves nothing: the packets
/// never leave. `address::detect` closed the previous gap -- an address
/// discovered from the operator's laptop would be the laptop's -- but a
/// *detected* address is still not a *proven* one. A transparent proxy, an
/// egress gateway, or a firewall that permits outbound and drops inbound
/// each yields an address that is real, correct as an egress address, and
/// not where inbound traffic arrives. Only a request issued from somewhere
/// other than the target can tell those apart, so everything below runs in
/// the `ferrum-install` process, on the operator's own machine, over the
/// public internet.
///
/// Residual, recorded rather than papered over: an operator whose own
/// machine shares the target's egress (both behind the same CGNAT) is not
/// a genuinely independent vantage point. Nothing here can fix that, and a
/// `Reachable` from that position is weaker evidence than it looks.
///
/// # The assertion
///
/// A plain HTTP/1.1 request to port 80, which `modules/proxy/nginx.nix`
/// opens (`networking.firewall.allowedTCPPorts = [ 80 443 ]`) and where
/// every vhost's `forceSSL = true` produces a redirect to
/// `https://<host>/`. That redirect is what makes the check discriminating:
/// it names the hostname asked for, so only an nginx configured with *this*
/// host's vhosts can produce it. Anything else at that address answers
/// differently, and the catch-all vhost closes the connection with no
/// response at all (`locations."/".return = "444"`), which is a distinct
/// and reported outcome rather than a pass.
///
/// Port 80 rather than 443 for one reason: an HTTPS request needs a TLS
/// client, and this binary links none -- it shells out instead (see
/// `crate::collect`), and `curl` is deliberately not on the wrapper PATH
/// that `nix/pkgs/ferrum-install/default.nix` pins. The redirect on 80 is
/// served by the same nginx, from the same address, through the same
/// firewall, so it answers the question A8 actually asks.
///
/// # Arguments
/// * `domain` - `ferrum.proxy.baseDomain`.
/// * `apps` - the published apps, used when there is no auth host.
/// * `sso_enabled` - whether `auth.<domain>` exists to be asked. With no
///   auth host and no app, the dashboard's own hostname is asked for: it is
///   published whenever the proxy is, so "nothing is published" stopped
///   being true at R13.
/// * `dns` - the operator's record decision. `None`, or a `CNAME`, yields
///   no checks: A8 is about the static address ferrum writes, and under a
///   `CNAME` ferrum states no address to prove.
///
/// # Returns
/// At most one check. One probe answers the question -- does traffic sent
/// to this address arrive at this host -- and repeating it per app would
/// add rows to the report without adding evidence.
pub fn external_reachability_checks(
    domain: &str,
    apps: &[String],
    sso_enabled: bool,
    dns: Option<&DnsDecision>,
) -> Vec<ExternalCheck> {
    let Some(DnsDecision {
        target: RecordTarget::A(address),
        ..
    }) = dns
    else {
        return Vec::new();
    };

    // The auth host when there is one: it is the hostname every *arr
    // redirects to, so an operator who can reach nothing else still has to
    // reach this. Otherwise the first published app.
    //
    // And failing both, the dashboard -- which was the whole of the gap
    // here. `!sso_enabled && apps.is_empty()` returned no check at all, on
    // the grounds that no hostname was published; after R13 that is simply
    // untrue. `ferrum.<domain>` is published because the proxy is, so a
    // host that selected no app and declined SSO still has exactly one name
    // whose reachability is worth proving, and it is the only one the
    // operator will actually visit.
    let host = if sso_enabled {
        format!("auth.{domain}")
    } else if let Some(app) = apps.first() {
        format!("{app}.{domain}")
    } else if crate::sso::daemon_published(Some(domain)) {
        format!("{}.{domain}", crate::dns::DAEMON_SUBDOMAIN)
    } else {
        return Vec::new();
    };

    vec![ExternalCheck {
        what: "the published address reaches this host from the internet",
        host,
        address: *address,
        port: EXTERNAL_PROBE_PORT,
    }]
}

/// The port the reachability probe knocks on.
///
/// `modules/proxy/nginx.nix` opens 80 and 443; 80 is the one reachable
/// without a TLS implementation. See [`external_reachability_checks`].
pub const EXTERNAL_PROBE_PORT: u16 = 80;

/// How long a single probe waits, for connect and for read alike.
///
/// The same eight seconds `address::DETECT_COMMAND` gives its own request,
/// so a slow link is treated the same way on both sides of the proof.
const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// Addresses used only to answer "can this machine reach the internet at
/// all?".
///
/// Raw addresses, never hostnames: a machine whose DNS is broken can still
/// open a TCP connection, and resolving a control name would turn that into
/// a *false* "the server is unreachable" -- exactly the conflation this
/// whole three-state result exists to prevent. Two, because one operator's
/// network blocking one of them must not become a verdict about the target.
const CONTROL_ADDRESSES: [(Ipv4Addr, u16); 2] = [
    (Ipv4Addr::new(1, 1, 1, 1), 443),
    (Ipv4Addr::new(8, 8, 8, 8), 443),
];

/// One outbound attempt this process makes, by address and port.
///
/// Deliberately **not** a shell command string like [`Check::command`]:
/// a `Check` is something `collect::run` executes on the target over SSH,
/// and giving this a different type is what makes handing it to that runner
/// a compile error rather than a code-review comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCheck {
    /// What passing it would prove, in the operator's words.
    pub what: &'static str,
    /// The hostname asked for -- the `Host:` header, and the name the
    /// redirect must echo back.
    pub host: String,
    /// The address the request is sent to. Not resolved from `host`: the
    /// claim under test is about this address.
    pub address: Ipv4Addr,
    /// The port knocked on.
    pub port: u16,
}

impl ExternalCheck {
    /// The socket the probe connects to.
    ///
    /// # Returns
    /// The address and port, paired.
    #[must_use]
    pub fn socket(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.address, self.port)
    }

    /// The HTTP/1.1 request sent once the connection is open.
    ///
    /// `Connection: close` so the server ends the response itself and the
    /// read finishes on EOF rather than on a timeout. `host` reaches here
    /// already validated as a DNS name, so it carries no CR/LF to split the
    /// header with.
    ///
    /// # Returns
    /// The request bytes, as text.
    #[must_use]
    pub fn request(&self) -> String {
        format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: ferrum-install\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n",
            self.host
        )
    }
}

/// What came back from one probe, before any judgement is made about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Bytes arrived from the address. May be empty -- a connection
    /// accepted and closed without a response is an answer of a kind, and
    /// [`classify`] names it rather than letting it fall through.
    Answered(String),
    /// Nothing arrived: the connection was refused, timed out, or failed.
    NoAnswer(String),
}

/// Why an address that ferrum published is not where traffic arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotReachableCause {
    /// Nothing accepted the connection.
    NothingAnswered(String),
    /// Something answered, but not this host's nginx.
    NotThisHost(String),
}

/// The three states A8's proof can end in -- and they are three, not two.
///
/// "I could not run the check" is not "the server is unreachable", and
/// collapsing them is the defect this project has now hit twice: D-11b,
/// where an empty result read as an unsupported feature, and `dig`'s exit
/// code in R1-S3. They call for opposite things from the operator: one
/// means go and fix a port forward, the other means the answer is simply
/// not known yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reachability {
    /// Traffic sent to the published address arrived at this host.
    Reachable {
        /// The hostname proven reachable.
        host: String,
        /// The address it was sent to.
        address: Ipv4Addr,
        /// The status line that proved it.
        status: String,
    },
    /// It did not arrive. Reported, never fatal: an operator may be
    /// installing before the port forward exists.
    NotReachable {
        /// The hostname asked for.
        host: String,
        /// The address it was sent to.
        address: Ipv4Addr,
        /// Which of the two shapes of failure it was.
        cause: NotReachableCause,
    },
    /// The check itself could not run, so it says nothing about the server.
    CouldNotCheck {
        /// The hostname that would have been asked for.
        host: String,
        /// The address that would have been probed.
        address: Ipv4Addr,
        /// Why the check could not be made.
        reason: String,
    },
}

impl Reachability {
    /// What the operator is told, including what to do about it.
    ///
    /// # Returns
    /// The lines to print. Never empty: a silent check is indistinguishable
    /// from one that was never run.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Reachability::Reachable {
                host,
                address,
                status,
            } => format!(
                "  reachable: {host} answered on {address}:{port} from this machine, over\n  \
                 the public internet -- not from the server itself, which could not have\n  \
                 told you this. The address ferrum published is where traffic arrives.\n  \
                 ({status})",
                port = EXTERNAL_PROBE_PORT
            ),
            Reachability::NotReachable {
                host,
                address,
                cause: NotReachableCause::NothingAnswered(reason),
            } => format!(
                "  NOT reachable: nothing answered at {address}:{port} from here ({reason}).\n  \
                 The server is installed and healthy -- this is about the path to it.\n  \
                 Usually one of: port {port} and 443 are not forwarded to this server;\n  \
                 a firewall upstream drops inbound connections; or your line is behind\n  \
                 carrier-grade NAT, where no forward is possible at all.\n  \
                 {host} will not answer from outside until that is fixed. Nothing about\n  \
                 the install needs redoing when it is.",
                port = EXTERNAL_PROBE_PORT
            ),
            Reachability::NotReachable {
                host,
                address,
                cause: NotReachableCause::NotThisHost(sample),
            } => format!(
                "  NOT reachable: something answered at {address}:{port}, but it was not\n  \
                 this server -- it did not redirect {host} the way this host's own\n  \
                 configuration does. A transparent proxy, an ISP interception page, or\n  \
                 a different machine holding that address will all look like this. The\n  \
                 address ferrum published is not this server's.\n  \
                 It replied: {sample:?}",
                port = EXTERNAL_PROBE_PORT
            ),
            Reachability::CouldNotCheck {
                host,
                address,
                reason,
            } => format!(
                "  could not check: {reason}\n  \
                 This says NOTHING about {host} or about {address} -- it is this\n  \
                 machine that could not make the request. The server may be perfectly\n  \
                 reachable. Re-run the check from a connected machine, or simply visit\n  \
                 https://{host}/ from anywhere outside your network."
            ),
        }
    }
}

/// Judges one answer, consulting the control only when it has to.
///
/// The control is a closure and is called **lazily**, for two reasons: an
/// answer that arrived needs no control at all, and a run where everything
/// works must not pay for an extra outbound connection to prove it.
///
/// # Arguments
/// * `check` - what was probed.
/// * `answer` - what came back.
/// * `control` - proves this machine can reach the internet at all. Only
///   consulted when nothing answered, because that is the only outcome that
///   "my own connection is down" could otherwise be mistaken for.
///
/// # Returns
/// One of three states. An empty answer never becomes a pass (D-11b): a
/// connection accepted and closed with no response is nginx's catch-all
/// refusing an unknown hostname, which is a real finding.
pub fn classify(
    check: &ExternalCheck,
    answer: Answer,
    control: impl FnOnce() -> Result<(), String>,
) -> Reachability {
    match answer {
        Answer::Answered(response) if redirects_to(&check.host, &response) => {
            Reachability::Reachable {
                host: check.host.clone(),
                address: check.address,
                status: first_line(&response),
            }
        }
        Answer::Answered(response) => Reachability::NotReachable {
            host: check.host.clone(),
            address: check.address,
            cause: NotReachableCause::NotThisHost(if response.trim().is_empty() {
                // nginx's `return 444` on the catch-all vhost. Empty is the
                // most misleading possible result, so it is the one spelled
                // out rather than shown as "".
                "(the connection was accepted and closed with no response at all)".to_string()
            } else {
                first_line(&response)
            }),
        },
        Answer::NoAnswer(reason) => match control() {
            Ok(()) => Reachability::NotReachable {
                host: check.host.clone(),
                address: check.address,
                cause: NotReachableCause::NothingAnswered(reason),
            },
            Err(why) => Reachability::CouldNotCheck {
                host: check.host.clone(),
                address: check.address,
                reason: format!(
                    "this machine could not reach the internet either ({why}), so the \
                     probe\n  proves nothing. The original failure was: {reason}"
                ),
            },
        },
    }
}

/// Whether a response is this host's own redirect for `host`.
///
/// Both halves matter. A 3xx alone could come from anything; the
/// `https://<host>` target is what only an nginx holding this host's vhost
/// can produce, because `forceSSL` builds the redirect from the very name
/// that was asked for.
fn redirects_to(host: &str, response: &str) -> bool {
    let status = first_line(response);
    let is_redirect = status.starts_with("HTTP/1.")
        && status
            .split_whitespace()
            .nth(1)
            .is_some_and(|code| matches!(code, "301" | "302" | "307" | "308"));
    is_redirect && response.contains(&format!("https://{host}"))
}

/// The response's status line, trimmed and bounded.
///
/// Bounded because an interception page's first line can be a whole
/// minified document, and pasting that into the report buries the sentence
/// explaining it.
fn first_line(response: &str) -> String {
    let line = response.lines().next().unwrap_or("").trim();
    let mut out: String = line.chars().take(80).collect();
    if line.chars().count() > 80 {
        out.push('\u{2026}');
    }
    out
}

/// Runs every reachability check through caller-supplied transports.
///
/// Both transports are seams for the same reason `address::detect` takes
/// one: the Nix sandbox that runs `workspace-tests` has no network, so a
/// test that opened a socket would fail CI by construction and would be
/// measuring somebody else's uptime rather than this logic.
///
/// # Arguments
/// * `checks` - from [`external_reachability_checks`].
/// * `probe` - makes one outbound attempt. Production passes [`tcp_probe`].
/// * `control` - proves this machine has outbound connectivity. Production
///   passes [`outbound_control`].
///
/// # Returns
/// One verdict per check, in order. Never an error: a failure to prove
/// reachability is a thing to report, not a reason to fail an install that
/// has already succeeded.
pub fn assess(
    checks: &[ExternalCheck],
    mut probe: impl FnMut(&ExternalCheck) -> Answer,
    mut control: impl FnMut() -> Result<(), String>,
) -> Vec<Reachability> {
    checks
        .iter()
        .map(|check| {
            let answer = probe(check);
            classify(check, answer, &mut control)
        })
        .collect()
}

/// The production probe: one TCP connection from **this** process.
///
/// No SSH, no `collect::run`, no target credentials -- see
/// [`external_reachability_checks`] for why that is the requirement rather
/// than an implementation detail.
///
/// # Arguments
/// * `check` - the address, port and hostname to ask for.
///
/// # Returns
/// Whatever came back, or the reason nothing did. Never an error: every
/// failure here is an outcome [`classify`] knows how to describe.
pub fn tcp_probe(check: &ExternalCheck) -> Answer {
    let socket = SocketAddr::V4(check.socket());
    let mut stream = match TcpStream::connect_timeout(&socket, PROBE_TIMEOUT) {
        Ok(s) => s,
        Err(e) => return Answer::NoAnswer(e.to_string()),
    };
    // Without both timeouts, a black-holing firewall makes this hang rather
    // than report -- which for the operator is indistinguishable from the
    // installer having crashed.
    if let Err(e) = stream
        .set_read_timeout(Some(PROBE_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(PROBE_TIMEOUT)))
        .and_then(|()| stream.write_all(check.request().as_bytes()))
    {
        return Answer::NoAnswer(e.to_string());
    }

    // Headers only. The redirect body is a few bytes of nginx boilerplate
    // and an interception page can be megabytes, so the read is capped.
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() >= 4096 || buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            // A read that times out after the connection was accepted is
            // still an answer of nothing -- reported as such rather than as
            // the empty string, which would read as nginx's 444.
            Err(e) => return Answer::NoAnswer(e.to_string()),
        }
    }
    Answer::Answered(String::from_utf8_lossy(&buf).into_owned())
}

/// The production control: can this machine reach the internet at all?
///
/// # Returns
/// `Ok` as soon as any control address accepts a connection; otherwise the
/// reason none did, which turns a would-be "not reachable" into "could not
/// check".
pub fn outbound_control() -> Result<(), String> {
    let mut reasons = Vec::new();
    for (address, port) in CONTROL_ADDRESSES {
        let socket = SocketAddr::V4(SocketAddrV4::new(address, port));
        match TcpStream::connect_timeout(&socket, PROBE_TIMEOUT) {
            Ok(_) => return Ok(()),
            Err(e) => reasons.push(format!("{address}:{port} {e}")),
        }
    }
    Err(reasons.join("; "))
}

/// Where the two one-time credentials live.
///
/// There are two, not one. `ferrumd-setup-password` is generated by
/// `ensure_first_user` in `crates/ferrumd/src/auth.rs`;
/// `authelia-setup-password` is written by `ferrum-apply` during the very
/// stage-2 apply, whenever SSO is on. Printing only the first would report
/// success while leaving the operator locked out of every app.
pub fn credential_paths(sso_enabled: bool) -> Vec<(&'static str, &'static str)> {
    let mut v = vec![("ferrum UI", "/var/lib/ferrum/daemon/ferrumd-setup-password")];
    if sso_enabled {
        v.push((
            "single sign-on",
            "/var/lib/authelia-main/authelia-setup-password",
        ));
    }
    v
}

#[cfg(test)]
mod tests {
    /// SEC-L-N5. Executes the real command against real files, because the
    /// bug being guarded is a SHELL semantics bug -- `grep -q ... && A ||
    /// B` prints B when the file is absent -- and no amount of reading the
    /// string catches that.
    #[test]
    fn the_hardware_config_check_distinguishes_real_standin_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hardware-configuration.nix");
        let run = || {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(super::hardware_config_command(path.to_str().unwrap()))
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        // Absent -- the state that must never pass. The two-outcome form
        // this replaced printed REAL here.
        assert_eq!(run(), "MISSING");

        let mut files = crate::render::Files::new();
        crate::render::insert_hardware_config_placeholder(&mut files);
        std::fs::write(&path, &files["hardware-configuration.nix"]).unwrap();
        assert_eq!(run(), "STANDIN");

        std::fs::write(
            &path,
            "{ ... }:\n{ boot.initrd.availableKernelModules = [ \"nvme\" ]; }\n",
        )
        .unwrap();
        assert_eq!(run(), "REAL");

        // `expect` is matched with `contains`, so the three words must not
        // shadow each other.
        for (a, b) in [
            ("REAL", "STANDIN"),
            ("REAL", "MISSING"),
            ("STANDIN", "MISSING"),
        ] {
            assert!(!b.contains(a) && !a.contains(b), "{a} / {b}");
        }
    }

    use super::*;
    use crate::inventory::Filesystem;

    fn disk(by_id: &str, fstype: Option<&str>) -> Device {
        Device {
            name: "sdb".into(),
            size: "3.6T".into(),
            model: None,
            serial: Some("S".into()),
            by_id: Some(by_id.into()),
            children: fstype
                .map(|f| {
                    vec![Filesystem {
                        name: "sdb1".into(),
                        fstype: Some(f.into()),
                        mountpoint: None,
                        by_id: None,
                    }]
                })
                .unwrap_or_default(),
        }
    }

    #[test]
    fn the_ownership_checks_match_what_bootstrap_nix_documents() {
        let c = ownership_checks();
        assert_eq!(c[0].expect, "root:ferrum 664");
        assert_eq!(c[1].expect, "ferrum:ferrum 750");
        assert_eq!(c[2].expect, "root:root 755");
    }

    /// Three of the first install's ten defects were found by typing a bare
    /// command. Nothing that goes through systemd or a store path can.
    #[test]
    fn ferrum_apply_is_checked_as_a_bare_command_not_a_store_path() {
        let c = service_checks();
        let check = c.iter().find(|c| c.what.contains("bare command")).unwrap();
        assert_eq!(check.command, "command -v ferrum-apply");
        assert!(!check.command.contains("/nix/store"));
        assert!(!check.command.contains("systemctl"));
    }

    #[test]
    fn auth_checks_expect_a_redirect_for_every_unprotected_app() {
        let apps = vec!["sonarr".to_string(), "plex".to_string()];
        let c = auth_checks("thesyms.ca", &apps, true);
        assert!(c.iter().any(|c| c.command.contains("auth.thesyms.ca")));
        let sonarr = c
            .iter()
            .find(|c| c.command.contains("sonarr.thesyms.ca"))
            .unwrap();
        assert_eq!(sonarr.expect, "302");
        // plex carries its own login, so ferrum does not put Authelia in
        // front of it and a redirect would be the wrong expectation.
        assert!(!c.iter().any(|c| c.command.contains("plex.thesyms.ca")));
    }

    /// R9 A4: declining does not mean verifying nothing -- it means the
    /// assertion inverts.
    #[test]
    fn declining_sso_inverts_the_assertion_rather_than_skipping_it() {
        let apps = vec!["sonarr".to_string(), "plex".to_string()];
        assert!(auth_checks("d.com", &apps, false).is_empty());

        let inverted = unauthenticated_checks("d.com", &apps);
        let sonarr = inverted
            .iter()
            .find(|c| c.command.contains("sonarr"))
            .unwrap();
        assert_eq!(
            sonarr.expect, "200",
            "a redirect would mean SSO is on after all"
        );
        assert!(
            !inverted.iter().any(|c| c.command.contains("plex")),
            "plex has its own login and is not part of this claim"
        );
    }

    /// R13/A2, at the site that verifies the finished machine.
    ///
    /// The apps are checked through `sso::apps_left_open`, which is a
    /// function of the catalog -- and ferrumd is not a catalog app. So
    /// until this existed, the installer confirmed every *arr was behind a
    /// login and never once asked whether the dashboard was, on a host
    /// where the dashboard is the surface that writes secrets and applies
    /// generations.
    #[test]
    fn the_dashboard_is_checked_for_its_login_like_every_other_surface() {
        let c = auth_checks("thesyms.ca", &["sonarr".into()], true);
        let dashboard = c
            .iter()
            .find(|c| c.command.contains("ferrum.thesyms.ca"))
            .expect("the control plane is verified too");
        assert_eq!(
            dashboard.expect, "302",
            "a 200 here would mean the dashboard is published with no login"
        );
        // And it is not merely the auth host under another name.
        assert!(c.iter().any(|c| c.command.contains("auth.thesyms.ca")));
        assert!(c.iter().any(|c| c.command.contains("sonarr.thesyms.ca")));
    }

    /// The same surface on the path the operator had to type a phrase to
    /// reach -- and the one this module's own docstring already described
    /// happening somewhere else.
    ///
    /// Declining SSO leaves the control plane open. Verifying every app it
    /// left open while never verifying the control plane it left open is
    /// exactly the inversion `unauthenticated_checks` exists to prevent,
    /// applied to everything except the most dangerous surface.
    #[test]
    fn declining_sso_still_verifies_the_control_plane_it_left_open() {
        let c = unauthenticated_checks("thesyms.ca", &["sonarr".into(), "plex".into()]);
        let dashboard = c
            .iter()
            .find(|c| c.command.contains("ferrum.thesyms.ca"))
            .expect("the control plane is verified too");
        assert_eq!(
            dashboard.expect, "200",
            "a redirect would mean SSO is on after all"
        );
        assert!(
            dashboard.what.contains("as the operator accepted"),
            "the report has to say this was consented to, not that it is fine: {}",
            dashboard.what
        );

        // A host with no app at all is the sharpest case: before this, it
        // produced no checks whatsoever while publishing the dashboard.
        let alone = unauthenticated_checks("thesyms.ca", &[]);
        assert_eq!(
            alone.len(),
            1,
            "{:?}",
            alone.iter().map(|c| &c.command).collect::<Vec<_>>()
        );
        assert!(alone[0].command.contains("ferrum.thesyms.ca"));
    }

    #[test]
    fn remote_urls_are_shell_quoted_at_the_sink() {
        let c = auth_checks("d.com", &["sonarr".into()], true);
        assert!(
            c.iter().all(|c| c.command.contains("'https://")),
            "{:?}",
            c[0].command
        );
    }

    #[test]
    fn a_kept_disk_is_checked_for_its_recorded_filesystem() {
        let d = disk("/dev/disk/by-id/ata-DATA_1", Some("ext4"));
        let c = data_disk_checks(&[&d]);
        assert_eq!(c.len(), 1);
        assert!(c[0].command.contains("ata-DATA_1"));
        assert!(
            c[0].command.contains("'/dev/disk/by-id/ata-DATA_1'"),
            "must be quoted: {}",
            c[0].command
        );
        assert_eq!(c[0].expect, "ext4");
    }

    #[test]
    fn a_disk_with_no_recorded_filesystem_is_not_checked() {
        let d = disk("/dev/disk/by-id/ata-EMPTY", None);
        assert!(data_disk_checks(&[&d]).is_empty());
    }

    /// Reporting only ferrumd's password would claim success while leaving
    /// the operator locked out of every app.
    #[test]
    fn both_credentials_are_reported_when_sso_is_on() {
        let c = credential_paths(true);
        assert_eq!(c.len(), 2);
        assert!(c.iter().any(|(_, p)| p.contains("ferrumd-setup-password")));
        assert!(c.iter().any(|(_, p)| p.contains("authelia-setup-password")));
    }

    #[test]
    fn only_ferrumds_credential_is_reported_without_sso() {
        assert_eq!(credential_paths(false).len(), 1);
    }

    // ---- R1 A8: the reachability proof ---------------------------------

    /// The nginx `forceSSL` redirect, as it arrives on the wire.
    fn redirect_from(host: &str) -> String {
        format!(
            "HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\n\
             Location: https://{host}/\r\nConnection: close\r\n\r\n"
        )
    }

    fn dns_a(address: &str) -> DnsDecision {
        DnsDecision {
            target: RecordTarget::A(address.parse().expect("a literal address")),
            ddns_updater: true,
        }
    }

    fn one_check() -> ExternalCheck {
        let checks = external_reachability_checks(
            "thesyms.ca",
            &["sonarr".into()],
            true,
            Some(&dns_a("203.0.113.10")),
        );
        checks.into_iter().next().expect("one check")
    }

    /// The claim A8 actually makes: the request leaves THIS process, aimed
    /// at the detected address, and nothing about it touches the target.
    ///
    /// The strongest half of this is a mutation that **cannot be expressed**:
    /// `collect::run(&Target, &SshAuth, &str)` takes a shell command string,
    /// and the probe seam takes `&ExternalCheck`, so routing this check over
    /// SSH is a type error rather than a test failure. The assertions below
    /// cover what the type system cannot -- that the call site in `main.rs`
    /// has not grown an SSH path alongside it, and that the probe is aimed
    /// at the address rather than at a name a resolver could redirect.
    ///
    /// Mutation check: make `report_external_reachability` call
    /// `collect::run`, or give `ExternalCheck` a command string this module
    /// hands to it, and this fails.
    #[test]
    fn the_reachability_probe_is_never_issued_over_ssh() {
        let check = one_check();
        assert_eq!(
            check.socket().ip(),
            &"203.0.113.10".parse::<Ipv4Addr>().unwrap(),
            "the probe must go to the detected address, not to whatever a \
             resolver says the name is today"
        );

        // A double that records what it was asked to do, and refuses to be
        // anything a remote runner could drive.
        let mut probed = Vec::new();
        let outcome = assess(
            &[check],
            |c| {
                probed.push(c.clone());
                Answer::Answered(redirect_from(&c.host))
            },
            || panic!("the control must not run when the probe answered"),
        );
        assert_eq!(probed.len(), 1);
        assert!(matches!(outcome[0], Reachability::Reachable { .. }));

        // The call site, and this module, must stay clear of the SSH path.
        // Comments are stripped first: this module's prose says "not over
        // SSH" a great many times, and the claim under test is the code.
        let src = include_str!("verify.rs");
        let reachability = &src[src
            .find("pub fn external_reachability_checks")
            .expect("the check exists")
            ..src.find("#[cfg(test)]").expect("the tests follow it")];
        let code: String = reachability
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        // `RecordTarget` legitimately appears here, so the needle is the
        // SSH machinery itself rather than the word "target".
        for forbidden in ["collect::", "SshAuth", "preconditions::", "\"ssh\""] {
            assert!(
                !code.contains(forbidden),
                "the reachability check must not be able to reach the target: \
                 found {forbidden:?}"
            );
        }
        let main_src = include_str!("main.rs");
        let call_site = &main_src[main_src
            .find("fn report_external_reachability")
            .expect("the call site exists")..];
        let call_site = &call_site[..call_site.find("\n}\n").expect("it ends")];
        assert!(
            !call_site.contains("collect::") && !call_site.contains("pre."),
            "a host asking itself whether the world can reach it can only \
             ever answer yes:\n{call_site}"
        );
    }

    /// The three states are three, and the middle one is the whole point.
    ///
    /// Mutation check: make `classify` return `NotReachable` when the
    /// control fails -- the D-11b collapse -- and the third row fails.
    #[test]
    fn a_check_that_could_not_run_is_never_reported_as_unreachable() {
        let check = one_check();

        let reachable = classify(&check, Answer::Answered(redirect_from(&check.host)), || {
            panic!("not consulted")
        });
        assert!(
            matches!(reachable, Reachability::Reachable { .. }),
            "{reachable:?}"
        );

        let refused = classify(
            &check,
            Answer::NoAnswer("Connection refused (os error 111)".into()),
            || Ok(()),
        );
        assert!(
            matches!(
                refused,
                Reachability::NotReachable {
                    cause: NotReachableCause::NothingAnswered(_),
                    ..
                }
            ),
            "the internet is fine and the server did not answer: {refused:?}"
        );

        // The identical probe failure, with this machine offline. It must
        // NOT become a verdict about the server.
        let unknown = classify(
            &check,
            Answer::NoAnswer("Connection refused (os error 111)".into()),
            || Err("1.1.1.1:443 Network is unreachable".into()),
        );
        let Reachability::CouldNotCheck { reason, .. } = &unknown else {
            panic!(
                "identical probe failure + no outbound connectivity must be \
                 'could not check', never 'not reachable': {unknown:?}"
            );
        };
        assert!(reason.contains("1.1.1.1"), "{reason}");
        let said = unknown.summary();
        assert!(said.contains("could not check"), "{said}");
        assert!(
            said.contains("says NOTHING about"),
            "the operator must not read this as a broken server: {said}"
        );
        assert!(
            !said.contains("NOT reachable"),
            "the two verdicts must not share vocabulary: {said}"
        );
    }

    /// D-11b, in its original shape. nginx's catch-all vhost accepts the
    /// connection and closes it with no response; an empty answer must be a
    /// stated finding, never a pass.
    ///
    /// Mutation check: treat an empty response as reachable, or let
    /// `redirects_to` return true for it, and this fails.
    #[test]
    fn a_connection_accepted_and_closed_silently_is_not_a_pass() {
        let check = one_check();
        for empty in ["", "   ", "\r\n"] {
            let got = classify(&check, Answer::Answered(empty.into()), || Ok(()));
            let Reachability::NotReachable {
                cause: NotReachableCause::NotThisHost(sample),
                ..
            } = &got
            else {
                panic!("{empty:?} must not pass: {got:?}");
            };
            assert!(
                sample.contains("closed with no response"),
                "an empty reply is the most misleading one and must be spelled \
                 out: {sample}"
            );
        }
    }

    /// The discriminator. A 3xx alone proves nothing -- only a redirect
    /// naming the host that was asked for can come from this host's nginx.
    ///
    /// Mutation check: drop either half of `redirects_to` and a row fails.
    #[test]
    fn only_this_hosts_own_redirect_counts_as_reaching_this_host() {
        let check = one_check();
        let verdict =
            |response: &str| classify(&check, Answer::Answered(response.into()), || Ok(()));

        assert!(matches!(
            verdict(&redirect_from("auth.thesyms.ca")),
            Reachability::Reachable { .. }
        ));

        for impostor in [
            // A redirect, but to somebody else's name: an interception page.
            "HTTP/1.1 302 Found\r\nLocation: https://portal.isp.example/login\r\n\r\n",
            // Our name, but not a redirect: a proxy serving its own page.
            "HTTP/1.1 200 OK\r\n\r\n<html>https://auth.thesyms.ca</html>",
            // Not HTTP at all.
            "SSH-2.0-OpenSSH_9.6\r\n",
        ] {
            let got = verdict(impostor);
            assert!(
                matches!(
                    got,
                    Reachability::NotReachable {
                        cause: NotReachableCause::NotThisHost(_),
                        ..
                    }
                ),
                "{impostor:?} is not this host answering: {got:?}"
            );
        }
    }

    /// Reported, never fatal, and specific about what to go and fix.
    #[test]
    fn a_server_that_cannot_be_reached_is_told_what_to_do_about_it() {
        let check = one_check();
        let said = classify(&check, Answer::NoAnswer("timed out".into()), || Ok(())).summary();
        assert!(said.contains("NOT reachable"), "{said}");
        assert!(said.contains("203.0.113.10"), "{said}");
        for cause in ["forwarded", "firewall", "carrier-grade NAT"] {
            assert!(
                said.contains(cause),
                "the likely causes must be named: {said}"
            );
        }
        assert!(
            said.contains("Nothing about\n  the install needs redoing"),
            "an operator installing before the port forward exists must not \
             be told to start again: {said}"
        );
    }

    /// A8 is about the address ferrum writes. Under a CNAME it writes none,
    /// and a host with no published name has nothing to prove.
    #[test]
    fn there_is_nothing_to_prove_without_a_stated_address() {
        assert!(external_reachability_checks("d.com", &["sonarr".into()], true, None).is_empty());
        let cname = DnsDecision {
            target: RecordTarget::Cname("home.dyn.example".into()),
            ddns_updater: false,
        };
        assert!(
            external_reachability_checks("d.com", &["sonarr".into()], true, Some(&cname))
                .is_empty(),
            "a CNAME delegates the address, so ferrum states none to prove"
        );
        // No third case here any more, and its removal is the point. It
        // asserted that a host with no app and no SSO "has no hostname to
        // ask for" -- which R13 falsified: `ferrum.d.com` is published
        // because the proxy is. See
        // `a_dashboard_only_host_still_proves_its_address_reaches_it`.
    }

    /// A8 on the configuration the old code returned nothing for: SSO
    /// declined, no app selected, and `ferrum.<domain>` published anyway.
    ///
    /// That combination was not hypothetical -- it is the smallest thing
    /// this installer can build with a domain -- and it was the one where
    /// the only published hostname went unprobed, because the host
    /// selection was written when the control plane had no vhost.
    #[test]
    fn a_dashboard_only_host_still_proves_its_address_reaches_it() {
        let checks =
            external_reachability_checks("thesyms.ca", &[], false, Some(&dns_a("203.0.113.10")));
        assert_eq!(checks.len(), 1, "{checks:?}");
        assert_eq!(checks[0].host, "ferrum.thesyms.ca");
        assert_eq!(checks[0].address, Ipv4Addr::new(203, 0, 113, 10));
        // Still one probe, not one per surface: the question is whether
        // traffic to this address arrives here, and it is asked once.
        assert!(
            checks[0].request().contains("Host: ferrum.thesyms.ca\r\n"),
            "{:?}",
            checks[0].request()
        );
    }

    /// The auth host when there is one, because it is the hostname every
    /// *arr redirects to; otherwise a published app.
    #[test]
    fn the_probe_asks_for_a_hostname_this_host_actually_serves() {
        let apps = vec!["sonarr".to_string()];
        let dns = dns_a("203.0.113.10");
        let with_sso = external_reachability_checks("thesyms.ca", &apps, true, Some(&dns));
        assert_eq!(with_sso[0].host, "auth.thesyms.ca");
        let without = external_reachability_checks("thesyms.ca", &apps, false, Some(&dns));
        assert_eq!(without[0].host, "sonarr.thesyms.ca");

        // The request must carry the name as its Host header, or nginx
        // answers from the catch-all and the check proves the opposite of
        // what it claims.
        let request = with_sso[0].request();
        assert!(request.contains("Host: auth.thesyms.ca\r\n"), "{request:?}");
        assert!(request.contains("Connection: close"), "{request:?}");
        assert_eq!(with_sso[0].port, 80, "nginx's forceSSL redirect lives here");
    }

    /// The three operator-facing texts, printed so the story's report can
    /// quote what an operator actually sees rather than what it compiles to.
    #[test]
    fn the_three_verdicts_read_differently_to_an_operator() {
        let check = one_check();
        let states = [
            classify(&check, Answer::Answered(redirect_from(&check.host)), || {
                Ok(())
            }),
            classify(
                &check,
                Answer::NoAnswer("Connection refused".into()),
                || Ok(()),
            ),
            classify(
                &check,
                Answer::NoAnswer("Connection refused".into()),
                || {
                    Err(
                        "1.1.1.1:443 Network is unreachable; 8.8.8.8:443 Network is unreachable"
                            .into(),
                    )
                },
            ),
        ];
        println!("\nchecking from HERE, over the internet -- not from the server:");
        for state in &states {
            println!("{}\n", state.summary());
            assert!(!state.summary().trim().is_empty());
        }
    }
}
