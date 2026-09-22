//! The pre-erase DNS gate: what ferrum will do to the operator's zone,
//! shown and decided **before** the disk is touched (spec R1 A7, A3, A6).
//!
//! **Why this runs where it does.** The whole of R1 exists because
//! `auth.thesyms.ca` never resolved after an install that reported success.
//! Showing the record plan *after* the install would reproduce a quieter
//! version of the same defect: a pre-existing `plex.<domain>` pointing at
//! the operator's old box would be discovered, reported and left alone once
//! the new machine was already serving Plex -- so ferrum would publish an
//! app at a name that still answers from somewhere else, and the operator
//! would be handed a manual step at the end. The decision has to happen
//! while it can still change the outcome, which is why the gate sits inside
//! `plan_install` between the disk confirmation and the point of no return.
//! R2/A4 learned the same lesson about the same window.
//!
//! **This module renders a plan; it does not compute one.** Every action
//! comes from [`ferrum_dns::record::plan`] against a live listing, so the
//! dry run and the later apply cannot describe different intentions. A
//! second implementation of "what would happen" is a second thing to drift.
//!
//! **Three things this module must never do**, each of which has already
//! cost someone real time:
//!
//! 1. Print an empty plan when the credential is broken (decision D-11).
//!    The owner's first live attempt produced no output at all because a
//!    missing file left the token empty and every request went out
//!    unauthenticated -- and an empty result reads exactly like "this
//!    feature is unsupported". "Nothing to change" and "I could not
//!    authenticate, so I saw nothing" are opposite facts, so they are
//!    different outputs here: the first is a rendered sentence, the second
//!    is a named [`GateError`] and no plan at all.
//! 2. Show a foreign record the way it shows a correct one. A record ferrum
//!    did not create is [`RecordAction::SkipForeign`] and is rendered
//!    loudly; a record that already matches is `Unchanged` and is rendered
//!    quietly. "I am leaving this alone because it is not mine" and "this
//!    is already right" lead to opposite operator actions. The same holds
//!    for a foreign record sitting *beside* one of ferrum's at the same
//!    name ([`RecordAction::SkipForeignBeside`]): ferrum's own line there
//!    says `unchanged`, which on its own reads as a clean plan while half
//!    the requests for that name reach a host ferrum never mentioned.
//! 3. Let the operator believe every hostname will answer. Two caveats are
//!    emitted verbatim -- [`SPLIT_HORIZON_CAVEAT`] and
//!    [`daemon_record_caveat`] -- in both the dry run and the final report.
//!    [`SPLIT_HORIZON_CAVEAT`] is a fixed string; [`daemon_record_caveat`]
//!    is a fixed string *per state*, since R13 made what is true of
//!    `ferrum.<domain>` depend on how the host was answered. Either way the
//!    text is exact rather than assembled, so a test can assert the whole
//!    of it and a regression cannot quietly reword one out of existence.
//!    The third
//!    case is the zone's own Cloudflare status: a zone sitting at `pending`
//!    because the registrar's nameservers were never switched accepts every
//!    write, answers correctly when asked directly, and resolves nowhere
//!    for the rest of the internet. That is `auth.thesyms.ca` exactly, so
//!    this gate refuses a zone Cloudflare will never serve and shouts about
//!    one it does not serve *yet* -- here, while the disk is still intact,
//!    rather than in a final report that says success.

use ferrum_dns::client::Client;
use ferrum_dns::record::{DesiredRecord, RecordAction};
use ferrum_dns::zone::{ResolvedZone, ZoneService};
use ferrum_dns::CloudflareError;

use crate::answers::{Answers, ClientFactory, DnsDecision, RecordTarget};
use crate::prompt::PromptIo;

/// The subdomain the ferrum daemon is published under.
///
/// Matches the `ferrum.<domain>` line the final report already prints and
/// `ferrum.daemon.subdomain`'s own default. A1 requires a record for it.
pub const DAEMON_SUBDOMAIN: &str = "ferrum";

/// A6, verbatim and in one place.
///
/// Split-horizon and NAT hairpin are out of R1's scope, but silence about
/// them is not free: the owner watched every hostname return `HTTP 000`
/// from inside the LAN while the same names worked perfectly from outside,
/// and spent real time concluding the install had failed when it had not.
///
/// The wording is frozen by the spec so both emission sites say the same
/// thing and a test can match it exactly.
pub const SPLIT_HORIZON_CAVEAT: &str =
    "records point at the public address; reaching them from inside your LAN depends on \
     your router's NAT hairpin, which many do not support -- this is expected, not a failure.";

/// Where the credential lives once a host exists, in its real shape.
///
/// Stated rather than paraphrased because paraphrasing it is the defect
/// (D-11a): it is not a bare token on disk. It is a systemd
/// `EnvironmentFile`, so its content is one `KEY=value` line, and an
/// operator who pastes a bare value into that file has produced something
/// every reader parses as empty -- which is the failure that produced the
/// silent empty result in the first place.
pub const CREDENTIAL_LOCATION: &str =
    "on the host this credential becomes /run/secrets/acme-dns, a systemd EnvironmentFile \
     whose single line is CLOUDFLARE_DNS_API_TOKEN=<token> -- not a bare token";

/// What `ferrum.<baseDomain>` will actually do, for the host as answered.
///
/// **This used to be one frozen sentence, and R13 falsified it.** It said
/// the name "will resolve, and then the connection will close with no
/// response ... until daemon web access ships in Phase 1.7c R13". A1 is
/// what ships that, so an installer still printing it would be telling the
/// operator the dashboard is unreachable while building a host on which it
/// is the first thing that works. A7 is the criterion that forbids exactly
/// this: degrade honestly, and never describe a state the host does not
/// have. So the caveat is now a pure function of the answered state.
///
/// The state that decides it is `daemonPublished` in
/// `modules/proxy/lib.nix` -- `daemon.enable && proxy.enable && baseDomain
/// != ""` -- plus `auth.enable` for whether the published vhost is gated.
/// Two of those four terms are settled by this installer rather than asked
/// about: `ferrum.daemon.enable` defaults to true and nothing here writes
/// it, and `render.rs` emits `proxy.enable = true` exactly when a base
/// domain was answered. `ferrum.daemon.subdomain` is likewise never asked
/// and is [`DAEMON_SUBDOMAIN`]. That leaves the two parameters below, and
/// an empty `base_domain` is how "no vhost at all" is spelled.
///
/// This is the one place where independently written Rust and Nix describe
/// the same runtime fact, so it can drift without anything failing. If the
/// sentence and the host ever disagree, the operator is being told
/// something the machine does not do -- which is the entire defect A7
/// exists to prevent.
///
/// # Arguments
/// * `base_domain` - `ferrum.proxy.baseDomain`; empty when none was
///   answered, which in this installer also means the proxy is off.
/// * `auth_enabled` - `ferrum.auth.enable`, i.e. whether the operator kept
///   single sign-on.
///
/// # Returns
/// One exact sentence per state, so a test can assert the whole of it for
/// a known domain.
#[must_use]
pub fn daemon_record_caveat(base_domain: &str, auth_enabled: bool) -> String {
    if base_domain.is_empty() {
        return "ferrum's own web interface has no hostname on this host: with no base \
                domain there is no vhost for it, so it stays reachable only over an SSH \
                tunnel to its loopback port. That is expected -- it is not a failed install."
            .to_string();
    }
    if auth_enabled {
        return format!(
            "{DAEMON_SUBDOMAIN}.{base_domain} is ferrum's own web interface, and it is \
             published like any other app: it resolves, answers on a real certificate at \
             https://{DAEMON_SUBDOMAIN}.{base_domain}, and asks for the single sign-on \
             login at auth.{base_domain} before it shows you anything."
        );
    }
    format!(
        "{DAEMON_SUBDOMAIN}.{base_domain} is ferrum's own web interface, and because you \
         declined single sign-on it answers at https://{DAEMON_SUBDOMAIN}.{base_domain} \
         with NO login in front of it. It writes secrets, rewrites this host's settings \
         and applies system generations, so anyone who finds that hostname has this \
         machine. You confirmed this during the install."
    )
}

/// Why no plan could be produced.
///
/// A named error rather than an empty result, and that distinction is the
/// whole of decision D-11: the alternative -- a blank listing produced by
/// an unauthenticated request -- told the owner the exact opposite of the
/// truth about whether ferrum manages DNS at all.
#[derive(Debug)]
pub enum GateError {
    /// The operator's answers call for managed records but no Cloudflare
    /// credential is in hand.
    MissingCredential {
        /// The domain whose records could not be planned.
        base_domain: String,
    },
    /// The credential still carries the `CLOUDFLARE_DNS_API_TOKEN=` prefix
    /// of the `EnvironmentFile` it lives in on a host. Sent as a bearer
    /// token it authenticates nothing and lists nothing.
    PrefixedCredential,
    /// Cloudflare itself refused, or could not be reached.
    Cloudflare {
        /// The domain whose records could not be planned.
        base_domain: String,
        /// What `ferrum-dns` reported. Its `Display` never carries the
        /// token.
        cause: CloudflareError,
    },
    /// Cloudflare holds the zone but will never answer for it -- it has
    /// been moved, deleted or deactivated.
    ///
    /// A refusal rather than a warning for the same reason
    /// [`CloudflareError::ZoneDelegated`] is: every write would be accepted
    /// and not one name would resolve, and unlike a `pending` zone no
    /// amount of waiting changes it. `pending` is deliberately *not* here:
    /// an operator who has already switched their registrar and is waiting
    /// for propagation has a legitimate install, so that case is disclosed
    /// loudly in [`render`] instead of blocked.
    ZoneNotServing {
        /// The domain whose records could not be planned.
        base_domain: String,
        /// The whole operator-facing sentence, from
        /// [`ResolvedZone::advisory`], so the installer and the apply
        /// describe the same condition the same way.
        detail: String,
    },
}

impl std::fmt::Display for GateError {
    /// Renders the failure for an operator, naming the credential's real
    /// location and shape. Never the token itself.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateError::MissingCredential { base_domain } => write!(
                f,
                "cannot show the DNS plan for {base_domain}: no Cloudflare API token is \
                 available, so ferrum could not list a single record. This is a refusal, \
                 not an empty result -- an unauthenticated listing comes back blank and \
                 reads exactly like \"ferrum does not manage DNS\". Enter the token when \
                 asked, and note that {CREDENTIAL_LOCATION}."
            ),
            GateError::PrefixedCredential => write!(
                f,
                "the Cloudflare credential still carries its CLOUDFLARE_DNS_API_TOKEN= \
                 prefix, so it is the EnvironmentFile line rather than the token inside \
                 it. Sent as a bearer token it authenticates nothing and lists nothing, \
                 which looks identical to a zone with no records. Note that \
                 {CREDENTIAL_LOCATION}."
            ),
            GateError::Cloudflare { base_domain, cause } => write!(
                f,
                "cannot show the DNS plan for {base_domain}: {cause} Nothing has been \
                 changed, in Cloudflare or on the target. This is a refusal rather than an \
                 empty plan on purpose: a listing that failed and a zone with nothing to do \
                 look the same, and only one of them means ferrum will publish your apps."
            ),
            GateError::ZoneNotServing {
                base_domain,
                detail,
            } => write!(
                f,
                "refusing to plan DNS for {base_domain}: {detail} Nothing has been changed, \
                 in Cloudflare or on the target. This is refused rather than attempted \
                 because the attempt would succeed: every record would be written, the \
                 install would report success, and not one hostname would answer."
            ),
        }
    }
}

impl std::error::Error for GateError {}

/// A record ferrum wanted but does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignName {
    /// The fully qualified name, e.g. `plex.thesyms.ca`.
    pub name: String,
    /// Where the operator's record points today.
    pub current: String,
    /// Where ferrum would have pointed it.
    pub wanted: String,
}

/// What the operator decided about the names ferrum does not own, carried
/// forward to the final report.
///
/// Declines are the load-bearing half: A3 lets an operator keep their own
/// record, and the consequence is that the app is **not** reachable at its
/// ferrum hostname. Left as a line in a log the operator scrolled past
/// before the install even started, that fact arrives as a mystery hours
/// later -- which is the shape of failure R1 exists to remove.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Adoption {
    /// Names the operator handed to ferrum.
    pub adopted: Vec<ForeignName>,
    /// Names the operator kept, each of which is an app that will not
    /// answer at its ferrum hostname.
    pub declined: Vec<ForeignName>,
}

impl Adoption {
    /// The outcome for a run with no DNS gate at all: a host with no base
    /// domain, or a resume, which never re-asks anything.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The adopted names, for `ferrum.proxy.dns.adoptedNames`.
    ///
    /// This is the one value that has to survive the gate: without it the
    /// operator types `adopt`, reads a line saying it was recorded, and the
    /// host then does nothing with the record -- which is the "reported and
    /// left alone" behaviour they explicitly opted out of.
    ///
    /// # Returns
    /// The fully qualified names in the order the operator was asked about
    /// them, so a diff of two settings files reads the way the gate read.
    /// Declines contribute nothing: only an explicit `adopt` appears here.
    #[must_use]
    pub fn adopted_names(&self) -> Vec<String> {
        self.adopted.iter().map(|r| r.name.clone()).collect()
    }
}

/// Everything the pre-erase gate learned that the final report still needs.
///
/// [`Adoption`] alone was not enough, and the missing half is the point:
/// it carries what the *operator* decided, while a zone Cloudflare does
/// not serve yet is a fact about the zone that no answer at the gate can
/// change. Left behind on the [`DryRun`] that fact is printed once, before
/// the disk is erased, and then discarded -- so the last screen of a
/// successful install lists URLs that resolve for nobody, with nothing
/// qualifying them. That is R1's originating incident restated, which is
/// why the value has to come *out* of the gate rather than stop at it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GateOutcome {
    /// What the operator decided about the names ferrum does not own.
    pub adoption: Adoption,
    /// `Some` when Cloudflare is not serving this zone yet, carrying the
    /// sentence [`ResolvedZone::advisory`] produced.
    pub zone_not_serving_yet: Option<String>,
}

impl GateOutcome {
    /// The outcome for a run with no gate at all: a host with no base
    /// domain, or a resume, which never re-asks and never re-checks.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

/// A computed plan for one zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRun {
    /// `ferrum.proxy.baseDomain`.
    pub base_domain: String,
    /// The Cloudflare zone that turned out to cover it -- not necessarily
    /// the base domain, since the base domain may be a subdomain of a zone.
    pub zone_name: String,
    /// What every record will point at, as the operator stated it (A2).
    pub target: String,
    /// The plan, exactly as [`ferrum_dns::record::plan`] computed it.
    pub actions: Vec<RecordAction>,
    /// `Some` when Cloudflare does not serve this zone yet, carrying the
    /// sentence [`ResolvedZone::advisory`] produced.
    ///
    /// Carried on the plan rather than printed at the point it is
    /// discovered so that the one renderer the operator actually reads owns
    /// every caveat -- a warning emitted somewhere else is a warning that
    /// scrolls off the top of the screen before the plan appears.
    pub zone_not_serving_yet: Option<String>,
    /// `ferrum.auth.enable`, carried here for [`daemon_record_caveat`].
    ///
    /// The plan knows the base domain already, and the other two terms of
    /// `daemonPublished` are settled by this installer -- this is the only
    /// one it cannot derive from what it holds, so it is the only one
    /// added. [`dry_run`] takes it straight from the SSO decision.
    pub auth_enabled: bool,
}

impl DryRun {
    /// The names ferrum wants but does not own (A3).
    #[must_use]
    pub fn foreign(&self) -> Vec<ForeignName> {
        self.actions
            .iter()
            .filter_map(|action| match action {
                RecordAction::SkipForeign {
                    name,
                    current,
                    wanted,
                } => Some(ForeignName {
                    name: name.clone(),
                    current: current.to_string(),
                    wanted: wanted.to_string(),
                }),
                _ => None,
            })
            .collect()
    }
}

/// Every record ferrum wants for this host (A1).
///
/// The set mirrors what `modules/proxy/acme.nix` already issues
/// certificates for -- one per published app, plus `auth` when SSO is on
/// and something is published -- with the daemon's own subdomain added per
/// A1 and the owner's H-01 option-C ruling.
///
/// **This is the one place that names a record before the host exists**, so
/// it is also the one place that can name a *different* record than the
/// host will. `modules/proxy/dns.nix` decides the same set from
/// `modules/proxy/lib.nix`'s `vhostNameFor`, which is
/// `<subdomain>.<baseDomain>`; the names below are `<id>.<baseDomain>`.
/// Those agree only while every catalog app's `defaultSubdomain` equals its
/// id, which is not left to chance: `checks.installer-offers-every-catalog-app`
/// (`nix/modules/flake/checks.nix`, run by CI's cheap-checks job) fails the
/// build the moment one does not. The failure that assertion prevents is
/// specific -- the dry run would list, and offer for adoption, a name the
/// apply never touches, so a foreign record at the *real* name would be
/// invisible here and silently overwritten later. That is the
/// `auth.thesyms.ca` shape of defect, one layer quieter.
///
/// The daemon record is unconditional here while `modules/proxy/dns.nix`
/// gates it on `ferrum.daemon.dns.includeRecord`. They agree for every host
/// this function can describe: that option defaults to `true`, the
/// installer writes no `daemon` settings at all (`render::settings`), and
/// no prompt or flag can reach it. Teaching the installer to set it means
/// teaching this function to read it.
///
/// # Arguments
/// * `base_domain` - `ferrum.proxy.baseDomain`.
/// * `answers` - the operator's answers, for the app list and SSO choice.
/// * `dns` - the record target decided once, at the prompt (A2).
///
/// # Returns
/// The desired records, ordered the way the final report lists the URLs, so
/// the two readings of the same host agree.
#[must_use]
pub fn desired_records(
    base_domain: &str,
    answers: &Answers,
    dns: &DnsDecision,
) -> Vec<DesiredRecord> {
    let target = to_dns_target(&dns.target);
    let mut names = vec![format!("{DAEMON_SUBDOMAIN}.{base_domain}")];
    if answers.sso.enabled && !answers.apps.is_empty() {
        names.push(format!("auth.{base_domain}"));
    }
    names.extend(
        answers
            .apps
            .iter()
            .map(|app| format!("{app}.{base_domain}")),
    );

    names
        .into_iter()
        .map(|name| DesiredRecord {
            name,
            target: target.clone(),
        })
        .collect()
}

/// Translates the installer's own record-target answer into the seam's.
///
/// Two types rather than one because they answer different questions: the
/// installer's is what a human typed at a prompt, the seam's is what goes
/// into a Cloudflare body. They happen to have the same two shapes today,
/// and a conversion here is cheaper than either crate depending on the
/// other's vocabulary.
fn to_dns_target(target: &RecordTarget) -> ferrum_dns::RecordTarget {
    match target {
        RecordTarget::A(address) => ferrum_dns::RecordTarget::A(*address),
        RecordTarget::Cname(host) => ferrum_dns::RecordTarget::Cname(host.clone()),
    }
}

/// Mints the client's token from the answers, refusing every shape that
/// would produce a blank listing (D-11).
///
/// # Arguments
/// * `answers` - the collected answers.
/// * `base_domain` - for the error message.
///
/// # Returns
/// The bare token, wrapped so it cannot be printed by accident.
///
/// # Errors
/// [`GateError::MissingCredential`] when there is no token, or one that is
/// empty or whitespace; [`GateError::PrefixedCredential`] when it is the
/// `EnvironmentFile` line rather than the token inside it.
fn credential(answers: &Answers, base_domain: &str) -> Result<ferrum_dns::Secret, GateError> {
    let raw = answers
        .cloudflare_token
        .as_ref()
        .map(crate::answers::Secret::expose)
        .unwrap_or_default()
        .trim();

    if raw.is_empty() {
        return Err(GateError::MissingCredential {
            base_domain: base_domain.to_string(),
        });
    }
    if raw.starts_with("CLOUDFLARE_DNS_API_TOKEN=") {
        return Err(GateError::PrefixedCredential);
    }
    Ok(ferrum_dns::Secret::new(raw.to_string()))
}

/// Computes the plan without changing anything (A7).
///
/// # Arguments
/// * `base_domain` - `ferrum.proxy.baseDomain`.
/// * `answers` - the operator's answers, for the credential and app list.
/// * `dns` - the record-target decision.
/// * `make_client` - how Cloudflare is reached; tests pass a factory
///   pointed at `ferrum_dns::testing::FakeCloudflare`, because the sandbox
///   that runs this suite has no network and must never reach the real API.
///
/// # Returns
/// The zone that was resolved and the actions reconciling it would take.
///
/// # Errors
/// A [`GateError`]. Never an empty plan standing in for a failure.
pub fn dry_run(
    base_domain: &str,
    answers: &Answers,
    dns: &DnsDecision,
    make_client: ClientFactory<'_>,
) -> Result<DryRun, GateError> {
    let client: Client = make_client(credential(answers, base_domain)?);
    let resolved: ResolvedZone =
        client
            .resolve_zone(base_domain)
            .map_err(|cause| GateError::Cloudflare {
                base_domain: base_domain.to_string(),
                cause,
            })?;

    // The status split, and the reason it is a split rather than one rule:
    // a zone Cloudflare will never serve is a decision the operator has to
    // change, while a zone it does not serve *yet* is one they may already
    // have changed and be waiting on. Refusing both would block a
    // legitimate install mid-propagation; passing both silently is the
    // defect this check exists for.
    let zone_not_serving_yet = match resolved.status.service() {
        ZoneService::Serving => None,
        ZoneService::NotYetServing => resolved.advisory(base_domain),
        ZoneService::NeverServing => {
            return Err(GateError::ZoneNotServing {
                base_domain: base_domain.to_string(),
                detail: resolved
                    .advisory(base_domain)
                    .unwrap_or_else(|| format!("Cloudflare reports it as {}", resolved.status)),
            })
        }
    };

    let desired = desired_records(base_domain, answers, dns);
    let actions = client
        .plan_records(&resolved.zone, &desired)
        .map_err(|cause| GateError::Cloudflare {
            base_domain: base_domain.to_string(),
            cause,
        })?;

    Ok(DryRun {
        base_domain: base_domain.to_string(),
        zone_name: resolved.zone.name,
        target: describe_target(&dns.target),
        actions,
        zone_not_serving_yet,
        auth_enabled: answers.sso.enabled,
    })
}

/// The block that says none of ferrum's hostnames resolve yet.
///
/// A shared function for the same reason [`SPLIT_HORIZON_CAVEAT`] is a
/// shared constant: this text is emitted twice -- once in the dry run and
/// once in the final report -- and two copies of it are two things a later
/// edit can reword apart.
///
/// # Arguments
/// * `detail` - the sentence [`ResolvedZone::advisory`] produced, naming
///   the status and the nameservers the registrar has to be pointed at.
///
/// # Returns
/// Unindented lines; each caller indents them to suit its own block.
#[must_use]
pub fn not_published_yet_lines(detail: &str) -> Vec<String> {
    vec![
        "NOT PUBLISHED YET -- Cloudflare is not answering for this domain.".to_string(),
        detail.to_string(),
        "Until that zone is active, every record ferrum manages will be created correctly"
            .to_string(),
        "and none of these hostnames will resolve for anyone, including you. The install"
            .to_string(),
        "itself is unaffected and will finish; the names start working when the zone does."
            .to_string(),
    ]
}

/// Renders a target the way the operator stated it, type included.
fn describe_target(target: &RecordTarget) -> String {
    match target {
        RecordTarget::A(address) => format!("A {address}"),
        RecordTarget::Cname(host) => format!("CNAME {host}"),
    }
}

/// The width the action column is padded to, so the names line up and the
/// plan can be read down the page rather than across it.
const ACTION_WIDTH: usize = 10;

/// Renders the plan for a human (A7), with both caveats.
///
/// # Arguments
/// * `plan` - the dry run to render.
///
/// # Returns
/// The whole block, ending with [`SPLIT_HORIZON_CAVEAT`] and
/// [`daemon_record_caveat`]. Both appear here *and* in the final report:
/// the operator reads this one before the disk is erased and the other
/// after the host is up, and the second is the one still on screen when a
/// hostname does not answer.
#[must_use]
pub fn render(plan: &DryRun) -> String {
    let mut out = format!(
        "\nDNS records ferrum will manage for {}\n  Cloudflare zone:   {}\n  \
         records point at:  {}\n  credential:        the Cloudflare API token you \
         entered --\n                     {}\n\n",
        plan.base_domain, plan.zone_name, plan.target, CREDENTIAL_LOCATION
    );

    if plan.actions.is_empty() {
        // Deliberately a sentence rather than a blank space. D-11: the one
        // output that must never be mistaken for a failure is the one that
        // means there is genuinely nothing to do.
        out.push_str(
            "  nothing to change -- the zone already holds exactly the records ferrum \
             wants.\n  This is a listing that succeeded and found no work, not a listing \
             that failed.\n",
        );
    }

    // The name column is sized to the longest name in this plan rather than
    // to a constant: a fixed width either truncates a long hostname or
    // leaves a ragged gap on a short domain, and the whole value of the
    // block is being readable down the page.
    let name_width = plan
        .actions
        .iter()
        .map(|action| action_name(action).len())
        .max()
        .unwrap_or(0);
    for action in &plan.actions {
        out.push_str(&render_action(action, name_width));
    }

    out.push_str(&format!("\n  note: {SPLIT_HORIZON_CAVEAT}\n"));
    out.push_str(&format!(
        "  note: {}\n",
        daemon_record_caveat(&plan.base_domain, plan.auth_enabled)
    ));

    // Last, and shouted, because it is the only line here that means none
    // of the rows above will do anything for anybody. Its own block rather
    // than a third `note:` for exactly that reason: the two notes above
    // describe a working install with a caveat, and this describes an
    // install that publishes nothing.
    if let Some(detail) = &plan.zone_not_serving_yet {
        out.push('\n');
        for line in not_published_yet_lines(detail) {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out
}

/// The record name an action is about, for the column width.
fn action_name(action: &RecordAction) -> &str {
    match action {
        RecordAction::Create { name, .. }
        | RecordAction::Update { name, .. }
        | RecordAction::Unchanged { name, .. }
        | RecordAction::Delete { name, .. }
        | RecordAction::Adopt { name, .. }
        | RecordAction::SkipForeign { name, .. }
        | RecordAction::SkipForeignBeside { name, .. }
        | RecordAction::SkipUnmodelledType { name, .. } => name,
    }
}

/// Renders one action.
///
/// `SkipForeign` is the one line that shouts. It is capitalised, it says
/// outright that ferrum did not create the record, and it names both
/// addresses -- because the operator's next decision depends on knowing
/// this is *their* record, and an `Unchanged` line means the opposite thing
/// while looking almost identical.
///
/// # Arguments
/// * `action` - one entry of [`ferrum_dns::record::plan`]'s output.
/// * `name_width` - the widest record name in the plan, so the columns line
///   up across every row.
fn render_action(action: &RecordAction, name_width: usize) -> String {
    match action {
        RecordAction::Create { name, target } => {
            format!(
                "  {:<ACTION_WIDTH$} {name:<name_width$}  ->  {target}\n",
                "create"
            )
        }
        RecordAction::Update {
            name,
            current,
            target,
            ..
        } => format!(
            "  {:<ACTION_WIDTH$} {name:<name_width$}  {current}  ->  {target}\n",
            "update"
        ),
        RecordAction::Unchanged { name, .. } => format!(
            "  {:<ACTION_WIDTH$} {name:<name_width$}  ferrum's own record, already correct\n",
            "unchanged"
        ),
        RecordAction::Delete { name, .. } => format!(
            "  {:<ACTION_WIDTH$} {name:<name_width$}  ferrum created it and nothing needs \
             it now\n",
            "delete"
        ),
        // Reachable only on a re-run of the gate for a host whose settings
        // already carry the adoption -- the first pass plans against an
        // empty adopted set, because the decision has not been made yet.
        // Worded as strongly as SKIPPED for the opposite reason: this is the
        // one line that says ferrum is about to write over something the
        // operator put there.
        RecordAction::Adopt {
            name,
            current,
            target,
            ..
        } => format!(
            "  {:<ACTION_WIDTH$} {name:<name_width$}  you adopted this name; ferrum will \
             take it over.\n  {:<ACTION_WIDTH$} {:<name_width$}  it points at {current} \
             and will point at {target}.\n",
            "ADOPT", "", ""
        ),
        RecordAction::SkipForeign {
            name,
            current,
            wanted,
        } => format!(
            "  {:<ACTION_WIDTH$} {name:<name_width$}  ferrum did NOT create this record \
             and will not touch it.\n  {:<ACTION_WIDTH$} {:<name_width$}  it points at \
             {current}; ferrum wanted {wanted}.\n",
            "SKIPPED", "", ""
        ),
        // The other "also here" line, and the wording is the whole point of
        // keeping it separate from the one below. Both say a second record
        // answers at this name; they differ in what the operator can do
        // about it. This one is a record ferrum *could* manage and did not
        // create, so the reason it survives is ownership (A3) -- the
        // operator can delete it, or re-run the installer and adopt the
        // name. The one below is a type ferrum has no model for, which no
        // decision here can change. Collapsing them into one sentence would
        // tell an operator with a stray A record that ferrum cannot manage
        // A records.
        RecordAction::SkipForeignBeside { name, current } => format!(
            "  {:<ACTION_WIDTH$} {name:<name_width$}  another record you own also answers \
             here, pointing at\n  {:<ACTION_WIDTH$} {:<name_width$}  {current}. ferrum did \
             NOT create it and will not touch it, so\n  {:<ACTION_WIDTH$} {:<name_width$}  \
             some requests for this name will reach that address and\n  \
             {:<ACTION_WIDTH$} {:<name_width$}  some will reach this server.\n",
            "ALSO YOURS", "", "", "", "", "", ""
        ),
        // An extra line beside this name's own, never instead of it. The
        // case that makes it worth the noise is an existing AAAA: ferrum
        // creates its A, both answer, and every IPv6-capable client keeps
        // reaching the old host. Silence there is indistinguishable from a
        // clean plan.
        RecordAction::SkipUnmodelledType { name, record_type } => format!(
            "  {:<ACTION_WIDTH$} {name:<name_width$}  a {record_type} record also answers \
             here. ferrum does not\n  {:<ACTION_WIDTH$} {:<name_width$}  manage \
             {record_type} records and leaves it alone; clients that\n  \
             {:<ACTION_WIDTH$} {:<name_width$}  prefer it will not reach this server.\n",
            "ALSO HERE", "", "", "", ""
        ),
    }
}

/// The whole pre-erase gate: show the plan, decide the foreign names, and
/// hand the outcome to the final report.
///
/// # Arguments
/// * `answers` - the operator's answers. A host with no base domain or no
///   record decision has nothing to plan, and the gate is a no-op.
/// * `make_client` - how Cloudflare is reached.
/// * `io` - the question-and-answer channel with the operator.
///
/// # Returns
/// A [`GateOutcome`]: what was adopted, what was declined, and whether
/// Cloudflare answers for this zone yet -- all three for the final report,
/// which is the screen still on-screen when a hostname does not work.
///
/// # Errors
/// A [`GateError`], which aborts the install while the target is still
/// untouched -- deliberately, because every later moment is a worse one to
/// discover that ferrum cannot publish a single record.
pub fn gate(
    answers: &Answers,
    make_client: ClientFactory<'_>,
    io: &mut impl PromptIo,
) -> anyhow::Result<GateOutcome> {
    let (Some(base_domain), Some(dns)) = (answers.base_domain.as_deref(), answers.dns.as_ref())
    else {
        return Ok(GateOutcome::none());
    };

    let plan = dry_run(base_domain, answers, dns, make_client)?;
    io.say(&render(&plan));

    // Taken on *every* path out, including the one that asks the operator
    // nothing: a zone Cloudflare does not serve yet is exactly as fatal to
    // the URL list whether or not a single name is contested.
    let zone_not_serving_yet = plan.zone_not_serving_yet.clone();

    let foreign = plan.foreign();
    if foreign.is_empty() {
        return Ok(GateOutcome {
            adoption: Adoption::none(),
            zone_not_serving_yet,
        });
    }

    io.say(
        "\nSome of those names already exist and ferrum did not create them. ferrum never \
         overwrites\na record it does not own, so each one is your decision -- and this is \
         the last moment it\ncan be made, because nothing on the target has been erased yet.",
    );

    let mut adoption = Adoption::none();
    for record in foreign {
        io.say(&format!(
            "\n  {} points at {} and ferrum wanted {}.\n\n    \
             adopt   hand this name to ferrum. Your record is REPLACED on the first \
             apply\n            and ferrum owns it from then on. Nothing else in your \
             zone is\n            affected, and this name only.\n    \
             leave   (default) ferrum does not touch it. The name keeps pointing at {}, \
             and\n            the app will NOT be reachable at {}.",
            record.name, record.current, record.wanted, record.current, record.name
        ));
        let answer = io.ask(&format!(
            "Type 'adopt' to hand {} to ferrum, or press enter to leave it:",
            record.name
        ))?;
        if answer.eq_ignore_ascii_case("adopt") {
            adoption.adopted.push(record);
        } else {
            adoption.declined.push(record);
        }
    }
    Ok(GateOutcome {
        adoption,
        zone_not_serving_yet,
    })
}

/// The lines the final report prints about names ferrum does not own.
///
/// Split out from the report itself so the wording is pinned by a test
/// rather than asserted by a comment. A decline is reported as a **named
/// unreachable app**: it is the one thing an operator will otherwise
/// rediscover hours later as an unexplained failure.
///
/// # Arguments
/// * `adoption` - the gate's outcome.
///
/// # Returns
/// Zero lines when every name was ferrum's to take -- a report that always
/// prints a DNS section trains the operator to skip it.
#[must_use]
pub fn report_lines(adoption: &Adoption) -> Vec<String> {
    let mut lines = Vec::new();
    if !adoption.declined.is_empty() {
        lines.push(
            "NOT reachable at its ferrum hostname -- you kept your own DNS record:".to_string(),
        );
        for record in &adoption.declined {
            lines.push(format!(
                "  {} still points at {}, not at this server.",
                record.name, record.current
            ));
        }
    }
    if !adoption.adopted.is_empty() {
        lines.push("adopted -- you told ferrum these names are its to manage:".to_string());
        for record in &adoption.adopted {
            lines.push(format!("  {}", record.name));
        }
        lines.push(
            "  ferrum replaces each of these on the first apply and owns it from then on. \
             Every other record in your zone is untouched."
                .to_string(),
        );
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answers::Secret;
    use crate::prompt::testing::Scripted;
    use crate::sso::SsoDecision;
    use ferrum_dns::testing::{CannedResponse, FakeCloudflare, Route, TEST_TOKEN};
    use std::net::Ipv4Addr;

    const HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

    fn answers(apps: &[&str]) -> Answers {
        Answers {
            hostname: "saltbox".to_string(),
            base_domain: Some("thesyms.ca".to_string()),
            acme_email: Some("me@thesyms.ca".to_string()),
            sso: SsoDecision {
                enabled: true,
                unauthenticated_accepted_for: Vec::new(),
                admin_email: Some("me@thesyms.ca".to_string()),
            },
            apps: apps.iter().map(|a| (*a).to_string()).collect(),
            cloudflare_token: Some(Secret::new(TEST_TOKEN.to_string())),
            dns: Some(DnsDecision {
                target: RecordTarget::A(HOST),
                ddns_updater: true,
            }),
        }
    }

    /// One visible zone covering `thesyms.ca`, delegated nowhere.
    ///
    /// The record route is scripted twice on purpose: `resolve_zone` reads
    /// it once for `NS` delegations and `plan_records` reads it again for
    /// the listing the plan is computed from.
    fn fake_with(records: serde_json::Value) -> FakeCloudflare {
        fake_with_zone_status(records, "active")
    }

    /// The same fake, with Cloudflare's zone `status` set explicitly.
    ///
    /// The status is the one field that decides whether any of these
    /// records will ever be seen by anybody, and it is invisible to every
    /// other check in this crate: no `NS` record exists for the delegation
    /// check to find, the writes all succeed, and a query aimed at
    /// Cloudflare's own nameservers gets the right answer.
    fn fake_with_zone_status(records: serde_json::Value, status: &str) -> FakeCloudflare {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "thesyms.ca",
                "status": status,
                "name_servers": ["amber.ns.cloudflare.com", "bob.ns.cloudflare.com"],
            }])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(records),
        );
        fake
    }

    fn against(fake: &FakeCloudflare) -> impl Fn(ferrum_dns::Secret) -> Client + '_ {
        let base_url = fake.base_url().to_string();
        move |token| Client::with_base_url(token, base_url.clone())
    }

    fn record(id: &str, name: &str, content: &str, ferrums: bool) -> serde_json::Value {
        let mut value = serde_json::json!({
            "id": id, "name": name, "type": "A", "content": content, "proxied": false,
        });
        if ferrums {
            value["comment"] = serde_json::json!(ferrum_dns::OWNERSHIP_MARKER);
        }
        value
    }

    /// A1: the published apps, `auth` when SSO is on, and the daemon's own
    /// subdomain -- the same set the certificates are issued for, plus the
    /// record H-01 option C rules in.
    #[test]
    fn the_wanted_records_are_the_apps_plus_auth_plus_the_daemon() {
        let a = answers(&["plex", "sonarr"]);
        let names: Vec<String> = desired_records("thesyms.ca", &a, a.dns.as_ref().unwrap())
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(
            names,
            vec![
                "ferrum.thesyms.ca",
                "auth.thesyms.ca",
                "plex.thesyms.ca",
                "sonarr.thesyms.ca",
            ]
        );
    }

    /// No SSO means no sign-in hostname, exactly as `acme.nix` issues no
    /// certificate for one.
    #[test]
    fn a_host_without_sso_wants_no_auth_record() {
        let mut a = answers(&["plex"]);
        a.sso.enabled = false;
        let names: Vec<String> = desired_records("thesyms.ca", &a, a.dns.as_ref().unwrap())
            .into_iter()
            .map(|r| r.name)
            .collect();
        assert_eq!(names, vec!["ferrum.thesyms.ca", "plex.thesyms.ca"]);
    }

    /// A7, and the shape of the whole story: the plan the operator reads is
    /// the plan `record::plan` computed, with a create, an unchanged, an
    /// update, a foreign skip and the daemon record all visible.
    #[test]
    fn the_dry_run_renders_every_kind_of_action_the_planner_produces() {
        let fake = fake_with(serde_json::json!([
            record("r1", "sonarr.thesyms.ca", "203.0.113.7", true),
            record("r2", "plex.thesyms.ca", "198.51.100.9", false),
            record("r3", "radarr.thesyms.ca", "198.51.100.9", true),
        ]));
        let a = answers(&["plex", "sonarr"]);
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake))
            .expect("the plan is computed against the fake");
        let rendered = render(&plan);

        assert!(
            rendered.contains("create     ferrum.thesyms.ca"),
            "{rendered}"
        );
        assert!(
            rendered.contains("create     auth.thesyms.ca"),
            "{rendered}"
        );
        assert!(
            rendered.contains("unchanged  sonarr.thesyms.ca"),
            "{rendered}"
        );
        assert!(
            rendered.contains("SKIPPED    plex.thesyms.ca"),
            "{rendered}"
        );
        assert!(
            rendered.contains("delete     radarr.thesyms.ca"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(TEST_TOKEN),
            "the token must never be printed"
        );
    }

    /// A3, and the distinction the operator's next decision rests on: a
    /// record ferrum is leaving alone because it is not ferrum's must not
    /// read like a record that is already correct. Omitting the foreign
    /// name entirely -- the tempting "nothing to do here" -- is the same
    /// defect in a quieter form.
    #[test]
    fn a_foreign_record_is_shown_and_is_visibly_not_an_unchanged_one() {
        let fake = fake_with(serde_json::json!([
            record("r1", "sonarr.thesyms.ca", "203.0.113.7", true),
            record("r2", "plex.thesyms.ca", "198.51.100.9", false),
        ]));
        let a = answers(&["plex", "sonarr"]);
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake)).unwrap();
        let rendered = render(&plan);

        assert!(
            rendered.contains("plex.thesyms.ca"),
            "a skipped record must still be listed: {rendered}"
        );
        assert!(
            rendered.contains("ferrum did NOT create this record"),
            "the reason for the skip must be stated: {rendered}"
        );
        assert!(
            rendered.contains("it points at 198.51.100.9"),
            "the operator must see where their own record points: {rendered}"
        );

        let skip_line = rendered
            .lines()
            .find(|l| l.contains("plex.thesyms.ca"))
            .expect("the skipped name is on a line of its own");
        let unchanged_line = rendered
            .lines()
            .find(|l| l.contains("sonarr.thesyms.ca"))
            .expect("the unchanged name is on a line of its own");
        assert!(skip_line.contains("SKIPPED"), "{skip_line}");
        assert!(unchanged_line.contains("unchanged"), "{unchanged_line}");
    }

    /// The dry run is the operator's last look before the disk is erased,
    /// so a record type ferrum cannot reconcile must appear in it. Before
    /// this line existed the `AAAA` was dropped on the way in and the plan
    /// showed a bare `create` -- true, and materially incomplete.
    #[test]
    fn a_record_type_ferrum_does_not_manage_is_disclosed_beside_the_create() {
        let fake = fake_with(serde_json::json!([{
            "id": "theirs-v6",
            "name": "plex.thesyms.ca",
            "type": "AAAA",
            "content": "2001:db8::1",
            "proxied": false,
        }]));
        let a = answers(&["plex"]);
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake)).unwrap();
        let rendered = render(&plan);

        assert!(
            rendered.contains("ALSO HERE"),
            "the other record must be visible: {rendered}"
        );
        assert!(
            rendered.contains("a AAAA record also answers here"),
            "the type must be named: {rendered}"
        );
        assert!(
            rendered.contains("create     plex.thesyms.ca"),
            "ferrum still creates its own record: {rendered}"
        );
        assert!(
            plan.foreign().is_empty(),
            "a type ferrum cannot manage is not something the operator can \
             adopt: {:?}",
            plan.foreign()
        );
    }

    /// The case the type-based disclosure above did **not** cover: a record
    /// ferrum does not own at the same name *and* the same type as one it
    /// does. Nothing touches it -- A3/A4 held all along -- but until this
    /// test the plan said only `unchanged` for that name, which is what a
    /// hostname that resolves correctly every time also looks like. In fact
    /// Cloudflare round-robins the two, so it resolves correctly about half
    /// the time, and nothing ferrum printed said so.
    #[test]
    fn a_foreign_record_at_the_same_name_and_type_as_ferrums_is_disclosed() {
        let fake = fake_with(serde_json::json!([
            record("mine", "plex.thesyms.ca", "203.0.113.7", true),
            record("theirs", "plex.thesyms.ca", "198.51.100.9", false),
        ]));
        let a = answers(&["plex"]);
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake)).unwrap();
        let rendered = render(&plan);

        assert!(
            rendered.contains("ALSO YOURS"),
            "the operator's other record must be visible: {rendered}"
        );
        assert!(
            rendered.contains("another record you own also answers here"),
            "the disclosure must say what it is: {rendered}"
        );
        assert!(
            rendered.contains("198.51.100.9"),
            "the operator must see where their own record points: {rendered}"
        );
        assert!(
            rendered.contains("ferrum did NOT create it and will not touch it"),
            "the reason it survives is ownership, and that must be said: {rendered}"
        );
        assert!(
            rendered.contains("unchanged  plex.thesyms.ca"),
            "ferrum's own record is still reported on its own terms: {rendered}"
        );
    }

    /// The two "there is something else here" lines must not read as the
    /// same sentence. One is a record an operator can delete or adopt; the
    /// other is a type no decision of theirs can make ferrum manage.
    /// Collapsing them would tell an operator with a stray `A` record that
    /// ferrum cannot manage `A` records.
    #[test]
    fn the_two_disclosures_do_not_describe_themselves_the_same_way() {
        let fake = fake_with(serde_json::json!([
            record("mine", "plex.thesyms.ca", "203.0.113.7", true),
            record("theirs", "plex.thesyms.ca", "198.51.100.9", false),
            {
                "id": "theirs-v6",
                "name": "plex.thesyms.ca",
                "type": "AAAA",
                "content": "2001:db8::1",
                "proxied": false,
            },
        ]));
        let a = answers(&["plex"]);
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake)).unwrap();
        let rendered = render(&plan);

        assert!(
            rendered.contains("a AAAA record also answers here"),
            "the unmodelled type keeps its own wording: {rendered}"
        );
        assert!(
            rendered.contains("another record you own also answers here"),
            "the foreign record of a managed type keeps its own: {rendered}"
        );
        assert!(
            rendered.contains("ferrum does not"),
            "only the unmodelled line claims ferrum cannot manage the type: {rendered}"
        );
    }

    /// Disclosure is not an adoption offer. A3's opt-in is for a name ferrum
    /// **cannot publish** because the operator's record holds it; here
    /// ferrum's own record already exists, so there is nothing to hand over
    /// -- and widening the adoption path to reach this record would turn a
    /// reporting gap into a permissions one.
    #[test]
    fn a_disclosed_foreign_record_is_not_offered_for_adoption() {
        let fake = fake_with(serde_json::json!([
            record("mine", "plex.thesyms.ca", "203.0.113.7", true),
            record("theirs", "plex.thesyms.ca", "198.51.100.9", false),
        ]));
        let a = answers(&["plex"]);
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake)).unwrap();
        assert!(
            plan.foreign().is_empty(),
            "nothing here is the operator's to hand over: {:?}",
            plan.foreign()
        );

        // And therefore the gate asks nothing. A `Scripted` with no answers
        // panics if one is requested, which is the assertion.
        let fake = fake_with(serde_json::json!([
            record("mine", "plex.thesyms.ca", "203.0.113.7", true),
            record("theirs", "plex.thesyms.ca", "198.51.100.9", false),
        ]));
        let outcome = gate(&a, &against(&fake), &mut Scripted::new(&[]))
            .unwrap()
            .adoption;
        assert_eq!(outcome, Adoption::none());
    }

    /// A6, at the first of its two emission sites.
    #[test]
    fn the_dry_run_carries_the_split_horizon_caveat_verbatim() {
        let fake = fake_with(serde_json::json!([]));
        let a = answers(&["plex"]);
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake)).unwrap();
        assert!(render(&plan).contains(SPLIT_HORIZON_CAVEAT));
    }

    /// A7, at the first of the caveat's two emission sites: the dry run
    /// describes the host the operator is about to build.
    ///
    /// The assertion is still an exact whole-string match -- it is just no
    /// longer the same string for every host, because R13 made the answer
    /// depend on the answers. This covers the default: SSO kept, so the
    /// dashboard is published and gated.
    #[test]
    fn the_dry_run_describes_a_published_and_gated_dashboard() {
        let fake = fake_with(serde_json::json!([]));
        let a = answers(&["plex"]);
        assert!(a.sso.enabled, "this test's premise");
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake)).unwrap();
        let rendered = render(&plan);

        assert!(
            rendered.contains(&daemon_record_caveat("thesyms.ca", true)),
            "{rendered}"
        );
        assert!(
            rendered.contains("https://ferrum.thesyms.ca"),
            "the real reachable url, not a warning about a dead name: {rendered}"
        );
        assert!(
            rendered.contains("auth.thesyms.ca"),
            "and where the login it asks for lives: {rendered}"
        );
    }

    /// The same site, the other published state: R13's dashboard is up, but
    /// the operator declined single sign-on, so it is up with nothing in
    /// front of it. Saying "it will ask you to log in" here would be the
    /// A7 defect pointed the opposite way.
    #[test]
    fn the_dry_run_says_plainly_when_the_dashboard_will_be_ungated() {
        let fake = fake_with(serde_json::json!([]));
        let mut a = answers(&["plex"]);
        a.sso.enabled = false;
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake)).unwrap();
        let rendered = render(&plan);

        assert!(
            rendered.contains(&daemon_record_caveat("thesyms.ca", false)),
            "{rendered}"
        );
        assert!(
            rendered.contains("NO login"),
            "the ungated state must be stated, not implied: {rendered}"
        );
        assert!(
            !rendered.contains("single sign-on login at"),
            "and must not claim a gate that is not there: {rendered}"
        );
    }

    /// A7's own words -- "with no `baseDomain`, or with the proxy
    /// disabled, there is no vhost and the UI states where it *is*
    /// reachable rather than advertising a hostname that will not
    /// resolve."
    ///
    /// Unreachable from either emission site in this installer, since both
    /// are reached only with a domain in hand. Asserted anyway because it
    /// is the branch that makes the function total, and a caveat that
    /// silently interpolated an empty domain would print `ferrum.` as a
    /// hostname.
    #[test]
    fn the_caveat_advertises_no_hostname_when_there_is_no_vhost() {
        for auth in [true, false] {
            let text = daemon_record_caveat("", auth);
            assert_eq!(
                text,
                "ferrum's own web interface has no hostname on this host: with no base \
                 domain there is no vhost for it, so it stays reachable only over an SSH \
                 tunnel to its loopback port. That is expected -- it is not a failed install."
            );
            assert!(!text.contains("https://"), "no url is offered: {text}");
            assert!(!text.contains("ferrum."), "no hostname is offered: {text}");
        }
    }

    /// The sentence R13 falsified must be gone from every state, not
    /// merely unused by the default one. It named a ship date, so it is
    /// the phrase most likely to survive a careless edit.
    #[test]
    fn no_state_still_claims_the_dashboard_has_not_shipped() {
        for (domain, auth) in [("thesyms.ca", true), ("thesyms.ca", false), ("", false)] {
            let text = daemon_record_caveat(domain, auth);
            for stale in [
                "the connection will close",
                "has no vhost yet",
                "Phase 1.7c R13",
            ] {
                assert!(!text.contains(stale), "{stale:?} survives in: {text}");
            }
        }
    }

    /// D-11, the sharpest case in the requirement. A missing credential
    /// must produce a named refusal, never a plan with nothing in it: the
    /// owner's first live attempt printed nothing at all for exactly this
    /// reason, and an empty result reads as "unsupported".
    #[test]
    fn a_missing_credential_is_a_named_error_and_never_an_empty_plan() {
        let fake = fake_with(serde_json::json!([]));
        let mut a = answers(&["plex"]);
        a.cloudflare_token = None;

        let err = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake))
            .expect_err("an absent credential cannot produce a plan");

        assert!(
            matches!(err, GateError::MissingCredential { .. }),
            "{err:?}"
        );
        let message = err.to_string();
        assert!(message.contains("no Cloudflare API token"), "{message}");
        assert!(message.contains("reads exactly like"), "{message}");
        assert!(message.contains("/run/secrets/acme-dns"), "{message}");
        assert!(
            message.contains("CLOUDFLARE_DNS_API_TOKEN=<token>"),
            "the credential's real shape, not a paraphrase: {message}"
        );
        assert!(
            fake.requests().is_empty(),
            "nothing may go out unauthenticated"
        );
    }

    /// The same rule for an empty-but-present credential, which is what a
    /// missing file actually produces.
    #[test]
    fn an_empty_credential_is_refused_before_a_single_request_goes_out() {
        let fake = fake_with(serde_json::json!([]));
        let mut a = answers(&["plex"]);
        a.cloudflare_token = Some(Secret::new("   ".to_string()));

        let err = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake))
            .expect_err("an empty credential cannot produce a plan");
        assert!(
            matches!(err, GateError::MissingCredential { .. }),
            "{err:?}"
        );
        assert!(fake.requests().is_empty());
    }

    /// D-11a: the credential on a host is an `EnvironmentFile` line, so a
    /// value that still carries the prefix is the line, not the token.
    /// Sent as a bearer token it lists nothing, which is indistinguishable
    /// from a zone with no records.
    #[test]
    fn a_credential_that_is_still_the_environmentfile_line_is_refused() {
        let fake = fake_with(serde_json::json!([]));
        let mut a = answers(&["plex"]);
        a.cloudflare_token = Some(Secret::new(format!(
            "CLOUDFLARE_DNS_API_TOKEN={TEST_TOKEN}"
        )));

        let err = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake))
            .expect_err("the EnvironmentFile line is not a token");
        assert!(matches!(err, GateError::PrefixedCredential), "{err:?}");
        let message = err.to_string();
        assert!(message.contains("CLOUDFLARE_DNS_API_TOKEN="), "{message}");
        assert!(!message.contains(TEST_TOKEN), "never the token itself");
        assert!(fake.requests().is_empty());
    }

    /// D-11 again, from the other side: Cloudflare refusing the token is a
    /// refusal here too, not an empty zone.
    #[test]
    fn a_cloudflare_refusal_is_a_named_error_and_never_an_empty_plan() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );
        let a = answers(&["plex"]);

        let err = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake))
            .expect_err("a refused token cannot produce a plan");
        let message = err.to_string();
        assert!(message.contains("9109"), "{message}");
        assert!(message.contains("Nothing has been changed"), "{message}");
        assert!(!message.contains(TEST_TOKEN), "never the token itself");
    }

    // ---- the zone's own status (the parent incident, one door out) -----

    /// The whole of this requirement, reproduced through the one door it
    /// never checked. Zone in Cloudflare, registrar never switched, status
    /// `pending`: resolution succeeds, the plan is correct, every write
    /// would be accepted, and `auth.thesyms.ca` resolves for nobody. The
    /// gate must say so here -- while the disk is intact -- not in a final
    /// report that says success.
    #[test]
    fn a_pending_zone_is_shouted_about_in_the_plan_rather_than_passing_green() {
        let fake = fake_with_zone_status(serde_json::json!([]), "pending");
        let a = answers(&["plex"]);
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake))
            .expect("a pending zone still plans -- it is a disclosure, not a refusal");

        let detail = plan
            .zone_not_serving_yet
            .as_deref()
            .expect("a pending zone must be carried on the plan");
        assert!(detail.contains("pending"), "{detail}");

        let rendered = render(&plan);
        assert!(rendered.contains("NOT PUBLISHED YET"), "{rendered}");
        assert!(rendered.contains("registrar"), "{rendered}");
        assert!(
            rendered.contains("amber.ns.cloudflare.com"),
            "the operator must be told which nameservers to set: {rendered}"
        );
        assert!(
            rendered.contains("none of these hostnames will resolve"),
            "{rendered}"
        );
    }

    /// An `active` zone is the ordinary case and must stay quiet: a caveat
    /// printed on every install is a caveat nobody reads on the one install
    /// that needed it.
    #[test]
    fn an_active_zone_adds_no_warning_at_all() {
        let fake = fake_with(serde_json::json!([]));
        let a = answers(&["plex"]);
        let plan = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake))
            .expect("an active zone plans");
        assert_eq!(plan.zone_not_serving_yet, None);
        assert!(!render(&plan).contains("NOT PUBLISHED YET"));
    }

    /// `deactivated` cannot become `active` by waiting, so this is the one
    /// status shape that is refused outright -- the same reasoning as a
    /// delegated zone, and the refusal lands before the disk is erased.
    #[test]
    fn a_zone_cloudflare_will_never_serve_is_refused_before_anything_is_erased() {
        let fake = fake_with_zone_status(serde_json::json!([]), "deactivated");
        let a = answers(&["plex"]);
        let err = dry_run("thesyms.ca", &a, a.dns.as_ref().unwrap(), &against(&fake))
            .expect_err("a deactivated zone publishes nothing");
        let message = err.to_string();
        assert!(matches!(err, GateError::ZoneNotServing { .. }), "{message}");
        assert!(message.contains("deactivated"), "{message}");
        assert!(message.contains("Nothing has been changed"), "{message}");
        assert!(
            message.contains("not one hostname would answer"),
            "{message}"
        );
        assert!(!message.contains(TEST_TOKEN), "never the token itself");
    }

    /// The other half of D-11's distinction: a listing that succeeded and
    /// found nothing to do says so in words, so it cannot be read as the
    /// failure above.
    #[test]
    fn a_genuinely_empty_plan_says_so_rather_than_printing_nothing() {
        let plan = DryRun {
            base_domain: "thesyms.ca".to_string(),
            zone_name: "thesyms.ca".to_string(),
            target: "A 203.0.113.7".to_string(),
            actions: Vec::new(),
            zone_not_serving_yet: None,
            auth_enabled: true,
        };
        let rendered = render(&plan);
        assert!(rendered.contains("nothing to change"), "{rendered}");
        assert!(rendered.contains("not a listing that failed"), "{rendered}");
    }

    /// A3's decision, at the gate, before anything is erased.
    #[test]
    fn declining_a_foreign_name_records_it_as_an_app_that_will_not_be_reachable() {
        let fake = fake_with(serde_json::json!([record(
            "r2",
            "plex.thesyms.ca",
            "198.51.100.9",
            false
        )]));
        let a = answers(&["plex"]);
        let mut io = Scripted::new(&[""]);

        let outcome = gate(&a, &against(&fake), &mut io)
            .expect("the gate runs")
            .adoption;

        assert_eq!(
            outcome.declined,
            vec![ForeignName {
                name: "plex.thesyms.ca".to_string(),
                current: "198.51.100.9".to_string(),
                wanted: "203.0.113.7".to_string(),
            }]
        );
        assert!(outcome.adopted.is_empty());

        let report = report_lines(&outcome).join("\n");
        assert!(report.contains("NOT reachable"), "{report}");
        assert!(report.contains("plex.thesyms.ca"), "{report}");
        assert!(report.contains("198.51.100.9"), "{report}");
    }

    /// Adoption is explicit, and only the exact word does it: a name the
    /// operator deliberately points elsewhere must not be handed over by a
    /// reflexive "y".
    #[test]
    fn adoption_takes_the_word_and_nothing_else() {
        for (answer, adopted) in [("adopt", true), ("ADOPT", true), ("y", false), ("", false)] {
            let fake = fake_with(serde_json::json!([record(
                "r2",
                "plex.thesyms.ca",
                "198.51.100.9",
                false
            )]));
            let a = answers(&["plex"]);
            let mut io = Scripted::new(&[answer]);
            let outcome = gate(&a, &against(&fake), &mut io).unwrap().adoption;
            assert_eq!(outcome.adopted.is_empty(), !adopted, "answer {answer:?}");
            assert_eq!(outcome.declined.is_empty(), adopted, "answer {answer:?}");
        }
    }

    /// The gate must ask nothing when nothing is contested -- an install
    /// with a clean zone is not a conversation. The caveats still reach the
    /// operator.
    #[test]
    fn a_zone_with_no_foreign_names_asks_the_operator_nothing() {
        let fake = fake_with(serde_json::json!([]));
        let a = answers(&["plex"]);
        let mut io = Scripted::new(&[]);

        let outcome = gate(&a, &against(&fake), &mut io)
            .expect("no question to ask")
            .adoption;
        assert_eq!(outcome, Adoption::none());
        assert!(io.asked.is_empty(), "{:?}", io.asked);
        assert!(
            io.transcript().contains(SPLIT_HORIZON_CAVEAT),
            "the caveat still reaches the operator"
        );
    }

    /// A host with no base domain publishes nothing, so there is no zone to
    /// plan and no question to ask -- and no Cloudflare call to make, which
    /// is what makes passing the production factory safe here.
    #[test]
    fn a_host_with_no_base_domain_has_no_dns_gate() {
        let mut a = answers(&["plex"]);
        a.base_domain = None;
        a.dns = None;
        let mut io = Scripted::new(&[]);
        assert_eq!(
            gate(&a, &crate::answers::cloudflare_client, &mut io).unwrap(),
            GateOutcome::none()
        );
        assert!(io.asked.is_empty());
        assert!(io.said.is_empty());
    }

    /// The report says nothing at all when every wanted name was ferrum's
    /// to take.
    #[test]
    fn nothing_is_reported_when_nothing_was_contested() {
        assert!(report_lines(&Adoption::none()).is_empty());
    }
}
