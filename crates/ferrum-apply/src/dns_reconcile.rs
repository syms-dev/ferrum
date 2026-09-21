//! The on-host half of R1: making the DNS records ferrum publishes actually
//! exist.
//!
//! `modules/proxy/dns.nix` decides *which* names should exist and *what*
//! they point at, and bakes that decision into the closure as
//! `/etc/ferrum-dns-config.json`. `crates/ferrum-dns` owns every Cloudflare
//! call and the ownership guards. This module is the thin layer between
//! them: read the document, get a credential, drive
//! [`ferrum_dns::record::plan`], execute the plan, prove the result, and
//! report per record.
//!
//! **Why this runs inside `ferrum-apply apply` rather than as its own
//! systemd unit (decision D-08).** `crate::apply::classify` already turns
//! the switch's exit code and `all_managed_units_active()` into one verdict.
//! A separate unit would be absorbed by that boolean, and a DNS failure
//! would reach the operator as "one or more managed units failed to become
//! active" with no record, no operation, and no cause. So reconciliation is
//! a plain function call after the switch and the health check, and its
//! per-record breakdown is folded into the same [`crate::apply::ApplyResult`]
//! the switch already produces.
//!
//! **What counts as a failure, and what deliberately does not.** D-08 names
//! the failing set exactly: a create, update or delete error, or a
//! post-write verification that did not match. Those degrade the apply.
//! [`ferrum_dns::record::RecordAction::SkipForeign`] and
//! [`ferrum_dns::record::RecordAction::Unchanged`] are *planned* outcomes,
//! not failures -- A3's whole point is that a record ferrum does not own is
//! reported and left alone -- so they appear in the report and never degrade
//! the result. `crate::apply::classify`'s own history is the argument for
//! that line: five consecutive applies on a healthy host said "degraded"
//! about a service that had already fixed itself, and a warning that is
//! usually wrong is how a real one gets ignored. An operator who declined to
//! adopt a foreign record would otherwise see every future apply degrade
//! forever.
//!
//! **The credential is not a bare token (decision D-11 / finding UF-07).**
//! `/run/secrets/acme-dns` is a systemd `EnvironmentFile=`, so its content
//! is the literal line `CLOUDFLARE_DNS_API_TOKEN=<value>`.
//! `crates/ferrum-reconcile/src/main.rs`'s `read_api_key` -- which returns a
//! secret file's trimmed content verbatim -- is the wrong function for this
//! one secret: it would send `CLOUDFLARE_DNS_API_TOKEN=abc123` as the bearer
//! token. [`read_token`] strips the prefix and **refuses** without it.
//!
//! **An unusable credential is an error, never an empty plan.** This is the
//! failure that cost a live attempt: a missing file left the token empty,
//! every request went out unauthenticated, Cloudflare answered with nothing
//! useful, and the run read exactly like "there is nothing to do". Silence
//! and success are indistinguishable from outside, so every unusable shape
//! -- missing, unreadable, empty, whitespace-only, prefix-less, or a prefix
//! with no value after it -- names the path and what was wrong and stops.
//!
//! **Nothing here may log the token.** It travels from [`read_token`] into
//! [`ferrum_dns::Secret`] and out again only in
//! `crates/ferrum-dns/src/client.rs`'s `Authorization` header. No error
//! variant below carries it, no progress event carries it, and it never
//! reaches argv: the subcommand takes a config path, not a credential.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ferrum_dns::client::Client;
use ferrum_dns::dns_query::Verification;
use ferrum_dns::record::{DesiredRecord, RecordAction};
use ferrum_dns::{CloudflareError, RecordTarget, Secret, Zone};
use serde::Deserialize;

/// The `EnvironmentFile=` key the Cloudflare token is stored under.
///
/// Written by `crates/ferrum-install/src/stage2.rs`'s `acme_payload` and
/// consumed by lego through systemd. Kept as a constant because the
/// stripping below and the error that reports its absence must name the same
/// string.
const TOKEN_ENV_KEY: &str = "CLOUDFLARE_DNS_API_TOKEN=";

/// Where the closure keeps the desired-record document, relative to a
/// system toplevel.
///
/// `modules/proxy/dns.nix` puts the same file at both
/// `{toplevel}/etc/ferrum-dns-config.json` and `/etc/ferrum-dns-config.json`
/// precisely so an apply can read the *newly built* closure's document
/// without waiting for the switch to publish it to `/etc`.
const CONFIG_IN_CLOSURE: &str = "etc/ferrum-dns-config.json";

/// The desired-record document `modules/proxy/dns.nix` emits.
///
/// Field names follow that file's `builtins.toJSON` output exactly. Unknown
/// fields are ignored rather than rejected so a document written by a newer
/// module tree still parses on an older binary -- the reverse (a field this
/// binary needs going missing) is caught by serde as a hard parse error,
/// which is the direction that must fail loudly.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    /// Whether this host manages DNS at all. False on a host with the proxy
    /// off or `ferrum.proxy.dns.enable = false`; the document is still
    /// emitted so a consumer always has one file to read.
    pub enable: bool,
    /// `ferrum.proxy.baseDomain`, the domain every record name derives from.
    #[serde(rename = "baseDomain")]
    pub base_domain: String,
    /// Every name that should exist, already sorted by `dns.nix`.
    pub records: Vec<ConfiguredRecord>,
    /// Where all of them point (A2) -- one target for one box.
    pub target: ConfiguredTarget,
    /// The decrypted sops path holding the Cloudflare credential, or `null`
    /// on a host that declares none.
    #[serde(rename = "credentialFile")]
    pub credential_file: Option<PathBuf>,
    /// The scheduled-updater block.
    #[serde(rename = "ddnsUpdater")]
    pub ddns_updater: DdnsUpdater,
}

/// One name `dns.nix` wants a record for.
///
/// The document also carries `source` (`app:<id>`, `auth`, `daemon`) and a
/// per-record `proxied`. Neither is read here, deliberately: `source` is
/// there so a human can read the generated JSON, and the record *name* is
/// what an operator looks up when a report names it, while `proxied` states
/// an invariant `ferrum_dns::record::RecordWrite` already enforces on every
/// write. Deserializing them into fields nothing consults would be two more
/// places for the document and this binary to drift apart.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfiguredRecord {
    /// The fully qualified record name, e.g. `auth.example.com`.
    pub name: String,
}

/// A8's scheduled updater, as configured.
#[derive(Debug, Clone, Deserialize)]
pub struct DdnsUpdater {
    /// Whether `ferrum-dns-updater.timer` exists on this host. Not a gate on
    /// anything here -- a manual `ferrum-apply reconcile-dns` must work
    /// whatever the schedule says -- but it is reported, because "records
    /// were correct once" and "records are being re-checked" are different
    /// facts and only the second one survives a changed address.
    pub enable: bool,
}

/// Where every record points (A2).
///
/// Tagged by `dns.nix`'s own `mode` field. The payload is a string rather
/// than a parsed address because a host with DNS management *off* legally
/// carries the empty defaults from `modules/core/options.nix`; parsing is
/// deferred to [`ConfiguredTarget::resolve`], which only runs once
/// reconciliation is actually going to happen.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum ConfiguredTarget {
    /// `recordMode = "a"`: a stated public IPv4 address.
    A {
        /// `ferrum.proxy.dns.staticAddress`.
        address: String,
    },
    /// `recordMode = "cname"`: a stated hostname the records follow.
    Cname {
        /// `ferrum.proxy.dns.cnameTarget`.
        hostname: String,
    },
}

impl ConfiguredTarget {
    /// Turns the configured target into the one `ferrum-dns` writes.
    ///
    /// # Returns
    /// The [`RecordTarget`] every desired record will point at.
    ///
    /// # Errors
    /// [`ReconcileError::Target`] when the address is not a valid IPv4
    /// address or either field is empty. `dns.nix` asserts both at
    /// evaluation time, so reaching this is a document that did not come
    /// from that module -- which is exactly when guessing would publish
    /// every app at somewhere that is not this server.
    pub fn resolve(&self) -> Result<RecordTarget, ReconcileError> {
        match self {
            ConfiguredTarget::A { address } => {
                address
                    .trim()
                    .parse()
                    .map(RecordTarget::A)
                    .map_err(|_| ReconcileError::Target {
                        detail: format!(
                        "recordMode is \"a\" but staticAddress ({address:?}) is not an IPv4 address"
                    ),
                    })
            }
            ConfiguredTarget::Cname { hostname } if hostname.trim().is_empty() => {
                Err(ReconcileError::Target {
                    detail: "recordMode is \"cname\" but cnameTarget is empty".to_string(),
                })
            }
            ConfiguredTarget::Cname { hostname } => {
                Ok(RecordTarget::Cname(hostname.trim().to_string()))
            }
        }
    }
}

/// Why the credential could not be used.
///
/// Every variant names the path and what was wrong with it, and none of them
/// carries the file's content: a credential file that is *almost* right is
/// the case where an error message is most tempted to quote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// The file could not be read at all -- absent, or unreadable by this
    /// process.
    Unreadable {
        /// The path that was tried.
        path: PathBuf,
        /// The I/O error's own message.
        detail: String,
    },
    /// The file exists but holds nothing usable.
    Empty {
        /// The path that was read.
        path: PathBuf,
    },
    /// No line carries the `CLOUDFLARE_DNS_API_TOKEN=` key, so there is no
    /// token to extract. Sending the content as-is would put the key name
    /// into the `Authorization` header and every call would be refused.
    MissingPrefix {
        /// The path that was read.
        path: PathBuf,
    },
    /// The key is there with nothing after it.
    NoValue {
        /// The path that was read.
        path: PathBuf,
    },
}

impl fmt::Display for CredentialError {
    /// Renders the failure for an operator, naming the path and the
    /// remedy. Never renders any part of the file's content.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::Unreadable { path, detail } => write!(
                f,
                "could not read the Cloudflare credential at {}: {detail}",
                path.display()
            ),
            CredentialError::Empty { path } => write!(
                f,
                "the Cloudflare credential at {} is empty -- DNS records \
                 cannot be managed without it, and an unauthenticated call \
                 looks identical to a zone with nothing in it",
                path.display()
            ),
            CredentialError::MissingPrefix { path } => write!(
                f,
                "the Cloudflare credential at {} carries no {TOKEN_ENV_KEY} \
                 line. That file is a systemd EnvironmentFile, so the token \
                 is the part after that key; refusing rather than sending \
                 the whole line as a token",
                path.display()
            ),
            CredentialError::NoValue { path } => write!(
                f,
                "the Cloudflare credential at {} has {TOKEN_ENV_KEY} with no \
                 value after it",
                path.display()
            ),
        }
    }
}

impl std::error::Error for CredentialError {}

/// Why a whole reconcile run could not produce a per-record verdict.
///
/// Distinct from a per-record failure: these are the failures that stop the
/// run before any record has an outcome at all, so there is nothing to break
/// down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileError {
    /// The desired-record document could not be read or parsed.
    Config {
        /// The path that was tried.
        path: PathBuf,
        /// What went wrong reading or parsing it.
        detail: String,
    },
    /// `enable` is true but `credentialFile` is `null`. `dns.nix` asserts
    /// against this at evaluation time; reaching it means the document did
    /// not come from that module.
    NoCredentialConfigured,
    /// The credential was configured but unusable.
    Credential(CredentialError),
    /// The configured target cannot be turned into a record.
    Target {
        /// What was wrong with it.
        detail: String,
    },
    /// Cloudflare refused, or could not be reached, before any record was
    /// touched -- zone resolution or the listing itself.
    Cloudflare(CloudflareError),
}

impl fmt::Display for ReconcileError {
    /// Renders the failure for an operator. Carries no credential material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReconcileError::Config { path, detail } => write!(
                f,
                "could not read the DNS record document at {}: {detail}",
                path.display()
            ),
            ReconcileError::NoCredentialConfigured => f.write_str(
                "DNS record management is enabled but no Cloudflare credential \
                 is declared -- add the acme-dns secret to ferrum.secrets and \
                 re-apply",
            ),
            ReconcileError::Credential(inner) => write!(f, "{inner}"),
            ReconcileError::Target { detail } => {
                write!(f, "the DNS record target is unusable: {detail}")
            }
            ReconcileError::Cloudflare(inner) => write!(f, "{inner}"),
        }
    }
}

impl std::error::Error for ReconcileError {}

impl From<CredentialError> for ReconcileError {
    /// Lifts a credential failure into the run-level error.
    fn from(value: CredentialError) -> Self {
        ReconcileError::Credential(value)
    }
}

impl From<CloudflareError> for ReconcileError {
    /// Lifts a pre-record Cloudflare failure into the run-level error.
    fn from(value: CloudflareError) -> Self {
        ReconcileError::Cloudflare(value)
    }
}

/// What reconciliation did to one name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// The record did not exist and was created.
    Create,
    /// A ferrum-owned record existed and was corrected.
    Update,
    /// A ferrum-owned record already matched; nothing was called.
    Unchanged,
    /// A ferrum-owned record for a name nothing wants any more was removed.
    Delete,
    /// A record ferrum does not own occupies the name (A3). Reported, never
    /// written to.
    SkipForeign,
}

impl Operation {
    /// The word the per-record breakdown uses for this operation.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Operation::Create => "create",
            Operation::Update => "update",
            Operation::Unchanged => "unchanged",
            Operation::Delete => "delete",
            Operation::SkipForeign => "skip (not ferrum's)",
        }
    }
}

/// One name's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordReport {
    /// The fully qualified record name.
    pub name: String,
    /// What was attempted.
    pub operation: Operation,
    /// `None` when it worked; otherwise why it did not. A `Some` here is
    /// what degrades the apply (D-08).
    pub failure: Option<String>,
    /// A non-failing remark, e.g. what a foreign record points at today.
    pub note: Option<String>,
}

impl fmt::Display for RecordReport {
    /// One line of the per-record breakdown: which record, which operation,
    /// and why.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.operation.label())?;
        match (&self.failure, &self.note) {
            (Some(why), _) => write!(f, ": {why}"),
            (None, Some(note)) => write!(f, ": {note}"),
            (None, None) => Ok(()),
        }
    }
}

/// Every name's outcome from one reconcile run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileReport {
    /// One entry per desired name, plus one per record removed, in plan
    /// order.
    pub records: Vec<RecordReport>,
    /// Whether the scheduled updater is configured on this host, carried so
    /// a manual run can say whether anything will re-check this later.
    pub scheduled: bool,
}

impl ReconcileReport {
    /// Whether every record ended as intended.
    ///
    /// # Returns
    /// `true` when no entry carries a failure. A skipped foreign record and
    /// an unchanged record are both clean outcomes -- see this module's
    /// header for why they must not degrade an apply.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.records.iter().all(|r| r.failure.is_none())
    }

    /// The per-record breakdown D-08 requires, or `None` when nothing
    /// failed.
    ///
    /// # Returns
    /// A sentence naming every failed record, its operation and its cause.
    /// Only failures appear: the reason string is appended to an
    /// `ApplyResult` an operator reads on a terminal, and burying two real
    /// failures among fourteen successes is how they get missed.
    #[must_use]
    pub fn failure_summary(&self) -> Option<String> {
        if self.is_clean() {
            return None;
        }
        let failed: Vec<String> = self
            .records
            .iter()
            .filter(|r| r.failure.is_some())
            .map(ToString::to_string)
            .collect();
        Some(format!(
            "{} of {} DNS record(s) could not be reconciled: {}",
            failed.len(),
            self.records.len(),
            failed.join("; ")
        ))
    }

    /// Every entry, one per line, for a human running the subcommand.
    #[must_use]
    pub fn full_summary(&self) -> String {
        if self.records.is_empty() {
            return "no DNS records are configured for this host".to_string();
        }
        self.records
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Builds a `ferrum-dns` client for the real Cloudflare API.
///
/// # Arguments
/// * `token` - the bare token, prefix already stripped by [`read_token`].
#[must_use]
pub fn cloudflare_client(token: Secret) -> Client {
    Client::new(token)
}

/// How the caller supplies a client. Production passes
/// [`cloudflare_client`]; tests pass one pointed at
/// `ferrum_dns::testing::FakeCloudflare`, because the sandbox that runs the
/// suite has no network and must never reach Cloudflare.
pub type ClientFactory<'a> = &'a dyn Fn(Secret) -> Client;

/// How a written record is proved to resolve. Production passes
/// [`Client::verify_authoritative`]; tests substitute it, because the real
/// one shells out to `dig` against public nameservers.
pub type Verifier<'a> = &'a dyn Fn(&Client, &Zone, &str, &RecordTarget) -> Verification;

/// The production verifier: ask the zone's own authoritative nameservers
/// (decision D-07).
///
/// # Arguments
/// * `client` - the client the zone came from.
/// * `zone` - carries the nameservers to ask.
/// * `name` - the record just written.
/// * `target` - what it was written with.
#[must_use]
pub fn authoritative_verifier(
    client: &Client,
    zone: &Zone,
    name: &str,
    target: &RecordTarget,
) -> Verification {
    client.verify_authoritative(zone, name, target)
}

/// Reads the Cloudflare token out of its systemd `EnvironmentFile` (decision
/// D-11).
///
/// # Arguments
/// * `path` - the decrypted secret, normally `/run/secrets/acme-dns`.
///
/// # Returns
/// The bare token, with the `CLOUDFLARE_DNS_API_TOKEN=` key and any
/// surrounding whitespace removed. `crates/ferrum-apply/src/put_secret.rs`
/// deliberately writes the operator's value byte-for-byte -- including
/// padding -- because systemd needs the line intact, so trimming is this
/// reader's job rather than the writer's.
///
/// # Errors
/// [`CredentialError`] for every unusable shape: missing, unreadable,
/// empty, whitespace-only, carrying no `CLOUDFLARE_DNS_API_TOKEN=` line, or
/// carrying one with nothing after it. None of these degrades into an empty
/// token: an unauthenticated Cloudflare call returns nothing, and nothing is
/// indistinguishable from a zone that needs no work.
pub fn read_token(path: &Path) -> Result<Secret, CredentialError> {
    let raw = fs::read_to_string(path).map_err(|e| CredentialError::Unreadable {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    if raw.trim().is_empty() {
        return Err(CredentialError::Empty {
            path: path.to_path_buf(),
        });
    }
    let value = raw
        .lines()
        .find_map(|line| line.trim_start().strip_prefix(TOKEN_ENV_KEY))
        .ok_or_else(|| CredentialError::MissingPrefix {
            path: path.to_path_buf(),
        })?
        .trim();
    if value.is_empty() {
        return Err(CredentialError::NoValue {
            path: path.to_path_buf(),
        });
    }
    Ok(Secret::new(value.to_string()))
}

/// Reads and parses the desired-record document.
///
/// # Arguments
/// * `path` - `/etc/ferrum-dns-config.json`, or the same file inside a
///   freshly built closure.
///
/// # Errors
/// [`ReconcileError::Config`] when the file cannot be read or is not the
/// shape `modules/proxy/dns.nix` emits.
pub fn load_config(path: &Path) -> Result<DnsConfig, ReconcileError> {
    let raw = fs::read_to_string(path).map_err(|e| ReconcileError::Config {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    serde_json::from_str(&raw).map_err(|e| ReconcileError::Config {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })
}

/// Reconciles the zone against the document.
///
/// The plan comes from [`ferrum_dns::record::plan`] against a live listing,
/// so a second run over an unchanged zone issues no writes and a run after a
/// partial failure completes only what is missing. Records ferrum does not
/// own are never written to or deleted -- not by policy here, but because
/// `plan` mints no [`ferrum_dns::ownership::ManagedRecordId`] for them, and
/// the client's write and delete methods accept nothing else.
///
/// # Arguments
/// * `config` - the desired-record document.
/// * `client` - the Cloudflare client.
/// * `verify` - how to prove a written record resolves (D-07).
///
/// # Returns
/// One [`RecordReport`] per planned action.
///
/// # Errors
/// [`ReconcileError`] when the run could not start at all: an unusable
/// target, or a zone resolution or listing that failed. A failure that
/// affects only some records is not an error here -- it is a per-record
/// entry, because a partial result must be reported record by record rather
/// than collapsed into one cause.
pub fn reconcile_with(
    config: &DnsConfig,
    client: &Client,
    verify: Verifier<'_>,
) -> Result<ReconcileReport, ReconcileError> {
    let target = config.target.resolve()?;
    let desired: Vec<DesiredRecord> = config
        .records
        .iter()
        .map(|r| DesiredRecord {
            name: r.name.clone(),
            target: target.clone(),
        })
        .collect();

    let zone = client.resolve_zone(&config.base_domain)?;
    let actions = client.plan_records(&zone, &desired)?;

    let records = actions
        .into_iter()
        .map(|action| execute(client, &zone, verify, action))
        .collect();

    Ok(ReconcileReport {
        records,
        scheduled: config.ddns_updater.enable,
    })
}

/// Performs one planned action and reports what happened.
///
/// A create or an update is followed by D-07's proof that the zone's own
/// nameservers answer with what was just written: Cloudflare accepting a
/// write only proves Cloudflare accepted it, and the incident R1 exists to
/// fix is a name that never resolved while the install reported success.
/// A delete is not verified -- proving an absence is a different question,
/// and D-07 scopes the check to records just written.
fn execute(
    client: &Client,
    zone: &Zone,
    verify: Verifier<'_>,
    action: RecordAction,
) -> RecordReport {
    match action {
        RecordAction::Create { name, target } => match client.create_record(zone, &name, &target) {
            Ok(_) => verified(client, zone, verify, name, Operation::Create, &target),
            Err(e) => failed(name, Operation::Create, &e.to_string()),
        },
        RecordAction::Update {
            record_id,
            name,
            current,
            target,
        } => match client.update_record(zone, &record_id, &name, &target) {
            Ok(_) => {
                let mut report = verified(client, zone, verify, name, Operation::Update, &target);
                if report.failure.is_none() {
                    report.note = Some(format!("was {current}, now {target}"));
                }
                report
            }
            Err(e) => failed(name, Operation::Update, &e.to_string()),
        },
        RecordAction::Unchanged { name, .. } => RecordReport {
            name,
            operation: Operation::Unchanged,
            failure: None,
            note: None,
        },
        RecordAction::Delete { record_id, name } => match client.delete_record(zone, &record_id) {
            Ok(()) => RecordReport {
                name,
                operation: Operation::Delete,
                failure: None,
                note: Some("no longer published by this host".to_string()),
            },
            Err(e) => failed(name, Operation::Delete, &e.to_string()),
        },
        // A3. Not a failure: see this module's header. The note is what the
        // operator needs -- their record, where it points, and what ferrum
        // wanted instead -- so adopting it stays their explicit decision.
        RecordAction::SkipForeign {
            name,
            current,
            wanted,
        } => RecordReport {
            name,
            operation: Operation::SkipForeign,
            failure: None,
            note: Some(format!(
                "left alone: it points at {current} and ferrum did not create it \
                 (ferrum would have pointed it at {wanted})"
            )),
        },
    }
}

/// Runs D-07's post-write proof and turns it into a report entry.
///
/// Both non-matching verdicts degrade the apply, and both must say which one
/// they are: telling an operator their DNS is wrong when a nameserver merely
/// timed out sends them to fix a zone that is already correct.
/// [`Verification`]'s own `Display` carries that distinction, so the two
/// sentences cannot drift apart here.
fn verified(
    client: &Client,
    zone: &Zone,
    verify: Verifier<'_>,
    name: String,
    operation: Operation,
    target: &RecordTarget,
) -> RecordReport {
    match verify(client, zone, &name, target) {
        Verification::Matched => RecordReport {
            name,
            operation,
            failure: None,
            note: None,
        },
        outcome => failed(name, operation, &format!("written, but it {outcome}")),
    }
}

/// A failed entry, so every construction site words it the same way.
fn failed(name: String, operation: Operation, why: &str) -> RecordReport {
    RecordReport {
        name,
        operation,
        failure: Some(why.to_string()),
        note: None,
    }
}

/// Reads the document, gets a credential, and reconciles.
///
/// # Arguments
/// * `config_path` - the desired-record document.
/// * `make_client` - how to build the Cloudflare client.
/// * `verify` - how to prove a written record resolves.
///
/// # Returns
/// `None` when `enable` is false -- that host does not manage DNS, and the
/// document exists precisely so a consumer can read it and say so. Otherwise
/// the report.
///
/// # Errors
/// [`ReconcileError`] for every other stopping condition. In particular an
/// unusable credential is an error here and never an empty report: those two
/// look identical from outside, and the second one is what a live attempt
/// actually produced.
pub fn run(
    config_path: &Path,
    make_client: ClientFactory<'_>,
    verify: Verifier<'_>,
) -> Result<Option<ReconcileReport>, ReconcileError> {
    let config = load_config(config_path)?;
    if !config.enable {
        return Ok(None);
    }
    let credential_file = config
        .credential_file
        .as_deref()
        .ok_or(ReconcileError::NoCredentialConfigured)?;
    let client = make_client(read_token(credential_file)?);
    reconcile_with(&config, &client, verify).map(Some)
}

/// Reconciles as a step inside `ferrum-apply apply` (decision D-08).
///
/// # Arguments
/// * `toplevel` - the system closure being applied; the document is read
///   from inside it, so the records reconciled are the ones the closure just
///   activated rather than the ones the previous generation wanted.
/// * `progress` - the job stream, for the operator watching an apply.
///
/// # Returns
/// `None` when there is nothing to report, and `Some(reason)` when the apply
/// must be degraded. Deliberately not a `Result`: a switch that succeeded
/// must not turn into an apply *error* because Cloudflare was unreachable.
/// The failure is reported through the verdict the operator already reads.
///
/// A closure with no document at all yields `None`: that means
/// `modules/proxy/dns.nix` is not in this system's module tree, which is a
/// host that never asked ferrum to manage DNS. A document that exists and
/// cannot be read is the opposite case and degrades the apply.
pub fn reconcile_for_apply(
    toplevel: &str,
    progress: &mut crate::progress::Progress,
) -> Option<String> {
    let path = Path::new(toplevel).join(CONFIG_IN_CLOSURE);
    if !path.exists() {
        return None;
    }
    progress.event("dns", "reconciling the DNS records for published apps");
    match run(&path, &cloudflare_client, &authoritative_verifier) {
        Ok(None) => None,
        Ok(Some(report)) => report.failure_summary(),
        Err(e) => Some(format!("DNS records could not be reconciled: {e}")),
    }
}

/// Records that a reconcile cycle completed cleanly (A8).
///
/// The updater's own failure mode is the one A8's rationale describes for
/// the records themselves: a timer erroring silently for six weeks looks,
/// from outside, exactly like one that has never needed to do anything. The
/// age of this file is the difference.
///
/// # Arguments
/// * `path` - normally `/var/lib/ferrum/state/dns-updater-last-success`.
/// * `at` - when the cycle finished.
///
/// # Errors
/// Any I/O error creating the parent directory or writing the file.
pub fn record_last_success(path: &Path, at: SystemTime) -> std::io::Result<()> {
    let seconds = at
        .duration_since(UNIX_EPOCH)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
        .as_secs();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{seconds}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_dns::testing::{CannedResponse, FakeCloudflare, Route, TEST_TOKEN};
    use std::net::Ipv4Addr;

    const HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

    fn config_json(records: &[(&str, &str)], enable: bool) -> String {
        let records: Vec<serde_json::Value> = records
            .iter()
            .map(|(name, source)| serde_json::json!({ "name": name, "source": source, "proxied": false }))
            .collect();
        serde_json::json!({
            "enable": enable,
            "baseDomain": "example.com",
            "records": records,
            "target": { "mode": "a", "address": "203.0.113.7" },
            "credentialFile": "/run/secrets/acme-dns",
            "ddnsUpdater": { "enable": true, "intervalMinutes": 30 },
        })
        .to_string()
    }

    fn parsed(records: &[(&str, &str)]) -> DnsConfig {
        serde_json::from_str(&config_json(records, true)).expect("the document parses")
    }

    /// A fake holding `example.com`, with `existing` already in it.
    ///
    /// Scripts the two record listings `resolve_zone` + `plan_records` make
    /// against the same route, in the order the client issues them: the `NS`
    /// delegation check first, then the real listing.
    fn fake_zone(existing: serde_json::Value) -> FakeCloudflare {
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
            CannedResponse::ok(serde_json::json!([])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(existing),
        );
        fake
    }

    fn record_json(id: &str, name: &str, addr: &str, owned: bool) -> serde_json::Value {
        let mut value = serde_json::json!({
            "id": id,
            "name": name,
            "type": "A",
            "content": addr,
            "proxied": false,
        });
        if owned {
            value["comment"] = serde_json::json!(ferrum_dns::OWNERSHIP_MARKER);
        }
        value
    }

    fn client_for(fake: &FakeCloudflare) -> Client {
        Client::with_base_url(
            Secret::new(TEST_TOKEN.to_string()),
            fake.base_url().to_string(),
        )
    }

    /// A verifier that always agrees, so a test exercises the reconcile
    /// logic rather than `dig` -- which the sandbox has no network for.
    fn always_matches(_: &Client, _: &Zone, _: &str, _: &RecordTarget) -> Verification {
        Verification::Matched
    }

    fn write_credential(dir: &tempfile::TempDir, content: &str) -> PathBuf {
        let path = dir.path().join("acme-dns");
        fs::write(&path, content).expect("write the fixture credential");
        path
    }

    // ---- the document ---------------------------------------------------

    #[test]
    fn the_document_modules_proxy_dns_nix_emits_parses() {
        let config = parsed(&[
            ("auth.example.com", "auth"),
            ("plex.example.com", "app:plex"),
        ]);
        assert!(config.enable);
        assert_eq!(config.base_domain, "example.com");
        assert_eq!(config.records.len(), 2);
        assert_eq!(config.records[1].name, "plex.example.com");
        assert_eq!(
            config.credential_file.as_deref(),
            Some(Path::new("/run/secrets/acme-dns"))
        );
        assert!(config.ddns_updater.enable);
        assert_eq!(config.target.resolve().unwrap(), RecordTarget::A(HOST));
    }

    #[test]
    fn a_cname_document_resolves_to_a_cname_target() {
        let config: DnsConfig = serde_json::from_str(
            &serde_json::json!({
                "enable": true,
                "baseDomain": "example.com",
                "records": [],
                "target": { "mode": "cname", "hostname": "box.dyn.example.net" },
                "credentialFile": null,
                "ddnsUpdater": { "enable": false, "intervalMinutes": 30 },
            })
            .to_string(),
        )
        .expect("a cname document parses");
        assert_eq!(
            config.target.resolve().unwrap(),
            RecordTarget::Cname("box.dyn.example.net".to_string())
        );
        assert!(config.credential_file.is_none());
    }

    /// A host with DNS management off carries `options.nix`'s empty
    /// defaults, so parsing must not demand a usable target -- only
    /// reconciling does.
    #[test]
    fn a_disabled_document_with_empty_defaults_still_parses_and_then_refuses_to_reconcile() {
        let config: DnsConfig = serde_json::from_str(
            &serde_json::json!({
                "enable": false,
                "baseDomain": "",
                "records": [],
                "target": { "mode": "a", "address": "" },
                "credentialFile": null,
                "ddnsUpdater": { "enable": false, "intervalMinutes": 30 },
            })
            .to_string(),
        )
        .expect("a disabled document parses");
        assert!(matches!(
            config.target.resolve(),
            Err(ReconcileError::Target { .. })
        ));
    }

    #[test]
    fn a_disabled_host_reconciles_nothing_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ferrum-dns-config.json");
        fs::write(&path, config_json(&[("auth.example.com", "auth")], false)).unwrap();
        let fake = FakeCloudflare::start();
        let outcome = run(&path, &|_| client_for(&fake), &always_matches)
            .expect("a disabled host is not an error");
        assert_eq!(outcome, None);
        assert!(
            fake.requests().is_empty(),
            "a disabled host must make no Cloudflare call at all"
        );
    }

    #[test]
    fn an_unreadable_document_is_an_error_naming_the_path() {
        let err = load_config(Path::new("/nonexistent/ferrum-dns-config.json"))
            .expect_err("a missing document must not be read as 'nothing to do'");
        assert!(err.to_string().contains("/nonexistent/"), "{err}");
    }

    // ---- the credential (decision D-11) ---------------------------------

    #[test]
    fn the_token_is_the_part_after_the_environment_file_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_credential(&dir, "CLOUDFLARE_DNS_API_TOKEN=abc123\n");
        assert_eq!(read_token(&path).unwrap().expose(), "abc123");
    }

    /// `put_secret` writes the operator's value byte-for-byte, padding
    /// included, because systemd needs the line intact. Trimming is this
    /// reader's job.
    #[test]
    fn surrounding_whitespace_is_stripped_from_the_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_credential(&dir, "CLOUDFLARE_DNS_API_TOKEN=  abc123  \n");
        assert_eq!(read_token(&path).unwrap().expose(), "abc123");
    }

    /// UF-07, the whole reason `ferrum-reconcile`'s `read_api_key` is the
    /// wrong function for this secret.
    ///
    /// Mutation check: return the file's trimmed content when the key is
    /// absent (what `read_api_key` does) and this test fails.
    #[test]
    fn a_bare_token_with_no_key_is_refused_rather_than_sent_as_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_credential(&dir, "abc123\n");
        let err = read_token(&path).expect_err("a prefix-less file must be refused");
        assert_eq!(err, CredentialError::MissingPrefix { path: path.clone() });
        let rendered = err.to_string();
        assert!(rendered.contains(&path.display().to_string()), "{rendered}");
        assert!(rendered.contains("CLOUDFLARE_DNS_API_TOKEN="), "{rendered}");
        assert!(
            !rendered.contains("abc123"),
            "the error must not quote the file's content: {rendered}"
        );
    }

    /// The shape that produced the live failure: an empty credential meant
    /// every call went out unauthenticated and the run read as "nothing to
    /// do".
    ///
    /// Mutation check: fall back to an empty `Secret` on any of these and
    /// this test fails.
    #[test]
    fn every_unusable_credential_shape_is_an_error_naming_the_path() {
        let dir = tempfile::tempdir().unwrap();
        for (content, expected) in [
            ("", "empty"),
            ("   \n\t\n", "empty"),
            ("CLOUDFLARE_DNS_API_TOKEN=", "no value"),
            ("CLOUDFLARE_DNS_API_TOKEN=   \n", "no value"),
            ("CF_API_KEY=abc123\n", "missing prefix"),
            ("{\"token\": \"abc123\"}\n", "missing prefix"),
        ] {
            let path = write_credential(&dir, content);
            let err = read_token(&path)
                .expect_err(&format!("{content:?} ({expected}) must not yield a token"));
            assert!(
                err.to_string().contains(&path.display().to_string()),
                "{expected}: the error must name the path: {err}"
            );
            assert!(
                !err.to_string().contains("abc123"),
                "{expected}: the error must not quote the content: {err}"
            );
        }
    }

    #[test]
    fn a_missing_credential_file_is_an_error_naming_the_path() {
        let path = Path::new("/nonexistent/run/secrets/acme-dns");
        let err = read_token(path).expect_err("a missing credential must be refused");
        assert!(matches!(err, CredentialError::Unreadable { .. }));
        assert!(err.to_string().contains("/nonexistent/"), "{err}");
    }

    /// An unusable credential must stop the run, not produce a clean report
    /// with nothing in it -- the two are indistinguishable from outside and
    /// the second one is what a live attempt actually produced.
    ///
    /// Mutation check: make `run` skip reconciliation and return an empty
    /// report when the credential is unusable and this fails.
    #[test]
    fn an_unusable_credential_stops_the_run_instead_of_producing_an_empty_plan() {
        let dir = tempfile::tempdir().unwrap();
        let credential = write_credential(&dir, "not-an-environment-file\n");
        let config_path = dir.path().join("ferrum-dns-config.json");
        let mut document: serde_json::Value =
            serde_json::from_str(&config_json(&[("auth.example.com", "auth")], true)).unwrap();
        document["credentialFile"] = serde_json::json!(credential.display().to_string());
        fs::write(&config_path, document.to_string()).unwrap();

        let fake = fake_zone(serde_json::json!([]));
        let err = run(&config_path, &|_| client_for(&fake), &always_matches)
            .expect_err("an unusable credential must be an error, not an empty report");
        assert!(matches!(
            err,
            ReconcileError::Credential(CredentialError::MissingPrefix { .. })
        ));
        assert!(
            fake.requests().is_empty(),
            "nothing may be sent to Cloudflare without a usable token"
        );
    }

    #[test]
    fn an_enabled_host_with_no_credential_declared_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ferrum-dns-config.json");
        let mut document: serde_json::Value =
            serde_json::from_str(&config_json(&[("auth.example.com", "auth")], true)).unwrap();
        document["credentialFile"] = serde_json::Value::Null;
        fs::write(&path, document.to_string()).unwrap();
        let fake = FakeCloudflare::start();
        let err = run(&path, &|_| client_for(&fake), &always_matches)
            .expect_err("no credential is a refusal");
        assert_eq!(err, ReconcileError::NoCredentialConfigured);
    }

    // ---- reconciliation -------------------------------------------------

    #[test]
    fn a_missing_record_is_created_and_verified() {
        let fake = fake_zone(serde_json::json!([]));
        fake.script(
            Route::post("/zones/z1/dns_records"),
            CannedResponse::ok(record_json("r1", "auth.example.com", "203.0.113.7", true)),
        );
        let report = reconcile_with(
            &parsed(&[("auth.example.com", "auth")]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.records[0].operation, Operation::Create);
        assert_eq!(report.failure_summary(), None);

        let posted = fake.requests_for(&Route::post("/zones/z1/dns_records"));
        assert_eq!(posted.len(), 1);
        let body = posted[0].json_body().expect("a JSON body");
        assert_eq!(body["proxied"], serde_json::json!(false), "D-05");
        assert_eq!(
            body["comment"],
            serde_json::json!(ferrum_dns::OWNERSHIP_MARKER),
            "a record written without the marker can never be recognised again"
        );
    }

    /// A3, at the level this module is responsible for: a foreign record
    /// occupying a wanted name produces no write of any kind.
    ///
    /// Mutation check: see this test's sibling
    /// `a_foreign_record_is_never_deleted_when_it_is_no_longer_wanted`.
    #[test]
    fn a_foreign_record_is_never_updated() {
        let fake = fake_zone(serde_json::json!([record_json(
            "r1",
            "plex.example.com",
            "198.51.100.9",
            false
        )]));
        let report = reconcile_with(
            &parsed(&[("plex.example.com", "app:plex")]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert_eq!(report.records[0].operation, Operation::SkipForeign);
        assert!(
            report.is_clean(),
            "a declined adoption must not degrade every future apply: {report:?}"
        );
        let note = report.records[0].note.as_deref().expect("a note");
        assert!(note.contains("198.51.100.9"), "{note}");

        for method in ["POST", "PUT", "DELETE"] {
            assert!(
                fake.requests().iter().all(|r| r.method != method),
                "a foreign record must not be written to ({method})"
            );
        }
    }

    /// A4's other half: a ferrum-owned record for a name nothing wants is
    /// removed, and a foreign record beside it is not.
    #[test]
    fn a_foreign_record_is_never_deleted_when_it_is_no_longer_wanted() {
        let fake = fake_zone(serde_json::json!([
            record_json("mine", "old.example.com", "203.0.113.7", true),
            record_json("theirs", "mail.example.com", "198.51.100.9", false),
        ]));
        fake.script(
            Route::delete("/zones/z1/dns_records/mine"),
            CannedResponse::ok(serde_json::json!({ "id": "mine" })),
        );

        let report = reconcile_with(&parsed(&[]), &client_for(&fake), &always_matches)
            .expect("the run completes");

        assert_eq!(report.records.len(), 1, "only ferrum's record is acted on");
        assert_eq!(report.records[0].operation, Operation::Delete);
        assert_eq!(report.records[0].name, "old.example.com");
        assert!(
            fake.requests_for(&Route::delete("/zones/z1/dns_records/theirs"))
                .is_empty(),
            "the operator's record must survive"
        );
    }

    #[test]
    fn a_drifted_record_ferrum_owns_is_corrected() {
        let fake = fake_zone(serde_json::json!([record_json(
            "r1",
            "auth.example.com",
            "198.51.100.9",
            true
        )]));
        fake.script(
            Route::put("/zones/z1/dns_records/r1"),
            CannedResponse::ok(record_json("r1", "auth.example.com", "203.0.113.7", true)),
        );
        let report = reconcile_with(
            &parsed(&[("auth.example.com", "auth")]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert!(report.is_clean(), "{report:?}");
        assert_eq!(report.records[0].operation, Operation::Update);
        let note = report.records[0].note.as_deref().expect("a note");
        assert!(note.contains("198.51.100.9"), "{note}");
        assert!(note.contains("203.0.113.7"), "{note}");
    }

    /// Idempotence: a second run over a zone that already matches issues no
    /// write at all, which is what makes the DDNS timer safe to run every
    /// half hour.
    #[test]
    fn a_zone_that_already_matches_produces_no_writes() {
        let fake = fake_zone(serde_json::json!([record_json(
            "r1",
            "auth.example.com",
            "203.0.113.7",
            true
        )]));
        let report = reconcile_with(
            &parsed(&[("auth.example.com", "auth")]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert!(report.is_clean());
        assert_eq!(report.records[0].operation, Operation::Unchanged);
        assert!(
            fake.requests().iter().all(|r| r.method == "GET"),
            "an unchanged zone must be read and not written"
        );
    }

    // ---- D-08 result semantics ------------------------------------------

    /// A partial result is a reported failure, never a success.
    ///
    /// Mutation check: report only whether *any* record succeeded, or drop
    /// the failed entry from the summary, and this fails.
    #[test]
    fn one_failed_record_among_successes_is_still_a_failure_naming_it() {
        let fake = fake_zone(serde_json::json!([]));
        fake.script(
            Route::post("/zones/z1/dns_records"),
            CannedResponse::ok(record_json("r1", "auth.example.com", "203.0.113.7", true)),
        );
        fake.script(
            Route::post("/zones/z1/dns_records"),
            CannedResponse::api_error(10000, "Authentication error"),
        );

        let report = reconcile_with(
            &parsed(&[
                ("auth.example.com", "auth"),
                ("plex.example.com", "app:plex"),
            ]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert!(!report.is_clean(), "a partial result is not a success");
        let summary = report.failure_summary().expect("a breakdown");
        assert!(summary.contains("plex.example.com"), "{summary}");
        assert!(summary.contains("create"), "{summary}");
        assert!(summary.contains("Authentication error"), "{summary}");
        assert!(
            !summary.contains("auth.example.com"),
            "the breakdown lists what failed, not what worked: {summary}"
        );
    }

    /// D-07/D-08: both non-matching verdicts degrade, and the sentences must
    /// be different -- an operator must never be sent to fix a zone that is
    /// already correct because a nameserver timed out.
    #[test]
    fn a_mismatch_and_an_unreachable_nameserver_both_fail_but_do_not_read_alike() {
        let mismatch = |_: &Client, _: &Zone, _: &str, _: &RecordTarget| Verification::Mismatch {
            reason: "amber.ns.cloudflare.com answered 198.51.100.9".to_string(),
        };
        let unreachable =
            |_: &Client, _: &Zone, _: &str, _: &RecordTarget| Verification::CouldNotCheck {
                reason: "amber.ns.cloudflare.com did not answer".to_string(),
            };

        let mut summaries = Vec::new();
        for verify in [&mismatch as Verifier<'_>, &unreachable] {
            let fake = fake_zone(serde_json::json!([]));
            fake.script(
                Route::post("/zones/z1/dns_records"),
                CannedResponse::ok(record_json("r1", "auth.example.com", "203.0.113.7", true)),
            );
            let report = reconcile_with(
                &parsed(&[("auth.example.com", "auth")]),
                &client_for(&fake),
                verify,
            )
            .expect("the run completes");
            assert!(!report.is_clean(), "an unproved record is not a success");
            summaries.push(report.failure_summary().expect("a breakdown"));
        }

        assert!(
            summaries[0].contains("does not resolve as expected"),
            "{:?}",
            summaries[0]
        );
        assert!(
            summaries[1].contains("could not be checked"),
            "{:?}",
            summaries[1]
        );
        assert_ne!(
            summaries[0], summaries[1],
            "'your DNS is wrong' and 'a nameserver was unreachable' must not read alike"
        );
    }

    #[test]
    fn a_zone_that_cannot_be_resolved_stops_the_run_rather_than_reporting_nothing_to_do() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );
        let err = reconcile_with(
            &parsed(&[("auth.example.com", "auth")]),
            &client_for(&fake),
            &always_matches,
        )
        .expect_err("a refused listing is not an empty zone");
        assert!(err.to_string().contains("9109"), "{err}");
    }

    // ---- A8's observability ---------------------------------------------

    #[test]
    fn a_clean_cycle_records_a_unix_timestamp_the_next_run_can_age() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("dns-updater-last-success");
        record_last_success(
            &path,
            UNIX_EPOCH + std::time::Duration::from_secs(1_770_000_000),
        )
        .expect("the marker is written");
        assert_eq!(fs::read_to_string(&path).unwrap(), "1770000000\n");
    }

    // ---- reporting ------------------------------------------------------

    #[test]
    fn the_full_summary_names_every_record_and_its_operation() {
        let report = ReconcileReport {
            records: vec![
                RecordReport {
                    name: "auth.example.com".to_string(),
                    operation: Operation::Create,
                    failure: None,
                    note: None,
                },
                RecordReport {
                    name: "plex.example.com".to_string(),
                    operation: Operation::SkipForeign,
                    failure: None,
                    note: Some("left alone".to_string()),
                },
            ],
            scheduled: false,
        };
        let rendered = report.full_summary();
        assert!(rendered.contains("auth.example.com (create)"), "{rendered}");
        assert!(
            rendered.contains("plex.example.com (skip (not ferrum's)): left alone"),
            "{rendered}"
        );
    }

    #[test]
    fn a_host_with_no_records_says_so_rather_than_printing_nothing() {
        let report = ReconcileReport {
            records: Vec::new(),
            scheduled: false,
        };
        assert!(report.is_clean());
        assert_eq!(report.failure_summary(), None);
        assert!(report.full_summary().contains("no DNS records"));
    }
}
