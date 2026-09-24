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
//! **Adoption is the operator's decision, arriving as data (A3).** A foreign
//! record is skipped by default and that is the whole of A3's first half.
//! Its second half -- *"unless the operator opts in"* -- arrives here as
//! `adoptedNames` in the document, written from the answer the installer's
//! pre-erase gate collected per name. This module does not decide anything
//! about it: it hands the list to
//! [`ferrum_dns::record::plan_with_adoptions`], which is the only public way
//! to mint a capability over a record ferrum does not own, and which matches
//! per name so an adoption of `plex` reaches nothing else. An empty list --
//! the ordinary case, and the case for every document written before this
//! field existed -- plans exactly what it always did.
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
use ferrum_dns::ownership::AdoptedNames;
use ferrum_dns::record::{plan_with_adoptions, DesiredRecord, RecordAction};
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
    /// The names the operator explicitly handed to ferrum at the install
    /// gate (A3), from `ferrum.proxy.dns.adoptedNames`.
    ///
    /// Defaulted rather than required, on purpose in both directions: a
    /// document written before this field existed parses and adopts nothing,
    /// which is the safe reading, and a host whose operator declined
    /// everything carries an empty list rather than a missing key. The list
    /// is never a permission to write generally -- it only ever converts one
    /// named `SkipForeign` into one named `Adopt`.
    #[serde(rename = "adoptedNames", default)]
    pub adopted_names: Vec<String>,
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
    /// A record ferrum did not create, taken over because the operator
    /// explicitly adopted that name (A3's opt-in half). Its own word rather
    /// than `update`: an operator reading the breakdown must be able to see
    /// that their record was replaced, not that ferrum corrected its own.
    Adopt,
    /// A record of a type ferrum does not model shares a name ferrum
    /// manages. Nothing was called; the entry exists so the operator is told
    /// what else answers at that name.
    SkipUnmodelledType,
    /// A record ferrum does not own, of a type it does model, shares a name
    /// ferrum manages. Nothing was called. Its own word rather than
    /// `SkipUnmodelledType`'s: an operator can remove this one, or adopt the
    /// name, and neither is true of a type ferrum cannot manage.
    SkipForeignBeside,
    /// Not a record at all: Cloudflare is not answering for this zone, so
    /// every other line in the report describes a write that succeeded and
    /// changed nothing anyone can see.
    ///
    /// Carried as an entry rather than a field on the report so that every
    /// renderer already in place -- the `reconcile-dns` breakdown, the apply
    /// disclosure stream -- shows it without being taught to. A zone
    /// disclosure that only one of two readers prints is the defect this
    /// variant exists to close.
    ZoneNotServing,
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
            Operation::Adopt => "adopt (was yours, you handed it over)",
            Operation::SkipUnmodelledType => "also here (a type ferrum does not manage)",
            Operation::SkipForeignBeside => "also here (a record ferrum does not own)",
            Operation::ZoneNotServing => "NOT PUBLISHED (Cloudflare is not answering for this zone)",
        }
    }

    /// Whether this operation is something the operator must be *told*
    /// rather than something that either worked or failed.
    ///
    /// The distinction is load-bearing and it is the reason this method
    /// exists rather than the callers each filtering by variant. A
    /// disclosure is clean -- it must never degrade an apply, because a
    /// deliberately skipped foreign record is a planned outcome and an
    /// apply that warns forever is an apply nobody reads. But it is also
    /// not nothing: a foreign record at an app's hostname means that app is
    /// dead at its ferrum name, and an operator who is never told that has
    /// a mystery instead of a fact.
    #[must_use]
    pub fn is_disclosure(self) -> bool {
        matches!(
            self,
            Operation::SkipForeign
                | Operation::SkipForeignBeside
                | Operation::SkipUnmodelledType
                | Operation::ZoneNotServing
        )
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

    /// The entries that did not fail but that the operator still has to
    /// hear about.
    ///
    /// # Returns
    /// Every clean entry whose operation [`Operation::is_disclosure`]
    /// reports, in plan order. Empty on the ordinary run, which is what
    /// lets a caller emit these unconditionally without adding noise.
    #[must_use]
    pub fn disclosures(&self) -> Vec<&RecordReport> {
        self.records
            .iter()
            .filter(|r| r.failure.is_none() && r.operation.is_disclosure())
            .collect()
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

    let resolved = client.resolve_zone(&config.base_domain)?;
    let zone = &resolved.zone;
    // Deliberately `list_records` + `plan_with_adoptions` rather than
    // `Client::plan_records`: the latter plans with no adoptions, which is
    // the right default for every other caller and the wrong one here. The
    // listing is still the single source of truth -- ownership is re-derived
    // from it on every run, and the adopted list only widens what the plan
    // may do to names the operator named.
    let existing = client.list_records(zone)?;
    let actions = plan_with_adoptions(&desired, &existing, &AdoptedNames::recorded(&config.adopted_names));

    let mut records: Vec<RecordReport> = actions
        .into_iter()
        .map(|action| execute(client, zone, verify, action))
        .collect();

    // First, not last. Every line below it describes a write that will
    // succeed, and reading those as good news is the whole failure: the
    // zone answers ferrum correctly and answers the internet not at all.
    // Not a failure either -- the writes really did succeed, the records
    // really are right, and the fix is in the operator's registrar rather
    // than on this host.
    if let Some(detail) = resolved.advisory(&config.base_domain) {
        records.insert(
            0,
            RecordReport {
                name: resolved.zone.name.clone(),
                operation: Operation::ZoneNotServing,
                failure: None,
                note: Some(detail),
            },
        );
    }

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
        // A3's opt-in half. The write is the ordinary one, so it carries the
        // ownership marker and this record is ferrum's from the next listing
        // onwards -- the adopted list is a one-time transition, not a
        // standing permission.
        RecordAction::Adopt {
            record_id,
            name,
            current,
            target,
        } => match client.update_record(zone, &record_id, &name, &target) {
            Ok(_) => {
                let mut report = verified(client, zone, verify, name, Operation::Adopt, &target);
                if report.failure.is_none() {
                    report.note = Some(format!(
                        "you adopted this name at install; it pointed at {current} and now \
                         points at {target}, and ferrum owns it from here"
                    ));
                }
                report
            }
            Err(e) => failed(name, Operation::Adopt, &e.to_string()),
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
        // Disclosure, not an outcome, and the worse half of the pair below:
        // this record is the same type as ferrum's own at this name, so the
        // two round-robin and the name answers correctly about half the
        // time. A3 still forbids touching it -- the variant carries no
        // record id to touch it with -- but an intermittent failure the
        // report never mentioned is the shape of defect R1 exists to close.
        RecordAction::SkipForeignBeside { name, current } => RecordReport {
            name,
            operation: Operation::SkipForeignBeside,
            failure: None,
            note: Some(format!(
                "another record that ferrum did not create also answers at this name, \
                 pointing at {current}. It was left exactly as it is, so some requests for \
                 this name reach that address instead of this server"
            )),
        },
        // Disclosure, not an outcome: ferrum's own record at this name was
        // still created or corrected by its own entry. An AAAA left silently
        // beside ferrum's A sends IPv6-capable clients to the old host, and
        // the operator has no way to see it if this line is missing.
        RecordAction::SkipUnmodelledType { name, record_type } => RecordReport {
            name,
            operation: Operation::SkipUnmodelledType,
            failure: None,
            note: Some(format!(
                "a {record_type} record also answers at this name. ferrum does not manage \
                 {record_type} records, so it was left exactly as it is -- but clients that \
                 prefer it will not reach this server"
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
    reconcile_for_apply_with(
        toplevel,
        progress,
        &cloudflare_client,
        &authoritative_verifier,
    )
}

/// [`reconcile_for_apply`] with its two production dependencies injected.
///
/// The seam exists because the function above had none, and that is exactly
/// why the defect it now fixes survived three reviews: every test asserted
/// on the in-memory [`ReconcileReport`], and the step that decided what an
/// operator actually sees had no test at all. The sandbox running this
/// suite has no network, so the real client and the real `dig`-based
/// verifier cannot appear in a test -- without this parameterisation there
/// is nothing to drive.
///
/// # Arguments
/// * `toplevel` - the system closure holding the document.
/// * `progress` - the job stream the operator's dashboard tails.
/// * `make_client` - how Cloudflare is reached.
/// * `verify` - how a written record is proved to resolve.
///
/// # Returns
/// The same as [`reconcile_for_apply`]: `Some(reason)` only when the apply
/// must be degraded.
fn reconcile_for_apply_with(
    toplevel: &str,
    progress: &mut crate::progress::Progress,
    make_client: ClientFactory<'_>,
    verify: Verifier<'_>,
) -> Option<String> {
    let path = Path::new(toplevel).join(CONFIG_IN_CLOSURE);
    if !path.exists() {
        return None;
    }
    progress.event("dns", "reconciling the DNS records for published apps");
    match run(&path, make_client, verify) {
        Ok(None) => None,
        Ok(Some(report)) => {
            disclose(&report, progress);
            report.failure_summary()
        }
        Err(e) => Some(format!("DNS records could not be reconciled: {e}")),
    }
}

/// Puts the report's non-failing disclosures where an operator will see
/// them.
///
/// Before this existed the apply path called `failure_summary()` and
/// nothing else, so a foreign record at an app's hostname produced
/// `Succeeded`, one progress line, a dead app and not one sentence saying
/// why. The disclosures were computed correctly on every run and thrown
/// away at the last step.
///
/// Two channels because there are two ways an apply is watched and they do
/// not overlap: `progress` is the JSONL stream ferrumd tails for the
/// dashboard, and it writes nothing at all when the run has no job id --
/// which is precisely the hand-run `ferrum-apply apply` over SSH, where
/// stderr is what the operator and the journal have.
///
/// Deliberately not folded into the returned reason: that value degrades
/// the apply, and a planned skip is not a fault. See
/// [`Operation::is_disclosure`].
///
/// # Arguments
/// * `report` - the finished reconcile report.
/// * `progress` - the job stream.
fn disclose(report: &ReconcileReport, progress: &mut crate::progress::Progress) {
    for entry in report.disclosures() {
        let line = entry.to_string();
        progress.event("dns-disclosure", &line);
        eprintln!("ferrum-apply dns: {line}");
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

    /// The same document, plus the names the operator adopted at the gate.
    fn parsed_with_adoptions(records: &[(&str, &str)], adopted: &[&str]) -> DnsConfig {
        let mut value: serde_json::Value =
            serde_json::from_str(&config_json(records, true)).expect("the document parses");
        value["adoptedNames"] = serde_json::json!(adopted);
        serde_json::from_value(value).expect("the document with adoptions parses")
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

    /// A fake system closure carrying the document an apply would read,
    /// pointed at a credential file that exists.
    ///
    /// # Returns
    /// The closure root, for [`reconcile_for_apply_with`]'s `toplevel`.
    fn closure_with_document(
        dir: &tempfile::TempDir,
        records: &[(&str, &str)],
    ) -> PathBuf {
        let credential = write_credential(dir, "CLOUDFLARE_DNS_API_TOKEN=abc123\n");
        let mut value: serde_json::Value =
            serde_json::from_str(&config_json(records, true)).expect("the document parses");
        value["credentialFile"] = serde_json::json!(credential);

        let toplevel = dir.path().join("closure");
        let config_path = toplevel.join(CONFIG_IN_CLOSURE);
        fs::create_dir_all(config_path.parent().expect("a parent")).expect("mkdir");
        fs::write(&config_path, value.to_string()).expect("write the document");
        toplevel
    }

    /// Every `dns-disclosure` line the apply wrote to its job stream.
    fn disclosures_written(progress_path: &Path) -> Vec<String> {
        let raw = fs::read_to_string(progress_path).unwrap_or_default();
        raw.lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|event| event["event"] == "dns-disclosure")
            .map(|event| event["detail"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    // ---- the apply path's own output (not the in-memory report) ---------

    /// DA-TC-01, and the reason it survived three reviews: every other
    /// test in this file asserts on the [`ReconcileReport`] that
    /// `reconcile_for_apply` then throws away. `is_clean` treats a skipped
    /// foreign record as clean -- correctly, it is not a failure -- so
    /// `failure_summary()` returns `None` and the whole disclosure went
    /// nowhere. An operator enabling an app whose hostname is already
    /// occupied got `Succeeded`, a dead app, and not one sentence saying
    /// why.
    ///
    /// Mutation check: drop the `disclose(&report, progress)` call from
    /// `reconcile_for_apply_with` and this test fails on the empty
    /// disclosure list.
    #[test]
    fn an_apply_that_skipped_a_foreign_record_says_so_where_the_operator_can_see_it() {
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_zone(serde_json::json!([record_json(
            "r1",
            "plex.example.com",
            "198.51.100.9",
            false
        )]));
        let toplevel = closure_with_document(&dir, &[("plex.example.com", "app:plex")]);
        let progress_path = dir.path().join("job.jsonl");
        let mut progress = crate::progress::Progress::to_path(&progress_path);

        let degraded = reconcile_for_apply_with(
            toplevel.to_str().expect("utf-8"),
            &mut progress,
            &|_| client_for(&fake),
            &always_matches,
        );

        assert_eq!(
            degraded, None,
            "a record left alone on purpose is not a fault and must not degrade the apply"
        );
        let disclosed = disclosures_written(&progress_path);
        assert_eq!(disclosed.len(), 1, "{disclosed:?}");
        assert!(disclosed[0].contains("plex.example.com"), "{disclosed:?}");
        assert!(disclosed[0].contains("198.51.100.9"), "{disclosed:?}");
        assert!(
            disclosed[0].contains("ferrum did not create it"),
            "{disclosed:?}"
        );
    }

    /// The complement, and the reason this is a disclosure channel rather
    /// than a warning: an apply with nothing to disclose must stay silent,
    /// or the line stops being read on the run that carries one.
    #[test]
    fn an_ordinary_apply_discloses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_zone(serde_json::json!([record_json(
            "r1",
            "plex.example.com",
            "203.0.113.7",
            true
        )]));
        let toplevel = closure_with_document(&dir, &[("plex.example.com", "app:plex")]);
        let progress_path = dir.path().join("job.jsonl");
        let mut progress = crate::progress::Progress::to_path(&progress_path);

        assert_eq!(
            reconcile_for_apply_with(
                toplevel.to_str().expect("utf-8"),
                &mut progress,
                &|_| client_for(&fake),
                &always_matches,
            ),
            None
        );
        assert!(disclosures_written(&progress_path).is_empty());
    }

    /// DA-TC-02 on the apply path. The install-time gate is the first line
    /// of defence, but a host that was installed while its zone was active
    /// and later had it moved would otherwise reconcile happily forever.
    ///
    /// Mutation check: make `ResolvedZone::advisory` return `None` for a
    /// pending zone (or drop the `Operation::ZoneNotServing` insert in
    /// `reconcile_with`) and this test fails.
    #[test]
    fn an_apply_into_a_zone_cloudflare_is_not_serving_says_so_rather_than_reporting_success() {
        let dir = tempfile::tempdir().unwrap();
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "example.com",
                "status": "pending",
                "name_servers": ["amber.ns.cloudflare.com"],
            }])),
        );
        for _ in 0..2 {
            fake.script(
                Route::get("/zones/z1/dns_records"),
                CannedResponse::ok(serde_json::json!([])),
            );
        }
        fake.script(
            Route::post("/zones/z1/dns_records"),
            CannedResponse::ok(record_json("r1", "plex.example.com", "203.0.113.7", true)),
        );

        let toplevel = closure_with_document(&dir, &[("plex.example.com", "app:plex")]);
        let progress_path = dir.path().join("job.jsonl");
        let mut progress = crate::progress::Progress::to_path(&progress_path);

        let degraded = reconcile_for_apply_with(
            toplevel.to_str().expect("utf-8"),
            &mut progress,
            &|_| client_for(&fake),
            &always_matches,
        );

        assert_eq!(
            degraded, None,
            "the records really were written; the fix is at the registrar, not on this host"
        );
        let disclosed = disclosures_written(&progress_path);
        assert_eq!(disclosed.len(), 1, "{disclosed:?}");
        assert!(disclosed[0].contains("NOT PUBLISHED"), "{disclosed:?}");
        assert!(disclosed[0].contains("pending"), "{disclosed:?}");
        assert!(disclosed[0].contains("registrar"), "{disclosed:?}");
        assert!(
            disclosed[0].contains("amber.ns.cloudflare.com"),
            "{disclosed:?}"
        );
    }

    /// `reconcile-dns`'s own renderer must carry the zone disclosure too:
    /// the timer that runs it is the only thing looking at a host between
    /// applies.
    #[test]
    fn the_subcommand_breakdown_also_names_a_zone_cloudflare_is_not_serving() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "example.com",
                "status": "moved",
                "name_servers": ["amber.ns.cloudflare.com"],
            }])),
        );
        for _ in 0..2 {
            fake.script(
                Route::get("/zones/z1/dns_records"),
                CannedResponse::ok(serde_json::json!([])),
            );
        }
        fake.script(
            Route::post("/zones/z1/dns_records"),
            CannedResponse::ok(record_json("r1", "plex.example.com", "203.0.113.7", true)),
        );

        let report = reconcile_with(
            &parsed(&[("plex.example.com", "app:plex")]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the reconcile runs");

        assert!(
            report.is_clean(),
            "the writes succeeded; the zone is the operator's problem, not a record failure"
        );
        let rendered = report.full_summary();
        assert!(rendered.contains("NOT PUBLISHED"), "{rendered}");
        assert!(rendered.contains("moved"), "{rendered}");
        assert!(
            rendered.contains("waiting does not change that"),
            "{rendered}"
        );
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

    /// The quieter silent case: a record ferrum does **not** own at the same
    /// name *and* the same type as one it does. Nothing is written to it --
    /// that held before this test existed -- but until the plan grew a
    /// variant for it, the apply report said only `unchanged` for that name
    /// while Cloudflare round-robinned the two. An operator reading a clean
    /// report then debugs a hostname that works about half the time.
    #[test]
    fn a_foreign_record_beside_ferrums_own_is_reported_and_never_written_to() {
        let fake = fake_zone(serde_json::json!([
            record_json("mine", "plex.example.com", "203.0.113.7", true),
            record_json("theirs", "plex.example.com", "198.51.100.9", false),
        ]));

        let report = reconcile_with(
            &parsed(&[("plex.example.com", "app:plex")]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert!(
            report.is_clean(),
            "a disclosure must not degrade: {report:?}"
        );
        let disclosed = report
            .records
            .iter()
            .find(|r| r.operation == Operation::SkipForeignBeside)
            .expect("the operator's own record at this name is disclosed");
        let note = disclosed.note.as_deref().expect("a disclosure explains");
        assert!(note.contains("198.51.100.9"), "{note}");
        assert!(note.contains("ferrum did not create"), "{note}");
        assert!(
            report
                .records
                .iter()
                .any(|r| r.operation == Operation::Unchanged),
            "ferrum's own record is still reported on its own terms: {report:?}"
        );

        for method in ["PUT", "DELETE", "POST"] {
            assert!(
                fake.requests().iter().all(|r| r.method != method),
                "disclosure is not permission: no write may be made for {method}"
            );
        }
    }

    /// The silent case: an `AAAA` at a wanted name. ferrum still creates its
    /// `A`, but the report has to say the other record is there -- otherwise
    /// the operator's IPv6-capable clients keep reaching the old host and
    /// nothing ferrum printed ever mentioned it.
    #[test]
    fn an_aaaa_sharing_a_wanted_name_is_reported_and_never_written_to() {
        let fake = fake_zone(serde_json::json!([{
            "id": "theirs-v6",
            "name": "plex.example.com",
            "type": "AAAA",
            "content": "2001:db8::1",
            "proxied": false,
        }]));
        fake.script(
            Route::post("/zones/z1/dns_records"),
            CannedResponse::ok(record_json("r1", "plex.example.com", "203.0.113.7", true)),
        );

        let report = reconcile_with(
            &parsed(&[("plex.example.com", "app:plex")]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert!(
            report.is_clean(),
            "a disclosure must not degrade: {report:?}"
        );
        let disclosed = report
            .records
            .iter()
            .find(|r| r.operation == Operation::SkipUnmodelledType)
            .expect("the AAAA is disclosed");
        let note = disclosed.note.as_deref().expect("a disclosure explains");
        assert!(note.contains("AAAA"), "{note}");
        assert!(
            report
                .records
                .iter()
                .any(|r| r.operation == Operation::Create),
            "the A record is still created: {report:?}"
        );

        for method in ["PUT", "DELETE"] {
            assert!(
                fake.requests().iter().all(|r| r.method != method),
                "a record ferrum does not model must never be written to"
            );
        }
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

    /// The stronger form of the idempotence claim: not merely "an
    /// already-matching zone is left alone" but "running the same
    /// reconcile twice in a row, the way the DDNS timer actually does,
    /// creates once and then goes quiet". The first call creates the
    /// record from an empty zone; the second call is scripted to see that
    /// exact record on its listing (as a real Cloudflare zone would) and
    /// must issue zero write requests.
    ///
    /// Mutation check: have a second `reconcile_with` call re-create or
    /// re-update a record it just wrote, and this fails on the `all(|r|
    /// r.method == "GET")` assertion below.
    #[test]
    fn running_reconcile_twice_creates_once_and_then_converges_with_no_writes() {
        let fake = FakeCloudflare::start();
        let zone = || {
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "example.com",
                "name_servers": ["amber.ns.cloudflare.com"],
            }]))
        };
        // Round 1: GET /zones, the NS-delegation listing, the real listing
        // (empty -- nothing exists yet), then the create.
        fake.script(Route::get("/zones"), zone());
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );
        fake.script(
            Route::post("/zones/z1/dns_records"),
            CannedResponse::ok(record_json("r1", "auth.example.com", "203.0.113.7", true)),
        );
        // Round 2: the same two listings, this time reporting the record
        // round 1 just created -- exactly what a real zone would show on a
        // second poll. No write route is scripted at all for round 2: an
        // unscripted write would fail the request outright and any write
        // attempt would show up as a non-GET entry below.
        fake.script(Route::get("/zones"), zone());
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([record_json(
                "r1",
                "auth.example.com",
                "203.0.113.7",
                true
            )])),
        );

        let client = client_for(&fake);
        let config = parsed(&[("auth.example.com", "auth")]);

        let first = reconcile_with(&config, &client, &always_matches).expect("round 1 completes");
        assert_eq!(first.records[0].operation, Operation::Create);
        let after_first = fake.requests().len();

        let second =
            reconcile_with(&config, &client, &always_matches).expect("round 2 completes");
        assert_eq!(
            second.records[0].operation,
            Operation::Unchanged,
            "the record round 1 created must be recognised as already correct"
        );
        assert!(second.is_clean());

        let round_two_requests = &fake.requests()[after_first..];
        assert!(
            !round_two_requests.is_empty(),
            "round 2 must actually have talked to the fake"
        );
        assert!(
            round_two_requests.iter().all(|r| r.method == "GET"),
            "a converged zone must issue no create/update/delete on the next \
             run: {round_two_requests:?}"
        );
    }

    /// `ferrum_dns::record`'s own module doc says a [`ferrum_dns::record::ZoneListing`]
    /// "comes from `Client::list_records` or it does not exist" -- but the
    /// type derives `Default`, and `Default::default()` is a public trait
    /// impl regardless of the struct's fields being crate-private. Called
    /// from this crate (a real, external consumer of `ferrum-dns`, not a
    /// test inside that crate), it builds an empty listing with no
    /// Cloudflare call at all, and [`ferrum_dns::record::plan`] cannot tell
    /// it apart from a listing of a genuinely empty zone: every desired name
    /// comes back `Create`.
    ///
    /// This is not reachable from any call site in this crate today --
    /// `reconcile_with` always calls `client.list_records(&zone)` -- so it is
    /// not a live bypass of A3/A4. It is recorded here because the
    /// documented invariant ("no public constructor") is false, and the
    /// ordinary Rust reflex `listing.unwrap_or_default()` on some future
    /// error-handling path would silently reintroduce the exact failure D-01
    /// exists to prevent: a plan computed as if the zone had nothing in it.
    #[test]
    fn zonelisting_default_is_a_public_constructor_the_module_doc_says_does_not_exist() {
        let empty = ferrum_dns::record::ZoneListing::default();
        let desired = vec![DesiredRecord {
            name: "plex.example.com".to_string(),
            target: RecordTarget::A(HOST),
        }];
        let actions = ferrum_dns::record::plan(&desired, &empty);
        assert_eq!(actions.len(), 1);
        assert!(
            matches!(actions[0], RecordAction::Create { .. }),
            "an externally-constructed empty listing plans a Create with no \
             way to know whether a foreign record already occupies the name \
             in the real zone: {:?}",
            actions[0]
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
    // ---- A3's opt-in half, end to end through the document -------------

    /// The mechanism this story exists to add: a name the operator adopted
    /// is taken over, and the write carries the ownership marker so the next
    /// run needs no decision at all.
    #[test]
    fn an_adopted_name_is_taken_over_and_the_write_carries_the_marker() {
        let fake = fake_zone(serde_json::json!([record_json(
            "theirs",
            "plex.example.com",
            "198.51.100.9",
            false
        )]));
        fake.script(
            Route::put("/zones/z1/dns_records/theirs"),
            CannedResponse::ok(record_json("theirs", "plex.example.com", "203.0.113.7", true)),
        );

        let report = reconcile_with(
            &parsed_with_adoptions(&[("plex.example.com", "app:plex")], &["plex.example.com"]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert_eq!(report.records[0].operation, Operation::Adopt);
        assert!(report.is_clean(), "{report:?}");

        // The note is the only place the operator reads what happened to
        // their record, so its prose is asserted rather than assumed: an
        // earlier revision shipped a run of 26 spaces mid-sentence, and a
        // test that checked only the operation could not see it.
        let note = report.records[0]
            .note
            .as_deref()
            .expect("an adoption explains itself");
        assert_eq!(
            note,
            "you adopted this name at install; it pointed at 198.51.100.9 and now points at \
             203.0.113.7, and ferrum owns it from here"
        );
        assert!(
            !note.contains("  "),
            "no run of spaces mid-sentence: {note}"
        );

        let writes = fake.requests_for(&Route::put("/zones/z1/dns_records/theirs"));
        assert_eq!(writes.len(), 1, "exactly one write to the adopted record");
        let body: serde_json::Value =
            serde_json::from_str(&writes[0].body).expect("the write carries a JSON body");
        assert_eq!(
            body["comment"],
            serde_json::json!(ferrum_dns::OWNERSHIP_MARKER),
            "without the marker the adoption would have to be re-decided every run"
        );
        assert_eq!(body["content"], serde_json::json!("203.0.113.7"));
    }

    /// The per-name guarantee, at the level an operator would feel it:
    /// adopting `plex` leaves `sonarr` exactly where it was.
    #[test]
    fn adopting_one_name_does_not_adopt_another() {
        let fake = fake_zone(serde_json::json!([
            record_json("theirs-plex", "plex.example.com", "198.51.100.9", false),
            record_json("theirs-sonarr", "sonarr.example.com", "198.51.100.9", false),
        ]));
        fake.script(
            Route::put("/zones/z1/dns_records/theirs-plex"),
            CannedResponse::ok(record_json("theirs-plex", "plex.example.com", "203.0.113.7", true)),
        );

        let report = reconcile_with(
            &parsed_with_adoptions(
                &[
                    ("plex.example.com", "app:plex"),
                    ("sonarr.example.com", "app:sonarr"),
                ],
                &["plex.example.com"],
            ),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        let sonarr = report
            .records
            .iter()
            .find(|r| r.name == "sonarr.example.com")
            .expect("sonarr is reported");
        assert_eq!(sonarr.operation, Operation::SkipForeign);
        assert!(
            fake.requests_for(&Route::put("/zones/z1/dns_records/theirs-sonarr"))
                .is_empty(),
            "adopting plex must not write to sonarr"
        );
        assert!(
            fake.requests_for(&Route::delete("/zones/z1/dns_records/theirs-sonarr"))
                .is_empty(),
            "adopting plex must not delete sonarr"
        );
    }

    /// The guard that must survive this story: with no adopted names, a
    /// foreign record is still untouchable. This is the test the mutation
    /// report kills by removing the per-name check.
    #[test]
    fn a_name_the_operator_did_not_adopt_is_still_never_written_to() {
        let fake = fake_zone(serde_json::json!([record_json(
            "theirs",
            "sonarr.example.com",
            "198.51.100.9",
            false
        )]));

        let report = reconcile_with(
            &parsed_with_adoptions(&[("sonarr.example.com", "app:sonarr")], &["plex.example.com"]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert_eq!(report.records[0].operation, Operation::SkipForeign);
        for method in ["POST", "PUT", "DELETE"] {
            assert!(
                fake.requests().iter().all(|r| r.method != method),
                "an unadopted foreign record must not be written to ({method})"
            );
        }
    }

    /// A document written before `adoptedNames` existed must still parse,
    /// and must adopt nothing -- the safe reading in both directions.
    #[test]
    fn a_document_without_the_adopted_field_adopts_nothing() {
        let config = parsed(&[("plex.example.com", "app:plex")]);
        assert!(config.adopted_names.is_empty());
    }

    /// An adopted name that nothing publishes any more is not a licence to
    /// prune the operator's zone: the record survives.
    #[test]
    fn an_adopted_name_nothing_publishes_is_still_never_deleted() {
        let fake = fake_zone(serde_json::json!([record_json(
            "theirs",
            "plex.example.com",
            "198.51.100.9",
            false
        )]));

        let report = reconcile_with(
            &parsed_with_adoptions(&[], &["plex.example.com"]),
            &client_for(&fake),
            &always_matches,
        )
        .expect("the run completes");

        assert!(report.records.is_empty(), "{report:?}");
        assert!(
            fake.requests_for(&Route::delete("/zones/z1/dns_records/theirs"))
                .is_empty(),
            "an adopted hostname is not permission to delete the operator's record"
        );
    }

    /// The breakdown must not describe a takeover of the operator's record
    /// with the same word it uses for correcting ferrum's own.
    #[test]
    fn the_breakdown_says_adopt_rather_than_update() {
        assert_eq!(Operation::Adopt.label(), "adopt (was yours, you handed it over)");
        assert_ne!(Operation::Adopt.label(), Operation::Update.label());
    }
}
