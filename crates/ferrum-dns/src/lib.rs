//! ferrum-dns: the one place in this workspace that talks to Cloudflare.
//!
//! R1 exists because `auth.thesyms.ca` never resolved after an install that
//! reported success: ferrum publishes apps on a base domain but had no
//! A/CNAME mechanism at all. This crate is where that mechanism lives.
//!
//! **The boundary this crate enforces (decision OQ1/D-01).** Every
//! Cloudflare HTTP call in ferrum passes through here, and nothing else in
//! the workspace depends on `ureq` for Cloudflare's sake. Three call sites
//! consume it -- `ferrum-install` (token verification at collection time and
//! the pre-erase dry run), `ferrum-apply apply` (create/update/delete folded
//! into the existing `ApplyResult`), and the optional DDNS timer -- and none
//! of them re-implements zone, ownership, or record logic. Keeping the
//! surface narrow is the cheap insurance the design asked for: a second DNS
//! provider would be an additional implementation behind this seam rather
//! than a refactor of three call sites. It is deliberately *not* a provider
//! abstraction today; ferrum already requires Cloudflare for ACME DNS-01, so
//! a trait for a provider nobody has asked for would be speculative.
//!
//! **Two rules that outlive any one function here.**
//!
//! 1. Cloudflare's v4 API answers **HTTP 200** with `{"success": false,
//!    "errors": [...]}` for some permission and validation failures. The
//!    house idiom elsewhere in this workspace -- `ureq::get(..).call()
//!    .map_err(..)` -- only inspects the HTTP status and would read that as
//!    success. Every method added here must check the body's own `success`
//!    field independent of status, and surface Cloudflare's own error code
//!    and message ([`CloudflareError::Api`]).
//! 2. No test in this workspace may call the real Cloudflare API. The Nix
//!    sandbox that runs `workspace-tests` has no network at all, so a real
//!    call fails CI by construction. [`testing`] is the fake every test
//!    points at instead.
//!
//! **Where the rest of it lives.** This file holds the vocabulary -- the
//! types the seam is expressed in. The behaviour is in four modules, each
//! owning one decision:
//!
//! * [`client`] -- every HTTP call, with the `success`-field check,
//!   pagination, and timeouts the house idiom lacks.
//! * [`dns_query`] -- the post-apply proof that a record ferrum wrote is
//!   actually answered by the zone's own nameservers. The only module here
//!   that is not an HTTP call: it shells out to `dig` (decision D-10), so
//!   no DNS wire format is ever parsed in this process.
//! * [`zone`] -- which zone a base domain belongs to, and whether that zone
//!   is actually authoritative for it.
//! * [`ownership`] -- the marker that decides whether a record is ferrum's
//!   to change, and the explicit per-name operator adoption that is the only
//!   other way past it. The Critical guards live here.
//! * [`record`] -- the record model and the idempotent reconcile plan.
//!
//! **One thing this crate still owes a live API.** Decision D-01 rests on
//! Cloudflare's `comment` field persisting across reads, being returned by a
//! listing without a second call, being long enough for
//! [`OWNERSHIP_MARKER`], and surviving a reduced-scope token. That has not
//! been verified against the real API -- this desk has no access to one --
//! so it is built exactly as specified and the marker is read and written
//! through the same seam as every other Cloudflare call. If the field turns
//! out to be unusable, the fallback is an **advisory-only** local cache
//! keyed by record id, never authoritative, and it is a swap inside
//! [`client`] rather than a redesign.

use std::fmt;
use std::net::Ipv4Addr;

pub mod client;
pub mod dns_query;
pub mod ownership;
pub mod record;
pub mod zone;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// A secret that cannot be printed by accident.
///
/// The Cloudflare token grants zone-wide DNS manipulation, which makes it
/// the highest-value credential ferrum handles. Transport discipline alone
/// is not enough: a single `dbg!` on a struct holding a bare `String` leaks
/// it with nothing to catch that, so the redaction is in the type.
///
/// Deliberately a local newtype rather than a reuse of
/// `ferrum-install`'s: that crate depends on this one, so the dependency
/// cannot run the other way, and the discipline is identical.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wraps a token.
    ///
    /// # Arguments
    /// * `value` - the bare token. On-host the caller must already have
    ///   stripped the `CLOUDFLARE_DNS_API_TOKEN=` prefix that the secret
    ///   file carries, because that file is a systemd `EnvironmentFile=`
    ///   line rather than a bare credential.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The token itself, for the one place that may see it: the
    /// `Authorization` header.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    /// Renders `<redacted>`. There is deliberately no `Display`: a token
    /// that can be formatted into a string is a token that ends up in a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// A Cloudflare zone the configured token can see.
///
/// `name` is the zone's own apex (`example.com`), which is not necessarily
/// the ferrum base domain: `ferrum.proxy.baseDomain` may be a subdomain of
/// it (`home.example.com`), so zone resolution is a longest-suffix match
/// over every visible zone rather than a lookup by name.
///
/// `nameservers` are the zone's authoritative servers as Cloudflare reports
/// them. They are carried on the zone rather than looked up again later
/// because post-apply verification must query the record against *these*
/// servers: a local recursive resolver can hold a negative-cache entry from
/// an earlier lookup and report a freshly created record as absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// Cloudflare's opaque zone identifier, used in every record URL.
    pub id: String,
    /// The zone apex, e.g. `example.com`.
    pub name: String,
    /// The zone's authoritative nameservers, as reported by Cloudflare.
    pub nameservers: Vec<String>,
}

/// Where a record points.
///
/// IPv4-only, and that is a scoped decision for R1 rather than an omission:
/// a dual-stack host advertises no `AAAA` record and an IPv6-only host is
/// unsupported. Revisit when a requirement needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordTarget {
    /// An `A` record pointing at a stated public IPv4 address.
    A(Ipv4Addr),
    /// A `CNAME` pointing at a stated hostname -- the form a host behind a
    /// dynamic address needs.
    Cname(String),
}

impl RecordTarget {
    /// The Cloudflare record `type` string for this target (`A` or `CNAME`).
    #[must_use]
    pub fn record_type(&self) -> &'static str {
        match self {
            RecordTarget::A(_) => "A",
            RecordTarget::Cname(_) => "CNAME",
        }
    }
}

impl fmt::Display for RecordTarget {
    /// Renders the target as Cloudflare's `content` value, which is also the
    /// form the dry run shows the operator.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordTarget::A(addr) => write!(f, "{addr}"),
            RecordTarget::Cname(host) => write!(f, "{host}"),
        }
    }
}

/// The marker ferrum writes into a record's Cloudflare `comment` field to
/// claim ownership of it.
///
/// Authority lives in Cloudflare itself, not in `/var/lib/ferrum/state`:
/// that directory is on the OS disk, and a reinstall wipes it -- which is
/// exactly the event ownership tracking has to survive. The marker is a
/// bare literal with no version tag or JSON payload because it is
/// operator-editable surface, and more of it is more to be silently
/// changed, not less.
pub const OWNERSHIP_MARKER: &str = "ferrum-managed";

/// One DNS record as it exists in the zone right now.
///
/// `owned_by_ferrum` is derived from [`OWNERSHIP_MARKER`] in the record's
/// `comment` on every listing rather than remembered locally. A record
/// without the marker is foreign: it is reported and left alone, never
/// overwritten and never deleted.
///
/// **The fields are crate-private, and that is what the ownership guard
/// rests on.** [`crate::record::plan`] mints a
/// [`crate::ownership::ManagedRecordId`] -- the capability every write and
/// delete demands -- from `owned_by_ferrum`. If a caller could set that
/// flag, it could hand the planner a record it invented and receive a real
/// capability for an id it chose, which is the guard defeated without
/// touching the guard. So the only way to obtain a `DnsRecord` is a live
/// listing: `RecordJson::into_model` is the sole constructor and it is
/// crate-private, which makes the forgery a compile error rather than a
/// review finding.
///
/// ```compile_fail
/// # use ferrum_dns::{DnsRecord, RecordTarget};
/// # use std::net::Ipv4Addr;
/// // Claiming a record is ferrum's is not something a caller may do.
/// let forged = DnsRecord {
///     id: "an-id-i-chose".to_string(),
///     name: "plex.example.com".to_string(),
///     target: RecordTarget::A(Ipv4Addr::new(203, 0, 113, 7)),
///     proxied: false,
///     owned_by_ferrum: true,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Cloudflare's opaque record identifier.
    pub(crate) id: String,
    /// The fully qualified record name, e.g. `auth.example.com`.
    pub(crate) name: String,
    /// Where the record points.
    pub(crate) target: RecordTarget,
    /// Cloudflare's orange-cloud proxying. ferrum always writes `false`:
    /// proxying makes every request arrive from a Cloudflare edge address,
    /// which turns the LAN allow-list in front of `lan` apps into a total
    /// outage, and it routes Plex/Jellyfin streams through that edge.
    pub(crate) proxied: bool,
    /// Whether [`OWNERSHIP_MARKER`] was present on this record.
    pub(crate) owned_by_ferrum: bool,
}

impl DnsRecord {
    /// Cloudflare's opaque record identifier.
    ///
    /// Read-only on purpose: an id is not proof of ownership, and the only
    /// id a write accepts is the one carried inside a
    /// [`crate::ownership::ManagedRecordId`].
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The fully qualified record name, e.g. `auth.example.com`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Where the record points.
    #[must_use]
    pub fn target(&self) -> &RecordTarget {
        &self.target
    }

    /// Whether Cloudflare's orange-cloud proxying is on for this record.
    #[must_use]
    pub fn proxied(&self) -> bool {
        self.proxied
    }

    /// Whether [`OWNERSHIP_MARKER`] was present on this record when the zone
    /// was listed.
    #[must_use]
    pub fn owned_by_ferrum(&self) -> bool {
        self.owned_by_ferrum
    }
}

/// Why a Cloudflare call did not produce the answer the caller needed.
///
/// **This taxonomy is an interface, not an implementation detail.** Stories
/// R1-S4, R1-S8 and R1-S9 match on these variants to decide whether to
/// re-prompt the operator, degrade the apply, or retry, so the rule for
/// which variant a failure becomes is fixed here rather than at each call
/// site:
///
/// | What happened | Variant |
/// |---|---|
/// | Any response, any HTTP status, whose body says `success: false` and names an error | [`CloudflareError::Api`] |
/// | A failing HTTP status whose body is not a usable Cloudflare envelope | [`CloudflareError::Transport`] |
/// | Connection refused, TLS failure, timeout, truncated read | [`CloudflareError::Transport`] |
/// | A body that is not JSON, not the documented shape, or claims failure while naming no error | [`CloudflareError::Malformed`] |
/// | No visible zone covers the base domain | [`CloudflareError::ZoneNotFound`] |
/// | A zone covers it, but the name is served by other nameservers | [`CloudflareError::ZoneDelegated`] |
///
/// The first row is the load-bearing one: an HTTP 200 carrying
/// `success: false` is a **refusal**, and collapsing it into a transport
/// error or (worse) a success is the defect UF-15 records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudflareError {
    /// Cloudflare refused the request in its own response body, carrying its
    /// own error code and message.
    ///
    /// This variant exists because the refusal frequently arrives with
    /// **HTTP 200** and `{"success": false}`; collapsing it into a transport
    /// or status error would report a permission failure as success.
    Api {
        /// Cloudflare's own `errors[].code`.
        code: i64,
        /// Cloudflare's own `errors[].message`.
        message: String,
    },
    /// The request never completed: connection refused, TLS failure,
    /// timeout, or a non-2xx status with no usable Cloudflare error body.
    Transport(String),
    /// No zone the token can see is a suffix of the configured base domain,
    /// so the token cannot manage records for it.
    ZoneNotFound {
        /// The `ferrum.proxy.baseDomain` that could not be matched.
        base_domain: String,
    },
    /// A zone covering the base domain exists, but the base domain (or an
    /// ancestor of it below the zone apex) has been delegated to other
    /// nameservers with an `NS` record.
    ///
    /// This is a refusal rather than a warning because the alternative is
    /// the exact failure R1 exists to fix: Cloudflare accepts every write,
    /// the installer reports success, and not one hostname resolves --
    /// because the servers the world asks are not the ones ferrum wrote to.
    ZoneDelegated {
        /// The `ferrum.proxy.baseDomain` that cannot be served from here.
        base_domain: String,
        /// The delegated name found in the zone.
        delegated_name: String,
        /// The nameservers it was delegated to, so the operator can see
        /// where their records would actually have to go.
        nameservers: Vec<String>,
    },
    /// Cloudflare answered with a body this crate could not read as the
    /// shape its API documents.
    Malformed(String),
}

impl fmt::Display for CloudflareError {
    /// Renders the error for an operator. Never includes the API token: the
    /// token travels only in the `Authorization` header and must not reach a
    /// log line, a URL, or process argv.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CloudflareError::Api { code, message } => {
                write!(f, "Cloudflare refused the request (code {code}): {message}")
            }
            CloudflareError::Transport(detail) => {
                write!(f, "could not reach the Cloudflare API: {detail}")
            }
            CloudflareError::ZoneNotFound { base_domain } => write!(
                f,
                "no Cloudflare zone this token can see covers {base_domain}"
            ),
            CloudflareError::ZoneDelegated {
                base_domain,
                delegated_name,
                nameservers,
            } => write!(
                f,
                "{base_domain} is delegated away from this Cloudflare zone: \
                 an NS record for {delegated_name} points at {}. Records \
                 written here would be accepted and would resolve nowhere.",
                if nameservers.is_empty() {
                    "other nameservers".to_string()
                } else {
                    nameservers.join(", ")
                }
            ),
            CloudflareError::Malformed(detail) => {
                write!(f, "Cloudflare returned an unexpected response: {detail}")
            }
        }
    }
}

impl std::error::Error for CloudflareError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_renders_as_cloudflares_own_content_value() {
        let target = RecordTarget::A(Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(target.record_type(), "A");
        assert_eq!(target.to_string(), "203.0.113.7");
    }

    #[test]
    fn a_cname_target_renders_as_the_hostname() {
        let target = RecordTarget::Cname("host.example.net".to_string());
        assert_eq!(target.record_type(), "CNAME");
        assert_eq!(target.to_string(), "host.example.net");
    }

    #[test]
    fn an_api_refusal_reports_cloudflares_own_code_and_message() {
        let err = CloudflareError::Api {
            code: 9109,
            message: "Invalid access token".to_string(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("9109"), "{rendered}");
        assert!(rendered.contains("Invalid access token"), "{rendered}");
    }

    #[test]
    fn a_delegation_refusal_names_the_nameservers_the_records_would_need_to_go_to() {
        let err = CloudflareError::ZoneDelegated {
            base_domain: "home.example.com".to_string(),
            delegated_name: "home.example.com".to_string(),
            nameservers: vec!["ns1.elsewhere.net".to_string()],
        };
        let rendered = err.to_string();
        assert!(rendered.contains("home.example.com"), "{rendered}");
        assert!(rendered.contains("ns1.elsewhere.net"), "{rendered}");
        assert!(rendered.contains("resolve nowhere"), "{rendered}");
    }

    #[test]
    fn a_secret_redacts_itself_rather_than_trusting_every_future_call_site() {
        let secret = Secret::new("a-real-looking-token".to_string());
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{secret:?}").contains("a-real-looking-token"));
        assert_eq!(secret.expose(), "a-real-looking-token");
    }

    #[test]
    fn a_missing_zone_names_the_base_domain_that_could_not_be_matched() {
        let err = CloudflareError::ZoneNotFound {
            base_domain: "home.example.com".to_string(),
        };
        assert!(err.to_string().contains("home.example.com"));
    }
}
