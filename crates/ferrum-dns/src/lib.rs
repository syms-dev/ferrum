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
//! **What is not here yet.** The `Client` and its zone/ownership/record
//! logic are the next story's work (R1-S2); this file carries only the data
//! types that seam is expressed in, so that story adds behaviour rather than
//! re-deciding vocabulary. Those modules are not declared here because a
//! `mod` declaration without its file does not compile and those files are
//! outside this story's scope.

use std::fmt;
use std::net::Ipv4Addr;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Cloudflare's opaque record identifier.
    pub id: String,
    /// The fully qualified record name, e.g. `auth.example.com`.
    pub name: String,
    /// Where the record points.
    pub target: RecordTarget,
    /// Cloudflare's orange-cloud proxying. ferrum always writes `false`:
    /// proxying makes every request arrive from a Cloudflare edge address,
    /// which turns the LAN allow-list in front of `lan` apps into a total
    /// outage, and it routes Plex/Jellyfin streams through that edge.
    pub proxied: bool,
    /// Whether [`OWNERSHIP_MARKER`] was present on this record.
    pub owned_by_ferrum: bool,
}

/// Why a Cloudflare call did not produce the answer the caller needed.
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
    fn a_missing_zone_names_the_base_domain_that_could_not_be_matched() {
        let err = CloudflareError::ZoneNotFound {
            base_domain: "home.example.com".to_string(),
        };
        assert!(err.to_string().contains("home.example.com"));
    }
}
