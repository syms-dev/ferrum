//! Which Cloudflare zone a base domain belongs to, and whether writing into
//! that zone would actually be seen by the internet.
//!
//! **Why not `GET /zones?name=<baseDomain>` (decision D-06).**
//! `modules/core/options.nix:182-186` documents `ferrum.proxy.baseDomain`
//! with `example = "home.example.com"` -- a subdomain, not an apex. A lookup
//! by name asks Cloudflare for a zone literally called `home.example.com`,
//! gets an empty list from a token correctly scoped to `example.com`, and
//! the A5 prompt then rejects a **working** credential. So [`select`] lists
//! every zone the token can see and takes the one whose name is the longest
//! label-aligned suffix of the base domain.
//!
//! **Longest, not merely matching.** A token that can see both `example.com`
//! and `home.example.com` must write into `home.example.com`: records
//! written into the parent for a name the child is authoritative for are
//! shadowed by the delegation and resolve to nothing.
//!
//! **Label-aligned, not string-suffix.** `example.com` is a string suffix of
//! `notexample.com`, and treating that as a match would write an operator's
//! records into a zone for a different domain entirely.
//!
//! **The delegation check ([`delegation_away`]) is the same failure caught
//! one level deeper,** and it is the one R1 exists to prevent. If the
//! resolved zone contains an `NS` record at the base domain or at an
//! ancestor of it, that subtree has been delegated to someone else's
//! nameservers. Cloudflare will happily accept the record -- the API call
//! succeeds, the installer reports success -- and the name resolves
//! nowhere, because the authoritative servers for it are not Cloudflare's.
//! That is exactly the shape of the incident this requirement exists for, so
//! resolution refuses rather than proceeding.
//!
//! The check uses the zone's own `NS` records rather than a live DNS query
//! deliberately: it needs no resolver, no network path beyond the Cloudflare
//! API the caller is already using, and it works from the installer's
//! container. The complementary live check against the zone's authoritative
//! nameservers is `verify_authoritative`, which belongs to R1-S3.

use serde::Deserialize;

use crate::{CloudflareError, Zone};

/// One `NS` record found inside a zone: a subtree handed to other
/// nameservers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The delegated name, e.g. `home.example.com`.
    pub name: String,
    /// One nameserver the subtree was delegated to. Cloudflare returns one
    /// record per nameserver, so a delegation with four nameservers appears
    /// as four [`Delegation`] values sharing a `name`.
    pub nameserver: String,
}

/// One zone as Cloudflare's JSON describes it.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ZoneJson {
    pub(crate) id: String,
    pub(crate) name: String,
    /// Cloudflare's own spelling. Absent on a zone that has not finished
    /// provisioning, which is not an error here -- it only means the
    /// post-apply verification in R1-S3 has no servers to ask.
    #[serde(default, rename = "name_servers")]
    pub(crate) name_servers: Vec<String>,
}

impl From<ZoneJson> for Zone {
    /// Converts a wire zone into the crate's model.
    fn from(json: ZoneJson) -> Self {
        Zone {
            id: json.id,
            name: json.name,
            nameservers: json.name_servers,
        }
    }
}

/// Normalizes a DNS name for comparison.
///
/// # Arguments
/// * `domain` - a name in any case, with or without a trailing dot.
///
/// # Returns
/// The name lowercased with any trailing dots removed. DNS names are
/// case-insensitive and `example.com` and `example.com.` denote the same
/// name, so comparing them literally would call two spellings of one zone
/// two different zones. This is *not* the loose matching the ownership
/// marker forbids: that marker is an opaque string, while these are names
/// with defined equality.
#[must_use]
pub fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `candidate` is `domain` itself or a parent zone of it.
///
/// # Arguments
/// * `domain` - the base domain, e.g. `home.example.com`.
/// * `candidate` - a zone or delegation name, e.g. `example.com`.
///
/// # Returns
/// `true` when the two names are equal, or when `candidate` is a
/// label-aligned suffix of `domain`. `example.com` covers
/// `home.example.com` but not `notexample.com`.
#[must_use]
pub fn covers(domain: &str, candidate: &str) -> bool {
    let domain = normalize_domain(domain);
    let candidate = normalize_domain(candidate);
    if candidate.is_empty() {
        return false;
    }
    domain == candidate || domain.ends_with(&format!(".{candidate}"))
}

/// Picks the zone that should hold the base domain's records.
///
/// # Arguments
/// * `base_domain` - `ferrum.proxy.baseDomain`.
/// * `zones` - every zone the token can see, from a full paginated listing.
///   A truncated listing can hide the correct zone and pick a parent, which
///   is the failure [`delegation_away`] then has to catch.
///
/// # Returns
/// The zone whose name is the longest label-aligned suffix of
/// `base_domain`.
///
/// # Errors
/// [`CloudflareError::ZoneNotFound`] when no visible zone covers the base
/// domain -- which is what an operator sees when the token is scoped to a
/// different domain, or scoped to no zone at all.
pub fn select(base_domain: &str, zones: &[Zone]) -> Result<Zone, CloudflareError> {
    zones
        .iter()
        .filter(|zone| covers(base_domain, &zone.name))
        .max_by_key(|zone| normalize_domain(&zone.name).len())
        .cloned()
        .ok_or_else(|| CloudflareError::ZoneNotFound {
            base_domain: base_domain.to_string(),
        })
}

/// Finds a delegation that would make records written into `zone`
/// unreachable.
///
/// # Arguments
/// * `base_domain` - `ferrum.proxy.baseDomain`.
/// * `zone` - the zone [`select`] resolved.
/// * `delegations` - every `NS` record in that zone.
///
/// # Returns
/// `Some((name, nameservers))` for the most specific delegation covering the
/// base domain, or `None` when the zone really is authoritative for it.
///
/// A zone's own apex `NS` records name Cloudflare's servers for the zone
/// itself and are not a delegation away from it, so they are excluded.
#[must_use]
pub fn delegation_away(
    base_domain: &str,
    zone: &Zone,
    delegations: &[Delegation],
) -> Option<(String, Vec<String>)> {
    let apex = normalize_domain(&zone.name);
    let offending = delegations
        .iter()
        .filter(|d| normalize_domain(&d.name) != apex && covers(base_domain, &d.name))
        .max_by_key(|d| normalize_domain(&d.name).len())?;

    let name = normalize_domain(&offending.name);
    let nameservers = delegations
        .iter()
        .filter(|d| normalize_domain(&d.name) == name)
        .map(|d| d.nameserver.clone())
        .collect();
    Some((offending.name.clone(), nameservers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(name: &str) -> Zone {
        Zone {
            id: format!("id-{name}"),
            name: name.to_string(),
            nameservers: vec!["ns1.example.net".to_string()],
        }
    }

    #[test]
    fn an_apex_base_domain_resolves_to_its_own_zone() {
        let zones = vec![zone("example.com"), zone("other.net")];
        assert_eq!(
            select("example.com", &zones).expect("a zone").name,
            "example.com"
        );
    }

    /// D-06's whole reason for existing: `options.nix` documents a
    /// subdomain as the example base domain, and a name lookup would reject
    /// a correctly scoped token for it.
    #[test]
    fn a_subdomain_base_domain_resolves_to_its_parent_zone() {
        let zones = vec![zone("example.com")];
        assert_eq!(
            select("home.example.com", &zones).expect("a zone").name,
            "example.com"
        );
    }

    #[test]
    fn the_longest_matching_zone_wins_over_its_parent() {
        let zones = vec![zone("example.com"), zone("home.example.com")];
        assert_eq!(
            select("app.home.example.com", &zones).expect("a zone").name,
            "home.example.com",
            "records written into the parent would be shadowed by the \
             delegation to the child and resolve to nothing"
        );
    }

    #[test]
    fn a_zone_that_is_only_a_string_suffix_does_not_match() {
        let zones = vec![zone("example.com")];
        let error = select("notexample.com", &zones).expect_err("not a label-aligned suffix");
        assert_eq!(
            error,
            CloudflareError::ZoneNotFound {
                base_domain: "notexample.com".to_string()
            }
        );
    }

    #[test]
    fn no_visible_zone_names_the_base_domain_in_the_error() {
        let zones = vec![zone("somewhere-else.net")];
        let error = select("example.com", &zones).expect_err("no zone covers it");
        assert!(error.to_string().contains("example.com"), "{error}");
    }

    #[test]
    fn zone_matching_ignores_case_and_a_trailing_dot() {
        let zones = vec![zone("Example.COM.")];
        assert!(select("home.example.com", &zones).is_ok());
    }

    #[test]
    fn an_empty_zone_list_is_a_zone_not_found_not_a_panic() {
        assert!(select("example.com", &[]).is_err());
    }

    #[test]
    fn a_zone_with_no_delegations_is_authoritative() {
        assert_eq!(
            delegation_away("home.example.com", &zone("example.com"), &[]),
            None
        );
    }

    /// The failure R1 exists to prevent: the API call succeeds, the
    /// installer reports success, and the name resolves nowhere.
    #[test]
    fn a_delegation_at_the_base_domain_is_refused() {
        let delegations = vec![
            Delegation {
                name: "home.example.com".to_string(),
                nameserver: "ns1.elsewhere.net".to_string(),
            },
            Delegation {
                name: "home.example.com".to_string(),
                nameserver: "ns2.elsewhere.net".to_string(),
            },
        ];
        let (name, nameservers) =
            delegation_away("home.example.com", &zone("example.com"), &delegations)
                .expect("the delegation is detected");
        assert_eq!(name, "home.example.com");
        assert_eq!(nameservers, vec!["ns1.elsewhere.net", "ns2.elsewhere.net"]);
    }

    #[test]
    fn a_delegation_at_an_ancestor_of_the_base_domain_is_refused() {
        let delegations = vec![Delegation {
            name: "home.example.com".to_string(),
            nameserver: "ns1.elsewhere.net".to_string(),
        }];
        assert!(
            delegation_away("apps.home.example.com", &zone("example.com"), &delegations).is_some()
        );
    }

    #[test]
    fn a_delegation_of_an_unrelated_subtree_is_not_our_problem() {
        let delegations = vec![Delegation {
            name: "lab.example.com".to_string(),
            nameserver: "ns1.elsewhere.net".to_string(),
        }];
        assert_eq!(
            delegation_away("home.example.com", &zone("example.com"), &delegations),
            None
        );
    }

    /// A delegation *below* the base domain does not affect the records
    /// ferrum writes, which sit at `<app>.<baseDomain>` and not under it.
    #[test]
    fn a_delegation_below_the_base_domain_is_not_a_conflict() {
        let delegations = vec![Delegation {
            name: "deep.home.example.com".to_string(),
            nameserver: "ns1.elsewhere.net".to_string(),
        }];
        assert_eq!(
            delegation_away("home.example.com", &zone("example.com"), &delegations),
            None
        );
    }

    /// Every zone lists its own apex `NS` records. Reading those as a
    /// delegation away from itself would refuse every correctly configured
    /// zone in existence.
    #[test]
    fn the_zones_own_apex_nameservers_are_not_a_delegation() {
        let delegations = vec![Delegation {
            name: "example.com".to_string(),
            nameserver: "amber.ns.cloudflare.com".to_string(),
        }];
        assert_eq!(
            delegation_away("example.com", &zone("example.com"), &delegations),
            None
        );
        assert_eq!(
            delegation_away("home.example.com", &zone("example.com"), &delegations),
            None
        );
    }

    #[test]
    fn a_zone_json_carries_cloudflares_own_name_servers_spelling() {
        let json: ZoneJson = serde_json::from_value(serde_json::json!({
            "id": "z1",
            "name": "example.com",
            "name_servers": ["amber.ns.cloudflare.com", "bob.ns.cloudflare.com"],
        }))
        .expect("a Cloudflare-shaped zone parses");
        let model: Zone = json.into();
        assert_eq!(model.id, "z1");
        assert_eq!(model.nameservers.len(), 2);
    }

    #[test]
    fn a_zone_json_without_nameservers_still_parses() {
        let json: ZoneJson =
            serde_json::from_value(serde_json::json!({ "id": "z1", "name": "example.com" }))
                .expect("a provisioning zone parses");
        assert!(Zone::from(json).nameservers.is_empty());
    }
}
