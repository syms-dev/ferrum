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
//!
//! **[`ZoneStatus`] is the same failure one door further out, and it is the
//! door the original incident walked through.** [`delegation_away`] can only
//! see an `NS` record that exists *inside* the Cloudflare zone. The
//! commonest new-domain state produces no such record at all: the operator
//! adds the zone to Cloudflare, never switches the registrar's nameservers,
//! and Cloudflare reports `status: "pending"`. Zone resolution succeeds,
//! every write succeeds, and a query aimed at the zone's own nameservers --
//! which is what `verify_authoritative` does, deliberately, to dodge a
//! recursive resolver's negative cache -- gets the correct answer, because
//! Cloudflare really does hold the record. Nobody else on the internet ever
//! asks Cloudflare, so the name resolves nowhere. That is
//! "`auth.thesyms.ca` did not resolve while the installer reported success",
//! reproduced exactly.
//!
//! So the zone's `status` is parsed rather than dropped, and carried to the
//! caller on [`ResolvedZone`] -- a struct rather than a bare [`Zone`]
//! specifically so a caller cannot fail to receive it. What to *do* about a
//! non-serving status is the caller's decision rather than this crate's,
//! because the two callers legitimately differ: the installer can still
//! refuse while the disk is untouched, whereas a post-switch apply must
//! never turn a completed switch into a failure. This module supplies the
//! fact and the sentence; the policy lives where the operator is.

use std::fmt;

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

/// Whether a zone's Cloudflare lifecycle state means the world's resolvers
/// will actually reach Cloudflare for it.
///
/// This is the question `status` is being read to answer, and it has three
/// answers rather than two because the remedies differ: one state needs
/// nothing, one needs waiting (or a registrar change already in flight),
/// and one needs the operator to make a different decision entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneService {
    /// Cloudflare is authoritative for this zone right now.
    Serving,
    /// Cloudflare holds the zone but the internet is not being sent here
    /// yet. Records written now are correct and invisible. This resolves
    /// itself once the registrar's nameservers point at Cloudflare and the
    /// change propagates, so it is a disclosure rather than a refusal.
    NotYetServing,
    /// Cloudflare will not serve this zone, and no amount of waiting
    /// changes that. Writing records here is pointless work with a
    /// confident success report attached.
    NeverServing,
}

/// Cloudflare's own `status` field for a zone.
///
/// The variants are Cloudflare's documented values verbatim. `Unreported`
/// and `Unrecognized` are this crate's, and they are deliberately different
/// things: a value we have never heard of is a fact worth telling the
/// operator about, while a *missing* field is not a fact at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneStatus {
    /// Cloudflare is authoritative: the registrar's nameservers point here.
    Active,
    /// The zone exists in Cloudflare and the registrar's nameservers do not
    /// point at it yet. **This is the state the R1 incident was in.**
    Pending,
    /// Cloudflare is still setting the zone up; it has not reached
    /// `Pending` yet, let alone `Active`.
    Initializing,
    /// The zone was active and its nameservers have since been pointed
    /// somewhere else.
    Moved,
    /// The zone has been deleted from the account.
    Deleted,
    /// The zone has been disabled.
    Deactivated,
    /// Cloudflare reported a status this crate does not model. Disclosed
    /// rather than assumed good: an unknown state is exactly the kind of
    /// thing that turns out to mean "not serving".
    Unrecognized(String),
    /// The envelope carried no `status` at all.
    ///
    /// Treated as [`ZoneService::Serving`] on purpose. Cloudflare's live API
    /// always sends `status`, so silence here comes from a fixture or an
    /// intermediary, and manufacturing a warning out of it would put an
    /// unactionable line in front of every operator -- which is how the real
    /// warning gets skimmed past.
    Unreported,
}

impl ZoneStatus {
    /// Reads Cloudflare's `status` string.
    ///
    /// # Arguments
    /// * `raw` - the wire value, in any case.
    ///
    /// # Returns
    /// The matching variant, or [`ZoneStatus::Unrecognized`] carrying the
    /// value as Cloudflare sent it so an operator can look it up.
    #[must_use]
    pub fn from_wire(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "active" => ZoneStatus::Active,
            "pending" => ZoneStatus::Pending,
            "initializing" => ZoneStatus::Initializing,
            "moved" => ZoneStatus::Moved,
            "deleted" => ZoneStatus::Deleted,
            "deactivated" => ZoneStatus::Deactivated,
            other => ZoneStatus::Unrecognized(other.to_string()),
        }
    }

    /// What this status means for whether records written here resolve.
    #[must_use]
    pub fn service(&self) -> ZoneService {
        match self {
            ZoneStatus::Active | ZoneStatus::Unreported => ZoneService::Serving,
            ZoneStatus::Pending | ZoneStatus::Initializing | ZoneStatus::Unrecognized(_) => {
                ZoneService::NotYetServing
            }
            ZoneStatus::Moved | ZoneStatus::Deleted | ZoneStatus::Deactivated => {
                ZoneService::NeverServing
            }
        }
    }
}

impl fmt::Display for ZoneStatus {
    /// Renders Cloudflare's own word, so an operator can match it against
    /// what their dashboard shows them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZoneStatus::Active => f.write_str("active"),
            ZoneStatus::Pending => f.write_str("pending"),
            ZoneStatus::Initializing => f.write_str("initializing"),
            ZoneStatus::Moved => f.write_str("moved"),
            ZoneStatus::Deleted => f.write_str("deleted"),
            ZoneStatus::Deactivated => f.write_str("deactivated"),
            ZoneStatus::Unrecognized(raw) => write!(f, "{raw}"),
            ZoneStatus::Unreported => f.write_str("not reported"),
        }
    }
}

/// A zone, together with the Cloudflare lifecycle state that decides
/// whether anything written into it will ever be seen.
///
/// The two travel together rather than the status being a second lookup
/// because the whole defect class is a caller that had the zone and never
/// asked the question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedZone {
    /// The zone itself.
    pub zone: Zone,
    /// Cloudflare's `status` for it.
    pub status: ZoneStatus,
}

impl ResolvedZone {
    /// The sentence an operator needs when this zone is not serving, or
    /// `None` when it is.
    ///
    /// One wording in one place, used by the installer's pre-erase gate and
    /// by the apply's DNS step, so the same condition never gets described
    /// two different ways to the same person.
    ///
    /// # Arguments
    /// * `base_domain` - `ferrum.proxy.baseDomain`, so the sentence names
    ///   the name that will not resolve rather than the zone apex.
    ///
    /// # Returns
    /// A sentence naming the status, what it means, and the one action that
    /// fixes it -- pointing the registrar's nameservers at the servers
    /// Cloudflare listed, which are named inline so the operator does not
    /// have to go and find them.
    #[must_use]
    pub fn advisory(&self, base_domain: &str) -> Option<String> {
        let nameservers = if self.zone.nameservers.is_empty() {
            "the nameservers Cloudflare lists on that zone's Overview page".to_string()
        } else {
            self.zone.nameservers.join(", ")
        };
        match self.status.service() {
            ZoneService::Serving => None,
            ZoneService::NotYetServing => Some(format!(
                "Cloudflare reports the zone {} as \"{}\", not \"active\": it holds the \
                 zone but the internet is not being sent there yet. ferrum's records will \
                 be written correctly and {base_domain} will still resolve nowhere for \
                 anyone, including you. Point your domain registrar's nameservers at {}, \
                 then re-check the zone in the Cloudflare dashboard -- it flips to \
                 \"active\" on its own once the change propagates.",
                self.zone.name, self.status, nameservers
            )),
            ZoneService::NeverServing => Some(format!(
                "Cloudflare reports the zone {} as \"{}\", so it will not answer for \
                 {base_domain} at all. Records written here would be accepted and would \
                 resolve nowhere, and waiting does not change that. Re-add or re-enable \
                 the zone in the Cloudflare dashboard and point your registrar's \
                 nameservers at {}, or choose a base domain in a zone this account \
                 actually serves.",
                self.zone.name, self.status, nameservers
            )),
        }
    }
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
    /// Cloudflare's zone lifecycle state. Parsed as a bare string and
    /// mapped in [`ZoneStatus::from_wire`] rather than deserialized into the
    /// enum directly: an unknown value must become
    /// [`ZoneStatus::Unrecognized`] and be disclosed, not fail the whole
    /// listing and lock the operator out of a zone that works.
    #[serde(default)]
    pub(crate) status: Option<String>,
}

impl From<ZoneJson> for ResolvedZone {
    /// Converts a wire zone into the crate's model, keeping the status.
    fn from(json: ZoneJson) -> Self {
        let status = json
            .status
            .as_deref()
            .map_or(ZoneStatus::Unreported, ZoneStatus::from_wire);
        ResolvedZone {
            zone: Zone {
                id: json.id,
                name: json.name,
                nameservers: json.name_servers,
            },
            status,
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
/// `base_domain`, with the Cloudflare lifecycle status it was listed with.
///
/// # Errors
/// [`CloudflareError::ZoneNotFound`] when no visible zone covers the base
/// domain -- which is what an operator sees when the token is scoped to a
/// different domain, or scoped to no zone at all.
pub fn select(base_domain: &str, zones: &[ResolvedZone]) -> Result<ResolvedZone, CloudflareError> {
    zones
        .iter()
        .filter(|resolved| covers(base_domain, &resolved.zone.name))
        .max_by_key(|resolved| normalize_domain(&resolved.zone.name).len())
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

    /// A listed zone Cloudflare is already serving, which is what every
    /// selection test is about. Status-specific behaviour gets its own
    /// fixtures below.
    fn listed(name: &str) -> ResolvedZone {
        ResolvedZone {
            zone: zone(name),
            status: ZoneStatus::Active,
        }
    }

    #[test]
    fn an_apex_base_domain_resolves_to_its_own_zone() {
        let zones = vec![listed("example.com"), listed("other.net")];
        assert_eq!(
            select("example.com", &zones).expect("a zone").zone.name,
            "example.com"
        );
    }

    /// D-06's whole reason for existing: `options.nix` documents a
    /// subdomain as the example base domain, and a name lookup would reject
    /// a correctly scoped token for it.
    #[test]
    fn a_subdomain_base_domain_resolves_to_its_parent_zone() {
        let zones = vec![listed("example.com")];
        assert_eq!(
            select("home.example.com", &zones)
                .expect("a zone")
                .zone
                .name,
            "example.com"
        );
    }

    #[test]
    fn the_longest_matching_zone_wins_over_its_parent() {
        let zones = vec![listed("example.com"), listed("home.example.com")];
        assert_eq!(
            select("app.home.example.com", &zones)
                .expect("a zone")
                .zone
                .name,
            "home.example.com",
            "records written into the parent would be shadowed by the \
             delegation to the child and resolve to nothing"
        );
    }

    #[test]
    fn a_zone_that_is_only_a_string_suffix_does_not_match() {
        let zones = vec![listed("example.com")];
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
        let zones = vec![listed("somewhere-else.net")];
        let error = select("example.com", &zones).expect_err("no zone covers it");
        assert!(error.to_string().contains("example.com"), "{error}");
    }

    #[test]
    fn zone_matching_ignores_case_and_a_trailing_dot() {
        let zones = vec![listed("Example.COM.")];
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
            "status": "active",
            "name_servers": ["amber.ns.cloudflare.com", "bob.ns.cloudflare.com"],
        }))
        .expect("a Cloudflare-shaped zone parses");
        let model: ResolvedZone = json.into();
        assert_eq!(model.zone.id, "z1");
        assert_eq!(model.zone.nameservers.len(), 2);
        assert_eq!(model.status, ZoneStatus::Active);
    }

    #[test]
    fn a_zone_json_without_nameservers_still_parses() {
        let json: ZoneJson =
            serde_json::from_value(serde_json::json!({ "id": "z1", "name": "example.com" }))
                .expect("a provisioning zone parses");
        assert!(ResolvedZone::from(json).zone.nameservers.is_empty());
    }

    /// The single most common new-domain state, and the one the whole of
    /// this requirement exists for: the zone is in Cloudflare, the
    /// registrar still points somewhere else, and every other signal --
    /// zone resolution, the record writes, a query aimed at Cloudflare's
    /// own nameservers -- comes back green while nothing resolves for
    /// anyone.
    #[test]
    fn a_pending_zone_envelope_is_parsed_as_pending_and_not_serving() {
        let json: ZoneJson = serde_json::from_value(serde_json::json!({
            "id": "z1",
            "name": "thesyms.ca",
            "status": "pending",
            "name_servers": ["amber.ns.cloudflare.com", "bob.ns.cloudflare.com"],
        }))
        .expect("a pending zone parses");
        let resolved: ResolvedZone = json.into();
        assert_eq!(resolved.status, ZoneStatus::Pending);
        assert_eq!(resolved.status.service(), ZoneService::NotYetServing);
    }

    #[test]
    fn a_pending_zone_tells_the_operator_to_switch_the_registrars_nameservers() {
        let resolved = ResolvedZone {
            zone: Zone {
                id: "z1".to_string(),
                name: "thesyms.ca".to_string(),
                nameservers: vec![
                    "amber.ns.cloudflare.com".to_string(),
                    "bob.ns.cloudflare.com".to_string(),
                ],
            },
            status: ZoneStatus::Pending,
        };
        let advisory = resolved
            .advisory("auth.thesyms.ca")
            .expect("a pending zone is disclosed");
        assert!(advisory.contains("pending"), "{advisory}");
        assert!(advisory.contains("auth.thesyms.ca"), "{advisory}");
        assert!(advisory.contains("registrar"), "{advisory}");
        assert!(advisory.contains("amber.ns.cloudflare.com"), "{advisory}");
        assert!(advisory.contains("resolve nowhere"), "{advisory}");
    }

    #[test]
    fn an_active_zone_has_nothing_to_disclose() {
        let resolved = ResolvedZone {
            zone: zone("example.com"),
            status: ZoneStatus::Active,
        };
        assert_eq!(resolved.advisory("home.example.com"), None);
    }

    /// A status of `moved`, `deleted` or `deactivated` cannot become
    /// `active` by waiting, so the remedy sentence must not tell the
    /// operator to wait.
    #[test]
    fn a_terminal_status_is_never_serving_and_says_waiting_will_not_help() {
        for status in [
            ZoneStatus::Moved,
            ZoneStatus::Deleted,
            ZoneStatus::Deactivated,
        ] {
            assert_eq!(status.service(), ZoneService::NeverServing, "{status}");
            let resolved = ResolvedZone {
                zone: zone("example.com"),
                status,
            };
            let advisory = resolved
                .advisory("home.example.com")
                .expect("a terminal status is disclosed");
            assert!(
                advisory.contains("waiting does not change that"),
                "{advisory}"
            );
        }
    }

    /// An unknown status is Cloudflare telling us something; refusing the
    /// whole listing over it would lock an operator out of a zone that may
    /// well work, and assuming it is fine is the defect this parses for.
    #[test]
    fn an_unknown_status_is_disclosed_rather_than_assumed_good_or_fatal() {
        let status = ZoneStatus::from_wire("Some-Future-State");
        assert_eq!(
            status,
            ZoneStatus::Unrecognized("some-future-state".to_string())
        );
        assert_eq!(status.service(), ZoneService::NotYetServing);
        assert_eq!(status.to_string(), "some-future-state");
    }

    /// Cloudflare's live API always sends `status`. Silence comes from a
    /// fixture or an intermediary, and a warning invented from silence is
    /// the one that trains operators to skim past the real one.
    #[test]
    fn an_absent_status_is_not_turned_into_a_warning() {
        let json: ZoneJson =
            serde_json::from_value(serde_json::json!({ "id": "z1", "name": "example.com" }))
                .expect("a zone with no status parses");
        let resolved: ResolvedZone = json.into();
        assert_eq!(resolved.status, ZoneStatus::Unreported);
        assert_eq!(resolved.advisory("example.com"), None);
    }

    #[test]
    fn every_status_cloudflare_documents_is_recognised() {
        for (raw, expected) in [
            ("active", ZoneStatus::Active),
            ("pending", ZoneStatus::Pending),
            ("initializing", ZoneStatus::Initializing),
            ("moved", ZoneStatus::Moved),
            ("deleted", ZoneStatus::Deleted),
            ("deactivated", ZoneStatus::Deactivated),
        ] {
            assert_eq!(ZoneStatus::from_wire(raw), expected, "{raw}");
            assert_eq!(
                ZoneStatus::from_wire(&raw.to_uppercase()),
                expected,
                "{raw}"
            );
        }
    }
}
