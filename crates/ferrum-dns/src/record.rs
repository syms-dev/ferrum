//! The record model: what ferrum wants in the zone, what Cloudflare says is
//! there, and the plan that turns the first into the second without ever
//! touching a record ferrum does not own.
//!
//! **Idempotence is the property that matters.** `ferrum-apply apply` runs
//! on every switch, and the DDNS timer runs on a schedule; both call this
//! planner against a fresh listing. A second run over an unchanged zone must
//! produce no writes at all, and a run after a partial failure must complete
//! only what is missing. That is why the plan is computed from a listing
//! rather than from anything remembered between runs, and why
//! [`RecordAction::Unchanged`] is a first-class outcome rather than an
//! absence.
//!
//! **Two invariants the planner enforces rather than documents.**
//!
//! * A desired name occupied by a foreign record yields
//!   [`RecordAction::SkipForeign`] and **no create**. Creating a second A
//!   record alongside it would not "add" ferrum's answer -- Cloudflare would
//!   round-robin the two, sending roughly half of all traffic to the wrong
//!   host, which is worse than the record being absent because it looks
//!   intermittent rather than broken.
//! * A desired name occupied by a foreign record the operator **explicitly
//!   adopted** yields [`RecordAction::Adopt`] instead -- A3's *"unless the
//!   operator opts in"*. It is a separate variant from
//!   [`RecordAction::Update`] so the operator's own report cannot describe
//!   a takeover of their record with the same word it uses for correcting
//!   ferrum's. The adopting write carries [`OWNERSHIP_MARKER`], so from the
//!   next run onwards that record is simply ferrum's and takes the ordinary
//!   `Update`/`Unchanged` path with no adoption list involved.
//! * A desired name that also carries a record of a type this crate does
//!   not model yields [`RecordAction::SkipUnmodelledType`] **in addition to**
//!   that name's own action. Nothing is blocked by it -- the point is that
//!   an `AAAA` sitting beside the `A` ferrum creates must not be invisible,
//!   because the resulting IPv4/IPv6 split sends some clients to the old
//!   host and appears in no output ferrum produced.
//! * `proxied` is always written `false` (decision D-05). Cloudflare's
//!   orange cloud makes every request arrive from an edge address, which
//!   turns the LAN allow-list in front of `lan` apps into a total outage and
//!   routes Plex/Jellyfin streams through that edge. A managed record found
//!   with `proxied: true` is drift and is corrected like any other.

use serde::{Deserialize, Serialize};

use crate::ownership::{is_ferrum_marker, AdoptedNames, ManagedRecordId};
use crate::zone::normalize_domain;
use crate::{DnsRecord, RecordTarget, OWNERSHIP_MARKER};

/// One record ferrum wants to exist, as computed from the published apps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredRecord {
    /// The fully qualified name, e.g. `auth.example.com`.
    pub name: String,
    /// Where it should point.
    pub target: RecordTarget,
}

/// What reconciling one name requires.
///
/// The variants are exhaustive over the reconcile outcomes A3, A4 and A7
/// name, so a dry run can render the plan directly and an apply can execute
/// it without a second decision anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordAction {
    /// Nothing exists at this name; create it.
    Create {
        /// The fully qualified name to create.
        name: String,
        /// Where the new record points.
        target: RecordTarget,
    },
    /// A ferrum-owned record exists but does not match the desired state --
    /// a changed address, or an operator-toggled `proxied: true`.
    Update {
        /// Proof that this record is ferrum's, and the id to write to.
        record_id: ManagedRecordId,
        /// The fully qualified name, for reporting.
        name: String,
        /// Where the record points today, so the dry run can show the
        /// change rather than just announcing one.
        current: RecordTarget,
        /// Where it should point.
        target: RecordTarget,
    },
    /// A ferrum-owned record already matches; no call is made.
    Unchanged {
        /// Proof that this record is ferrum's, and its id.
        record_id: ManagedRecordId,
        /// The fully qualified name.
        name: String,
    },
    /// A ferrum-owned record exists for a name nothing wants any more --
    /// the app was disabled. This is the only variant that removes anything.
    Delete {
        /// Proof that this record is ferrum's, and the id to remove.
        record_id: ManagedRecordId,
        /// The fully qualified name.
        name: String,
    },
    /// A record ferrum does not own occupies a name ferrum wants, and the
    /// operator explicitly adopted that name (A3's opt-in half).
    ///
    /// Distinct from [`RecordAction::Update`] on purpose: this one writes
    /// over a record the operator placed, which is exactly the act A3
    /// forbids by default. Keeping it visible as its own variant means a
    /// report, a log line and a future `match` all have to acknowledge it,
    /// rather than it disappearing into the ordinary update count.
    Adopt {
        /// Proof that the operator named this exact record, and the id to
        /// write to.
        record_id: ManagedRecordId,
        /// The fully qualified name being taken over.
        name: String,
        /// Where the operator's record points today, so the report can say
        /// what was replaced.
        current: RecordTarget,
        /// Where ferrum will point it.
        target: RecordTarget,
    },
    /// A record ferrum does not own occupies a name ferrum wants (A3). It
    /// is reported and left alone; adopting it is the operator's call.
    SkipForeign {
        /// The fully qualified name that is already taken.
        name: String,
        /// Where the operator's record points, so the report can say what
        /// would have been overwritten.
        current: RecordTarget,
        /// Where ferrum would have pointed it.
        wanted: RecordTarget,
    },
    /// A record of a type ferrum does not model shares a name ferrum wants.
    ///
    /// Additive and never blocking: ferrum still creates or corrects its own
    /// `A`/`CNAME` at that name. The variant exists because the alternative
    /// is silence, and silence here has a specific shape -- an operator with
    /// an existing `AAAA` at `plex.example.com` gets ferrum's `A` beside it
    /// and a dry run that never mentioned the other record. Half the clients
    /// on the network then reach the old address over IPv6 and the split is
    /// invisible in every output ferrum produced.
    SkipUnmodelledType {
        /// The fully qualified name shared with a wanted record.
        name: String,
        /// Cloudflare's own type string for the record found there, e.g.
        /// `AAAA`.
        record_type: String,
    },
}

/// A record at a wanted name whose type this crate has no model for.
///
/// Only ever produced by [`Client::list_records`], and only disclosed by the
/// planner when it shares a name with a desired record. It carries no
/// content and no id: ferrum will not read it, write it, or delete it, and
/// carrying the means to would be carrying a capability nothing needs.
///
/// [`Client::list_records`]: crate::client::Client::list_records
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmodelledRecord {
    pub(crate) name: String,
    pub(crate) record_type: String,
}

impl UnmodelledRecord {
    /// The fully qualified record name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Cloudflare's own type string, e.g. `AAAA`, `MX`, `TXT`.
    #[must_use]
    pub fn record_type(&self) -> &str {
        &self.record_type
    }
}

/// One whole listing of a zone: what ferrum can model, and what it cannot.
///
/// The two halves travel together because separating them is exactly the
/// defect this type was added for. A planner given only the modelled half
/// cannot tell "nothing is at this name" from "something ferrum does not
/// understand is at this name", and it answers both with a create.
///
/// There is no public constructor: a listing comes from
/// [`Client::list_records`] or it does not exist, which is the same
/// discipline [`DnsRecord`] carries and for the same reason.
///
/// [`Client::list_records`]: crate::client::Client::list_records
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZoneListing {
    pub(crate) records: Vec<DnsRecord>,
    pub(crate) unmodelled: Vec<UnmodelledRecord>,
}

impl ZoneListing {
    /// Sorts one page of wire records into the two halves.
    pub(crate) fn from_wire(wire: Vec<RecordJson>) -> Self {
        let mut listing = ZoneListing::default();
        for raw in wire {
            match raw.classify() {
                Listed::Modelled(record) => listing.records.push(record),
                Listed::Unmodelled(other) => listing.unmodelled.push(other),
                Listed::Ignored => {}
            }
        }
        listing
    }

    /// Every `A` and `CNAME` record in the zone.
    #[must_use]
    pub fn records(&self) -> &[DnsRecord] {
        &self.records
    }

    /// Every record of a type this crate does not model, excluding the
    /// `_acme-challenge` `TXT` records lego owns.
    #[must_use]
    pub fn unmodelled(&self) -> &[UnmodelledRecord] {
        &self.unmodelled
    }
}

/// What one wire record turns into.
pub(crate) enum Listed {
    /// An `A` or `CNAME` this crate models.
    Modelled(DnsRecord),
    /// A type this crate does not model, worth disclosing if it collides.
    Unmodelled(UnmodelledRecord),
    /// Not ferrum's business and not a collision either: the
    /// `_acme-challenge` `TXT` records lego creates and removes during an
    /// ACME DNS-01 challenge. Disclosing them would report ferrum's own
    /// certificate machinery to the operator as a foreign record.
    Ignored,
}

/// The name prefix lego writes its ACME DNS-01 challenge records under.
const ACME_CHALLENGE_PREFIX: &str = "_acme-challenge.";

/// The body ferrum sends when creating or updating a record.
///
/// A named struct rather than an ad-hoc `serde_json::json!` map, so the
/// fields that carry an invariant -- `proxied: false` and the ownership
/// `comment` -- cannot be dropped at one call site while surviving at
/// another.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RecordWrite {
    /// Cloudflare's record type, `A` or `CNAME`.
    #[serde(rename = "type")]
    pub record_type: &'static str,
    /// The fully qualified record name.
    pub name: String,
    /// The address or hostname the record points at.
    pub content: String,
    /// Seconds; `1` is Cloudflare's "automatic" TTL. Records ferrum manages
    /// may change when the public address changes, and the DDNS updater's
    /// correction is only as fast as the TTL lets it be.
    pub ttl: u32,
    /// Always `false`; see this module's header.
    pub proxied: bool,
    /// [`OWNERSHIP_MARKER`]. This is the entire ownership mechanism: if it
    /// is not written here, ferrum cannot recognise its own record on the
    /// next run and will treat it as the operator's.
    pub comment: &'static str,
}

/// Cloudflare's automatic TTL.
const AUTOMATIC_TTL: u32 = 1;

impl RecordWrite {
    /// Builds the write body for a record ferrum owns.
    ///
    /// # Arguments
    /// * `name` - the fully qualified record name.
    /// * `target` - where the record should point.
    ///
    /// # Returns
    /// A body with `proxied: false` and the ownership marker already set.
    #[must_use]
    pub fn new(name: &str, target: &RecordTarget) -> Self {
        RecordWrite {
            record_type: target.record_type(),
            name: name.to_string(),
            content: target.to_string(),
            ttl: AUTOMATIC_TTL,
            proxied: false,
            comment: OWNERSHIP_MARKER,
        }
    }
}

/// One record as Cloudflare's JSON describes it.
///
/// Kept separate from [`DnsRecord`] because the wire shape carries fields
/// this crate has no opinion about and a `type`/`content` pair that only
/// becomes a [`RecordTarget`] after validation.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RecordJson {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) record_type: String,
    pub(crate) content: String,
    #[serde(default)]
    pub(crate) proxied: bool,
    #[serde(default)]
    pub(crate) comment: Option<String>,
}

impl RecordJson {
    /// Converts a wire record into the crate's model.
    ///
    /// # Returns
    /// `Some(record)` for an `A` with a parseable IPv4 address or a `CNAME`;
    /// `None` for every other type and for an `A` whose content is not an
    /// IPv4 address.
    ///
    /// Skipping rather than failing is deliberate: a real zone holds MX,
    /// TXT and NS records, including the `_acme-challenge` TXT records lego
    /// creates and removes. Treating those as an error would make every
    /// listing fail on a zone that is working perfectly, and treating them
    /// as records would put lego's entries inside ferrum's ownership
    /// partition. They are neither ferrum's business nor a problem.
    pub(crate) fn into_model(self) -> Option<DnsRecord> {
        let target = match self.record_type.as_str() {
            "A" => RecordTarget::A(self.content.parse().ok()?),
            "CNAME" => RecordTarget::Cname(self.content),
            _ => return None,
        };
        Some(DnsRecord {
            id: self.id,
            name: self.name,
            target,
            proxied: self.proxied,
            owned_by_ferrum: is_ferrum_marker(self.comment.as_deref()),
        })
    }

    /// Sorts a wire record into the three things a listing can hold.
    ///
    /// # Returns
    /// [`Listed::Modelled`] for a usable `A` or `CNAME`; [`Listed::Ignored`]
    /// for lego's `_acme-challenge` `TXT` records, which are ferrum's own
    /// certificate machinery rather than the operator's zone; and
    /// [`Listed::Unmodelled`] for everything else, so a type this crate
    /// cannot reconcile can still be disclosed when it shares a name with a
    /// record ferrum wants.
    pub(crate) fn classify(self) -> Listed {
        if self.record_type == "TXT" && self.name.starts_with(ACME_CHALLENGE_PREFIX) {
            return Listed::Ignored;
        }
        let record_type = self.record_type.clone();
        let name = self.name.clone();
        match self.into_model() {
            Some(record) => Listed::Modelled(record),
            None => Listed::Unmodelled(UnmodelledRecord { name, record_type }),
        }
    }
}

/// Computes the reconcile plan for a zone.
///
/// # Arguments
/// * `desired` - every record ferrum wants, from the published-app set.
/// * `existing` - the zone as one [`crate::client::Client::list_records`]
///   call saw it. It must be the **whole** listing: a truncated one makes an
///   existing record look absent, and the plan then creates a duplicate.
///
/// # Returns
/// One action per desired name -- plus a [`RecordAction::SkipUnmodelledType`]
/// for each record of another type sharing that name -- followed by a
/// [`RecordAction::Delete`] for each ferrum-owned record no longer wanted.
/// Records that are neither wanted nor ferrum's produce no action at all --
/// they are the operator's zone, and ferrum is a guest in it.
#[must_use]
pub fn plan(desired: &[DesiredRecord], existing: &ZoneListing) -> Vec<RecordAction> {
    plan_with_adoptions(desired, existing, &AdoptedNames::none())
}

/// Computes the reconcile plan, honouring the names the operator explicitly
/// adopted (A3's opt-in half).
///
/// This is the whole public surface of adoption: there is no way to obtain a
/// [`ManagedRecordId`] for a foreign record except by passing an
/// [`AdoptedNames`] set that names it here. A caller holding a client, a zone
/// and a listing still cannot write to the operator's record -- it has to go
/// through this function, with a name the operator actually gave.
///
/// # Arguments
/// * `desired` - every record ferrum wants, from the published-app set.
/// * `existing` - the **whole** listing, as [`plan`] requires, including the
///   records of other types it carries alongside the A/CNAMEs.
/// * `adopted` - the names the operator handed to ferrum at the install gate,
///   carried to the host in `ferrum.proxy.dns.adoptedNames`. Matching is per
///   name: a set containing `plex.example.com` changes nothing about
///   `sonarr.example.com`.
///
/// # Returns
/// The same plan as [`plan`], except that a desired name occupied by a
/// foreign record the operator adopted becomes [`RecordAction::Adopt`]
/// instead of [`RecordAction::SkipForeign`]. Every other guarantee is
/// unchanged -- in particular a foreign record at a name nobody adopted is
/// still never written to, and a foreign record at a name nothing wants is
/// still never deleted whether it was adopted or not.
#[must_use]
pub fn plan_with_adoptions(
    desired: &[DesiredRecord],
    existing: &ZoneListing,
    adopted: &AdoptedNames,
) -> Vec<RecordAction> {
    let mut actions = Vec::new();
    let mut claimed: Vec<&str> = Vec::new();

    for want in desired {
        let wanted_name = normalize_domain(&want.name);
        let matches: Vec<&DnsRecord> = existing
            .records
            .iter()
            .filter(|r| normalize_domain(&r.name) == wanted_name)
            .collect();

        // Disclosed before this name's own action rather than instead of it:
        // ferrum still creates or corrects its A/CNAME here, and the point
        // is only that the operator sees what else answers at the same name.
        for other in &existing.unmodelled {
            if normalize_domain(&other.name) == wanted_name {
                actions.push(RecordAction::SkipUnmodelledType {
                    name: other.name.clone(),
                    record_type: other.record_type.clone(),
                });
            }
        }

        // Ferrum's own records are considered before the operator's, so the
        // plan does not depend on the order Cloudflare happened to return
        // the listing in -- a plan that flips between runs is not idempotent
        // however correct each individual run looks.
        //
        // The split is by `ManagedRecordId::claim`, not by a boolean: a
        // foreign record yields no capability, so the `theirs` branch below
        // has nothing it could pass to a write or a delete even if someone
        // later edited it to try.
        let mut mine: Vec<(ManagedRecordId, &DnsRecord)> = Vec::new();
        let mut theirs: Vec<&DnsRecord> = Vec::new();
        for candidate in &matches {
            match ManagedRecordId::claim(candidate) {
                Some(id) => mine.push((id, candidate)),
                None => theirs.push(candidate),
            }
        }

        let Some((first_id, first)) = mine.first() else {
            // A3: a name the operator already uses is not ferrum's to take,
            // and adding a second record beside it would not add ferrum's
            // answer -- it would round-robin traffic between the two.
            if let Some(foreign) = theirs.first() {
                // A3's opt-in half. The capability is minted only when the
                // operator's decision names this exact record, so an
                // adoption of one name cannot reach another -- and with no
                // decision at all there is nothing to mint, which is why the
                // default below stays untouchable rather than merely
                // discouraged.
                let adoption = adopted
                    .decision_for(&want.name)
                    .and_then(|decision| ManagedRecordId::adopt_by_operator(foreign, &decision));
                match adoption {
                    Some(record_id) => {
                        claimed.push(foreign.id.as_str());
                        actions.push(RecordAction::Adopt {
                            record_id,
                            name: foreign.name.clone(),
                            current: foreign.target.clone(),
                            target: want.target.clone(),
                        });
                    }
                    None => actions.push(RecordAction::SkipForeign {
                        name: want.name.clone(),
                        current: foreign.target.clone(),
                        wanted: want.target.clone(),
                    }),
                }
            } else {
                actions.push(RecordAction::Create {
                    name: want.name.clone(),
                    target: want.target.clone(),
                });
            }
            continue;
        };

        claimed.push(first.id.as_str());
        if first.target == want.target && !first.proxied {
            actions.push(RecordAction::Unchanged {
                record_id: first_id.clone(),
                name: first.name.clone(),
            });
        } else {
            actions.push(RecordAction::Update {
                record_id: first_id.clone(),
                name: first.name.clone(),
                current: first.target.clone(),
                target: want.target.clone(),
            });
        }

        // Duplicates at a wanted name are ferrum's own mess to clear: two A
        // records for one host round-robin, so half of all requests land
        // nowhere. They arise from a create that retried after a listing
        // that had silently dropped a page. Only ferrum-owned duplicates are
        // removed; a foreign record sharing the name is never deleted in any
        // branch of this function.
        for (duplicate_id, duplicate) in mine.iter().skip(1) {
            actions.push(RecordAction::Delete {
                record_id: duplicate_id.clone(),
                name: duplicate.name.clone(),
            });
            claimed.push(duplicate.id.as_str());
        }
    }

    // A4: an app that was disabled loses the record ferrum created for it,
    // and nothing else in the zone changes.
    for record in &existing.records {
        if claimed.contains(&record.id.as_str()) {
            continue;
        }
        if let Some(record_id) = ManagedRecordId::claim(record) {
            actions.push(RecordAction::Delete {
                record_id,
                name: record.name.clone(),
            });
        }
    }

    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ownership::AdoptedNames;
    use std::net::Ipv4Addr;

    const HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const OTHER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);

    fn want(name: &str) -> DesiredRecord {
        DesiredRecord {
            name: name.to_string(),
            target: RecordTarget::A(HOST),
        }
    }

    /// A listing holding only A/CNAME records, which is what every test
    /// below that predates the unmodelled-type disclosure describes.
    fn listing(records: &[DnsRecord]) -> ZoneListing {
        ZoneListing {
            records: records.to_vec(),
            unmodelled: Vec::new(),
        }
    }

    fn existing(id: &str, name: &str, addr: Ipv4Addr, owned: bool) -> DnsRecord {
        DnsRecord {
            id: id.to_string(),
            name: name.to_string(),
            target: RecordTarget::A(addr),
            proxied: false,
            owned_by_ferrum: owned,
        }
    }

    #[test]
    fn a_missing_record_is_created() {
        let actions = plan(&[want("auth.example.com")], &listing(&[]));
        assert_eq!(
            actions,
            vec![RecordAction::Create {
                name: "auth.example.com".to_string(),
                target: RecordTarget::A(HOST),
            }]
        );
    }

    #[test]
    fn a_second_run_over_an_unchanged_zone_writes_nothing() {
        let zone = vec![existing("r1", "auth.example.com", HOST, true)];
        let actions = plan(&[want("auth.example.com")], &listing(&zone));
        assert_eq!(
            actions,
            vec![RecordAction::Unchanged {
                record_id: ManagedRecordId::unchecked("r1"),
                name: "auth.example.com".to_string(),
            }]
        );
    }

    #[test]
    fn a_ferrum_record_pointing_elsewhere_is_updated() {
        let zone = vec![existing("r1", "auth.example.com", OTHER, true)];
        let actions = plan(&[want("auth.example.com")], &listing(&zone));
        assert_eq!(
            actions,
            vec![RecordAction::Update {
                record_id: ManagedRecordId::unchecked("r1"),
                name: "auth.example.com".to_string(),
                current: RecordTarget::A(OTHER),
                target: RecordTarget::A(HOST),
            }]
        );
    }

    /// D-05: an operator who turned the orange cloud on in the dashboard has
    /// created drift, not a preference ferrum should preserve.
    #[test]
    fn a_ferrum_record_someone_switched_to_proxied_is_corrected() {
        let mut record = existing("r1", "auth.example.com", HOST, true);
        record.proxied = true;
        let actions = plan(&[want("auth.example.com")], &listing(&[record]));
        assert!(
            matches!(actions.as_slice(), [RecordAction::Update { .. }]),
            "{actions:?}"
        );
    }

    /// A3, Critical. The foreign record must be reported, must not be
    /// updated, and must not be joined by a second record at the same name.
    #[test]
    fn a_foreign_record_at_a_wanted_name_is_reported_and_left_alone() {
        let zone = vec![existing("r1", "plex.example.com", OTHER, false)];
        let actions = plan(&[want("plex.example.com")], &listing(&zone));
        assert_eq!(
            actions,
            vec![RecordAction::SkipForeign {
                name: "plex.example.com".to_string(),
                current: RecordTarget::A(OTHER),
                wanted: RecordTarget::A(HOST),
            }]
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, RecordAction::Update { .. } | RecordAction::Create { .. })),
            "a foreign record must never be overwritten, and never shadowed \
             by a second record at the same name: {actions:?}"
        );
    }

    /// A4, Critical. The operator's own records survive ferrum deciding it
    /// no longer wants anything at that name.
    #[test]
    fn a_foreign_record_nobody_wants_is_never_deleted() {
        let zone = vec![
            existing("r1", "legacy.example.com", OTHER, false),
            existing("r2", "old-app.example.com", HOST, true),
        ];
        let actions = plan(&[], &listing(&zone));
        assert_eq!(
            actions,
            vec![RecordAction::Delete {
                record_id: ManagedRecordId::unchecked("r2"),
                name: "old-app.example.com".to_string(),
            }],
            "only the ferrum-owned record may be removed"
        );
    }

    #[test]
    fn a_disabled_app_loses_the_record_ferrum_created_for_it() {
        let zone = vec![
            existing("r1", "auth.example.com", HOST, true),
            existing("r2", "sonarr.example.com", HOST, true),
        ];
        let actions = plan(&[want("auth.example.com")], &listing(&zone));
        assert_eq!(
            actions,
            vec![
                RecordAction::Unchanged {
                    record_id: ManagedRecordId::unchecked("r1"),
                    name: "auth.example.com".to_string(),
                },
                RecordAction::Delete {
                    record_id: ManagedRecordId::unchecked("r2"),
                    name: "sonarr.example.com".to_string(),
                },
            ]
        );
    }

    /// The convergence case a dropped pagination page creates: two ferrum
    /// records at one name. One is kept, the rest are removed, and a rerun
    /// is then a no-op.
    #[test]
    fn duplicate_ferrum_records_at_one_name_converge_to_a_single_record() {
        let zone = vec![
            existing("r1", "auth.example.com", HOST, true),
            existing("r2", "auth.example.com", HOST, true),
        ];
        let actions = plan(&[want("auth.example.com")], &listing(&zone));
        assert_eq!(
            actions,
            vec![
                RecordAction::Unchanged {
                    record_id: ManagedRecordId::unchecked("r1"),
                    name: "auth.example.com".to_string(),
                },
                RecordAction::Delete {
                    record_id: ManagedRecordId::unchecked("r2"),
                    name: "auth.example.com".to_string(),
                },
            ]
        );
    }

    /// The plan must not depend on the order Cloudflare returned the
    /// listing in. Both orders below describe the same zone, so both must
    /// produce the same plan -- and in neither may the foreign record be
    /// touched.
    #[test]
    fn a_foreign_and_a_ferrum_record_at_one_name_plan_the_same_in_either_order() {
        let mine = existing("mine", "auth.example.com", OTHER, true);
        let theirs = existing("theirs", "auth.example.com", OTHER, false);

        let expected = vec![RecordAction::Update {
            record_id: ManagedRecordId::unchecked("mine"),
            name: "auth.example.com".to_string(),
            current: RecordTarget::A(OTHER),
            target: RecordTarget::A(HOST),
        }];

        assert_eq!(
            plan(
                &[want("auth.example.com")],
                &listing(&[mine.clone(), theirs.clone()])
            ),
            expected
        );
        assert_eq!(
            plan(&[want("auth.example.com")], &listing(&[theirs, mine])),
            expected
        );
    }

    #[test]
    fn name_matching_ignores_case_and_a_trailing_dot_as_dns_does() {
        let zone = vec![existing("r1", "AUTH.Example.COM.", HOST, true)];
        let actions = plan(&[want("auth.example.com")], &listing(&zone));
        assert!(
            matches!(actions.as_slice(), [RecordAction::Unchanged { .. }]),
            "{actions:?}"
        );
    }

    #[test]
    fn a_write_body_always_carries_the_marker_and_never_the_orange_cloud() {
        let body = RecordWrite::new("auth.example.com", &RecordTarget::A(HOST));
        let json = serde_json::to_value(&body).expect("the write body serializes");
        assert_eq!(json["type"], serde_json::json!("A"));
        assert_eq!(json["name"], serde_json::json!("auth.example.com"));
        assert_eq!(json["content"], serde_json::json!("203.0.113.7"));
        assert_eq!(json["proxied"], serde_json::json!(false));
        assert_eq!(json["comment"], serde_json::json!(OWNERSHIP_MARKER));
    }

    #[test]
    fn a_cname_write_body_carries_the_hostname() {
        let body = RecordWrite::new(
            "auth.example.com",
            &RecordTarget::Cname("host.dyn.example.net".to_string()),
        );
        assert_eq!(body.record_type, "CNAME");
        assert_eq!(body.content, "host.dyn.example.net");
    }

    #[test]
    fn a_listed_record_with_the_marker_is_ferrums() {
        let json: RecordJson = serde_json::from_value(serde_json::json!({
            "id": "r1",
            "name": "auth.example.com",
            "type": "A",
            "content": "203.0.113.7",
            "proxied": false,
            "comment": OWNERSHIP_MARKER,
        }))
        .expect("a Cloudflare-shaped record parses");
        let model = json.into_model().expect("an A record becomes a model");
        assert!(model.owned_by_ferrum);
        assert_eq!(model.target, RecordTarget::A(HOST));
    }

    #[test]
    fn a_listed_record_without_a_comment_is_foreign() {
        let json: RecordJson = serde_json::from_value(serde_json::json!({
            "id": "r1",
            "name": "plex.example.com",
            "type": "A",
            "content": "198.51.100.9",
        }))
        .expect("a record with no comment field still parses");
        assert!(!json.into_model().expect("a model").owned_by_ferrum);
    }

    #[test]
    fn records_of_other_types_are_not_part_of_ferrums_world() {
        for (record_type, content) in [
            ("TXT", "some-acme-challenge-value"),
            ("MX", "mail.example.com"),
            ("NS", "ns1.example.com"),
            ("AAAA", "2001:db8::1"),
        ] {
            let json: RecordJson = serde_json::from_value(serde_json::json!({
                "id": "r1",
                "name": "example.com",
                "type": record_type,
                "content": content,
            }))
            .expect("parses");
            assert!(
                json.into_model().is_none(),
                "{record_type} must not enter the ownership partition"
            );
        }
    }

    #[test]
    fn an_a_record_whose_content_is_not_an_address_is_skipped_rather_than_fatal() {
        let json: RecordJson = serde_json::from_value(serde_json::json!({
            "id": "r1",
            "name": "example.com",
            "type": "A",
            "content": "not-an-address",
        }))
        .expect("parses");
        assert!(json.into_model().is_none());
    }

    // ---- disclosure of types this crate does not model ----

    fn wire(id: &str, name: &str, record_type: &str, content: &str) -> RecordJson {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "name": name,
            "type": record_type,
            "content": content,
        }))
        .expect("a Cloudflare-shaped record parses")
    }

    /// The defect this variant exists for. Before it, the `AAAA` was dropped
    /// by `into_model`, the planner saw an empty name, and the operator read
    /// a dry run that said `create` and nothing else -- while half their
    /// clients kept reaching the old host over IPv6.
    #[test]
    fn an_aaaa_at_a_wanted_name_is_disclosed_and_the_a_record_is_still_created() {
        let zone =
            ZoneListing::from_wire(vec![wire("r1", "plex.example.com", "AAAA", "2001:db8::1")]);
        let actions = plan(&[want("plex.example.com")], &zone);
        assert_eq!(
            actions,
            vec![
                RecordAction::SkipUnmodelledType {
                    name: "plex.example.com".to_string(),
                    record_type: "AAAA".to_string(),
                },
                RecordAction::Create {
                    name: "plex.example.com".to_string(),
                    target: RecordTarget::A(HOST),
                },
            ]
        );
    }

    /// The disclosure is additive, never a substitute: a name ferrum already
    /// owns still reports its own outcome.
    #[test]
    fn a_disclosed_name_ferrum_owns_still_reports_its_own_action() {
        let mut zone =
            ZoneListing::from_wire(vec![wire("r2", "auth.example.com", "AAAA", "2001:db8::2")]);
        zone.records
            .push(existing("r1", "auth.example.com", HOST, true));
        let actions = plan(&[want("auth.example.com")], &zone);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, RecordAction::Unchanged { .. })),
            "{actions:?}"
        );
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, RecordAction::SkipUnmodelledType { .. })),
            "{actions:?}"
        );
    }

    /// lego creates and removes these during every ACME DNS-01 challenge.
    /// Reporting ferrum's own certificate machinery back to the operator as
    /// something in their zone would train them to ignore the line that
    /// matters.
    #[test]
    fn an_acme_challenge_txt_is_not_disclosed_as_a_collision() {
        let zone = ZoneListing::from_wire(vec![
            wire(
                "r1",
                "_acme-challenge.plex.example.com",
                "TXT",
                "a-challenge-value",
            ),
            wire("r2", "_acme-challenge.example.com", "TXT", "another"),
        ]);
        assert!(zone.unmodelled().is_empty(), "{zone:?}");
        assert!(zone.records().is_empty(), "{zone:?}");
    }

    /// A record of another type at a name ferrum never asked for is not a
    /// collision. Reporting the operator's whole zone back to them is noise,
    /// and ferrum is a guest here.
    #[test]
    fn an_unmodelled_record_at_a_name_nothing_wants_produces_no_action() {
        let zone = ZoneListing::from_wire(vec![
            wire("r1", "example.com", "MX", "mail.example.com"),
            wire("r2", "example.com", "TXT", "v=spf1 -all"),
        ]);
        assert_eq!(zone.unmodelled().len(), 2);
        assert!(
            plan(&[want("auth.example.com")], &zone).contains(&RecordAction::Create {
                name: "auth.example.com".to_string(),
                target: RecordTarget::A(HOST),
            })
        );
        assert!(!plan(&[want("auth.example.com")], &zone)
            .iter()
            .any(|a| matches!(a, RecordAction::SkipUnmodelledType { .. })));
    }

    /// An `A` whose content is not an address cannot be modelled either, and
    /// silently dropping it has the same shape as dropping an `AAAA`.
    #[test]
    fn an_unparseable_a_record_is_disclosed_rather_than_vanishing() {
        let zone =
            ZoneListing::from_wire(vec![wire("r1", "auth.example.com", "A", "not-an-address")]);
        assert_eq!(zone.unmodelled()[0].name(), "auth.example.com");
        assert_eq!(zone.unmodelled()[0].record_type(), "A");
    }

    /// Matching uses the same normalisation as everything else here, so a
    /// trailing dot or a capital does not hide a collision.
    #[test]
    fn disclosure_matches_names_the_way_dns_does() {
        let zone =
            ZoneListing::from_wire(vec![wire("r1", "AUTH.Example.COM.", "AAAA", "2001:db8::1")]);
        assert!(plan(&[want("auth.example.com")], &zone)
            .iter()
            .any(|a| matches!(a, RecordAction::SkipUnmodelledType { .. })));
    }

    // ---- A3's opt-in half: the planner ----

    /// The adopted name is taken over; every other foreign record in the
    /// same zone is still reported and left alone.
    #[test]
    fn an_adopted_name_is_taken_over_and_its_neighbours_are_not() {
        let zone = vec![
            existing("theirs-plex", "plex.example.com", OTHER, false),
            existing("theirs-sonarr", "sonarr.example.com", OTHER, false),
        ];
        let actions = plan_with_adoptions(
            &[want("plex.example.com"), want("sonarr.example.com")],
            &listing(&zone),
            &AdoptedNames::recorded(&["plex.example.com"]),
        );
        assert_eq!(
            actions,
            vec![
                RecordAction::Adopt {
                    record_id: ManagedRecordId::unchecked("theirs-plex"),
                    name: "plex.example.com".to_string(),
                    current: RecordTarget::A(OTHER),
                    target: RecordTarget::A(HOST),
                },
                RecordAction::SkipForeign {
                    name: "sonarr.example.com".to_string(),
                    current: RecordTarget::A(OTHER),
                    wanted: RecordTarget::A(HOST),
                },
            ],
            "adopting plex must not adopt sonarr"
        );
    }

    /// A3's default, restated against the adoption-aware planner: with no
    /// decision recorded, nothing changes at all.
    #[test]
    fn an_empty_adoption_set_plans_exactly_what_the_plain_planner_plans() {
        let zone = vec![
            existing("theirs", "plex.example.com", OTHER, false),
            existing("mine", "auth.example.com", HOST, true),
            existing("stale", "old.example.com", HOST, true),
        ];
        let desired = [want("plex.example.com"), want("auth.example.com")];
        assert_eq!(
            plan_with_adoptions(&desired, &listing(&zone), &AdoptedNames::none()),
            plan(&desired, &listing(&zone))
        );
        assert!(
            !plan_with_adoptions(&desired, &listing(&zone), &AdoptedNames::none())
                .iter()
                .any(|a| matches!(a, RecordAction::Adopt { .. })),
            "no decision means no adoption"
        );
    }

    /// Adoption is scoped to names ferrum actually wants. A foreign record
    /// nothing publishes is never deleted, adopted or not -- deleting it is
    /// the irreversible act A4 exists to prevent, and the operator adopted a
    /// hostname for an app, not a licence to prune their zone.
    #[test]
    fn an_adopted_name_nothing_wants_is_still_never_deleted() {
        let zone = vec![existing("theirs", "plex.example.com", OTHER, false)];
        let actions = plan_with_adoptions(
            &[],
            &listing(&zone),
            &AdoptedNames::recorded(&["plex.example.com"]),
        );
        assert!(
            actions.is_empty(),
            "an adopted name that nothing publishes produces no action at all: {actions:?}"
        );
    }

    /// The second run. The adopting write carried the marker, so the record
    /// now reaches the ordinary path and the adopted set is irrelevant to it.
    #[test]
    fn the_run_after_an_adoption_needs_no_decision_and_writes_nothing() {
        let zone = vec![existing("theirs-plex", "plex.example.com", HOST, true)];
        let desired = [want("plex.example.com")];
        let expected = vec![RecordAction::Unchanged {
            record_id: ManagedRecordId::unchecked("theirs-plex"),
            name: "plex.example.com".to_string(),
        }];
        assert_eq!(
            plan_with_adoptions(
                &desired,
                &listing(&zone),
                &AdoptedNames::recorded(&["plex.example.com"])
            ),
            expected
        );
        assert_eq!(
            plan_with_adoptions(&desired, &listing(&zone), &AdoptedNames::none()),
            expected,
            "once the marker is there the decision is no longer load-bearing"
        );
    }

    /// Adopting a name ferrum already owns a record for changes nothing: the
    /// managed record wins and the foreign one is left where it is.
    #[test]
    fn adoption_does_not_disturb_a_name_ferrum_already_owns() {
        let zone = vec![
            existing("mine", "auth.example.com", OTHER, true),
            existing("theirs", "auth.example.com", OTHER, false),
        ];
        let actions = plan_with_adoptions(
            &[want("auth.example.com")],
            &listing(&zone),
            &AdoptedNames::recorded(&["auth.example.com"]),
        );
        assert_eq!(
            actions,
            vec![RecordAction::Update {
                record_id: ManagedRecordId::unchecked("mine"),
                name: "auth.example.com".to_string(),
                current: RecordTarget::A(OTHER),
                target: RecordTarget::A(HOST),
            }]
        );
    }

    /// The write that follows an adoption is the ordinary one, so it carries
    /// the marker -- which is what makes adoption a one-time transition
    /// rather than a standing grant.
    #[test]
    fn the_adopting_write_carries_the_ownership_marker() {
        let body = RecordWrite::new("plex.example.com", &RecordTarget::A(HOST));
        assert_eq!(body.comment, OWNERSHIP_MARKER);
        assert!(!body.proxied);
    }
}
