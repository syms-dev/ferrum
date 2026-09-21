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
//! * `proxied` is always written `false` (decision D-05). Cloudflare's
//!   orange cloud makes every request arrive from an edge address, which
//!   turns the LAN allow-list in front of `lan` apps into a total outage and
//!   routes Plex/Jellyfin streams through that edge. A managed record found
//!   with `proxied: true` is drift and is corrected like any other.

use serde::{Deserialize, Serialize};

use crate::ownership::{is_ferrum_marker, ManagedRecordId};
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
}

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
}

/// Computes the reconcile plan for a zone.
///
/// # Arguments
/// * `desired` - every record ferrum wants, from the published-app set.
/// * `existing` - every A/CNAME record currently in the zone, from one
///   [`crate::client::Client::list_records`] call. It must be the **whole**
///   listing: a truncated one makes an existing record look absent, and the
///   plan then creates a duplicate.
///
/// # Returns
/// One action per desired name, followed by a [`RecordAction::Delete`] for
/// each ferrum-owned record no longer wanted. Records that are neither
/// wanted nor ferrum's produce no action at all -- they are the operator's
/// zone, and ferrum is a guest in it.
#[must_use]
pub fn plan(desired: &[DesiredRecord], existing: &[DnsRecord]) -> Vec<RecordAction> {
    let mut actions = Vec::new();
    let mut claimed: Vec<&str> = Vec::new();

    for want in desired {
        let wanted_name = normalize_domain(&want.name);
        let matches: Vec<&DnsRecord> = existing
            .iter()
            .filter(|r| normalize_domain(&r.name) == wanted_name)
            .collect();

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
                actions.push(RecordAction::SkipForeign {
                    name: want.name.clone(),
                    current: foreign.target.clone(),
                    wanted: want.target.clone(),
                });
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
    for record in existing {
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
    use std::net::Ipv4Addr;

    const HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
    const OTHER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);

    fn want(name: &str) -> DesiredRecord {
        DesiredRecord {
            name: name.to_string(),
            target: RecordTarget::A(HOST),
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
        let actions = plan(&[want("auth.example.com")], &[]);
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
        let actions = plan(&[want("auth.example.com")], &zone);
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
        let actions = plan(&[want("auth.example.com")], &zone);
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
        let actions = plan(&[want("auth.example.com")], &[record]);
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
        let actions = plan(&[want("plex.example.com")], &zone);
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
        let actions = plan(&[], &zone);
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
        let actions = plan(&[want("auth.example.com")], &zone);
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
        let actions = plan(&[want("auth.example.com")], &zone);
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
            plan(&[want("auth.example.com")], &[mine.clone(), theirs.clone()]),
            expected
        );
        assert_eq!(plan(&[want("auth.example.com")], &[theirs, mine]), expected);
    }

    #[test]
    fn name_matching_ignores_case_and_a_trailing_dot_as_dns_does() {
        let zone = vec![existing("r1", "AUTH.Example.COM.", HOST, true)];
        let actions = plan(&[want("auth.example.com")], &zone);
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
}
