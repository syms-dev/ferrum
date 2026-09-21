//! Who owns a DNS record, and the two things ferrum may never do to one it
//! does not own.
//!
//! **Where authority lives (decision D-01).** A record is ferrum's if and
//! only if its Cloudflare `comment` field is exactly [`OWNERSHIP_MARKER`].
//! Authority is in Cloudflare, never in `/var/lib/ferrum/state`: that
//! directory sits on the OS disk and a reinstall wipes it, which is exactly
//! the event A4 has to survive. A local ledger would fail in both
//! directions at once -- after a reinstall ferrum would refuse to touch the
//! records it created itself, and it would happily adopt and later delete a
//! record the operator placed deliberately.
//!
//! **The guards are enforced by the type system, not by review.**
//! [`ManagedRecordId`] is proof that an id names a record ferrum owns; it
//! can only be minted from a record carrying the marker, and the client's
//! write and delete methods accept nothing else. The predicates below say
//! *why*; the type makes the wrong call impossible to write.
//!
//! **The two guards, and why they are graded Critical.**
//!
//! * [`may_overwrite`] -- a foreign `plex.example.com` points somewhere the
//!   operator chose. Overwriting it silently redirects live traffic away
//!   from whatever it served, and nothing in the install output would say
//!   so.
//! * [`may_delete`] -- a deleted foreign record cannot be restored from
//!   anything ferrum holds; the operator's only copy of that intent was the
//!   record.
//!
//! **There are exactly two ways to mint a [`ManagedRecordId`], and they
//! must not be merged into one.** [`ManagedRecordId::claim`] is the ordinary
//! rule: the record already carries ferrum's marker, so it is already
//! ferrum's. [`ManagedRecordId::adopt_by_operator`] is A3's second half --
//! *"reported and left alone **unless the operator opts in**. Adoption is
//! explicit."* -- and it mints for a record ferrum does **not** own, but
//! only against an [`AdoptionDecision`] naming that exact record. Collapsing
//! them into one constructor that takes a boolean, or widening `claim` to
//! accept a foreign record, deletes the guard entirely: the whole reason the
//! adoption path is separate is that it is impossible to reach by accident
//! from a call site that merely wanted to write a record.
//!
//! **The match is exact, and that is load-bearing.** A substring, prefix, or
//! case-insensitive comparison would claim an unrelated record: an operator
//! comment reading `"migrated off ferrum-managed host"` contains the marker,
//! and `"Ferrum-Managed"` differs from it only in case. Either would make a
//! foreign record look owned, which is precisely the failure both guards
//! exist to prevent -- so [`is_ferrum_marker`] compares the whole string,
//! byte for byte, with no trimming. Cloudflare returns the comment
//! verbatim, so a marker ferrum wrote comes back byte-identical; anything
//! that does not match was not written by this code.

use crate::zone::normalize_domain;
use crate::{DnsRecord, OWNERSHIP_MARKER};

/// Whether a record is ferrum's to change, or the operator's to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// Carries [`OWNERSHIP_MARKER`] exactly: ferrum created it and may
    /// update or delete it as the desired-record set changes.
    Managed,
    /// Does not carry the marker. Reported to the operator, never written
    /// to and never removed. Adoption is an explicit operator decision, not
    /// something this crate infers.
    Foreign,
}

/// Whether a Cloudflare `comment` value claims ferrum ownership.
///
/// # Arguments
/// * `comment` - the record's `comment` field as Cloudflare returned it;
///   `None` when the field is absent or null.
///
/// # Returns
/// `true` only when the comment is present and equals [`OWNERSHIP_MARKER`]
/// exactly. No trimming, no case folding, no substring search -- see this
/// module's header for why a looser comparison is the Critical failure.
#[must_use]
pub fn is_ferrum_marker(comment: Option<&str>) -> bool {
    comment == Some(OWNERSHIP_MARKER)
}

/// Classifies one record as ferrum's or the operator's.
///
/// # Arguments
/// * `record` - a record as [`crate::client::Client::list_records`] parsed
///   it, whose `owned_by_ferrum` was derived from the live `comment` field
///   on that listing rather than from anything remembered locally.
///
/// # Returns
/// [`Ownership::Managed`] or [`Ownership::Foreign`].
#[must_use]
pub fn classify(record: &DnsRecord) -> Ownership {
    if record.owned_by_ferrum {
        Ownership::Managed
    } else {
        Ownership::Foreign
    }
}

/// Whether ferrum may write over this record (A3).
///
/// # Arguments
/// * `record` - the record that already exists at a name ferrum wants.
///
/// # Returns
/// `true` only for a ferrum-managed record. A foreign record is reported to
/// the operator and left exactly as it is.
#[must_use]
pub fn may_overwrite(record: &DnsRecord) -> bool {
    classify(record) == Ownership::Managed
}

/// Whether ferrum may remove this record (A4).
///
/// # Arguments
/// * `record` - the record found in the zone that is no longer wanted.
///
/// # Returns
/// `true` only for a ferrum-managed record. Disabling an app removes the
/// record ferrum created for it and nothing else; a record that predated
/// ferrum outlives it.
#[must_use]
pub fn may_delete(record: &DnsRecord) -> bool {
    classify(record) == Ownership::Managed
}

/// One operator decision to hand **one** named record to ferrum (A3).
///
/// **There is deliberately no public constructor.** No `new`, no
/// `From<String>`, no tuple-struct literal: the only way to obtain one is
/// [`AdoptedNames::decision_for`], which will only produce a decision for a
/// name the operator actually adopted. A type that could be built from any
/// string would be a `bool` with extra steps, and the guard it exists to
/// carry would be back to a doc comment.
///
/// The decision is **per name**. An operator who adopted `plex.example.com`
/// has said nothing at all about `sonarr.example.com`, and there is no value
/// of this type that means "all of them".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptionDecision {
    /// The normalized record name this decision is about, and only this one.
    name: String,
}

impl AdoptionDecision {
    /// The name this decision covers, normalized the way DNS compares names.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The names the operator explicitly adopted, as recorded at install time.
///
/// **What this is not.** It is not a permission to write to the zone, and it
/// is not an "adopt everything" switch. There is no wildcard constructor and
/// no `all()`: the only content is an explicit list of names, and a name that
/// is not in the list produces no [`AdoptionDecision`], so
/// [`ManagedRecordId::adopt_by_operator`] can mint nothing for it. That is
/// the mechanism behind A3's *"an operator who adopted `plex` must not
/// thereby have adopted `sonarr`"*.
///
/// **Where the list comes from.** `crates/ferrum-install/src/dns.rs`'s
/// pre-erase gate asks per foreign name and requires the literal word
/// `adopt`; the answer is written into `ferrum.proxy.dns.adoptedNames` and
/// reaches the host in `/etc/ferrum-dns-config.json`. The single constructor
/// is named [`AdoptedNames::recorded`] after that provenance so a future call
/// site inventing a list has to write a word that says it did not come from
/// an operator.
///
/// **It stops mattering after the first successful reconcile.** Adopting a
/// record rewrites it through [`crate::record::RecordWrite`], which carries
/// [`OWNERSHIP_MARKER`]; on the next run that record is ferrum's under the
/// ordinary rule and [`ManagedRecordId::claim`] handles it with no decision
/// in sight. The adopted list is therefore a one-shot key, not a standing
/// grant -- and leaving it in settings is harmless precisely because it
/// grants nothing a marker does not already grant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdoptedNames {
    /// Normalized names, so a decision matches the way DNS itself compares.
    names: Vec<String>,
}

impl AdoptedNames {
    /// No name was adopted: the ordinary case, and the one every existing
    /// caller gets.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The names an operator adopted at the install gate.
    ///
    /// # Arguments
    /// * `names` - fully qualified record names, exactly as the operator was
    ///   asked about them. Case and a trailing dot are normalized away, so
    ///   `Plex.Example.COM.` adopts `plex.example.com`; nothing else is
    ///   interpreted, and in particular no value is treated as a wildcard.
    ///
    /// # Returns
    /// The recorded set. An empty slice yields the same thing as
    /// [`AdoptedNames::none`].
    #[must_use]
    pub fn recorded<S: AsRef<str>>(names: &[S]) -> Self {
        Self {
            names: names
                .iter()
                .map(|n| normalize_domain(n.as_ref()))
                .filter(|n| !n.is_empty())
                .collect(),
        }
    }

    /// Whether this exact name was adopted.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(&normalize_domain(name))
    }

    /// Whether the operator adopted nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The decision covering one name, if the operator made one.
    ///
    /// # Arguments
    /// * `name` - the fully qualified name a plan wants a record for.
    ///
    /// # Returns
    /// `Some(decision)` only when `name` is in the recorded set; `None`
    /// otherwise, which leaves the name on A3's default path -- reported and
    /// left alone.
    #[must_use]
    pub fn decision_for(&self, name: &str) -> Option<AdoptionDecision> {
        let wanted = normalize_domain(name);
        if self.names.contains(&wanted) {
            Some(AdoptionDecision { name: wanted })
        } else {
            None
        }
    }
}

/// Proof that a record id names a record ferrum owns.
///
/// **This type is the A3/A4 guard, expressed so the compiler enforces it.**
/// [`crate::client::Client::update_record`] and
/// [`crate::client::Client::delete_record`] accept only this, never a bare
/// `&str`, and the only ways to mint one outside this crate are
/// [`crate::record::plan`] -- which mints it only for a record carrying
/// [`OWNERSHIP_MARKER`] -- and [`crate::record::plan_with_adoptions`], which
/// additionally mints it for a record the operator explicitly named.
///
/// A comment saying "ids must come from the plan" is advice a future caller
/// can miss; this is advice a future caller cannot compile past. That
/// asymmetry is the whole reason the type exists: an id read straight out of
/// [`crate::client::Client::list_records`] and handed to `delete_record`
/// would remove an operator's record irrecoverably, in their real zone, and
/// reinstalling the host does not bring it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedRecordId(String);

impl ManagedRecordId {
    /// Mints the proof, if and only if the record is ferrum's.
    ///
    /// Crate-private by design: every public path to a `ManagedRecordId`
    /// runs through [`crate::record::plan`]. Making this `pub` would
    /// reintroduce exactly the bypass the type removes.
    ///
    /// # Arguments
    /// * `record` - a record from a live listing.
    ///
    /// # Returns
    /// `Some(id)` when the record carries the marker, `None` when it is the
    /// operator's.
    pub(crate) fn claim(record: &DnsRecord) -> Option<Self> {
        match classify(record) {
            Ownership::Managed => Some(ManagedRecordId(record.id.clone())),
            Ownership::Foreign => None,
        }
    }

    /// Mints the proof for a record ferrum does **not** own, against an
    /// explicit operator decision naming that exact record (A3).
    ///
    /// This is the *"unless the operator opts in"* half of A3, and it is a
    /// second constructor rather than a flag on [`ManagedRecordId::claim`]
    /// on purpose. `claim` answers "is this already ferrum's?" and must stay
    /// answerable from the record alone; this one answers "did a human say to
    /// take this one?", which no record can answer. A single constructor
    /// taking `(record, adopt: bool)` would put the two questions behind one
    /// argument a caller can get wrong by passing `true`, and the guard would
    /// be gone. **Do not merge them.**
    ///
    /// Crate-private for the same reason `claim` is: the only public path is
    /// [`crate::record::plan_with_adoptions`], so no caller outside this
    /// crate can pair a decision with a record of its own choosing.
    ///
    /// **On the second run this function is not reached.** The write that
    /// follows carries [`OWNERSHIP_MARKER`]
    /// ([`crate::record::RecordWrite::new`]), so the next listing reports the
    /// record as ferrum's and `claim` handles it. Adoption is a one-time
    /// transition, not a standing permission -- which is also why losing the
    /// adopted list later changes nothing.
    ///
    /// # Arguments
    /// * `record` - the record that occupies the wanted name.
    /// * `decision` - the operator's decision, from
    ///   [`AdoptedNames::decision_for`].
    ///
    /// # Returns
    /// `Some(id)` only when the decision is about **this** record's name.
    /// `None` otherwise -- so a decision about `plex.example.com` mints
    /// nothing for `sonarr.example.com`, however the two were paired up.
    pub(crate) fn adopt_by_operator(
        record: &DnsRecord,
        decision: &AdoptionDecision,
    ) -> Option<Self> {
        if normalize_domain(&record.name) == decision.name {
            Some(ManagedRecordId(record.id.clone()))
        } else {
            None
        }
    }

    /// The id itself, for building the Cloudflare record URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// An unchecked id, for this crate's own tests only.
    ///
    /// Exists so a test can write the expected [`crate::record::RecordAction`]
    /// without going through a record. Gated on `test` alone -- not on the
    /// `testing` feature -- so it is unreachable from any other crate, even
    /// one that enables the fake API.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn unchecked(id: &str) -> Self {
        ManagedRecordId(id.to_string())
    }
}

/// Splits a zone listing into the records ferrum manages and the records it
/// must only report.
///
/// # Arguments
/// * `records` - every A/CNAME record in the zone, from one listing.
///
/// # Returns
/// `(managed, foreign)`, each preserving the order Cloudflare returned, so a
/// dry run lists them the way the operator would see them in the dashboard.
#[must_use]
pub fn partition(records: &[DnsRecord]) -> (Vec<DnsRecord>, Vec<DnsRecord>) {
    let mut managed = Vec::new();
    let mut foreign = Vec::new();
    for record in records {
        match classify(record) {
            Ownership::Managed => managed.push(record.clone()),
            Ownership::Foreign => foreign.push(record.clone()),
        }
    }
    (managed, foreign)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RecordTarget;
    use std::net::Ipv4Addr;

    fn record(name: &str, owned: bool) -> DnsRecord {
        DnsRecord {
            id: format!("id-{name}"),
            name: name.to_string(),
            target: RecordTarget::A(Ipv4Addr::new(203, 0, 113, 7)),
            proxied: false,
            owned_by_ferrum: owned,
        }
    }

    #[test]
    fn the_exact_marker_claims_the_record() {
        assert!(is_ferrum_marker(Some(OWNERSHIP_MARKER)));
    }

    #[test]
    fn an_absent_comment_is_foreign() {
        assert!(!is_ferrum_marker(None));
        assert!(!is_ferrum_marker(Some("")));
    }

    /// The Critical case. Every string below would pass a substring,
    /// prefix, trimming, or case-insensitive comparison, and each of them is
    /// a record ferrum did not create.
    #[test]
    fn a_comment_that_merely_resembles_the_marker_does_not_claim_the_record() {
        for impostor in [
            "ferrum-managed-by-hand",
            "not ferrum-managed",
            "migrated off a ferrum-managed host",
            "Ferrum-Managed",
            "FERRUM-MANAGED",
            " ferrum-managed",
            "ferrum-managed ",
            "ferrum-managed\n",
            "ferrum",
            "managed",
        ] {
            assert!(
                !is_ferrum_marker(Some(impostor)),
                "{impostor:?} must not be read as ferrum's marker: a loose \
                 match here lets ferrum overwrite or delete a record the \
                 operator placed deliberately"
            );
        }
    }

    #[test]
    fn a_foreign_record_is_never_overwritten() {
        assert!(!may_overwrite(&record("plex.example.com", false)));
    }

    #[test]
    fn a_foreign_record_is_never_deleted() {
        assert!(!may_delete(&record("plex.example.com", false)));
    }

    #[test]
    fn a_ferrum_record_may_be_updated_and_removed() {
        let owned = record("auth.example.com", true);
        assert!(may_overwrite(&owned));
        assert!(may_delete(&owned));
        assert_eq!(classify(&owned), Ownership::Managed);
    }

    /// The type-level form of both guards: a foreign record yields no
    /// capability to write to it at all, so there is nothing to pass to
    /// `update_record` or `delete_record`.
    #[test]
    fn a_foreign_record_mints_no_capability_to_change_it() {
        assert_eq!(
            ManagedRecordId::claim(&record("plex.example.com", false)),
            None
        );
    }

    #[test]
    fn a_ferrum_record_mints_a_capability_carrying_its_own_id() {
        let claimed = ManagedRecordId::claim(&record("auth.example.com", true))
            .expect("a ferrum record is claimable");
        assert_eq!(claimed.as_str(), "id-auth.example.com");
    }

    #[test]
    fn partition_keeps_cloudflares_own_order_within_each_group() {
        let records = vec![
            record("a.example.com", true),
            record("b.example.com", false),
            record("c.example.com", true),
            record("d.example.com", false),
        ];
        let (managed, foreign) = partition(&records);
        assert_eq!(
            managed.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["a.example.com", "c.example.com"]
        );
        assert_eq!(
            foreign.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["b.example.com", "d.example.com"]
        );
    }
    // ---- A3's opt-in half: adoption ----

    #[test]
    fn nothing_is_adopted_by_default() {
        let adopted = AdoptedNames::none();
        assert!(adopted.is_empty());
        assert_eq!(adopted.decision_for("plex.example.com"), None);
    }

    /// The Critical case for the adoption path, and the mutation this story
    /// exists to prove: adopting one name must not adopt its neighbours.
    #[test]
    fn adopting_one_name_adopts_nothing_else() {
        let adopted = AdoptedNames::recorded(&["plex.example.com"]);
        let plex = record("plex.example.com", false);
        let sonarr = record("sonarr.example.com", false);

        let decision = adopted
            .decision_for("plex.example.com")
            .expect("the adopted name has a decision");
        assert!(ManagedRecordId::adopt_by_operator(&plex, &decision).is_some());

        assert_eq!(adopted.decision_for("sonarr.example.com"), None);
        // Even handed the wrong record, plex's decision mints nothing for
        // sonarr: the name on the decision is checked against the record's own.
        assert_eq!(
            ManagedRecordId::adopt_by_operator(&sonarr, &decision),
            None,
            "a decision about plex must never mint a capability over sonarr"
        );
    }

    /// There is no "adopt everything" value. A wildcard, an empty string and
    /// a bare domain are all just strings that match no record name.
    #[test]
    fn no_value_in_the_adopted_set_means_all_of_them() {
        let adopted = AdoptedNames::recorded(&["*", "*.example.com", "", "   "]);
        for name in [
            "plex.example.com",
            "sonarr.example.com",
            "auth.example.com",
            "example.com",
        ] {
            assert_eq!(
                adopted.decision_for(name),
                None,
                "{name:?} must not be adopted by a wildcard-shaped string"
            );
        }
    }

    #[test]
    fn an_adopted_name_matches_the_way_dns_compares_names() {
        let adopted = AdoptedNames::recorded(&["PLEX.Example.COM."]);
        assert!(adopted.contains("plex.example.com"));
        let decision = adopted
            .decision_for("plex.example.com.")
            .expect("case and a trailing dot are not a different name");
        assert_eq!(decision.name(), "plex.example.com");
        assert!(
            ManagedRecordId::adopt_by_operator(&record("Plex.Example.Com", false), &decision)
                .is_some()
        );
    }

    /// Adoption is a one-time transition. The write that follows carries the
    /// marker, so the next run reaches the record through `claim` and the
    /// adopted list is no longer consulted for it.
    #[test]
    fn an_adopted_record_is_ferrums_by_the_ordinary_rule_on_the_next_run() {
        let after_the_adopting_write = record("plex.example.com", true);
        assert!(ManagedRecordId::claim(&after_the_adopting_write).is_some());
        assert_eq!(
            classify(&after_the_adopting_write),
            Ownership::Managed,
            "the adopting write wrote the marker, so nothing further needs a decision"
        );
    }

    #[test]
    fn a_name_nobody_adopted_still_mints_no_capability_at_all() {
        let adopted = AdoptedNames::recorded(&["plex.example.com"]);
        let sonarr = record("sonarr.example.com", false);
        assert_eq!(ManagedRecordId::claim(&sonarr), None);
        assert_eq!(adopted.decision_for(&sonarr.name), None);
        assert!(!may_overwrite(&sonarr));
        assert!(!may_delete(&sonarr));
    }
}
