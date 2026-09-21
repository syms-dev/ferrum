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
//! **The match is exact, and that is load-bearing.** A substring, prefix, or
//! case-insensitive comparison would claim an unrelated record: an operator
//! comment reading `"migrated off ferrum-managed host"` contains the marker,
//! and `"Ferrum-Managed"` differs from it only in case. Either would make a
//! foreign record look owned, which is precisely the failure both guards
//! exist to prevent -- so [`is_ferrum_marker`] compares the whole string,
//! byte for byte, with no trimming. Cloudflare returns the comment
//! verbatim, so a marker ferrum wrote comes back byte-identical; anything
//! that does not match was not written by this code.

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

/// Proof that a record id names a record ferrum owns.
///
/// **This type is the A3/A4 guard, expressed so the compiler enforces it.**
/// [`crate::client::Client::update_record`] and
/// [`crate::client::Client::delete_record`] accept only this, never a bare
/// `&str`, and the only way to mint one outside this crate is
/// [`crate::record::plan`] -- which mints it only for a record carrying
/// [`OWNERSHIP_MARKER`].
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
}
