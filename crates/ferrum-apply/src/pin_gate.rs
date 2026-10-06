// The gate that stops an ordinary settings apply from carrying an update in
// on its back (R8's third criterion).
//
// The hole it closes, exactly: `rollback.rs` reverts the system closure and
// never touches `/etc/ferrum/flake.lock` -- it names neither that file nor
// `FERRUM_FLAKE_REF` anywhere -- while every apply rebuilds from whatever
// the on-disk lock currently pins. So update -> regression -> rollback ->
// (days later) toggle an unrelated setting -> Apply silently rebuilt from
// the still-advanced pin and the rejected update came back, as a generation
// that reads like an ordinary settings change. No attacker, no unusual
// sequence.
//
// What this module is NOT. It is not a lock, a policy, or a second opinion
// about whether an update is wise. It exists to make the decision VISIBLE,
// which is why `decide` takes an acknowledgement and why that
// acknowledgement passes: an operator who deliberately wants the new pin
// after rolling the closure back must be able to say so and proceed. A wall
// here would turn a rolled-back host into one that cannot be updated at all
// without hand-editing the lock, which is strictly worse than the hole.
//
// Everything is a pure function over values the caller read, so the whole
// decision is exercised below without a flake, a journal, or a profile
// directory.
use ferrum_state::journal::Pin;

/// How the on-disk pin stands against the pin the running generation was
/// built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinState {
    /// One side or both could not be established. Named, so a caller can
    /// say WHICH is unknown rather than reporting a disagreement it did not
    /// observe.
    ///
    /// This is the state the owner's live host is in for every generation
    /// that predates `built_toplevel`/`built_pin`, and R8's own edge case
    /// settles what it means: the absence is an artifact of age, not a
    /// disagreement, and it must never gate an apply. A spurious gate on a
    /// host whose journal simply predates the fields would be a
    /// self-inflicted outage.
    Unknown(UnknownSide),
    /// Both pins are known and identical. An ordinary apply.
    Matches,
    /// Both pins are known and differ. This rebuild would move the host to
    /// a different ferrum revision.
    Differs { on_disk: Pin, recorded: Pin },
}

/// Which half of the comparison could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownSide {
    /// `/etc/ferrum/flake.lock` could not be read, or does not pin `ferrum`
    /// in a shape `pin::parse` accepts.
    OnDisk,
    /// No journal entry claims the running closure, or the entry that does
    /// recorded no pin -- normally because it was written by a ferrum that
    /// had neither field.
    Running,
    /// Neither side is known.
    Both,
}

/// What an apply should do about the comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Build and switch. Every state but an unacknowledged `Differs`.
    Proceed,
    /// Refuse before anything is built, with the operator-facing text.
    Refuse(Refusal),
}

/// A refusal, with the revision an acknowledgement would have to name.
///
/// Two fields rather than one formatted string because the two have
/// different audiences: `message` is prose for the operator, and
/// `accept_rev` is the exact value the retry has to carry. Formatting them
/// into one string and asking the caller to pick it apart is how the UI
/// would end up parsing prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The on-disk revision, full 40-hex. The retry acknowledges THIS, so
    /// an acknowledgement cannot outlive the revision it was given for.
    pub accept_rev: String,
    /// What the operator is told.
    pub message: String,
}

/// The first seven characters of a revision, the short form the rest of the
/// codebase displays.
///
/// # Arguments
/// * `rev` - a revision, of any length.
///
/// # Returns
/// Its first seven characters, or the whole thing when it is shorter.
fn short(rev: &str) -> &str {
    rev.get(..7).unwrap_or(rev)
}

/// Compare the pin on disk with the pin the running generation was built
/// from.
///
/// # Arguments
/// * `on_disk` - `pin::read` of the flake the next build would use.
/// * `recorded` - `generations::built_pin_of` for the running closure.
///
/// # Returns
/// `Unknown` when either side is absent, `Matches` when both are present
/// and equal, `Differs` otherwise. Equality is over the WHOLE pin: a
/// matching revision whose NAR hash moved is a different tree under the
/// same name, which is exactly the case an operator would want named.
pub fn classify(on_disk: Option<Pin>, recorded: Option<Pin>) -> PinState {
    match (on_disk, recorded) {
        (None, None) => PinState::Unknown(UnknownSide::Both),
        (None, Some(_)) => PinState::Unknown(UnknownSide::OnDisk),
        (Some(_), None) => PinState::Unknown(UnknownSide::Running),
        (Some(on_disk), Some(recorded)) if on_disk == recorded => PinState::Matches,
        (Some(on_disk), Some(recorded)) => PinState::Differs { on_disk, recorded },
    }
}

/// Decide whether an apply may proceed.
///
/// # Arguments
/// * `state` - the comparison from `classify`.
/// * `generation` - the generation this host is running, named in the
///   message so the operator can find it in the Generations view.
/// * `accepted` - the revision the operator acknowledged on this attempt,
///   from the request file. Compared for EQUALITY against the on-disk
///   revision and used for nothing else -- it decides nothing about what is
///   fetched or built, so a hostile value can only fail to match.
///
/// # Returns
/// `Proceed` for `Matches`, for every `Unknown`, and for a `Differs` whose
/// on-disk revision the operator acknowledged exactly. `Refuse` only for an
/// unacknowledged `Differs`.
pub fn decide(state: &PinState, generation: u32, accepted: Option<&str>) -> Decision {
    let PinState::Differs { on_disk, recorded } = state else {
        return Decision::Proceed;
    };
    if accepted == Some(on_disk.rev.as_str()) {
        return Decision::Proceed;
    }

    // Said separately when the revision is the same, because "ferrum
    // abc1234 -> abc1234" reads as a bug in this message rather than as the
    // real finding, which is that the tree behind that revision moved.
    let what_moved = if on_disk.rev == recorded.rev {
        format!(
            "the revision is unchanged ({}) but the tree behind it is not: the lock now records \
             {} where generation {generation} was built from {}",
            short(&on_disk.rev),
            on_disk.nar_hash,
            recorded.nar_hash
        )
    } else {
        format!(
            "it would move ferrum from {} -- the revision generation {generation} was built from \
             -- to {}",
            short(&recorded.rev),
            short(&on_disk.rev)
        )
    };

    Decision::Refuse(Refusal {
        accept_rev: on_disk.rev.clone(),
        message: format!(
            "this is not only a settings change: {what_moved}. Nothing has been built and nothing \
             has changed. Either apply again accepting that revision, or put the pin back \
             (`git -C /etc/ferrum checkout flake.lock`) and apply."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(rev: &str, hash: &str) -> Pin {
        Pin { rev: rev.to_string(), nar_hash: hash.to_string() }
    }

    const OLD: &str = "1111111111111111111111111111111111111111";
    const NEW: &str = "2222222222222222222222222222222222222222";

    #[test]
    fn two_identical_pins_match() {
        assert_eq!(classify(Some(pin(OLD, "h")), Some(pin(OLD, "h"))), PinState::Matches);
    }

    #[test]
    fn a_different_revision_differs() {
        let state = classify(Some(pin(NEW, "h2")), Some(pin(OLD, "h1")));
        assert_eq!(
            state,
            PinState::Differs { on_disk: pin(NEW, "h2"), recorded: pin(OLD, "h1") }
        );
    }

    /// The same revision resolving to a different tree is a difference too.
    /// Comparing revisions alone would let a re-pointed tag through as
    /// "matches", which is the one case the NAR hash is in `Pin` for.
    #[test]
    fn the_same_revision_with_a_different_nar_hash_differs() {
        assert!(matches!(
            classify(Some(pin(OLD, "sha256-NEW=")), Some(pin(OLD, "sha256-OLD="))),
            PinState::Differs { .. }
        ));
    }

    #[test]
    fn an_absent_side_is_named_rather_than_guessed() {
        assert_eq!(classify(None, Some(pin(OLD, "h"))), PinState::Unknown(UnknownSide::OnDisk));
        assert_eq!(classify(Some(pin(OLD, "h")), None), PinState::Unknown(UnknownSide::Running));
        assert_eq!(classify(None, None), PinState::Unknown(UnknownSide::Both));
    }

    /// The gate fires on a real difference, names both revisions, and says
    /// nothing has happened yet.
    #[test]
    fn an_unacknowledged_difference_refuses_before_anything_is_built() {
        let state = classify(Some(pin(NEW, "h2")), Some(pin(OLD, "h1")));
        let Decision::Refuse(refusal) = decide(&state, 7, None) else {
            panic!("a real pin difference must gate the apply");
        };
        assert_eq!(refusal.accept_rev, NEW, "the retry acknowledges the ON-DISK revision");
        assert!(refusal.message.contains("1111111"), "names the running pin: {}", refusal.message);
        assert!(refusal.message.contains("2222222"), "names the on-disk pin: {}", refusal.message);
        assert!(refusal.message.contains("generation 7"), "{}", refusal.message);
        assert!(
            refusal.message.contains("Nothing has been built"),
            "the operator must know this cost them nothing: {}",
            refusal.message
        );
    }

    /// The anti-vacuity half, and the one that matters most: a gate that
    /// fires on everything is as broken as one that fires on nothing. Every
    /// state but an unacknowledged difference proceeds silently.
    #[test]
    fn nothing_but_a_real_unacknowledged_difference_is_gated() {
        for (label, state) in [
            ("matching pins", classify(Some(pin(OLD, "h")), Some(pin(OLD, "h")))),
            ("the on-disk pin unknown", classify(None, Some(pin(OLD, "h")))),
            ("the running generation's pin unknown", classify(Some(pin(NEW, "h")), None)),
            ("neither known", classify(None, None)),
        ] {
            assert_eq!(
                decide(&state, 7, None),
                Decision::Proceed,
                "{label} must not gate an apply"
            );
        }
    }

    /// R8's edge case, held on its own: a generation predating the fields
    /// reads as a `None` recorded pin, and a `None` must never become a
    /// difference however loudly the on-disk side disagrees with everything
    /// else. The host this feature was built for has a journal made
    /// entirely of such entries.
    #[test]
    fn a_pin_unknown_generation_never_justifies_a_gate() {
        let aged = classify(Some(pin(NEW, "h")), None);
        assert_eq!(aged, PinState::Unknown(UnknownSide::Running));
        assert_eq!(decide(&aged, 42, None), Decision::Proceed);
        // ...including when the operator supplies an acknowledgement that
        // matches nothing, which must not turn a non-event into one either.
        assert_eq!(decide(&aged, 42, Some(OLD)), Decision::Proceed);
    }

    /// The gate is passable: acknowledging the exact on-disk revision lets
    /// the same apply through.
    #[test]
    fn acknowledging_the_on_disk_revision_passes_the_gate() {
        let state = classify(Some(pin(NEW, "h2")), Some(pin(OLD, "h1")));
        assert_eq!(decide(&state, 7, Some(NEW)), Decision::Proceed);
    }

    /// And only that revision. An acknowledgement of some other value --
    /// including the revision being rolled away from, the short form, and a
    /// stale one from a previous attempt -- is not an acknowledgement of
    /// this one.
    #[test]
    fn an_acknowledgement_of_any_other_value_does_not_pass() {
        let state = classify(Some(pin(NEW, "h2")), Some(pin(OLD, "h1")));
        for other in ["", OLD, "2222222", "3333333333333333333333333333333333333333"] {
            assert!(
                matches!(decide(&state, 7, Some(other)), Decision::Refuse(_)),
                "{other:?} must not pass the gate"
            );
        }
    }

    /// A tree that moved under an unchanged revision gets its own sentence,
    /// because "ferrum abc1234 -> abc1234" would read as a bug in the
    /// message rather than as the finding.
    #[test]
    fn a_moved_tree_under_one_revision_says_so_rather_than_naming_one_revision_twice() {
        let state = classify(Some(pin(OLD, "sha256-NEW=")), Some(pin(OLD, "sha256-OLD=")));
        let Decision::Refuse(refusal) = decide(&state, 3, None) else {
            panic!("a moved tree is a difference");
        };
        assert!(refusal.message.contains("sha256-NEW="), "{}", refusal.message);
        assert!(refusal.message.contains("sha256-OLD="), "{}", refusal.message);
        assert!(
            !refusal.message.contains("would move ferrum from"),
            "the revision did not move, so the message must not say it did: {}",
            refusal.message
        );
    }

    #[test]
    fn short_takes_seven_characters_and_tolerates_a_shorter_revision() {
        assert_eq!(short(OLD), "1111111");
        assert_eq!(short("abc"), "abc");
    }
}
