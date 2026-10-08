//! The rate limit that stops a flapping link from burning the Cloudflare
//! quota -- and the memory that makes "the address changed" a fact rather
//! than a guess.
//!
//! **Why a file at all.** Discovery (`ferrum_dns::public_ip`) answers *what
//! the address is now*. Two of F1/R1's requirements need *what it was*: the
//! journal line that names the old and the new value, and the flap
//! rate-limit. The zone itself cannot answer the second one -- it holds one
//! value, not a history -- so the updater keeps its own, beside the
//! last-success marker `modules/proxy/dns.nix` already makes the state
//! directory writable for.
//!
//! **The rate limit is a budget, not a delay.** The obvious design -- a
//! minimum gap between changes -- is wrong here in both directions: set
//! shorter than `ddnsUpdater.intervalMinutes` it never fires, and set longer
//! it delays the *first*, legitimate change, which is the one the operator
//! is actually waiting for. So the rule is a rolling budget instead:
//! [`MAX_CHANGES_PER_WINDOW`] published changes per [`WINDOW`]. A real ISP
//! reconnect is published immediately, every time. A link oscillating
//! between two addresses gets three passes and is then held, with the
//! oscillation named, until the window clears.
//!
//! **Holding is a disclosure, never a silent success and never a failure.**
//! The records keep pointing at the last address ferrum published, which may
//! well be wrong -- so the operator is told, in the journal, with both
//! addresses and the fact that the link is flapping. It is not an error
//! because nothing failed: ferrum looked, found an answer, and deliberately
//! declined to spend a write on a value that is about to change again.
//!
//! **A corrupt or missing file is never fatal.** It degrades to an empty
//! history, which costs at most one extra permitted change, and it says so.
//! Refusing to publish because a bookkeeping file was unreadable would turn
//! a cosmetic problem into the outage this requirement exists to prevent.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// How many address changes may be published in one [`WINDOW`].
///
/// Three is chosen against the real distribution rather than a round
/// number: a residential ISP reassigns on reconnect, which is a handful of
/// times a year for most lines and at most daily for the worst. A line
/// changing four times in a day is not reassigning, it is flapping, and
/// every further Cloudflare write buys nothing.
pub const MAX_CHANGES_PER_WINDOW: usize = 3;

/// The rolling window the budget is counted over.
pub const WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// How many past changes are retained.
///
/// Enough to recognise an oscillation between two or three addresses, small
/// enough that the file stays a few hundred bytes and can be read at a
/// glance by an operator debugging their own link.
const RETAINED: usize = 8;

/// The file name under `ferrum.storage.stateDir`.
///
/// Beside `dns-updater-last-success`, and for the same reason: that
/// directory is the one path `modules/proxy/dns.nix` grants the updater unit
/// write access to under `ProtectSystem = "strict"`.
pub const FILE_NAME: &str = "dns-public-address.json";

/// One address this host published, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// The address that was published.
    pub address: Ipv4Addr,
    /// Seconds since the Unix epoch. A bare integer rather than a formatted
    /// timestamp because the only consumer is arithmetic, and a format is
    /// one more thing two versions of this binary could disagree about.
    pub at: u64,
}

/// Every address change this host has published recently, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct History {
    /// Up to [`RETAINED`] entries, oldest first.
    #[serde(default)]
    pub changes: Vec<Change>,
}

impl History {
    /// The address most recently published, if any.
    #[must_use]
    pub fn current(&self) -> Option<Ipv4Addr> {
        self.changes.last().map(|c| c.address)
    }

    /// Records a published change, keeping only the most recent
    /// [`RETAINED`].
    ///
    /// # Arguments
    /// * `address` - the address just published.
    /// * `at` - when it was published.
    pub fn record(&mut self, address: Ipv4Addr, at: SystemTime) {
        self.changes.push(Change {
            address,
            at: epoch_seconds(at),
        });
        let overflow = self.changes.len().saturating_sub(RETAINED);
        self.changes.drain(..overflow);
    }
}

/// What to do with a freshly discovered address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The discovered address is already the published one. Nothing to say
    /// and nothing to spend.
    Unchanged {
        /// The address, carried so the caller never re-derives it.
        address: Ipv4Addr,
    },
    /// Publish it, and record that it was published.
    Change {
        /// What was published before, or `None` on the first ever run.
        previous: Option<Ipv4Addr>,
        /// Whether this address was already in the retained history, i.e.
        /// the link is oscillating rather than moving on.
        flapping: bool,
    },
    /// The change budget for this window is spent. Keep publishing the old
    /// address and tell the operator why.
    RateLimited {
        /// What stays published.
        keep: Ipv4Addr,
        /// What was discovered and deliberately not published.
        discovered: Ipv4Addr,
        /// How many changes have already been published inside [`WINDOW`].
        changes_in_window: usize,
        /// Whether the discovered address is one already seen recently.
        flapping: bool,
        /// Seconds until the budget frees up, so the message can say when
        /// rather than only that.
        retry_in_seconds: u64,
    },
}

/// Decides what to do with a discovered address, given what was published
/// before.
///
/// # Arguments
/// * `history` - the retained changes, oldest first.
/// * `discovered` - the address the quorum agreed on.
/// * `now` - the current time.
///
/// # Returns
/// [`Decision::Unchanged`] when the address is already published,
/// [`Decision::Change`] when it may be published, and
/// [`Decision::RateLimited`] when the budget for this window is spent.
#[must_use]
pub fn decide(history: &History, discovered: Ipv4Addr, now: SystemTime) -> Decision {
    let Some(current) = history.current() else {
        // Nothing has ever been published by discovery on this host, so
        // there is no budget to spend and nothing to compare against. The
        // first observation always goes through: making an operator wait a
        // window for their first correct record would be the defect again,
        // wearing a rate limit.
        return Decision::Change {
            previous: None,
            flapping: false,
        };
    };
    if current == discovered {
        return Decision::Unchanged { address: current };
    }

    // The last entry is the address being replaced, so it is excluded: it is
    // not evidence of oscillation, it is simply the present.
    let flapping = history
        .changes
        .iter()
        .rev()
        .skip(1)
        .any(|c| c.address == discovered);

    let cutoff = epoch_seconds(now).saturating_sub(WINDOW.as_secs());
    let in_window: Vec<&Change> = history
        .changes
        .iter()
        .filter(|c| c.at >= cutoff)
        .collect();
    if in_window.len() >= MAX_CHANGES_PER_WINDOW {
        let oldest = in_window
            .first()
            .map_or(cutoff, |c| c.at);
        return Decision::RateLimited {
            keep: current,
            discovered,
            changes_in_window: in_window.len(),
            flapping,
            retry_in_seconds: (oldest + WINDOW.as_secs()).saturating_sub(epoch_seconds(now)),
        };
    }

    Decision::Change {
        previous: Some(current),
        flapping,
    }
}

/// Reads the history file.
///
/// # Arguments
/// * `path` - normally `<stateDir>/dns-public-address.json`.
///
/// # Returns
/// The history, plus a sentence to disclose when the file existed and could
/// not be used. Never an error: see this module's header for why a
/// bookkeeping problem must not become an outage.
#[must_use]
pub fn load(path: &Path) -> (History, Option<String>) {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        // A missing file is the ordinary first run, not a problem.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (History::default(), None),
        Err(e) => {
            return (
                History::default(),
                Some(format!(
                    "the published-address history at {} could not be read ({e}), so this run \
                     treats the address as new",
                    path.display()
                )),
            )
        }
    };
    match serde_json::from_str(&raw) {
        Ok(history) => (history, None),
        Err(e) => (
            History::default(),
            Some(format!(
                "the published-address history at {} is not readable JSON ({e}), so this run \
                 treats the address as new and the flap budget starts over",
                path.display()
            )),
        ),
    }
}

/// Writes the history file.
///
/// # Arguments
/// * `path` - where to write it.
/// * `history` - the history to persist.
///
/// # Errors
/// Any I/O or serialisation error. The caller discloses it rather than
/// failing the run: the records were already published correctly, and the
/// only casualty is the next run's flap budget.
pub fn save(path: &Path, history: &History) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string(history)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(path, format!("{body}\n"))
}

/// Seconds since the Unix epoch, clamped at zero for a clock before it.
fn epoch_seconds(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: Ipv4Addr = Ipv4Addr::new(184, 148, 39, 165);
    const NEW: Ipv4Addr = Ipv4Addr::new(142, 180, 179, 64);
    const THIRD: Ipv4Addr = Ipv4Addr::new(24, 114, 9, 2);

    fn at(seconds_ago: u64, now: SystemTime) -> SystemTime {
        now - Duration::from_secs(seconds_ago)
    }

    fn history_of(entries: &[(Ipv4Addr, u64)], now: SystemTime) -> History {
        let mut history = History::default();
        for (address, seconds_ago) in entries {
            history.record(*address, at(*seconds_ago, now));
        }
        history
    }

    #[test]
    fn the_first_observation_is_published_immediately() {
        let now = SystemTime::now();
        assert_eq!(
            decide(&History::default(), NEW, now),
            Decision::Change {
                previous: None,
                flapping: false
            }
        );
    }

    #[test]
    fn an_unchanged_address_spends_nothing() {
        let now = SystemTime::now();
        let history = history_of(&[(NEW, 60)], now);
        assert_eq!(decide(&history, NEW, now), Decision::Unchanged { address: NEW });
    }

    /// The owner's actual incident: the address moved once, and that single
    /// move must be published at the first opportunity. A rate limit that
    /// delays this is the defect again.
    #[test]
    fn a_single_real_move_is_never_rate_limited() {
        let now = SystemTime::now();
        let history = history_of(&[(OLD, 90 * 24 * 3600)], now);
        assert_eq!(
            decide(&history, NEW, now),
            Decision::Change {
                previous: Some(OLD),
                flapping: false
            }
        );
    }

    #[test]
    fn a_fourth_change_inside_the_window_is_held_and_named_as_flapping() {
        let now = SystemTime::now();
        let history = history_of(&[(OLD, 10 * 3600), (NEW, 6 * 3600), (OLD, 2 * 3600)], now);
        match decide(&history, NEW, now) {
            Decision::RateLimited {
                keep,
                discovered,
                changes_in_window,
                flapping,
                retry_in_seconds,
            } => {
                assert_eq!(keep, OLD);
                assert_eq!(discovered, NEW);
                assert_eq!(changes_in_window, 3);
                assert!(flapping, "NEW is already in the retained history");
                assert!(
                    retry_in_seconds > 0 && retry_in_seconds <= WINDOW.as_secs(),
                    "{retry_in_seconds}"
                );
            }
            other => panic!("a fourth change in one window must be held: {other:?}"),
        }
    }

    /// Three changes that are all older than the window leave a full budget:
    /// the limit is rolling, not a lifetime cap.
    #[test]
    fn changes_older_than_the_window_do_not_count_against_the_budget() {
        let now = SystemTime::now();
        let history = history_of(
            &[(OLD, 72 * 3600), (NEW, 60 * 3600), (THIRD, 48 * 3600)],
            now,
        );
        assert_eq!(
            decide(&history, NEW, now),
            Decision::Change {
                previous: Some(THIRD),
                flapping: true
            }
        );
    }

    /// Three distinct addresses in a day is still a budget spend, even
    /// though nothing is oscillating -- the Cloudflare writes cost the same.
    #[test]
    fn a_held_change_is_reported_even_when_the_address_is_genuinely_new() {
        let now = SystemTime::now();
        let history = history_of(&[(OLD, 9 * 3600), (NEW, 5 * 3600), (THIRD, 3600)], now);
        match decide(&history, Ipv4Addr::new(8, 8, 4, 4), now) {
            Decision::RateLimited { flapping, keep, .. } => {
                assert!(!flapping, "a never-seen address is not an oscillation");
                assert_eq!(keep, THIRD);
            }
            other => panic!("the budget is spent: {other:?}"),
        }
    }

    #[test]
    fn the_history_keeps_only_the_most_recent_entries() {
        let now = SystemTime::now();
        let mut history = History::default();
        for i in 0..20u64 {
            history.record(Ipv4Addr::new(10, 0, 0, i as u8), now);
        }
        assert_eq!(history.changes.len(), RETAINED);
        assert_eq!(history.current(), Some(Ipv4Addr::new(10, 0, 0, 19)));
    }

    #[test]
    fn a_missing_file_is_an_empty_history_and_not_a_complaint() {
        let dir = tempfile::tempdir().unwrap();
        let (history, warning) = load(&dir.path().join(FILE_NAME));
        assert_eq!(history, History::default());
        assert_eq!(warning, None);
    }

    #[test]
    fn a_corrupt_file_degrades_to_empty_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        fs::write(&path, "{ this is not json").unwrap();
        let (history, warning) = load(&path);
        assert_eq!(history, History::default());
        let warning = warning.expect("a corrupt history must not be silent");
        assert!(warning.contains(FILE_NAME), "{warning}");
    }

    #[test]
    fn a_saved_history_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join(FILE_NAME);
        let now = SystemTime::now();
        let history = history_of(&[(OLD, 3600), (NEW, 60)], now);
        save(&path, &history).expect("the history is written");
        let (read_back, warning) = load(&path);
        assert_eq!(read_back, history);
        assert_eq!(warning, None);
    }
}
