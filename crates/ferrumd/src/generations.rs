// GET /api/generations -- the generation list the rollback UI is built on.
//
// Enumerates `$FERRUM_PROFILES_DIR` directly rather than shelling out to
// `nix-env --list-generations`: a subprocess would put the whole `nix`
// closure on the unprivileged daemon's PATH (modules/core/daemon.nix gives
// ferrumd exactly `pkgs.sops` and `pkgs.ssh-to-age`) and talk to the Nix
// database on every page load of a read-only view.
// `ferrum_state::generations::parse_nix_env_list` stays where it is and
// keeps its tests; it is simply not the right mechanism here.
//
// `rollbackable: true` is a PRECHECK, NOT A GUARANTEE. ferrum-apply's
// gc.rs:105-132 deletes a snapshot subvolume BEFORE its journal entry, so a
// crash between the two leaves an entry pointing at nothing; rollback.rs:43-49
// catches exactly that and fails loudly. `POST /api/jobs` remains the
// authority on whether a rollback can actually proceed.
use anyhow::Context;
use axum::{http::StatusCode, response::IntoResponse, Json};
use ferrum_state::generations::{correlate, is_rollbackable};
use ferrum_state::journal::{self, JournalEntry};
use serde::Serialize;
use std::path::Path;
use std::time::UNIX_EPOCH;

/// One row of the response: a generation, its correlated journal entry, and
/// whether the UI may offer a rollback control for it.
#[derive(Serialize)]
pub struct GenerationRow {
    pub generation: u32,
    /// Unix-seconds-as-a-string, the identical shape
    /// `JournalEntry::taken_at` already uses. The browser localises it.
    pub date: String,
    pub current: bool,
    /// The full five-field `JournalEntry`, serialised as-is rather than
    /// trimmed into a second struct that would have to be kept in step with
    /// the crate.
    pub snapshot: Option<JournalEntry>,
    pub rollbackable: bool,
    pub reason: Option<String>,
}

/// The `GET /api/generations` document.
#[derive(Serialize)]
pub struct GenerationsResponse {
    /// `null` only when `system` resolves to a target that does not match
    /// `system-<N>-link`; the generation list is still truthful there.
    pub current: Option<u32>,
    pub generations: Vec<GenerationRow>,
}

/// Parses the generation number out of a `system-<N>-link` profile entry.
///
/// Returns `None` for anything else -- `/nix/var/nix/profiles/` legitimately
/// holds `per-user` and other profiles, and encountering one is normal.
fn parse_generation_link(name: &str) -> Option<u32> {
    name.strip_prefix("system-")?.strip_suffix("-link")?.parse().ok()
}

/// Lists the generations in a Nix profile directory, newest first.
///
/// # Arguments
/// * `dir` - the profile directory, normally `/nix/var/nix/profiles`.
///
/// # Returns
/// `(generation, date, current)` triples sorted descending by generation
/// number, in the shape `ferrum_state::generations::correlate` consumes.
/// `date` is each link's own mtime as unix-seconds-as-a-string.
///
/// # Errors
/// Names the real path when the directory cannot be read, when the `system`
/// symlink cannot be resolved, or when a link's metadata cannot be read. A
/// fault must never render as an empty list: an empty list is indistinguishable
/// from the valid "this host has never applied through ferrum-apply" state.
pub fn list_profile_generations(dir: &Path) -> anyhow::Result<Vec<(u32, String, bool)>> {
    let system = dir.join("system");
    let target = std::fs::read_link(&system).with_context(|| {
        format!("failed to resolve the `system` symlink at {}", system.display())
    })?;
    // `None` when `system` points somewhere that is not a generation link --
    // the one case that degrades `current` rather than failing the request.
    let current = target
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(parse_generation_link);

    let mut generations = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("failed to read profile directory {}", dir.display()))?
    {
        let entry = entry
            .with_context(|| format!("failed to read profile directory {}", dir.display()))?;
        let name = entry.file_name();
        let Some(generation) = name.to_str().and_then(parse_generation_link) else {
            continue;
        };
        let path = entry.path();
        // symlink_metadata (lstat), NEVER metadata (stat): stat follows
        // through to the store path, whose mtime is the Nix epoch and is
        // identical for every generation.
        let mtime = std::fs::symlink_metadata(&path)
            .with_context(|| format!("failed to stat {}", path.display()))?
            .modified()
            .with_context(|| format!("no modification time for {}", path.display()))?
            .duration_since(UNIX_EPOCH)
            .with_context(|| format!("modification time for {} precedes the unix epoch", path.display()))?;
        generations.push((generation, mtime.as_secs().to_string(), Some(generation) == current));
    }
    generations.sort_by_key(|g| std::cmp::Reverse(g.0));
    Ok(generations)
}

/// Builds the response from a profile directory and a journal directory.
///
/// # Arguments
/// * `profiles_dir` - the Nix profile directory.
/// * `journal_dir` - ferrum's snapshot journal directory. A directory that
///   does not exist is NOT an error: `journal::list` returns `Ok(vec![])`,
///   which correctly renders as "every generation exists, none is rollbackable".
///
/// # Returns
/// The `current` generation number (or `None`) and one row per generation.
///
/// # Errors
/// Propagates `list_profile_generations`, or a journal that exists but cannot
/// be read or parsed.
pub fn build_response(profiles_dir: &Path, journal_dir: &Path) -> anyhow::Result<GenerationsResponse> {
    let listed = list_profile_generations(profiles_dir)?;
    let entries = journal::list(journal_dir)
        .with_context(|| format!("failed to read the journal directory {}", journal_dir.display()))?;
    let current = listed.iter().find(|(_, _, c)| *c).map(|(g, _, _)| *g);

    let generations = correlate(listed, entries)
        .into_iter()
        .map(|info| {
            // ferrumd's OWN check, layered on top of the crate's result.
            // Rolling back to the generation already running is a destructive
            // no-op, and gc.rs:76 protects the current generation's snapshot by
            // design -- so the crate's "no state snapshot ... or its snapshot
            // was pruned" message would be actively false here.
            let (rollbackable, reason) = if info.current {
                (
                    false,
                    Some(format!(
                        "generation {} is the generation this host is already running -- rolling back \
                         to it would restore every app's state directory from the last apply's \
                         snapshot and reboot, without changing the system closure",
                        info.generation
                    )),
                )
            } else {
                match is_rollbackable(&info) {
                    Ok(()) => (true, None),
                    // The crate's own message, verbatim -- the UI displays it.
                    Err(msg) => (false, Some(msg)),
                }
            };
            GenerationRow {
                generation: info.generation,
                date: info.date,
                current: info.current,
                snapshot: info.snapshot,
                rollbackable,
                reason,
            }
        })
        .collect();

    Ok(GenerationsResponse {
        current,
        generations,
    })
}

/// Resolves both directories from the environment and builds the response.
///
/// # Errors
/// An unset `FERRUM_PROFILES_DIR` or `FERRUM_JOURNAL_DIR` names the variable,
/// following the error style `catalog.rs` established.
pub fn build_generations() -> anyhow::Result<GenerationsResponse> {
    let profiles_dir = std::env::var("FERRUM_PROFILES_DIR")
        .map_err(|_| anyhow::anyhow!("FERRUM_PROFILES_DIR not set"))?;
    let journal_dir = std::env::var("FERRUM_JOURNAL_DIR")
        .map_err(|_| anyhow::anyhow!("FERRUM_JOURNAL_DIR not set"))?;
    build_response(Path::new(&profiles_dir), Path::new(&journal_dir))
}

/// `GET /api/generations` -- `200` with the generation list, or `500` naming
/// the real path that failed.
pub async fn get_generations() -> impl IntoResponse {
    match build_generations() {
        Ok(doc) => (StatusCode::OK, Json(doc)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, FileTimes};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    /// Creates `system-<generation>-link` inside `dir`, pointing at `target`.
    fn link(dir: &Path, generation: u32, target: &Path) {
        symlink(target, dir.join(format!("system-{generation}-link"))).unwrap();
    }

    /// The whole-seconds mtime of `path` itself -- lstat, so a symlink
    /// reports its own mtime rather than its target's.
    fn mtime_secs(path: &Path) -> u64 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Writes a journal entry for `generation` so it correlates as having a
    /// snapshot.
    fn journal_entry(journal_dir: &Path, generation: u32, unix_ts: u64) {
        journal::write(
            journal_dir,
            &JournalEntry {
                snapshot: format!("{unix_ts}-gen{generation}"),
                generation,
                toplevel: format!("/nix/store/toplevel-gen{generation}"),
                taken_at: unix_ts.to_string(),
                quiesced: true,
            },
        )
        .unwrap();
    }

    /// A profile directory whose generation links all point at ONE shared
    /// target, plus an empty journal directory. Returns both paths.
    fn fixture(dir: &Path, generations: &[u32], current: u32) -> (PathBuf, PathBuf) {
        let profiles = dir.join("profiles");
        let journal = dir.join("journal");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::create_dir_all(&journal).unwrap();
        let target = dir.join("shared-target");
        std::fs::create_dir_all(&target).unwrap();
        for generation in generations {
            link(&profiles, *generation, &target);
        }
        symlink(
            profiles.join(format!("system-{current}-link")),
            profiles.join("system"),
        )
        .unwrap();
        (profiles, journal)
    }

    /// AC16 -- the discriminating lstat-vs-stat test.
    ///
    /// EVERY generation link points at ONE shared target directory whose
    /// mtime is stamped decades away with `std::fs::File::set_times`, so the
    /// assertion is two-sided: each reported `date` must EQUAL its own link's
    /// mtime (which a `stat`-following implementation cannot satisfy, since
    /// stat would report the shared target's stamped mtime for all three) and
    /// must DIFFER from the shared target's mtime (which rejects a degenerate
    /// implementation returning a constant). A one-sided ordering assertion
    /// cannot do both -- see the plan's Step 5 note.
    #[test]
    fn date_is_the_links_own_mtime_not_its_targets() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2, 3], 2);
        let target = dir.path().join("shared-target");
        // Every generation gets a snapshot whose `taken_at` is a DIFFERENT
        // fixed instant from any link mtime, so the response-level assertion
        // below discriminates a `date` sourced from the snapshot instead of
        // from the link.
        for generation in [1, 2, 3] {
            journal_entry(&journal, generation, 1_770_000_000);
        }

        // 2001-09-09T01:46:40Z -- a fixed distance far more than the 1s
        // resolution `date` is serialised at, so no `sleep` is needed.
        let stamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let handle = File::open(&target).expect("stamp shared target mtime");
        handle
            .set_times(FileTimes::new().set_accessed(stamp).set_modified(stamp))
            .expect("stamp shared target mtime");
        let target_secs = mtime_secs(&target);
        assert_eq!(target_secs, 1_000_000_000, "the fixture's stamp must hold");

        let listed = list_profile_generations(&profiles).unwrap();
        assert_eq!(listed.len(), 3);
        for (generation, date, _) in &listed {
            let own = mtime_secs(&profiles.join(format!("system-{generation}-link")));
            assert_eq!(
                date,
                &own.to_string(),
                "generation {generation}'s date must be its own link's mtime (lstat)"
            );
            assert_ne!(
                date,
                &target_secs.to_string(),
                "generation {generation}'s date must NOT be the shared target's mtime (stat)"
            );
        }

        // The same fixture, through the function that actually builds the
        // WIRE document. `list_profile_generations` being right is necessary
        // but not sufficient: `build_response` copies the date into each row,
        // and nothing else asserts that it copies THAT field. A row whose
        // `date` silently became the snapshot's `taken_at` -- the "installed
        // at" column quietly turning into "snapshot taken at" for every
        // snapshotted generation -- fails here and only here.
        let doc = build_response(&profiles, &journal).unwrap();
        assert_eq!(doc.generations.len(), 3);
        for row in &doc.generations {
            let generation = row.generation;
            let own = mtime_secs(&profiles.join(format!("system-{generation}-link")));
            assert!(
                row.snapshot.is_some(),
                "generation {generation} must have a correlated snapshot, or this \
                 assertion cannot discriminate"
            );
            assert_eq!(
                row.date,
                own.to_string(),
                "generation {generation}'s response date must be its own link's mtime, \
                 not its snapshot's taken_at"
            );
            assert_ne!(
                row.date, "1770000000",
                "generation {generation}'s response date must not be the snapshot's taken_at"
            );
        }
    }

    /// AC17 -- `system` resolving to one of the links marks that generation.
    #[test]
    fn the_system_symlink_marks_the_right_generation_current() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2, 3], 2);

        let doc = build_response(&profiles, &journal).unwrap();
        assert_eq!(doc.current, Some(2));
        let marked: Vec<u32> = doc
            .generations
            .iter()
            .filter(|r| r.current)
            .map(|r| r.generation)
            .collect();
        assert_eq!(marked, vec![2], "exactly one row may be marked current");
    }

    /// AC18 -- `per-user` and friends are normal profile-directory contents.
    #[test]
    fn non_generation_entries_are_skipped_rather_than_erroring() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2], 1);
        std::fs::create_dir(profiles.join("per-user")).unwrap();
        std::fs::write(profiles.join("default"), "not a generation").unwrap();
        symlink(dir.path(), profiles.join("system-not-a-number-link")).unwrap();

        let doc = build_response(&profiles, &journal).expect("non-matching entries must not error");
        let listed: Vec<u32> = doc.generations.iter().map(|r| r.generation).collect();
        assert_eq!(listed, vec![2, 1]);
    }

    /// Adversarial gap: a generation number too large for `u32` must be
    /// skipped like any other non-matching entry, never panic or bubble up
    /// as a parse error -- `str::parse::<u32>().ok()` already turns overflow
    /// into `None`, but that safety property had no test naming it.
    #[test]
    fn a_generation_number_overflowing_u32_is_skipped_rather_than_erroring() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2], 1);
        let target = dir.path().join("shared-target");
        // u32::MAX is 4294967295 (10 digits); this is 11 nines, well past it.
        symlink(&target, profiles.join("system-99999999999-link")).unwrap();

        let doc = build_response(&profiles, &journal)
            .expect("an overflowing generation number must not error");
        let listed: Vec<u32> = doc.generations.iter().map(|r| r.generation).collect();
        assert_eq!(listed, vec![2, 1], "the overflowing entry must be skipped, not listed");
    }

    /// The list is newest-first, which the rollback UI depends on.
    #[test]
    fn generations_are_sorted_descending_by_generation_number() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[2, 10, 1, 9], 1);

        let doc = build_response(&profiles, &journal).unwrap();
        let listed: Vec<u32> = doc.generations.iter().map(|r| r.generation).collect();
        assert_eq!(listed, vec![10, 9, 2, 1], "10 must sort above 9, not below");
    }

    /// AC19 -- a non-current generation with a snapshot is rollbackable; one
    /// without carries `is_rollbackable`'s message VERBATIM, because the UI
    /// displays it.
    #[test]
    fn rollbackable_and_reason_track_whether_a_snapshot_exists() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2, 3], 3);
        journal_entry(&journal, 2, 1_770_000_000);

        let doc = build_response(&profiles, &journal).unwrap();
        let row = |g: u32| doc.generations.iter().find(|r| r.generation == g).unwrap();

        let with = row(2);
        assert!(with.rollbackable, "a snapshotted generation is rollbackable");
        assert!(with.reason.is_none(), "no reason accompanies a true");
        assert_eq!(with.snapshot.as_ref().unwrap().snapshot, "1770000000-gen2");

        let without = row(1);
        assert!(!without.rollbackable);
        assert!(without.snapshot.is_none());
        let info = ferrum_state::generations::GenerationInfo {
            generation: 1,
            date: String::new(),
            current: false,
            snapshot: None,
        };
        let verbatim = is_rollbackable(&info).unwrap_err();
        assert_eq!(
            without.reason.as_deref(),
            Some(verbatim.as_str()),
            "the crate's message must be passed through unaltered"
        );
    }

    /// AC20 -- rolling back to the generation already running is a
    /// destructive no-op, so it is never offered EVEN WITH a snapshot, and
    /// the reason says so rather than claiming the snapshot was pruned.
    #[test]
    fn the_current_generation_is_never_rollbackable_even_with_a_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2], 2);
        journal_entry(&journal, 2, 1_770_000_000);

        let doc = build_response(&profiles, &journal).unwrap();
        let current = doc.generations.iter().find(|r| r.current).unwrap();
        assert_eq!(current.generation, 2);
        assert!(
            current.snapshot.is_some(),
            "the fixture must give the current generation a snapshot, or this proves nothing"
        );
        assert!(!current.rollbackable);
        let reason = current.reason.as_deref().unwrap();
        assert!(
            reason.contains("already running"),
            "the reason must name it as already running, got: {reason}"
        );
        assert!(
            !reason.contains("pruned"),
            "the crate's pruned-snapshot wording is actively false here, got: {reason}"
        );
    }

    /// AC21 -- a host that has never applied through ferrum-apply has no
    /// journal directory. That is a valid state, not a fault.
    #[test]
    fn an_absent_journal_directory_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, _journal) = fixture(dir.path(), &[1, 2], 2);
        let absent = dir.path().join("no-journal-here");
        assert!(!absent.exists());

        let doc = build_response(&profiles, &absent).expect("an absent journal dir must not error");
        assert_eq!(doc.generations.len(), 2, "the generation list stays truthful");
        assert!(
            doc.generations.iter().all(|r| !r.rollbackable),
            "nothing is rollbackable without a journal"
        );
        assert!(doc.generations.iter().all(|r| r.snapshot.is_none()));
    }

    /// Adversarial gap: a journal entry for a generation number that has
    /// since been garbage-collected (no matching `system-<N>-link` remains)
    /// must be silently ignored -- never fabricate a phantom row for a
    /// generation that no longer exists on disk, and never attach the stale
    /// entry to a different generation.
    #[test]
    fn a_stale_journal_entry_with_no_matching_profile_link_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2], 2);
        // Generation 7 was gc'd off the profile directory already; its
        // journal entry is left behind (a real, expected state).
        journal_entry(&journal, 7, 1_770_000_000);

        let doc = build_response(&profiles, &journal).unwrap();
        let listed: Vec<u32> = doc.generations.iter().map(|r| r.generation).collect();
        assert_eq!(listed, vec![2, 1], "generation 7 must not appear -- it has no profile link");
        assert!(
            doc.generations.iter().all(|r| r.snapshot.is_none()),
            "the stale entry must not be misattached to generation 1 or 2 either"
        );
    }

    /// AC23 -- `system` pointing somewhere that is not a generation link
    /// degrades `current` to null without losing the list.
    #[test]
    fn a_system_symlink_off_the_generation_naming_yields_a_null_current() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles");
        let journal = dir.path().join("journal");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::create_dir_all(&journal).unwrap();
        let target = dir.path().join("shared-target");
        std::fs::create_dir_all(&target).unwrap();
        link(&profiles, 1, &target);
        link(&profiles, 2, &target);
        symlink(&target, profiles.join("system")).unwrap();

        let doc = build_response(&profiles, &journal).unwrap();
        assert_eq!(doc.current, None, "an unrecognised target degrades `current`");
        let listed: Vec<u32> = doc.generations.iter().map(|r| r.generation).collect();
        assert_eq!(listed, vec![2, 1], "the generation list is still truthful");
        assert!(doc.generations.iter().all(|r| !r.current));
    }

    /// Drives the real handler and returns its status and body.
    async fn call_endpoint() -> (StatusCode, String) {
        let response = get_generations().await.into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    /// AC22 -- the five DEC-03 error cases, plus the happy path.
    ///
    /// These mutate process-wide environment, which the other tests in this
    /// binary also read, so they are serialized into one #[test] rather than
    /// racing each other across the harness's threads -- the same discipline
    /// catalog.rs already applies for the identical reason.
    ///
    /// Each case asserts on the REAL PATH in the body, never on distinct
    /// wording: `read_link(dir/"system")` runs before `read_dir(dir)`, so an
    /// absent and an unreadable profile directory both surface as the same
    /// "failed to resolve the `system` symlink at ..." message. The path is
    /// what distinguishes them, and the path is what the operator needs.
    #[tokio::test]
    async fn generations_endpoint_error_cases_name_the_real_path() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2], 2);

        // The happy path through the real handler.
        std::env::set_var("FERRUM_PROFILES_DIR", &profiles);
        std::env::set_var("FERRUM_JOURNAL_DIR", &journal);
        let (status, body) = call_endpoint().await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert!(body.contains("\"current\":2"), "got: {body}");

        // 1. An unset FERRUM_PROFILES_DIR names the variable.
        std::env::remove_var("FERRUM_PROFILES_DIR");
        let (status, body) = call_endpoint().await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("FERRUM_PROFILES_DIR not set"), "got: {body}");

        // 2. An unset FERRUM_JOURNAL_DIR names the variable.
        std::env::set_var("FERRUM_PROFILES_DIR", &profiles);
        std::env::remove_var("FERRUM_JOURNAL_DIR");
        let (status, body) = call_endpoint().await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("FERRUM_JOURNAL_DIR not set"), "got: {body}");
        std::env::set_var("FERRUM_JOURNAL_DIR", &journal);

        // 3. A profile directory that does not exist names that directory.
        let absent = dir.path().join("no-profiles-here");
        std::env::set_var("FERRUM_PROFILES_DIR", &absent);
        let (status, body) = call_endpoint().await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains(absent.to_str().unwrap()), "got: {body}");

        // 4. A profile directory that cannot be READ -- genuinely reaching
        // `read_dir`'s error arm rather than being a second spelling of
        // case 3.
        //
        // Two details make it discriminating. The fixture is COMPLETE (it has
        // a real `system` symlink), so the earlier `read_link` succeeds and
        // execution really gets as far as `read_dir`. And the mode is 0111,
        // not 0000: `--x` still lets `readlink profiles/system` resolve while
        // denying the directory listing, which is exactly the split this case
        // needs. Root bypasses both via CAP_DAC_OVERRIDE, so this follows the
        // project's probe-and-skip idiom (cf. `permission_bits_are_ignored_here`
        // in main.rs) -- `cargo test` runs as uid 0 in CI.
        use std::os::unix::fs::PermissionsExt;
        let case4 = dir.path().join("case4");
        std::fs::create_dir(&case4).unwrap();
        let (unreadable, _journal4) = fixture(&case4, &[1, 2], 2);
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o111)).unwrap();
        if std::fs::read_dir(&unreadable).is_ok() {
            eprintln!(
                "skipping DEC-03 case 4's permission branch: this process ignores permission \
                 bits (root/CAP_DAC_OVERRIDE), so a 0111 directory is still listable here"
            );
        } else {
            std::env::set_var("FERRUM_PROFILES_DIR", &unreadable);
            let (status, body) = call_endpoint().await;
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(body.contains(unreadable.to_str().unwrap()), "got: {body}");
            assert!(
                body.contains("failed to read profile directory"),
                "this case must reach read_dir, not read_link -- got: {body}"
            );
        }
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o755)).unwrap();

        // 5. A `system` symlink that cannot be resolved names the symlink.
        let no_system = dir.path().join("no-system");
        std::fs::create_dir(&no_system).unwrap();
        let target = dir.path().join("shared-target");
        link(&no_system, 7, &target);
        std::env::set_var("FERRUM_PROFILES_DIR", &no_system);
        let (status, body) = call_endpoint().await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            body.contains(no_system.join("system").to_str().unwrap()),
            "got: {body}"
        );

        std::env::remove_var("FERRUM_PROFILES_DIR");
        std::env::remove_var("FERRUM_JOURNAL_DIR");
    }

    // ---------------------------------------------------------------
    // Senior Tester additions -- gaps the tester lane did not cover.
    // ---------------------------------------------------------------

    /// The WIRE CONTRACT. Every other test in this module asserts on Rust
    /// structs; nothing asserted the JSON a browser actually receives. A
    /// `#[serde(rename)]`, a field renamed on `GenerationRow`, a `u32`
    /// retyped to `String`, a `skip_serializing_if` added to an `Option`, or
    /// a sixth field appearing on `JournalEntry` would all ship green.
    /// This pins field names, types, `null`-vs-absent, and the exact key set
    /// at both levels.
    #[test]
    fn the_serialised_json_pins_field_names_types_and_null_vs_absent() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2, 3], 3);
        // gen 2 has a snapshot; gen 1 has none; gen 3 is current.
        journal_entry(&journal, 2, 1_770_000_000);

        let doc = build_response(&profiles, &journal).unwrap();
        let v = serde_json::to_value(&doc).unwrap();

        let top: Vec<&str> = {
            let mut k: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
            k.sort_unstable();
            k
        };
        assert_eq!(top, vec!["current", "generations"], "top-level key set is the contract");
        assert_eq!(v["current"], serde_json::json!(3), "`current` is a bare number");

        let rows = v["generations"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        for row in rows {
            let mut keys: Vec<&str> = row.as_object().unwrap().keys().map(|s| s.as_str()).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec!["current", "date", "generation", "reason", "rollbackable", "snapshot"],
                "every row carries exactly these six keys, present even when null"
            );
            assert!(row["generation"].is_u64(), "`generation` is a number, not a string");
            let date = row["date"].as_str().expect("`date` is a STRING");
            assert!(
                !date.is_empty() && date.chars().all(|c| c.is_ascii_digit()),
                "`date` is unix-seconds-as-a-string, got: {date}"
            );
            assert!(row["current"].is_boolean());
            assert!(row["rollbackable"].is_boolean());
        }

        let row = |g: u64| rows.iter().find(|r| r["generation"] == g).unwrap();

        // A generation with no snapshot: BOTH optional fields are present
        // and null -- a client may read them without an existence check.
        let one = row(1);
        assert!(one["snapshot"].is_null(), "absent snapshot serialises as null, not omitted");
        assert!(one["reason"].is_string(), "a false rollbackable always carries a reason");
        assert_eq!(one["rollbackable"], serde_json::json!(false));

        // A rollbackable generation: `reason` is present and null.
        let two = row(2);
        assert_eq!(two["rollbackable"], serde_json::json!(true));
        assert!(two["reason"].is_null(), "a true rollbackable serialises reason as null, not omitted");
        let mut snap: Vec<&str> =
            two["snapshot"].as_object().expect("nested entry is an object").keys().map(|s| s.as_str()).collect();
        snap.sort_unstable();
        assert_eq!(
            snap,
            vec!["generation", "quiesced", "snapshot", "taken_at", "toplevel"],
            "the nested JournalEntry's five fields are part of this endpoint's contract"
        );
        assert_eq!(two["snapshot"]["snapshot"], serde_json::json!("1770000000-gen2"));
        assert!(two["snapshot"]["quiesced"].is_boolean());
        assert!(two["snapshot"]["taken_at"].is_string());

        // `current: null` serialises as an explicit null, not an absent key.
        let off = dir.path().join("off");
        std::fs::create_dir_all(&off).unwrap();
        link(&off, 1, &dir.path().join("shared-target"));
        symlink(dir.path().join("shared-target"), off.join("system")).unwrap();
        let doc = build_response(&off, &journal).unwrap();
        let v = serde_json::to_value(&doc).unwrap();
        assert!(v.as_object().unwrap().contains_key("current"), "`current` key is never omitted");
        assert!(v["current"].is_null());
    }

    /// A journal directory holding a file that is not valid JSON fails the
    /// WHOLE request rather than skipping the bad file. That is the
    /// fail-loud choice, but nothing pinned it, so a later "just skip it"
    /// change would silently turn a corrupt journal into a UI that offers no
    /// rollbacks and says nothing. Pins the behaviour and the path named.
    #[test]
    fn a_malformed_journal_entry_fails_the_request_naming_the_journal_directory() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2], 2);
        journal_entry(&journal, 1, 1_770_000_000);
        std::fs::write(journal.join("corrupt.json"), "{ not json at all").unwrap();

        let Err(err) = build_response(&profiles, &journal) else {
            panic!("a corrupt journal entry must not pass silently");
        };
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(journal.to_str().unwrap()),
            "the operator needs the real journal path, got: {rendered}"
        );
    }

    /// `rollbackable` is a PRECHECK, not a guarantee (see this module's
    /// header): gc.rs deletes the snapshot subvolume BEFORE its journal
    /// entry, so an entry whose `snapshot` names a subvolume that no longer
    /// exists must still report `true` -- this endpoint deliberately does
    /// not stat the store. Nothing tested that, so a well-meant "verify the
    /// snapshot exists" addition would change the contract unnoticed and
    /// put a stat of the btrfs store on every page load.
    #[test]
    fn a_journal_entry_whose_snapshot_subvolume_is_gone_is_still_reported_rollbackable() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2], 2);
        journal_entry(&journal, 1, 1_770_000_000);
        // The snapshot name "1770000000-gen1" corresponds to no subvolume
        // anywhere on this filesystem -- the post-gc, pre-journal-delete state.
        assert!(!dir.path().join("1770000000-gen1").exists());

        let doc = build_response(&profiles, &journal).unwrap();
        let one = doc.generations.iter().find(|r| r.generation == 1).unwrap();
        assert!(
            one.rollbackable,
            "the precheck is journal-entry existence only; POST /api/jobs is the authority"
        );
        assert!(one.reason.is_none());
    }

    /// The interaction AC20 and AC23 leave open between them: when `system`
    /// resolves off the generation naming, NO row is `current`, so the
    /// "already running" guard cannot fire -- and a snapshotted generation
    /// that may well be the one actually booted is offered as rollbackable.
    /// Truthful given what the endpoint knows, but nothing asserted it, so
    /// the behaviour was neither chosen nor pinned.
    #[test]
    fn a_null_current_leaves_every_snapshotted_generation_rollbackable() {
        let dir = tempfile::tempdir().unwrap();
        let profiles = dir.path().join("profiles");
        let journal = dir.path().join("journal");
        std::fs::create_dir_all(&profiles).unwrap();
        std::fs::create_dir_all(&journal).unwrap();
        let target = dir.path().join("shared-target");
        std::fs::create_dir_all(&target).unwrap();
        link(&profiles, 1, &target);
        link(&profiles, 2, &target);
        symlink(&target, profiles.join("system")).unwrap();
        journal_entry(&journal, 2, 1_770_000_000);

        let doc = build_response(&profiles, &journal).unwrap();
        assert_eq!(doc.current, None);
        let two = doc.generations.iter().find(|r| r.generation == 2).unwrap();
        assert!(
            two.rollbackable,
            "with no known current, the already-running guard cannot fire"
        );
        assert!(
            doc.generations.iter().all(|r| r.reason.as_deref().is_none_or(|m| !m.contains("already running"))),
            "no row may claim to be already running when `current` is null"
        );
    }

    /// `system` may resolve to a `system-<N>-link` that read_dir no longer
    /// finds -- the gc window in which the link is unlinked while `system`
    /// still names it. The response stays SELF-CONSISTENT there: top-level
    /// `current` is derived from the listed rows, not from the symlink
    /// parse, so it degrades to null rather than naming a generation with no
    /// row. Nothing asserted that, and the struct's own doc-comment claims
    /// null happens "only" on an off-naming target -- this is the second,
    /// undocumented way. A future refactor that took `current` straight from
    /// `list_profile_generations`'s parse would hand the UI a `current` it
    /// cannot look up, and every existing test would still pass.
    #[test]
    fn a_current_whose_link_is_already_gone_degrades_to_null_rather_than_dangling() {
        let dir = tempfile::tempdir().unwrap();
        let (profiles, journal) = fixture(dir.path(), &[1, 2], 2);
        // `system` -> system-5-link, which was never created (or was gc'd).
        std::fs::remove_file(profiles.join("system")).unwrap();
        symlink(profiles.join("system-5-link"), profiles.join("system")).unwrap();

        let doc = build_response(&profiles, &journal).unwrap();
        let listed: Vec<u32> = doc.generations.iter().map(|r| r.generation).collect();
        assert_eq!(listed, vec![2, 1], "generation 5 has no link, so it has no row");
        assert_eq!(
            doc.current, None,
            "`current` must never name a generation absent from `generations`"
        );
        assert!(!doc.generations.iter().any(|r| r.current));
    }

}
