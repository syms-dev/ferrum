# Test sufficiency audit — can these tests fail?

**Date:** 2026-09-23. **Scope:** the whole suite, audited on one axis — **vacuity**. A test that
cannot fail is worse than no test, because it reports safety it never checked.

The axis was chosen rather than assumed. Road-to-public item 17 exists because this run's
test-coverage gate failed **twice** on exactly this: assertions scanning an empty corpus, and an
acceptance criterion enforced by nothing. So the question is not "is coverage high" but "of the
tests that exist, which are incapable of reporting a failure".

## Result

**The suite is in good shape on this axis.** Every candidate found was a false positive of the
detection heuristic, and the dangerous classes are guarded systematically rather than incidentally.

| Check | Population | Finding |
|---|---|---|
| Rust `#[test]` functions | **765** | — |
| Tests with no assertion of any kind | 765 | **0** (2 flagged, both false positives — `progress.rs:95` asserts three lines below the flag) |
| Tests whose corpus is **scanned** rather than literal | 51 | all guarded or literal |
| Nix checks registered | **41** | — |
| Nix check bodies with no anti-vacuity signal | 29 examined | **0 genuine** (7 flagged: 5 are helpers/fixtures/paths, 2 use hardcoded literal data and assert exact equality) |

Anti-vacuity vocabulary in `nix/modules/flake/checks.nix`: **176 occurrences** — `control` ×82,
`vacuous` ×9, `anti-vacuity` ×7, `would pass` ×7. That is not an accident of style; it is the
project having been bitten and responded.

## The pattern worth copying, found at `crates/ferrumd/src/main.rs:2124`

`the_source_scan_covers_every_module` is the strongest test in the suite, and it is strong because
it defends itself on **three** levels rather than one:

```rust
assert!(!declared.is_empty(), "the mod declarations must really have been found");
assert_eq!(declared, scanned, "CRATE_SOURCES must list every module main.rs declares, in order");
```

1. **The cross-check** — a hardcoded file list must equal the modules `main.rs` actually declares,
   so a new module cannot join the crate and silently escape every source scan built on that list.
2. **The anti-vacuity assertion** — if the recogniser returns nothing, the equality would hold
   between two empty lists and pass triumphantly. The `is_empty` line is what stops that.
3. **A positive control for the recogniser itself** —
   `a_module_declaration_is_recognised_whatever_its_visibility`. Without it, a recogniser that
   always returned `None` would sit green forever, pinning nothing.

Level 3 is the one usually missing elsewhere in the industry, and it is the one that matters: every
assertion level 2 feeds is of the form "nothing matched", so the recogniser is the whole guard.

This was independently re-derived twice during this run — the `pool-branches-are-all-seeded` check
added for item 5 is only load-bearing because of its length floor (reverting the bug leaves three
branches that agree *because all three are empty*, so the comparison alone passes), and
`no_comment_still_claims_the_daemon_has_no_vhost` ships with the same positive control.

## What this audit does NOT claim

Honest scope, because a sufficiency audit that overstates itself is the defect it hunts:

- **One axis only.** This says tests *can* fail. It does not say coverage is adequate, that the
  right behaviours are tested, or that the assertions are the right assertions.
- **No mutation testing of the suite as a whole.** Individual fixes this run were mutation-proved
  (revert the fix, watch the check go red) — that standard was applied per change, not retroactively
  to all 765 tests.
- **21 of 41 Nix checks have never run on this machine** — they are KVM-gated and this is a Mac.
  **Corrected 2026-09-23 after CI ran:** they are *not* unproven. CI's `vm-tests` job runs eight of
  them on `x86_64-linux` and **passed** — `install-from-nothing`, `rollback`,
  `rollback-proves-necessity`, `apply-generation-switch`, `daemon-end-to-end`,
  `daemon-apply-end-to-end`, `privilege-boundary`, `state-restore-interlock`. An earlier draft of
  this section said everything about a running system was "unproven rather than safe", which was
  materially overstated: it was true of this laptop and false of the project. The real residue is
  narrower — no run on *real hardware* (item 10) and no browser confirmation of the SSH-tunnel
  route (item 11).
- **The heuristics were crude on purpose** and produced 159 and then 26 candidates before being
  narrowed. Every survivor was inspected by hand. A quieter heuristic would have found less and
  claimed more.

## Conclusion

Item 17 was raised on real evidence — two gate failures on unfailable tests. Both were fixed during
the run, and this audit finds the pattern did not survive elsewhere. The remaining sufficiency risk
is **not** in the tests that exist; it is in the 21 checks that have never been executed.
