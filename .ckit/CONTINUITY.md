# CONTINUITY — Working Memory

## Current Phase
**Phase 1.6a — pull-and-install.** Run `f81bafcf`, Mode B. Gates `spec-complete` + `em-approved`
CLOSED PASSED. **13 of 14 stories done. 12 commits, PUSHED. HEAD `9f12af8`.**

Spec: `docs/superpowers/specs/2026-09-17-phase-1-6a-install-path-design.md` (revision 4 + an
S13 deferral section). Story map: `.ckit/state/phase-1-6a-stories.md`.

## The installer, as built
`crates/ferrum-install/` — 14 modules. Invariants are documented in the commit messages and
module headers; the load-bearing ones are restated where the reviews touch them below.

## Security: BAR MET — cycle 5 PASS, 0 Critical/High/Medium
Five cycles, four Criticals, THREE of them in `precreate_serial_guard`. Cycle 5 proved it
empirically: 28 payloads x 3 shells x 5 contexts through real Rust -> real Nix -> real shells,
mutation-proved against the cycle-4 defect. Full narrative + the six durable lessons:
`.ckit/state/evidence/phase-1-6a-security-clear.md`. The ones that keep mattering:
**shell-quoted is not shell-safe — context decides** · **escaped-for-the-inner-layer is not safe
at the outer sink** · **a test asserting "the quoted form appears" is worthless — RENDER IT AND
EXECUTE IT** · **validate once at the boundary on EVERY ingress; a deserialize is not a
validation** · **confirm a mutation actually applied**.

## Also fixed after review: rustls RUSTSEC-2026-0285 bumped 0.23.43 -> 0.23.45 (owner-authorized;
one package, patch, 2 lines). `cargo audit` clean. `cargo-audit` CI job added and green.

## Owner bar: "keep going until it's fixed and no more medium or above"
Authorizes the rustls bump despite the dependency hard stop, FIXING the SEC-CRIT-002 residual
rather than accepting it, and security cycles past the 2-cycle budget.

## All 14 stories implemented. S13 is ITERATING IN CI and finding REAL BUGS.
Each run of `tests/stage2/run.sh` has found a genuine defect — the whole reason the story exists.
**Three of four would have hit real hardware, and NONE was visible to a unit test** (each piece
individually correct; only the real-world ordering wrong):
1. QEMU virtio disks report NO SERIAL → R2 A8 refused. *The gate working.* Fixed by giving the
   target disk one (`emptyDiskImages[].driveConfig.deviceExtraOpts.serial`).
2. **`check_serials_identify` refused the WHOLE machine because `fd0` (a floppy) has no serial.**
   Real hardware: empty optical drive, card reader. Fixed — no serial = **unselectable**
   (`match_serial` can never name it), not disqualifying. Still refused: duplicates, or a machine
   where nothing can be named.
3. **`custom/` was only created when there were data disks**, but the flake calls
   `importDir ./custom` unconditionally (= `readDir`, a hard error). **Any single-disk install
   produced an unevaluable config.** Fixed — always write `custom/.gitkeep`; a TRACKED file,
   because git ignores empty dirs and Nix ignores untracked files.
4. **`hardware-configuration.nix` does not exist at preflight time** — nixos-anywhere writes it
   DURING the install. So **Tier 1 could never evaluate a fresh install**, i.e. the
   pre-destructive check never ran. Fixed with a placeholder that nixos-anywhere overwrites.
   *Same file and same root cause as the code review's Critical* (the single-invocation design
   removed INSTALL.md's Step 3 without replacing what it provided).
Also raised the resume test's `Installing`-phase wait 10min → 60min: Tier 1 is a real flake eval
against the pinned rev and CI's nix cache is routinely throttled.

**When reading these CI logs:** magic-nix-cache spam (`HTTP error 418`, `rate limit exceeded`)
drowns everything and INTERLEAVES ONTO THE SAME LINE as real errors — my greps hid the real
`FAILED at` twice. Dump the log to a file and `grep -oE "FAILED at \[[^]]*\]: .{0,120}"`.


## PROCESS FAILURE — three times now, same shape
I trusted a command/edit instead of the result it produced:
1. a mutation test that silently failed to apply and showed a **false pass**;
2. a string `replace` that no-opped, so I **claimed a test in a commit message that did not
   exist** (the code reviewer caught it);
3. `83216ac` **pushed with a failing test**, because my chain used `;` instead of `&&` before the
   git block — and the failure was printed in output I had read.
**Every edit now asserts its anchor was found AND that the result landed; verification must gate
the commit with `&&`, never `;`.**

## Gate progress
- `spec-complete` PASSED · `em-approved` PASSED · **`code-review` PASSED** (3 reviewer passes,
  ending APPROVED, 0 C/H/M; evidence records the Critical no test could catch and the High my own
  fix caused).
- **NEXT: `build-green`** — waits on CI for the current HEAD.
- `contract-clear`: evidence WRITTEN and verified — `git diff 9e66264..HEAD -- crates/ferrumd
  modules/lib/settings-schema.json modules/core/options.nix modules/apps` is **empty**, so the
  condition `no-api-contract-surface` genuinely holds. Resolve with
  `not-applicable contract-clear --condition no-api-contract-surface`.
- `test-coverage`, then `security-clear` (evidence already written, cycle 5 PASS).

## VERIFIED for `2587799` (real output, gathered BEFORE the push this time)
`cargo test --workspace`: all 8 binaries `test result: ok`, 0 failed (196 in ferrum-install).
`clippy -p ferrum-install --all-targets -D warnings`: 0.


## Blind-spot patterns (full text in the spec's revision logs)
Cite a doc for INTENT, re-derive every FACTUAL claim from source · when a revision flips a default,
re-run every existing constraint against the newly-enabled surface · a spec asserting capability X
of component Y must cite the `file:line` providing it, and **when reasoning about a list, WALK THE
LIST**.

## Owner decisions (do NOT re-litigate)
Install before updates · **Docker image** the sole entry point · **force SSO on whenever a domain
is set** (declining needs a 2nd differently-shaped typed confirmation) · SSH by **shelling out**
(a Rust SSH crate was authorized but deliberately unused) · `nixos-anywhere` flake input and the
`ferrum-install` crate authorized · close the spec gate on the enumeration without a 4th review.
Full ledger with rejected alternatives + reopen triggers: `.ckit/state/evidence/phase-1-6a-em-decision.md`.

## Mistakes & Learnings
Parse checks/greps prove NOTHING about a UI — only a browser found Task 7's four bugs · never
write a settings.json value still equal to its default · a `pkgs.<name>` used in the MODULE TREE
must also be in `nix/overlays/default.nix` (4 instances) · Nix ignores untracked files, `git add`
first · mutation-test a guard before believing its test.

## Standing constraints (user-set)
- **No agent pushes, opens PRs, or comments on PRs — ever.** Those are main-session actions
  needing the user's in-conversation approval each time. No `pr-raiser` in runs.
- **Cargo.lock:** a cargo-produced workspace path-dep edge is pre-authorised; adding or bumping a
  real third-party package is a **HARD STOP** needing explicit authorization. Never hand-edit.
- The 3 pre-existing `assert_eq!`-literal-bool clippy errors in `apply.rs` are noted, never
  repaired; CI config untouched. build-green = "adds zero NEW findings".

## Toolchain (do not re-derive)
No native nix/cargo. Docker: `rust:1-bookworm` + volume `ferrum-cargo` + **btrfs-progs AND git**
+ `cp -r /src/examples /work/examples` (include_str! needs it). Nix: `nixos/nix` + volume
`ferrum-nixstore`; container is aarch64 so use `.#checks.aarch64-linux.*`. `timeout` is absent.
**Agent worktrees are cut at `main` and unusable — point reviewers at /Users/cs/repos/ferrum.**

## Repo State (from commands, never memory)
- branch `grounding-and-install-path`, PR #3. Last PUSHED: `9f12af8` (CI + VM tests GREEN).
- Gates: `spec-complete` and `em-approved` CLOSED. `code-review` is next and is FAILING.
  The ledger REFUSED `close-gate build-green` out of order — resolve code-review first.
- Security defect-loop: cycle 1 of 2 used.
