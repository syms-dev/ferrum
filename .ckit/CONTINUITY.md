# CONTINUITY — Working Memory

## Current Phase
**Phase 1.6a — pull-and-install.** Run `f81bafcf`, Mode B. Gates `spec-complete` + `em-approved`
CLOSED PASSED. **13 of 14 stories done. 12 commits, PUSHED. HEAD `9f12af8`.**

Spec: `docs/superpowers/specs/2026-09-17-phase-1-6a-install-path-design.md` (revision 4 + an
S13 deferral section). Story map: `.ckit/state/phase-1-6a-stories.md`.

## The installer, as built
`crates/ferrum-install/` — 14 modules. Invariants are documented in the commit messages and
module headers; the load-bearing ones are restated where the reviews touch them below.

## Review fixes COMMITTED as `fc27b86` (local, NOT pushed)
Both reviews of `9e66264..9f12af8` blocked. **Every Critical, High and Medium is now fixed.**

- **code-review CRITICAL** `hardware-configuration.nix` never reached `/etc/ferrum`
  (staged BEFORE nixos-anywhere writes it; flake imports it unconditionally => every apply fails,
  stage 2 included). Now transferred+committed after install. Test asserts the staged tree CANNOT
  contain it.
- **SEC-CRIT-001** resume skipped the auth backstop AND `from_stage2` re-read settings off disk
  with zero validation. Now the auth check runs on EVERY invocation regardless of phase, and every
  recovered field is re-validated. *"Don't re-ask" had become "don't re-check."*
- **SEC-CRIT-002 / HIGH(a)** the pre-disko re-verification is inert (runs pre-kexec). Found by
  BOTH reviewers. `--phases` exists but a second invocation is undocumented + untested, so rather
  than ship unverifiable machinery the code, docstrings and **spec R2 A9** now state exactly what
  is and is not checked. **RESIDUAL RISK for the owner to accept or close:** a post-kexec
  re-enumeration is not caught; bounded because only udev `model_serial` aliases are accepted.
- **SEC-MED-001** real domain allowlist + shared `collect::sh_quote` at the remote sinks.
- **SEC-MED-002** `StrictHostKeyChecking=accept-new` + `UserKnownHostsFile=<host_dir>/known_hosts`
  (persists across `--rm`; excluded from copy_tree). **This was likely breaking the shipped Docker
  path outright** — BatchMode=yes REFUSES an unknown host. The VM test hid it by ssh-keyscan.
- **SEC-MED-003** token in a `Secret` newtype, `Debug` prints `<redacted>`, asserted.
- **SEC-LOW-001** copy_tree refuses symlinks · **002** token read with echo off via `stty` ·
  **003** cargo-audit CI job · **004/HIGH(c)** SSO-decline could NEVER complete; consent now
  recorded in install-state.json (NOT settings.json — Nix schema-validates that) and honoured,
  and R9 A4's inverted assertion implemented.
- **MEDIUM (R4 A5)** local settings.json swapped to stage-2 post-install, stage1 kept.
  **LOW** README documents the installer + put-secret.
- **Deleted `tests/stage2/`** — it stopped before the install and would have been a green check
  proving nothing.

## VERIFIED for `fc27b86` (real output)
`cargo test --workspace`: **8/8 binaries ok, 0 failed, 351 total** (was 342).
`cargo clippy -p ferrum-install --all-targets -- -D warnings`: **exit 0**.
Workspace-wide clippy still shows exactly the **3 pre-existing** `assert_eq!`-literal-bool errors
in ferrum-apply — standing policy says note, never repair.
**`nix build .#checks.aarch64-linux.workspace-tests` GREEN** (351 in the sandbox) and
**`.#packages.aarch64-linux.ferrum-install` GREEN** (176). Ran because cargo green does NOT prove
the Nix derivations build — that is what broke CI on the first push.

## Next Steps (in order)
1. **Push `fc27b86`** (needs the owner's per-push approval) and watch CI + VM tests.
2. **Owner decision needed:** accept or close SEC-CRIT-002's residual (post-kexec re-enumeration
   not caught). Critical/High are never waivable, so if it must be CLOSED the work is a
   `--phases`-split spike; if the corrected claims are sufficient, it is now a documented
   limitation rather than a false claim, and the reviewer offered that as an acceptable outcome.
3. Re-dispatch `owasp-reviewer` + `policy-validator` on the affected files only (security cycle
   1 of 2 used). Then close `code-review`, then `build-green` — the ledger enforces that order.
4. S13 still the one unimplemented story; its requirements are written into the spec.


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
