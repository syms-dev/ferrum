# CONTINUITY — Working Memory

## Current Phase
**Phase 1.6a — pull-and-install.** Run `f81bafcf`, Mode B. Gates `spec-complete` + `em-approved`
CLOSED PASSED. **13 of 14 stories done. 12 commits, PUSHED. HEAD `9f12af8`.**

Spec: `docs/superpowers/specs/2026-09-17-phase-1-6a-install-path-design.md` (revision 4 + an
S13 deferral section). Story map: `.ckit/state/phase-1-6a-stories.md`.

## The installer, as built
`crates/ferrum-install/` — 14 modules. Invariants are documented in the commit messages and
module headers; the load-bearing ones are restated where the reviews touch them below.

## BOTH REVIEWS ARE IN. BOTH BLOCK. Do not push or close gates yet.

### code-review: CHANGES REQUESTED — Critical 1 · High 3 · Medium 1 · Low 1
- **CRITICAL — FIXED locally, uncommitted.** `hardware-configuration.nix` never reached
  `/etc/ferrum`. `stage_extra_files` snapshots the repo at `main.rs:147`; nixos-anywhere runs at
  `:153` and only THEN does `--generate-hardware-config` write the file — so the transferred tree
  structurally cannot contain it, while the transferred `flake.nix` imports it unconditionally.
  EVERY later apply fails, **including stage 2 in the same run**. **I verified this myself.**
  Fixed via `install::hardware_config_commands()` + `main::transfer_hardware_config()` after
  `wait_for_ssh`, committed on the target AND back into /host. Test asserts the staged tree
  CANNOT contain it, so the step is never mistaken for redundant.
- **HIGH still open:** (a) R2 A9 recheck runs PRE-kexec while docstrings claim post-kexec.
  (b) Resume from `PreflightPassed` re-prompts every answer but never re-runs `generate()`, so
  in-memory answers diverge from disk. (c) R9 A4 decline-path inversion unimplemented —
  `auth_checks` returns EMPTY when SSO is off, so declining verifies nothing.
- **MEDIUM:** R4 A5 — local `/host/settings.json` never swapped post-install; no
  `settings.stage1.json`. **LOW:** README not updated.
- **CLEAN:** the five-variable table (all 14 `--set-default` enumerated; exactly 5 covered), no
  unwrap/expect outside tests, no dead code.

### security-reviewer: BLOCKED — Critical 2 · Medium 3 · Low 4 · Cosmetic 1
- **SEC-CRIT-001 — resume skips the auth backstop.** Any resume at `PreflightPassed` or later
  takes the `else` branch and **never re-runs `preflight::tier1()`**, so
  `check_published_apps_are_authenticated` never fires again; meanwhile `recover_plan`/
  `from_stage2` re-read `settings.stage2.json` fresh off disk with **zero re-validation** (no
  `validate_domain`, no `validate_email`, no CATALOG_APPS membership). Interrupted run + plain
  resume + the operator's own edit to a file we told them is theirs = an unauthenticated admin
  app published on a real cert. **"Don't re-ask" silently became "don't re-check."**
- **SEC-CRIT-002** = the same defect as code-review's HIGH (a): the documented pre-disko
  re-verification is inert. Two independent reviewers found it. Either wire a real pre-disko hook
  via `--extra-files`, or rewrite spec R2 A9 + the docstrings to admit it is pre-kexec only.
- **SEC-MED-001 shell injection:** `base_domain` is interpolated UNESCAPED into
  `format!("curl ... https://{app}.{domain}/")` in `verify.rs:78,85` and run as **root on the
  target**. `validate_domain` is a typo-catcher, not an allowlist — it permits `` ` $ ; | & ' " ``.
  Fix: real allowlist `[a-z0-9.-]`, plus lift `stage2::env_prefix`'s `'\''` escaping into a shared
  `sh_quote()` used at EVERY remote interpolation site.
- **SEC-MED-002 host keys:** no `StrictHostKeyChecking` policy + no HOME/known_hosts in the image.
  Measured on OpenSSH 10.3p1: `BatchMode=yes` **refuses** an unknown host — so **the shipped
  Docker path may fail on first contact every time**. The VM test hides it by pre-seeding via
  `ssh-keyscan`, which the real path never does. Fix: `-o StrictHostKeyChecking=accept-new -o
  UserKnownHostsFile=<host_dir>/known_hosts` (and exclude it from `copy_tree`), plus a test that
  connects WITHOUT pre-seeding.
- **SEC-MED-003:** `Answers` derives `Debug` unredacted with the Cloudflare token in it. No active
  leak today; one `dbg!` away from one.
- **SEC-LOW-001** `copy_tree` follows symlinks on the copy (plant `x -> /ssh/id_ed25519`).
  **SEC-LOW-002** the token is echoed to the terminal — no `ask_secret`/ECHO suppression.
  **SEC-LOW-003** no `cargo audit` in CI. **SEC-LOW-004 (functional, important):** the SSO-decline
  path can NEVER complete — `sso::decide` lets you decline, then `preflight` unconditionally
  bails on exactly that state. Two independently-tested paths that contradict each other.

## Next Steps (in order)
1. Fix the 2 security Criticals + 3 code-review Highs. SEC-CRIT-002 and code-review HIGH(a) are
   ONE defect. SEC-CRIT-001 and code-review HIGH(b) are ONE root cause: resume trusts disk.
2. Fix SEC-MED-001/002/003 (all small; 002 may be breaking the shipped path outright).
3. Re-run `cargo test --workspace` AND **`nix build .#checks.<sys>.workspace-tests`** and
   `.#ferrum-install` — cargo green does NOT prove the Nix derivations build (see the harness
   lesson below).
4. Re-dispatch owasp-reviewer + policy-validator on the affected files only (security cycle 1 of 2
   used). Then close `code-review`, then `build-green` — the ledger enforces that order.
5. `tests/stage2/` is scaffolding that stops before the install. **Finish it or delete it** — as
   is it would be a green check proving nothing.

## VERIFIED just now (real output)
`cargo test --workspace` (rust:1-bookworm + btrfs-progs + git, examples/ copied in):
**8 binaries all `test result: ok`, 0 failed, 342 total.**
`cargo clippy -p ferrum-install --all-targets -- -D warnings` -> **exit 0**.
**NOT re-run since these edits:** `nix build .#checks.<sys>.workspace-tests`, `.#ferrum-install`.

## Uncommitted right now
`crates/ferrum-install/src/{collect,install,main,preconditions}.rs` (--ssh-port + the Critical
fix) and `tests/stage2/`. Nothing staged, nothing pushed. Last pushed commit: `9f12af8` (CI green).


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
