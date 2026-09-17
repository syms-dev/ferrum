# CONTINUITY — Working Memory

## Current Phase
**Phase 1.6a — pull-and-install.** Run `f81bafcf-bc88-4ba8-805f-2cfca8e884f1`, **Mode B**.
**Gates `spec-complete` AND `em-approved` CLOSED PASSED.** Stage: `code-review`.
**S5 S1 S2 S11 S3 S4 COMMITTED — NOT pushed. 6 of 14 stories. HEAD `dbcbcdd`.**

Spec: `docs/superpowers/specs/2026-09-17-phase-1-6a-install-path-design.md` **revision 4**,
`ea6aad9c237ea62d1783d3917dbc13e671312ec4df2a8f6a318f94b2e2b7fc10`. 9 requirements.
Evidence: `.ckit/state/evidence/phase-1-6a-{planning-panel,recheck,rev3-verify,spec-complete}.md`.

Review path: 3 spec generations, all FAILED by the panel, then an owner-authorized enumeration
pass closed it. Detail in `.ckit/state/evidence/phase-1-6a-*.md` and the spec's revision logs.
**Panel budget SPENT; revision 4 was NOT adversarially re-reviewed.**

## Implementation progress
Story breakdown + coverage map: `.ckit/state/phase-1-6a-stories.md`. 14 stories, no gaps, no
scope creep, acyclic. Immediately-startable disjoint set was **S1, S5, S14**.
- **S5** `6f8db33` `put-secret` · **S1** `d9dc702`+`03087b8` crate/Nix/image/CI · **S2**
  `07bf3a3` inventory + firmware truth table. All mutation-tested where they guard something.
  Key facts kept: the SSH key is LOCATED never READ · ferrum-install is NOT in the overlay (that
  is for `pkgs.<name>` in the MODULE TREE) · INSTALL.md's "no vfat => BIOS" is WRONG for a blank
  target and would build an unbootable host. Detail in the commit messages + archive.
- **S11 + R3 A1** `b5e86e4` — `prompt.rs` (closed stdin = refusal, no `--yes`), `sso.rs`,
  `answers.rs`. **SSO on by default when a domain is set**; declining costs the typed phrase
  `publish without authentication`, a DIFFERENT SHAPE from S3's serial. plex+jellyfin exempt.
  Cloudflare token asked last, in memory only, never echoed. `CATALOG_APPS` enforced against
  catalog.nix by the `installer-offers-every-catalog-app` check (mutation-tested, in CI).
- **S3 DONE** (`68d5017`) — `confirm.rs`, the disk gate. **RESTRICTED risk.**
  Suggestion (disk mounted at `/`) is NEVER a default — **enter aborts**. A typo is a REFUSAL,
  never the nearest match / first disk / suggestion. Ambiguous serial refuses. **No by-id path =>
  refuse** (`/dev/sdX` is not stable and disko.nix is re-read every apply). Firmware conflict
  stops here, not after the disk is gone. `install-inventory.json` written atomically BEFORE
  anything destructive, carrying the WHOLE inventory so R6 A4 can assert the KEPT disks mounted.
  `verify_still` re-resolves by-id + serial — runs before recording AND (S7) after kexec.
  **All 3 guards mutation-tested**, each reddens exactly one test.
  Verified: **261 passed / 0 failed**; clippy `-D warnings` exit 0.
- **S4 DONE** (`dbcbcdd`) — `render.rs`. Subvolume layout VERBATIM from the template, which is
  **`include_str!`'d so drift is a FAILING TEST** (restore_state.rs hardcodes `@state`; drift =>
  host installs, boots, looks healthy, silently cannot roll back). Exactly one device in
  disko.nix; data disks DETECTED (not asked) and mounted from custom/media.nix with `nofail`.
  Stage 1 = no apps + no auth; stage 2 adds apps, auth, AND the `acme-dns` declaration in
  `ferrum.secrets` (acme.nix checks the DECLARATION as well as the .sops file). Apps written with
  `enable` ONLY. UEFI=>EF00+systemd-boot, BIOS=>EF02+GRUB on the erased disk.
  **Two real bugs the tests caught:** the placeholder sentinel was a bare `AAAA`, which rejects
  EVERY real ssh-ed25519 key (they all start `AAAAC3NzaC1lZDI1NTE5AAAA`) — must be `AAAA...` with
  the ellipsis; and the Nix package needed `git` in nativeCheckInputs plus `src` = repo root with
  `cargoRoot = "crates"` because include_str! escapes crates/.
  Mutation-tested x3. Verified: **280 passed / 0 failed**; clippy `-D warnings` exit 0;
  **`nix build .#ferrum-install` green with all 105 tests passing in the sandbox.**
- **NEXT: S6** (preflight Tier 1: `nix eval`, placeholder assert, hostname==attr name, and the
  R9 public-without-auth check which reads **settings.stage2.json** not the stage-1 eval) →
  **S7** (install: nixos-anywhere + `--extra-files` to /etc/ferrum + hardware-config commit-back,
  RESTRICTED) → **S8** (stage 2, the five-variable override table — the remaining highest-risk
  item). S14 (INSTALL.md) batchable, unblocked.

## Gotcha that cost time twice
`cargo test` for **ferrum-apply** needs **btrfs-progs installed in the container** or
`preflight::tests::is_subvolume_check_fails_on_a_plain_directory` fails for an ENVIRONMENT reason.
It looks exactly like a regression. Always `apt-get install -y btrfs-progs` in the test container.

## THE REMAINING HIGHEST-RISK ITEM — verify in code FIRST
**R4 A3b's five-variable override table (story S8).** Stage 2 must pass `FERRUM_SERVARR_APPS`,
`FERRUM_AUTH_ENABLED`, `FERRUM_ADMIN_EMAIL`, `FERRUM_SABNZBD_STATE_DIR`, `FERRUM_SABNZBD_PORT`
explicitly. Works ONLY because `overlays.nix:154` uses `--set-default`, not `--set`.
Rule: exactly the vars derived from `ferrum.apps.*` / `ferrum.auth.*` differ, because stage-1
settings IS stage-2 minus `apps` minus `auth`. 14 vars at `overlays.nix:168-183`; 5 differ.
**`main.rs:165`'s `unwrap_or_else` fires only when UNSET — an empty string survives the filter.**
**R8 A2's CI job must enable sabnzbd alongside sonarr** so this fails red in CI, not on a host.
(The other one, `put-secret`, is DONE in S5.)

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

## Spec (revision 4 `ea6aad9c…`) — 9 requirements
R1 one Docker command · R2 inventory + TYPED-SERIAL confirm · R3 render host repo · R4 the
two-stage sops bootstrap · R5 two-tier preflight · R6 install+verify+report · R7 resume ·
R8 test from nothing · R9 published means authenticated. Read the spec for detail.
OQ4 (ghcr publish credential) and OQ5 (pull image by digest / verify the pinned rev) are the two
open ones — both block the first RELEASE, not the gate.

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

## Toolchain & dispatch (do not re-derive)
No native cargo/rustc/nix; **Docker Desktop**, and `--platform linux/amd64` works.
Rust: `rust:1-bookworm` + NAMED volume `ferrum-cargo` (bind-mounting from macOS breaks) +
`btrfs-progs`; copy `crates/` into the workdir. Nix: `nixos/nix` + volume `ferrum-nixstore`;
that image has no `sed`/`python3`. Full recipes in `.ckit/state/continuity-archive.md`.
- **Agent worktrees are cut at `main`** (stale, no `crates/ferrum-state/`) — dispatch writing roles
  against `/Users/cs/repos/ferrum` directly. Read-only reviewers are unaffected.
- `timeout` is NOT available in this shell (zsh/macOS). Use the Bash tool's own timeout param.

## Next Steps
1. **S11** — SSO prompting + the decline path's 2nd differently-shaped typed confirmation (R9).
2. **S3** — the typed-serial confirmation gate. **RESTRICTED risk**; mutation-test every guard.
3. **S4** — host repo rendering (4 files, zero placeholders, `@root/@nix/@state/@snapshots`
   VERBATIM or rollback silently breaks, git init/add/commit, pinned rev).
4. S14 (INSTALL.md corrections) is batchable and unblocked — good filler.

## Repo State (from commands, never memory)
- branch `grounding-and-install-path`  HEAD `07bf3a3`  PR #3. **4 commits NOT pushed.**
- Gates passed: `spec-complete`, `em-approved`. Stage: `code-review`.

## Test/Build Status
- Workspace **221 passed / 0 failed**. clippy `-p ferrum-install -D warnings` exit 0.
- `nix eval` OK for both new packages. CI has NOT run on these commits (nothing pushed).
