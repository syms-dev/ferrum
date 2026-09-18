# CONTINUITY — Working Memory

## Current Phase
**Phase 1.6a — pull-and-install.** Run `f81bafcf`, Mode B. Gates `spec-complete` + `em-approved`
CLOSED PASSED. **13 of 14 stories done. 12 commits, PUSHED. HEAD `9f12af8`.**

Spec: `docs/superpowers/specs/2026-09-17-phase-1-6a-install-path-design.md` (revision 4 + an
S13 deferral section). Story map: `.ckit/state/phase-1-6a-stories.md`.

## The installer, as built
`crates/ferrum-install/` — 14 modules. Invariants are documented in the commit messages and
module headers; the load-bearing ones are restated where the reviews touch them below.


## Also fixed after review: rustls RUSTSEC-2026-0285 bumped 0.23.43 -> 0.23.45 (owner-authorized;
one package, patch, 2 lines). `cargo audit` clean. `cargo-audit` CI job added and green.

## Owner bar: "keep going until it's fixed and no more medium or above"
Authorizes the rustls bump despite the dependency hard stop, FIXING the SEC-CRIT-002 residual
rather than accepting it, and security cycles past the 2-cycle budget.


## PROCESS FAILURE — three times now, same shape
I trusted a command/edit instead of the result it produced:
1. a mutation test that silently failed to apply and showed a **false pass**;
2. a string `replace` that no-opped, so I **claimed a test in a commit message that did not
   exist** (the code reviewer caught it);
3. `83216ac` **pushed with a failing test**, because my chain used `;` instead of `&&` before the
   git block — and the failure was printed in output I had read.
**Every edit now asserts its anchor was found AND that the result landed; verification must gate
the commit with `&&`, never `;`.**

## AUTH MODEL: declared for 3 phases, ENFORCED BY NOTHING (fixed `6e65ae3`)
Owner caught it: *"Plex and Jellyfin don't allow SSO right?"* Every meta.nix declared
`authBypassPaths`; nginx put `auth_request` on `locations."/"` and generated nothing else. With
SSO on this broke Plex/Jellyfin native clients, Prowlarr -> *arr `/api`, and **ferrum's own
reconciler** -- enabling SSO disabled the self-setup feature SSO exists to protect. Fixed:
per-bypass-path locations + plex/jellyfin `policy = "bypass"`. New `auth-model-enforced` check
asserts the GENERATED nginx config; both halves mutation-proved.
**No proxy or auth test existed at all before this** -- that is how it stayed dead.
Durable lesson also saved to auto-memory (`media-servers-must-not-sit-behind-sso`).


## S13 stage2 HAS NEVER PASSED, and two runs produced zero evidence
Both `stage2` jobs hit the 180-min cap having printed NOTHING (GitHub shows a timed-out job as
"cancelled", which reads as someone cancelling it). Cause of the blindness: the harness
redirected the installer to a file and only tailed it AFTER exit -- and it never exited. Fixed
in `dc40ab8`: `tee` + `PIPESTATUS[0]` + a heartbeat (silence is ambiguous because
`--build-on remote` builds the whole closure in the nested guest). Guest raised to 4 cores /
24G disk.
`stage2-resume` failed for a REAL reason, now fixed (`f51dcb1`): nixos-anywhere retries
`ssh-copy-id` FOREVER after the target is kexec'd, because the kexec'd system only accepts the
keys the FIRST run installed. 150 min of silent looping. R7 A1e now says resume-after-kexec
cannot work; the installer refuses promptly and says to power-cycle then `--fresh`.

## The installer IMAGE was broken and nothing caught it (fixed `0b23acc`)
No `/etc/passwd` -> OpenSSH exits "No user exists for uid 0" -> EVERY target interaction failed.
394 tests and six security cycles passed with it shipped, because all of them run the binary
OUTSIDE the image. Also: a refusal told operators to use a flag that does not exist, and a TEST
was holding that in place. CI now drives the real image against a real sshd container
(`50715c2`). **Building the artifact is not running it, and running it without a target is not
using it.**


## VERIFIED ON THIS MAC (not inferred)
`ferrum-install:latest` is built, fixed and loaded in Docker. Against a live x86_64 sshd
container it connects, runs lsblk, parses the inventory, detects firmware + arch, renders the
disk table, and refuses at the serial gate with the corrected message. That is the whole
pre-destructive path, on the real delivery vehicle.
Rebuild: `docker run --rm -v <repo>:/src -v ferrum-nixstore:/nix -w /src nixos/nix sh -c 'nix
--extra-experimental-features "nix-command flakes" build .#packages.aarch64-linux.ferrum-install-image
--no-link --print-out-paths 2>/dev/null | tail -1 | xargs cat' > /tmp/img.tar.gz && docker load -i /tmp/img.tar.gz`

## User's chosen first run: SPARE PHYSICAL BOX, NO DOMAIN (local-only)
So SSO is not forced (it is forced only when a domain is set) and the unauthenticated-apps gate
does not fire. Steps were given. Target must be x86_64 and its disks MUST report serials --
blank serials usually mean an HBA in RAID mode.

## Gate progress — ALL GATES CLOSED
`spec-complete` · `em-approved` · `code-review` · `build-green` · `test-coverage` ·
**`security-clear`** all PASSED. `contract-clear` NOT-APPLICABLE. Ledger is at
**`ready-to-complete`** at commit `0e989a8`.

**DO NOT run `pipeline complete` yet.** The S13 `stage2`/`stage2-resume` CI jobs have never once
passed, and they are the ONLY thing that can exercise the install and resume paths for real --
no NixOS VM test has run locally at any point (no KVM on this Mac). Completing now would record
as finished a feature whose central claim is unproven. Wait for a raised-budget run to report.

## Security: SIX delta cycles, 0 C/H/M -- CLOSED
Evidence: `.ckit/state/evidence/phase-1-6a-security-clear-delta.md` (supersedes the old file,
which was ten commits stale). Two Criticals and three Highs, several introduced BY THE FIXES for
the previous ones. Narrative archived in `.ckit/state/continuity-archive.md`.
**The lesson, earned four times: a fix and a pin are different claims, and only a mutation that
DIES tells them apart.** Four fixes were real, correct, and held by nothing.


## THE lesson, earned FOUR times
**A fix and a pin are different claims, and only a mutation that DIES tells them apart.** Four
fixes were real, correct and held by NOTHING (`write_repo`'s `.gitignore`, verify.rs's
missing-file guard, `check_device_name`'s survives-cleaning clause, and the reviewer's own N8
advice). All passed the full suite. All were found by RUNNING the mutation. Also: mutations that
test the CONSTANTS instead of the CONTROL FLOW are worthless -- reverting the phase comparison
reintroduced SEC-H1 with 205/205 green.
Corollaries: **cargo green does NOT prove the Nix build** (an `include_str!` of flake.lock broke
the sandbox -- the file sat outside BOTH source filters) · **`$?` after a pipe is the LAST
command's status** -- it falsely reported a failed `nix build` as green THREE times; gate with
`&&` and capture the real exit · **`is_control()` is a Unicode category, not a security
boundary** -- filter to what you ALLOW.



## THE lesson from this gate
**A coverage claim is a testable assertion about a file -- verify it by reading the FILE, not
another document that agrees with it.** Consistency across seven documents was the symptom,
not the evidence.



## Repo State (from commands, never memory)
- branch `grounding-and-install-path`, PR #3. HEAD `0e989a8`, PUSHED.
  219 ferrum-install / 393 workspace green; clippy clean at `--all-targets`;
  `.#checks.aarch64-linux.workspace-tests` and the NEW `clippy-ferrum-install` both build.
- **S13 is the only open item.** Six VM-test runs in flight; the ones on `357328f`/`620e255`/
  `5a70ff4` carry the OLD 90-min cap and their failures mean NOTHING. Raised-budget runs
  (180 min) at 15:17 UTC: `a556b4c` 65 min, `74f504a` 45, `6b79dc2` 30, `8943cc9` 16.
  Watcher `b0o3ejp4m` reports `a556b4c` (earliest signal) and `0e989a8` (authoritative).
- `stage2-resume` previously failed `the resume exited 124` -- its inner `timeout 3600` -- with
  the guest ALREADY BOOTED. Budget, not defect. Jobs 180 min, inner timeout 9000s.
- aarch64 `smoke` fails EVERY run by design (`continue-on-error`; no /dev/kvm on ARM runners).
- Reading CI logs: `::error::` is STRIPPED from downloaded logs -- use
  `gh api repos/syms-dev/ferrum/check-runs/<job-id>/annotations`.

