# CONTINUITY — Working Memory

## Current Phase
**Phase 1.6a — pull-and-install.** Run `f81bafcf`, Mode B. Gates `spec-complete` + `em-approved`
CLOSED PASSED. **13 of 14 stories done. 12 commits, PUSHED. HEAD `9f12af8`.**

Spec: `docs/superpowers/specs/2026-09-17-phase-1-6a-install-path-design.md` (revision 4 + an
S13 deferral section). Story map: `.ckit/state/phase-1-6a-stories.md`.

## The installer, as built
`crates/ferrum-install/` — 14 modules. Invariants are documented in the commit messages and
module headers; the load-bearing ones are restated where the reviews touch them below.

## Security cycle 2 found a CRITICAL IN MY OWN FIX. Fixed in `646a365` (local).
`fc27b86` closed SEC-LOW-004 by recording consent as a **boolean** in install-state.json. That
boolean was an authorization bypass: forgeable by hand in the operator's own bind mount, and —
with no forgery at all — **unscoped**, so consent for `[sonarr]` covered a `qbittorrent` added to
settings.stage2.json between an interrupted run and a resume. The same commit contradicted itself
one file over: `answers.rs` refuses to recover consent from disk ("consent is a fact about what
the operator was shown and typed"), while `main.rs` recovered the identical bit from a sibling
file with the same write properties.
**Now:** consent is the sorted app list actually shown; preflight recomputes and compares; this
run's live answer wins whenever this run asked.

Also fixed in `646a365`: verify.rs's unquoted `findmnt --source {by_id}` (CRITICAL — the one sink
I was asked to check and missed) + a by-id allowlist · pre-destructive resume now RE-RENDERS
(HIGH — could install the previous run's settings while reporting the new ones) · `nix_str`
escaping of device strings into generated Nix evaluated as root (HIGH) · missing
settings.stage2.json now fails CLOSED (was fail-open) · **a test pins the backstop's call order**
(deleting it used to leave the suite green — that is how SEC-CRIT-001 got in) · sh_quote shared ·
install-inventory.json excluded from copy_tree · stale spec line removed.
SEC-CRIT-002 was dispositioned **fixed as filed** (the false claims are gone); the reviewer
explicitly declined to call the missing post-kexec check Critical and reclassified the residual
**Medium**, which still blocks an ordinary PASS until the owner runs `accept-risk`.

## VERIFIED for `646a365` (real output)
`cargo test --workspace`: **8/8 binaries ok, 0 failed** (183 in ferrum-install).
`cargo clippy -p ferrum-install --all-targets -- -D warnings`: **exit 0**.
`nix build .#checks.aarch64-linux.workspace-tests` GREEN · `.#packages.aarch64-linux.ferrum-install` GREEN.
**Mutation-tested**: deleting the backstop call, un-scoping consent, and removing Nix escaping
each redden exactly their own test; restored 183 pass.

## CI on `fc27b86` (pushed)
`flake-check` `rust` `installer-image` **success**; **VM tests success**. `cargo-audit` **FAILED**
— and correctly: **RUSTSEC-2026-0285, rustls 0.23.43, CVSS 5.3, fix = >=0.23.45.** Reached via
`ureq` <- `ferrum-reconcile`, which only ever calls `http://` on loopback (`main.rs:53`) and
declares no TLS feature — so it looks unreachable, but it is a real advisory in the tree.

## Owner bar: "keep going until it's fixed and no more medium or above"
Authorizes the rustls bump despite the dependency hard stop, FIXING the SEC-CRIT-002 residual
rather than accepting it, and security cycles past the 2-cycle budget.

## SECURITY BAR MET — cycle 5 PASS: 0 Critical / 0 High / 0 Medium
Five cycles. Criticals in cycles 1-4, THREE of them in `precreate_serial_guard` alone. Cycle 5
verified empirically: 28 payloads x 3 shells x 5 wrapping contexts through real Rust -> real Nix
-> real shells with a hostile `lsblk` on PATH, **mutation-proved** against the cycle-4 defect
(restoring it pops 6 payloads). All five of its Low notes are now also fixed (`a281b29`).

**THE DURABLE LESSONS — these are what actually stopped it:**
1. **Shell-quoted is not shell-safe.** A `'...'` is INERT inside `"..."`, a here-doc, `eval`, or
   another `'...'`. What matters is the context the quoted text lands in. Assign untrusted values
   ONCE at a top-level assignment and reference via `"$var"`.
2. **Escaped-for-the-inner-layer is not safe at the outer sink.** The value was correctly
   `nix_str`-escaped for Nix and still landed unquoted in disko's own `for dev in ${toString …}`.
3. **A test that asserts "the quoted form appears" is worthless** — equally true of text that is
   inert and text that is not. **RENDER IT AND EXECUTE IT** against payloads
   (`the_generated_guard_cannot_be_made_to_execute_anything`), and execute the POST-Nix text, not
   the pre-escaping text.
4. **Validate once at the boundary with an allowlist, on EVERY ingress.** Three injections all
   came from re-deriving safety per call site. `inventory::validate_by_id_path` now runs on the
   resume deserialize too. **A deserialize is not a validation.**
5. **Confirm a mutation actually applied** before trusting a mutation test — mine silently failed
   once and showed a false pass.
6. `install-inventory.json` / `install-state.json` are ATTACKER-CONTROLLED on the resume path.

## VERIFIED for `a281b29` (real output)
`cargo test --workspace` 8/8 binaries ok (191 in ferrum-install) · `clippy -p ferrum-install
--all-targets -D warnings` 0 · `nix build .#checks.aarch64-linux.workspace-tests` +
`.#packages...ferrum-install` both built.

## Unpushed commits (5): 646a365 d5e48aa 1b02cb7 f866983 a281b29
Last PUSHED is `fc27b86`, whose CI was green except `cargo-audit` (the rustls advisory, fixed in
`d5e48aa`).

## Next Steps
1. **Push** the five commits (per-push approval) and watch CI — `cargo-audit` should now pass.
2. Close the `code-review` gate, then `build-green` — the ledger enforces that order and refused
   an out-of-order attempt already. Record the security-clear evidence.
3. S13 remains the one unimplemented story, and the ONLY thing that can prove the `preCreateHook`
   actually executes on a real host. Its requirements are written into the spec.


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
