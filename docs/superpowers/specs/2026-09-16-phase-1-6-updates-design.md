# Specification: Phase 1.6 — Updates

## Overview

ferrum has no app-update mechanism today. Confirmed by search: grepping `crates/`, `modules/`,
`nix/` and every plan/spec under `docs/superpowers/` for `flake update|flake lock|nix-channel
|Command::Update|fn run_update` returns **zero matches**. `ferrum-apply`'s complete subcommand set
is `Preflight`, `Apply`, `Rollback`, `RestoreState`, `Gc`, `RunRequest`, `PreviewMigration`
(`crates/ferrum-apply/src/main.rs:20-46`) — there is no `Update`. When an app (e.g. Plex) reports
"update available, install manually," that instruction cannot be followed on a ferrum host: the
package comes from nixpkgs and the running system is immutable.

The real version chain, confirmed against the repo: a host flake pins `ferrum.url = "github:YOUR-
USER/ferrum"` (`examples/hosts/template/flake.nix:21`, comment recommending a pinned tag/commit for
a real host); ferrum's own `flake.nix` pins `nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11"`
(`flake.nix:5`); ferrum's own `flake.lock` freezes that nixpkgs input at
`lastModified: 1782847189` (`flake.lock:43`), which is late June 2026. Every app version an
operator sees today traces back to that one frozen nixpkgs revision. Updating anything today means
hand-editing pins across two repositories and re-applying — confirmed as the operator's actual,
lived experience in `.ckit/CONTINUITY.md`'s working notes ("every deploy tonight has been a
hand-edited SHA"). Saltbox, the product ferrum is positioned against, has update roles; this is
ferrum's largest remaining gap relative to it.

This is a full-stack, backend-and-UI feature. It adds no new NixOS module surface and touches no
per-app `service.nix` — every change is in `crates/ferrum-apply`, `crates/ferrumd`, `ui/`, and the
Nix packaging that feeds the catalog artifact.

### The central design tension

`/etc/ferrum/flake.nix` is root-owned and unwritable by ferrumd by design — its own header comment
states this is what makes "compromising the daemon does not yield arbitrary Nix evaluation as root"
true (`examples/hosts/template/flake.nix:5-7`). An update, by definition, changes a flake input
pin — i.e. it changes exactly the file (or its companion `flake.lock`) that this privilege boundary
exists to protect. Separately, `ferrum-apply`'s `Request` enum is a deliberately closed, five-
variant surface with a file header stating it "must never grow a variant that accepts arbitrary
shell/Nix content" (`crates/ferrum-apply/src/request.rs:1-19`), and the identical, hand-mirrored
`JobRequest` enum on the daemon side carries the same constraint in its own header comment
(`crates/ferrumd/src/jobs.rs:1-37`). A naive `Update { flakeRef: String }` variant — an
operator-or-attacker-supplied ref, dispatched by ferrumd, executed as root by ferrum-apply — is
exactly the injection both of those comments warn against: it would let a compromised, merely
*unprivileged* ferrumd cause root-privileged, arbitrary-remote-content `nix build` execution.

This spec does not resolve *how* the update pin advances (that choice is deferred to Open Question
1, below, as a Technical Architect decision) — it states the invariants any resolution must satisfy,
as testable requirements (R2), and the read-only guarantee needed before any commitment (R3).

## Requirements

### R1: Update Discovery

**Description**: An operator can see, without applying or committing anything, that a newer
nixpkgs-derived package set is available for this host, and — where evaluable — approximately what
each currently-enabled catalog app's version would become.

**User Story**: As an operator, I want to know an update exists and roughly what it would change,
the same way I'd see "Plex 1.42.2 → 1.43.4" in Plex's own UI, so that I can decide whether and when
to act, without ferrum silently doing anything on my behalf.

**Acceptance Criteria**:
- [ ] The operator can determine, on demand (no polling/scheduling required by this phase — see
      Out of Scope), whether a newer package set is available for this host.
- [ ] When available, the response names, for every **enabled** catalog app, its current version
      and the version it would become, sourced from the resolved NixOS configuration rather than
      invented per-app metadata (see Assumptions on `services.<app>.package.version`
      evaluability).
- [ ] ferrum's own release version (current vs. candidate — see
      `docs/superpowers/specs/2026-08-23-settings-schema-migration-design.md`'s versioning
      scheme) is shown alongside the app deltas, not as a separate check.
- [ ] Discovery performs no write to `settings.json`, `flake.nix`, or `flake.lock`, and triggers no
      build, switch, or health check (this is the read-only guarantee R3 makes binding).
- [ ] Since nixpkgs pins one package set for the whole host, discovery reports **one** pending
      update event carrying **all** affected apps' deltas — never a per-app "update available"
      flag implying apps can be checked or moved independently (see R7).

**Edge Cases**:
- No newer package set is resolvable: reported as an explicit "up to date" state, not an empty or
  missing response.
- The only resolvable candidate is **older** than what the host is currently running (e.g. the
  tracked reference moved backwards, or the operator's host is ahead of what this mechanism can
  see): must not be reported as an available update. `ferrum-apply`'s own `preview-migration`
  already establishes this exact discipline for schema versions — it warns rather than treats a
  target below the current version as "would migrate"
  (`crates/ferrum-apply/src/main.rs:352-356`) — Discovery must apply the same rule to app/nixpkgs
  versions.
- A catalog app is **disabled** in `settings.json`: excluded from the per-app delta list (nothing
  is currently running to compare against); it will pick up the new pin's version if the operator
  enables it after updating, and the Discovery/Preview text should say so rather than stay silent.
- A package the resolved config depends on was removed or renamed in the candidate nixpkgs
  revision: the evaluation fails for that app. This must surface as a loud, specific, per-app
  failure (mirroring `checks.schema-uniformity`'s and `preview-migration`'s "refuse to evaluate,
  never guess" convention, `crates/ferrum-apply/src/main.rs:332-343`), not a silently dropped row.
- The candidate reference is unreachable (network failure, DNS failure, revoked access): reported
  as "could not check for updates: `<real error>`," never as "up to date" — an unreachable check
  must never be indistinguishable from a clean result.
- A `custom/` override already pins an app's package away from the catalog default (e.g.
  `services.sonarr.package = pkgs.sonarr_3;`, the mechanism `docs/design/2026-08-19-phase-1-design.md:138`
  already reserves for this): Discovery must evaluate the **fully resolved** configuration
  (which already incorporates `custom/`), not a naive catalog-only lookup, so an overridden app is
  correctly reported as unaffected by the pin change rather than falsely flagged.

---

### R2: Update Authorization & the Pin-Advance Boundary

**Description**: The mechanism that decides and applies a new flake input pin is a closed request
with no operator-, ferrumd-, or attacker-controlled content — following exactly the shape of the
existing `Request`/`JobRequest` enums — and never causes ferrumd (unprivileged) to write to
`/etc/ferrum/flake.nix` or `/etc/ferrum/flake.lock` under any code path.

**User Story**: As an operator, I want confidence that checking for or applying an update cannot be
turned into a way for a compromised or buggy ferrumd to run arbitrary Nix content as root, so that
the update feature does not undermine the project's core security thesis (the daemon.nix polkit
rule's own stated purpose, `modules/core/daemon.nix:22-43`).

**Acceptance Criteria**:
- [ ] Any new `Request` variant(s) added to `crates/ferrum-apply/src/request.rs` for update
      discovery/preview/apply carry **zero fields whose value originates from the request file** —
      the same shape as today's `Preflight`, `Apply`, and `Gc` unit variants
      (`crates/ferrum-apply/src/request.rs:13-19`), never a string/path/URL field like the rejected
      `Update { flakeRef }` shape this spec's Overview names explicitly.
- [ ] Any new `JobRequest` variant mirrored into `crates/ferrumd/src/jobs.rs` carries the identical
      zero-argument shape; `POST /api/jobs` for the new kind(s) accepts no body field beyond
      `kind`, matching the existing hand-written `request_body` mapping's discipline
      (`crates/ferrumd/src/jobs.rs:109-121`) of spelling the wire format out literally rather than
      deriving it.
- [ ] `modules/core/daemon.nix`'s `ReadWritePaths` for `ferrumd` (`modules/core/daemon.nix:188-194`)
      gains no new writable path; ferrumd's process never opens `/etc/ferrum/flake.nix` or
      `/etc/ferrum/flake.lock` for writing, under any code path this feature adds.
- [ ] Whatever candidate value `ferrum-apply` (running as root, dispatched via the existing
      polkit-authorized `ferrum-apply@.service` template, `modules/core/daemon.nix:57-105`)
      ultimately writes to advance the pin is **computed by `ferrum-apply` itself** from data
      already present in the already-trusted, root-owned `flake.nix` (or a ferrum-published,
      out-of-band-trusted reference — see Open Question 2) — never taken from the request file.
      An injected/extra field on the request file for this job kind must be provably inert.
- [ ] `/etc/ferrum/flake.nix`'s byte content is unchanged by every code path this feature adds,
      under the pinning-policy option that keeps it immutable (see Open Question 1); if the
      alternative policy is chosen instead, this criterion is replaced by an equivalent one scoped
      to the actual mutated file, decided alongside that question — this spec does not allow the
      criterion to simply disappear.
- [ ] `ferrumd` gains no new subprocess invocation of `nix` anywhere in its own process — the
      existing, verified invariant (confirmed by inspection: no `Command::new` and no `nix eval`
      appear anywhere under `crates/ferrumd/`) that every `nix` invocation in the codebase runs
      inside root-privileged `ferrum-apply`, never inside the unprivileged daemon, holds unchanged
      after this feature ships.

**Edge Cases**:
- A compromised ferrumd repeatedly requests the update-check/update-apply job kinds: rate-limiting
  and the existing single-job interlock (see R3's edge cases and Open Question 3) bound how much
  it can do, but the primary defense is that the request carries no exploitable content regardless
  of frequency.
- The candidate-resolution step itself fails partway (e.g. network drop mid-fetch): must fail
  loudly and leave `flake.lock`/`flake.nix` byte-for-byte untouched — an atomic write (temp file +
  rename), the same discipline `ferrum_state::journal::write` already uses
  (`crates/ferrum-state/src/journal.rs:20-26`), not a partial in-place edit.
- An ordinary (non-update) `apply` job must remain provably incapable of advancing any pin as a
  side effect — see the Assumption below about `nix build`'s default lock-file behavior; if that
  assumption is ever found false, this requirement's isolation from ordinary applies breaks and
  must be re-verified.

---

### R3: Read-Only Preview

**Description**: Before an operator commits to anything, the exact set of changes an update would
produce — app version deltas, ferrum's own version, and any pending settings-schema migration — is
computable and displayable with a provable read-only guarantee, extending the existing
`preview-migration` precedent (`crates/ferrum-apply/src/main.rs:284-364`, which already shells out
to `nix eval --json` against the real flake with no `nix build` and no write).

**User Story**: As an operator, I want to see precisely what an update will change before it
touches my running system, the same way I already review a settings diff before applying it
(`ui/app.js:180-268`), so that I never discover a consequence only after committing to it.

**Acceptance Criteria**:
- [ ] Preview performs zero mutating operations: no `nix build`, no `nix-env --set`, no
      `switch-to-configuration`, no write under `/etc/ferrum` or `/var/lib/ferrum`, and no
      `systemctl stop`/`start` of `ferrum-apps.target` — the same guarantee `preview-migration`
      already gives for schema migrations alone.
- [ ] Because `ferrumd` never shells out to `nix` (R2's last criterion), Preview is dispatched
      through the same privileged job-request mechanism as every other `ferrum-apply` capability —
      it does not become a new, ferrumd-local code path just because it happens to be read-only.
- [ ] A blocked or impossible update surfaces the evaluator's own real error text, exactly as
      `preview-migration` already does for a `throw`-ing migration
      (`crates/ferrum-apply/src/main.rs:332-343`) — never a generic "preview failed."
- [ ] Any pending settings-schema migration appears in the **same** preview output as the app
      version deltas — one unified "what's changing" review — matching the explicit intent already
      recorded in `docs/superpowers/specs/2026-08-23-settings-schema-migration-design.md`'s
      "Showing the operator what's changing" section ("shown as one more line in the same
      'what's changing' review that already exists for every apply").
- [ ] Preview is idempotent and safe to invoke repeatedly without changing any on-disk state or
      counter.

**Edge Cases**:
- Preview's `nix eval` cost scales with flake evaluation time, the same known cost the settings-
  schema-migration spec already names as its Known Risk 3 ("For a large catalog this could become
  a real, felt delay… not a blocker for the initial design, worth measuring"); this phase inherits
  that cost rather than introducing a new one.
- Preview is requested while an `apply`/`rollback`/`gc` job is already running: see Open Question 3
  for whether it shares the existing `job_running` interlock or is exempted from it.
- The settings-schema migration write-back step described in that spec's Design section is not yet
  implemented (that spec's own Known Risk 4: "No task in the implementing plan built this"). Until
  it is, a migration would appear as pending in every Preview forever, even immediately after it
  was already shown once — Preview must not claim a migration is "new" if it has no way to know it
  was previously seen; see Dependencies.

---

### R4: Applying an Update as a Generation

**Description**: Once an operator commits, an update is applied through the identical build →
snapshot-state → switch → health-check pipeline that already exists for any other apply
(`crates/ferrum-apply/src/apply.rs`), producing exactly one new generation and one new journal
entry, exactly as a settings-only apply does today. This is ferrum's stated advantage over Saltbox
made concrete: an update is not a special case of the rollback story, it is an ordinary instance of
it.

**User Story**: As an operator, I want an update to be exactly as safe to apply and reverse as any
other change to my host, so that "update" never means a lesser rollback guarantee than "changed a
setting."

**Acceptance Criteria**:
- [ ] Once the pin is advanced (R2), the resulting apply runs through the unmodified `apply::run`
      pipeline (`crates/ferrum-apply/src/apply.rs`); this feature does not fork, duplicate, or add
      an update-specific branch to that function.
- [ ] The resulting generation's journal entry captures the real `toplevel` store path that was
      actually running immediately before the snapshot (`crates/ferrum-state/src/journal.rs:8-11`),
      exactly as it does today — an update's pre-image is distinguishable in the Generations view
      from its post-image using existing fields, with no new field required.
- [ ] `ApplyResult::Succeeded` / `Degraded` / `Failed` classification
      (`crates/ferrum-apply/src/apply.rs:6-29`) applies unchanged to an update-triggered apply; a
      degraded update (e.g. the new Plex version fails its own health check) is reported with the
      exact same vocabulary as a degraded settings apply.
- [ ] The Preview review (R3) is shown immediately before the commit action, in the same
      "review, then commit" shape the Apply view already uses for settings
      (`ui/app.js:180-268`, "Saving settings never rebuilds the system. Applying is a separate,
      deliberate step.") — this feature does not invent a second commit shape.

**Edge Cases**:
- Build failure at the candidate pin (nixpkgs eval error, hash mismatch, network failure mid-build):
  must fail at the build step, **before** `ferrum-apps.target` is stopped (the existing apply
  ordering, `docs/design/2026-08-19-phase-1-design.md:162-173`, steps 1–3 precede step 5's stop) —
  a bad update must never cause downtime by itself; only a successfully built candidate reaches the
  stop/snapshot/switch steps.
- Free space (`ferrum.storage.minFreeGiB`): an update-triggered apply must still refuse below the
  configured threshold, unchanged from today's preflight check.
- Many apps change version in the same apply (the common case, since nixpkgs moves them together):
  the existing single-generation/single-snapshot model already treats "many things changed at once"
  uniformly; no per-app tracking inside one generation is required or introduced.
- The candidate pin advanced but resolves to **no change** in the built closure: `apply::run`
  returns early after a health check when the built toplevel equals the running one
  (`crates/ferrum-apply/src/apply.rs:250-257`) — **no preflight, no snapshot, no journal entry, no
  new generation**. An earlier draft of this spec asserted the opposite; satisfying that would have
  required forking `apply::run`, which R4's first criterion forbids. The operator is therefore told
  "no change — nothing to apply", and the UI copy must say exactly that rather than implying a
  generation was created.

---

### R5: Rollback of a Bad Update

**Description**: Rolling back an update-produced generation uses the unmodified rollback +
reboot + state-restore pipeline that already exists (`crates/ferrum-apply/src/rollback.rs`,
`crates/ferrum-apply/src/restore_state.rs`), including for an app whose own internal database
migrated forward the first time it started against the new version. This is the sharpest instance
of Phase 1's central thesis (closure-only rollback is insufficient) — not a new scenario for the
rollback mechanism, but the scenario `docs/design/2026-08-19-phase-1-design.md`'s own
`ferrum-testapp` v1/v2 rollback test (lines 229–245) was built to prove.

**User Story**: As an operator, I want to revert a bad update — including an app that already wrote
to its database in the new version's format — back to exactly the state it was in before I updated,
so that an update is never a one-way door.

**Acceptance Criteria**:
- [ ] Rolling back an update-produced generation uses the existing `GET /api/generations`
      `rollbackable`/`reason` fields and the existing rollback job kind
      (`crates/ferrum-state/src/generations.rs:73-81`; 1.5b spec's generations endpoint) with no
      new rollback code path conditioned on "this generation came from an update."
- [ ] An app whose own internal database migrated forward on first start against the new version is
      restored, together with the pre-update binary, by the same state-subvolume-swap mechanism the
      design doc's rollback test already proves end-to-end for exactly this failure mode
      (`docs/design/2026-08-19-phase-1-design.md:229-245`).
- [ ] The confirmation dialog for rolling back an update-produced generation reuses `confirmRollback`'s
      existing prose pattern verbatim (`ui/app.js:340-398`) — stating concretely what reverts (the
      app's database/state, back to its pre-update shape) and what does not (media files, in-flight
      downloads, TLS certificates, Authelia users) — no second, update-specific dialog design.
- [ ] The currently-running generation is never offered as a rollback target, including
      immediately after an update apply — unchanged from the existing rule (1.5b spec: "The
      currently-running generation is always reported `rollbackable: false`").

**Edge Cases**:
- **The pre-update generation's snapshot CAN be pruned before an operator notices the update is
  bad, and this is a PRESENT risk, not a future one.** An earlier draft of this spec said the
  opposite, citing a stale README line; `ferrum-apply gc` is fully implemented
  (`crates/ferrum-apply/src/gc.rs` — `plan()` at :58, `delete_one()` at :105, `run()` at :136, nine
  unit tests; wired via `run_gc`/`run_gc_inner` at `crates/ferrum-apply/src/main.rs:397-443`, and
  `main.rs:389-396`'s own comment records that it stopped being a stub on 2026-09-15). Retention is
  `FERRUM_KEEP_GENERATIONS`, default **10**, and `gc::plan` protects only the **currently-running**
  generation's snapshot (`gc.rs:71-78`). So an operator who updates and then applies ten more times
  can lose the pre-update snapshot, after which `is_rollbackable` reports that generation as
  unrollbackable with "its snapshot was pruned"
  (`crates/ferrum-state/src/generations.rs:73-81`). The one mitigating fact — no systemd timer runs
  gc, so it is operator-triggered (confirmed: `keepGenerations` appears only in
  `modules/core/options.nix` and `modules/core/overlays.nix`, with no timer unit anywhere) — is the
  reason this is survivable today, and it is not something to rely on.
- **Therefore a requirement this phase needs and does not yet have:** an update-produced
  generation's pre-image snapshot must be protected from `gc` until the operator confirms the
  update is good. Without it, "an update is never a one-way door" is true only for about ten
  applies.
- A generation genuinely has no snapshot (applied by a bare `nixos-rebuild switch` bypassing
  `ferrum-apply`): already handled — the daemon's own `reason` string is shown and no control is
  offered; unchanged by this phase.
- An operator bundled a settings change into the same apply as the update (both staged together
  before clicking "Apply"): rolling back reverts **both**, since one apply is one generation
  regardless of what changed within it. The confirmation dialog's existing "the system and every
  app's state directory" language already technically covers this, but the update-specific wording
  added under R5's third criterion must say so by name, not rely on the operator inferring it.

---

### R6: The Updates UI Surface

**Description**: A new view in the existing hand-written, no-build, ES-module UI
(`ui/app.js`, `ui/api.js`, `ui/forms.js`) that surfaces Discovery/Preview (R1, R3) and, when the
operator commits, Apply (R4) and, from the existing Generations view, Rollback (R5) — using the
UI's established patterns rather than introducing new ones.

**User Story**: As an operator, I want an "Updates" screen that looks and behaves like the rest of
the ferrum UI I already use for Apps, Apply, and Generations, so that updating isn't a
context-switch into a different mental model.

**Acceptance Criteria**:
- [ ] A new `#/updates` hash route is added to `ui/app.js`'s `routes` map
      (`ui/app.js:456-461`) and its nav bar, following the existing `el()` DOM-builder convention —
      no framework, no build step, no new client-side dependency (`ui/app.js:1-6`).
- [ ] The view fetches from a new read-only endpoint the same way `appsView`/`generationsView`
      already fetch `/api/catalog`/`/api/generations` (`ui/app.js:95-125`, `400-452`).
- [ ] The view shows: ferrum's own release version (current → candidate), and per enabled catalog
      app, current version → candidate version, or an explicit "up to date"/"not shown — disabled"
      state per R1's edge cases — never a blank list for "no update" (project convention: every
      data-driven view handles loading/empty/error/success).
- [ ] Any pending settings-schema migration renders on this **same** screen using its own
      human-authored `description` text (per R3's fourth criterion) — not a separate screen or a
      generated JSON diff.
- [ ] Committing an update is gated behind a confirmation dialog following the same pattern as
      `confirmRollback` (`ui/app.js:348-398`): concrete, prose language naming what will happen —
      not a field dump of the raw preview JSON.
- [ ] Progress after commit streams via the existing `GET /api/jobs/:id/stream` /
      `streamJob` mechanism (`ui/api.js:169-198`) and reattaches on reload exactly as the Apply
      view already does for an in-flight job (`ui/app.js:261-267`) — no new streaming mechanism.
- [ ] The Updates view's own JavaScript makes no `fetch()` (or equivalent) to any third-party host —
      any outbound check for a new candidate happens server-side, inside `ferrum-apply`, preserving
      the UI's existing "no external request of any kind" invariant (`ui/app.js:1-6`).

**Edge Cases**:
- Loading state while the privileged Preview job runs (which, per R3's first edge case, can take a
  real, felt amount of time): the view must show a pending state, not a blank screen, and must
  reattach to an already-running check job on reload the same way the Apply view reattaches to a
  running apply (`ui/app.js:261-267`).
- Discovery/Preview fails (network error, evaluator error): shown inline via the same
  `error.textContent = err.message` pattern already used on the Apply and Generations views
  (`ui/app.js:219`, `420`), never swallowed.
- A job is already running when the operator opens Updates or clicks commit: the existing `409`
  handling pattern is reused verbatim (`ui/app.js:234-244`), naming the job already holding the
  lock via `GET /api/jobs`.
- The UI is a stale tab loaded before a rebuild (1.5b's Global Constraint, inherited unchanged): a
  `PUT /api/settings` or update-commit rejection from a schema/shape mismatch must render as the
  daemon's own readable, field-anchored message, not a generic failure.

---

### R7: Selective vs Wholesale Updates

**Description**: Because a single nixpkgs pin supplies every catalog app's package, ferrum cannot
offer, and must not claim to offer, an update to one app independent of the others. This
requirement states that limitation honestly and names the one mechanism ferrum already has for an
operator who needs a specific app held back or pinned differently.

**User Story**: As an operator who is happy with my current Sonarr version but wants Plex updated,
I want ferrum to tell me plainly whether that's possible, and if not, what my actual options are, so
that I don't assume a per-app control exists and go looking for one that isn't there.

**Acceptance Criteria**:
- [ ] The Updates view and its underlying API never present a per-app "Update this app" action —
      a pending update is framed as one host-wide event (R1's last criterion) listing every
      affected app's delta together, since accepting it means advancing the one pin all of them
      share.
- [ ] Documentation/UI copy directs an operator who needs one app held at a specific version to the
      existing `custom/` override mechanism (`services.<app>.package = ...`, the same escape hatch
      the original design doc already reserves for this exact need,
      `docs/design/2026-08-19-phase-1-design.md:138`) rather than implying this phase builds a new
      one.
- [ ] Enabling a catalog app for the **first time** is treated as an ordinary settings change (an
      `apply` of a newly-enabled app), never conflated with an "update" — it must not appear in the
      Updates view's delta list, since there is no "current version" for an app that wasn't
      running.

**Edge Cases**:
- An app is `custom/`-overridden to a specific package: R1's discovery, by evaluating the fully
  resolved configuration (which already incorporates `custom/`), correctly reports that app as
  unaffected by the pending pin change rather than misreporting a version it will not actually
  receive.
- An operator asks (via a support channel, not the UI) "can I update just Plex?": the honest answer
  ferrum gives, per this requirement, is no — updating means moving the whole host's package set
  forward by one pin, and the only per-app lever is the pre-existing `custom/` override, which
  *removes* an app from tracking the shared pin rather than letting it move independently ahead of
  it.

### R8: A Generation Records the Pin It Was Built From

**Description**: Every generation records the resolved flake pin that produced it, and the system
refuses to silently rebuild from a pin the running generation was not built from.

**User Story**: As an operator who rolled back a bad update, I want the rollback to stay rolled
back, so that changing an unrelated setting a week later does not quietly reinstall the update I
rejected.

**Why this requirement exists** (found in adversarial review, verified against the code): **rollback
does not revert the pin.** `crates/ferrum-apply/src/rollback.rs` contains no reference to
`flake.nix`, `flake.lock` or `FERRUM_FLAKE_REF` at all — it writes the intent file, runs
`nix-env --switch-generation` (:112-119), `switch-to-configuration boot` (:128), and reboots
(:137). Meanwhile every apply rebuilds from `FERRUM_FLAKE_REF`, defaulting to the live on-disk
`/etc/ferrum` flake (`crates/ferrum-apply/src/main.rs:191-192`). So:

> update → the app regresses → roll back → the machine is healthy → days later the operator toggles
> an unrelated setting and clicks Apply → `apply::run` rebuilds from the **still-advanced pin** →
> the rejected update returns, with no preview, no confirmation, and a generation that reads as an
> ordinary settings change.

This needs no attacker and no unusual sequence. It is also currently **undetectable**:
`JournalEntry` is `{snapshot, generation, toplevel, taken_at, quiesced}`
(`crates/ferrum-state/src/journal.rs:4-14`) — no field records which pin produced a generation, so
R4's claim that no new journal field is required is **retracted**.

**Acceptance Criteria**:
- [ ] `JournalEntry` gains a field recording the resolved pin (the `nodes.ferrum.locked.rev` and
      `narHash` from `/etc/ferrum/flake.lock`) that the generation was built from. Adding a field
      to that struct is a settings-schema-adjacent change; entries written before this field exists
      must deserialise with it absent rather than failing, the same tolerance
      `jobs::summarize` applies to job files predating the `started` line.
- [ ] Rolling back to a generation whose recorded pin differs from the on-disk pin **either**
      reverts the on-disk pin to the recorded one, **or** refuses to complete silently — it must
      not leave the two disagreeing without saying so.
- [ ] Any apply whose on-disk pin differs from the running generation's recorded pin is **gated**:
      the operator is told, in the Apply view, that this rebuild will also move the system to a
      different ferrum revision, and which one. An ordinary settings change must never carry an
      update in on its back unannounced.
- [ ] The rollback confirmation dialog (`ui/app.js`'s `confirmRollback`) states plainly what the
      rollback does and does not do about the pin, in the same prose register as the rest of that
      dialog.
- [ ] Discovery reports "your on-disk pin differs from the pin the running generation was built
      from" as a first-class state, not an error — it is also what an operator sees after a
      `git checkout` in `/etc/ferrum` reverts a machine-written `flake.lock` (see R2's edge cases).

**Edge Cases**:
- A generation predating this field: reported as "pin unknown" and never used to justify gating an
  apply, since the absence is an artifact of age rather than a disagreement.
- The operator deliberately wants the new pin after rolling back the closure: the gate must be
  passable, not a wall — it exists to make the decision visible, not to prevent it.

---

## Review outcomes — architect decision and the open register

This section records what the planning review changed. The requirements above are revised; this
explains why, so a reader does not have to reconstruct it.

### Open Question 1 — RESOLVED by the Technical Architect: track a curated release ref

A host's `ferrum.url` names a ferrum-published release branch/tag; `ferrum-apply` advances the pin
with `nix flake lock --update-input ferrum`, mutating **only `flake.lock`**.
`/etc/ferrum/flake.nix` stays byte-identical forever.

The reasoning that decided it is not the one this spec originally framed. The
compromised-ferrumd invariant holds identically either way — what matters is that the mutated file
is root-owned, not *which* root-owned file it is. What actually decided it was tooling fit:
`nix flake lock --update-input` is a first-class Nix command whose entire job is this operation,
whereas rewriting a `ferrum.url` string inside a human-authored `.nix` file means new,
root-privileged, bespoke source-text mutation with no Nix-native atomicity. Secondarily, ferrum's
own `flake.nix:5` already tracks a ref with a pinned rev underneath it for nixpkgs, so this applies
an existing pattern rather than inventing one.

**The cost, accepted explicitly:** every host that requests an update trusts that ferrum's release
ref only ever receives tested commits. A compromised maintainer account fans out to every host on
its next check. Mitigations: Preview shows the exact candidate rev before any commit; `flake.lock`
records the resolved rev and narHash afterwards, so the audit trail an exact-commit pin gives is
preserved; and nothing removes the manual path for an operator who wants zero delegated trust.

**New dependency this creates:** the ferrum project must establish and maintain a curated release
ref with a pre-publish testing gate. That is an organisational obligation, not code, and it is the
mechanism the accepted cost rests on.

### The correction that decision forced: two job kinds, not one

`nix flake lock --update-input` **is a write**. Wiring it into Discovery/Preview would violate R3's
read-only guarantee outright. Verified against `nix 2.35.2`: `nix eval` accepts both
`--override-input` and `--no-write-lock-file`, which is the read-only path.

- **`CheckUpdate`** (Discovery + Preview), zero fields, strictly read-only: `git ls-remote` against
  the repo and ref already in `flake.nix` to resolve the candidate SHA, then
  `nix eval --override-input ... --no-write-lock-file` to compute deltas. Touches neither
  `flake.nix` nor `flake.lock` — directly testable by hashing both files before and after.
- **`Update`** (commit), zero fields, the only writer: `nix flake lock --update-input ferrum`,
  then an unmodified call into `apply::run`.

This also answers **Open Question 2** — the trusted source is `git ls-remote` against the exact
repo and ref the operator already committed to their own root-owned `flake.nix`. No new artifact,
no second trust root. And **Open Question 5** — advance-and-apply is one atomic operator action,
because an advanced-but-unapplied lock is exactly the drift R8 now exists to prevent.

### Pre-implementation spikes — BOTH RUN, both pass

Two findings were flagged as unverified risks that could force a redo. Both were settled
empirically rather than argued, against the real pinned nixpkgs (`nixos-25.11` at
`flake.lock`'s locked rev) on 2026-09-16.

**Spike A — does every catalog app expose a uniformly evaluable version?** The architect could not
settle this by inspection and named it the highest-value spike; R1's per-app delta reporting has no
data source without it. Evaluated `services.<app>.package.version` for all seven enabled apps
through a real `mkHost`:

```
jellyfin 10.11.10          plex 1.42.2.10156-f737b826c   prowlarr 2.4.0.5397
qbittorrent 5.1.4          radarr 6.2.1.10461            sabnzbd 4.5.5
sonarr 4.0.18.2971
```

All seven, one attribute path, no per-app special-casing. **R1's per-app version reporting is
buildable as specified.** The fallback R1 already describes for a failing app remains the right
shape if a future app's module differs, but no app needs it today.

**Spike B (closes DA-6's binary question) — can a candidate be evaluated without writing the
lockfile?** `nix eval --no-write-lock-file --override-input <name> <ref>` against the real flake,
with `flake.lock` hashed before and after:

```
flake.lock before: 8d70b2543a394ecb
flake.lock after:  8d70b2543a394ecb
RESULT: lockfile UNTOUCHED
```

**The mechanism R3 depends on exists and does what R3 needs.** What this spike does NOT settle is
DA-6's cost question: the run above overrode an input already present in the store and finished in
2s. A real candidate check overrides `ferrum`, which pulls a different nixpkgs tree and forces a
full module-system evaluation twice. That cost is still unmeasured, and R3's "this phase inherits
that cost rather than introducing a new one" remains wrong until it is. Measure it before
committing to a UI that implies a check is instant.

### Findings — all four resolved; the planning gate can close

The adversarial pass returned UPHELD with 3 High and 4 Medium. Two were resolved by revision
(DA-2 became R8; DA-3 corrected the gc claims; DA-4 restated R4's no-change case). The remaining
four are resolved here — two by the spikes above, two by decisions recorded below.

**DA-1 — candidate authenticity. DECIDED by the project owner: trust the ref, record the rev.**

The threat is real and is stated rather than waved away: `apply` runs `nix build --impure`
(`crates/ferrum-apply/src/apply.rs:239-241`, whose own comment at :232-237 notes this disables the
purity sandbox for the whole build), so a candidate is evaluated **impurely, as root**. If ferrum's
release ref is ever pushed a malicious commit, every host that checks for updates is exposed. No
signature verification is required, because the operator already made a trust decision when they
pointed `ferrum.url` at this project, and requiring signing commits the project to maintaining
signing keys forever — a real obligation for a self-hosted product with one maintainer.

What that decision does NOT excuse, and what R2 must therefore bind:

- [ ] **Preview shows the exact resolved commit before anything is applied.** The operator sees the
      candidate `rev` and can refuse it. This is the control that replaces signature verification,
      so an `Update` that applies a rev the operator was never shown is a defect, not a shortcut.
- [ ] **`flake.lock` records the resolved `rev` and `narHash` after every update**, so "what am I
      running" is answerable from the host afterwards, with no external service.
- [ ] **Repo identity may never change through an update.** A pin advance that alters the
      `owner/repo` or host of the `ferrum` input is refused. Advancing a ref is a different
      operation from being pointed at a different repository, and only the first is an update.
- [ ] **Monotonicity is enforced at apply, not only at discovery.** A candidate whose resolved
      revision is not newer than the installed one is refused by the `Update` job itself — R1's
      "never report an older candidate as an update" rule is not sufficient on its own, because
      discovery and apply resolve independently.
- [ ] The spec and the UI state plainly that a candidate is evaluated as root, and that the three
      criteria above are the whole control. An operator who wants no delegated trust keeps pinning
      an exact commit by hand, which this feature never removes.

**DA-5 — the git working tree. DECIDED.** `/etc/ferrum` must be a git repository with every file
tracked (`examples/hosts/template/flake.nix:9-12`), so a machine-written `flake.lock` leaves it
dirty and a later `git checkout` silently reverts the pin — after which the next ordinary settings
apply downgrades every package on the host, with no preview and no confirmation.

- [ ] `ferrum-apply` **refuses to advance the pin when `/etc/ferrum`'s working tree is dirty**, and
      says so naming the files. It does not commit on the operator's behalf: that tree is theirs.
- [ ] Discovery reports **"your on-disk pin differs from the pin the running generation was built
      from"** as a first-class state, not an error. This is the same signal R8 needs after a
      rollback, and one detector serves both.

**DA-6 — mechanism proven (Spike B), cost unmeasured.** Downgraded from Medium to a tracked Low:
there is no correctness risk, only an unknown duration. Time a real candidate check before
designing a UI that implies it is instant.

**DA-7 — the interlock. DECIDED, and it resolves Open Question 3.** `create_job` claims a single
`job_running` bool and returns 409 to everything else (`crates/ferrumd/src/jobs.rs:148-158`), with
no timeout and no cancel. A candidate check can take minutes.

- [ ] **A read-only `CheckUpdate` does NOT take the job interlock.** The invariant that decides
      this: *a rollback must never be blocked by a read-only check.* The one path that has to work
      on a host an update just broke is exactly the one a shared interlock would block.
- [ ] `Update`, which builds and switches, takes the interlock exactly as `apply` does today.

**Gate status: the planning register is closed.** Zero Critical, zero High, zero Medium remain
open; one Low (DA-6's unmeasured cost) is tracked with an owner and a revisit trigger — measure it
before the Updates view is designed. Story breakdown may begin.

## Dependencies

- **Per-app version metadata does not exist today** and must be added before Discovery/Preview can
  report anything: no `modules/apps/*/meta.nix` file declares a version or a version-attribute path
  (confirmed by inspection of `modules/apps/plex/meta.nix` and `modules/lib/catalog.nix`), and
  `nix/modules/flake/packages.nix`'s catalog builder emits only `ferrumVersion` (the ferrum repo's
  own `shortRev`, `nix/modules/flake/packages.nix:19`), never a per-app package version.
- **A trusted "candidate" resolution source for the `ferrum` input** must exist before R2/R3 can be
  built — see Open Questions 1 and 2. This is a prerequisite architectural decision, not a detail
  this spec can resolve.
- **The settings-schema-migration write-back step is not yet implemented** — that spec's own Known
  Risk 4 states "No task in the implementing plan built this." R3's unification of app-version and
  schema-migration previews on one screen depends on that gap being closed (see Open Question 6).
- **`ferrum-apply gc` IS implemented** (corrected — see R5's edge cases; the earlier claim came from a
  stale `README.md` line, now fixed). What remains true is that nothing schedules it. (`crates/ferrum-apply/src/main.rs:397-443`, both the
  bare `Gc` subcommand and its `run-request` dispatch print "not yet implemented" and exit
  non-zero). Update, like any apply, grows the generation/snapshot count; this phase does not
  implement GC but its absence bears directly on Update's practical usability (see Open Question 4).
- **The closed `Request`/`JobRequest` enums** (`crates/ferrum-apply/src/request.rs`,
  `crates/ferrumd/src/jobs.rs`) must each gain new variant(s) under R2's constraints — this is a
  cross-cutting change to the project's whole privileged-request surface, not a local addition.
- **A new read-only daemon endpoint** for Discovery/Preview results, following the precedent of
  `GET /api/catalog` (`crates/ferrumd/src/catalog.rs`) and `GET /api/generations`
  (`crates/ferrumd/src/generations.rs`) — but unlike those two, which are synchronous ferrumd-local
  reads, this one's underlying computation must run inside privileged `ferrum-apply` (R3's second
  criterion), so its shape is closer to the existing job/progress-file mechanism
  (`GET /api/jobs/:id`) than to a plain synchronous handler. This is a new combination of two
  existing patterns, not a copy of either.

## Out of Scope

- **Implementing generation garbage collection** (`ferrum-apply gc`) — tracked as pre-existing,
  separate work this phase depends on but does not build.
- **Unattended, scheduled, or automatic updates.** This phase covers operator-initiated discovery,
  preview, apply, and rollback only; no timer, poller, or background job is introduced.
- **Multi-host or fleet update coordination** — out of scope for Phase 1 generally
  (`docs/design/2026-08-19-phase-1-design.md:57`, "multi-host management").
- **Adding a `package` option to the uniform app submodule.** The original design explicitly
  forbids this ("There is deliberately no `package` option," `docs/design/2026-08-19-phase-1-design.md:138`);
  this phase does not revisit that decision.
- **The rclone/mergerfs cloud storage tier** — already out of scope for Phase 1
  (`docs/design/2026-08-19-phase-1-design.md:57`), unaffected by this phase.
- **Completing the settings-schema-migration write-back step** — tracked as that spec's own Known
  Risk 4; this phase depends on it (see Dependencies) but does not implement it here.
- **Fixing the `mediaAccess` "read" vs "readwrite" defect** — recorded below as a finding to
  preserve, not fixed in this phase.
- **Managing or hiding Plex's `claimToken` post-claim** — recorded below as a finding to preserve,
  not built in this phase.

### Findings recorded for future work (not to be lost)

1. **`mediaAccess` has three declared values but only two behaviors.** Every catalog app grants
   media-group membership identically for `"read"` and `"readwrite"` —
   `lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup` appears verbatim in
   `modules/apps/plex/service.nix:25`, and identically in `sonarr/service.nix:111`,
   `radarr/service.nix:89`, `qbittorrent/service.nix:66`, `sabnzbd/service.nix:67`, and
   `jellyfin/service.nix:18` — and the media directories themselves are created group-**writable**
   at `0775 root ${mediaGroup}` (`modules/core/storage.nix:71-73`). There is no read-only
   enforcement anywhere in the tree: `mediaAccess = "read"` grants the same write access as
   `"readwrite"`. This is a defect in the implementation against the schema's own stated intent,
   not a design choice, and is out of scope for this phase.
2. **Plex's `claimToken` cannot currently be hidden once a server is claimed.** It is a short-lived,
   single-use `plex.tv` bootstrap credential (`modules/apps/plex/meta.nix:1-7`,
   `docs/superpowers/specs/2026-08-20-phase-1-3-catalog-apps-design.md`'s "Plex Claim-Token
   Mechanism") that becomes meaningless the moment a server is claimed, but neither ferrum nor the
   Nix module tree tracks whether a claim has happened (`modules/apps/plex/service.nix:34-36` only
   checks whether the string is non-empty), so `forms.js` renders it as an ordinary, permanently
   visible text field with no way to detect and hide it post-claim without new machinery.

## Assumptions

- The `/etc/ferrum` parent directory's `root:root 0755` permission model
  (`modules/core/bootstrap.nix:78`, activation-script check at lines 99–103) protects `flake.lock`
  the same way it already protects `flake.nix` and `hardware-configuration.nix`, even though
  `flake.lock` is not individually named by any tmpfiles rule or by the original design doc's file
  list (`docs/design/2026-08-19-phase-1-design.md:89`). This is inferred from the same
  directory-permission argument bootstrap.nix's own comment makes for its named siblings ("Write
  permission on a directory is create/delete/rename permission on every name in it regardless of
  the individual files' modes") — it has not been independently verified by a dedicated test.
- Every current catalog app's underlying nixpkgs `services.<app>` module exposes a `package` option
  whose resolved `.version` (or an equivalent evaluable attribute) is retrievable via `nix eval`,
  giving a uniform per-app version-discovery mechanism across all seven current apps. Confirmed
  only that every `service.nix` in this repo delegates to a `services.<app>` NixOS module rather
  than referencing a `pkgs.<app>` derivation directly (e.g. `modules/apps/qbittorrent/service.nix:26`,
  `modules/apps/sabnzbd/service.nix:42`); the exact attribute path per app was not verified against
  nixpkgs source during this investigation.
- `nix build --impure --no-link --print-out-paths <ref>` — the command an ordinary `apply` job
  already runs (`crates/ferrum-apply/src/apply.rs:239-241`) — does not itself rewrite
  `/etc/ferrum/flake.lock` when that lock file is already complete for the flake's declared inputs.
  This keeps R2's "the daemon never advances a pin except through the closed Update path" invariant
  intact for every *ordinary* apply; it is a behavioral assumption about `nix build`'s default
  input-locking semantics, not verified by a dedicated test in this repo today.
- The host has outbound network reachability at the moment an operator checks for updates, under
  either candidate-resolution model in Open Question 1/2. This is consistent with the project's
  existing acceptance of outbound calls for ACME/Cloudflare DNS-01 (`README.md`'s "Reverse proxy,
  TLS" section) and for `sops`/`ssh-to-age` tooling, and is distinct from — and does not change —
  the static UI's own "no external request of any kind" invariant (`ui/app.js:1-6`): any outbound
  call happens server-side inside `ferrum-apply`, never as a browser-side `fetch()`.

## Open Questions

**Status: OQ1, OQ2, OQ3 and OQ5 are resolved** — see "Review outcomes" above. OQ1 by the
Technical Architect (track a curated release ref; advance only `flake.lock`), OQ2 as its corollary
(`git ls-remote` against the repo and ref already in the operator's own `flake.nix` — no new trust
object), OQ3 by the DA-7 decision (a read-only check does not take the job interlock, because a
rollback must never be blocked by one), and OQ5 as a corollary of OQ1 (advance-and-apply is one
atomic operator action; an advanced-but-unapplied lock is the drift R8 exists to prevent). The
numbered list below is kept as written for history; read it against those resolutions.



1. **Pinning policy — the crux of R2/R3, a Technical Architect decision.** Should a host track a
   curated, ferrum-published moving reference (a release branch/tag that `ferrum-apply` re-resolves
   with `nix flake lock --update-input ferrum`, rewriting only `flake.lock` and leaving `flake.nix`
   byte-identical forever), or continue pinning an exact commit (today's template guidance,
   `examples/hosts/template/flake.nix:17-21`) and have `ferrum-apply` itself compute and rewrite the
   `ferrum.url` line in the root-owned `flake.nix`? The first keeps the one file the security thesis
   protects truly immutable, at the cost of trusting ferrum's own release process to only ever
   publish an already-tested reference; the second preserves "nothing moves without an exact,
   named commit" but requires the automated path to write to the file R2 otherwise keeps untouched
   — even though it is `ferrum-apply` (root), not ferrumd or the request file, doing the writing
   with self-computed content. Neither option is free, and this spec deliberately does not choose
   between them.
2. **What candidate-resolution source is trusted, concretely?** A `git ls-remote` against ferrum's
   own already-declared repository, a curated release manifest ferrum's project publishes
   separately, or something else — and what happens if that source is unreachable, compromised, or
   serves a reference older than what is already installed?
3. **Does Discovery/Preview share the existing single `job_running: Mutex<bool>` interlock**
   (`crates/ferrumd`'s design, confirmed by the 1.5b spec's description of the daemon re-seeding
   this from systemd at startup) with `apply`/`rollback`/`gc`, or does it get its own, given it is
   provably read-only and safe to run concurrently with a build/switch already in progress? Sharing
   it is simplest and consistent with today's code; exempting it needs new interlock machinery this
   spec does not otherwise require.
4. **Update cadence versus generation growth.** Since `ferrum-apply gc` is implemented but unscheduled, and protects only the running generation's snapshot
   (`crates/ferrum-apply/src/main.rs:373-376`), every update — like every apply — grows the
   generation/snapshot history without bound. Should this phase be blocked on GC landing first, or
   ship with an explicit, documented caveat that disk usage grows until GC exists?
5. **Should advancing the pin and applying it be one atomic operator action, or two staged steps**
   (mirroring today's Save-Settings-then-Apply split)? A single "review, then commit" action
   (matching the existing rollback-confirmation UX, `ui/app.js:348-398`) avoids a state where the
   pin has silently advanced but not yet been applied — where an unrelated, later settings-only
   apply would pick up the new versions without the operator ever having reviewed them. A two-step
   model mirrors an existing UI convention but introduces that exact drift risk. This spec does not
   settle which shape R2/R4 should take.
6. **Where does the settings-schema-migration write-back gap get resolved** — as a prerequisite fix
   landed against that spec's own implementation, or bundled into this phase's implementation work,
   given R3's unified preview screen depends on it behaving correctly (a migration must not appear
   as "new" on every single preview forever)?
7. **Does Plex's `claimToken` (recorded as a finding, not a requirement, above) deserve a follow-up
   spec** for hiding it post-claim, and if so, what detection mechanism would that need — probing
   Plex's own API, or a simpler operator-driven "clear this field" action?
