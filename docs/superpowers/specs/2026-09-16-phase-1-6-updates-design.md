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
- The candidate pin advanced but resolves to **no change** for this host's enabled apps (none of
  them happened to move in that nixpkgs revision): the apply still proceeds and succeeds as an
  ordinary, if uneventful, generation — not treated as an error or a no-op that's silently skipped.

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
- The pre-update generation's snapshot could in principle be pruned before an operator notices the
  update is bad — today nothing prunes automatically (`ferrum-apply gc` is stated as
  "not yet implemented," `crates/ferrum-apply/src/main.rs:373-376`), so this is a known future
  interaction with GC rather than a present risk; flagged so it is not rediscovered as a surprise
  once GC ships (see Open Question 4).
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
- **`ferrum-apply gc` is not yet implemented** (`crates/ferrum-apply/src/main.rs:373-376`, both the
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
4. **Update cadence versus generation growth.** Since `ferrum-apply gc` is not yet implemented
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
