# Parity for the mergerfs pool

**Date:** 2026-10-07. **Status:** spec, awaiting owner approval before implementation.
ROAD-TO-PUBLIC item 26b (`docs/ROAD-TO-PUBLIC.md:598-605`), interacting with item 23
(`docs/ROAD-TO-PUBLIC.md:581-587`, staleness as a first-class state) and item 26c
(`docs/ROAD-TO-PUBLIC.md:606-613`, the `epmfs` decision).

---

## Overview

ferrum pools data disks with mergerfs (`modules/core/pool.nix`) and ships **no parity of any
kind**. Grepping `modules/`, `crates/` and the design docs for SnapRAID or parity returns nothing —
confirmed again while researching this spec. Perfect Media Server, the canonical guide in this
space, says exactly why that matters, on its mergerfs page (quoted, PMS content is CC BY-NC-SA
4.0, `docs/competitive/perfect-media-server.md:53-54`):

> mergerfs has **nothing whatsoever** to do with parity. If a drive fails, the data on that drive
> is gone.

What mergerfs *does* buy is real and worth stating plainly rather than letting the gap read as
"mergerfs is pointless without parity": it does not stripe, so a failed disk loses only what was on
that disk, every surviving disk stays independently readable, and any surviving disk is mountable
on any other machine with no ferrum involved at all. That is the property mergerfs actually sells.
Parity is the separate, currently-missing property of surviving the failure itself without losing
what was on the failed disk.

`services.snapraid` is a first-class NixOS module, and the author of the guide every prospective
ferrum user has already read runs it himself: his own `morphnix` host
(`ironicbadger/nix-config`, cited in `docs/competitive/perfect-media-server.md:27-36,68-75`) pairs
mergerfs with SnapRAID, using `parityFiles`, `contentFiles`, `dataDisks`, and an exclusion list of
`downloads/`, `appdata/`, `/.snapshots/`, `*.unrecoverable`. That makes this cheaper to add on
ferrum's substrate than on almost any other, and it is also why a reader who already knows PMS will
notice the gap immediately if ferrum does not close it.

This is a **full-stack** spec: a new Nix module (`ferrum.storage.parity.*` options plus
`services.snapraid` wiring), changes to `ferrum-install`'s disk-detection flow, a new privileged
status surface in `ferrum-apply`/`ferrumd`, and a dashboard tile. Six requirements follow. R4
(staleness) is the highest-value one — it is the one piece of this story PMS structurally cannot
give a reader, because PMS is documentation and does not run on the box.

**Everything below is a proposal for review, not a decision already made.** Where this spec takes a
position (R3's scheduling, R1's opt-in default), it argues the position rather than asserting it,
precisely so the owner can overturn it cheaply.

---

### R1: A parity disk is a declared role, structurally excluded from the pool

**Description**: Introduce a parity-disk role — a new option, `ferrum.storage.parity.disks` (a
list of absolute mount paths, the same `hostnames.absolutePath` type pattern already used for
`ferrum.storage.pool.branches`, `modules/core/options.nix:106-124`) — and make it structurally
impossible for a disk in that list to also end up inside the mergerfs pool, both at the Nix-module
level and at the installer's own disk-detection step.

This matters because of how disk detection already works, confirmed by reading it: `ferrum-install`
does not ask which disks are data disks — it detects them. `render::data_disks` returns "every disk
that is not the one being erased and that already carries a filesystem"
(`crates/ferrum-install/src/render.rs:172-180`). A parity disk that already carries a filesystem
(reused from a previous system, or pre-formatted by the operator so SnapRAID has somewhere to put
its content file) would, under today's logic, be silently swept into the auto-detected data-disk
set and unioned into the pool the moment a second such disk exists. That is exactly the "serious
error" the task names: a parity disk inside the pool is not redundant disk space, it is disk space
SnapRAID is also trying to use for its own content/parity files, fighting the pool for the same
blocks.

**User Story**: As an operator who dedicates a disk to parity, I want that disk to never be treated
as library storage by mistake, so that a typo or a reused disk does not silently turn my parity
disk into one more mergerfs branch.

**Acceptance Criteria**:
- [ ] A new Nix assertion (new module, e.g. `modules/core/parity.nix`, following the existing
      `assertions = lib.optionals pool.enable [...]` shape in `modules/core/pool.nix:38-79`) fires
      at evaluation when any path appears in both `ferrum.storage.pool.branches` and
      `ferrum.storage.parity.disks`, naming the offending path(s). Proved by a flake check building
      two fixture hosts — one with disjoint lists (zero assertions) and one with an overlapping
      path (assertion failure) — mirroring the differential-fixture style already used by
      `pool-branches-are-all-seeded` (`docs/ROAD-TO-PUBLIC.md:136-139`).
- [ ] This assertion fires on **every** evaluation, not only at first install — i.e. hand-editing
      `settings.json` (or its post-schema-migration equivalent) to add an existing pool branch to
      `parity.disks` after the host is already running must also fail the next `nixos-rebuild`/
      `ferrum-apply apply`. Proved by evaluating a fixture that performs exactly that edit and
      confirming the assertion fires identically to the first-install case.
- [ ] `ferrum-install`'s disk-selection flow asks, during the same pass that currently builds
      `data_disks()` (`crates/ferrum-install/src/render.rs:172-180`), which of the detected
      non-target disks (if any) is a parity disk, and removes any such disk from the pool/media-disk
      candidate set **before** `custom/media.nix` is rendered. Proved by a unit test that feeds a
      fixture `Device` list with one disk marked as the operator's parity answer into the
      (post-change) detection function and asserts that disk is absent from the returned
      data-disk/pool-branch set.
- [ ] A parity disk's mount is rendered into its own `custom/parity.nix`, never into
      `custom/media.nix` — extending the existing `custom/` convention
      (`crates/ferrum-install/src/render.rs:928`, `files.insert("custom/media.nix".into(), ...)`).
      Proved by a fixture test asserting the parity disk's `by-id` path appears in
      `custom/parity.nix` and nowhere in `custom/media.nix`.

**Edge Cases**:
- A disk named in `parity.disks` carries no filesystem yet at evaluation time: SnapRAID's content
  file needs somewhere to live, so state explicitly whether ferrum formats this disk the way it
  prepares pool branches, or refuses cleanly and tells the operator to format it first. This spec
  does not pick one — see Open Questions.
- An operator names the **OS disk itself** (the one the installer's own destructive-erase
  confirmation targets, `crates/ferrum-install/src/confirm.rs:115-119`, "The disk you name will be
  COMPLETELY ERASED") as a parity disk: refuse at the same evaluation-time assertion that guards
  pool overlap, not only at the interactive prompt, since `settings.json` can be hand-edited later.
- More than one disk is named in `parity.disks`: the option's type is a list specifically so this is
  not foreclosed (SnapRAID supports multiple parity levels), but this spec's acceptance criteria
  only require a single-parity-disk flow to work end-to-end — see Out of Scope.

---

### R2: The exclusion list, derived from ferrum's own layout

**Description**: Churning paths make every SnapRAID sync enormous and useless — PMS's own stated
reason for excluding `downloads/`, `appdata/`, `/.snapshots/`, `*.unrecoverable`
(`docs/competitive/perfect-media-server.md:69-71`). ferrum's actual directory layout is not
`morphnix`'s, so the list has to be re-derived from this repository rather than copied.

ferrum's TRaSH layout creates, under every pool branch (`modules/core/storage.nix:141-145`,
`trashSubdirs`): `torrents/`, `usenet/` (with `incomplete` and per-category `complete`
subdirectories), and `media/` (the imported library, organized by category). Only `torrents/` and
`usenet/` are churn — files pass through them and are then hardlinked into `media/` by the *arr
import step (same header comment, `storage.nix:1-14`, point 2: "the *arr import workflow depends on
hardlinks"). `media/` is the stable, final content parity exists to protect, and must never be
excluded.

The second, ferrum-specific interaction is the one the task calls out: ferrum snapshots application
*state* with btrfs, keyed to NixOS generations (`ferrum.storage.stateDir`/`snapshotDir`, defaulting
to `/var/lib/ferrum/state` and `/var/lib/ferrum/snapshots`, `modules/core/options.nix:38-52`). By
default, those subvolumes live outside the media pool entirely — on the `@root` btrfs volume
alongside `/var/lib/ferrum` itself (`examples/hosts/homelab-btrfs/disko.nix:33-67`), not on any pool
branch — so under the *default* layout, SnapRAID (configured to protect `pool.branches`) would
never see them at all, and no exclusion entry is strictly required for the default case.

But nothing currently stops an operator from relocating them into a pool branch.
`storage.nix`'s own containment assertions (`storage.nix:221-271`) check `stateDir` against
`snapshotDir`, and `journalDir` against all three of `stateDir`/`snapshotDir`/`mediaDir` — but there
is **no assertion anywhere checking `stateDir` or `snapshotDir` against `mediaDir` or
`pool.branches`**. That is exactly the configuration PMS's own `morphnix` defends against with its
`/.snapshots/` entry, and it is a real, currently-open gap in this repository, not a hypothetical
one. This spec does not close that gap (a Nix module fix independent of parity — see Dependencies),
but it means the SnapRAID exclude list must be **generated from the live, resolved option values**,
not hardcoded as a literal string, so that if `stateDir`/`snapshotDir` ever do end up nested under a
branch, the exclusion still finds them.

**User Story**: As an operator, I want a parity sync to be fast and to cost real protection, not CPU
re-churning downloads and rollback snapshots that were never meant to be protected this way.

**Acceptance Criteria**:
- [ ] The generated SnapRAID `exclude` list is computed from `config.ferrum.storage`'s resolved
      values, not a static string — proved by a flake check that relocates `stateDir` (via a
      fixture override) to a path nested under a pool branch and asserts the rendered exclude list
      contains that moved path.
- [ ] Under the **default** layout, the rendered exclude list is exactly: `${branch}/torrents/**`
      and `${branch}/usenet/**` for every pool branch, plus `*.unrecoverable` (SnapRAID's own marker
      for a file it declined to restore during a scrub fix). Proved by evaluating the same two-
      branch fixture host already used by `pool-branches-are-all-seeded`
      (`docs/ROAD-TO-PUBLIC.md:136-139`) and diffing the rendered `services.snapraid.exclude`
      against this exact set.
- [ ] `media/` (and its per-category subdirectories) never appears in the exclude list under any
      fixture — proved by the same test asserting its absence.
- [ ] `stateDir`, `snapshotDir`, and `journalDir` each contribute a defensive exclude entry
      whenever their resolved value nests under a pool branch (per the gap named above) — proved by
      three separate fixtures, one per option, each relocating exactly one of the three under a
      branch and asserting only that one's exclude entry appears.

**Edge Cases**:
- An operator adds a `custom/` override that writes new files directly under a pool branch, outside
  the TRaSH layout entirely: not detectable at evaluation time from `config.ferrum.storage` alone.
  Named as a residual limitation (see Dependencies), not solved here.
- A branch is rebalanced by `epmfs`/`mfs` policy (new seasons landing on a different branch than
  their show's earlier seasons, `modules/core/pool.nix:143-159`'s own documented trade-off): this is
  ordinary `media/` content moving within the protected set, not a reason to exclude anything —
  covered by the same "`media/` never excluded" criterion above.
- SnapRAID's own handling of hardlinks between `torrents/`/`usenet/` and `media/` (the *arr import
  mechanism means the same inode can appear in both an excluded and an included directory) is
  **unverified** against a real SnapRAID binary in this analysis — see Assumptions.

---

### R3: Sync and scrub scheduling — automatic, breaking from the `gc` precedent, argued

**Description**: ferrum deliberately runs **no timer** for `ferrum-apply gc` — it is
operator-triggered only (`modules/core/options.nix:177-196`'s `keepGenerations` documentation, and
independently confirmed in `docs/superpowers/specs/2026-09-16-phase-1-6-updates-design.md:301-304`:
"no systemd timer runs gc… confirmed: `keepGenerations` appears only in
`modules/core/options.nix` and `modules/core/overlays.nix`, with no timer unit anywhere"). It would
be consistent to default parity sync the same way. **This spec recommends the opposite — automatic
by default — and argues it explicitly, because the two operations have opposite failure
directions.**

`gc` is destructive: it deletes snapshots, and a deletion that happens without the operator having
looked is the single worst thing that file can do (`crates/ferrum-apply/src/gc.rs:1-18`). Manual-only
is the safe default precisely because running it automatically risks removing someone's only way
back before they know they need it.

Parity sync has the inverse risk profile. The dangerous state is **not** running it: every file
written since the last sync is unprotected, in PMS's own words (quoted and discussed under R4
below). Running sync does not delete anything the pool holds — the worst outcome of an automatic
sync is wasted I/O at a bad moment, not lost data. Under that asymmetry, the `gc` precedent argues
*for* automating parity sync, not against it: the two operations sit on opposite sides of the same
reasoning ("never do the destructive thing without the operator present").

ferrum already has a closer precedent than `gc` for exactly this shape of background task: the DNS
updater's self-healing timer (`modules/proxy/dns.nix:431-444`), which runs non-destructively on a
schedule with `OnBootSec = "5min"`, `OnUnitActiveSec = "${intervalMinutes}min"`, and
`Persistent = true` (so a check due while the host was off still runs promptly on boot). That shape
— not `gc`'s — is the one this spec proposes to copy.

**User Story**: As an operator, I want parity protection to stay current without having to remember
to run a command, the same way DNS already corrects itself without my attention — while still being
able to trigger a sync by hand whenever I want one sooner.

**Acceptance Criteria**:
- [ ] A new `systemd.timers.ferrum-parity-sync` runs `snapraid sync` on a default schedule
      (nightly), generated with the same `OnBootSec`/`OnUnitActiveSec`/`Persistent = true` shape as
      `modules/proxy/dns.nix:431-444`. Proved by a flake check asserting the generated unit carries
      all three fields.
- [ ] The interval is operator-configurable, mirroring `dns.ddnsUpdater.intervalMinutes`'s existing
      option shape, and the whole timer is disablable — an operator who wants fully manual control
      (matching `gc`'s default) can configure it that way. Proved by evaluating both a default
      fixture (timer present) and a disabled fixture (no timer unit generated).
- [ ] A manual trigger is available regardless of the timer's state — a `ferrum-apply` subcommand
      callable independent of the schedule. Proved by a CLI invocation test that does not depend on
      any timer being enabled.
- [ ] `snapraid scrub` runs on its own, separately-configurable, longer-period timer (default
      weekly) — proved by a flake check asserting two distinct timer units exist with independent
      enable/schedule options.
- [ ] Both generated units are deprioritized relative to interactive/streaming work (e.g.
      `IOSchedulingClass = "idle"`, matching the deprioritization intent already present elsewhere
      in the tree for background units) — proved by inspecting the generated `serviceConfig`.

**Edge Cases**:
- A sync is still running when its own timer fires again on a very large pool: whether
  `services.snapraid`'s generated unit already serializes this (systemd's default "already active,
  skip" behavior for a `Type=oneshot` unit bound to a timer) is **unverified** against the real
  module in this analysis — confirm before relying on it; see Assumptions.
- A sync/scrub is in progress when an unrelated settings change triggers `ferrum-apply apply`'s own
  quiesce/snapshot sequence (`crates/ferrum-apply/src/apply.rs`): this spec requires a stated
  decision (wait, proceed, or refuse) rather than an accidental interaction — see Open Questions;
  this is new interlock surface area, not reuse of an existing one.
- An operator disables both timers entirely: must remain a fully legal, supported configuration —
  automatic is the default, not a requirement, and R4's staleness reporting must work identically
  whether the operator relies on the timer or triggers sync by hand.

---

### R4: Staleness is the dashboard figure PMS cannot give you

**Description**: This is the highest-value requirement in this spec. PMS states the limitation of
its own recommended approach without hedging (quoted, CC BY-NC-SA 4.0,
`docs/competitive/perfect-media-server.md:77-78`):

> parity is computed on a schedule, so **between syncs, new files are unprotected**.

PMS can only ever *tell* a reader this. ferrum runs on the box and can *show* it, as a number that
changes: last sync N hours ago, M files/GB written since. ROAD-TO-PUBLIC item 23
(`docs/ROAD-TO-PUBLIC.md:581-587`) already names the shape this has to take — "a data-model choice —
`Option<T>` + timestamp + reason, not a bare number" — and names the exact failure to avoid: "a
mergerfs branch that drops out must render *unavailable* or *last measured N days ago*, never as
free space." A parity tile that reads "protected" with no timestamp attached is precisely that
frozen-gauge failure arriving in a new place, and this project has already caught its sibling twice
(the empty `systemctl list-dependencies` reading as health; `sonarr/meta.nix` probing `/ping` rather
than trusting `is-active` — both cited at `docs/ROAD-TO-PUBLIC.md:584-586`).

This status must **not** be folded into the existing `GET /api/health`/`GET /api/ready` pair.
`health.rs`'s own file header is explicit that readiness "does NOT mean… that the media pool is
mounted, that every mergerfs branch is present, or that there is free space" — "Nothing here touches
storage" (`crates/ferrumd/src/health.rs:70-71`, mirrored in `README.md:364-365`), and both routes are
deliberately the only unauthenticated `/api/` surface besides login/logout/sso
(`README.md:377`, "the only `/api/` routes besides login, logout and sso that are"). Parity status
is operator-facing detail (file/byte counts, a parity-disk identity), not a monitor-robot liveness
signal, so it belongs on a new, separate, **authenticated** endpoint rather than stretched onto the
two routes whose entire design is "ask nothing about storage."

**User Story**: As an operator, I want to see at a glance whether my parity protection is current or
stale, with a real timestamp, so that "it says protected" never means something different from "it
is actually protected right now."

**Acceptance Criteria**:
- [ ] A new, read-only, authenticated endpoint reports: last successful sync timestamp
      (`Option<DateTime>`, `None` meaning never synced), the elapsed time since it, and — where
      `snapraid status`/`diff` can report it (unverified against a real binary; see Assumptions) —
      an approximate count/size of files changed since that sync. Proved by a unit test asserting
      the response shape against a fixture "last sync" record.
- [ ] "Never synced," "sync currently running," and "synced, but stale" are three distinct, named
      states — not inferred by the caller from a bare timestamp — mirroring the explicit
      `applying`/`degraded`/dead distinction `health.rs` already makes for apply jobs
      (`crates/ferrumd/src/health.rs:49-58`). Proved by three fixtures, each producing a different
      named state in the response.
- [ ] No derived number (elapsed time, changed-file count) is ever returned without the timestamp or
      state it was computed from traveling in the same response object — proved by the response
      schema making the timestamp a required sibling field, never a separately fetchable value.
- [ ] A failed sync/scrub (SnapRAID exits non-zero) is its own state, distinguishable from both
      "never synced" and "stale-but-last-run-succeeded" — an unreachable/failed check must never
      read the same as a clean result, the same rule the field-defects spec already states for DNS
      discovery ("an unreachable check must never be indistinguishable from a clean result,"
      `docs/superpowers/specs/2026-10-05-field-defects-design.md:40`). Proved by a fixture
      simulating a non-zero SnapRAID exit and asserting a distinct response state.
- [ ] Wherever the dashboard (ROAD-TO-PUBLIC item 8's eventual revamp) renders this, it follows the
      same loading/empty/error/success discipline required of every data-driven view in this
      project — never a blank tile for "parity not configured." Proved by the view's own fixture
      tests covering all four states.

**Edge Cases**:
- Parity is not configured on this host at all: the endpoint reports an explicit "not configured"
  state — never a 404 that could be confused with a transient error, never silent absence.
- The parity disk itself is unmounted or has failed: this is a sharper, distinct state from
  "stale" — a dead parity disk cannot protect anything no matter how recent its last sync was, and
  must not be reported merely as an old timestamp.
- Host rebooted mid-sync: "sync in progress" must resolve to a terminal state (failed, or
  stale-with-last-known-good) rather than sticking at "in progress" forever — the same class of
  concern the phase-1-6 spec's DA-7 finding already raised for the job interlock having no timeout
  (`docs/superpowers/specs/2026-09-16-phase-1-6-updates-design.md:597-604`).

---

### R5: Restoring from parity — documented and exercised, not just claimed

**Description**: A parity system nobody has restored from is a backup nobody has tested. This
requirement is deliberately not satisfied by documentation alone.

**User Story**: As an operator who just lost a data disk, I want a documented, exact procedure to
rebuild it from parity, and I want to trust that procedure because it has actually been run once
against a real failure, not merely described.

**Acceptance Criteria**:
- [ ] A documented, numbered restore procedure exists (README or a new `docs/storage/` page)
      covering at minimum: replacing a failed data disk and rebuilding its contents from parity, and
      restoring individual files a scrub flagged as bad.
- [ ] The procedure is **exercised** before this requirement is marked done: delete a known file
      from a data disk (or simulate a disk replacement) in a VM or test fixture, run the documented
      steps, and confirm the file reappears byte-identical — proved by a checksum comparison
      recorded as the evidence artifact for this criterion (the kind of captured command + output
      this project's own quality gates require rather than an assumed PASS).
- [ ] Restore is **operator-triggered only, never automatic**, gated behind an explicit confirmation
      naming exactly what will be overwritten — reusing the existing `confirmRollback` prose pattern
      (`ui/app.js:348-398`, already the precedent the phase-1-6 spec points rollback-adjacent UI at)
      rather than inventing a new confirmation shape.
- [ ] A restore attempted while R4 reports the parity data as stale surfaces that warning plainly —
      files changed since the last successful sync will not be recovered correctly, and the restore
      surface must read R4's status rather than operate blind to it.

**Edge Cases**:
- Both a data disk and its SnapRAID content-file copy are unreadable at the same time: refuse
  clearly rather than attempting a partial restore that could corrupt what remains.
- The replacement disk is smaller than the failed one: refuse with a clear message naming both
  sizes, rather than a silent truncated restore.
- A restore target is also a live `pool.branches` member with apps actively writing to it: state
  whether apps are quiesced first, reusing the existing apply pipeline's stop/snapshot ordering
  (`crates/ferrum-apply/src/apply.rs`) rather than inventing a second quiesce mechanism.

---

### R6: "RAID is not backup," stated by the product itself

**Description**: If ferrum ships parity, the product's own surfaces — not only its docs — must
never imply parity is a backup. PMS says this in its own words, in two separate places for a
reason (quoted, CC BY-NC-SA 4.0, `docs/competitive/perfect-media-server.md:93`): "'RAID is not
backup' … If ferrum ships parity, ship the sentence with it. The UI must never imply parity is a
backup."

**User Story**: As an operator, I want ferrum to tell me plainly what parity does and does not
protect against, everywhere it shows me a "protected" state, so that I never mistake "my disk can
fail safely" for "my data is backed up."

**Acceptance Criteria**:
- [ ] Every surface that reports a healthy/"protected" parity state (R4's dashboard tile, any CLI
      status output) carries a sentence to the effect that parity protects against a single local
      disk failure only — not deletion, not corruption that gets synced before anyone notices, not
      ransomware, not fire or theft. Proved by a text-content assertion on the rendered UI/CLI
      output, mirroring the existing stale-comment-scan precedent that greps generated output for a
      required or forbidden phrase (`docs/ROAD-TO-PUBLIC.md:177-183`,
      `no_comment_still_claims_the_daemon_has_no_vhost`).
- [ ] R5's restore confirmation dialog states the same limitation again, immediately before an
      operator relies on it.
- [ ] No UI, CLI, or doc surface this spec adds ever uses the word "backup" to describe parity.
      Proved by the same text-scan asserting the word's absence from every new surface.

**Edge Cases**: none beyond the text-presence/absence checks above — this is a UX/documentation
requirement, not a logic one.

---

## Dependencies

- **`services.snapraid`'s real option surface is unverified in this repository.** It is not
  vendored in-tree (ferrum's `flake.lock` pins nixpkgs by revision, but this analysis did not read
  nixpkgs source), so `parityFiles`/`contentFiles`/`dataDisks`/`exclude` are taken on PMS's own
  description of `morphnix`'s usage (`docs/competitive/perfect-media-server.md:68-69`), not
  independently confirmed against the module. Confirm the real option names and their exact
  semantics before implementation.
- **A new `/etc/ferrum/custom/parity.nix` convention**, extending the existing `custom/media.nix`
  pattern (`crates/ferrum-install/src/render.rs:928`) for parity-disk mounts.
- **R2's exclusion-list generation** needs read access to `config.ferrum.storage`'s resolved values
  at module-eval time — the same shape `storage.nix` already uses to build `treeRoots`
  (`modules/core/storage.nix:166-176`).
- **R4's status endpoint needs a privileged command surface.** SnapRAID commands touch raw disk
  devices and should not be invoked directly by the unprivileged `ferrumd` process, mirroring the
  existing "the daemon never shells out to `nix`" invariant the phase-1-6 spec establishes for
  update checking (`docs/superpowers/specs/2026-09-16-phase-1-6-updates-design.md`, R2's last
  criterion) — this was not independently re-verified against `modules/core/daemon.nix` in this
  session, but the same reasoning applies: a new privileged job kind in `ferrum-apply`, surfaced to
  `ferrumd` through the existing job-request mechanism, is the shape to follow rather than a new
  direct shell-out from the daemon.
- **The dashboard revamp (ROAD-TO-PUBLIC item 8)** is the natural home for R4's tile. This spec does
  not require item 8 to land first, but its UI acceptance criteria assume *some* dashboard surface
  exists to render into.
- **The pre-existing gap named in R2** — no assertion currently checks `stateDir`/`snapshotDir`
  against `mediaDir`/`pool.branches` in `modules/core/storage.nix` — is named, not fixed, by this
  spec. Closing it is a smaller, independent fix worth doing regardless of whether parity ships.

## Out of Scope

- **Off-box or cloud backup of any kind.** ferrum has no off-box backup story today, and this spec
  does not create one. Parity protects against a single local disk failure only. This is a
  separate, larger gap than this spec addresses, and it should be named honestly rather than implied
  as solved by shipping parity.
- **Rollback as backup.** Noted, not solved: `ferrum-apply rollback` reverts a generation, it does
  not recover from a data-loss event. The README should eventually say this plainly, per the task's
  own framing, but that edit is not an acceptance criterion of this spec.
- **Multiple parity disks / multiple SnapRAID fault-tolerance levels.** R1's option shape (a list)
  does not foreclose this, but no acceptance criterion here requires more than one parity disk to
  work.
- **Automatic disk-failure detection or unprompted self-healing restore.** R5 requires the restore
  procedure to exist and work when the operator triggers it; it does not require ferrum to detect a
  failed disk and propose a restore unprompted — that is downstream of ROAD-TO-PUBLIC item 26d's
  SMART/drive-temperature monitoring work, not this spec.
- **Resolving ROAD-TO-PUBLIC item 26c (`epmfs` vs `pfrd`).** Named as an interacting open question
  below, not resolved here.
- **The installer's exact interactive wording/flow for naming a parity disk.** R1 requires the
  mechanical disjointness guard and the `custom/parity.nix` rendering shape; the precise prompt flow
  in `ferrum-install` is left to implementation, consistent with the task's own framing of this as
  an open question rather than something to silently answer.

## Assumptions

- `services.snapraid` exists in the pinned nixpkgs revision with an option surface at least as rich
  as `parityFiles`/`contentFiles`/`dataDisks`/`exclude`, per PMS's description of `morphnix`'s usage
  (`docs/competitive/perfect-media-server.md:68`) — **not independently verified** against nixpkgs
  source in this repository.
- `snapraid status`/`diff` (or an equivalent subcommand) can report enough to approximate "what
  changed since the last sync" in a machine-parseable way — assumed from SnapRAID's documented CLI,
  **not run against a real binary** during this analysis.
- A parity disk is, like a pool branch, identifiable by a stable `/dev/disk/by-id/` path through the
  same `Device`/`by_id` detection machinery the installer already uses
  (`crates/ferrum-install/src/render.rs`'s `Device` type) — consistent with, but not separately
  verified beyond, the existing pool-branch mounting convention.
- The generated `services.snapraid` systemd units tolerate being re-pointed at
  `IOSchedulingClass = "idle"`/nice without the module fighting that configuration —
  **unverified**.
- SnapRAID's handling of hardlinks shared between an excluded directory (`torrents/`/`usenet/`) and
  an included one (`media/`) behaves sanely (protects the shared data once, does not double-count or
  silently skip it) — **unverified** against a real binary; worth an explicit spike before
  implementation, in the same spirit as the phase-1-6 spec's pre-implementation spikes
  (`docs/superpowers/specs/2026-09-16-phase-1-6-updates-design.md:510-546`).

## Open Questions

1. **Does adding parity change the `epmfs` vs `pfrd` calculus (ROAD-TO-PUBLIC item 26c,
   `docs/ROAD-TO-PUBLIC.md:606-613`)?** SnapRAID's `dataDisks` are keyed to specific mount paths
   regardless of mergerfs's create policy, so the two appear independent at the SnapRAID layer — but
   a policy that scatters one show's seasons across more branches also scatters it across more
   parity-protected disks, changing the blast radius of losing one disk from "one show" to "pieces
   of several shows." Posed, not resolved here; the owner's decision on 26c should account for this
   interaction.
2. **What happens on a single-data-disk host?** SnapRAID can protect a single data disk with one
   parity disk — this is a common single-disk-NAS configuration — but every requirement above was
   written assuming a pooled, multi-branch host. Is parity meaningful, refused outright, or silently
   unavailable on a one-disk ferrum host? Not decided here.
3. **How does a parity disk interact with the installer's disk-selection gate
   (`crates/ferrum-install/src/confirm.rs`) and its destructive-erase confirmation?** Does naming a
   disk as parity happen before or after the OS-disk erase confirmation, and does ferrum ever format
   an unformatted parity disk the way it prepares pool branches, or must the operator always
   pre-prepare it? Posed in R1's edge cases, not resolved.
4. **Opt-in or on-by-default?** This spec recommends **opt-in**: parity claims a whole dedicated
   disk's worth of capacity the operator must deliberately supply, "a suitable disk exists" is
   ambiguous to detect automatically without risking silently claiming a disk the operator meant for
   something else (squarely the kind of scope-expanding, hard-to-reverse decision
   `.claude/rules/human-in-the-loop.md` reserves for an explicit ask), and it should follow the same
   "detect candidates, then ask" pattern `pool.enable`'s own installer behavior already uses rather
   than defaulting on. The exact installer UX for presenting that choice (a strong nudge vs. a
   passive, operator-sought option) is left to implementation.
5. **Does R3's automatic sync timer need to coordinate with `ferrum-apply apply`'s own
   quiesce/snapshot sequence**, and if so, through the existing single `job_running` interlock (the
   phase-1-6 spec's DA-7 precedent,
   `docs/superpowers/specs/2026-09-16-phase-1-6-updates-design.md:597-604`) or a new, separate one?
   Posed in R3's edge cases, not resolved.
6. **Should R4's status live at a new top-level `/api/storage/...` route, or alongside an existing
   read-only pattern** such as `GET /api/catalog`'s? This spec requires it be a distinct,
   authenticated endpoint, separate from `/api/health`/`/api/ready` — it does not fix the exact path.
