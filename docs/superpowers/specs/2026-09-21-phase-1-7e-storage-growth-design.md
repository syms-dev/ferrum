# Phase 1.7e — R21: disks you add actually get used

**Status:** drafted 2026-09-21. Contains a **reproduced defect**, not a speculative one. Owner has
authorised implementing every outstanding requirement; this one is sequenced with the rest.

## The defect, reproduced

`modules/core/storage.nix:84-99` creates the TRaSH tree with `systemd.tmpfiles` rules at
`${cfg.mediaDir}` — that is, **through the mergerfs mount**, not on each branch.
`modules/core/pool.nix:44` sets `category.create=epmfs`, and `epmfs` means *existing path, most
free space*: a branch is only a candidate for a new file if it **already has the parent path**.

Run against real mergerfs in a container, with the same options ferrum uses:

```
--- both branches EMPTY, create the TRaSH tree through the pool ---
d0:   (nothing)
d1:   /b/d1/media  /b/d1/media/movies  /b/d1/media/tv  /b/d1/torrents  /b/d1/torrents/tv

--- write a new show ---
landed on d0? no        landed on d1? YES

--- now add a new empty disk d2 ---
new show on d2 (the new disk)? NO       d2 contents: 0 entries
```

Two consequences, both silent:

1. **A fresh install with two or more empty disks puts the entire library on one of them.** The
   first `mkdir` picks one branch; every subsequent `mkdir` has only that branch as a candidate,
   because only it has the parent path. The other disks receive nothing until the first falls
   below `minfreespace`, at which point there is no eligible branch at all.
2. **A disk added later is inert.** It has no paths, so `epmfs` never selects it. The operator
   plugs in a disk, sees the pool's total capacity grow, and nothing is ever written to it.

The owner's own host is not affected *today* only because both its disks already held media at
those paths when the pool was created. That is luck, not design, and it is exactly the shape of
bug this project keeps finding: it works on the machine it was built against.

## R21 — a disk you add is set up, used, and visible

**User story.** Both my disks are nearly full. I plug in a third, tell ferrum to use it, and it
becomes part of the library with the right folders — without me formatting it, editing Nix, or
learning what `epmfs` means.

**Acceptance criteria.**

- **A1. Every branch carries the TRaSH tree.** The directory structure is created on each pool
  branch directly, not through the mount. This is the fix for the reproduced defect and it must
  ship whether or not the rest of R21 does — it is a correctness bug today, not a feature gap.
- **A2.** Adding a branch seeds the tree onto it before it joins the pool, so it is a candidate
  for new writes immediately rather than after the operator manually creates a folder.
- **A3. ferrum detects an unused disk and offers it.** The installer already has the inventory
  code (`crates/ferrum-install/src/inventory.rs`); the dashboard needs the same view: what disks
  exist, which are in the pool, which are untouched, and their serials.
- **A4. Adding a disk is one confirmed action**, and it is destructive, so it gets the same
  treatment as the installer's erase gate: the disk is named by serial and the operator confirms
  it. `ConfirmErase` and `DiskCard` in `ui-kit` exist for this.
- **A5. Removing a branch is not a delete.** An operator retiring a disk needs its contents moved
  to the remaining branches first, and ferrum must refuse rather than silently drop a branch whose
  files would vanish from the library view.
- **A6. Per-disk usage is visible.** The pool presents one filesystem, which hides the thing the
  operator needs to know: *which* disk is nearly full. `CapacityBar` exists and is unwired.
- **A7.** A branch approaching `minfreespace` is surfaced before it crosses it, not after.

## Rebalancing existing data — deliberately separate

A1 and A2 fix *placement*: new content spreads across branches correctly. Neither moves a file
that is already written, so two disks at 95% and a new empty one stay that way for existing media
while new content lands on the new disk.

`mergerfs-tools` ships `mergerfs.balance` for exactly this, so it is packaging rather than
invention. It is kept out of R21's critical path because moving terabytes between disks is slow,
IO-heavy on a box that is also transcoding, and — unlike A1 — nothing is broken without it.

**Recommendation:** ship A1–A7, then add rebalancing as its own requirement with a scheduled,
interruptible, progress-reporting job. Doing it as a fire-and-forget action inside R21 would be
the worst version of it.

## Open questions

- **OQ1.** Does ferrum format a new disk, or only adopt one that is already formatted?
  Recommendation: **format it**, through the same disko path the installer uses, because "go
  partition it yourself first" is the manual step this requirement exists to remove. A4's
  confirmation is what makes that safe.
- **OQ2.** Should A1's fix be backfilled onto existing hosts? An installed host has the tree on
  one branch only. Recommendation: **yes, idempotently** — creating the tree on every branch is
  harmless where it already exists, and without it existing installs keep the defect forever.
- **OQ3.** Should rebalancing run automatically once it exists? Recommendation: **no**, matching
  R16's report-only decision. Surface the imbalance, let the operator start it.
