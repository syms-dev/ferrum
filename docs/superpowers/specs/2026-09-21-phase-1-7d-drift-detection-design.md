# Phase 1.7d — R16: ferrum notices when the box stops matching its configuration

**Status:** drafted 2026-09-21. **OQ1 answered by the owner (report only).** OQ2–OQ3 carry recommendations and do not block. No implementation
until that runs, and not until the Phase 1.7 R1 pipeline run finishes (one run per checkout).

## Why this exists

The dashboard design produced in Claude Design put configuration drift at the top of the apps
screen — the first and largest thing an operator sees — and it is right to. But `grep -rn "drift"
crates modules` returns only incidental uses of the word in comments. **Nothing in ferrum detects
drift.** The dashboard's best screen is blocked on a capability Phase 1 never specced.

This is not a UI gap. It is the half of the product the owner named and that was never built:

> it was supposed to be completely self-setup during the initial setup, and self-healing

And it is the failure ferrum was positioned against. The project's own critique of Saltbox names
**silent state drift** as a structural weakness, citing Saltbox issues #495 and #475. ferrum
currently shares it.

## What makes this worth building rather than obvious

A NixOS system is *already* declarative, so it is tempting to assume drift is impossible. It is
not, and the three cases below are all real — the third was observed on the owner's own host:

1. **Files ferrum does not own, under paths it does.** `nginx.conf` is generated, but nothing stops
   an operator editing the generated file in place. The next apply silently reverts it, which is
   correct behaviour presented as no behaviour at all.
2. **Runtime state diverging from declared state.** A unit `systemctl stop`ped by hand stays
   stopped. The generation says it is enabled. Both are true, and nobody is told.
3. **Application-internal configuration ferrum reconciles.** The *arrs own their own
   `config.xml`, and ferrum writes root folders and download clients into them. An operator
   changing a root folder in Sonarr's UI has made a change ferrum will overwrite on the next
   reconcile — without warning, and possibly weeks later.

The third is the one that stings: ferrum's own self-setup is what makes it destructive.

## R16 — drift is detected, named, and correctable

**User story.** Something on the box no longer matches what ferrum declared. I find out from
ferrum, on the dashboard, with enough detail to decide whether to re-apply or to roll back — not
by noticing an app behaving oddly three weeks later.

**Acceptance criteria.**

- **A1.** ferrum detects drift in all three classes above: a managed file changed on disk, a
  managed unit whose runtime state contradicts the generation, and a reconciled application
  setting changed out from under it.
- **A2. Each drifted item is named individually**, with what changed and what re-applying will do
  to it. A count is not a finding — "3 things differ" tells the operator nothing they can act on.
  The `DriftPanel` component in `ui-kit` is the contract this must satisfy (`subject`, `kind`,
  `detail`).
- **A3. Detection is read-only and never repairs anything by itself.** Re-applying is the
  operator's decision. Silent self-repair would make ferrum destroy deliberate local changes
  without being asked, which is the same defect as the drift it is fixing, pointed the other way.
- **A4.** It runs on a schedule and on demand, and the dashboard shows when it last ran. A detector
  that silently stopped running is worse than none, because the absence of findings reads as
  health. (Same failure shape as R1/A8's `dns-updater-last-success`.)
- **A5. A clean result is stated, not implied.** "Everything matches generation 48, checked 4
  minutes ago" is the healthy state, not an empty panel.
- **A6.** Detection must be cheap enough to run often on a media box that is also transcoding.
  Hashing every file in the closure on a timer is not acceptable; the design must say what it
  compares and why that is sufficient.
- **A7. No false positives from ferrum's own activity.** An apply in progress, a reconcile writing
  a root folder, or a service restarting mid-check must not be reported as drift. A detector that
  cries wolf gets ignored, and then the real finding is ignored too.
- **A8.** Findings are structured data over the API (`/api/drift` or equivalent), not rendered
  text, so the dashboard, the CLI and any future notifier read the same source.

## Open questions for the owner

- **OQ1 — ANSWERED: report only.** ferrum never repairs drift by itself; A3 stands as written. The owner's call, matching the recommendation. Original reasoning kept below because it is the reopen trigger: if "self-healing" is later taken to mean automatic repair, it returns as an opt-in, per-class, default-off setting and never as a default.

  Original question. **Does ferrum ever repair drift automatically, or only report it?** A3 above says report
  only, and that is the recommendation: automatic repair on a schedule would silently revert a
  change an operator made deliberately at 2am to get something working. But "self-healing" was the
  owner's own word for the product, so this is their call, not mine. A middle option exists —
  auto-repair only for classes the operator opts into, per class, defaulting to off.
- **OQ2. How far into application config should detection reach?** Root folders and download
  clients are reconciled today, so they are the natural scope. Every setting in Sonarr's
  `config.xml` is not, and pretending to own settings ferrum does not manage would produce
  permanent false positives. Recommendation: exactly what the reconciler writes, no more.
- **OQ3. Should drift produce a notification, not just a dashboard panel?** An operator who does
  not open the dashboard never learns. This depends on the SMTP relay deferred in R4b, so the
  recommendation is to build A1–A8 now and revisit once a notification channel exists.

## Dependencies and sequencing

- The `DriftPanel` component already exists in `ui-kit` and is synced; A2 is written against it.
- Belongs after R13 (the dashboard must be reachable) and alongside the dashboard revamp, which is
  where the panel lands.
- Independent of R1, R14 and R9–R12.

## Out of scope

- Repairing drift automatically (OQ1 pending).
- Detecting changes to files ferrum never declared. An operator's own scripts in `/opt` are not
  ferrum's business, and reporting them would be noise.
- Media files. They are never part of a generation and must never be compared.
