# The UI mockups, and what was actually built

> The mockups are committed beside this file at
> [`mockups/2026-10-07-ferrum-ui-mockups.html`](mockups/2026-10-07-ferrum-ui-mockups.html) — the
> owner's own design work, exported from a Claude artifact on 2026-10-07. Self-contained: it
> fetches nothing. Open it in a browser; it is desktop-first, so a phone viewport shows a slice.

## Why this file exists

The owner's recollection was that the designs *"seemed to be all implemented"*. **They were not.**
Measured against `ui/app.js` on 2026-10-07, three of the eight screens do not exist at all and the
most distinctive one — the app detail view — has **zero** occurrences of anything resembling it.

That matters more than a to-do list, because what shipped and what was designed are different
*kinds* of thing. The implementation is a schema-driven settings form: it renders whatever the
settings schema contains, which is why adding an app needs no UI change. The mockups are a product:
they know what an app *is*, what it is connected to, whether it is healthy, and what the operator
is likely to want next. The renderer underneath is worth keeping. The form as the primary surface
is not.

## Screen by screen

| # | Mockup screen | State in `ui/` on 2026-10-07 |
|---|---|---|
| 1 | **Onboarding** — replace the one-time setup password | **Not built** |
| 2 | **First run** — "Nothing's running yet", every app offered, Sonarr suggested | **Not built** |
| 3 | **Dashboard** — per-app health, hostname, port, pending-change banner | **Partial.** No pending-change banner (`grep` for "pending change": 0). Health language barely present (2 occurrences) |
| 4 | **App detail** — general, access, resources, app settings, **integrations** | **Not built.** No detail view of any kind |
| 5 | **qBittorrent VPN** — paste a WireGuard config, kill-switch explained | **Not built.** `wireguard`/`vpn`/`killswitch` appear **0 times** in the whole UI |
| 6 | **Apply flow** — review the diff, then live step-by-step progress | **Partial.** Apply and job streaming exist; the designed review-then-progress shape does not |
| 7 | **Updates** | **Built** |
| 8 | **Settings** — proxy, authentication, backups, apply behaviour | **Not built as designed.** What exists is "Settings schema", the generic form |

## The mockups already answer questions the owner later had to ask

Three of the five observations the owner reported on 2026-10-07 after using the deployed system are
things their own designs had already solved. That is the clearest possible evidence the designs were
right and the gap is implementation.

- **"How do we know on qBit if the VPN is active or not? I think it would make sense to be able to
  paste the configuration into the dashboard."** Screen 5 is exactly that, and it gets the security
  property right rather than hand-waving it: *"Encrypted immediately on save. ferrumd can write this
  but can never read it back."* That is a true statement about ferrum's actual privilege boundary —
  `secrets_api::write_secret` exists and there is no read path.
- **"Have you already tied prowlarr to sonarr and radarr?"** Screen 4 carries an Integrations line:
  *"Registered as an application in Prowlarr · pulls downloads from qBittorrent, SABnzbd."*
  `ferrum-reconcile` has been doing this on every apply all along. Having to ask is the defect, and
  the design had already fixed it.
- **The Updates framing.** Screen 7: *"Every app shares one pinned package set — updating brings all
  of them forward together."* That is R7's honest wholesale-not-selective framing, drawn before the
  Phase 1.6 spec reasoned its way to the same place.

## Two features the mockups contain that ferrum does not have at all

Neither is a UI gap. Both are product decisions already made in the design and never built.

- **Scheduled, encrypted state backups via restic**, with a repository and a schedule. ferrum has
  *no off-box backup story whatsoever* — the parity spec names this as out of scope and the README
  should say it plainly. Rollback is not backup, and a disk that dies takes the generations with it.
- **Auto-rollback on a failed health check**, drawn **off by default** with the reason attached:
  *"health checks aren't mature enough to trust with an automatic reboot yet."* That judgement has
  aged well and is now sharper than when it was written — `/api/ready` exists as of 2026-10-07, and
  `health.rs` carries an explicit banner that no watchdog or restart policy may point at it, because
  `main.rs` already records a ferrumd restarted mid-apply by its own generation switch.

## What to do with this

The mockups are the specification for ROAD-TO-PUBLIC item 8 (dashboard revamp) and item 28
(generation diffs). **Build to them rather than designing again.** Two notes for whoever does:

1. **Keep the schema renderer.** It is what makes "adding an app needs no UI change" true, and the
   read-only APIs beneath it — `/api/catalog`, `/api/generations`, `/api/jobs`, `/api/session`, and
   now `/api/health` and `/api/ready` — are precisely what a window onto the system needs. The
   plumbing survives the redesign; the form as the front door does not.
2. **The mockups do not cover generation diffs** (item 28) — screen 7 shows per-app version deltas
   for a pending update, which is a different thing from "what changed between generation 46 and
   47". That screen still needs designing, and it should be designed in the mockups' own register
   rather than bolted onto the current page.
