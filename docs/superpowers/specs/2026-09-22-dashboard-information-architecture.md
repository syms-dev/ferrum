# The ferrum dashboard — what is on each screen, and what is not

**Status:** decided 2026-09-22. This is the input a design tool renders. It is deliberately
opinionated: the previous two design passes came back overcrowded because scope was left to the
design step, and scope is a product decision.

## Why the last two attempts missed

Both were briefed with the option list and asked to render it. That produced a per-app settings
page offering, for **Prowlarr**: *"Paths that skip the login"*, *"Media access"*, *"Memory limit"*
and *"CPU quota (%)"*.

Every one of those is wrong, and in a different way:

- **Paths that skip the login** is `authBypassPaths` — a correctness value from the catalog.
  Editing it breaks Prowlarr's sync into Sonarr and Radarr, silently. It is not a setting; it is
  the app definition.
- **Media access** is meaningless for Prowlarr, which never touches media.
- **Memory limit** and **CPU quota** are tuning almost nobody needs, presented as routine.

The failure is not visual. **An option existing is not a reason to render it**, and this contradicts
the product's own stated principle: the dashboard is a window onto the system, not a rendering of
every option in the schema.

## The one rule

**A healthy ferrum dashboard is mostly empty.** Emptiness is the feature — it is how an operator
knows at a glance that there is nothing to do. Every element earns its place by being either a
*problem*, an *action*, or a *fact the operator came to look up*.

Three consequences, applied everywhere below:

1. **Anything that is not a problem gets one line.** Anything that *is* a problem gets room.
2. **Never render a panel whose message is "this is fine."** A green box saying the VPN is up is
   noise; one line saying so is information.
3. **Colour marks a state change, not a category.** A filled colour block means *something
   happened*. If three panels are tinted at rest, none of them read as urgent when one should.

---

## Screen 1 — Apps (the home screen)

### Healthy state, which is the state it is in almost always

```
Everything matches generation 48 · 7 apps running · checked 2 minutes ago

[ Plex ]  [ Sonarr ]  [ Radarr ]  [ Prowlarr ]  [ qBittorrent ]  [ SABnzbd ]  [ Authelia ]
```

One status line and the tiles. **That is the whole screen.** No reachability table, no VPN panel,
no updates table, no capacity bars.

Each tile carries: the name, whether it is running, its URL as a link, and one way in. Nothing else.

### What appears only when it is true

In priority order, at the top, above the tiles:

| Condition | What shows | Size |
|---|---|---|
| Configuration drift | `DriftPanel`, full detail, every item named | Full panel — this is the one thing that earns it |
| An app is not running | That tile shows it; no separate banner | Inline |
| Updates available | **One line**: "3 apps have updates · Review" | One line, links to a detail view |
| VPN tunnel down **with** kill switch | **One line**: "qBittorrent is stopped — the VPN tunnel is down" | One line |
| VPN down **without** kill switch | `VpnStatus`, full, red — traffic is leaving over the real address right now | Full panel |
| A pool disk near full | **One line**: "sdb has 40 GB left" | One line |

### Explicitly not on this screen

- The reachability table. It belongs in each app's own page, or behind a "check reachability"
  action. A permanent seven-row table of `200`/`302` is a diagnostic, not a dashboard.
- `VpnStatus`'s six fields when the tunnel is up.
- Version numbers and release notes for available updates.
- Storage capacity bars. Storage has its own screen.

---

## Screen 2 — One app

Reached by clicking a tile. Four blocks, in this order.

**1. What it is and how to open it.** Name, one-line summary, running or not, its URL as a large
link, an Open button.

**2. How it is reached.** Read-only facts, one line each: its address, whether it is behind SSO or
uses its own login, and its certificate. These answer "why can't I get in" and are not editable
here.

**3. Settings — only the ones a human would ever change.** See the classification below. For most
apps this is **two things**: whether it is enabled, and its subdomain. If that looks sparse, it is
because it is; the rest is machinery and ferrum manages it.

**4. What is specific to this app**, and only where it exists:

| App | Block |
|---|---|
| Plex | Claim status, the libraries ferrum created |
| qBittorrent | `VpnStatus` when configured, and `VpnSettings` to change it |
| Sonarr / Radarr | Root folder and download client, stated as facts ferrum manages |
| Prowlarr | Indexers, and which apps it syncs into |
| Everything else | Nothing. The block does not render |

**Advanced**, collapsed, and only rendered where it is meaningful: memory limit, CPU quota,
URL base. Never expanded by default, never on the main path.

---

## The settings classification — the code change this depends on

Today the UI renders whatever options exist. Instead, **each app's `meta.nix` declares which
settings are operator-facing**, and the UI renders only those.

Three tiers:

- **`operator`** — a person might reasonably change this. `enable`, `subdomain`. That is nearly
  the whole list.
- **`advanced`** — real, occasionally needed, collapsed by default: `resources.memoryMax`,
  `resources.cpuQuota`, `settings.urlBase`.
- **`machinery`** — **never rendered.** `authBypassPaths`, `port`, `stateDir`, `exposure`,
  `auth.policy`, and `mediaAccess` for any app with no media role. These are the app definition.
  An operator changing them breaks cross-app wiring in ways that surface days later.

**Relevance is per app, not global.** `mediaAccess` renders for Sonarr, Radarr and Plex, and does
not exist for Prowlarr. The catalog already knows this — `mediaCategory` is declared in
`meta.nix` — so the UI should ask rather than assume.

The settings audit's R18 covers the risky-setting classification; this extends it with *relevance*,
which is the half that produced the Prowlarr screen.

---

## Screen 3 — Apply

Only interesting while something is happening.

- **Idle:** one line — "Generation 48, applied 2 hours ago" — and a button to re-apply. Nothing else.
- **Running:** `ApplyProgress` (steps plus live log). This is the one screen that is allowed to be
  dense, because the operator is watching a thing happen and the log is the diagnostic.
- **Failed:** the failing step, its reason, the log scrolled to it, and one action.

---

## Screen 4 — Generations

- The list, newest first, each with what changed and a way back.
- One line above it: how many are kept and what they occupy.
- Rolling back opens `RollbackConfirm`.

Nothing else. This screen is a list.

---

## Screen 5 — Secrets

- One short paragraph on why a value can be replaced but never shown.
- The secrets, each as `SecretField`.

The host key is a fact worth having and belongs behind a disclosure, not at the top.

---

## Screen 6 — Storage *(new; needs R21)*

The pool hides the thing an operator most needs — **which** disk is full — so this screen exists to
say it.

- One line: total, used, free across the pool.
- One row per disk: its own capacity, and whether it is near the floor.
- Adding a disk, which is destructive and uses the erase confirmation.

---

## Writing rules for every screen

- **One sentence per element.** If it needs a paragraph, it belongs behind a disclosure.
- Numbers, paths and names stay exact. Precision is never traded for friendliness.
- A failure says what broke, what it means, and what to do. Nothing else.
- No element explains what ferrum is. The operator installed it.
- The voice is `.claude/skills/humanize` plus the installed `humanizer` skill.

## How to tell if a render is right

1. Open the healthy dashboard. Is it mostly empty?
2. Count the tinted colour blocks at rest. More than zero is probably wrong.
3. Open Prowlarr's page. Does it offer to change anything that would break it?
4. Read every sentence aloud. Would you say it to someone standing next to you?
