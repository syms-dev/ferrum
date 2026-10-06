# The landscape, and an honest reading of ferrum's uniqueness claim

> Surveyed 2026-10-06 across four parallel research lanes. Repository metrics pulled live from the
> GitHub API that day. **The session's web-search budget was exhausted**, so late findings lean on
> direct documentation and API fetches, and the "new 2025–26 projects" slice is GitHub-search-only
> and will under-count anything with a landing page and little GitHub traction. Re-run that slice
> before treating this as complete.

## The headline: "nobody else has atomic closure+state rollback" is wrong as worded

This is the most valuable thing the survey produced, and it needs to change before anyone outside
the project reads the claim.

**It has shipped before, to millions of machines, and it ships today in three narrower forms.**

- **Ubuntu ZSys (2019–2024) did the thing.** It snapshotted system datasets and per-user
  `USERDATA` datasets under the *same snapshot ID*, and GRUB offered two literal menu entries:
  *"Revert system only"* and **"Revert system and user data"**. One bootloader choice, one
  transaction, boot. Canonical even named ferrum's own motivating failure mode: *"you are taking the
  risk of reverting to older version of some softwares not being forward-compatible with your user
  data"*. **It is dead** — removed from Ubuntu 25.10 after its own author filed
  [Launchpad #2109962](https://bugs.launchpad.net/ubuntu/+source/zsys/+bug/2109962) (2025-05-05)
  asking for its removal, *"unmaintained for many years"*. Killed by GRUB's weak ZFS support and
  two-pool complexity, **not because the idea failed**.
- **TrueNAS CE ships it today as a checkbox.** Its app Roll Back dialog *"reverts both the
  application and app data stored in the apps pool to the exact state from when the snapshot was
  created"* — with the caveat that it *"only affects data saved in the apps dataset… **Data in
  mounted host paths is not rolled back**."* TrueNAS also deliberately decouples this from the OS:
  *"Boot environments do not preserve or restore the state of any attached storage pools or apps."*
- **Start9 StartOS 0.4.0** (2026-07-24) moved to btrfs specifically so *"every service install and
  update takes a snapshot first, so a failed update rolls back instead of stranding you"*. Failure
  path only; a user-initiated downgrade is *refused* when the older version cannot take the data.
- **YunoHost** auto-restores app and data when an upgrade script fails — failure path only, and it
  deliberately excludes large app data.
- **The one to actually watch: Red Hat's `snapm` + `boom`.** `snapm snapset create --bootable
  --revert` builds a *coordinated snapshot set* across `/` and `/var` "managed as a single unit",
  with a GRUB revert entry — and `dnf-plugin-snapm` is proposed to fire it on **every package
  transaction**. Fedora Change targeted at **Fedora 45**, last modified 2025-11-05. That is ferrum's
  headline feature, from Red Hat, triggered by the package manager, in a mainstream distro.

### What *is* defensible, and should be the claim from now on

> **The only system that does it for the whole machine, operator-initiated, at any generation,
> including host-path data.**

Every piece of prior art fails at least one clause:

| Prior art | Fails on |
|---|---|
| ZSys | dead; system + *user* data, not service state; no app awareness |
| TrueNAS | per-app, not the system closure; **excludes host paths**, which is where every homelab keeps config; decoupled from the OS version |
| StartOS | failure-path undo only; a user downgrade is refused when data cannot migrate backwards |
| YunoHost | failure-path only; large data excluded; demonstrably fragile in 2026 forum reports |
| snapm/boom | not shipped; no application quiesce; revert is per-mount |
| ZFS/FreeBSD boot environments | manual, opt-in, not update-keyed; every doc recommends against it |

**Cite TrueNAS and ZSys ourselves.** Being the project that knows the prior art is a far stronger
position than being the project that claimed a first and got corrected in a comment thread.

> **Verification note.** The TrueNAS quotations were fetched directly by the surveying lane on
> 2026-10-06 from `apps.truenas.com/managing-apps/managing-installed-apps/`. I could not
> independently re-verify them — the web-search budget was spent and that documentation has
> restructured — so **treat them as reported-not-confirmed until someone opens the page**. Given
> what this exercise found about our own unchecked claims, that distinction is the point.

## Two hard technical objections — both already answered in ferrum's code

These are the strongest engineering criticisms the survey raised. I checked both against the
implementation rather than reasoning about them, and ferrum already does the right thing.

**1. btrfs has exactly one default subvolume per filesystem.** snapper's rollback *is*
`btrfs subvolume set-default`, which is why snapper's maintainer says multi-subvolume atomic
rollback needs btrfs support that *"will not happen"*, and why openSUSE's own documentation says
`/var` *"cannot be rolled back"*. Any design that reverts by setting a default subvolume can revert
root **or** data, never both.

**ferrum does not use `set-default`.** `crates/ferrum-apply/src/restore_state.rs` performs a
validated snapshot-and-rename swap through an intermediate `@state.restoring` subvolume. That is
structurally the same escape ZSys took on ZFS — clone and switch rather than roll back in place —
and it sidesteps the single-default-subvolume constraint entirely.

**2. Crash-consistent is not application-consistent.** A btrfs snapshot of a live SQLite volume is a
crash image. This is the objection a NixOS core contributor raised when someone asked for exactly
ferrum's feature on Discourse: *"You still need to put your database in backup mode… since there is
no generic way to ensure this happens, you can't build a generic snapshot tool."*

**ferrum stops `ferrum-apps.target` before snapshotting and records `quiesced: true` on the journal
entry** (`apply.rs:479`, `journal.rs:38`). The survey's own conclusion is that this — not the
snapshot — is the defensible moat, and it is already built. **It should be a demo, not a bullet.**

## The gap nobody fills

Not "atomic rollback" alone. It is the conjunction, and the conjunction is genuinely empty:

> An operator with their own domain, mismatched disks and no NixOS experience, who wants a media
> stack that is SSO'd, publicly reachable on real certificates, pooled, and genuinely undoable, is
> currently served by nobody.

They get Cosmos (no rollback, and a Commons Clause licence), TrueNAS (rollback, but no DNS or SSO
and host paths excluded), SelfHostBlocks (everything except rollback and a UI), or ElfHosted
(someone else's hardware).

Two corrections to ferrum's assumptions about its own differentiators:

- **SSO is less unserved than assumed.** YunoHost, Cosmos, SelfHostBlocks, Deployrr, HomelabOS and
  ansible-hms-docker all wire it. It is table stakes, not a moat.
- **DNS *record creation* is the genuinely unserved axis.** Nearly everything either hands you a
  copy-paste snippet or updates a record you made by hand. Creating the records through the
  provider's API is rare.
- **Storage pooling is nearly extinct in installers** — only Cosmos (mergerfs with parity) and the
  dead Cloudbox. Ansible-NAS says outright that it *"doesn't set up disk partitions."*

## The five closest threats

**1. SelfHostBlocks + Skarabox** (ibizaman, AGPL-3.0, 507★ and 102★, both pushed 2026-10-06). A
headless NixOS installer built on **nixos-anywhere + disko + sops-nix**, x86_64 and aarch64, plus
NixOS modules with automatic reverse proxy, Let's Encrypt, **Authelia + LLDAP SSO**, Jellyfin and
the \*arrs, with full VM test coverage. That is ferrum's install story, TLS story and SSO story,
already shipped, by one developer. It lacks a control plane and any closure+state rollback — **and
it is funded to close the first gap**, with an NLnet grant *"SelfHostBlocks Onboarding"* that began
2026-08 explicitly to *"lower the bar to self-hosting"*. **The biggest threat in the survey, and
accelerating.**

**2. TrueNAS CE (+ HexOS).** The only shipping product with real version+state rollback, ZFS
pooling, a mature UI and a company behind it. Not fatal: the rollback is per-app, excludes host
paths, is decoupled from the boot environment, and TrueNAS does no DNS automation and no app SSO.
HexOS has visibly cooled — 1.0 shipped 2026-04-21, and a 2026-07-06 check-in found development
*"slower and less visible than many early users expected"*.

**3. Start9 StartOS.** MIT, 2.0k★, a ground-up 0.4.0 rewrite shipped 2026-07-24. Has the
snapshot-before-update primitive in production and real certificates for your own domain. **You add
DNS records at your registrar by hand**; no SSO; no pooling; marketplace is sovereignty-flavoured
rather than media-first. Directionally the most likely party to generalise its primitive into
ferrum's exact claim.

**4. Clan (clan.lol).** The NixOS fleet framework — peer-to-peer, built on nixos-anywhere, disko and
sops-nix, with a `clan.core.state` primitive and weekly changelogs through 2026. No media stack, no
DNS automation, no generation-keyed state rollback. **If Clan ever wires `clan.core.state` to a
per-generation snapshot it becomes threat number one overnight**, and it would arrive with the Nix
community's distribution behind it.

**5. Cosmos Cloud** (6.2k★). The only project outside ferrum combining automatic Let's Encrypt,
wildcard DNS-01 across all lego providers, its own built-in identity provider with MFA and OIDC,
**mergerfs pooling with parity**, and encrypted incremental backups — in one binary. Not NixOS, no
closure rollback, and **Apache-2.0 + Commons Clause**, which is source-available, not open source,
and bars selling it. The threat is positional: it is the comparison a prospective ferrum user will
actually make.

Also worth knowing: **Deployrr** (820★, TUI installer, 160+ apps, wires Authelia/Authentik/TinyAuth
for you) is the strongest direct competitor to a "does the toil for you" positioning. **Runtipi**
(9.7k★) has the best app-level rollback in the field — it tars app data, the compose definition and
user config into one archive, automatically, with the container stopped, before every update.
**community-scripts/ProxmoxVE** (29.7k★) gets accidental per-app OS+data rollback for free, because
one LXC per app means Proxmox's own snapshot covers both.

## nixarr — our nearest neighbour, audited at source

Worth its own section, because it is the project most likely to make a NixOS user decide ferrum is
unnecessary. Audited by cloning `nix-media-server/nixarr` at commit `0f960a2` (2026-09-22) and
reading the module source. 431 stars, GPL-3.0, created 2024-02-21, **zero releases and zero tags
ever** — consumption is off `main`, and `CHANGELOG.md`'s top section is still "Unreleased".

**It does not ship closure+state rollback, and it never tried.** Grepping the entire repository for
snapshot, btrfs, zfs, rollback and mergerfs returns **two hits**, both in the secrets documentation,
both caveats that a NixOS rollback will *not* restore secrets. Its state model is the inverse of
ferrum's: state is concentrated in `/data/.state/nixarr/*` and you are told to back it up yourself.
Roll back a generation there and you get **yesterday's Sonarr binary against today's `sonarr.db`** —
precisely the version-skew hazard ferrum exists to eliminate.

Where it is at **parity** with ferrum, and ferrum should stop claiming otherwise:

- **TLS on your own domain.** Every service has an `expose.https` block configuring an nginx vhost
  with `enableACME = true` — real Let's Encrypt via HTTP-01. (An earlier draft of this survey said
  nixarr had no TLS; that came from website copy and the source contradicts it.)
- **VPN architecture is the same idea** — a WireGuard network namespace via `VPN-Confinement`, with a
  firewall and DNS-leak kill switch, opted into per service. Treat as parity, not an advantage.
- **x86_64 and aarch64** both supported.
- **A broader app list than ferrum's** — a superset including Lidarr, Bazarr, Whisparr, Jellyseerr,
  Audiobookshelf, Komga, Autobrr and Recyclarr.
- **Declarative inter-app wiring**: Prowlarr indexers and applications, \*arr download clients and
  Bazarr connections, all expressed in Nix. ferrum achieves the same outcome through
  `crates/ferrum-reconcile`, which registers download clients and Prowlarr applications at runtime.
  Different mechanism, same promise — **so "no hand-editing config files" is not a line ferrum owns
  on this axis**, and we should expect to be compared on it.

Where ferrum is genuinely different:

- **nixarr does not install the OS.** It is a flake input and a NixOS module; you must already run
  NixOS and have already partitioned. ferrum converts a bare machine over SSH. **This is the
  structural difference.**
- **No DNS record creation** — two dynamic-DNS providers (Njalla and 1984) that update a hostname you
  made by hand. No Cloudflare, no zone management.
- **No SSO at all.** Zero references to Authelia, Authentik, OIDC or forward-auth. Authentication is
  handed back to each app, with the warning *"Do not enable this without setting up Jellyfin
  authentication through localhost first!"*
- **No storage pooling, no web UI, no control plane, no job system, no audit log.**

Activity is maintenance cadence, not a race: five commits in the last eight weeks, and `flake.nix`
still pins nixpkgs to `nixos-25.11` while 26.05 is current. Bus factor approximately one.

**The risk is not that nixarr ships the rollback — the source says it never tried. It is that a user
already running NixOS decides nixarr is close enough and stops looking.** ferrum's answer has to be
the install path and the rollback, not the app list, because on the app list nixarr wins.

## Is anyone else building this on NixOS?

Shape-wise yes, substance-wise no. Two
people are independently building ferrum's exact *shape* right now — **YoLab** (NixOS installer ISO
plus web UI, per-app subdomain and TLS, 1,404 commits, **0 stars**) and **imperfect-homelab** (NixOS
installer ISO and configurator, explicitly a nod to Perfect Media Server, **0 stars**). Pre-traction
both, but confirmation the gap is visible to others.

**And the NixOS community has looked straight at ferrum's headline feature and concluded it is
unsolved.** The Discourse thread *"Rolling back data as well, not only Nix config"* (opened
2025-04-17, live into 2026) poses the exact scenario, and the answer was *"I haven't seen any
projects attempt this."* Supporting evidence that it is structurally unsolved upstream: nixpkgs
#273972 *"NixOS: declare all state locations"* has been open since 2023-12-13 — **NixOS cannot even
enumerate where its services keep state** — and RFC 155 *"NixOS Migrations"* closed in 2025 without
acceptance.

**One assumption to correct: impermanence is the inverse of ferrum's feature, not adjacent to it.**
It rolls `/` back to a fixed empty snapshot identical for every generation, and `/persist` exists
precisely to *exempt* app data from the wipe. Do not let anyone frame ferrum as "impermanence but
nicer."

## The immutable-OS world refuses to do this, in writing

Useful ammunition, because it means ferrum's design is contrarian rather than merely unbuilt.

**bootc**, verbatim: *"`/var` has arbitrarily large data (system logs, databases, etc.). **It would
also not be expected to be rolled back if the operating system state is rolled back.** A simple
example is that an `apt|dnf downgrade postgresql` should not affect the physical database… Similarly,
a bootc update or rollback should not affect this application data."* ostree: *"**OSTree does not
touch the contents of `/var`.**"* `bootc rollback` is literally a bootloader reordering.

**ZFSBootMenu** argues against the feature by name: *"recovering from a bad system update is
generally not expected to discard user email or recent database transactions."* **Kubernetes cannot
do it at all** — the PVC-rollback issue was closed as not planned, and CSI cannot revert a PVC in
place.

So the honest framing is not "we invented this." It is **"everyone else decided the two layers
should not be coupled, and for a media server that decision is wrong"** — because a Sonarr database
that migrated forward is exactly the thing that makes a rollback useless.

## Momentum — weight last-commit over stars in this market

**Growing:** SelfHostBlocks + Skarabox · Clan · Runtipi · Start9 · Umbrel (umbrelOS 2.0, 2026-09-22)
· community-scripts/ProxmoxVE · nixarr.

**Cooling:** HexOS · Ansible-NAS (last real commit 2025-05-13; newer activity is Dependabot against
the docs site's npm dependencies — a `pushed_at` trap) · MediaStack.guide · Geek Cookbook.

**Dead:** PlexGuide/PGBlitz (the organisation itself 404s; real development stopped 2024-09) ·
Cloudbox (archived) · Buildarr · htpc-download-box · **CasaOS** (37,281★ but last stable release
2024-12-19 — *that star count is a tombstone*; IceWhale moved to ZimaOS) · **Ubuntu ZSys** ·
nixos-generators (archived 2026-01-30, upstreamed).

**Licence hygiene is poor across the field and is a real differentiator.** MediaStack.guide (1,842★)
and htpc-download-box (2,144★) ship with no licence file at all; Umbrel is PolyForm Noncommercial;
Cosmos is Commons Clause; ZimaOS has no LICENSE despite "Open" branding; Unraid, HexOS and Easypanel
are proprietary. **Fully permissive, commercially-safe options are thinner than the star counts
suggest**, and ferrum's Apache-2.0 is worth more than it looks.

## What to do with this

1. **Reword the headline claim before anyone else reads it**, to the scoped version above, and cite
   TrueNAS and ZSys ourselves.
2. **Make quiescing the demo.** It is the defensible moat, it is already built, and it is the exact
   objection a NixOS core contributor raised against the whole idea.
3. **Make host-path coverage a demo too.** TrueNAS's rollback is largely hollow in practice
   *because* it excludes bind-mounted host paths, which is where homelabbers keep everything.
4. **Watch two funded efforts**: SelfHostBlocks' onboarding grant, and `snapm` landing in Fedora 45.
   They are aimed at ferrum's two differentiators.
5. **Look at Apple's US10509646B2** (filed 2017, expires 2037) before the claim goes on a marketing
   page. It covers snapshot-before-update-and-restore-on-failure, scoped to OS and filesystem-volume
   updates rather than application state — so probably not a problem, but someone should actually
   read it.

## Gaps in this survey

Reddit, Hacker News and Lemmy were never searched — the budget was exhausted early. ElfHosted's SSO
technology is undisclosed since its charts repositories were pulled. Deployrr's backup scope is
unverified and it is the strongest direct competitor found. Whether TrueNAS snapshots at install
time or update time is undocumented and worth a direct test.
