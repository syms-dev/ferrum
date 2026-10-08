# Phase 1.7b — the stack sets itself up

**Status:** requirements settled 2026-09-21. **OQ1–OQ4 are all answered by the owner, inline
below.** Not yet through the planning review gate; no implementation until that runs, and not
until the Phase 1.7 R1 pipeline run finishes (one run per checkout).

## Why this exists

Phase 1.7 (`2026-09-19-phase-1-7-hands-off-gaps-design.md`) covers the gaps between *installed* and
*hands off* at the infrastructure layer: DNS, credentials, certificates, storage. This spec covers
the layer above it — the applications are installed, published, authenticated and wired to each
other, and the operator still has to open four web UIs and configure them.

The owner named these after using the running host:

> Have the downloads etc. already been setup? [...] Do we have autoscan enabled so that the media
> is automatically detected? Do we have torrent healing so that they don't seed infinitely. Do we
> have the thing with Plex automatically set up the LAN Networks and Custom server access URLs?
> I'd like to take away as much of the manual initial setup as possible.

What was verified in the code on 2026-09-21, so the scope below is grounded rather than assumed:

| Concern | State | Evidence |
|---|---|---|
| Downloads land in one tree and import by hardlink | **done** | TRaSH layout in `modules/core/storage.nix`; `set_download_path` in `crates/ferrum-reconcile/src/main.rs:330`; shared `/data` root so links cannot cross a filesystem |
| Prowlarr → Sonarr/Radarr, clients → every *arr | **done** | `register_application` / `register_download_client`, derived from the catalog |
| Plex claimed, libraries created | **done** | `reconcile_plex`, `create_plex_library` |
| qBittorrent behind WireGuard with a kill switch | **done** | `modules/apps/qbittorrent/service.nix` |
| **Media appears without asking** | **missing** | nothing calls a Plex scan; `library/sections` is only ever listed or created |
| **Seeding ever stops** | **missing** | the only qBittorrent preferences ferrum sets are `save_path` and `temp_path` |
| **Plex knows how it is reached** | **missing** | claim and libraries only; no connection or network preferences |
| **Prowlarr has any indexer** | **missing** | Prowlarr is wired to everything and ships empty, so the stack finds nothing |

The standing test applies unchanged: *from a bare machine, does the operator reach a working system
without being told to do anything by hand?* Today the answer is no, for four reasons.

---

## R9 — media appears in Plex without anyone asking it to

**User story.** Sonarr imports an episode. It is in Plex by the time I look, and I never configured
a scan.

**Why this is not optional.** ferrum creates the libraries and then never speaks to Plex again. A
library with no scan trigger updates whenever Plex next decides to look, which on a default install
means the operator watches an empty library after a successful download and concludes the stack is
broken. Plex's own filesystem watching is unreliable on network and union filesystems — and ferrum
mounts `/data` through mergerfs (`modules/core/pool.nix`), which is exactly that case.

**Acceptance criteria.**
- A1. On import or upgrade, the *arr notifies ferrum, and ferrum issues a **targeted** section
  refresh for the affected directory — not a whole-library scan. A full scan of a large library on
  every episode is its own failure mode.
- A2. **The operator configures nothing.** The webhook is registered by the reconciler from the
  catalog, the same way download clients and applications already are. An instruction to "add a
  Connect entry in Sonarr" is the failure this requirement exists to remove.
- A3. It is idempotent and debounced. A season pack fires one webhook per file; that must collapse
  into one scan per directory per short window.
- A4. **A scan failure never fails an import.** If Plex is unclaimed, restarting or unreachable,
  ferrum logs it and the media is still imported. The library is a cache of the filesystem, not the
  other way around.
- A5. Jellyfin gets the same treatment when enabled, through its own API. Whatever the mechanism,
  the operator configures nothing there either.
- A6. The receiving endpoint is not an attack surface: it binds locally, it is not published
  through nginx, and it accepts only the shape the *arr sends.

**Design note.** `ferrumd` already runs, already holds the catalog, and already knows each app's
base URL and secrets. It is the natural home for the receiver; a new service would be a second
thing to supervise for no gain.

---

## R10 — torrents stop seeding, without destroying the library

**User story.** I do not run out of disk because every torrent I have ever grabbed is still
seeding, and nothing I have watched disappears.

**Why this is not optional.** ferrum sets exactly two qBittorrent preferences, both paths. There is
no ratio limit, no seed-time limit and no removal rule anywhere in the repo, so **seeding is
unbounded by construction**. The disk fills, and the first symptom is an import failing for a
reason that has nothing to do with the import.

**Why it is delicate.** The import is a **hardlink**: the file in `/data/torrents` and the file in
`/data/media` are the same bytes. That makes the obvious fix dangerous in one direction and safe in
another, and the difference must be explicit in the implementation rather than discovered:
- removing a torrent *and its files* after the *arr has imported it only drops one link — the
  library copy survives, and the space is genuinely reclaimed;
- removing it *before* the import completes destroys the download.
So removal must be conditioned on the import having happened, never on the torrent alone.

**Acceptance criteria.**
- A1. qBittorrent enforces a share-ratio limit **and** a seeding-time limit, whichever is reached
  first, set through the same `setPreferences` seam that already sets the paths.
- A2. The limit action **pauses**; it does not delete. Deletion is the *arr's decision, because only
  the *arr knows whether the item was imported.
- A3. Completed, imported, paused items are removed with their files, reclaiming the download-side
  link. An item that failed to import is left alone and surfaced, never silently deleted.
- A4. Both limits are options with stated defaults, not constants. A private tracker can require a
  ratio or a seed time ferrum's default would violate, and an operator who gets banned by their
  tracker because of a default is a serious failure.
- A5. Nothing in this requirement may delete a file that is not hardlinked into the library. If the
  import copied rather than linked (a cross-filesystem misconfiguration), the safe behaviour is to
  leave it and report.
- A6. The defaults are stated in the UI where the operator can see them, not only in a Nix option.

---

## R11 — Plex knows how it is reached

**User story.** Plex clients connect over my domain with a real certificate, LAN clients are not
throttled, and I never opened port 32400.

**Why this is not optional.** ferrum publishes `plex.<domain>` through nginx with a Let's Encrypt
certificate, and then leaves Plex believing it is an unconfigured server on a LAN. Three
consequences, all of which the operator has to diagnose themselves:
- Plex advertises no working remote connection, so clients fall back to Plex's relay or fail.
- Every connection arrives from nginx **on the same host**, so without the proxy declared as local
  Plex can misjudge who is local and apply the wrong bandwidth policy.
- Plex's own Remote Access tries to forward port 32400 through the router — which is precisely the
  job the reverse proxy already does, and a second, worse path to the same server.

The owner reached the same conclusion independently: *"I don't think we need Remote Access if it's
setup this way?"* That is correct, and it is the requirement.

**Acceptance criteria.**
- A1. Plex is given a custom connection URL of `https://plex.<baseDomain>` so clients discover the
  published path.
- A2. The LAN networks list includes the local subnet and the proxy, so local clients are treated
  as local.
- A3. Remote Access is **off**. The proxy is the remote access, and two mechanisms for one job is
  how a working system develops an intermittent fault.
- A4. Preferences are set through **Plex's own API** (`PUT /:/prefs`), never by editing
  `Preferences.xml` underneath a running server, which rewrites the file and would race the edit.
- A5. Idempotent, and **ownership-aware in the same sense as R1/A3**: a preference the operator has
  deliberately changed is not stamped back on every apply. Reconciling is not enforcing.
- A6. This runs after the claim, because an unclaimed server has no token to authorise the calls,
  and it must degrade cleanly when the claim has not happened yet.

**Verification required before implementation.** The exact preference keys
(`customConnections`, the LAN networks key, the WAN-as-LAN key, the Remote Access key) are asserted
from memory in this document and **must be read off the running host's `Preferences.xml` and Plex's
`GET /:/prefs` output before any code writes them.** Writing a misspelled preference key is silent:
Plex accepts it and nothing happens.

---

## R12 — Prowlarr ships with working indexers

**User story.** Sonarr can find an episode on the day I install ferrum, without me hunting for
indexers first.

**Why this is not optional.** Prowlarr is registered with every *arr and every download client, and
contains **zero indexers**. Every other piece of the chain is wired, so the whole stack is inert for
the one reason an operator is least likely to guess is deliberate.

**Owner decision.** Seed public indexers automatically; private trackers stay manual, because they
need the operator's own account and credentials belong in neither a prompt nor a default.

**Acceptance criteria.**
- A1. A set of public, no-credential indexers is added to Prowlarr on first reconcile, built from
  Prowlarr's own `GET /api/v1/indexer/schema` rather than hand-written definitions that rot when
  Prowlarr updates.
- A2. Idempotent by indexer name, like every other reconcile operation.
- A3. **An indexer the operator deletes is not re-added.** This is the same ownership problem as
  R1/A4 for DNS records, and it gets the same answer: ferrum tracks what it created and never
  resurrects a deliberate removal. Getting this wrong makes ferrum fight its own operator once a
  week, which is worse than shipping no indexers at all.
- A4. A failing indexer does not fail the reconcile. Public indexers go down; that is their nature.
- A5. Private trackers remain the operator's own action, and the UI says so rather than leaving the
  absence to be inferred.

---

## Open questions — all answered

- **OQ1 (R10) — ANSWERED: ratio 2.0 or 14 days, whichever comes first, and both stay
  configurable.** Neither value is a constant in the code; both are `ferrum.*` options with these
  defaults, and A6 still requires the effective values to be visible in the UI rather than only in
  a Nix file. The owner's emphasis was on configurability: a private tracker can demand a ratio or
  a seed time that would get an operator banned, and ferrum must never make that choice
  unchangeable.
- **OQ2 (R12) — ANSWERED: a small, conservative default set.** The selection criterion is
  mechanical rather than editorial, so it does not rot and ferrum is not in the business of
  recommending trackers: seed only definitions that Prowlarr's own
  `GET /api/v1/indexer/schema` reports as public and that require no credential field. The default
  list is a `ferrum.*` option with a short default, so an operator changes it without touching
  code, and A3's ownership rule still means a deleted indexer is never resurrected.
- **OQ3 (R9) — ANSWERED: yes, scan on delete too.** An upgrade replaces a file and the old entry
  lingers until Plex notices on its own; an entry that plays nothing is as visible a fault as a
  missing one, and it is the same mechanism and the same targeted refresh.
- **OQ4 (R11) — ANSWERED: leave Plex's relay alone for now.** Revisit once R1 (DNS) is proven
  against a real zone. The relay is the fallback that makes a broken remote connection look merely
  slow, which is a genuine diagnostic cost — but disabling it before DNS is known-good removes the
  only working path for anyone whose records are not yet right. Sequence matters more than the
  end state here.

---

## Out of scope

- Split-horizon DNS / NAT hairpin (already stated out of scope in Phase 1.7 R1/A6).
- Usenet provider accounts, exactly as with private trackers: credentials are the operator's.
- Quality profiles and custom formats. TRaSH publishes opinionated profiles and syncing them is a
  real feature, but it is a larger decision about how opinionated ferrum should be, and it is not
  what blocks a working first install.
- Transcoding, hardware acceleration, and tuning.
