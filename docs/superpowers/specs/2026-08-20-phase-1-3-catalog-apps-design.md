# Phase 1.3 — Remaining Catalog Apps Design

## Context

Phase 1.1 built the uniform app-submodule mechanism (`modules/lib/app-submodule.nix`) and proved it with one app, Sonarr (`modules/apps/sonarr/`). Phase 1.2 built and merged the rollback engine. This phase adds the rest of the Phase 1 catalog: Radarr, Prowlarr, qBittorrent, SABnzbd, Jellyfin, Plex — six apps, following Sonarr's exact pattern.

Full background: `docs/design/2026-08-19-phase-1-design.md`. This document only covers what's new or app-specific for this phase; it doesn't re-derive the uniform-submodule mechanism, the storage layout, or the rollback engine, all of which are already built and unchanged by this work.

## Scope

**In scope:** six new `modules/apps/<id>/{meta.nix,service.nix}` pairs, each following Sonarr's established pattern (uniform submodule instantiation, `mediaGroup` membership when `mediaAccess != "none"`, wired under `ferrum-apps.target` with `wantedBy`/`partOf`/`unitConfig.ConditionPathExists`), plus one new option (`ferrum.apps.plex.claimToken`) and its systemd wiring.

**Explicitly out of scope**, matching the original plan's own phase boundaries and confirmed during this design's brainstorm:

- **Jackett, NZBHydra2** — Prowlarr is the modern unified replacement for both; add either later only if a specific indexer setup actually needs it.
- **The reconciler** (Phase 1.4) — `integrations.providesTo`/`consumes` metadata gets populated correctly by each app's `meta.nix`, but nothing in this phase acts on it. Cross-app API-key registration is Phase 1.4's job.
- **`ferrum.secrets`/sops wiring** (Phase 1.4) — apps generate their own credentials on first start, same as Sonarr does today.
- **The proxy/auth layer actually enforcing `authBypassPaths`/`exposure`** (Phase 1.4) — nginx and Authelia don't exist yet. This phase declares the metadata correctly so 1.4 has it ready; nothing routes through a real reverse proxy yet.
- **The web UI** (Phase 1.5), including the "slick input box" for Plex's claim token — this phase only builds the option and systemd mechanism underneath it.
- **Per-app VM tests** — `checks.catalog-consistency` and `checks.schema-uniformity` already guard structural correctness (every catalog entry has both `meta.nix` and `service.nix`, every option stays JSON-expressible). Real boot/health-check verification for each app happens once the daemon (1.5) exercises it for real, or in a later dedicated hardening pass — not six new KVM-boot VM tests in this phase.
- **Multi-drive storage, NAS-mounted media (NFS/SMB), and cloud-backed storage (rclone to a Hetzner Storage Box, Backblaze B2, etc.)** — raised during this design's brainstorm and confirmed to be its own future phase, matching the original plan's explicit "the rclone/mergerfs cloud tier (its own later phase)" scoping. Not touched here. This phase assumes the storage layout Phase 1.1/1.2 already built (a single btrfs pool with `@state`/`@snapshots`/`@media` as established subvolumes).

## The Six Apps

| App | nixpkgs module | mediaAccess | authBypassPaths | Notes |
|---|---|---|---|---|
| Radarr | `services.radarr` (servarr framework, same module directory as Sonarr) | `readwrite` | `/api`, `/feed`, `/ping` | Near-identical to Sonarr — same framework, same API-key-in-`environmentFiles` pattern once secrets land in 1.4. |
| Prowlarr | `services.prowlarr` (servarr framework) | `none` | `/api`, `/ping` | Indexer manager — never touches media files directly, so no media group membership. `integrations.consumes` will eventually list every app it needs to register indexers into. |
| qBittorrent | `services.qbittorrent` | `readwrite` | none needed | WebUI has its own auth (not forward-auth-bypassable the same way); `serverConfig` (a freeform attrset the module already exposes) can set WebUI credentials declaratively once 1.4 wires secrets in. |
| SABnzbd | `services.sabnzbd` | `readwrite` | none needed | **Known gap for Phase 1.4, not this phase**: the module only exposes `configFile` (a path), not inline declarative settings the way servarr's `.settings` attrset does — SABnzbd's own API key lives in an INI file the module doesn't manage. Phase 1.4's reconciler will need to either write that file directly or find another route; noting it now so it isn't a surprise later. |
| Jellyfin | `services.jellyfin` | `read` | native-client paths (exact set determined during implementation — Jellyfin's own clients need unauthenticated access to specific API routes to function, matching the existing app-submodule.nix comment: "apps that cannot follow an auth redirect") | No external account/claim step. |
| Plex | `services.plex` | `read` | native-client paths (same reasoning as Jellyfin) | See claim-token mechanism below — the one genuinely novel piece of this phase. |

Each app's `meta.nix` also needs `category`, `summary`, `defaultPort`, `defaultSubdomain`, `healthCheck` (path/expectStatus/timeoutSec, matching Sonarr's `/ping` pattern — exact health-check endpoint varies per app and gets determined during implementation, e.g. qBittorrent's API has its own status endpoint, Jellyfin has `/health`), and `docsUrl`/`iconSlug`, all following Sonarr's `meta.nix` as the template.

## Plex Claim-Token Mechanism

Plex's NixOS module (`services.plex`) has no claim-token or API-key option — confirmed by reading the module directly. Plex's claim token is fundamentally different from a servarr API key: it's short-lived (~4 minutes), single-use, and can only be generated by an authenticated `plex.tv` session, by design (Plex deliberately prevents claiming a server without proving account ownership).

Two mechanisms were considered:

1. **Automated** (rejected): store a long-lived Plex.tv API token via `ferrum.secrets`, and have a startup script call Plex's account API to fetch a fresh claim token automatically before every start. Fully hands-off, but depends on an unofficial (if long-stable, community-relied-upon) Plex.tv API endpoint rather than anything Plex documents or the NixOS module exposes.
2. **Manual paste** (chosen): a new option, `ferrum.apps.plex.claimToken` (`types.str`, default `""`) — JSON-expressible, satisfies `checks.schema-uniformity` since it's a plain string, not a real secret in the `ferrum.secrets`/sops sense (a token that's already worthless within minutes of being generated doesn't need write-only secret storage). The operator visits `plex.tv/claim` once, pastes the token into settings within its validity window, and `ferrum-apply apply` picks it up.

**Implementation:**
- `modules/apps/plex/service.nix` sets `systemd.services.plex.environment.PLEX_CLAIM = app.claimToken;`, conditional on it being non-empty (`lib.mkIf (app.claimToken != "")` on that one line, not the whole service — an already-claimed server should keep running fine with an empty/stale token present).
- Once the token is consumed (Plex claims itself on that start), it's inert on every subsequent start — no cleanup needed, no risk in it lingering in `settings.json` history.
- Phase 1.5's UI need only render a text input bound to this one option — "the slick input box" is a UI-layer concern with no new mechanism underneath it.

## Verification

- `checks.catalog-consistency` — every new `modules/apps/<id>/` directory has both `meta.nix` and `service.nix`, and every catalog entry (from `meta.nix`) has a matching module.
- `checks.schema-uniformity` — every new option (including `plex.claimToken`) stays JSON-expressible.
- `checks.eval-example-hosts` — the example host(s) evaluate cleanly with the new apps enabled (at least one example host should enable a representative subset, e.g. Radarr + qBittorrent + Jellyfin, to catch cross-app eval issues like the `mediaGroup`/`authBypassPaths` wiring actually working, without needing to enable all eight — sorry, six — apps everywhere).
- Real KVM verification on `ferrum-dev` (per [[reference-ferrum-dev-vm]]) for each app's `nix build`/eval, matching the rigor applied to every prior phase in this project — but no new VM *test* files, per the scope decision above.

## Open Items for Future Phases

Carried forward from this design's brainstorm, not solved here:

- **DNS record automation** (Phase 1.4): Cloudflare `dnsProvider` is already wired for ACME DNS-01 validation, but that alone doesn't create the routing A/CNAME record pointing a subdomain at the box. Needs explicit design — likely the same Cloudflare API token used for ACME, extended to also manage routing records (or tunnel CNAMEs, see next item).
- **Cloudflare Tunnel as an exposure mechanism** (Phase 1.4): a real alternative/complement to direct nginx+ACME exposure for homelab hosts behind a home router (no port-forwarding, no exposed IP). NixOS has a mature `services.cloudflared` module. Composes naturally with the DNS-automation item above, since tunnel routing is also Cloudflare-API-driven.
- **Multi-drive / NAS / cloud storage** (its own future phase): local multi-disk expansion, NFS/SMB-mounted NAS storage, rclone-backed cloud remotes (Hetzner Storage Box, Backblaze B2, etc.), mergerfs pooling, and how any of that interacts with the *arr apps' hardlink-based import workflow (hardlinks don't cross network/cloud filesystems — non-local storage likely needs copy+delete import behavior instead, worth surfacing early in that phase's design).
- **SABnzbd's non-declarative config** (Phase 1.4): flagged in the app table above — its module only exposes a config file path, not inline settings, which the reconciler will need to work around.
