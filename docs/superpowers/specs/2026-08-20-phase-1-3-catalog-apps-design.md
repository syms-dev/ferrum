# Phase 1.3 — Remaining Catalog Apps Design

## Context

Phase 1.1 built the uniform app-submodule mechanism (`modules/lib/app-submodule.nix`) and proved it with one app, Sonarr (`modules/apps/sonarr/`). Phase 1.2 built and merged the rollback engine. This phase adds the rest of the Phase 1 catalog: Radarr, Prowlarr, qBittorrent, SABnzbd, Jellyfin, Plex — six apps, following Sonarr's exact pattern.

Full background: `docs/design/2026-08-19-phase-1-design.md`. This document only covers what's new or app-specific for this phase; it doesn't re-derive the uniform-submodule mechanism, the storage layout, or the rollback engine, all of which are already built and unchanged by this work.

## Scope

**In scope:** six new `modules/apps/<id>/{meta.nix,service.nix}` pairs, each following Sonarr's established pattern (uniform submodule instantiation, `mediaGroup` membership when `mediaAccess != "none"`, wired under `ferrum-apps.target` with `wantedBy`/`partOf`/`unitConfig.ConditionPathExists`); a new `settings.claimToken` key for Plex and its systemd wiring; and a VPN-gated network namespace for qBittorrent (`settings.vpnWireguardConfig`/`settings.vpnKillSwitch`), covered in its own section below.

**Explicitly out of scope**, matching the original plan's own phase boundaries and confirmed during this design's brainstorm:

- **Jackett, NZBHydra2** — Prowlarr is the modern unified replacement for both; add either later only if a specific indexer setup actually needs it.
- **The reconciler** (Phase 1.4) — `integrations.providesTo`/`consumes` metadata gets populated correctly by each app's `meta.nix`, but nothing in this phase acts on it. Cross-app API-key registration is Phase 1.4's job.
- **`ferrum.secrets`/sops wiring** (Phase 1.4) — apps generate their own credentials on first start, same as Sonarr does today. The one exception is qBittorrent's VPN WireGuard config, which genuinely needs to exist in this phase and is handled as flagged tech debt — see the qBittorrent VPN Kill Switch section below.
- **The proxy/auth layer actually enforcing `authBypassPaths`/`exposure`** (Phase 1.4) — nginx and Authelia don't exist yet. This phase declares the metadata correctly so 1.4 has it ready; nothing routes through a real reverse proxy yet.
- **The web UI** (Phase 1.5), including the "slick input box" for Plex's claim token — this phase only builds the option and systemd mechanism underneath it.
- **Per-app VM tests** — `checks.catalog-consistency` and `checks.schema-uniformity` already guard structural correctness (every catalog entry has both `meta.nix` and `service.nix`, every option stays JSON-expressible). Real boot/health-check verification for each app happens once the daemon (1.5) exercises it for real, or in a later dedicated hardening pass — not six new KVM-boot VM tests in this phase.
- **Multi-drive storage, NAS-mounted media (NFS/SMB), and cloud-backed storage (rclone to a Hetzner Storage Box, Backblaze B2, etc.)** — raised during this design's brainstorm and confirmed to be its own future phase, matching the original plan's explicit "the rclone/mergerfs cloud tier (its own later phase)" scoping. Not touched here. This phase assumes the storage layout Phase 1.1/1.2 already built (a single btrfs pool with `@state`/`@snapshots`/`@media` as established subvolumes).

## The Six Apps

| App | nixpkgs module | mediaAccess | authBypassPaths | Notes |
|---|---|---|---|---|
| Radarr | `services.radarr` (servarr framework, same module directory as Sonarr) | `readwrite` | `/api`, `/feed`, `/ping` | Near-identical to Sonarr — same framework, same API-key-in-`environmentFiles` pattern once secrets land in 1.4. |
| Prowlarr | `services.prowlarr` (servarr framework) | `none` | `/api`, `/ping` | Indexer manager — never touches media files directly, so no media group membership. `integrations.consumes` will eventually list every app it needs to register indexers into. |
| qBittorrent | `services.qbittorrent` | `readwrite` | none needed | WebUI has its own auth (not forward-auth-bypassable the same way); `serverConfig` (a freeform attrset the module already exposes) can set WebUI credentials declaratively once 1.4 wires secrets in. Runs inside a VPN-gated network namespace — see below. |
| SABnzbd | `services.sabnzbd` | `readwrite` | none needed | **Known gap for Phase 1.4, not this phase**: the module only exposes `configFile` (a path), not inline declarative settings the way servarr's `.settings` attrset does — SABnzbd's own API key lives in an INI file the module doesn't manage. Phase 1.4's reconciler will need to either write that file directly or find another route; noting it now so it isn't a surprise later. |
| Jellyfin | `services.jellyfin` | `read` | native-client paths (exact set determined during implementation — Jellyfin's own clients need unauthenticated access to specific API routes to function, matching the existing app-submodule.nix comment: "apps that cannot follow an auth redirect") | No external account/claim step. |
| Plex | `services.plex` | `read` | native-client paths (same reasoning as Jellyfin) | See claim-token mechanism below — the one genuinely novel piece of this phase. |

Each app's `meta.nix` also needs `category`, `summary`, `defaultPort`, `defaultSubdomain`, `healthCheck` (path/expectStatus/timeoutSec, matching Sonarr's `/ping` pattern — exact health-check endpoint varies per app and gets determined during implementation, e.g. qBittorrent's API has its own status endpoint, Jellyfin has `/health`), and `docsUrl`/`iconSlug`, all following Sonarr's `meta.nix` as the template.

## Plex Claim-Token Mechanism

Plex's NixOS module (`services.plex`) has no claim-token or API-key option — confirmed by reading the module directly. Plex's claim token is fundamentally different from a servarr API key: it's short-lived (~4 minutes), single-use, and can only be generated by an authenticated `plex.tv` session, by design (Plex deliberately prevents claiming a server without proving account ownership).

Two mechanisms were considered:

1. **Automated** (rejected): store a long-lived Plex.tv API token via `ferrum.secrets`, and have a startup script call Plex's account API to fetch a fresh claim token automatically before every start. Fully hands-off, but depends on an unofficial (if long-stable, community-relied-upon) Plex.tv API endpoint rather than anything Plex documents or the NixOS module exposes.
2. **Manual paste** (chosen): a new key in Plex's `app.settings` bag, `claimToken`, declared in `modules/apps/plex/meta.nix`'s `settingsSchema` (`{ type = "string"; default = ""; }`) exactly the way Sonarr's `meta.nix` already declares `urlBase` — **not** a new top-level option on the submodule. `modules/lib/app-submodule.nix`'s `settings` type is `attrsOf (oneOf [bool int str (listOf str)])`, deliberately uniform across every app; adding a Plex-only top-level option would break the one property that makes the self-rendering UI possible (one form definition for every app). The operator visits `plex.tv/claim` once, pastes the token into `ferrum.apps.plex.settings.claimToken` within its validity window, and `ferrum-apply apply` picks it up.

**Implementation:**
- `modules/apps/plex/service.nix` sets `systemd.services.plex.environment.PLEX_CLAIM = app.settings.claimToken or "";`, conditional on it being non-empty (`lib.mkIf ((app.settings.claimToken or "") != "")` on that one line, not the whole service — an already-claimed server should keep running fine with an empty/stale token present). Follows the exact `app.settings ? key && app.settings.key != ""` guard pattern Sonarr's `service.nix` already uses for `urlBase`.
- Once the token is consumed (Plex claims itself on that start), it's inert on every subsequent start — no cleanup needed, no risk in it lingering in `settings.json` history.
- Phase 1.5's UI need only render a text input bound to this one option — "the slick input box" is a UI-layer concern with no new mechanism underneath it.

## qBittorrent VPN Kill Switch

Torrent traffic must never leak onto the host's normal network path if the VPN tunnel is down — this is a real privacy/legal concern, not a nicety, and was a hard requirement carried over from how qBittorrent is run today (behind `qbittorrentvpn`/`gluetun` on Saltbox, both of which use kernel-level network isolation, not application-level tricks).

**Isolation mechanism: a dedicated network namespace, not application-level interface binding.** qBittorrent's own "bind to interface" setting was considered and rejected — it's simpler to build, but has known historical leak classes (DHT/UDP tracker traffic bypassing app-level binding in some qBittorrent versions), which is exactly why the wider self-hosted community moved to namespace/container-based isolation (gluetun, qbittorrentvpn) in the first place. A network namespace is kernel-enforced: the qBittorrent process has literally no route to anywhere except what exists inside its namespace, full stop — no app-level trust required.

**Mechanics:**
- A `qbt-vpn` network namespace, brought up by a new `systemd.services.qbt-vpn-netns-setup` oneshot unit (`RemainAfterExit = true`): creates the namespace, then runs `wg-quick up` *inside* it against the pasted WireGuard config (see below) — reusing `wg-quick`'s own handling of `Address`/`DNS`/routing rather than hand-parsing the config.
- `systemd.services.qbittorrent` joins that namespace via `serviceConfig.NetworkNamespacePath = "/var/run/netns/qbt-vpn"` (a real, documented systemd feature — no container runtime needed), ordered `after`/`requires`/`bindsTo` the setup unit so qBittorrent never starts with stale or absent networking.
- **Kill switch ON (default)**: the namespace contains *only* the WireGuard interface and loopback. If the tunnel drops, qBittorrent has zero route out — not "detected and cut," structurally incapable of leaking.
- **Kill switch OFF**: the setup unit additionally creates a veth pair back to the host's normal network, with the WireGuard route preferred and a small health-check step that only activates the veth's fallback route once the tunnel is confirmed down (exact health-check heuristic — WireGuard handshake latency vs. a ping probe — determined during implementation; the requirement is "explicit, confirmed-down fallback," not "both routes exist and something wins").

**New `app.settings` keys** (declared in `modules/apps/qbittorrent/meta.nix`'s `settingsSchema`, same mechanism as Plex's `claimToken` above — flat keys in the existing free-form bag, not new top-level submodule options; `settings`' type is `attrsOf (oneOf [bool int str (listOf str)])`, which has no nested-attrset case, so a dotted `vpn.killSwitch`-style option isn't expressible here regardless):
- `vpnWireguardConfig` (`string`, default `""`) — the whole `wg-quick`-format config, pasted verbatim (e.g. what ProtonVPN's dashboard generates for a given server). The entire VPN mechanism is `lib.mkIf ((app.settings.vpnWireguardConfig or "") != "")` — empty means qBittorrent runs on the host's normal network, no namespace at all.
- `vpnKillSwitch` (`boolean`, default `true`) — the ON/OFF toggle described above. Phase 1.5's UI renders this as the visible kill-switch control the operator can flip.

**Known tech debt, explicitly flagged, must be resolved before production use:** `vpnWireguardConfig` is a genuine long-lived secret — unlike Plex's claim token (worthless within 4 minutes regardless of exposure), a leaked WireGuard private key grants real ongoing VPN access. Storing it as a plain string option means it sits in `settings.json` unencrypted until Phase 1.4's `ferrum.secrets`/sops mechanism exists to hold it properly. This is a deliberate, scoped trade-off (keeps Phase 1.3 self-contained rather than pulling secrets infrastructure forward), not an oversight — but it must migrate to sops-nix as part of Phase 1.4, not be left as-is.

## Secrets Tooling Considered

`itsasecret` (rockydotsystems) was evaluated as a possible alternative to sops-nix for Phase 1.4, at the user's suggestion. It genuinely is self-hostable (a two-container Docker Compose stack — `itsasecret/web` + Postgres — with a real backup/restore story, documented at itsasecret.dev/self-hosting), and its trust model is good (client-side end-to-end encryption, server only ever stores ciphertext). Not adopted as ferrum's default, for three concrete reasons found once the self-hosting docs were actually reviewed:

1. It's two more always-running services per box (a web app + Postgres) that must stay up for any other app to retrieve its secrets at boot/apply time — a new internal single point of failure, versus sops-nix's zero-services, static-file-decrypt model.
2. It complicates ferrum's rollback story: a Postgres database holding secrets is new stateful infrastructure whose snapshot/rollback semantics need explicit design (does it roll back with `@state`, or get excluded like Authelia's user database?) — sops-nix avoids this entirely since secrets are just files in the same git repo as everything else.
3. Its CLI exposes symmetric read+write secret access (`shh secret get`/`set`), with no apparent equivalent to sops-nix's write-only property that ferrumd's threat model depends on (a compromised ferrumd can never read back a secret it wrote).

It's a well-built tool for a different job — team secret-sharing across many projects/environments — than what ferrum needs on a single box. sops-nix remains the Phase 1.4 default. Self-hosted itsasecret could be revisited as an optional, non-default backend if a user explicitly wants that trade-off, but that's real added complexity (pluggable secrets backends) not planned by default.

## Verification

- `checks.catalog-consistency` — every new `modules/apps/<id>/` directory has both `meta.nix` and `service.nix`, and every catalog entry (from `meta.nix`) has a matching module.
- `checks.schema-uniformity` — the submodule's option shape is unchanged by this phase (no new top-level options at all — every addition lives inside the existing `settings` bag), so this check should pass trivially; it still runs to catch any accidental top-level option added by mistake.
- `checks.eval-example-hosts` — the example host(s) evaluate cleanly with the new apps enabled (at least one example host should enable a representative subset, e.g. Radarr + qBittorrent + Jellyfin, to catch cross-app eval issues like the `mediaGroup`/`authBypassPaths` wiring actually working, without needing to enable all eight — sorry, six — apps everywhere).
- Real KVM verification on `ferrum-dev` (per [[reference-ferrum-dev-vm]]) for each app's `nix build`/eval, matching the rigor applied to every prior phase in this project — but no new VM *test* files, per the scope decision above.
- The VPN kill switch's *structural* property (no route out when `wireguardConfig` is unset or the tunnel is down) can be verified for real on `ferrum-dev` without needing live VPN credentials — bring up the namespace with an intentionally-unreachable peer endpoint and confirm qBittorrent has no route. Verifying it actually reaches ProtonVPN and torrents flow through the tunnel requires real credentials and is a manual check, not something CI or an eval check can cover.

## Open Items for Future Phases

Carried forward from this design's brainstorm, not solved here:

- **DNS record automation** (Phase 1.4): Cloudflare `dnsProvider` is already wired for ACME DNS-01 validation, but that alone doesn't create the routing A/CNAME record pointing a subdomain at the box. Needs explicit design — likely the same Cloudflare API token used for ACME, extended to also manage routing records (or tunnel CNAMEs, see next item).
- **Cloudflare Tunnel as an exposure mechanism** (Phase 1.4): a real alternative/complement to direct nginx+ACME exposure for homelab hosts behind a home router (no port-forwarding, no exposed IP). NixOS has a mature `services.cloudflared` module. Composes naturally with the DNS-automation item above, since tunnel routing is also Cloudflare-API-driven.
- **Multi-drive / NAS / cloud storage** (its own future phase): local multi-disk expansion, NFS/SMB-mounted NAS storage, rclone-backed cloud remotes (Hetzner Storage Box, Backblaze B2, etc.), mergerfs pooling, and how any of that interacts with the *arr apps' hardlink-based import workflow (hardlinks don't cross network/cloud filesystems — non-local storage likely needs copy+delete import behavior instead, worth surfacing early in that phase's design).
- **SABnzbd's non-declarative config** (Phase 1.4): flagged in the app table above — its module only exposes a config file path, not inline settings, which the reconciler will need to work around.
