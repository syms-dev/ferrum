# Phase 1.3 — Remaining Catalog Apps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Radarr, Prowlarr, qBittorrent, SABnzbd, Jellyfin, and Plex to the ferrum catalog, each following Sonarr's already-proven uniform-app-submodule pattern, plus a VPN-gated network namespace for qBittorrent and Plex's claim-token mechanism.

**Architecture:** Each app is a `modules/apps/<id>/{meta.nix,service.nix}` pair, auto-discovered by `modules/lib/catalog.nix` (no registration elsewhere needed). `meta.nix` is plain data (id, display info, defaults, health-check, `settingsSchema`); `service.nix` is a NixOS module wiring the app's own nixpkgs `services.<app>` module into ferrum's storage/rollback/interlock conventions. qBittorrent additionally gets a `systemd-network-namespace` + WireGuard setup for VPN gating.

**Tech Stack:** Nix/NixOS modules only — no Rust, no new crates. Six real upstream nixpkgs service modules (servarr framework for Radarr/Prowlarr, dedicated modules for qBittorrent/SABnzbd/Jellyfin/Plex), whose exact option surfaces were read directly from `nixpkgs` source on `ferrum-dev` before writing this plan (not guessed).

**Spec:** `docs/superpowers/specs/2026-08-20-phase-1-3-catalog-apps-design.md`

## Global Constraints

- Every app's `systemd.services.<name>` block uses the exact same shape Sonarr's already does: `wantedBy = lib.mkForce [ "ferrum-apps.target" ];`, `partOf = [ "ferrum-apps.target" ];`, `unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";`, and a `serviceConfig` merging `lib.filterAttrs (_: v: v != null) { MemoryMax = app.resources.memoryMax; CPUQuota = app.resources.cpuQuota; }`. Copy this exactly — it's the fail-closed interlock every other app already participates in (see `modules/apps/sonarr/service.nix`).
- Media-group membership: `users.users.<user>.extraGroups = lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;` — only for apps with a real, persistent NixOS user (not Prowlarr, which uses `DynamicUser`).
- No new top-level options on the uniform submodule, ever. App-specific configuration is a key inside the existing `app.settings` free-form bag (`modules/lib/app-submodule.nix`'s `settings` type: `attrsOf (oneOf [bool int str (listOf str)])` — flat scalar keys only, no nested attrsets), declared in that app's `meta.nix` under `settingsSchema.properties`, consumed via the `app.settings.<key> or <default>` guard pattern Sonarr's `service.nix` already uses for `urlBase`.
- Any value that could contain a real secret (qBittorrent's `vpnWireguardConfig`) must **never** be Nix-string-interpolated into a systemd unit's script/environment/ExecStart text — that lands in the world-readable `/nix/store`. It must be read from `/etc/ferrum/settings.json` at runtime instead (`jq`), never embedded as a literal Nix value in generated unit content.
- No per-app VM test files. Verification is `checks.catalog-consistency`, `checks.schema-uniformity`, `checks.eval-example-hosts`, plus real `nix build`/service-start verification on `ferrum-dev` (see `reference-ferrum-dev-vm` project memory for how to reach it) — done by the controller after each task, not something the implementer runs (implementer sandboxes have no nix/cargo access, matching every prior task in this project).
- `examples/hosts/minimal/settings.json` gets one new `"appId": { "enable": true }` entry per task, so `checks.eval-example-hosts` stays a real, growing cross-app eval check throughout this plan, not just at the end.
- `modules/default.nix`'s `imports` list gets one new line per task (`./apps/<id>/service.nix`). Every task after Task 1 touches this same file — expected, not a conflict, since tasks run sequentially (see subagent-driven-development's ledger pattern already established in this project).

---

## Task 1: Radarr

**Files:**
- Create: `modules/apps/radarr/meta.nix`
- Create: `modules/apps/radarr/service.nix`
- Modify: `modules/default.nix` (add `./apps/radarr/service.nix` to `imports`)
- Modify: `examples/hosts/minimal/settings.json` (add `"radarr": { "enable": true }` under `apps`)

**Interfaces:**
- Consumes: `modules/lib/app-submodule.nix`'s uniform options (`app.enable`, `.port`, `.stateDir`, `.mediaAccess`, `.resources.memoryMax`/`.cpuQuota`, `.settings`), `ferrum.storage.mediaGroup`, the `ferrum-apps.target` interlock pattern from `modules/core/generations.nix`. `services.radarr` from nixpkgs (`nixos/modules/services/misc/servarr/radarr.nix`): `enable`, `dataDir` (str, default `/var/lib/radarr/.config/Radarr`), `user`/`group` (default `radarr`/`radarr`), `settings.server.port`/`.bindaddress`, `settings.log.analyticsenabled`, `settings.update.mechanism`.
- Produces: `modules/apps/radarr/{meta.nix,service.nix}`, following the exact template later tasks reuse.

- [ ] **Step 1: Write `modules/apps/radarr/meta.nix`**

```nix
# Catalog metadata for Radarr. Mirrors modules/apps/sonarr/meta.nix exactly
# -- Radarr shares Sonarr's servarr framework (same settings-options.nix),
# so the same shape applies verbatim.
{
  id = "radarr";
  displayName = "Radarr";
  category = "media-automation";
  summary = "Movie collection manager for Usenet and BitTorrent.";

  defaultPort = 7878;
  defaultSubdomain = "radarr";
  defaultMediaAccess = "readwrite";
  defaultAuthPolicy = "two_factor";

  # /api, /feed, /ping, /signalr must reach Radarr without a forward-auth
  # redirect, or every API client (Prowlarr, mobile apps, ferrum's own
  # reconciler) breaks the moment ferrum.auth.enable flips on, and the web
  # UI's live updates (SignalR) break too. Same reasoning as Sonarr's
  # identical bypass list. (The /signalr entry was missing in the original
  # version of this task, caught by Task 1's review after dispatch -- see
  # the ledger.)
  authBypassPaths = [ "/api" "/feed" "/ping" "/signalr" ];

  healthCheck = {
    path = "/ping";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ "prowlarr" ];
    consumes = [ "qbittorrent" "sabnzbd" ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties.urlBase = {
      type = "string";
      default = "";
    };
  };

  docsUrl = "https://wiki.servarr.com/radarr";
  iconSlug = "radarr";
}
```

- [ ] **Step 2: Write `modules/apps/radarr/service.nix`**

```nix
# Radarr, wired through the uniform ferrum.apps.radarr submodule onto
# nixpkgs' services.radarr (shares Sonarr's servarr framework -- see
# nixos/modules/services/misc/servarr/). Phase 1.1 scope only: no
# ferrum.secrets/sops wiring yet, so Radarr generates its own API key on
# first start, same as Sonarr.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.radarr or { enable = false; };
in
lib.mkIf app.enable {
  services.radarr = {
    enable = true;
    dataDir = app.stateDir;
    user = "radarr";
    group = "radarr";
    settings = {
      server = {
        port = app.port;
        bindaddress = "127.0.0.1";
      } // lib.optionalAttrs (app.settings ? urlBase && app.settings.urlBase != "") {
        urlbase = app.settings.urlBase;
      };
      log.analyticsenabled = false;
      update.mechanism = "external";
    };
  };

  users.users.radarr.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.radarr = {
    # Pulled in by ferrum-apps.target instead of multi-user.target directly,
    # so `systemctl stop ferrum-apps.target` (what apply does before every
    # snapshot) actually controls it, and the fail-closed interlock (every
    # app service must carry ConditionPathExists itself -- see
    # modules/core/generations.nix for why the target's own condition alone
    # doesn't gate dependents) applies.
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
```

- [ ] **Step 3: Add Radarr to `modules/default.nix`'s imports**

Modify `modules/default.nix`:

```nix
  imports = [
    ./core/options.nix
    ./core/storage.nix
    ./core/overlays.nix
    ./core/generations.nix
    ./core/state-restore.nix
    ./apps/sonarr/service.nix
    ./apps/radarr/service.nix
  ];
```

- [ ] **Step 4: Enable Radarr in the minimal example host**

Modify `examples/hosts/minimal/settings.json`:

```json
{
  "schemaVersion": 1,
  "proxy": {
    "baseDomain": "example.invalid",
    "acme": {
      "email": "admin@example.invalid"
    }
  },
  "apps": {
    "sonarr": {
      "enable": true
    },
    "radarr": {
      "enable": true
    }
  }
}
```

- [ ] **Step 5: Verify structural checks pass**

The implementer's sandbox has no `nix`. Note in the task report that these are the checks the controller will run for real on `ferrum-dev`:

```bash
nix build .#checks.x86_64-linux.catalog-consistency .#checks.x86_64-linux.schema-uniformity .#checks.x86_64-linux.eval-example-hosts --no-link
```

Expected: exit 0, all three pass. The controller will additionally build `nixosConfigurations`-equivalent for the `minimal` example host and confirm `services.radarr.settings.server.port == 7878` and Radarr's systemd unit exists with the fail-closed `ConditionPathExists`.

- [ ] **Step 6: Commit**

```bash
git add modules/apps/radarr modules/default.nix examples/hosts/minimal/settings.json
git commit -m "Add Radarr to the catalog"
```

---

## Task 2: Prowlarr

**Files:**
- Create: `modules/apps/prowlarr/meta.nix`
- Create: `modules/apps/prowlarr/service.nix`
- Modify: `modules/default.nix` (add `./apps/prowlarr/service.nix`)
- Modify: `examples/hosts/minimal/settings.json` (add `"prowlarr": { "enable": true }`)

**Interfaces:**
- Consumes: same uniform submodule options as Task 1. `services.prowlarr` from nixpkgs (`nixos/modules/services/misc/servarr/prowlarr.nix`): `enable`, `dataDir` (default `/var/lib/prowlarr`, relocatable via an automatic bind-mount the module handles internally since it uses `DynamicUser = true` + a fixed `StateDirectory`), `settings.server.port`/`.bindaddress`. **No `user`/`group` option** — Prowlarr uses `DynamicUser`, so there is no persistent `prowlarr` NixOS user to add to `mediaGroup`, which is fine since `defaultMediaAccess = "none"` (Prowlarr never touches media files).
- Produces: `modules/apps/prowlarr/{meta.nix,service.nix}`.

- [ ] **Step 1: Write `modules/apps/prowlarr/meta.nix`**

```nix
# Catalog metadata for Prowlarr. Same servarr framework as Sonarr/Radarr,
# but Prowlarr is an indexer manager -- it never touches media files, so
# mediaAccess is "none" and it has no media-group membership.
{
  id = "prowlarr";
  displayName = "Prowlarr";
  category = "media-automation";
  summary = "Indexer manager and proxy for Usenet and BitTorrent trackers.";

  defaultPort = 9696;
  defaultSubdomain = "prowlarr";
  defaultMediaAccess = "none";
  defaultAuthPolicy = "two_factor";

  # Same reasoning as Sonarr/Radarr -- Prowlarr shares the identical
  # Servarr web framework, which uses a SignalR hub for live updates
  # (indexer test results, task queue). Missing this breaks the web UI's
  # real-time updates once forward-auth is on (caught in Task 1's review;
  # fixed here before this task is dispatched).
  authBypassPaths = [ "/api" "/ping" "/signalr" ];

  healthCheck = {
    path = "/ping";
    expectStatus = 200;
    timeoutSec = 30;
  };

  # Every *arr app it registers indexers into -- Phase 1.4's reconciler
  # reads this list, unused until then.
  integrations = {
    providesTo = [ ];
    consumes = [ "radarr" "sonarr" "qbittorrent" "sabnzbd" ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = { };
  };

  docsUrl = "https://wiki.servarr.com/prowlarr";
  iconSlug = "prowlarr";
}
```

- [ ] **Step 2: Write `modules/apps/prowlarr/service.nix`**

```nix
# Prowlarr, wired through the uniform ferrum.apps.prowlarr submodule onto
# nixpkgs' services.prowlarr. Unlike Sonarr/Radarr, the upstream module
# uses DynamicUser -- there is no persistent "prowlarr" user, so (correctly,
# since mediaAccess defaults to "none" for this app) there is no media-group
# wiring here.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.prowlarr or { enable = false; };
in
lib.mkIf app.enable {
  services.prowlarr = {
    enable = true;
    dataDir = app.stateDir;
    settings = {
      server = {
        port = app.port;
        bindaddress = "127.0.0.1";
      };
      log.analyticsenabled = false;
      update.mechanism = "external";
    };
  };

  systemd.services.prowlarr = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
```

- [ ] **Step 3: Add Prowlarr to `modules/default.nix`'s imports**

```nix
    ./apps/radarr/service.nix
    ./apps/prowlarr/service.nix
```

- [ ] **Step 4: Enable Prowlarr in the minimal example host**

Add `"prowlarr": { "enable": true }` alongside `sonarr`/`radarr` in `examples/hosts/minimal/settings.json`'s `apps` object.

- [ ] **Step 5: Verify structural checks pass**

Same three checks as Task 1, plus the controller confirms `services.prowlarr.settings.server.port == 9696` and that no `users.users.prowlarr` entry was created (DynamicUser).

- [ ] **Step 6: Commit**

```bash
git add modules/apps/prowlarr modules/default.nix examples/hosts/minimal/settings.json
git commit -m "Add Prowlarr to the catalog"
```

---

## Task 3: Jellyfin

**Files:**
- Create: `modules/apps/jellyfin/meta.nix`
- Create: `modules/apps/jellyfin/service.nix`
- Modify: `modules/default.nix` (add `./apps/jellyfin/service.nix`)
- Modify: `examples/hosts/minimal/settings.json` (add `"jellyfin": { "enable": true }`)

**Interfaces:**
- Consumes: same uniform submodule options as Task 1. `services.jellyfin` from nixpkgs (`nixos/modules/services/misc/jellyfin.nix`): `enable`, `dataDir` (relocatable, default `/var/lib/jellyfin`), `user`/`group` (default `jellyfin`/`jellyfin`).
- Produces: `modules/apps/jellyfin/{meta.nix,service.nix}`.

**Known limitation, not a bug to fix in this task:** Jellyfin's NixOS module has no `port` option at all — it always listens on 8096/8920, configurable only through Jellyfin's own web UI at runtime, not through Nix. `app.port` therefore has no effect on Jellyfin's actual listen port in this phase; `defaultPort = 8096` documents Jellyfin's own hardcoded default rather than something ferrum controls.

- [ ] **Step 1: Write `modules/apps/jellyfin/meta.nix`**

```nix
# Catalog metadata for Jellyfin. Unlike the servarr apps, Jellyfin's own
# NixOS module exposes no port option -- it always listens on 8096/8920,
# configured through Jellyfin's own web UI. defaultPort documents that
# fixed default rather than something ferrum actually wires through.
{
  id = "jellyfin";
  displayName = "Jellyfin";
  category = "media-server";
  summary = "Free media server for streaming movies, TV, and music.";

  defaultPort = 8096;
  defaultSubdomain = "jellyfin";
  defaultMediaAccess = "read";
  defaultAuthPolicy = "one_factor";

  # Jellyfin's native apps (Android TV, Roku, smart TVs, etc.) authenticate
  # with Jellyfin's own token, not a browser session -- they cannot follow
  # a forward-auth redirect. /System/Info/Public and /Users/AuthenticateByName
  # are Jellyfin's own documented unauthenticated endpoints; this list is
  # metadata only until Phase 1.4's proxy actually enforces it, and should
  # be validated against real native-client behavior at that point.
  authBypassPaths = [ "/System/Info/Public" "/Users/AuthenticateByName" "/Sessions" ];

  healthCheck = {
    path = "/health";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ ];
    consumes = [ ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = { };
  };

  docsUrl = "https://jellyfin.org/docs/";
  iconSlug = "jellyfin";
}
```

- [ ] **Step 2: Write `modules/apps/jellyfin/service.nix`**

```nix
# Jellyfin, wired through the uniform ferrum.apps.jellyfin submodule onto
# nixpkgs' services.jellyfin. No API key / claim mechanism needed -- unlike
# Plex, Jellyfin has no external account requirement.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.jellyfin or { enable = false; };
in
lib.mkIf app.enable {
  services.jellyfin = {
    enable = true;
    dataDir = app.stateDir;
    user = "jellyfin";
    group = "jellyfin";
  };

  users.users.jellyfin.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.jellyfin = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
```

- [ ] **Step 3: Add Jellyfin to `modules/default.nix`'s imports**

```nix
    ./apps/prowlarr/service.nix
    ./apps/jellyfin/service.nix
```

- [ ] **Step 4: Enable Jellyfin in the minimal example host**

Add `"jellyfin": { "enable": true }` to `examples/hosts/minimal/settings.json`'s `apps` object.

- [ ] **Step 5: Verify structural checks pass**

Same three checks. The controller additionally confirms `services.jellyfin.dataDir` resolves to `app.stateDir` and that the `jellyfin` user was correctly added to `ferrum.storage.mediaGroup`.

- [ ] **Step 6: Commit**

```bash
git add modules/apps/jellyfin modules/default.nix examples/hosts/minimal/settings.json
git commit -m "Add Jellyfin to the catalog"
```

---

## Task 4: Plex (including the claim-token mechanism)

**Files:**
- Create: `modules/apps/plex/meta.nix`
- Create: `modules/apps/plex/service.nix`
- Modify: `modules/default.nix` (add `./apps/plex/service.nix`)
- Modify: `examples/hosts/minimal/settings.json` (add `"plex": { "enable": true }`)

**Interfaces:**
- Consumes: same uniform submodule options as Task 1, plus `app.settings.claimToken` (new `settingsSchema` key, per the spec's "Plex Claim-Token Mechanism" section). `services.plex` from nixpkgs (`nixos/modules/services/misc/plex.nix`): `enable`, `dataDir` (relocatable, default `/var/lib/plex`), `user`/`group` (default `plex`/`plex`). The base module already sets its own `systemd.services.plex.environment` (`PLEX_DATADIR`, `PLEX_PLUGINS`, etc.) — ferrum's addition merges into that same attrset rather than replacing it.
- Produces: the `claimToken` settings-key pattern other future apps needing manual one-time tokens can follow.

**Known limitation, not a bug to fix in this task:** like Jellyfin, Plex's NixOS module has no `port` option — always listens on 32400 (plus several other fixed ports for discovery/companion protocols), configured through Plex's own web UI. `defaultPort = 32400` documents Plex's own default.

- [ ] **Step 1: Write `modules/apps/plex/meta.nix`**

```nix
# Catalog metadata for Plex. Like Jellyfin, no port option in the NixOS
# module -- defaultPort documents Plex's own fixed default. claimToken is
# the one Plex-specific settings key: see
# docs/superpowers/specs/2026-08-20-phase-1-3-catalog-apps-design.md's
# "Plex Claim-Token Mechanism" for why this can't be a real declarative
# NixOS module option (Plex's claim tokens can only be generated by an
# authenticated plex.tv session, by design).
{
  id = "plex";
  displayName = "Plex";
  category = "media-server";
  summary = "Media server for streaming movies, TV, and music.";

  defaultPort = 32400;
  defaultSubdomain = "plex";
  defaultMediaAccess = "read";
  defaultAuthPolicy = "one_factor";

  # Plex's native apps (smart TVs, game consoles, mobile) cannot follow a
  # forward-auth redirect -- /identity is Plex's own documented
  # unauthenticated endpoint used by clients for server discovery.
  authBypassPaths = [ "/identity" ];

  healthCheck = {
    path = "/identity";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ ];
    consumes = [ ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties.claimToken = {
      type = "string";
      default = "";
    };
  };

  docsUrl = "https://support.plex.tv/";
  iconSlug = "plex";
}
```

- [ ] **Step 2: Write `modules/apps/plex/service.nix`**

```nix
# Plex, wired through the uniform ferrum.apps.plex submodule onto nixpkgs'
# services.plex. The claim-token mechanism (see this file's meta.nix
# comment) sets PLEX_CLAIM only when a token has been pasted -- an
# already-claimed server keeps running fine with an empty or stale token
# present, since Plex only consumes PLEX_CLAIM during the initial claim.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.plex or { enable = false; };
  claimToken = app.settings.claimToken or "";
in
lib.mkIf app.enable {
  services.plex = {
    enable = true;
    dataDir = app.stateDir;
    user = "plex";
    group = "plex";
  };

  users.users.plex.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.plex = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    # Merges into the base plex module's own environment (PLEX_DATADIR,
    # PLEX_PLUGINS, etc.) rather than replacing it -- environment is an
    # attrsOf option, and NixOS merges definitions from multiple modules.
    environment = lib.mkIf (claimToken != "") {
      PLEX_CLAIM = claimToken;
    };
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
```

- [ ] **Step 3: Add Plex to `modules/default.nix`'s imports**

```nix
    ./apps/jellyfin/service.nix
    ./apps/plex/service.nix
```

- [ ] **Step 4: Enable Plex in the minimal example host**

Add `"plex": { "enable": true }` to `examples/hosts/minimal/settings.json`'s `apps` object. Leave `settings.claimToken` unset (empty default) — the example host only needs to prove Plex evaluates and builds cleanly, not that it can actually claim a real Plex.tv account.

- [ ] **Step 5: Verify structural checks pass**

Same three checks. The controller additionally confirms that with `claimToken` unset, `systemd.services.plex.environment` does **not** contain a `PLEX_CLAIM` key at all (not even an empty one) — and, separately, that setting a non-empty test value for `claimToken` in a throwaway eval does cause `PLEX_CLAIM` to appear with that exact value.

- [ ] **Step 6: Commit**

```bash
git add modules/apps/plex modules/default.nix examples/hosts/minimal/settings.json
git commit -m "Add Plex to the catalog, with its claim-token mechanism"
```

---

## Task 5: SABnzbd

**Files:**
- Create: `modules/apps/sabnzbd/meta.nix`
- Create: `modules/apps/sabnzbd/service.nix`
- Modify: `modules/default.nix` (add `./apps/sabnzbd/service.nix`)
- Modify: `examples/hosts/minimal/settings.json` (add `"sabnzbd": { "enable": true }`)

**Interfaces:**
- Consumes: same uniform submodule options as Task 1. `services.sabnzbd` from nixpkgs (`nixos/modules/services/networking/sabnzbd.nix`): `enable`, `configFile` (a `types.path`, default `/var/lib/sabnzbd/sabnzbd.ini` — **not** a relocatable data directory), `user`/`group` (default `sabnzbd`/`sabnzbd`), `openFirewall`.
- Produces: `modules/apps/sabnzbd/{meta.nix,service.nix}`.

**The real complication this task exists to solve:** SABnzbd's upstream module hardcodes `serviceConfig.StateDirectory = "sabnzbd"`, which unconditionally creates and uses `/var/lib/sabnzbd` — there is no option to relocate it. Left as-is, SABnzbd's actual data (queue, history, and its own `sabnzbd.ini` — which holds its own API key, per the spec's already-flagged gap) would live outside `ferrum.storage.stateDir` entirely, silently breaking the "every app's `stateDir` participates in rollback" promise every other app in this catalog keeps. This task overrides `StateDirectory` to `null` (removing the upstream module's hardcoded value — the base module and this module both set `serviceConfig.StateDirectory`, so a plain assignment here would conflict; `lib.mkForce` is required to win) and provisions `app.stateDir` directly via `systemd.tmpfiles.rules`, matching how `modules/core/storage.nix` already provisions `ferrum.storage.stateDir` itself.

**Known limitation, not a bug to fix in this task:** SABnzbd's port isn't a real NixOS option either (only `configFile`, which points at an INI file the module doesn't manage declaratively) — `app.port` has no effect on SABnzbd's actual listen port in this phase, for a different reason than Jellyfin/Plex (no settings mechanism exposed at all, vs. a fixed hardcoded port).

- [ ] **Step 1: Write `modules/apps/sabnzbd/meta.nix`**

```nix
# Catalog metadata for SABnzbd. Its NixOS module exposes neither a
# relocatable data directory nor a port option -- see service.nix for the
# StateDirectory override this requires, and the spec's already-flagged
# gap around SABnzbd's own non-declarative sabnzbd.ini (Phase 1.4's
# problem, not this task's).
{
  id = "sabnzbd";
  displayName = "SABnzbd";
  category = "download-client";
  summary = "Usenet download client.";

  defaultPort = 8080;
  defaultSubdomain = "sabnzbd";
  defaultMediaAccess = "readwrite";
  defaultAuthPolicy = "two_factor";

  authBypassPaths = [ ];

  healthCheck = {
    path = "/api?mode=version";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ "radarr" "sonarr" "prowlarr" ];
    consumes = [ ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = { };
  };

  docsUrl = "https://sabnzbd.org/wiki/";
  iconSlug = "sabnzbd";
}
```

- [ ] **Step 2: Write `modules/apps/sabnzbd/service.nix`**

```nix
# SABnzbd, wired through the uniform ferrum.apps.sabnzbd submodule onto
# nixpkgs' services.sabnzbd. The upstream module hardcodes
# serviceConfig.StateDirectory = "sabnzbd" (always /var/lib/sabnzbd, no
# relocation option) -- overridden here via lib.mkForce null so SABnzbd's
# actual data lives under app.stateDir like every other app in this
# catalog, participating in the rollback mechanism the same way. Since
# removing StateDirectory means systemd no longer creates that directory
# for us, this module provisions app.stateDir itself via tmpfiles, the
# same way modules/core/storage.nix provisions ferrum.storage.stateDir.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.sabnzbd or { enable = false; };
in
lib.mkIf app.enable {
  services.sabnzbd = {
    enable = true;
    user = "sabnzbd";
    group = "sabnzbd";
    configFile = "${app.stateDir}/sabnzbd.ini";
  };

  systemd.tmpfiles.rules = [
    "d ${app.stateDir} 0750 sabnzbd sabnzbd - -"
  ];

  users.users.sabnzbd.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.sabnzbd = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = (lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    }) // {
      StateDirectory = lib.mkForce null;
    };
  };
}
```

- [ ] **Step 3: Add SABnzbd to `modules/default.nix`'s imports**

```nix
    ./apps/plex/service.nix
    ./apps/sabnzbd/service.nix
```

- [ ] **Step 4: Enable SABnzbd in the minimal example host**

Add `"sabnzbd": { "enable": true }` to `examples/hosts/minimal/settings.json`'s `apps` object.

- [ ] **Step 5: Verify structural checks pass, plus the StateDirectory override specifically**

Same three eval checks. This task's real risk is the `StateDirectory = lib.mkForce null` override actually taking effect at the systemd-unit level, not just evaluating without error — note in the task report that the controller will build the example host's toplevel on `ferrum-dev` and directly inspect the generated `sabnzbd.service` unit file (`systemctl cat sabnzbd` or reading the store path) to confirm `StateDirectory=` is genuinely absent, and confirm `app.stateDir` (not `/var/lib/sabnzbd`) is what actually gets created with `sabnzbd:sabnzbd` ownership.

- [ ] **Step 6: Commit**

```bash
git add modules/apps/sabnzbd modules/default.nix examples/hosts/minimal/settings.json
git commit -m "Add SABnzbd to the catalog"
```

---

## Task 6: qBittorrent (base app, no VPN yet)

**Files:**
- Create: `modules/apps/qbittorrent/meta.nix`
- Create: `modules/apps/qbittorrent/service.nix`
- Modify: `modules/default.nix` (add `./apps/qbittorrent/service.nix`)
- Modify: `examples/hosts/minimal/settings.json` (add `"qbittorrent": { "enable": true }`)

**Interfaces:**
- Consumes: same uniform submodule options as Task 1. `services.qbittorrent` from nixpkgs (`nixos/modules/services/torrent/qbittorrent.nix`): `enable`, `profileDir` (relocatable, default `/var/lib/qBittorrent/` — the module's own `tmpfiles.settings` creates subdirectories under whatever path is given, unlike SABnzbd, so no extra tmpfiles work is needed here), `user`/`group` (default `qbittorrent`/`qbittorrent`), `webuiPort`.
- Produces: `modules/apps/qbittorrent/service.nix`, which **Task 7 modifies** to add the VPN network namespace — this task's `systemd.services.qbittorrent` block is the exact same shape Task 7 extends, not something Task 7 rewrites from scratch.

**Deliberate port choice:** qBittorrent's own upstream default WebUI port (8080) collides with SABnzbd's default (also 8080, Task 5). `defaultPort = 8090` here is a deliberate ferrum-level choice to avoid that collision when both are enabled on the same host with defaults — not qBittorrent's own upstream default.

- [ ] **Step 1: Write `modules/apps/qbittorrent/meta.nix`**

```nix
# Catalog metadata for qBittorrent. defaultPort (8090) deliberately differs
# from qBittorrent's own upstream default (8080), which collides with
# SABnzbd's default port when both are enabled on the same host.
# vpnWireguardConfig/vpnKillSwitch are added and consumed starting in
# Task 7 (this task's meta.nix does not yet declare them -- Task 7 adds
# them to this same file's settingsSchema).
{
  id = "qbittorrent";
  displayName = "qBittorrent";
  category = "download-client";
  summary = "BitTorrent client.";

  defaultPort = 8090;
  defaultSubdomain = "qbittorrent";
  defaultMediaAccess = "readwrite";
  defaultAuthPolicy = "two_factor";

  authBypassPaths = [ ];

  healthCheck = {
    path = "/api/v2/app/version";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ "radarr" "sonarr" "prowlarr" ];
    consumes = [ ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = { };
  };

  docsUrl = "https://github.com/qbittorrent/qBittorrent/wiki";
  iconSlug = "qbittorrent";
}
```

- [ ] **Step 2: Write `modules/apps/qbittorrent/service.nix`**

```nix
# qBittorrent, wired through the uniform ferrum.apps.qbittorrent submodule
# onto nixpkgs' services.qbittorrent. VPN gating (Task 7) extends this
# same file -- this version runs qBittorrent on the host's normal network,
# no isolation yet.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.qbittorrent or { enable = false; };
in
lib.mkIf app.enable {
  services.qbittorrent = {
    enable = true;
    profileDir = app.stateDir;
    user = "qbittorrent";
    group = "qbittorrent";
    webuiPort = app.port;
  };

  users.users.qbittorrent.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.qbittorrent = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
```

- [ ] **Step 3: Add qBittorrent to `modules/default.nix`'s imports**

```nix
    ./apps/sabnzbd/service.nix
    ./apps/qbittorrent/service.nix
```

- [ ] **Step 4: Enable qBittorrent in the minimal example host**

Add `"qbittorrent": { "enable": true }` to `examples/hosts/minimal/settings.json`'s `apps` object.

- [ ] **Step 5: Verify structural checks pass**

Same three checks. The controller additionally confirms `services.qbittorrent.webuiPort == 8090` (not qBittorrent's own 8080 default) and that no port conflict exists with SABnzbd's unit in the same evaluated host.

- [ ] **Step 6: Commit**

```bash
git add modules/apps/qbittorrent modules/default.nix examples/hosts/minimal/settings.json
git commit -m "Add qBittorrent to the catalog (no VPN gating yet)"
```

---

## Task 7: qBittorrent VPN Kill Switch

**Files:**
- Modify: `modules/apps/qbittorrent/meta.nix` (add `vpnWireguardConfig`/`vpnKillSwitch` to `settingsSchema`)
- Modify: `modules/apps/qbittorrent/service.nix` (add the network namespace + WireGuard setup, extend the qBittorrent unit)

**Interfaces:**
- Consumes: Task 6's `modules/apps/qbittorrent/service.nix` (the base `systemd.services.qbittorrent` block this task extends, not replaces) and `app.settings` (the same guard pattern every other app-specific settings key uses).
- Produces: the `qbt-vpn` network namespace and `systemd.services.qbt-vpn-netns-setup` unit — internal to this app, nothing later depends on it.

**This is the highest-risk task in this plan** — a genuinely new networking mechanism, not a repeat of an already-proven pattern. Three things specifically need real verification on `ferrum-dev` before this task is accepted, beyond the usual eval checks (the implementer's sandbox cannot run any of these — note them in the task report as exactly what the controller will check):

1. **The isolation is genuine.** After `qbittorrent.service` starts with a VPN config set, `ip netns exec qbt-vpn ss -tlnp` (from the host) should show qBittorrent's WebUI listening inside that namespace, while a `curl` to the same port from the host's own default namespace should fail (no route). This is the actual kill-switch property this task exists to deliver — confirm it directly, don't just trust that `NetworkNamespacePath=` was set.
2. **`NetworkNamespacePath=` composes with the upstream module's hardening.** The base `services.qbittorrent` module hardcodes `PrivateNetwork = false` and `RestrictNamespaces = true` in its `serviceConfig`. `NetworkNamespacePath=` is systemd's own pre-exec setup (not a syscall the qBittorrent process performs), so it should be unaffected by `RestrictNamespaces`, and independent of `PrivateNetwork`'s value — but this needs confirming for real, not assumed from reading `systemd.exec(5)`.
3. **The secret never touches `/nix/store`.** After building the example host's toplevel, grep the resulting `qbt-vpn-netns-setup.service` unit file (and everything in its closure) for the literal test WireGuard config content used during verification — it must not appear anywhere in the store. Only the `jq` query logic should be present in the unit; the actual secret value should only ever exist in `/etc/ferrum/settings.json` and `/run/qbt-vpn/wg0.conf` (both outside the store).

- [ ] **Step 1: Add `vpnWireguardConfig`/`vpnKillSwitch` to `modules/apps/qbittorrent/meta.nix`**

Modify the `settingsSchema` block:

```nix
  # vpnWireguardConfig/vpnKillSwitch: see
  # docs/superpowers/specs/2026-08-20-phase-1-3-catalog-apps-design.md's
  # "qBittorrent VPN Kill Switch" section for the full design. NEVER read
  # via Nix string interpolation into a systemd unit -- see service.nix.
  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = {
      vpnWireguardConfig = {
        type = "string";
        default = "";
      };
      vpnKillSwitch = {
        type = "boolean";
        default = true;
      };
    };
  };
```

(This replaces the empty `properties = { };` block Task 6 wrote.)

- [ ] **Step 2: Extend `modules/apps/qbittorrent/service.nix` with the VPN network namespace**

Replace the whole file with:

```nix
# qBittorrent, wired through the uniform ferrum.apps.qbittorrent submodule
# onto nixpkgs' services.qbittorrent, with an optional VPN-gated network
# namespace. See docs/superpowers/specs/2026-08-20-phase-1-3-catalog-apps-
# design.md's "qBittorrent VPN Kill Switch" section for the full design and
# why network-namespace isolation was chosen over qBittorrent's own
# interface-binding setting (known historical leak classes).
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.qbittorrent or { enable = false; };
  vpnConfig = app.settings.vpnWireguardConfig or "";
  vpnEnabled = vpnConfig != "";
  killSwitch = app.settings.vpnKillSwitch or true;
in
lib.mkIf app.enable {
  services.qbittorrent = {
    enable = true;
    profileDir = app.stateDir;
    user = "qbittorrent";
    group = "qbittorrent";
    webuiPort = app.port;
  };

  users.users.qbittorrent.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  # The WireGuard config is deliberately NEVER Nix-interpolated into this
  # unit -- app.settings.vpnWireguardConfig can contain a private key, and
  # any value embedded into a systemd unit's script text lands in
  # /nix/store, which is world-readable by default to every local user,
  # not just root. This script instead reads /etc/ferrum/settings.json
  # directly at RUNTIME via jq, so the secret flows from one on-disk file
  # to another (settings.json -> /run/qbt-vpn/wg0.conf) without ever
  # passing through Nix evaluation as a literal embedded value.
  systemd.services.qbt-vpn-netns-setup = lib.mkIf vpnEnabled {
    description = "Create the VPN-gated network namespace for qBittorrent";
    unitConfig.DefaultDependencies = false;
    after = [ "network-pre.target" ];
    wants = [ "network-pre.target" ];
    before = [ "qbittorrent.service" ];
    path = [ pkgs.iproute2 pkgs.wireguard-tools pkgs.jq pkgs.iptables ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      set -euo pipefail
      ip netns del qbt-vpn 2>/dev/null || true
      ip netns add qbt-vpn
      mkdir -p /run/qbt-vpn
      jq -r '.apps.qbittorrent.settings.vpnWireguardConfig // ""' /etc/ferrum/settings.json \
        > /run/qbt-vpn/wg0.conf
      chmod 0600 /run/qbt-vpn/wg0.conf
      ip netns exec qbt-vpn wg-quick up /run/qbt-vpn/wg0.conf
      ${lib.optionalString (!killSwitch) ''
        # Kill switch OFF: add a fallback route back to the host's normal
        # network via a veth pair, lower priority than the WireGuard
        # route so the tunnel is always preferred when it's up.
        ip link add veth-qbt-host type veth peer name veth-qbt-ns
        ip link set veth-qbt-ns netns qbt-vpn
        ip addr add 10.200.1.1/30 dev veth-qbt-host
        ip link set veth-qbt-host up
        ip netns exec qbt-vpn ip addr add 10.200.1.2/30 dev veth-qbt-ns
        ip netns exec qbt-vpn ip link set veth-qbt-ns up
        ip netns exec qbt-vpn ip route add default via 10.200.1.1 dev veth-qbt-ns metric 200
        iptables -t nat -A POSTROUTING -s 10.200.1.0/30 -j MASQUERADE
      ''}
    '';
    preStop = ''
      ip netns del qbt-vpn 2>/dev/null || true
      ${lib.optionalString (!killSwitch) ''
        ip link del veth-qbt-host 2>/dev/null || true
        iptables -t nat -D POSTROUTING -s 10.200.1.0/30 -j MASQUERADE 2>/dev/null || true
      ''}
    '';
  };

  systemd.services.qbittorrent = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    after = lib.mkIf vpnEnabled [ "qbt-vpn-netns-setup.service" ];
    bindsTo = lib.mkIf vpnEnabled [ "qbt-vpn-netns-setup.service" ];
    serviceConfig = (lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    }) // lib.optionalAttrs vpnEnabled {
      NetworkNamespacePath = "/var/run/netns/qbt-vpn";
    };
  };
}
```

- [ ] **Step 3: Verify structural checks pass with `vpnWireguardConfig` unset (the default, no-op path)**

The three usual eval checks, with the example host's `qbittorrent` entry left at just `{ "enable": true }` (no VPN config set) — confirms the whole VPN mechanism is correctly a no-op (`lib.mkIf vpnEnabled` false everywhere) when the setting is empty, exactly matching Task 6's already-verified behavior. No settings.json change needed for this step; the entry Task 6 added already exercises the empty-config path.

- [ ] **Step 4: Real verification on ferrum-dev — the three risk points listed above**

Not something the implementer can do (no nix/KVM access). Note in the task report, precisely, so the controller can execute it:

1. Build the example host's toplevel on `ferrum-dev` with a **test** WireGuard config set (a syntactically valid `wg-quick` config pointing at an intentionally unreachable peer — no real VPN credentials needed to prove the structural property).
2. Boot it (or use `nixos-rebuild build-vm` / an ad-hoc throwaway `pkgs.testers.runNixOSTest` invocation that is **not** committed to the repo, matching the "no new test files" scope decision — this is a one-off verification run, not a permanent test).
3. Confirm `ip netns exec qbt-vpn ss -tlnp` shows qBittorrent's WebUI port bound inside the namespace, and a `curl` from the host's default namespace to that same port fails.
4. Confirm `qbittorrent.service`'s actual runtime environment shows it genuinely joined the namespace (e.g. `readlink /proc/$(systemctl show -p MainPID --value qbittorrent)/ns/net` differs from the host's own `/proc/1/ns/net`).
5. Grep the built toplevel's closure for the test config's literal content — confirm it appears nowhere in `/nix/store`.

- [ ] **Step 5: Commit**

```bash
git add modules/apps/qbittorrent
git commit -m "Add qBittorrent's VPN-gated network namespace and kill switch"
```
