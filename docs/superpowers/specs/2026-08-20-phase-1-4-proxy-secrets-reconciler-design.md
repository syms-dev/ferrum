# Phase 1.4 — Proxy, Secrets, Reconciler

## Context

Phase 1.3 shipped the full catalog (Sonarr, Radarr, Prowlarr, Jellyfin, Plex, SABnzbd, qBittorrent) with every app's uniform submodule already carrying options this phase needs to finally consume: `auth.policy`/`auth.bypassPaths`, `exposure`, `subdomain`, and each app's `meta.nix` `integrations.providesTo`/`consumes` graph. The very first scaffolding commit (`modules/core/options.nix`) also already declares `ferrum.proxy.*`, `ferrum.auth.*`, and `ferrum.secrets` — forward-looking options with no module behind them yet.

This phase builds that missing behavior: a real reverse proxy with TLS and forward-auth, a secrets mechanism (sops-nix) two different kinds of values flow through, and a reconciler that uses each app's already-declared `integrations` metadata to register download clients and indexer sources with each other automatically. It also closes a piece of tech debt Phase 1.3 explicitly flagged as due here: qBittorrent's `vpnWireguardConfig` moves out of `settings.json` and into a real sops secret.

**Scope boundary, matching the original design doc's own risk list:** the reconciler itself stays app-to-app registration only — no quality-profile sync there, since declarative *arr configuration is bottomless and Phase 1 holds that line on purpose. Recyclarr (added to this spec after initial approval, see its own section below) is a narrow, deliberate exception: it wires an existing, purpose-built upstream tool for exactly one well-known job (TRaSH Guide quality-profile/custom-format sync for Sonarr/Radarr), not a general declarative-config mechanism ferrum would have to design or maintain itself.

## Global Constraints

- Every option under `ferrum.*` must stay JSON-expressible — `checks.schema-uniformity` enforces this mechanically. This phase adds new options (`ferrum.daemon.subdomain`) under that same discipline.
- No default password, ever, for anything this phase adds (Authelia's first user included) — matches the existing daemon-auth commitment in the original design doc.
- Authelia's own user database and ACME's certificate state live on `@root`, not `@state` — they must **not** roll back. A rollback that reverted Authelia's user DB could lock the operator out of the box they're trying to repair.
- `ferrum.proxy.acme.dnsProvider` is already declared as `types.enum [ "cloudflare" ]` with no other values — this phase targets Cloudflare specifically, using a scoped API token (not the Global API key Saltbox defaults to — this was one of Saltbox's named weaknesses from the very start of this project).
- Secret values never get Nix-string-interpolated into a systemd unit's script/environment/ExecStart text. This was already the hard rule for qBittorrent's WireGuard config in Phase 1.3; this phase generalizes it to every secret this mechanism handles.

---

## Design

### Proxy, TLS, and Auth

**nginx `virtualHosts` generation, driven by each app's existing `exposure` option:**

- `exposure = "local"` — no vhost at all. Reached only through ferrumd's own internal proxying (Phase 1.5), matching the option's own doc comment.
- `exposure = "lan"` — an nginx vhost at `"${app.subdomain}.${ferrum.proxy.baseDomain}"`, `proxyPass` to `http://127.0.0.1:${app.port}`, restricted to `ferrum.proxy.trustedNetworks` via nginx `allow`/`deny`.
- `exposure = "public"` — the same vhost, on the public listener, with a real ACME certificate (`security.acme.certs."${vhost}"`, DNS-01 via Cloudflare, credential read from the secret named by `ferrum.proxy.acme.credentialSecret`).

**Authelia as forward-auth, one shared instance.** `services.authelia.instances.main`; every non-bypassed nginx location gets an `auth_request` pointed at it. Authelia's own `access_control` rules are generated straight from the catalog: one rule per app matching its vhost domain with `policy = app.auth.policy` (Authelia's own policy enum is literally `bypass`/`one_factor`/`two_factor`/`deny` — the same names ferrum already chose when this option was first scaffolded), plus a higher-priority `bypass` rule per entry in `app.auth.bypassPaths`. This is exactly why those bypass lists exist — the *arr apps' `/api`, `/feed`, `/ping` paths need to reach through even when the app's UI itself requires two-factor.

**First-user bootstrap.** Authelia's user database must exist before anyone can log in, and per the constraint above it never rolls back — so first-run needs a real answer, not a placeholder. Reuse the mechanism the original design doc already specifies for ferrumd's own first-run auth: a one-time setup token generated at first boot, readable only over SSH, no default password. `ferrum.auth.adminEmail` (already an existing option) names the account this creates.

**New option this phase adds:** `ferrum.daemon.subdomain` (`types.str`, default `"ferrum"`) — the daemon currently has `enable`/`port`/`listenAddress` but no public hostname. This gives ferrumd's own web UI a vhost the same way every catalog app already gets one, just not tied to `modules/lib/catalog.nix` since the daemon isn't a catalog app. Combined with `ferrum.proxy.baseDomain`, this is what makes `ferrum.<baseDomain>` work for the control UI specifically.

### Secrets

**Two distinct write paths — not one mechanism wearing two hats.**

1. **Operator-provided secrets** — anything a human has to type in: the ACME DNS token, qBittorrent's WireGuard config, the restic backup password. These are exactly what the existing `ferrum.secrets` option already models (`attrsOf (submodule { description })`, "names ferrumd is permitted to write a secret under"). The write itself needs no privilege at all: `sops --encrypt --age <public-recipient>` requires only the *public* key, so ferrumd (unprivileged, `ProtectSystem=strict`) can run it directly — browser POST → ferrumd shells out to `sops encrypt` → writes `/etc/ferrum/secrets/<name>.sops`. No polkit dance, no privileged helper, unlike `ferrum-apply`'s actual rebuild operations. ferrumd never holds or requests the private key, so the "a compromised ferrumd cannot exfiltrate a secret it wrote" property the original design doc promises is structural, not a policy someone has to remember to enforce.

2. **Auto-generated secrets** — per-app API keys, Authelia's session/storage secrets. Nothing needs a human. A new preflight step in `ferrum-apply`, ordered before the snapshot/switch step (secret paths get wired statically into unit definitions, so the value must exist before activation): for every enabled app that needs one and doesn't have a `.sops` file yet, generate a random value, encrypt it the same zero-privilege way, write it. Keyed by convention (`<appId>-apikey`), never appearing in `settings.json` — the operator never sees these exist.

   **Not every app gets one, and this phase must say explicitly which do.** The servarr-framework apps (Sonarr, Radarr, Prowlarr) use a real API-key env var (`environmentFiles` mapping to `SONARR__AUTH__APIKEY` and its siblings) — these three get auto-generated keys. qBittorrent has its own WebUI username/password, Plex uses Plex.tv account auth entirely outside ferrum's control, Jellyfin and SABnzbd have their own first-run setup flows — none of these four get an auto-generated "apikey" secret from this mechanism.

**Decryption is sops-nix's job, not ferrum's.** Its own NixOS module decrypts with the box's private age key at system activation, writing to `/run/secrets/<name>` with per-secret owner/group/mode. Consuming units reference `config.sops.secrets."<name>".path`.

**Real cross-cutting implementation footprint:** every app's `service.nix` from Phase 1.3 has zero secret wiring today. This phase touches all seven (Sonarr included) to add the relevant `environmentFiles`/config reference — small and mechanical, but it is a real diff across every already-shipped app, not confined to new files.

**Closes Phase 1.3's flagged tech debt:** `qbittorrent.vpnWireguardConfig` moves from a plain `app.settings` string into a proper sops secret, following path 1 above (operator-provided, via `ferrum.secrets`). The runtime-`jq`-read mechanism `modules/apps/qbittorrent/service.nix` already uses stays the *shape* — it just reads from the sops-decrypted `/run/secrets/` path instead of `/etc/ferrum/settings.json`, which is what actually closes the store-exposure gap the Phase 1.3 final review found (the old path was exposed via `/etc/ferrum` being copied into the store as the flake's own source; `/run/secrets/` is a tmpfs, never part of any flake evaluation).

### Reconciler

**Its own crate** (`crates/ferrum-reconcile`), a systemd oneshot ordered `after`/`wantedBy` `ferrum-apps.target` — decoupled from `ferrum-apply` entirely, so it re-runs any time the apps target restarts (crash recovery, a rollback's state-restore cycle), not only after an explicit config change.

**Driven by `integrations.providesTo`/`consumes`**, already present in every `meta.nix` since Phase 1.3, filtered to currently-enabled apps. What that metadata does *not* say is which *kind* of registration a pair needs — `category` turns out too coarse (Sonarr/Radarr/Prowlarr are all `"media-automation"` despite Prowlarr being an indexer source and Sonarr/Radarr being consumers of both indexers and download clients).

Given there are exactly two registration kinds in the current catalog (register-as-download-client, register-as-indexer-source), this phase hardcodes the small dispatch directly in Rust rather than inventing a new metadata field or a generic plugin mechanism for a two-case problem — matching the original design doc's explicit reconciler-scope-creep warning.

**Per pair:** read both apps' secret via its sops-nix path, call the provider's real API (Radarr's `/api/v3/downloadclient`, Prowlarr's app-sync endpoints) to register the other. Idempotent by construction — check for an existing entry matching by name before creating, so re-runs never pile up duplicates. Matches the nixarr `prowlarr/settings-sync` shape the original design doc already cited: JSON-driven, secret values indirected through a path reference, never embedded literally.

### Recyclarr

**Opinionated and optional, matching [[feedback-opinionated-design]]'s "strong opinions, strong docs, not maximally flexible" stance.** `ferrum.recyclarr.enable` (`types.bool`, default `false`) — off by default; an operator who wants ferrum's TRaSH-guide opinions turns it on, rather than ferrum shipping a blank slate the operator has to fill in themselves.

**Reuses nixpkgs' own `services.recyclarr` module directly** (confirmed present and packaged for both `x86_64-linux` and `aarch64-linux` against the pinned nixpkgs revision) rather than building a bespoke ferrum wrapper — that module already does exactly what's needed: a systemd timer running `recyclarr sync` on a schedule, and a secrets-substitution mechanism (`configuration.<app>.api_key._secret = "<path>"`, resolved via `LoadCredential=` at service start, never Nix-interpolated) that composes directly with a `config.sops.secrets."<app>-apikey".path` reference — the exact same secret Phase 1.4a's `ferrum-apply` preflight step already generates for Sonarr/Radarr. **No new secret-write path, no new generated value, nothing for this section to add to the Secrets design above** — Recyclarr consumes an already-existing secret through an already-existing NixOS mechanism.

**Scope: Sonarr and Radarr only**, each gated on both `ferrum.recyclarr.enable` and that app's own `enable` — Recyclarr's quality-profile/custom-format sync doesn't apply to Prowlarr (that's a different tool relationship entirely: Prowlarr's own built-in "Applications" sync, already covered by the Reconciler section above, pushes indexers *into* Sonarr/Radarr; Recyclarr has no comparable relationship with Prowlarr at all).

**ferrum ships one default TRaSH profile** (a real `services.recyclarr.configuration` attrset baked into `modules/apps/{sonarr,radarr}` or a new `modules/core/recyclarr.nix`, TBD at plan time) covering standard quality-profile tiers and the commonly-recommended custom formats — not a pass-through the operator must author from scratch. An operator who wants a different profile overrides `services.recyclarr.configuration` in `custom/`, following the same override pattern every other ferrum default already supports.

**Known risk this section adds:** the baked-in default profile is a snapshot of TRaSH Guides' recommendations at whatever point it was written — TRaSH's own guidance evolves, and ferrum's shipped default will drift from upstream over time unless something refreshes it. Out of scope for this phase to solve (no auto-update mechanism); worth flagging in ferrum's own docs as a "this is a snapshot, check TRaSH Guides directly for the latest" caveat, and revisiting if/when ferrum's catalog gets a general update-tracking story.

---

## Verification

**Real domain, real DNS-01 challenge, real Authelia login — not a local/self-signed placeholder.** `thesyms.ca`, Cloudflare, scoped API token. During this development phase, to coexist with the operator's still-running Saltbox instance on the same domain, every catalog app's `subdomain` is overridden in the test host's `settings.json` to a `"<name>-ferrum"` form (e.g. `sonarr-ferrum.thesyms.ca`) — this needs no new mechanism, since `subdomain` is already a per-app, settings.json-overridable option; it is purely a test-host configuration choice, not a design decision this spec needs to encode. The control UI gets the bare `ferrum.thesyms.ca` via the new `ferrum.daemon.subdomain` option.

Verification on [[reference-ferrum-dev-vm]] follows the same discipline established across Phase 1.2 and 1.3: real `nix build`/`nix eval` for structural checks, plus real boot tests wherever a claim can't be verified any other way (a real ACME cert actually issued and installed, Authelia actually gating a two-factor app and actually letting a bypass path through, the reconciler actually creating a working download-client registration a real *arr instance accepts, `recyclarr sync` actually running against a real Sonarr/Radarr instance and the resulting quality profile actually present via that app's own API afterward) — matching the standard this project has held since Phase 1.2's rollback tests and Phase 1.3's qBittorrent VPN kill-switch verification (where a route-table-only check missed a real bug that a genuine end-to-end handshake caught).

## Known Risks

1. **Authelia's bootstrap/rollback interaction.** Its user database staying on `@root` (not `@state`) means it survives a rollback — but that also means a *forward* apply that changes Authelia's own config could still leave the user database in a state the new config doesn't expect. Needs explicit verification, not just an assertion that "it's on `@root` so it's fine."
2. **sops-nix's private age key's own lifecycle.** Answered in part by Phase 1.4a's implementation: the box's age identity derives from its own SSH host key (`sops.age.sshKeyPaths`, defaulting to `config.services.openssh.hostKeys`), so `nixos-anywhere` provisions it for free as a side effect of the box having an SSH host key at all — nothing extra to provision. **Still genuinely open, flagged by Phase 1.4a's final review and explicitly carried forward here:** nothing detects or recovers from that key being lost or regenerated — every existing `.sops` file becomes silently, permanently undecryptable, and `ensure_all`'s idempotency check (an auto-generated secret is left alone once its file exists) means this fails silently rather than loudly. A real fix (recipient-mismatch detection against a `.sops` file's own embedded recipient, or a guided key-rotation flow) is real secret-rotation UX, not a mechanical patch — this phase's plan should either build it or make an explicit, ledgered decision to defer it further, not silently inherit Phase 1.4a's own deferral a second time.
3. **Per-app secret-eligibility list drifting from reality.** The "which apps get an auto-generated apikey" list (Sonarr/Radarr/Prowlarr yes; qBittorrent/Plex/Jellyfin/SABnzbd no) is asserted here from what's currently known about each app's auth model — worth a quick confirmation pass against each app's actual current nixpkgs module during implementation, since these details can drift between nixpkgs versions.
4. **Recyclarr's baked-in default quality-profile config is a point-in-time snapshot of TRaSH Guides' recommendations, not a live sync.** No auto-update mechanism ships in this phase; the profile will drift from upstream TRaSH guidance over time. Needs a documented caveat, not a code fix, for now.
