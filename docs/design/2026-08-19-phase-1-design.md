# ferrum — Phase 1 Implementation Plan

## Context

**ferrum** is a new, public, open-source NixOS-based alternative to [Saltbox](https://github.com/saltyorg/Saltbox) for self-hosted media and automation servers. The repository is empty — this plan starts the project from zero.

Saltbox deploys a containerised media stack (Plex/Jellyfin, the *arr apps, download clients, Traefik, rclone/mergerfs cloud storage) onto a dedicated Ubuntu box via Ansible. Research into its code and issue tracker confirmed its weaknesses are structural rather than incidental:

- **No rollback of any kind.** No generations, no atomic upgrades. Recovery means restoring a stop-the-world tar backup or `rm -fr /opt/<app>` and reinstalling.
- **User edits are destroyed by design.** `sb update` runs `git clean -df` and `git reset --hard @{u}` twice with no stash. Customisation is confined to a variable surface the maintainers chose; anything outside it is explicitly unsupported.
- **Silent state drift.** [#495](https://github.com/saltyorg/Saltbox/issues/495): container state declared in the inventory was ignored because `state: started` is hardcoded. [#475](https://github.com/saltyorg/Saltbox/issues/475): a failed `mv` was `ignoring`-ed and cleanup deleted user data anyway.
- **Secrets in plaintext**, with a Cloudflare *Global* API key as the documented default.
- **Backups off by default**, uncompressed, unencrypted at rest, hours of downtime.
- **Ubuntu-only, x86_64-only, clean-dedicated-machine-only**, enforced by an Ansible assert. ARM is explicitly refused.
- **No GUI and none planned** — the docs state all setup happens in text editors and on the command line.

Two motivations drive ferrum, chosen explicitly by the project owner:

1. **Atomic updates with real rollback.** When an update breaks the box, there must be a way back that works.
2. **Setup and maintenance must not require hand-editing config files.** The web UI is the point, not a nicety.

### The central design problem

NixOS rollback is a **weaker promise than users will assume**, and this plan is built around closing that gap honestly. `nixos-rebuild --rollback` restores the system closure — not `/var/lib`, not application databases. Upgrade Sonarr v3→v4, let it migrate its database, then roll back, and the old binary faces a database it cannot open: the rollback causes a *second* outage rather than a recovery.

So ferrum's headline feature is not "NixOS has generations". It is **system closure and application state rolled back together, atomically**, by pairing every apply with a btrfs snapshot of the state subvolume keyed to the generation. Shipping generation rollback alone and calling it a Saltbox-killer would burn trust the first time someone used it.

### Why a scoped UI can succeed where others failed

Every *generic* NixOS configuration GUI is dead or stalled — [nix-gui](https://github.com/nix-gui/nix-gui) untouched since 2022 — and the NixOS wiki concludes graphical config editors are impractical given the size and weak typing of the option space. The two living projects (Thymis, the Clan GUI) survived by narrowing scope hard.

ferrum's UI is viable because it does **not** edit arbitrary NixOS options. It edits a curated catalog with a uniform schema ferrum itself defines, so the UI can be *generated from that schema* rather than hand-built per app.

### On platform lock-in

Requiring NixOS is a stricter lock than Saltbox's Ubuntu requirement, and that is worth stating plainly. The difference is what it buys: Saltbox's Ubuntu requirement buys the user nothing, whereas NixOS is what makes atomic rollback possible at all.

ferrum resolves this by being **hardware- and provider-agnostic rather than distro-agnostic**: the user never installs NixOS themselves. [nixos-anywhere](https://github.com/nix-community/nixos-anywhere) converts any kexec-capable Linux box over SSH, so home servers, rented dedis and VPS instances all work. **aarch64 is first-class from Phase 1**, which Saltbox refuses outright — that covers ARM home servers and Ampere instances, and makes the owner's spare Mac Mini M4 a legitimate development machine.

Saltbox's real lock-in complaints are not "I wish it ran on Fedora" — they are *my edits get wiped*, *customising voids support*, and *it demands a clean dedicated machine*. ferrum fixes all three regardless of the base OS.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Foundation | Standalone flake (not Clan) | ferrum controls the option schema the UI depends on; no early-stage framework dependency |
| Audience | Public from day one | Uniform schema, per-app tests, honest docs from the start |
| Platform | Any hardware; ferrum provisions NixOS | Keeps rollback; avoids demanding users learn NixOS |
| Architectures | x86_64 **and** aarch64 | Differentiation Saltbox refuses; validates the Mac Mini dev path |
| Phase 1 scope | Rollback-safe core, ~7 apps, local disk only | Proves the differentiator before scaling the catalog |
| UI | Local web UI, Rust (axum/tokio), single binary | Fits a headless appliance; trivial to package |
| State filesystem | btrfs | In-tree, so no rebuild failures when the kernel outpaces the module (ZFS's recurring NixOS tax) |
| Secrets | sops-nix | Templating and many-secrets-per-file suit per-app credential bundles |
| License | Apache-2.0 | Maximum reuse across the Nix ecosystem |
| Config source of truth | `settings.json` in a git repo on the box | The UI never generates Nix syntax |

**Out of scope for Phase 1:** the rclone/mergerfs cloud tier (its own later phase), the long catalog tail (Saltbox documents ~232 roles), multi-host management, and Saltbox migration tooling.

## Reuse — do not rebuild

- **Provisioning:** [nixos-anywhere](https://github.com/nix-community/nixos-anywhere) + [disko](https://github.com/nix-community/disko)
- **Media modules:** nixpkgs' shared **servarr framework** (`nixos/modules/services/misc/servarr/`) — `services.sonarr.settings` exists now, with `environmentFiles` mapping to `SONARR__AUTH__APIKEY`. **This is load-bearing:** ferrum can *choose* each app's API key up front, turning cross-app registration into ordinary API calls rather than scraping `config.xml`.
- **Reconciler shape:** [nixarr](https://nixarr.com)'s `prowlarr/settings-sync` — a JSON-config-driven oneshot with `{ secret = <path>; }` indirection.
- **Conventions:** [SelfHostBlocks](https://github.com/ibizaman/selfhostblocks) — uniform option schema, per-service VM tests.
- **Proxy/TLS:** nixpkgs `services.nginx` + `security.acme` (the Traefik module is stale; nginx has the deepest ACME integration and `virtualHosts` is an attrset that generates cleanly).

## Design

### Repository layout

```
ferrum/
├── flake.nix                    # flake-parts; systems = x86_64-linux, aarch64-linux
├── nix/{modules/flake,pkgs}/    # packages, checks, devshells; ferrumd, ferrum-ui, testapp
├── modules/                     # the product
│   ├── lib/{app-submodule,catalog}.nix
│   ├── core/{options,storage,generations,state-restore,secrets,daemon}.nix
│   ├── proxy/{nginx,acme,authelia}.nix
│   └── apps/<name>/{meta,service}.nix
├── crates/                      # one cargo workspace
│   ├── ferrum-schema/           # settings types, shared with Nix via JSON Schema
│   ├── ferrumd/                 # axum web server, UNPRIVILEGED
│   ├── ferrum-apply/            # apply/rollback/restore-state/gc, PRIVILEGED
│   └── ferrum-reconcile/        # cross-app registration
├── ui/                          # schema-driven SPA
└── tests/                       # NixOS VM tests
```

On the box, `/etc/ferrum` is a git repo: `settings.json` (the only thing the UI writes), `flake.nix` and `hardware-configuration.nix` (root-owned, UI cannot touch), `secrets/*.sops`, and `custom/` — **`root:root 0755`, so ferrumd physically cannot write Nix expressions there.** That directory is the direct answer to Saltbox destroying user edits.

Settings are imported by the *host* flake and passed into `ferrum.lib.mkHost` as a plain attrset. Reading a path out of `config.ferrum.*` in order to define `config.ferrum` would be infinite recursion; doing the import one level up avoids it.

### Storage layout

Subvolume boundaries define what does and does not roll back:

```
@root      -> /                       NOT snapshotted
@nix       -> /nix                    NOT snapshotted
@state     -> /var/lib/ferrum/state   SNAPSHOTTED  <- all managed app state
@snapshots -> /var/lib/ferrum/snapshots
@media     -> /srv/media              NOT snapshotted
```

Three rules that must be asserted in `modules/core/storage.nix`:

1. **`/var/lib/ferrum` itself lives on `@root`.** ferrumd's database, job history and rollback journal must survive a rollback — the component reporting on a rollback cannot be erased by it.
2. **`downloads` and `library` are plain directories inside `@media`, never separate subvolumes.** btrfs forbids hardlinks across subvolumes, and the entire *arr import workflow depends on hardlinks. Getting this wrong silently degrades every import to a full copy.
3. Infra state (`/var/lib/acme`, Authelia) stays on `@root` and does *not* roll back — rolling back an Authelia user database could lock the operator out of the box they are repairing.

Apply refuses to run when free space is below `ferrum.storage.minFreeGiB` (default 10). btrfs ENOSPC mid-snapshot is the most likely way to brick a homelab box.

### The uniform app submodule

This is what makes the self-rendering UI possible — one submodule type, identical for every app:

```nix
types.attrsOf (types.submodule ({ name, ... }: let meta = catalog.${name}; in {
  options = {
    enable    = mkEnableOption meta.displayName;
    port      = mkOption { type = types.port; default = meta.defaultPort; };
    subdomain = mkOption { type = types.str;  default = meta.defaultSubdomain; };
    exposure  = mkOption { type = types.enum [ "local" "lan" "public" ]; default = "local"; };
    stateDir  = mkOption { type = types.str;  default = "${stateRoot}/${name}"; };
    auth = {
      policy      = mkOption { type = types.enum [ "bypass" "one_factor" "two_factor" ]; };
      bypassPaths = mkOption { type = types.listOf types.str; default = meta.authBypassPaths; };
    };
    mediaAccess = mkOption { type = types.enum [ "none" "read" "readwrite" ]; };
    resources   = { memoryMax = ...; cpuQuota = ...; };
    settings    = mkOption {   # JSON scalars ONLY — see security boundary below
      type = types.attrsOf (types.oneOf [ types.bool types.int types.str (types.listOf types.str) ]);
    };
  };
}))
```

**There is deliberately no `package` option.** A package is not JSON-serializable, so the UI must never set one; version changes happen by moving the flake's `nixpkgs` input. An operator pinning one app writes `services.sonarr.package = ...` in `custom/`.

`auth.bypassPaths` exists from day one even though auth ships disabled — `/api`, `/feed`, `/ping` must bypass forward-auth or every API client and mobile app breaks.

### How the UI discovers the catalog

Nix builds a `catalog.json` (per-app metadata plus a hand-written JSON Schema for the whole `ferrum.*` document); ferrumd reads it from `$FERRUM_CATALOG`. The UI renders the app list from the metadata and renders **one form definition for all apps**, because the submodule is uniform.

Two eval checks keep this honest, and they are what stop the architecture eroding:

- **`checks.catalog-consistency`** — catalog entries and `modules/apps/` must agree.
- **`checks.schema-uniformity`** — walk `options.ferrum` and assert every option type is in a JSON-expressible allowlist, with `path`, `package`, `functionTo` and `raw` forbidden.

Do **not** generate the schema from `nixosOptionsDoc`; its `type` field is a human-readable string ("attribute set of (submodule)"), far too lossy to render a form from.

### Snapshot and rollback — the core of the project

Two findings shape this and were verified against nixpkgs source:

- **An activation script cannot abort a switch.** `switch-to-configuration` records `exit_code = 2` on activation failure and *keeps going*. So "snapshot, and refuse to switch if it fails" cannot live in an activation script — it must be a wrapper that runs before `nixos-rebuild`.
- **Only *changed* units are stopped by a switch.** Any unchanged unit stopped beforehand will *not* be restarted. Hence an explicit `ferrum-apps.target` that apply stops and starts.

**Apply** (`ferrum-apply`, root, systemd oneshot):

```
1. Validate request; verify git HEAD matches
2. nix build ... -> $NEW              [apps still running; the slow part]
3. Preflight: free space, /boot room, snapshot dir is a subvolume  -> abort BEFORE any change
4. N = current generation
5. systemctl stop ferrum-apps.target  [downtime starts]
6. btrfs subvolume snapshot -r @state  ->  <ts>-gen<N>   (~50ms); fsync journal entry
7. nix-env -p .../system --set $NEW   -> creates generation N+1
8. switch-to-configuration switch     -> capture exit code (0 ok / 2 activation / 4 units)
9. systemctl start ferrum-apps.target [REQUIRED — see above]
10. Health-check each app; classify as succeeded / degraded / failed
```

Stopping apps before snapshotting is nearly free — the switch was going to stop the changed ones anyway — and it buys a clean snapshot with no SQLite WAL replay or torn `config.xml`. Snapshots are named `<unix_ts>-gen<N>`, because after a rollback the running generation is N again and a later apply would collide on generation number alone.

**Rollback is reboot-based, deliberately.** You cannot swap a mounted btrfs subvolume in place. Unmounting `@state` live has an open-ended set of `EBUSY` failure modes (systemd `StateDirectory` namespacing, prowlarr's `/var/lib/private` bind mount, an operator's shell in the directory), and a rollback that fails occasionally is not a rollback. A real rollback should revert the kernel anyway, which needs a reboot regardless.

```
rollback --to N:
  validate (generation exists, closure not GC'd, snapshot present and read-only)
  write /var/lib/ferrum/rollback-intent.json atomically
  nix-env --switch-generation N                    # NOT --rollback: that only steps back one
  switch-to-configuration boot                     # 'boot', not 'switch' — never activate the
                                                   # old closure against the new state
  reboot
--- next boot, stage 2, ordered Before= the @state mount unit ---
  ferrum-state-restore.service:
    snapshot the read-only snapshot -> a writable copy
    rename @state       -> trash/@state.replaced.<ts>     # atomic; kept as undo-of-the-undo
    rename the copy     -> @state                          # atomic
    on ANY error: touch /run/ferrum/state-restore-failed, exit 0
```

This needs no initrd integration: `@state` is not `neededForBoot`, so a stage-2 unit ordered before its mount runs while `@root` is writable and `@state` is not yet mounted.

Two safety properties worth defending:

- **Restore failure exits 0 so the box still boots**, but `ferrum-apps.target` carries `ConditionPathExists = "!/run/ferrum/state-restore-failed"`. Boot has already committed to generation N's closure; if the state restore failed we are one step from "old binary, new database", so holding the apps down is the correct fail-safe — box up, UI reachable, nothing corrupted further.
- **An operator running `nixos-rebuild switch` by hand** gets a marker file and a persistent UI warning that generation N has no snapshot and is not rollback-able. Honest and cheap. Do not snapshot from an activation script instead — a snapshot taken with services running and no ability to abort is a false promise.

Generation GC is the only thing allowed to delete generations, and must refuse to leave a generation whose closure exists but whose snapshot does not (or vice versa). `nix.gc.automatic` is disabled in ferrum-managed configs: a stray `nix-collect-garbage -d` silently destroys the rollback story.

### The daemon and its privilege boundary

A web UI that can rebuild the OS is root-equivalent unless the boundary is designed. **ferrumd runs unprivileged** (`ferrum:ferrum`, `ProtectSystem=strict`, empty capability set) and requests privileged work by writing a request file and starting a template unit over D-Bus, authorised by a narrow polkit rule:

```javascript
if (/^ferrum-apply@[0-9a-f-]{36}\.service$/.test(unit) && verb === "start")
  return polkit.Result.YES;
```

Parameters go in a root-read JSON file rather than the unit name, which removes the whole class of injection-through-instance-name bugs. Not setuid (a setuid binary dragging in a Nix closure is a large, poorly understood attack surface) and not a root daemon (that would put an HTTP parser in the same address space as `nix-env --set`).

The resulting property is statable: **compromising ferrumd gets you the power expressed by the settings schema, not arbitrary Nix evaluation as root.** It holds only because `settings` is restricted to JSON scalars and `custom/` is unwritable — which is exactly what `checks.schema-uniformity` mechanically enforces.

Auth: local accounts, argon2id, server-side sessions, CSRF on mutations, rate-limited login. First run generates a one-time setup token readable only over SSH. **No default password, ever** — Saltbox ships `password1234`.

Progress streams as JSONL written by `ferrum-apply` and re-emitted over SSE, so a job survives a ferrumd restart and replays cleanly for a reconnecting client.

### Secrets

One sops file per secret, binary format, always fully replaced and **never re-encrypted**. ferrumd holds only the public age recipient: it can write any secret but cannot read one. That makes the UI a write-only secret store — a compromised ferrumd cannot exfiltrate the Cloudflare token — and it is only available because we never re-encrypt.

## Verification

**Cheap checks, every push (target under 5 minutes):** `schema-uniformity`, `catalog-consistency`, `eval-example-hosts` (evaluate three example hosts to `drvPath`), clippy/rustfmt/cargo-test, and `json-roundtrip` asserting the Rust `Settings` struct and the Nix-emitted schema agree — that seam is the most likely to drift.

**The rollback test is the most important test in the project.** Real Sonarr v3→v4 is a poor subject: slow, hard to pin two majors, and a failure tells you little. Instead build `ferrum-testapp` in two versions — v1 refuses to start if `PRAGMA user_version > 1`; v2 migrates to 2 — reproducing the exact failure mode in ~80 lines, deterministically, in seconds.

`tests/rollback.nix` then proves the product's central claim:

```
boot -> POST a "before" row -> assert user_version == 1
upgrade to v2 -> assert user_version == 2 -> POST an "after" row
rollback --to N -> reboot
  assert /run/current-system == generation N's toplevel
  assert user_version == 1              # state rolled back, not just the closure
  assert rows contain "before"
  assert rows do NOT contain "after"    # <- THE assertion that distinguishes ferrum
  assert GET /ping == 200               # v1 actually starts against this database
  assert integrity_check == "ok"
```

A companion `tests/rollback-proves-necessity.nix` performs the same downgrade *without* the state restore and asserts v1 **fails**. If that test ever starts passing, the product's premise needs re-examining.

Other VM tests: rollback-failure (snapshot deleted between schedule and reboot — box boots, apps held down, nothing corrupted), apply-degraded, apply-preflight (fill the disk, assert abort before touching the profile), unmanaged-switch, proxy-auth (`/` redirects, `/api` with a valid key does not), secrets (including the write-only property), privilege-boundary (as `ferrum`, `systemctl start sshd` is denied and `custom/` write fails with EACCES), reconcile idempotence, and per-app tests **generated from the catalog** so adding an app adds a test.

**CI:** GitHub Actions with the Determinate Systems installer (it configures `/dev/kvm`, which is what makes NixOS VM tests viable on hosted runners); eval checks on every push, the VM suite on PRs and nightly, with the rollback job as a required check and an `ubuntu-24.04-arm` job keeping aarch64 honest.

**Dev loop:** edit on Windows; build nothing there. The Mac Mini M4 runs an aarch64 NixOS VM as the dev shell for eval, Rust checks and fast aarch64 VM tests. A cheap x86 mini-PC or VPS is the integration target, provisioned with `nixos-anywhere --build-on remote` so the aarch64 machine never builds x86_64 closures. Reprovision it from scratch weekly — the install path is what a new user hits first, and it is the thing most likely to rot.

## Phased execution

**Phase 1.0 — prove the risky assumptions first (2–3 days).** Each item invalidates part of the design if false: KVM on hosted runners; the btrfs snapshot-and-rename swap by hand; a stage-2 unit genuinely ordering before a `.mount` unit; `SONARR__AUTH__*` values against the pinned Sonarr; `--switch-generation` + `boot` + reboot landing on N; `sops --encrypt --input-type binary` consumable as `format = "binary"`; and `nixos-anywhere --build-on remote` provisioning the test target. **If the mount-ordering probe fails, redesign the restore mechanism before building anything on it.**

Then: **1.1** skeleton, schema and storage, ending with a real box installed from scratch running Sonarr from a `settings.json` (~1 week). **1.2** the rollback engine and its tests, *before* any UI (~2 weeks). **1.3** the remaining catalog — Radarr, Prowlarr, qBittorrent, SABnzbd, Jellyfin, Plex (~1 week). **1.4** proxy, secrets, reconciler (~1.5 weeks). **1.5** daemon and UI (~3 weeks). **1.6** install path, docs and release (~1 week). Roughly **9–11 weeks** of focused work.

The demo that sells the project arrives at the end of 1.2: enable testapp v1, write a row, upgrade, watch it migrate, roll back, show v1 starting cleanly against a v1 database with the row intact. That 40-second recording is the README.

## Known risks

1. **The stage-2 `Before=<mount>.mount` ordering.** The whole rollback design rests on it. Settled by the Phase 1.0 probe; fallback is a systemd-initrd service with `btrfs-progs` in `storePaths`.
2. **KVM on GitHub-hosted runners.** Works today for public repos but has changed before, and the VM suite is the entire quality story. Fallback: a self-hosted runner on the test box, or TCG nightly at 5–10× slower.
3. **btrfs CoW under a SQLite-heavy workload.** *arr databases fragment badly and snapshots pin old extents, so usage grows faster than "snapshots are free" intuition suggests. `chattr +C` helps but disables checksums and interacts oddly with snapshots. Needs a week of soak testing with real data before committing to a default — **this is the risk most likely to produce bad reviews six months in.**
4. **Rolling our own sops write path.** The never-decrypt property is valuable but off the beaten path.
5. **What "rollback" means to a user versus what it does.** Media files, download queues, ACME certs and Authelia users do *not* revert. The confirmation dialog must list concretely what will and will not roll back. Getting this wrong is how a technically correct product earns a reputation for losing data.
6. **Scope creep in the reconciler.** Declarative *arr configuration is bottomless. Phase 1 holds to app-to-app registration and defers quality profiles to Recyclarr.

## Open items

- Apache-2.0 versus MIT — the owner chose "MIT or Apache-2.0"; Apache-2.0 is assumed here for its patent grant. Confirm before the first public commit.
- Project name availability on GitHub and crates.io.
