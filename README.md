# ferrum

A NixOS-based, rollback-safe alternative to [Saltbox](https://github.com/saltyorg/Saltbox) for self-hosted media and automation servers.

**Status: pre-alpha — installs and runs on real hardware; no update mechanism, and the installer's own VM tests have never passed.**

Built and tested: the rollback engine, the seven-app catalog, the reverse proxy with TLS and SSO, sops secrets, the cross-app reconciler, storage pooling over several disks, `ferrumd` (the unprivileged daemon with its polkit privilege boundary), the schema-driven web UI, and an installer that takes a bare machine to a published, logged-in system. 518 Rust unit tests and nine NixOS VM tests cover them.

Proven on a real machine, not just in CI: a rollback that reverted both the system closure and application state together; Plex reachable on a real domain with a real Let's Encrypt certificate, served through ferrum's own nginx vhost from a typed `settings.json` with no hand-written Nix.

Not built: **any way to update an app**. App versions come from the nixpkgs revision ferrum's own flake pins, so updating means hand-editing pins across two repositories and re-applying; see [the Phase 1.6 spec](docs/superpowers/specs/2026-09-16-phase-1-6-updates-design.md), whose planning gate is currently open.

`ferrum-apply gc` **is** implemented (it was a stub until 2026-09-15) and prunes to `ferrum.storage.keepGenerations`, default 10. No timer runs it, so it is operator-triggered. Note that it protects only the *currently-running* generation's snapshot, so an older generation's snapshot can be pruned and that generation then becomes unrollbackable.

It has now been installed on a real machine end to end, and rollback has been exercised there for real. That is one machine, run by its author — **still do not point this at a server holding data you care about.**

One gap worth knowing before you try it: the installer's own VM tests (`tests/stage2`) have never passed in CI, so the install path is proven by one person on one machine rather than mechanically.

**DNS is ferrum's to manage now.** It creates and reconciles one record per published app, plus `auth` when SSO is on and `ferrum` for the daemon itself — on every apply, and on a timer if you enable the dynamic-address updater. The records it wrote carry a marker in their Cloudflare `comment`, and that marker is the whole permission model: a record without it is *yours*, so ferrum reports it, leaves it exactly as it is, and never writes to or deletes it — unless you name that one hostname at the install gate and hand it over explicitly. A record of a type ferrum does not model (an `AAAA`, say) sharing one of those names is disclosed in the plan rather than silently stepped around. **Cloudflare is the only provider**, which ferrum already required for ACME DNS-01. Split-horizon DNS is out of scope: every record points at the public address, so reaching these names from inside your own LAN depends on your router supporting NAT hairpin, and many do not.

## Why

Saltbox deploys Plex/Jellyfin, the *arr apps, download clients and a reverse proxy onto a dedicated Ubuntu box via Ansible, and it works, but it has no rollback of any kind, destroys local edits on every update (`git clean -df && git reset --hard`, twice, no stash), and ships secrets in plaintext YAML.

ferrum's two goals:

1. **Atomic updates with real rollback.** NixOS generations only roll back the system closure, not application state or databases — rolling back a migrated database just moves the outage. ferrum pairs every update with a btrfs snapshot of application state, keyed to the generation, so a rollback restores *both* together.
2. **Setup and maintenance without hand-editing config.** A local web UI reads and writes a typed `settings.json`; it never generates Nix. A `custom/` directory holds hand-written Nix the UI never touches, so — unlike Saltbox — your customisations survive an update.

The full design, including why each of these choices was made, is in [`docs/design/2026-08-19-phase-1-design.md`](docs/design/2026-08-19-phase-1-design.md).

## Platform

ferrum requires NixOS, but you don't have to install it yourself: [nixos-anywhere](https://github.com/nix-community/nixos-anywhere) provisions it onto any kexec-capable box over SSH, home server or rented VPS alike. Both `x86_64-linux` and `aarch64-linux` are first-class targets.

## Repository layout

```
flake.nix           flake-parts entry point
nix/                 flake-level packages, checks, devshells
modules/             the NixOS module tree — the product
  lib/               ferrum.lib.mkHost, the app catalog, the uniform app submodule
  core/              cross-cutting ferrum.* options, storage, generations
  apps/<name>/       one directory per catalog app: meta.nix + service.nix
crates/              Rust workspace: ferrum-apply (the rollback engine), ferrumd (the
                     daemon), ferrum-install (the installer), ferrum-reconcile
                     (cross-app registration), ferrum-secrets, ferrum-state
ui/                  the web UI — hand-written HTML/CSS/ES modules, no build step
tests/               NixOS VM tests
examples/hosts/      example settings.json + host config used by the guard checks
docs/design/         the approved design spec
```

## Secrets

Every secret on a ferrum host is a [sops](https://github.com/getsops/sops)-encrypted file under `ferrum.secretsDir` (default `/etc/ferrum/secrets`), decrypted at boot into a runtime-only path by [sops-nix](https://github.com/Mic92/sops-nix). The box's age decryption identity is derived from its own SSH host key — nothing to provision or lose track of separately.

**Installing a host takes one command.** `ferrum-install` ships as a Docker
image, so Docker is the only thing your own machine needs. It inventories the
target, makes you type the serial of the disk it will erase, generates the
whole host repository, installs, enables the apps behind single sign-on, and
prints the URLs and both first-run passwords. See `docs/INSTALL.md`; the manual
path is still documented there for anyone modifying ferrum itself.

```bash
docker run --rm -it -v ~/.ssh:/ssh:ro -v ~/ferrum-host:/host \
  ghcr.io/syms-dev/ferrum-install root@YOUR-TARGET
```

**Operator-supplied secrets go in with `ferrum-apply put-secret <name>`**, which
reads the value from stdin (never argv, so it stays out of `ps` and shell
history) and encrypts it to the host's own age recipient. The Cloudflare DNS-01
token is the one you will need; the installer handles it for you.

**Sonarr, Radarr and Prowlarr's API keys are fully automatic.** `ferrum-apply` generates and encrypts a random key for each enabled app on first apply; there is nothing an operator needs to do.

### qBittorrent VPN kill switch

qBittorrent's VPN kill-switch config is operator-provided, since it's your own WireGuard peer's config, not something ferrum can generate. To enable it:

1. Get this host's age recipient (its SSH host key's public half, converted):
   ```bash
   ssh-to-age -i /etc/ssh/ssh_host_ed25519_key.pub
   ```
2. Encrypt your WireGuard config to that recipient, as a raw binary blob (not YAML/JSON — `sops` would otherwise try to parse the `.conf` file's structure):
   ```bash
   sops --encrypt --age <recipient from step 1> \
     --input-type binary --output-type binary \
     /dev/stdin < your-wg0.conf > /etc/ferrum/secrets/qbittorrent-vpn.sops
   ```
3. Add `"qbittorrent-vpn"` to `ferrum.secrets` in `settings.json` — this is what actually enables qBittorrent's VPN-gated network namespace; the file's mere presence on disk is not enough on its own.
4. Re-apply. qBittorrent's traffic now routes exclusively through the tunnel; see `modules/apps/qbittorrent/service.nix` for the kill-switch mechanism itself.

If this host's SSH host key is ever regenerated, every existing `.sops` file under `ferrum.secretsDir` becomes permanently undecryptable — back up `/etc/ssh/ssh_host_ed25519_key` the same way you'd back up any other credential this box depends on. Auto-generated servarr keys recover on their own (delete the stale `.sops` file and re-apply; a fresh key is generated); a lost `qbittorrent-vpn.sops` must be re-encrypted from your original WireGuard config via the steps above.

## Reverse proxy, TLS, and single sign-on

Enabling `ferrum.proxy.enable` puts nginx in front of every non-`local`-exposure app, with TLS on every vhost: a real ACME certificate (via Cloudflare DNS-01) for `public` apps, and a self-signed one for `lan` apps and the Authelia portal itself. Enabling `ferrum.auth.enable` additionally puts [Authelia](https://www.authelia.com/) in front of every non-`local`-exposure app whose `auth.policy` isn't `"bypass"`, as the box's single sign-on layer — each app's own native login is disabled in favor of it.

### ACME / Cloudflare DNS-01 credential

Issuing a real certificate for a `public` app needs a Cloudflare API token, operator-provided the same way qBittorrent's VPN config is:

1. Create a **scoped** Cloudflare API token (Zone:Read + DNS:Edit on the zone that owns `ferrum.proxy.baseDomain`) — never the legacy Global API key.
2. Get this host's age recipient:
   ```bash
   ssh-to-age -i /etc/ssh/ssh_host_ed25519_key.pub
   ```
3. Encrypt the token to that recipient, as a raw binary blob:
   ```bash
   echo -n "CLOUDFLARE_DNS_API_TOKEN=<your token>" | sops --encrypt --age <recipient from step 2> \
     --input-type binary --output-type binary \
     /dev/stdin > /etc/ferrum/secrets/acme-dns.sops
   ```
4. Add `"acme-dns"` to `ferrum.secrets` in `settings.json` (or whatever name `ferrum.proxy.acme.credentialSecret` is set to).
5. Re-apply.

### First Authelia login

`ferrum-apply` generates a random password for Authelia's first user (`admin`) the first time `ferrum.auth.enable` turns on, and writes it once, in plaintext, to `/var/lib/authelia-main/authelia-setup-password` (mode `0400`, root-only). Read it over SSH:

```bash
ssh <host> sudo cat /var/lib/authelia-main/authelia-setup-password
```

Log in at `https://auth.<ferrum.proxy.baseDomain>/`, then change the password from Authelia's own UI — the setup file is never regenerated or deleted automatically once `users_database.yml` exists, so treat it as sensitive until you remove it by hand.

## Development

See the design doc's "Dev loop" section for the intended setup (an aarch64 dev VM plus a real x86_64 test target provisioned via `nixos-anywhere`).

The Rust workspace can be built and tested without a Nix install, which is useful on a machine that has neither Nix nor a Rust toolchain:

```bash
docker run --rm -v "$PWD:/src:ro" -w /work rust:1-bookworm bash -c '
  apt-get update -qq && apt-get install -y -qq btrfs-progs &&
  cp -r /src/crates /work/crates && cd /work/crates &&
  cargo test --workspace --locked'
```

`btrfs-progs` is required: `preflight::check_is_subvolume` shells out to `btrfs`, and without it one test fails on the spawn error rather than the assertion it means to make. The Nix build supplies it via `nativeCheckInputs`.

```bash
nix flake check
```

## License

Apache-2.0. See [LICENSE](LICENSE).
