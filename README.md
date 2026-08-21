# ferrum

A NixOS-based, rollback-safe alternative to [Saltbox](https://github.com/saltyorg/Saltbox) for self-hosted media and automation servers.

**Status: early scaffolding.** The design is written; the rollback engine described below is not built yet. Nothing here should be pointed at a real server.

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
crates/              Rust workspace (ferrumd, ferrum-apply, ferrum-reconcile) — not yet started
ui/                  the web UI — not yet started
tests/               NixOS VM tests
examples/hosts/      example settings.json + host config used by the guard checks
docs/design/         the approved design spec
```

## Secrets

Every secret on a ferrum host is a [sops](https://github.com/getsops/sops)-encrypted file under `ferrum.secretsDir` (default `/etc/ferrum/secrets`), decrypted at boot into a runtime-only path by [sops-nix](https://github.com/Mic92/sops-nix). The box's age decryption identity is derived from its own SSH host key — nothing to provision or lose track of separately.

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

## Development

There is no local nix install in this environment yet, so nothing here has been evaluated locally — `nix flake check` in CI is the first real test of any of it. See the design doc's "Dev loop" section for the intended setup (an aarch64 dev VM plus a real x86_64 test target provisioned via `nixos-anywhere`).

```bash
nix flake check
```

## License

Apache-2.0. See [LICENSE](LICENSE).
