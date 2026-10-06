# ferrum

A NixOS-based, rollback-safe alternative to [Saltbox](https://github.com/saltyorg/Saltbox) for self-hosted media and automation servers.

**Status: pre-alpha — installs and runs on real hardware; no update mechanism, and the installer's own VM tests have never passed.**

Built and tested: the rollback engine, the seven-app catalog, the reverse proxy with TLS and SSO, sops secrets, the cross-app reconciler, storage pooling over several disks, `ferrumd` (the unprivileged daemon with its polkit privilege boundary), the schema-driven web UI, and an installer that takes a bare machine to a published, logged-in system. 518 Rust unit tests and nine NixOS VM tests cover them.

Proven on a real machine, not just in CI: a rollback that reverted both the system closure and application state together; Plex reachable on a real domain with a real Let's Encrypt certificate, served through ferrum's own nginx vhost from a typed `settings.json` with no hand-written Nix.

Not built: **any way to update an app**. App versions come from the nixpkgs revision ferrum's own flake pins, so updating means hand-editing pins across two repositories and re-applying; see [the Phase 1.6 spec](docs/superpowers/specs/2026-09-16-phase-1-6-updates-design.md), whose planning gate is currently open.

`ferrum-apply gc` **is** implemented (it was a stub until 2026-09-15) and prunes to `ferrum.storage.keepGenerations`, default 10. No timer runs it, so it is operator-triggered. Note that it protects only the *currently-running* generation's snapshot, so an older generation's snapshot can be pruned and that generation then becomes unrollbackable.

It has now been installed on a real machine end to end, and rollback has been exercised there for real. That is one machine, run by its author — **still do not point this at a server holding data you care about.**

One gap worth knowing before you try it: the installer's own VM tests (`tests/stage2`) have never passed in CI, so the install path is proven by one person on one machine rather than mechanically.

**DNS is ferrum's to manage now.** It creates and reconciles one record per published app, plus `auth` when SSO is on and `ferrum` for the daemon itself — on every apply, and on a timer if you enable the dynamic-address updater. The records it wrote carry a marker in their Cloudflare `comment`, and that marker is the whole permission model: a record without it is *yours*, so ferrum reports it, leaves it exactly as it is, and never writes to or deletes it — unless you name that one hostname at the install gate and hand it over explicitly. A record of a type ferrum does not model (an `AAAA`, say) sharing one of those names is disclosed in the plan rather than silently stepped around. **Cloudflare is the only provider**, which ferrum already required for ACME DNS-01.

Turn the updater on (`ferrum.proxy.dns.ddnsUpdater.enable`) and ferrum finds your public IPv4 address itself rather than republishing one you typed in once — set `staticAddress` or don't, your call, but if you set one and it disagrees you get told, naming both, rather than one of them quietly winning. Finding the address is a trust decision, not a lookup: a wrong answer republishes *every* one of your hostnames at somebody else's server, with certificates ferrum obtained itself, which is worse than a record that is merely out of date. So it asks three services run by three different companies, needs at least two of those companies to answer, and publishes only if every answer that arrived agrees. A private or reserved answer is refused outright, a lookup that fails exits non-zero instead of looking like "nothing to do", and published changes are capped at three a day so a flapping line can't spend your Cloudflare quota. What ferrum still can't tell you is whether traffic *to* that address reaches your box — behind CGNAT, or a router with no port forward, the records are right and the apps are still dark — so it says exactly that when the address moves instead of implying it checked.

Split-horizon DNS is out of scope: every record points at the public address, so reaching these names from inside your own LAN depends on your router supporting NAT hairpin, and many do not.

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

### Plex's claim token

Plex will not serve anybody but localhost until the server is claimed by a Plex account, and ferrum opens no port you could claim it from on the LAN — so ferrum claims it for you. If you enable Plex and set a base domain, the installer asks for a token from [plex.tv/claim](https://plex.tv/claim) and sends it to the host as the `plex-claim` secret; `ferrum-reconcile` uses it on the next apply and is a no-op on a server that is already claimed. It is a secret and not a `settings.json` value on purpose: it associates the server with somebody's Plex account, and `settings.json` is world-readable by design.

That token expires **four minutes** after plex.tv issues it, and the system build between the question and the claim usually takes longer — so coming up unclaimed is the ordinary outcome rather than a fault. The closing report asks the host whether Plex is actually claimed and says so plainly when it is not, with the commands that finish the job:

```bash
ferrum-apply put-secret plex-claim --replace   # paste a fresh token on stdin
ferrum-apply apply
```

Skipping the question is one keystroke, and is reported the same way rather than silently — but the recovery is one step longer, because nothing declared the secret. Add it to `secrets` in `/etc/ferrum/settings.json` first:

```json
"plex-claim": { "description": "plex.tv claim token" }
```

then `ferrum-apply put-secret plex-claim` (no `--replace`, there is nothing there yet) and `ferrum-apply apply`. The declaration is what `modules/apps/plex/service.nix` and `modules/core/reconciler.nix` both key on; without it the secret is written and never read.

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

Encrypt the provider's file exactly as it was issued — there is nothing to edit out of it. A config
carrying several comma-separated addresses (`Address = 10.2.0.2/32, 2a07:b944::2:2/128`, which is
what Proton and most other providers hand out) is applied one entry at a time. **IPv6 entries in
`Address` and `DNS` are deliberately skipped**, because the namespace qBittorrent runs in is routed
IPv4-only; each skip is named in `journalctl -u qbt-vpn-netns-setup` so it is a visible decision
rather than a silent drop. An IPv4 entry the kernel would refuse, or a config with no IPv4 address
at all, fails the unit at setup time quoting the offending config line.

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

### Getting in when SSH is down — the console password

**Write this one down before you need it.** Every other credential on this page gets you into something over the network; this is the one that works when the network does not.

`ferrum-apply` gives root a random console password on any apply where root has no usable one, and writes the plaintext once to `/var/lib/ferrum/root-console-password` (mode `0400`, root-only). The installer prints it at the end of an install, under `console login`. Read it again any time:

```bash
ssh <host> sudo cat /var/lib/ferrum/root-console-password
```

Then, at the machine's own keyboard and monitor, log in as `root` with that password at the `<host> login:` prompt.

Two things about it:

- **A password you set yourself is never replaced.** The guard is `passwd -S root`, the account's real state — not the presence of the file. Run `passwd` at the console to choose your own, and every later apply leaves it alone. (The file then still holds the old generated value, so delete it once you have changed the password.)
- **It survives rebuilds.** `users.mutableUsers` is left at NixOS's default of `true`, so a password set at runtime is not wiped by the next `ferrum-apply apply`.

This exists because it did not, and a real host was unreachable because of it: SSH stopped answering, the machine still reached its login prompt, and the prompt accepted nothing — root had no password and never had one. The only remaining route was editing the bootloader to boot `init=/bin/sh`, which then broke the USB keyboard, because that path never starts systemd and so udev never loads the HID driver. `a-host-always-has-a-way-in` in `nix/modules/flake/checks.nix` fails the build if ferrum ever ships that shape again.

### Reaching the dashboard when the proxy or Authelia is broken

ferrumd keeps listening on loopback (`ferrum.daemon.listenAddress`, `127.0.0.1` by default) whether or not it is published. Publishing means nginx reaches it, not that it binds a public interface — so the SSH tunnel remains the recovery route for exactly the situation where you need the UI most: the proxy is down, Authelia will not start, or a bad certificate has made `ferrum.<baseDomain>` unusable.

```bash
ssh -L 7788:127.0.0.1:7788 <host>
```

Then browse **`http://127.0.0.1:7788`** (or `http://localhost:7788`).

Forward to the **loopback address specifically**. The session cookie is `Secure`, and a browser will only store and send a `Secure` cookie over plain HTTP when the origin is *potentially trustworthy* — which, under [W3C Secure Contexts](https://www.w3.org/TR/secure-contexts/), `127.0.0.1` and `localhost` are and a LAN address such as `192.168.1.10` is not. So a tunnel forwarded to a LAN IP will log you out on every request: the browser drops the cookie, and it is correct to do so.

That is expected behaviour, not a bug, and the fix is to use the loopback address — **not** to drop `Secure` from the cookie. Weakening it would re-open the attack it exists to close (below), to save one word in an SSH command.

### What Authelia does and does not defend

Authelia issues **two** session cookies on a host that publishes the dashboard (`session.cookies`, `modules/proxy/authelia.nix`):

| Cookie | Scope | Issued at | Covers |
|--------|-------|-----------|--------|
| `authelia_session` | `<baseDomain>` | `auth.<baseDomain>` | every published catalog app |
| `ferrum_control_session` | `ferrum.<baseDomain>` | `auth.ferrum.<baseDomain>` | the control plane, and nothing else |

The first is what makes single sign-on single across the apps: log in once at `auth.<baseDomain>` and every app under that domain accepts you. The second is deliberately **not** part of that: it is a separate scope with a separate cookie name and a portal hostname of its own, so a cookie obtained in an app's context is not a cookie for the dashboard.

That separation is the fix for `SEC-M02` (`docs/security/SEC-M02_authelia-cookie-scope.md`), and it costs a second interactive login at the control plane — which is exactly what the risk acceptance said it would cost, and why it was deferred until something needed it.

Its price is also structural rather than optional. Authelia refuses an `authelia_url` that sits outside the cookie scope it serves, so the control plane's portal cannot be `auth.<baseDomain>`; it needs its own vhost (`modules/proxy/nginx.nix`), its own certificate (`modules/proxy/acme.nix`) and its own DNS record (`modules/proxy/dns.nix`). All four files are held in agreement by the `authelia-cookie-scope`, `daemon-vhost-enforced` and `dns-record-set` checks.

The consequence for the **apps** is worth stating plainly, because the natural assumption is the opposite one. **Within the base domain's own scope, Authelia defends against the unauthenticated stranger from the internet, and against nothing else.** A *compromised app already behind the same SSO* — a sonarr with a remote-code-execution bug, say — holds a cookie every other app under that domain accepts. Authelia is not a boundary between two apps on one base domain; it never was. What it is now is a boundary between the apps and the control plane.

Three things stand between a compromised sibling app and this host's settings, secrets and system generations:

- **The dashboard's Authelia cookie scope is not the apps'.** A sibling app's `authelia_session` is not a `ferrum_control_session`, so it does not clear the control plane's edge gate at all. This is the newest of the three and the only one of them that stops the request at nginx.
- **ferrumd serves no CORS headers at all.** No `Access-Control-Allow-Origin` means a script running on `sonarr.<baseDomain>` cannot *read* any response it provokes from `ferrum.<baseDomain>`. This is enforced by a test that fails if such a header ever appears, rather than by the fact that nobody has added one.
- **The session cookie is `__Host-ferrumd_session`, with `Secure`, `HttpOnly`, `SameSite=Strict` and `Path=/`.** `SameSite=Strict` stops a sibling origin's requests from carrying it; `HttpOnly` stops script from reading it; and the `__Host-` prefix makes browsers reject any version of that cookie sent with a `Domain` attribute — which is what stops a compromised sibling from *planting* a session cookie for the whole base domain and having ferrumd honour it.

ferrumd also requires its own valid session on every request regardless of what Authelia concluded, and it trusts no `Remote-User` header on any request it receives. Nothing on this host runs in a network namespace that would stop a local process from talking straight to `127.0.0.1:7788`, so a header set by nginx would be a header any compromised app could forge.

### Single sign-on for the dashboard

Where the dashboard is published and Authelia is on, `POST /api/sso` turns an Authelia login into a ferrumd session, so the control plane takes one login rather than two.

It does **not** work by trusting a forwarded identity header, for the reason in the paragraph above. ferrumd takes the cookie the caller presented and asks Authelia, over loopback, who it belongs to — so what a forger would have to produce is not a header but a valid Authelia session cookie **in the dashboard's own cookie scope**, which is the thing the two-cookie split above makes unobtainable from an app's context. The two halves are one feature: `crates/ferrumd/src/sso.rs` is only safe because `ferrum_control_session` exists.

That is measured rather than asserted. The `authelia-asserts-only-its-own-scope` check starts the real Authelia on the real generated configuration and proves five things on every build: the dashboard's own cookie is accepted at the dashboard's URL and names its user; **an apps-scoped cookie is refused there**; an anonymous request is refused; the same apps cookie still works at an app's own URL (so the refusal is about scope, not a dud cookie); and a cookie logged out at Authelia stops verifying.

Three consequences worth knowing:

- **A session obtained this way is re-checked against Authelia on every request.** Logging out of Authelia therefore stops it working immediately. The cost is one loopback round trip per API call, and a brief window of `503` while `authelia-main.service` restarts — a `503`, deliberately, never a `401`: Authelia being down must not look like your login failing.
- **An Authelia identity ferrum has no account for is refused, never provisioned.** `ferrum-apply` creates one ferrumd account and one Authelia account, both `admin`, so the matching case is the one ferrum builds. Auto-creating one would make Authelia's user database ferrumd's authorization source.
- **The SSH-tunnel recovery route is untouched.** A tunnel-only host (`ferrum.daemon.publish = false`) gets no `FERRUMD_SSO_ORIGIN`, so `POST /api/sso` answers `404` and the password login is all there is — which is exactly right for the way in you use when the proxy is broken. A password session never consults Authelia even on a host that has it.

## Dashboard API

Everything the UI does, it does through these. The authority is `build_router`
(`crates/ferrumd/src/main.rs`); this table is a hand-kept mirror of it, and nothing mechanical
checks that the two agree — so where they disagree, the router is right.

| Method | Path | What it does | Auth |
|--------|------|--------------|------|
| POST | `/api/login` | Exchanges a username and password for a session cookie and a CSRF token | none |
| POST | `/api/logout` | Clears the session | none (see `logout_is_still_unguarded_and_the_ui_still_depends_on_that`) |
| POST | `/api/sso` | Exchanges an Authelia session for a ferrumd one. `404` where single sign-on is off, `401` where Authelia recognises nobody, `403` where it recognises somebody ferrum has no account for, `503` where it cannot be reached | an Authelia cookie in the dashboard's own scope — verified by asking Authelia, never by reading a header |
| GET | `/api/session` | The current session's user and CSRF token | session |
| POST | `/api/password` | Changes the signed-in user's password | session + CSRF |
| GET | `/api/catalog` | The app catalog and the settings JSON Schema the UI renders its form from | session |
| GET | `/api/settings` | The host's current `settings.json` | session |
| PUT | `/api/settings` | Replaces `settings.json` after schema validation | session + CSRF |
| POST | `/api/secrets/:name` | Writes one sops-encrypted secret | session + CSRF |
| GET | `/api/generations` | The system generations and their snapshots, for rollback | session |
| GET | `/api/updates` | The most recent update-check report, or `?job=<uuid>` for one run's own | session |
| POST | `/api/jobs` | Starts a privileged `ferrum-apply` job | session + CSRF |
| GET | `/api/jobs` | Recent jobs (`?limit=`) | session |
| GET | `/api/jobs/:id` | One job's summary and its progress events | session |
| GET | `/api/jobs/:id/stream` | That job's progress as server-sent events | session |

`GET /api/updates` serves a document ferrum-apply's `check_update` job wrote; ferrumd only reads
it, and runs no `nix` of its own. It answers `200` with
`{"status":"report","jobId":...,"report":{...}}`, or `200` with
`{"status":"never-checked","jobId":null,"report":null}` on a host where no check has ever run —
an explicit state rather than an empty body, so the UI can tell "never checked" from "checked,
and up to date". Reports are read from `FERRUM_UPDATE_REPORT_DIR`, falling back to
`FERRUM_JOBS_DIR` and then to `/var/lib/ferrum/jobs`, which is where the job writes them today.

`POST /api/jobs` takes a body of exactly `{"kind": "<kind>"}` — `preflight`, `apply`, `rollback`
(plus `"to": <generation>`), `restore_state`, `gc`, `check_update`, or `update`. Every kind but
`check_update` claims the daemon's single-job interlock and gets `409` while one is running; the
read-only check is exempt because a rollback must never be blocked by one.

`update` is the commit path for an update: it advances the `ferrum` input in
`/etc/ferrum/flake.lock` with `nix flake lock --update-input ferrum` and then runs the ordinary
apply pipeline, as one action. It carries no fields — the repository and ref come from the
operator's own root-owned `/etc/ferrum/flake.nix`, which ferrumd cannot write and which this path
never writes either. It refuses, leaving `flake.lock` byte-for-byte untouched, when `/etc/ferrum`
has uncommitted changes, when the candidate is not strictly newer than what the host runs, when
the advance would repoint the input at a different repository, or when it lands on a revision
other than the one just resolved. When the advanced pin builds the closure already running,
`apply::run` returns early and the job reports "no change — nothing to apply": no new generation
was created, and none is claimed.

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
