# What leaves the machine

> Written 2026-10-06 against this repository at `3137e05`. Every row below was derived by reading
> this repo's own code and module tree, and each cites the `file:line` it came from. Where a claim
> could not be settled from these files it is marked **unverified** rather than guessed in either
> direction — a confidently wrong row here is worse than an absent one.

Self-hosting is a decision about who gets to see your traffic, so a project that asks you to run it
on your own hardware owes you a list. This is ferrum's.

## The short answer

**ferrum has no telemetry, no analytics, no crash reporting, no version ping and no usage
statistics.** Nothing in this repository sends anything anywhere for ferrum's benefit. There is no
ferrum-operated service of any kind: no registry, no index, no licence check, no update server.
Searching every crate and the whole module tree for `telemetry`, `analytics`, `sentry`, `posthog`,
`mixpanel`, `segment`, `amplitude`, `beacon`, phone-home and usage-statistic spellings — and the
dependency manifests for the matching crates — returns nothing. The only matches anywhere are three
lines that turn *other* software's analytics **off**:
`modules/apps/sonarr/service.nix:105`, `modules/apps/radarr/service.nix:83`,
`modules/apps/prowlarr/service.nix:83` — each `log.analyticsenabled = false`.

**The dashboard makes no external request at all.** `ui/` is five hand-written files with no build
step, no bundler and no npm; there is no CDN, no web font and no absolute URL anywhere in it
(`ui/index.html:6` states the invariant; a grep of `ui/` for any `http://` or `https://` returns
nothing). `nix/modules/flake/checks.nix:4486` enforces it mechanically — though only for
`ui/app.js`, not for all five files, which is a gap in the guard rather than in the invariant.

**ferrum never checks for its own updates on a schedule.** The entire module tree declares exactly
one systemd timer, and it is the optional dynamic-DNS updater (`modules/proxy/dns.nix:431`). An
update check happens only when an authenticated operator asks for one.

What ferrum *does* contact is unavoidable and small: your DNS provider, your certificate authority,
the Nix binary cache, and — only if you turn it on — three address-echo services. Everything else in
the table belongs to an application you asked ferrum to install, doing the job you installed it for.

## ferrum's own calls

"On by default" means: on a host configured the way `ferrum-install` sets one up, with no operator
override.

| Contacted | When | What is sent | On by default | Evidence |
|---|---|---|---|---|
| `api.ipify.org` | Once during install, **from the target box** over the installer's SSH session | A plain `GET`. Nothing is sent but the request; the point is that ipify sees the connection's source address and echoes it back. One source only here, not the three-way quorum used later | Yes — it always runs, but its answer is never auto-accepted: a non-routable or unparseable result is shown to you and you type the address yourself | `crates/ferrum-install/src/address.rs:50`, `:141`, `:264` |
| `1.1.1.1:443` and `8.8.8.8:443` | Once during install, **from your own machine**, not the target | A raw TCP connect and nothing else — no request body, no hostname, no TLS handshake payload. Raw addresses deliberately, so a broken resolver cannot be mistaken for a broken server | Yes, when a DNS answer with a discovered address exists | `crates/ferrum-install/src/verify.rs:485`, `:838` |
| Your own host's public address, port 80 | Once during install, **from your own machine** | One minimal HTTP `GET` with a `Host:` header, to prove the box is reachable from outside its own network | Yes, same condition as above | `crates/ferrum-install/src/verify.rs:422`, `:465`, `:793` |
| `api.cloudflare.com/client/v4` | Once at install (a dry run **before** anything is erased), then at the end of **every apply**, plus on the DDNS timer when that is enabled | Your scoped API token as a bearer header, and the records ferrum manages: each hostname it publishes, its target (your public IPv4 in `a` mode, or your CNAME target), `proxied: false`, and the comment `ferrum-managed` that marks the record as ferrum's | Yes, once `ferrum.proxy.dns.enable` is on. The option itself defaults to **off**; the installer turns it on when you give it a record target | `crates/ferrum-dns/src/client.rs:68`, `:246`–`:476`; `crates/ferrum-apply/src/apply.rs:445`, `:543`; `crates/ferrum-install/src/dns.rs:827`; `crates/ferrum-dns/src/lib.rs:198`; `modules/core/options.nix:284` |
| **Let's Encrypt** (`acme-v02.api.letsencrypt.org`, or the staging directory when `ferrum.proxy.acme.staging` is set) | Certificate issuance, then renewal on `security.acme`'s own schedule | The ACME account email you gave (`ferrum.proxy.acme.email`), and **every hostname ferrum publishes** — one certificate order per public vhost. The challenge is DNS-01, so lego also writes `_acme-challenge` TXT records through the same Cloudflare token | Yes, on any host that publishes an app or the dashboard | `modules/proxy/acme.nix:57`, `:161`–`:211` |
| Your zone's **authoritative nameservers** | After a record write during an apply | A DNS query for the name just written, via `dig +short` sent directly at the zone's own nameservers rather than a recursive resolver — so a negative cache entry cannot report a fresh record as missing | Yes, when DNS management is on | `crates/ferrum-dns/src/dns_query.rs:1`–`:52`; `modules/proxy/dns.nix:417` |
| `one.one.one.one` (Cloudflare), `checkip.amazonaws.com` (Amazon), `api.ipify.org` (ipify) | Hourly by default once the DDNS updater is enabled, 5 minutes after each boot, and at the end of every apply | A plain `GET` to each, no credentials. All three companies learn this host's public address and that it asked. Three sources, three different operators, because one witness that is wrong — or compromised — would republish every one of your hostnames at somebody else's server | **No.** `ferrum.proxy.dns.ddnsUpdater.enable` defaults to `false` | `crates/ferrum-dns/src/public_ip.rs:164`; `modules/core/options.nix:397`, `:434`; `modules/proxy/dns.nix:341`, `:431` |
| **Whatever git forge your `/etc/ferrum/flake.nix` names** — `github.com` for the default `github:owner/repo` form | Only when an operator explicitly starts a `check_update` job, through the API or `ferrum-apply check-update`. **No timer ever fires it** | A `git ls-remote -- <url> <ref>` ref query, then `nix flake metadata --no-write-lock-file` on the candidate revision. No credentials (any userinfo in the URL is stripped before anything is built or logged), no host identity, no machine fingerprint. What the forge learns is that an address asked about this repository at this ref, and when | The capability is always present; it never runs unattended | `crates/ferrum-apply/src/update_candidate.rs:178`, `:408`, `:525`, `:606`; `crates/ferrumd/src/jobs.rs:71`; `modules/proxy/dns.nix:431` is the only timer in the tree |
| `cache.nixos.org`, and the forges hosting the flake inputs | Every `nix build` — so every apply, every update, and the install itself | Store-path hashes being asked for, and flake input fetches. **ferrum configures no substituters of its own**: `modules/core/nix-settings.nix:14` sets only `experimental-features`, so a host uses NixOS's stock default cache unchanged. Change it in `custom/` if you would rather it went elsewhere | Yes — unavoidably, this is how a NixOS system is built | `crates/ferrum-apply/src/apply.rs:410`; `modules/core/nix-settings.nix:14`; `flake.nix:5`–`:27` |

Two notes on that list.

**The Cloudflare records are grey-cloud, always.** `proxied = false` on every record ferrum writes
(`modules/proxy/dns.nix:53`, `crates/ferrum-dns/src/record.rs:43`), which means your real public
address is in public DNS rather than hidden behind Cloudflare's edge. That is deliberate and the
reasoning is recorded where the decision lives: the orange cloud makes every request arrive from a
Cloudflare address, which inverts nginx's `allow <trusted network>; deny all;` into a total outage
for exactly the apps that restriction protects, and streaming Plex or Jellyfin through Cloudflare's
edge is a bandwidth and terms-of-service problem. The cost is that your address is public. If you
would rather pay the other price, the record is yours to turn orange — ferrum will report the drift
and correct it back, so you would also need to take that name out of ferrum's hands.

**Authelia sends no mail.** Its notifier is the filesystem, not SMTP
(`modules/proxy/authelia.nix:108`), because ferrum assumes you have no mail server. Password-reset
notifications are written to a file on the box. *Unverified:* ferrum sets no `ntp` block for
Authelia, and Authelia upstream performs a time-sync check of its own at startup. Whether the
pinned version does so, and against which server, was not established from this repository.

## The apps' own calls — these are not ferrum's

Everything below is an application doing the job you installed it to do. ferrum configures the ones
marked as configured and leaves the rest entirely alone. **Every app is off by default**
(`modules/lib/app-submodule.nix:22`); the installer enables the ones you choose.

| App | What it contacts | What ferrum does about it | Evidence |
|---|---|---|---|
| **Plex** | `plex.tv`, to exchange your claim token for an account association, and thereafter whatever Plex's own software does | ferrum never talks to `plex.tv`. You paste a claim token; it is stored as a sops secret and `POST`ed to **`http://127.0.0.1:<plex port>/myplex/claim`** — the local Plex process makes the outbound call itself. Plex's ongoing calls — remote-access heartbeats, update checks, usage reporting — are **unverified**: the NixOS module exposes no switch for them and ferrum sets none | `crates/ferrum-reconcile/src/main.rs:485`; `modules/core/reconciler.nix:123`; `modules/apps/plex/service.nix:48` |
| **Sonarr, Radarr** | Metadata services (Skyhook/TheTVDB, TMDB), your indexers via Prowlarr, your download clients | ferrum **disables their analytics** and **disables their self-update** (`update.mechanism = "external"` — on NixOS the package is the update mechanism). What they fetch for metadata is the app's own behaviour and ferrum configures none of it — **unverified** in detail | `modules/apps/sonarr/service.nix:105`–`:106`; `modules/apps/radarr/service.nix:83`–`:84` |
| **Prowlarr** | The indexers and trackers you add to it | Same two switches off. **ferrum seeds no indexer** — nothing in `modules/` or `crates/` names one; every indexer on a ferrum host was added by its operator at runtime | `modules/apps/prowlarr/service.nix:83`–`:84` |
| **SABnzbd** | Your Usenet provider | Nothing. ferrum sets no outbound-affecting option for SABnzbd at all, and does not know who your provider is. Whether SABnzbd itself checks for updates is **unverified** | `modules/apps/sabnzbd/service.nix`, `meta.nix` — no such setting present |
| **qBittorrent** | Trackers, DHT and peers | **Only through the VPN**, when you have declared a `qbittorrent-vpn` secret. The app is `setns`'d into a dedicated network namespace whose only default route is the WireGuard interface, so if the tunnel drops it has no route out — a kill switch enforced by the kernel, not by the application. Its resolver comes from the `DNS=` line of your own WireGuard config and is left **empty** if there is none, so name resolution fails closed rather than falling back to the host's resolver. **Read this next line carefully:** with no `qbittorrent-vpn` secret declared there is no namespace and no kill switch — qBittorrent then uses the host's ordinary network like any other app | `modules/apps/qbittorrent/service.nix:11`, `:93`–`:259`, especially `:171`, `:191`, `:218`, `:258`; `modules/apps/qbittorrent/meta.nix:77` |
| **Jellyfin** | Metadata providers | Nothing. ferrum sets no outbound-affecting option; its settings schema is empty. **Unverified** what Jellyfin does on its own | `modules/apps/jellyfin/service.nix:9`–`:28`; `modules/apps/jellyfin/meta.nix:71` |
| **Recyclarr** (optional) | TRaSH-Guide data | **Off by default** (`ferrum.recyclarr.enable`). ferrum configures only `quality_definition`, which this repo's own note says uses tables bundled with the package rather than a live lookup, and talks to Sonarr and Radarr over loopback. Custom formats, which would need real TRaSH GUIDs, are deliberately out of scope. Whether `recyclarr sync` reaches the TRaSH repository anyway is **unverified**; so is its schedule, which ferrum does not set and which falls through to the nixpkgs module's own default | `modules/core/recyclarr.nix:10`–`:17`, `:33`–`:47`; `modules/core/options.nix:467` |

## What this page does not cover

- **The applications' internals.** Where a row says *unverified*, it means exactly that: nobody read
  the upstream source to settle it. Several of these programs are large and move quickly, and a
  claim about their default behaviour that was true when this was written is not a claim this
  repository can keep true.
- **Inbound traffic.** This is a list of what leaves; what reaches the box, and what it discloses
  when it answers, is the README's own subject.
- **Your own additions.** Anything you put in `custom/` is outside everything written here.

## One thing a certificate discloses, forever

ferrum obtains a real Let's Encrypt certificate for **each hostname it publishes** — `sonarr.`,
`radarr.`, `qbittorrent.`, `ferrum.`, `auth.` and the rest. Every certificate any public CA issues
is submitted to **Certificate Transparency logs**, which are public, append-only and permanently
searchable by anyone. There is no opt-out and nothing can be withdrawn once logged.

So anyone who knows your domain — or who is simply watching the CT firehose for newly issued names —
can read off exactly which media-automation stack runs there, and roughly when you installed it.
DNS does not give that away, because a resolver answers only names you already know to ask for;
CT hands over the list.

This is not a flaw in Let's Encrypt and it is not unique to ferrum. It is the price of a publicly
trusted certificate, and it is worth knowing before you publish an app rather than after.

**ferrum could publish less than it does.** Because it validates with DNS-01 rather than HTTP-01, a
single wildcard certificate is available to it, which would put only `*.<yourdomain>` in the logs
instead of every app name. That is a real trade with real costs on both sides, and it has not been
made: today's per-hostname behaviour is a decision that was arrived at rather than chosen. The
evidence, the arithmetic and a recommendation are in
[`docs/CERTIFICATE-TRANSPARENCY.md`](CERTIFICATE-TRANSPARENCY.md).

**The practical advice in the meantime** is the one Silo's own documentation gives about Tailscale
hostnames, and it applies here unchanged: the names you publish are names other people will read, so
choose a domain you do not mind being associated with what runs on it. Nothing about an app's
hostname is private, including the fact that it exists.
