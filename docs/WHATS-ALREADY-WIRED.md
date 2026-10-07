# What ferrum already did for you

This page exists because the operator of a running ferrum host asked whether Prowlarr had been
connected to Sonarr and Radarr. It had — on every apply, eight registrations on that host, since the
day the apps were enabled. **Having to ask is the defect this page fixes.**

Everything below happens automatically. None of it is a step you perform, and none of it is
documented anywhere you would have had to find.

## The apps are connected to each other

`ferrum-reconcile` runs as a systemd oneshot after every apply and registers each app with the
others through their own APIs. The edges are **derived from the catalog**, not from a list in the
reconciler, so enabling or disabling an app changes the wiring with no code anywhere.

Each app declares what it consumes in its `meta.nix`:

| App | Consumes | Which produces |
|---|---|---|
| Sonarr | qBittorrent, SABnzbd | both registered as download clients in Sonarr |
| Radarr | qBittorrent, SABnzbd | both registered as download clients in Radarr |
| Prowlarr | Sonarr, Radarr | each registered as an **application**, so Prowlarr pushes indexers to them |
| Prowlarr | qBittorrent, SABnzbd | both registered as download clients in Prowlarr |
| qBittorrent, SABnzbd, Plex, Jellyfin | nothing | they are providers, not consumers |

There are exactly two registration kinds. Prowlarr registering Sonarr or Radarr is an
*application* — its own indexer push-sync feature. Every other edge is a *download client*. An edge
whose provider is not enabled is skipped, so a host running Sonarr without SABnzbd gets the
qBittorrent registration and nothing broken.

**On a host with all five enabled that is eight registrations**, and they are re-asserted on every
apply rather than only at install, so an app that forgets its configuration gets it back.

> `ferrum-reconcile` commonly **fails once per apply and succeeds on its automatic retry.** The
> apps are not listening yet when it first runs. That is designed behaviour, not a fault — if you
> see it in an apply's output, look at whether the retry succeeded before investigating.

## The apps and the storage agree about where media lives

Root folders and download paths are built from `ferrum.storage.mediaDir`, so the apps are told about
exactly the tree ferrum created:

| App | Gets | At |
|---|---|---|
| Sonarr | root folder | `<mediaDir>/media/tv` |
| Radarr | root folder | `<mediaDir>/media/movies` |
| qBittorrent | download path | `<mediaDir>/torrents` |
| SABnzbd | download path | `<mediaDir>/usenet/complete` |

Both trees are under one `mediaDir` on purpose: **a hardlink cannot cross a filesystem**, so a
download client writing somewhere else turns every import into a copy. Keeping them together is what
makes imports instant and space-free.

This also closed a real incident. The apps and the storage layer deriving these paths separately is
what once left every app pointed at an empty `/srv/media` while the media sat on unmounted disks.

## The rest, in brief

- **TLS certificates** are obtained and renewed per published app, over DNS-01.
- **DNS records** are created and corrected for every published app — see
  [`EGRESS.md`](EGRESS.md) for what that talks to and when. With the dynamic-address updater on,
  they follow your address when it changes.
- **Single sign-on** fronts the \*arr apps and the dashboard, through Authelia. Plex and Jellyfin
  are deliberately **not** behind forward-auth: they have their own clients and their own auth, and
  putting a media server behind a login portal breaks every TV app you own.
- **Secrets** are generated where ferrum can generate them, and encrypted at rest with sops.
- **Plex's claim token** is exchanged with the local Plex process at install, so the server comes up
  claimed rather than leaving you to visit a web UI.

## What is genuinely outside the standard setup

These need the `custom/` escape hatch — a directory of hand-written Nix in `/etc/ferrum` that the
web UI never touches and no update overwrites. **Anything you put there is evaluated with everything
else**, so it is a first-class part of your configuration rather than a patch applied over it.

| You want | How |
|---|---|
| An app ferrum's catalog does not have | A NixOS module in `custom/` |
| One app held at a specific version | `services.<app>.package = …` in `custom/` — this takes that app out of the shared pin rather than letting it move independently |
| A setting the schema does not expose | Set the underlying NixOS option in `custom/` |
| To change ferrumd's own port, listen address or subdomain | `custom/` only — the daemon cannot safely reconfigure its own listener from inside its own request |

**`/etc/ferrum` is a git repository and Nix silently ignores untracked files inside one.** An
untracked `custom/whatever.nix` does not fail loudly; it does not exist as far as evaluation is
concerned. Every change there ends in `git add`. This has bitten a real host: two sops secret files
sat untracked and declared, and the next apply would have evaluated a configuration without them.

## What ferrum does not do for you

Stated here so you find it on this page rather than at the worst moment:

- **There is no off-box backup.** Rollback is not backup — it restores a previous generation and its
  application state from snapshots on the same machine. A disk that dies takes the generations with
  it.
- **There is no parity today** (see the parity spec). mergerfs does not stripe, so a failed disk
  loses only what was on that disk and every surviving disk stays readable — but that is not parity,
  and nothing reconstructs what was lost.
- **Reaching your apps from inside your own LAN** depends on your router supporting NAT hairpin, and
  many do not. Test from mobile data, not from the machine next to the server.
