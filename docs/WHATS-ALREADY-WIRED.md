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
| Decluttarr | nothing *through the reconciler* | it has no API to register anything into; ferrum generates its whole configuration instead — see below |

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

## Decluttarr is configured entirely, and you never see a config file

Decluttarr clears downloads that cannot finish out of the Sonarr and Radarr queues — a torrent
stalled with no connections, a magnet whose metadata never arrives, a release the \*arr finished
downloading and then refused to import because what arrived was a `.exe` and not a video. It
removes the queue entry, blocklists the release so the next search finds a different one, and
deletes the partial files.

Upstream's instructions are to write a `config.yaml` naming each \*arr's URL and API key, and the
name your download client is registered under inside each \*arr. **On a ferrum host you write none
of it.** Every one of those facts is already ferrum's — the ports come from the catalog, the
addresses from the same place nginx and the reconciler read them, the API keys are the sops secrets
`ferrum-apply` already generated, and the download-client name is the literal `ferrum-reconcile`
posted into Sonarr and Radarr. Enabling the app is the whole of the setup.

It has **no web interface**, so it gets no subdomain, no certificate and no DNS record, and nothing
appears for it on your domain. It is the first app in the catalog like that; the mechanism is in
`modules/apps/decluttarr/meta.nix`.

**Watch it with `journalctl -u decluttarr -f`.** That is where it says what it removed and why.

The defaults are deliberately patient, because deleting a download somebody wanted is a far worse
failure than leaving a stuck one in the queue:

| Setting | ferrum's default | Upstream's | Why |
|---|---|---|---|
| Interval | 30 minutes | 10 | with the strike count below, something must look broken for ~2.5 hours |
| `max_strikes` | 5 | 3 | one bad observation is a tracker hiccup, not a dead download |
| Enabled jobs | 4 | none by default | only the ones that mean "this will never finish" |
| Import-failure patterns | 6 explicit ones | `*` (any warning) | `*` removes on a transient import warning too |
| Private trackers | removed from the **queue** only | deleted | the torrent stays in qBittorrent, so your ratio does not |
| Test mode | off | on | it is installed to do the job; the toggle is in the UI if you want to watch first |

Four jobs are on: `remove_stalled`, `remove_metadata_missing`, `remove_failed_downloads` and
`remove_failed_imports`. Everything else upstream offers is off, including `remove_orphans` (it
deletes anything the \*arrs do not know about, which includes whatever you added by hand),
`remove_bad_files` (it judges by file extension) and the two search jobs (they hammer indexers).

**The manual override is a tag.** Tag a torrent `Keep` in qBittorrent and Decluttarr will not touch
it, whatever state it is in.

Two things it deliberately does not do here. It is not told about **SABnzbd**: none of the four
enabled jobs needs a download client to act, and upstream sends the SABnzbd API key as a URL query
parameter and logs the failing URL verbatim, so configuring it would put that key in your journal
every time SABnzbd was briefly unreachable. And it is not registered with **Prowlarr**, which has no
queue for it to act on.

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
