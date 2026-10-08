# Media tree permissions

Why every app runs as its own user in one shared group, and what the other
two thirds of that recipe are.

## The recipe

TRaSH's recommended setup is "a separate user per app, all in one shared
group", with **`UMASK 002`** and a **setgid** tree. ferrum had the first part
and neither of the other two.

| Part | Where | What it decides |
|---|---|---|
| A user per app, all in `ferrum-media` | each `modules/apps/<id>/service.nix` | who may enter the tree |
| `UMask = "0002"` on each of those units | the same files | whether a new file is group-**writable** |
| `2775` (setgid) on every tree directory | `modules/core/storage.nix` | which **group** a new file gets |

Either of the last two alone leaves the same hole, which is why both landed
together.

## The failure it closes, and why nothing ever reported it

systemd's default umask is `0022`, and without setgid a directory inherits
the creating process's own primary group. So a finished job directory SABnzbd
created inside the download tree came out `drwxr-xr-x sabnzbd:sabnzbd`.

Sonarr is in `ferrum-media` but not in `sabnzbd`, so it could traverse and
read that directory. A **hardlink import therefore still succeeded** —
`link()` needs read on the source and write on the *destination* directory,
and `media/tv` was already group-writable. What Sonarr could not do was
unlink the download copy afterwards, because deleting needs write on the
**containing** directory.

So imports worked, and anything that asked an \*arr to clean up, upgrade in
place, or remove a failed import inside the download tree failed on
permissions. Nothing errored in a way an operator would see; undeletable
leftovers simply accumulated until a disk filled.

## Which units carry `UMask`, and which do not

The predicate is exactly the one each `service.nix` already uses to decide
media-group membership — `mediaAccess != "none"` — so there is one rule, not
a second list to keep in step:

- **With it:** `sonarr`, `radarr`, `sabnzbd`, `qbittorrent`, `plex`,
  `jellyfin`. All six join `ferrum-media`, and a unit in that group is a unit
  that creates files in the shared tree. That includes the media servers:
  Plex and Jellyfin write metadata, artwork and trickplay files beside the
  media, and a `0644 plex:plex` file in `media/movies` is one an \*arr cannot
  replace during an upgrade.
- **Without it:** `prowlarr` and `decluttarr`. Both have `mediaAccess =
  "none"`, neither joins the group, and neither touches the tree. Loosening
  the umask of a process that creates nothing shared would be noise with a
  security cost and no benefit.
- **Jellyfin needs `lib.mkForce`.** The upstream nixpkgs module sets
  `UMask = "0077"`, which is *stricter* than systemd's default and makes
  Jellyfin's writes into the shared tree unreadable by the group entirely.
  Dropping the `mkForce` is a hard evaluation error, not a silent revert —
  proved by mutation.

Nothing outside the app units is touched. `ferrum-reconcile`, `ferrumd` and
`ferrum-apply` run as root and write to their own state directories, not into
the media tree.

`checks.media-writers-share-their-group` asserts all of this against one real
host's **rendered** units and **rendered** tmpfiles rules — including the
negative control that an app with `mediaAccess = "none"` has no `UMask`, so
an "every app" rule could not pass by accident.

## Upgrading an existing host

`systemd-tmpfiles` re-applies the mode of a `d` rule to a directory that
already exists, and NixOS re-processes these rules on every
switch-to-configuration. So **the tree becomes setgid on the next apply, with
no operator action**, and every app restarts with its new umask at the same
time.

Both changes are **forward-only**: a umask applies to files created after it,
and setgid applies to directories created after it. Nothing already on disk
is modified, and no hardlink is disturbed.

That leaves whatever a pre-fix host already accumulated — job directories
owned `<client>:<client>` with mode `0755`, and files `0644` — still
undeletable by the other apps. ferrum does not fix those, and deliberately:
a recursive `chmod`/`chgrp` across a media library is slow, irreversible, and
would rewrite modes an operator may have set on purpose. If you have such
leftovers, the one-liner is yours to run and to scope:

```sh
# Inspect first. Only the DOWNLOAD tree -- never media/, which is the
# library and whose files the *arrs already own.
find /data/torrents /data/usenet -not -group ferrum-media -print | head

# Then, if that list is what you expect:
sudo chgrp -R ferrum-media /data/torrents /data/usenet
sudo chmod -R g+w /data/torrents /data/usenet
sudo find /data/torrents /data/usenet -type d -exec chmod g+s {} +
```

Do it while the download clients are stopped, and note that changing the mode
of a hardlinked file changes it for every name that file has — including the
library name, which is the point rather than a hazard here, but is worth
knowing before running it on anything else.
