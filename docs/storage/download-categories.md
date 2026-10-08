# Download categories

Where a completed download lands, who decides it, and what changes on an
existing host when that decision changes.

## The rule

A download client puts a finished job in a subdirectory named after the
**category** the \*arr tagged it with. ferrum creates one directory per
library category under each client's download root
(`modules/core/trash-layout.nix`), so the category and the directory have to
be the same string.

They now come from one place. Each app declares `mediaCategory` in its own
`modules/apps/<id>/meta.nix`; `modules/core/reconciler.nix` uses that single
attribute for **both** the app's root folder and the download-client category
it registers; and `trash-layout.nix` refuses to evaluate a catalog whose
`mediaCategory` is not one of the categories it creates directories for. The
flake check `category-and-directory-cannot-diverge` compares the two shipped
artifacts — the JSON `ferrum-reconcile` is handed, and the
`systemd-tmpfiles` rules that build the tree — on every CI run.

| App | Category | Torrents land in | Usenet jobs land in |
|---|---|---|---|
| Sonarr | `tv` | `<mediaDir>/torrents/tv` | `<mediaDir>/usenet/complete/tv` |
| Radarr | `movies` | `<mediaDir>/torrents/movies` | `<mediaDir>/usenet/complete/movies` |
| Prowlarr | *(none)* | `<mediaDir>/torrents` | `<mediaDir>/usenet/complete` |

Prowlarr is an indexer manager. It has no `mediaCategory` because it manages
no library, and its download-client registration exists for the Test button
and for interactive searches launched from its own UI. A grab made that way
belongs to no library, so no library category is true of it — giving it `tv`
would file a manually-grabbed album under television. With no category the
client's own default applies, which is the **root** of its download tree, and
ferrum creates that too.

## qBittorrent needs the category too

A category registered on the \*arr side only **tags** a torrent. For
qBittorrent to **route** it, the category has to exist in qBittorrent with a
save path — and two things were missing:

1. **No categories at all.** `categories.json` on the owner's host was empty.
   `ferrum-reconcile` now creates one category per consumer category, each
   saving to that category's directory under qBittorrent's own download root
   (`ensure_qbittorrent_categories`). Both halves come from values Nix already
   supplies — the pair's category and the download path — so the save path
   cannot drift from the directory the tree has.
2. **Manual torrent management.** With Torrent Management Mode left at
   qBittorrent's default of Manual, a categorised torrent still uses the
   global save path, so the categories would exist and route nothing. ferrum
   now sets `auto_tmm_enabled`.

Deliberately **not** set: `category_changed_tmm_enabled` and
`save_path_changed_tmm_enabled`, which decide whether qBittorrent *relocates*
torrents it already has when a path or category changes. Those move files on a
live host. `auto_tmm_enabled` governs newly added torrents only, so everything
already seeding keeps the save path it has and every hardlink an \*arr has
already made stays intact.

SABnzbd needs none of this: it was already given its category over the API
before each registration (`ensure_sabnzbd_category`), and it routes by
category unconditionally.

## Upgrading an existing host

Before this fix the categories were the \*arr app ids (`sonarr`, `radarr`,
`prowlarr`), so completed jobs went to `usenet/complete/sonarr` — a directory
ferrum never created — while `usenet/complete/tv` stayed empty.

The apps re-register on every `ferrum-apply`, so **the new categories take
effect on the next apply with no operator action.** What that means for work
already under way:

- **Nothing in flight breaks.** An \*arr tracks a download by the client's own
  id for it (SABnzbd's `nzo_id`, qBittorrent's infohash) and asks the client
  where the files are. It does not look in a category directory. A job queued
  under the old category completes into the old directory and imports
  normally.
- **Already-seeding torrents keep their save path.** A category only decides
  where a *newly added* torrent is saved, and ferrum does not turn on either
  of the preferences that would make qBittorrent relocate what it already
  holds. Existing torrents, and the hardlinks the \*arrs made from them, are
  untouched.
- **No migration is run, and none is needed.** What remains is cosmetic: the
  old `torrents/sonarr` and `usenet/complete/sonarr` directories (empty once
  their last job imports), and the stale `sonarr`/`radarr`/`prowlarr` category
  entries in SABnzbd's own config. ferrum does not delete either — removing
  directories under an operator's data root is not something it should do
  unasked. Delete them by hand once they are empty, or leave them.

### The one thing that *is* rewritten

Every registration here is idempotent **by name**, so once `qbittorrent`
exists in Sonarr no later apply touches it. That is the right behaviour for
values an operator may have tuned — and the wrong behaviour for a value
ferrum derives and then corrects, because it would mean this fix reached only
hosts that had never been set up.

So the reconciler now corrects **the category field, and only the category
field,** on a registration that already exists
(`registration_needing_category_fix`). Priority, enable, the completed-
download toggles, and anything else set by hand in the app's own UI are
returned unchanged. A registration whose category is already right produces
no write at all, so this does not become a PUT on every apply forever.
