# TRaSH Guides

> Analysed 2026-10-07. Site <https://trash-guides.info>, source
> [`TRaSH-Guides/Guides`](https://github.com/TRaSH-Guides/Guides) (3,198 stars, last pushed
> 2026-09-28), **MIT licensed** — unlike Perfect Media Server's CC BY-NC-SA, TRaSH's text can be
> quoted and adapted into ferrum's own docs with attribution and no share-alike obligation. Worth
> knowing: the recommended naming schemes and folder tree are *copyable*.
>
> This is not a competitor analysis. TRaSH Guides installs nothing and competes for nothing. It is
> the de-facto standard configuration reference for the \*arr stack, which means it is the document
> every ferrum operator will read **second**, and the one they will believe when it disagrees with
> us.

## Verdict: ferrum implements TRaSH's hard part and skips TRaSH's easy part

The expensive, irreversible, "you will not notice it is wrong for six months" half of TRaSH — one
filesystem, one root, downloads and library as siblings, stable inodes across a union mount — ferrum
gets **right, deliberately, and with the failure it is avoiding written down in the source**. The
cheap, per-app, "ten checkboxes in a web UI" half — naming schemes, quality profiles, custom
formats, permissions hygiene, qBittorrent seeding limits — ferrum mostly **does not touch at all**,
and relies on upstream defaults that in two measurable cases are not what TRaSH recommends.

That is an unusual and mostly defensible shape. But it has one real hole (permissions/umask) and one
real omission with a cheap fix already half-installed (naming, via Recyclarr's `media_naming`).

---

## 1. Hardlinks and atomic moves — the paths hold, the permissions do not

### What TRaSH requires

> "You CAN'T hardlink across separate file systems, partitions, volumes or mounts"
> — [Hardlinks and Instant Moves](https://trash-guides.info/File-and-Folder-Structure/Hardlinks-and-Instant-Moves/), fetched 2026-10-07

and, on the same page, the half that is easy to miss:

> "Hardlinks and instant (atomic) moves require all paths to be on **one filesystem**, but they also
> depend on **permissions**. … every app must be able to read — and the apps that import, upgrade,
> or delete must be able to write — each other's files."

with two sanctioned setups, of which TRaSH prefers the first:

> "a separate user per app, all in one shared group" with "UMASK 002" → "folders `775`
> (`drwxrwxr-x`), files `664`"

### The filesystem half: ferrum passes, and knows why

`modules/core/options.nix:69-80` defines `mediaDir` as *"The single root under which downloads AND
media both live"*, and states the reason inline — *"a hardlink cannot cross a filesystem"*.
`modules/core/storage.nix:135-147` creates the whole tree under that one root, and records the
regression that produced the rule:

> "The old layout put downloads on the OS disk while media lived on the data disks, so imports
> degraded to copies -- silently, and invisibly until a library was large enough for the duplication
> to show."

The download clients are then *driven to that root through their own APIs* rather than left on
their defaults: `modules/core/reconciler.nix:100-112` builds `downloadPaths` from `mediaDir`, and
`crates/ferrum-reconcile/src/main.rs:329-392` sets qBittorrent's `save_path` and SABnzbd's
`complete_dir`/`download_dir` over the API, bailing out loudly if the directory does not exist. The
catalog records the rule at each client too (`modules/apps/qbittorrent/meta.nix:16-23`,
`modules/apps/sabnzbd/meta.nix:16-24`).

On a pooled host this is better than TRaSH's own advice contemplates. `modules/core/pool.nix:105-109`
sets mergerfs `use_ino` explicitly, with the right justification — *"The \*arrs compare inodes to
detect hardlinks, so this is what makes a hardlinked import recognisable as one rather than as a
duplicate"*. TRaSH assumes a single real filesystem and has nothing to say about a union mount;
ferrum is operating one filesystem *above* the layer TRaSH stops at, and has handled it.

**And ferrum structurally cannot have TRaSH's single most common support problem.** Remote Path
Mappings exist because the download client and the \*arr see different paths inside different
containers. ferrum runs these as native systemd services on one host, so every app sees the identical
absolute path and the whole category of bug is unreachable. That is a genuine architectural win worth
saying out loud in ferrum's own docs.

### The \*arr-settings half: correct by upstream default, undefended by ferrum

ferrum sets **no** Sonarr/Radarr media-management configuration at all. Grepping the repository for
`copyUsingHardlinks`, `mediamanagement`, `enableCompletedDownloadHandling` and `importExtraFiles`
across `modules/`, `crates/` and `ui/` returns nothing; `crates/ferrum-reconcile/src/main.rs` touches
only `/api/v3/rootfolder`, `/api/v3/downloadclient` and `/api/v1/applications`.

Checked against Sonarr's own source rather than assumed
([`ConfigService.cs`](https://raw.githubusercontent.com/Sonarr/Sonarr/develop/src/NzbDrone.Core/Configuration/ConfigService.cs),
fetched 2026-10-07):

| Setting | Sonarr default | TRaSH wants | ferrum sets |
|---|---|---|---|
| `CopyUsingHardlinks` ("Use Hardlinks instead of Copy") | `true` (line 206) | on | nothing |
| `EnableCompletedDownloadHandling` | `true` (line 136) | on | nothing |
| `ImportExtraFiles` | `false` (line 234) | operator preference | nothing |

**So the hardlink story does hold end to end today** — paths on one filesystem, inodes stable across
the pool, and the two \*arr settings that matter defaulting the right way upstream. It holds by
*coincidence of defaults*, not by anything ferrum asserts. An operator who toggles "Use Hardlinks
instead of Copy" off, or an upstream release that flips the default, degrades every import to a copy
and ferrum will neither prevent it nor report it. That is precisely the failure class
`storage.nix:140-143` was written to kill, left open one layer up.

### The permissions half: this is the real defect

ferrum has TRaSH's *recommended* shape half-built. Each app runs as its own user
(`modules/apps/sonarr/service.nix:83-84`, `radarr/service.nix:62-63`, `sabnzbd/service.nix:44-45`,
`qbittorrent/service.nix:29-30`) and each is added to one shared media group
(`sonarr/service.nix:110-111` and the identical lines in the other three). That is exactly
"a separate user per app, all in one shared group".

What is missing is the other two thirds of that recipe:

- **No `UMask`.** No app unit sets one; grepping `modules/` for `UMask` returns only unrelated
  `ReadWritePaths` hits. systemd's default is `0022`, so SABnzbd and qBittorrent create files `0644`
  and directories `0755` owned by `sabnzbd:sabnzbd` / `qbittorrent:qbittorrent`.
- **No setgid on the tree.** `modules/core/storage.nix:214` and the `concatMap` at `:216-218` create
  every directory `0775`, not `2775`. Without setgid, a directory a download client creates inside
  `usenet/complete/` or `torrents/` inherits the client's *primary* group, not `ferrum-media`.

The consequence is specific. Sonarr is in `ferrum-media` but not in `sabnzbd`. A finished job
directory created by SABnzbd is `drwxr-xr-x sabnzbd:sabnzbd`. Sonarr can traverse and read it, so a
**hardlink import still succeeds** — `link()` needs read on the source and write on the destination
directory, and `media/tv` is `0775 root:ferrum-media`. But Sonarr **cannot unlink the download copy
afterwards**, because deleting requires write on the *containing* directory, which it does not have.
Anything that asks an \*arr to clean up, upgrade in place, or delete a failed import inside the
download tree fails on permissions.

TRaSH names `UMASK 002` for exactly this and names the per-app-user-in-a-shared-group layout as the
setup it goes with. ferrum adopted the layout and not the umask. **This is an accident, not a
decision** — nothing in the repository argues for 022, and the group plumbing only makes sense if
the intent was shared write.

---

## 2. Folder structure — identical, down to the subdirectory list

TRaSH's recommended tree
([File and Folder Structure](https://trash-guides.info/File-and-Folder-Structure/) and the
[native setup page](https://trash-guides.info/File-and-Folder-Structure/How-to-set-up/Native/),
both fetched 2026-10-07):

```
data
├── torrents/{books,movies,music,tv}
├── usenet/{incomplete, complete/{books,movies,music,tv}}
└── media/{books,movies,music,tv}
```

ferrum's, from `modules/core/trash-layout.nix:13` (`categories = [ "movies" "tv" "music" "books" ]`)
and `:41-45`:

```nix
subdirs =
  [ "torrents" "usenet" "usenet/incomplete" "usenet/complete" "media" ]
  ++ lib.concatMap
    (cat: [ "torrents/${cat}" "usenet/complete/${cat}" "media/${cat}" ])
    categories;
```

**This is TRaSH's tree exactly**, under `mediaDir` instead of `/data`, which is a parameterisation
rather than a difference. The file is even named after the guide, and its header says so.

ferrum additionally derives the SnapRAID exclusion list from the same definition
(`modules/core/parity.nix:147`, `churnExcludes = map (sub: "/${sub}/") layout.churn`), with
`trash-layout.nix:20-29` recording a real `snapraid 12.4` experiment proving that excluding the
download names costs no protection for an imported file, because the hardlinked `media/` name is the
one taken into the array. **That is a use of the TRaSH layout TRaSH itself never contemplated**, and
it is the best thing in this comparison.

### One consequential mismatch: the category directories are decorative

ferrum creates `torrents/tv`, `usenet/complete/movies` and so on — and then names the download-client
categories after the **consumer app id**, not the media category.
`crates/ferrum-reconcile/src/main.rs:682-688` sets `tvCategory`/`movieCategory`/`category` to
`consumer_id`, i.e. the literal strings `"sonarr"`, `"radarr"`, `"prowlarr"`; and
`:645-653` creates the SABnzbd category with `name = "sonarr"` and `dir = "sonarr"`.

So in practice:

- SABnzbd writes completed Sonarr jobs to `<mediaDir>/usenet/complete/sonarr`, a directory ferrum
  never created, while the `usenet/complete/tv` it *did* create stays empty.
- qBittorrent gets no category object created at all (it accepts arbitrary category strings), and
  its default Torrent Management Mode is Manual, so **every torrent lands flat in
  `<mediaDir>/torrents`** regardless of category. TRaSH is explicit about this:
  > "Ensure 'Torrent Management Mode' is set to 'Automatic' — Your downloads will not go into the
  > category folder otherwise."
  > — [qBittorrent Basic Setup](https://trash-guides.info/Downloaders/qBittorrent/Basic-Setup/), fetched 2026-10-07

**Severity: cosmetic for hardlinks, consequential for comprehensibility.** Everything stays on one
filesystem, so nothing degrades to a copy and parity exclusion still matches (both excludes are at
the `torrents/` and `usenet/` top level). What breaks is the promise the tree makes: an operator who
read TRaSH, then opened ferrum's `/data` and saw a complete, empty, correct-looking category tree
next to the real downloads piled somewhere else, would reasonably conclude ferrum had mis-wired
itself. Either name the categories `tv`/`movies` to match the tree, or stop creating the category
subdirectories.

---

## 3. What Recyclarr actually syncs for us — one of four things

`modules/core/recyclarr.nix` is real, uses nixpkgs' own `services.recyclarr`, wires the API keys
through sops correctly, and has a genuinely good assertion (`:60-80`) refusing to install a timer
that would succeed every run while syncing nothing.

It syncs **`quality_definition` and nothing else** — confirmed: the whole generated `configuration`
is `base_url`, `api_key._secret`, and `quality_definition.type` (`recyclarr.nix:33-48`). The
scoping is deliberate and the reasoning is in the file header:

> "Scoped to quality_definition only, not custom_formats -- quality_definition is real, documented,
> and self-contained … custom_formats entries need real TRaSH-Guide trash_id GUIDs this plan has no
> way to verify without fabricating them."

Against what Recyclarr can sync
([recyclarr.dev](https://recyclarr.dev/wiki/), fetched 2026-10-07):

| Recyclarr section | TRaSH content | ferrum today | Assessment |
|---|---|---|---|
| `quality_definition` | per-quality file-size floor/ceiling tables | **synced** (`recyclarr.nix:38,45`) | ✅ |
| `quality_profiles` | the guide's named profiles + CF scores, by `trash_id` | not synced | deliberate — needs real `trash_id`s |
| `custom_formats` | release-group / codec / unwanted scoring | not synced | deliberate, per the header |
| `media_naming` | the recommended naming schemes (see §4) | not synced | **this one is an accident** |
| `delete_old_custom_formats` | cleanup | n/a | n/a |

**What an operator gets today:** Sonarr and Radarr will stop accepting a 400 MB "1080p" file and
stop rejecting a legitimately large one, because the size tables are correct. That is genuinely the
single highest-value TRaSH item per line of config, and refusing to invent GUIDs is the right call —
a fabricated `trash_id` is a silent no-op or a wrong-scored profile, which is worse than nothing.

**What they do not get:** any scoring opinion at all. The profiles stay at Sonarr/Radarr defaults,
so grab decisions are "highest quality that fits the size table", with no preference for a good
release group, no penalty for a bad one, and no handling of the things custom formats exist for.
An operator who read TRaSH expecting ferrum's Recyclarr to mean "I have TRaSH's setup" has
substantially less than they think. The `enable` switch and the docs should say which third of TRaSH
it turns on.

**`media_naming` is the gap worth closing**, because it needs no GUID — it is a preset name, and
Recyclarr's own reference confirms the keys exist for both apps (`folder`, `rename`, `standard` for
Radarr; `series`, `season`, `rename`, `standard`, `daily`, `anime` for Sonarr) and that *"If a
configuration property is not specified, Recyclarr will not sync that setting"*
([media-naming reference](https://recyclarr.dev/wiki/yaml/config-reference/media-naming/), fetched
2026-10-07). The mechanism ferrum already ships would carry it.

---

## 4. Naming schemes — ferrum sets none, and the default is the exact trap TRaSH warns about

ferrum sets no naming configuration anywhere; the reconciler never touches `/api/v3/config/naming`.
So an operator gets Sonarr's built-in defaults, checked against Sonarr's own source
([`NamingConfig.cs`](https://raw.githubusercontent.com/Sonarr/Sonarr/develop/src/NzbDrone.Core/Organizer/NamingConfig.cs),
fetched 2026-10-07):

```csharp
RenameEpisodes = false,
MultiEpisodeStyle = MultiEpisodeStyle.PrefixedRange,
StandardEpisodeFormat = "{Series Title} - S{season:00}E{episode:00} - {Episode Title} {Quality Full}",
SeriesFolderFormat = "{Series Title}",
SeasonFolderFormat = "Season {season}",
```

versus TRaSH
([Sonarr recommended naming scheme](https://trash-guides.info/Sonarr/Sonarr-recommended-naming-scheme/),
fetched 2026-10-07), whose standard format carries quality source, release group, edition and media
info, whose season folder is `Season {season:00}`, and which requires "Rename Episodes" **on**.

TRaSH's stated reason is not aesthetics:

> Without detailed filenames containing quality source and release group information, users risk
> creating "download loops" where Sonarr cannot recognize already-owned files and re-downloads them
> during imports.

and for Radarr
([recommended naming scheme](https://trash-guides.info/Radarr/Radarr-recommended-naming-scheme/),
fetched 2026-10-07), the folder format carries `{tmdb-{TmdbId}}` so Plex and Jellyfin match the
right film and a re-import reconstructs the library.

Three of these matter to ferrum specifically:

1. **`RenameEpisodes = false` means ferrum's library keeps raw release names.** The operator's
   `media/tv` fills with `Show.S01E01.1080p.WEB-DL.DDP5.1.H.264-GRP.mkv`. ferrum then points Plex at
   that directory (`modules/core/reconciler.nix:130-131`) and relies on Plex's matcher coping.
2. **No `{tmdb-...}` / `{tvdb-...}` id in the folder name** is the single biggest cause of a media
   server mis-matching a film, and ferrum's whole pitch is "log in and everything is pre-set-up".
3. **`Season {season}` vs `Season {season:00}`** sorts `Season 10` before `Season 2` in most
   clients. Cosmetic, but it is the kind of thing an operator blames ferrum for.

**This is an accident, not a decision.** Nothing in the repository argues against setting naming,
and the one TRaSH mechanism ferrum already ships supports it without a single fabricated identifier.

---

## 5. qBittorrent and SABnzbd

| TRaSH recommendation | ferrum | Verdict |
|---|---|---|
| Save path under the shared root, never `/downloads` | `save_path = <mediaDir>/torrents` via API (`main.rs:351-363`) | ✅ matches |
| "Your Download and Media Library should be **NEVER** the same locations" | siblings under `mediaDir`, never the same (`trash-layout.nix:41-45`) | ✅ matches |
| Torrent Management Mode = Automatic, or categories do nothing | not set; qBittorrent default is Manual | ⚠️ categories are inert (see §2) |
| Incomplete/temp path for torrents: optional, "creates unnecessary moves on most systems" | not set — qBittorrent has no `downloadIncompleteSubdir` in its catalog entry | ✅ agrees with TRaSH's preference, apparently by accident |
| Disable ratio / seeding-time / inactive-seeding limits; use the \*arrs' indexer seed goals | not set either way; qBittorrent's defaults are already unlimited | ⚠️ aligned by default, nothing asserts it |
| SABnzbd incomplete + complete folders on the shared root | `download_dir = usenet/incomplete`, `complete_dir = usenet/complete` (`main.rs:365-392`, `sabnzbd/meta.nix:23-24`) | ✅ matches |
| **"MAKE SURE THAT SORTING IS ENTIRELY DISABLED"** | not set; SABnzbd's default is disabled | ⚠️ correct by default, undefended |
| SABnzbd `host_whitelist` must contain the hostname the \*arrs reach it by | **not set anywhere** — grep returns nothing | see below |

Sources: [qBittorrent Basic Setup](https://trash-guides.info/Downloaders/qBittorrent/Basic-Setup/),
[SABnzbd Basic Setup](https://trash-guides.info/Downloaders/SABnzbd/Basic-Setup/), both fetched
2026-10-07.

**On `host_whitelist`:** TRaSH calls it out because it is the classic "Starr app cannot reach
SABnzbd" failure. ferrum publishes SABnzbd under a subdomain through nginx, but the \*arrs reach it
at `http://127.0.0.1:8080` (`modules/core/reconciler.nix` builds `base_url` from `appHost`/`port`),
which SABnzbd permits, so the \*arr→SABnzbd path is fine. Whether a *browser* request arriving with
`Host: sabnzbd.example.com` is rejected by SABnzbd's own whitelist is **unverified** — I did not test
it and no ferrum code sets the key. It is worth an explicit check, because the failure mode is
"SABnzbd's web UI returns 'Access denied — hostname verification failed' behind the proxy", which
looks like a ferrum proxy bug and is not one.

---

## 6. Traps TRaSH names that ferrum could walk into

Ranked by how expensive they are to discover late.

1. **Permissions, as above.** TRaSH's `UMASK 002` sentence sits directly under the per-app-user
   recipe ferrum adopted. ferrum took the users and the group and left the umask. The failure is
   silent: imports work, cleanups do not.
2. **"Modifying any copy of a hardlinked file will impact all copies"** (Hardlinks and Instant Moves,
   fetched 2026-10-07). After a hardlink import the seeding torrent and the library file are one
   inode. Anything that rewrites in place — a tag editor, a subtitle muxer, a transcode-in-place
   script — corrupts the seeding torrent and can earn a tracker ban. ferrum ships none of those
   today, but it is a rule any future "fix my library" feature must respect, and it belongs in
   ferrum's own docs because ferrum is what made the hardlink happen.
3. **`moveonenospc=true` can break a hardlink.** `modules/core/pool.nix:101` relocates a file to
   another branch when a write runs out of space mid-file. A relocation across branches is a copy,
   not a move, so a file that was hardlinked into the library can end up with the two names on
   different branches and no longer sharing an inode — the duplication TRaSH's whole hardlink story
   exists to prevent, arriving by a route TRaSH never describes because TRaSH does not assume a union
   mount. **Unverified** against mergerfs documentation; flagged as reasoning from the option's own
   semantics, not as a confirmed behaviour. It deserves a real test.
4. **`epmfs` and hardlink placement.** mergerfs can only hardlink within one branch. ferrum's
   per-branch tree seeding (`modules/core/storage.nix:149-170`) means `media/tv` exists on every
   branch, so the link can always be made on whichever branch holds the download. **The seeding is
   load-bearing for hardlinks, not only for balance** — worth stating in that comment, which
   currently only justifies seeding on distribution grounds.
5. **Quality definitions without quality profiles is a partial opinion.** TRaSH's size tables assume
   the profiles and custom formats that go with them. Syncing one third produces a system with
   TRaSH's *limits* and Sonarr's *preferences*, which is coherent but is not "TRaSH's setup", and
   `ferrum.recyclarr.enable`'s description should not let an operator believe otherwise.
6. **No naming scheme plus Plex auto-library.** ferrum creates Plex libraries pointed at
   `media/movies` and `media/tv` (`reconciler.nix:130-131`) containing unrenamed release filenames.
   TRaSH's naming recommendation exists largely to make that pairing reliable.

---

## Ranked changes worth making

### Real defects

1. **Set `UMask = "0002"` on the media-touching app units and create the shared tree setgid
   (`2775`).** Evidence: TRaSH's per-app-user recipe requires `UMASK 002`
   (Hardlinks and Instant Moves, fetched 2026-10-07); ferrum sets no `UMask` anywhere in `modules/`
   and creates every tree directory `0775` at `modules/core/storage.nix:214,216-218`, while apps run
   with distinct primary groups (`sonarr/service.nix:83-84` and the three siblings). Without it an
   \*arr cannot delete inside a download directory its client created. Low risk, high value,
   fully declarative.
2. **Sync `media_naming` through the Recyclarr config ferrum already generates.** Evidence:
   Sonarr ships `RenameEpisodes = false` and a format with no release group
   (`NamingConfig.cs`, fetched 2026-10-07); TRaSH attributes download loops to exactly that
   (Sonarr naming scheme, fetched 2026-10-07); Recyclarr supports the section with preset values and
   no `trash_id` (media-naming reference, fetched 2026-10-07); `modules/core/recyclarr.nix:33-48`
   already emits `configuration` and only needs more keys. This closes the §4 gap with the
   mechanism already installed.
3. **Make the category names and the created directories agree.** Evidence:
   `crates/ferrum-reconcile/src/main.rs:682-688` and `:645-653` use `consumer_id`
   (`"sonarr"`/`"radarr"`) as the category, while `modules/core/trash-layout.nix:44` creates
   `torrents/tv`, `usenet/complete/movies` and friends. Pick one. Using the media category also
   makes the tree TRaSH readers expect the tree they actually get.
4. **Assert the two \*arr settings the whole storage design depends on.** Evidence: ferrum sets
   nothing (no `copyUsingHardlinks` hit anywhere in `modules/` or `crates/`), and relies on upstream
   defaults confirmed as `true` (`ConfigService.cs:136,206`, fetched 2026-10-07). The reconciler
   already speaks the \*arr API; `GET /api/v3/config/mediamanagement` and either enforce or report is
   a small addition. A dashboard line — *"imports are hardlinking"* — is the ferrum-shaped version of
   TRaSH's manual "check if hardlinks are working" page, and the same class of check as the parity
   staleness figure already proposed in the Perfect Media Server analysis.

### Preferences TRaSH holds that ferrum could reasonably decline

5. **Quality profiles and custom formats via Recyclarr.** The existing refusal to invent `trash_id`s
   is correct. The reasonable middle is to use Recyclarr's own **templates** (`include:`), which
   carry the ids upstream rather than in ferrum's source — but shipping a scoring opinion by default
   is a product decision, not a correctness one. Declining is defensible; what is not defensible is
   letting `recyclarr.enable` imply more than it does.
6. **qBittorrent Torrent Management Mode = Automatic.** Only worth doing if change 3 goes the
   category-path route. Flat downloads in one directory are not wrong.
7. **Seeding and ratio limits.** TRaSH says disable them in the client and use the \*arrs' indexer
   seed goals. ferrum's defaults already behave this way and ferrum ships Decluttarr for the related
   queue problem (`docs/WHATS-ALREADY-WIRED.md:67,95`). Documenting the position beats configuring
   it.
8. **SABnzbd `host_whitelist`.** Add only if the proxied-browser case is confirmed broken — see
   unverified, below.

---

## Unverified

Recorded rather than guessed:

- **SABnzbd `host_whitelist` behind ferrum's nginx.** Not tested. The \*arr→SABnzbd path uses
  `127.0.0.1` and is unaffected; the browser-with-a-subdomain-`Host`-header path is unknown.
- **mergerfs `moveonenospc` versus an existing hardlink** (§6.3). Reasoned from the option's
  semantics, not confirmed against mergerfs documentation or a test.
- **Radarr's own `NamingConfig` defaults.** Sonarr's were read from source; Radarr's were inferred
  from parallel structure and TRaSH's page, not fetched.
- **The Servarr wiki's own stated defaults.** `wiki.servarr.com/sonarr/settings` renders
  client-side and returned only a title; the defaults cited here come from Sonarr's source instead,
  which is a stronger citation but means the *wiki's* wording is unquoted.
- **TRaSH's SABnzbd "Paths and Categories" page**, which the Basic Setup page defers to for the
  category/folder convention, was not fetched. If it names `tv`/`movies` as the category names, that
  strengthens change 3; if it names something else, change 3 should follow it.
- **Whether TRaSH's qBittorrent page recommends a specific category→save-path mapping** beyond
  "Automatic mode". Not retrieved in detail.

## Corrections to assumptions this analysis started from

| Assumed | Found |
|---|---|
| ferrum's hardlink story might be broken at the path layer | **It is not.** One root, siblings under it, clients driven to it by API, `use_ino` on the pool, and no remote path mappings possible. This is the strongest part of ferrum's app layer. |
| Recyclarr means ferrum broadly "has TRaSH" | **One section of four.** `quality_definition` only, deliberately — but `media_naming` was left out for no stated reason and needs no `trash_id`. |
| TRaSH is CC BY-NC-SA like Perfect Media Server | **MIT.** Its tree and naming formats can be adapted into ferrum's docs with attribution. |
| The \*arr-side hardlink settings would be the gap | **The permissions are the gap.** The \*arr settings default correctly; the umask does not. |
