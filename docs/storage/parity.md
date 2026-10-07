# Parity: what it protects, and how to restore from it

ferrum can protect its data disks with [SnapRAID](https://www.snapraid.it/) parity, so that losing
one disk loses nothing. This page is the operator's half: what parity does, what it does not, and
the exact steps to rebuild a disk when one dies.

## Parity is not a backup

Read this once before relying on any of it.

Parity lets ferrum **rebuild a data disk that failed**. It computes redundancy across the data
disks and stores it on a separate disk in the same machine. That is the whole of what it does.

It does **not**:

- undo a deletion — a file you remove is removed from parity at the next sync;
- survive a corruption that was synced before anyone noticed — the corrupted version becomes the
  protected version;
- survive ransomware, fire, theft, a power supply that takes the machine with it, or anything else
  that reaches the whole box, because the parity disk is **in** that box;
- protect anything written since the last sync. Between syncs, new files are unprotected. The
  Parity view reports exactly how many.

ferrum has no off-box copy of your library and does not claim to. If what is on these disks matters
to you, you still need one, kept somewhere else.

`ferrum-apply rollback` is not this either: it reverts a system generation, not a data-loss event.

## What ferrum configures

With `ferrum.storage.parity.enable` on and at least one disk named in
`ferrum.storage.parity.disks`, ferrum generates `/etc/snapraid.conf` through nixpkgs'
`services.snapraid`:

| Line | Where it comes from |
| --- | --- |
| `data d0 …`, `data d1 …` | `ferrum.storage.pool.branches`, or `ferrum.storage.mediaDir` on a host with no pool |
| `parity …` | `ferrum.storage.parity.disks` |
| `content …` | one per data disk, plus one on the OS disk under `/var/lib/ferrum/snapraid` |
| `exclude …` | the churning half of the TRaSH layout, computed from the live option values |

`modules/core/parity.nix` refuses at evaluation to let a disk be both a parity disk and a pool
branch. That configuration is not redundant capacity: it is capacity mergerfs and SnapRAID would
both be writing to, which invalidates the parity and leaves the library files stored there the only
ones on the host with no parity at all.

Two timers run, both deprioritised below anything a person is waiting for (`IOSchedulingClass=idle`,
`Nice=19`):

- `snapraid-sync` — nightly by default (`ferrum.storage.parity.sync.intervalMinutes`), and shortly
  after boot, so a library that changed while the machine was off is protected promptly rather than
  at the next calendar time.
- `snapraid-scrub` — weekly by default (`ferrum.storage.parity.scrub.intervalMinutes`). Scrub
  re-reads a percentage of already-synced data and checks it against the hashes recorded at sync.
  This is how silent corruption is found while parity can still repair it.

Either can be turned off (`…sync.enable`, `…scrub.enable`); a fully manual host is a supported
configuration. `ferrum-apply parity-sync` starts a sync by hand whatever the timers are doing.

## Checking the state

`ferrum-apply parity-status` prints the whole report, and the Parity view in the web UI renders it.
The states it distinguishes, and why each is its own:

| State | What it means |
| --- | --- |
| `not-configured` | no parity on this host |
| `never-synced` | parity is set up but has never completed a sync — **nothing is protected yet** |
| `syncing` | a sync is running right now |
| `in-sync` | every file is covered, and nothing has changed since |
| `stale` | files have changed since the last sync; those files are not protected |
| `last-sync-failed` | the last run did not succeed — parity is as old as the last one that did |
| `parity-disk-missing` | the parity disk is not mounted, so parity can rebuild nothing |
| `unknown` | the check did not complete. **This is not the same as being protected.** |

The changed-file figure comes from `snapraid diff` and is a count of **files**, not bytes: snapraid
reports no size figure, so ferrum shows none rather than estimating one.

---

## Procedure A — replacing a failed data disk

Use this when a whole disk has died or is being replaced.

1. **Check parity is current before you do anything else.**

   ```
   ferrum-apply parity-status
   ```

   Note the state and the last-sync time. Anything written since that sync is not in parity and
   will not come back. If the state is `last-sync-failed` or `unknown`, parity may be much older
   than the timestamp suggests.

   **Do not run a sync now.** A sync against a host with a missing disk records the disk as empty
   and destroys exactly the parity you are about to need.

2. **Physically replace the disk.** The replacement must be **at least as large** as the one it
   replaces. SnapRAID refuses a smaller one, and it is right to: the restore would be truncated.

3. **Format and mount it at the same path.** ferrum mounts data disks from
   `/etc/ferrum/custom/media.nix`, which is yours to edit; the mount point must be the same one
   `/etc/snapraid.conf` names for that disk, or SnapRAID will restore into the wrong place.

   ```
   lsblk -o NAME,SIZE,MODEL,SERIAL
   mkfs.ext4 /dev/disk/by-id/<the new disk>-part1
   # then point custom/media.nix at the new by-id path and apply
   ```

   Confirm the mount is up and that `/etc/snapraid.conf` still names it:

   ```
   findmnt /mnt/ferrum-disk-1
   grep '^data ' /etc/snapraid.conf
   ```

4. **Rebuild it from parity.**

   ```
   ferrum-apply parity-restore --disk d1 --confirm overwrite-d1
   ```

   The `--confirm` word names the disk, so an acknowledgement for one disk cannot authorise
   another. Without it the command prints what it would overwrite and does nothing. If parity is
   not current, it refuses again and tells you what you would lose; `--accept-stale` proceeds
   anyway, which is usually the right call — an older copy beats none — but it is your decision.

   The equivalent by hand, if you would rather run it yourself, is `snapraid fix -d d1`.

5. **Check the result.** The rebuild reports `0 unrecoverable errors` when it is complete. Spot-check
   a few files, then:

   ```
   ferrum-apply parity-sync
   ferrum-apply parity-status
   ```

   The sync after a restore is what re-establishes parity for the rebuilt disk.

### If it refuses

- **"a parity disk is missing"** — the parity disk is not mounted. Both a data disk and the parity
  disk being gone at once is the case parity cannot help with; restore from a real backup. Do not
  run a sync.
- **"the replacement is smaller"** — SnapRAID will say so, naming both sizes. Use a disk at least
  as large.
- **The content file is also unreadable** — ferrum writes a content file on every data disk and one
  on the OS disk, so losing one disk never loses the index. If the OS disk and a data disk are both
  gone, restore the OS from its own backup first.

---

## Procedure B — restoring individual files a scrub flagged as bad

Use this when `snapraid scrub` reported errors but every disk is present.

1. **Find out what is wrong.**

   ```
   snapraid -c /etc/snapraid.conf status
   ```

   The report names the number of errors and whether they are recoverable.

2. **Fix the specific files.** `snapraid fix` takes a filter, so a single bad file does not mean
   rewriting a disk:

   ```
   snapraid -c /etc/snapraid.conf fix -f /media/tv/Show/Season 01/episode.mkv -d d1
   ```

   The path is **relative to the data disk's root**, not absolute on the host — the same grammar
   `/etc/snapraid.conf`'s `exclude` lines use.

3. **Confirm it came back.** Compare a checksum against whatever you have — a copy elsewhere, the
   original download, a `*.sfv` — and re-run the scrub.

Files SnapRAID could not recover are renamed with a `.unrecoverable` suffix. ferrum excludes
`*.unrecoverable` from parity, so those markers are never themselves protected.

---

## Exercising this procedure

Procedure A's step 4 has been run for real against snapraid 12.4, on four separate ext4 filesystems
in the layout ferrum generates: a file was deleted from a data disk, `snapraid fix` was run as
documented, and the restored file's SHA-256 matched the original byte for byte. A parity system
nobody has restored from is a claim, not a feature.
