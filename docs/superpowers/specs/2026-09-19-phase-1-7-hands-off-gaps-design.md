# Phase 1.7 — the gaps between "installed" and "hands off"

**Status:** requirements settled -- every open question OQ1-OQ8 is answered inline. Not yet
through the planning review gate; no implementation until that runs.

## Why this exists

Phase 1.6a's installer was exercised end to end against real hardware on 2026-09-19. It produced a
booted host with seven apps, Authelia, nginx, real Let's Encrypt certificates and completed
cross-app registration — and the operator still could not use it without a list of manual steps.

That list is the subject of this spec. The owner's standing requirement is explicit:

> this is supposed to be a HANDS OFF installer so that people don't get bogged down and confused
> like Saltbox

So each item below is treated as unfinished work, not as documentation. The test applied
throughout: *from a bare machine, does the operator reach a working, published, logged-in system
without being told to do anything by hand?*

What was actually left manual after a "successful" install:

| # | Manual step the operator was handed | Root cause |
|---|---|---|
| 1 | Create DNS records for every app | ferrum creates none |
| 2 | Claim Plex; click through Jellyfin's mismatch | reinstall discards app identity |
| 3 | Pool the data disks | no pooling feature |
| 4 | Find the generated SSO/UI passwords | only printed in a report that never ran |
| 5 | Re-trigger ACME after fixing a credential | orders are oneshot and "succeed" self-signed |

---

## R1 — ferrum creates and owns the DNS records for what it publishes

**User story.** I set a base domain. Every app I enable becomes reachable at its hostname without
me touching a DNS console.

**Why this is not optional.** `auth.thesyms.ca` did not resolve after the install, so single
sign-on — the gate in front of every *arr — was unreachable. The other hostnames worked only
because records predating ferrum happened to exist. On a genuinely new domain nothing would have
resolved, while the installer reported success.

**A correction worth recording,** because it changes the design: the Cloudflare credential *does*
work. lego used it to create and remove `_acme-challenge` TXT records, which is why certificates
issued. There is no broken API mechanism — there is no A/CNAME mechanism at all.
`grep -rn "dns_records" modules/ crates/` returns nothing.

**Acceptance criteria.**
- A1. With `ferrum.proxy.baseDomain` set, ferrum ensures one record per published app, plus `auth`
  when SSO is on and the daemon's own `subdomain`.
- A2. The record target is a decision, not an assumption. Support **A to a stated public address**
  and **CNAME to a stated hostname**, configured once. A home server behind a dynamic address needs
  the CNAME form (or a dynamic updater); a static address needs A. Guessing wrong publishes an app
  at an address that is not the server.
- A3. **Never silently overwrite a record ferrum did not create.** An existing `plex.thesyms.ca`
  pointing somewhere deliberate must be reported and left alone unless the operator opts in.
  Adoption is explicit.
- A4. Records are reconciled, not created once: enabling an app later creates its record, disabling
  it removes the record ferrum created. Ownership is tracked so removal never deletes a
  pre-existing record.
- A5. The credential is the one already collected. Its required scope becomes `Zone:Read` +
  `DNS:Edit`, which is what the installer already asks for — verify at collection time that the
  token can actually list the zone, and fail at the prompt rather than after the install.
- A6. **Split-horizon is out of scope and must be said so.** Records point at the public address;
  reaching them from inside the LAN depends on the router's NAT hairpin, which many do not do. The
  installer states this rather than leaving the operator to conclude the install failed. *(This
  bit the owner: every hostname returned `HTTP 000` from inside the LAN while working correctly.)*
- A7. Dry-run output before any change: exactly which records will be created, modified or skipped.

- A8. **OWNER DECIDED (OQ2): a static A record, plus optional dynamic tracking.** The address is
  static today but is not guaranteed to stay so, and the failure mode of a silently stale A record
  is that every app becomes unreachable from outside with no error anywhere — the host is healthy,
  the certificates are valid, and the records point at someone else's address. So:
  - the record is written from a public address detected at install time and shown for
    confirmation, never guessed silently;
  - an optional updater re-checks the real public address on a schedule and corrects the record
    when it changes, touching only records ferrum owns (A4);
  - the updater is opt-in but **recommended by default**, because the operator cannot observe the
    failure it prevents.

**Open questions for the owner.**
- OQ1. **Recommendation: stay Cloudflare-only, but put the record operations behind one seam.**
  ferrum already requires Cloudflare for ACME DNS-01, so record management adds no constraint an
  operator does not already have, and it reuses the one credential they have already given. Adding
  a provider abstraction now would be speculative generality for a second provider nobody has
  asked for. The cheap insurance is to keep create/update/delete/list behind a single narrow
  interface so a second implementation is additive rather than a refactor — which costs nothing
  today. Owner to confirm.
- OQ2. ~~Dynamic address tracking?~~ **Answered: static A record + optional DDNS updater.** See A8.

---

## R2 — a reinstall does not hand back an unconfigured application

**User story.** I reinstall a host I already had. Plex is still my server, with my libraries.

**What happened.** `/var/lib/ferrum/state` lives on the OS disk, so the wipe discarded every app's
identity and database. Plex came back unclaimed — "You do not have access to this server" — and
Jellyfin warned of a server mismatch. Both are correct behaviour from the apps, and both are
exactly the "bogged down and confused" experience this product exists to avoid.

**Acceptance criteria.**
- A1. The installer detects that the target is **already a ferrum host** before erasing it, and
  says so at the confirmation gate — this is a reinstall, not a first install, and the operator is
  told what will be lost.
- A2. **Offer to preserve application state across the reinstall.** `/var/lib/ferrum/state` is a
  btrfs subvolume and is already snapshotted; the material question is whether it can be staged off
  the OS disk and restored afterwards. If it can, a reinstall keeps Plex's identity, the *arr
  databases and every library — and the Plex claim problem disappears rather than being worked
  around.
- A3. Where state genuinely cannot be preserved, the installer completes the app's onboarding
  itself rather than instructing the operator. For Plex that means collecting a claim token
  (`plex.tv/claim`, valid four minutes) at the right moment and writing it to the `claimToken`
  setting **which already exists in `modules/apps/plex/meta.nix` and which nothing ever asks for**.
- A4. Claim-token timing is handled, not documented: a four-minute token collected before a
  thirty-minute build has expired by the time it is used. Collect it immediately before the apply
  that consumes it, and re-prompt on expiry.
- A5. If an app still needs a human step after all of this, the installer says so **in its final
  report, per app, with the exact URL** — not in prose an operator has to infer.

- A6. **OWNER DECIDED (OQ3): both paths must work, because both happen.** A given run is either a
  first install or a reinstall, and the installer does not get to assume. So it detects which it
  is (A1) and takes the matching path:
  - **reinstall with state preserved** — identity survives, no claim token is needed, and the Plex
    problem does not arise;
  - **first install, or a reinstall where state cannot be preserved** — a claim token is collected
    and applied automatically (A3, A4).

  Note that a *first* install needs claiming too: a brand-new Plex server is reachable on the LAN
  but answers "You do not have access to this server" to anything else until it is associated with
  an account. Claiming is not a reinstall-only concern, which is why it cannot be handled purely by
  preserving state.

**Open questions.**
- OQ3. ~~Is state preservation in scope?~~ **Answered: both paths.** See A6.
- OQ6. **Recommendation: a data disk when there is one, the operator's machine otherwise, and
  measure before promising.** Reasoning, with a real number: `/var/lib/ferrum/state` on the freshly
  installed host is **230MB**, and that is with empty libraries. The bulk of a mature install is
  Plex metadata and thumbnails, which reaches single-digit to low-tens of GB on a large library —
  large enough that the choice matters, small enough that both options are viable.

  So, in order:
  1. **A data disk with room.** The install only erases the OS disk, so a data disk is untouched by
     definition — this is the strongest property available, and it is fast and local. `btrfs send`
     of the existing snapshot preserves the subvolume rather than copying a directory tree.
  2. **The operator's machine**, over the same SSH the installer already uses, when there is no
     data disk or not enough room. Slower, but it needs no assumption about the target at all.
  3. **Neither** — then the installer must not claim preservation. It says so BEFORE the disk gate,
     and takes R2's claim-token path instead.

  Two properties this must have, both learned the hard way tonight: the staged copy is
  **verified complete before anything is erased**, not after; and the size is **measured and shown
  at the confirmation gate**, so "preserve my state" is never a promise made against an unknown.

---

## R3 — multiple data disks present as one library

**User story.** I have two media disks. My apps see one library spanning both, as they did before.

**What happened.** The host previously pooled 7.3T and 9.1T into a 17T `mediapool` at
`/mnt/unionfs`. ferrum mounted them as two disjoint paths, `/mnt/media-0` and `/mnt/media-1`, and
has no pooling concept. Adding a library in Plex meant choosing one disk. This is the feature the
owner asked for by name.

**Acceptance criteria.**
- A1. With more than one data disk, ferrum presents a single pooled path, and that path is what
  apps are pointed at.
- A2. The pool tolerates a missing disk in the same way the individual mounts do. `nofail` already
  keeps a sleeping disk from blocking boot; the pool must not reintroduce that failure mode.
- A3. Writes land on a disk with room, with a stated policy rather than an emergent one.
- A4. Pooling is **visible** in the ferrum UI: which disks are in the pool, how full each is, and
  what happens when one is missing. Per the owner's standing direction, the UI is a window onto the
  system, so a pool that can only be understood by reading fstab is not finished.
- A5. Adding a disk later is a UI action that extends the pool, not a hand edit.
- A6. Existing data is never rearranged. Pooling is a view over what is already on the disks.

**Design note.** mergerfs is what Saltbox uses and what the owner's previous setup used, so it is
the presumptive choice; it is a union filesystem over existing mounts and satisfies A6 by
construction. The alternative — btrfs multi-device — would rewrite the disks and is therefore
ruled out by A6, not merely disfavoured.

- A7. **OWNER DECIDED (OQ4): `epmfs`.** Among the disks that already contain the target
  directory, write to the one with most free space; fall back to the emptiest disk for a path that
  exists nowhere yet. This keeps a show's seasons on one disk, which is what makes losing a single
  disk lose whole shows rather than gaps in every show, and what lets idle disks spin down.

- A8. **`epmfs` does not balance anything, and the spec must not pretend otherwise.** Neither does
  `mfs`. The policy chooses where a NEW file goes; no policy moves a file that already exists. The
  consequence to design for: once a show lives on disk A, every later season goes to disk A too,
  even when A is nearly full and B is empty. That is the behaviour being asked for, and it is also
  how a disk fills.

  So `epmfs` is only safe with:
  - **A minimum-free-space floor.** Below it, mergerfs skips that branch and places the write
    elsewhere rather than failing it. Without this, a full disk turns into failed writes in an app
    that reports them badly, if at all.
  - **Visibility of per-disk fullness in the UI** (A4), since the operator cannot otherwise see a
    pool that is 45% full overall and 98% full where it matters.
  - **A stated position on rebalancing.** ferrum does not move data implicitly — that would violate
    A6 and could run for hours. Whether it offers an explicit, operator-initiated rebalance is
    OQ7 below.

**Open questions.**
- OQ4. ~~Write policy?~~ **Answered: `epmfs`.** See A7, and A8 for what that does not do.
- OQ5. ~~Pool path?~~ **Answered: ferrum decides, following TRaSH.** This turned out to be much
  more than naming — see **R8**, which is a live defect: the pool is not what the apps are pointed
  at, so the media is unreachable, and downloads sit on a different filesystem so imports cannot
  hardlink. The remaining choice is only the root's name (OQ8).
- OQ7. ~~Explicit rebalance?~~ **Answered: not needed; handle fullness instead.** See A9.

- A9. **OWNER DECIDED (OQ7): a free-space floor, not rebalancing.** The question was what happens
  when a show's disk is at 98% and three more seasons arrive. Two settings cover it:
  - **`minfreespace`** — a branch below this is excluded from the candidate set, so the new seasons
    land on another disk instead of failing. The show is then **split across disks**, which is the
    honest trade: `epmfs` keeps a show together until keeping it together would mean not writing it
    at all. Sized as a floor rather than a percentage, because mergerfs takes a size; ferrum picks
    it from the disk's capacity rather than asking.
  - **`moveonenospc`** — if a write runs out of space mid-file anyway, mergerfs relocates that file
    to a branch with room rather than failing. Media files are large enough that a check at open
    time is not sufficient on its own.

  Together these mean a full disk degrades to "this show is now on two disks" rather than to a
  failed import that an *arr reports badly or not at all. Rebalancing existing data stays out of
  scope: it would move the operator's files (A6) and run for hours.

---

## R4 — credentials survive a failed run

**User story.** The install fails partway. I can still log in to what it built.

**What happened.** The generated SSO and ferrum-UI passwords are printed only in the installer's
final report. The run failed before that point, so a working Authelia sat behind a password the
operator had no way to know — the host looked broken and was not.

**Acceptance criteria.**
- A1. Credential locations are reported as soon as they exist, not only at the end.
- A2. The final report still lists them, and says plainly that they are readable on the host.
- A3. A resumed run re-reports them, because a resume is the likeliest path after the failure that
  loses them.

---

## R5 — a failed certificate order is retried, and a fake certificate is not reported as success

**User story.** I fix the credential and re-apply. My certificates are real.

**What happened.** The first apply's ACME orders failed on a malformed token and fell back to
self-signed, which is the correct safety behaviour. But the units are `oneshot` and had already
"succeeded", so fixing the token and re-applying changed nothing. Every hostname served a
`minica root ca` certificate while `ferrum-apply apply` reported success, and only a manual
`systemctl start acme-order-renew-*` produced real ones.

**Acceptance criteria.**
- A1. Post-install verification checks each certificate's **issuer**, and a self-signed fallback is
  a reported failure rather than a pass.
- A2. An apply re-attempts orders that previously fell back, rather than treating a completed
  oneshot as done.
- A3. The distinction is visible to the operator: "certificate issued by Let's Encrypt" versus
  "self-signed fallback in place, apps will warn".

---

## R6 — apply does not report a transient restart as a failure

**What happened.** `ferrum-reconcile` exits non-zero when the apps it registers are not listening
yet, and systemd restarts it; it succeeded on the next attempt, both times. Both applies reported
`apply degraded: one or more units failed` about a service that was already fixing itself. A
report that cries wolf on every install trains the operator to ignore it — which is how a real
failure gets missed.

**Acceptance criteria.**
- A1. A unit in `activating (auto-restart)` is not yet failed; wait for it to settle, within a
  bounded window, before judging.
- A2. Genuinely failed units are still reported, with their journal tail.
- A3. `ferrum-reconcile` should not need the retry in the first place: it should wait for the apps'
  health checks rather than racing them.

---

## R7 — put-secret validates the payload it is given

**What happened.** Two malformed values reached `acme-dns` from hand-run repairs: a token carrying
zsh's trailing `%`, and later `CLOUDFLARE_DNS_API_TOKEN=` with no token at all. `put-secret`
rejects an empty value and validates the secret's *name*, and that is all — so both were accepted,
encrypted and shipped, surfacing much later as an ACME error that blamed DNS.

**Acceptance criteria.**
- A1. For secrets whose shape ferrum knows — `acme-dns` today — validate that shape on write, with
  the same rules the installer applies at its prompt.
- A2. The error names the offending character and its codepoint, because the character is usually
  invisible.
- A3. Generic secrets keep working; this is a known-shape check, not a general schema.

---

## R8 — one filesystem root, laid out the way the *arr stack needs (TRaSH)

**Found while answering OQ5, and it is live on the installed host right now.**

`ferrum.storage.mediaDir` defaults to `/srv/media` and that is what every app is pointed at. The
installer mounts data disks at `/mnt/media-0` and `/mnt/media-1`. **Nothing connects the two.** On
the real host, `/srv/media` is an empty directory on the 500GB OS disk containing only
`downloads/`, while 7TB of media sits at `/mnt/media-*` referenced by nothing. Adding a library in
Plex cannot find the media because no app has ever been told where it is.

**The hardlink constraint, which decides the layout.** The *arrs import by hardlinking from the
download directory into the media library. A hardlink cannot cross a filesystem, so if downloads
and media are separate mounts the import silently degrades to a **copy**: double the disk used
during the copy, a long pause per import, and seeding broken if the original is moved rather than
copied. This is the single most common misconfiguration the TRaSH guides exist to prevent, and
ferrum currently has it by construction — `/srv/media/downloads` on the OS disk, media elsewhere.

**Acceptance criteria.**
- A1. Downloads and media live under **one filesystem root**, so imports hardlink. This is the
  requirement everything else in R8 serves.
- A2. That root is the pool from R3 when there is more than one data disk, and the single data disk
  otherwise. `mediaDir` stops being an independent path that can disagree with where the disks
  actually are.
- A3. **The root is `/data`** (OQ8, owner decided), with the TRaSH layout beneath it:

      /data/
      ├── torrents/{movies,tv,music,books}
      ├── usenet/{incomplete,complete/{movies,tv,music,books}}
      └── media/{movies,tv,music,books}

  ferrum is opinionated and picks this; it is not an operator choice. `/data` is the TRaSH
  convention and what community guides assume, so an operator following any *arr tutorial finds
  the paths where the tutorial says they will be -- which is itself part of not getting bogged
  down.
- A4. Every app's paths are derived from that root — qBittorrent and SABnzbd write into
  `torrents/` and `usenet/`, the *arrs read from those and import into `media/`, Plex and Jellyfin
  read `media/`. No app is configured with a path an operator typed.
- A5. **A host with no data disk still works**, on the OS disk, with the same layout and the same
  single-root property. Small installs must not be a different shape.
- A6. Verification asserts hardlinking actually works between the download and media directories —
  create, link, compare inode, remove. A layout that is correct on paper and split in practice is
  the failure this requirement exists to prevent, and it is invisible until a library is large.

**Open question.**
- OQ8. ~~What is the root?~~ **Answered: `/data`.** See A3.

**Migration note.** `ferrum.storage.mediaDir` currently defaults to `/srv/media`, and the running
host has an empty `/srv/media/downloads` on the OS disk. Moving to `/data` changes the meaning of
an existing option, so it needs a schema migration (`modules/lib/migrations.nix`) rather than a
silent default change: a host already running with files under `/srv/media` must not have them
quietly become invisible on an update.

---

## Out of scope

- The **visual step-through installer**, which is tracked separately and is a larger piece of work.
  R1–R7 are gaps in what the installer *does*; that is a gap in what it *is*. Several of these
  requirements get easier inside it — R4's credentials and R5's certificate status are obvious
  screens — so this spec deliberately avoids designing terminal UX that a browser UI would replace.
- Non-Cloudflare DNS providers, pending OQ1.
- Migrating an existing Saltbox host in place.

## Traceability

| Req | Manual step it removes | Evidence it is needed |
|-----|------------------------|-----------------------|
| R1 | create DNS records | `auth.thesyms.ca` did not resolve; no record code exists |
| R2 | claim Plex, dismiss Jellyfin mismatch | "You do not have access to this server" after reinstall |
| R3 | pool the disks | two disjoint mounts where a 17T pool used to be |
| R4 | hunt for passwords | run failed before the report that prints them |
| R5 | re-trigger ACME by hand | `issuer=CN=minica root ca` while apply reported success |
| R6 | ignore a false failure | `apply degraded` for a service that self-healed twice |
| R7 | — (prevents a class of silent misconfiguration) | two malformed tokens accepted in one session |
