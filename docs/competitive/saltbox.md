# Saltbox

> Analysed 2026-10-06 against `saltyorg/Saltbox`, `sb-go`, `Sandbox`, `Sandpit`, `saltbox_mod` and
> `saltyorg/docs` at HEAD, plus the GitHub API. Saltbox is **GPL-3.0** and ferrum is Apache-2.0, so
> role logic cannot be lifted even as reference.

ferrum was started as an alternative to Saltbox, so this page is the one most likely to be read
adversarially. It is written to survive that: **the rows where we lose are stated as sharply as the
rows where we win**, and three of ferrum's own published claims were found wrong or overstated
during the research and have been corrected rather than defended.

## What it is

An Ansible-plus-Docker deployer for a media stack, descended from Cloudbox. 891 stars, 5,442 commits
since 2017, 181 commits in the last six months, ~2,081 Discord members. The `sb` CLI is now a Go
binary (`saltyorg/sb-go`). Apps run as containers behind Traefik with Let's Encrypt and Authelia;
storage is rclone VFS plus a mergerfs union at `/mnt/unionfs`.

**It is effectively a one-maintainer project** — saltydk wrote 147 of ~180 commits in six months.
That is a real bus-factor risk and ferrum cannot score a point on it, because ferrum's bus factor is
also one.

## Where Saltbox wins, and it is not close

| | Saltbox | ferrum |
|---|---|---|
| **App catalog** | **301 installable roles**, ~267 documented | **7 apps** |
| **Maturity** | 2017 onward, thousands of installs | pre-alpha, proven on one machine by its author |
| **Community** | ~2,081 Discord, nine years | none yet |
| **Documentation** | 354 pages, **266 auto-generated from role metadata** | design docs and a README |
| **Cloud storage tier** | rclone VFS, Cloudplow, Autoscan, provider guides | none — out of Phase 1 |
| **Multi-instance** (`sonarr4k`) | inventory-driven, documented | not modelled |
| **Two-box Mediabox/Feederbox split** | supported | not modelled |
| **Postgres for the \*arrs** | `arr_db`, `timescaledb` | SQLite only |
| **Media servers** | Plex, Emby, Jellyfin | Plex, Jellyfin — **no Emby** |
| **Install CI** | installs **every changed role on a real Ubuntu runner** | nine NixOS VM tests; the stage2 installer test has never gone green |
| **Off-box backup** | imperfect, but real, plus a hosted encrypted config-restore service | **none. Rollback is not backup** |

The catalog gap is roughly forty to one and is the single largest thing a switcher gives up. Their CI
is a serious engineering operation that ferrum does not match. Their documentation is generated from
role metadata, which is why it stays true at 300 apps.

## Where ferrum wins

| | Saltbox | ferrum |
|---|---|---|
| **System rollback** | **none** — no `rollback` verb among the 38 CLI commands | NixOS generations |
| **App state rolled back *with* the system, atomically** | **none** | btrfs snapshot keyed to the generation, exercised on real hardware |
| **Reproducibility** | **zero releases, zero tags**; 171 roles pin `latest` or `release` | pinned flake inputs; a generation names a complete closure |
| **Secrets at rest** | plaintext YAML | sops-nix, encrypted |
| **Cloudflare credential** | Global API Key is the documented *preference*, in plaintext on the box — though a scoped-token path is fully documented (issue #455, closed 2026-01-26) | scoped token only |
| **Architectures** | x86_64 only; **ARM refused in code** | x86_64 and aarch64 both first-class |
| **Base OS** | Ubuntu LTS only, fresh, dedicated, no LXC, no desktop | any kexec-capable Linux, converted by `nixos-anywhere` |
| **GUI** | none, and none planned | schema-driven web UI |
| **qBittorrent behind VPN** | a `gluetun` role exists; wiring is a user-side override and its doc is marked `status: outdated` | netns-isolated WireGuard with a kill switch, config in sops, first-class |
| **Bootstrap integrity** | piped shell install validated with `file --mime-type` only | SSH plus `nixos-anywhere` from the operator's machine |

### Lead with reproducibility, not with any bug report

**Saltbox has zero releases and zero tags.** `sb update` means "jump to whatever `master` is today",
and across the role catalogs 171 roles pin a floating image tag. Re-running `sb install sonarr` next
week installs a different Sonarr.

This is verifiable in thirty seconds, current, structural, and impossible to dismiss as a stale bug
report — which is more than can be said for the issue citations ferrum previously led with. A pinned
flake closure is a categorical answer to it.

The rollback claim stands unchallenged. Saltbox's own app-recovery documentation instructs the
operator to recursively delete the application directory, under the heading **"THIS MAY DESTROY
DATA; BACK UP FIRST"**, and notes that it is then as if the app were never installed. Recovery means
restoring a backup onto a rebuilt box.

## Three of ferrum's own claims were wrong. They have been corrected

This is the most valuable output of the analysis.

**"Saltbox ships `password1234`" — deleted.** It was already wrong when written. Saltbox changed the
default to `password12345678` in commit `ce48beb9` on **2025-03-22**, eleven months before ferrum's
design doc, and `schema/accounts.schema.yml` now carries `not_equals: "password1234"` — it actively
*rejects* the value we accused it of shipping. Verified against the live repository. A Saltbox user
would have corrected this in under a minute, and would then have stopped reading.

**"Unlike Saltbox, your customisations survive an update" — narrowed.** Saltbox has a sanctioned
override surface, documented as existing for precisely this purpose: the inventory system *"allows
manipulation of variables without directly editing the roles themselves… ensuring persistent
configurations while avoiding conflicts during git merge operations"*, and `/opt/saltbox_mod` is an
official custom-role directory `sb update` never resets. The user's own config YAMLs are gitignored,
so `git clean -df` (no `-x`) does not touch them either. The accurate difference is narrower and
still real: ferrum's unit of customisation is a declarative module evaluated with everything else,
rather than a variable the maintainers chose to expose.

**"Hours of downtime" for backups — qualified.** True on the common ext4 install. On btrfs, Saltbox
snapshots and restarts containers in seconds (`roles/backup/tasks/snapshot.yml`).

Two further claims need rewriting rather than deleting:

- **Issue #495** closed `completed` on 2026-05-25, and the fix was to *remove the knob* and add a
  linter rule forbidding its return. The honest, quotable claim is not "silent drift from a bug" but
  the maintainer's own position: Saltbox deliberately does not model desired container state.
  `sb docker start` *"will not respect stopped containers as it is stateless"*. That is structural,
  and it is a better argument than the one it replaces.
- **Issue #475** was fixed on 2026-02-16. Cite it as evidence of the error-suppression class — there
  are 116 `ignore_errors: true` and 50 `failed_when: false` across the role tree — never as a live
  defect.
- **"Customising voids support"** is overstated; there is no blanket policy. Three specific
  documented refusals exist (Ubuntu Desktop, rclone encryption tweaks, and the "Danger Zone" page).
  Narrow it to those or drop it.

**Soften the Cloudflare claim further than first drafted.** Scoped tokens are supported and
documented with five zone-scoped permissions; the Global key is *recommended*, not *required*. Any
wording implying scoped tokens are unsupported is wrong.

Claims that **verified and stand**: `sb update` really does run `git clean -df` and `git reset --hard
@{u}` twice with no stash, in the new Go CLI (`sb-go/git/git.go:148-154`); Ubuntu-only and
x86_64-only are enforced in code, not merely documented; no GUI and none planned; the Cloudflare
Global API Key is still the documented preference as of a file modified 2026-08-24; backups are off
by default, uncompressed and unencrypted; and there is no rollback of any kind.

In fairness, and it belongs on this page: Saltbox's config files are created `O_EXCL` at `0600` with
symlink refusal and a TOCTOU-safe re-hardening check. That is deliberate, competent
plaintext-at-rest handling, not negligence. ferrum wins on encryption; it does not win on
carelessness.

## The maintainer's own words are better citations than any issue number

Three artifacts carry more weight than anything ferrum had been citing, because each is the
maintainer answering a specific user rather than a bug report that was later fixed:

- **#374 (2025-08-10)** — a user asks for ARM support. Same-day reply: *"We have no plans to support
  ARM."* Closed. Use this wherever ferrum's aarch64 row appears; it is stronger than quoting a README.
- **#440 (2025-11-17)** — *"I just recently updated SB and now when I go to qBittorrent it just gives
  me a 404."* The entire reply: *"Support is handled on discord."* Closed. Update fragility, the
  Discord-only policy and the GitHub deflection, in five lines.
- **#517 (2026-08-31)** — the maintainer on why a refactor broke Plex: *"didn't catch it during my own
  testing **as I do not bind the ports**."* Self-reported, and it names the structural mechanism: a
  one-maintainer project tests the configuration its maintainer runs. **ferrum has exactly this
  problem and should read it as a warning rather than a weapon.**

Also: `reference/server/` names **Linode and Vultr** as *"known to not work in at least one
significant way"*, and warns that preinstalled Docker means *"the installer will fail with a
non-obvious error"*. And the support page tells users to watch `#announcements` because *"new
incidents requiring user intervention are usually covered there"* — the project's own process assumes
updates periodically need hand-fixing.

There are **three** documented customisation-is-unsupported statements, not two; `advanced/your-own-containers.md`
adds *"arbitrary deployments fall outside our support scope."* That vindicates the narrowed version of
ferrum's claim and still does not rescue the broad one, because `saltbox_mod` and the Inventory remain
sanctioned.

## Migration: there is no import path, and we should say so

Media files move by pointing ferrum's pool branches at the same disks. Everything else is hard.

1. **Version skew.** Saltbox runs images such as `ghcr.io/hotio/sonarr:release`; ferrum runs what its
   pinned nixpkgs provides. The \*arrs refuse to open a database written by a *newer* build, so a
   user ahead of nixpkgs cannot import at all.
2. **Paths are baked into the databases.** Every root folder, download-client path and Plex library
   maps to `/mnt/unionfs/Media/…`. **Making `/mnt/unionfs` an aliasable media directory is the single
   highest-leverage migration affordance ferrum could ship.**
3. **Postgres.** A user who enabled `arr_db` has their \*arr databases in Postgres and must convert
   back.
4. Authelia users, Traefik middlewares, Cloudplow schedules, Autoscan and the ~290 roles ferrum does
   not have simply have no destination.

**Realistic positioning: a new install beside a Saltbox box, with media disks re-pooled and libraries
re-indexed — not a migration.** Say that plainly rather than implying an import path.

## What to learn from them

1. **Steal the three-tier catalog.** `Saltbox` (official, supported, CI'd) → `Sandbox` (*"Unofficial…
   Roles may get moved to the main repo if they become officially maintained"*) → `Sandpit`
   (*"Totally Unofficial… unsupported and may break your system"*). **This is how one maintainer
   carries 300 apps without owning 300 support burdens, and it is the only credible answer to
   ferrum's seven-versus-301 problem.** Their contribution bar is worth copying verbatim, including
   *"don't submit a role generated wholesale by AI."*
2. **Generate the documentation from the schema.** ferrum's catalog already has a uniform `meta.nix`;
   that is a docs generator waiting to be written, and the only way per-app documentation stays true
   as the catalog grows.
3. **CI that really installs.** A role matrix built from the diff, installing each changed app on a
   real machine, is a better safety net than unit tests — and it is exactly the gap ferrum's
   never-green stage2 test leaves open.
4. **Mark stale documentation in the documentation.** 55 pages carry `status: outdated` or
   `status: draft` front-matter. Honest, cheap, and it makes documentation debt measurable.
5. **Linter-as-architecture.** When the container-state knob turned out to be meaningless, they did
   not merely delete it — they added a lint rule making it impossible to reintroduce. That is how a
   defect class is closed once rather than twice.
6. **Keep support public.** Saltbox support is *"provided exclusively via our Discord server"*, so
   nine years of troubleshooting knowledge is unsearchable and unarchived. A public, archived tracker
   is a cheap and durable advantage.
7. **Rollback is not backup, and ferrum has no backup.** Saltbox has a hosted, client-side-encrypted
   config restore service so a user whose disk died can rebuild. ferrum's rollback does nothing for
   that user. **The README should say so before someone discovers it.**

## A caveat on method, which is load-bearing

**Community-sentiment research could not be completed, across two attempts.** Reddit and all twelve
Redlib mirrors were blocked or CAPTCHA'd; HN Algolia returns one substantive mention of Saltbox in its
entire index; AlternativeTo's entry has no reviews and was last updated 2024-11-17. A handful of
Reddit quotes were recovered as search-engine snippets only — the text, URL and date are as the engine
reported them, but **not** the surrounding context, the vote counts, or whether a quote was
contradicted downthread. **None of them appear on this page**, and none should be published without
opening the thread by hand first.

So nothing here rests on "users complain that…". It rests on code, documentation, and the maintainer's
own replies. That absence is itself the finding: support is Discord-exclusive by written policy,
GitHub Discussions is disabled, issues deflect to Discord and auto-stale at 30 days. Their open-issue
count of seven is therefore **not** a quality signal and must never be cited as one. A public,
searchable, archived support corpus is a real, cheap, compounding advantage ferrum can have for free.

Two honesty notes that cut against ferrum's framing, kept deliberately:

- A 2024-03-09 r/selfhosted thread's top answer to "what's the modern all-in-one media server?" is
  *"there is no all-in-one solution"*. **Saltbox is not the default answer that community gives**, so
  framing it as the incumbent to beat may overstate its reach.
- Cloudbox, archived since 2023-03-15, still carries 2,381 stars to Saltbox's 891. Worth a line;
  don't over-read it.

**Still unverified after both passes:** no "I moved off Saltbox because…" post could be found by
either researcher; Discord rules and moderation behaviour are unobtainable, **so ferrum cannot claim
Saltbox turns people away for a dirty machine — only that the documentation demands a clean one**.
