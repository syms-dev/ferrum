# Phase 1.9 — the round that makes ferrum something you can show people

**Status:** drafted 2026-09-21 from the owner's final-round list. Owner has authorised implementing
every outstanding requirement. Sequenced after the functional backlog; individual items may be
pulled forward where they are cheap and unblock others.

## Why this exists

Everything before this phase makes ferrum *work*. This phase is about whether someone in the
homelab community, who already has a working Saltbox, would switch — and whether they could.

The owner's framing: *"a solid asf product I can show to the homelab community about why ferrum is
the media hosting platform for everyone, over saltbox."*

That is a different bar from "the tests pass". It means the first five minutes have to be good, the
thing that makes ferrum different has to be *visible*, and a stranger has to be able to add an app
without asking permission.

---

## R22 — the code stops sounding like it was written by a machine

**The problem, measured.** Comments are **29% of `crates/`** (6,809 of 22,929 lines) and **41% of
`modules/`** (1,685 of 4,024). That is too much by any standard, and it is the first thing a
contributor reads.

**The carve-out that makes this safe.** This repo's most valuable comments are the ones recording
real incidents — *"found on the first real hardware run of any catalog app, 2026-09-16"*, *"five
consecutive applies on a healthy host said 'apply degraded' about a service that had already fixed
itself"*, *"Nix ignores untracked files"*. Those are why the codebase does not repeat its
mistakes, and a blanket strip would delete exactly them.

**Acceptance criteria.**
- **A1.** A comment that explains **why**, records an incident, or names a non-obvious constraint
  is kept. A comment narrating **what** the next line does is cut.
- **A2.** Survivors are rewritten with the `humanizer` skill against the 25 patterns, and ferrum's
  own voice layer.
- **A3.** The project's documentation rules still hold: every file keeps a module
  header, every public function keeps a docstring. This is a trim, not a strip.
- **A4.** No behaviour changes. The test count before and after is identical, and the diff is
  comments only — provable with `git diff --stat` on non-comment lines.
- **A5.** Realistic target: roughly a 40% reduction in comment lines. A 90% reduction would mean
  A1 was not applied.

## R23 — a real test sweep, and issues for what it finds

**Acceptance criteria.**
- **A1.** The full workspace suite, every `nix flake check`, and the NixOS VM tests are run and
  their real output captured. **The S13 install and resume VM tests have never once passed**, and
  are the most likely place real bugs are hiding.
- **A2.** Each finding gets a GitHub issue containing a reproduction, the evidence, and a proposed
  fix — a small spec, not a bug title.
- **A3.** Issues are opened by the owner's own account and by the main session only. No agent opens
  an issue, a PR, or a comment.
- **A4.** Findings that are one-line fixes are fixed rather than filed. An issue tracker full of
  trivia is noise.

## R24 — docs.ferrum.sh

**Acceptance criteria.**
- **A1.** A documentation site at `docs.ferrum.sh`, built with **Astro Starlight** and hosted on
  **Cloudflare Pages** — the owner is already on Cloudflare, and it looks credible without design
  work, which matters when the pitch is "not Saltbox".
- **A2.** It opens with a five-minute install, not with architecture. Someone deciding whether to
  try this gets to a running box before they get to a concept.
- **A3.** It states the rollback story early and concretely, because it is the one thing Saltbox
  cannot do.
- **A4.** It covers: install, the app catalog, adding your own app, migrating from Saltbox,
  storage and pooling, secrets and VPN, and recovery when things break.
- **A5.** It is built from the repo, so a doc describing a flag that no longer exists fails CI
  rather than rotting.

## R25 — the app catalog is something other people can add to

**Why this is the highest-leverage item here.** Saltbox has roughly 100 apps because its community
contributed them. ferrum has seven because the owner wrote seven. Shipping twenty more by hand
moves the number; making the catalog extensible changes who moves it.

**Acceptance criteria.**
- **A1.** A third party can add an app without forking ferrum — a declarative app definition
  ferrum discovers, in the shape `modules/apps/<id>/` already has.
- **A2.** The existing catalog-consistency checks extend to third-party apps, so a broken
  definition fails loudly at evaluation rather than at 3am.
- **A3.** A contributed app gets the same treatment as a built-in: a vhost, SSO, a subdomain,
  storage access, cross-app registration, health checks.
- **A4.** Adding an app does not require Rust. Today the installer's `CATALOG_APPS` lives in Rust
  and is checked against the Nix catalog — that check must not become the thing that blocks
  contribution.
- **A5.** A first batch of new apps ships alongside, as proof the mechanism works rather than as
  the point: Overseerr, Bazarr, Tautulli, Lidarr, Readarr are the obvious candidates.
- **A6.** Documented in R24, with a worked example.

## R26 — backup that exists

**The defect.** `ferrum.backup.{enable,repo,schedule,passwordSecret}` are declared in
`modules/core/options.nix:348-362`, `backup.enable` exists per-app in
`modules/lib/app-submodule.nix:112`, and `restic-password` is a known `put-secret` payload — and
there is **no backup module, no service, and no timer anywhere in the repo**. The settings screen
renders controls that do nothing.

For a product that holds other people's media libraries, a setting that lies about backups is
worse than having no backup feature at all.

**Acceptance criteria.**
- **A1.** The declared options actually drive a restic backup on the declared schedule.
- **A2.** It backs up what cannot be rebuilt — app databases, secrets metadata, ferrum's own state
  — and never the media, which is terabytes and replaceable by re-downloading.
- **A3.** Restore is tested, not assumed. A backup nobody has restored is a hypothesis.
- **A4.** Failure is loud. A backup that silently stopped running three weeks ago is the classic
  version of this feature failing, and it is the same shape as R16/A4 and R1/A8.
- **A5.** Until A1 ships, the settings UI must not present backup as functional.

**Where backups go (owner asked 2026-09-21).** ferrum already chose restic, and restic's own
backend list is almost exactly the question: **local or attached disk, SFTP, S3 and anything
S3-compatible (Cloudflare R2, Backblaze B2, Wasabi, MinIO), Backblaze B2 natively, Azure Blob,
Google Cloud Storage**, plus roughly seventy more through rclone. `ferrum.backup.repo` is already
a restic repository URL, so the transport is free; the work is credentials and not making an
operator learn restic's URL syntax.

- **A6.** The operator picks a destination from a list — local/attached disk, S3-compatible (with
  an endpoint field, which is what makes R2, B2, Wasabi and MinIO all work), Backblaze B2, Azure
  Blob, SFTP — and ferrum builds the repository URL. Typing `s3:https://…` by hand is the failure
  this avoids.
- **A7.** Each backend's credentials are sops secrets, handled exactly like the Cloudflare token
  and the VPN config: collected once, replaceable later, never displayed back. They differ per
  backend (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `B2_ACCOUNT_ID`/`B2_ACCOUNT_KEY`,
  `AZURE_ACCOUNT_NAME`/`AZURE_ACCOUNT_KEY`), which is the same shape as R15's per-provider VPN
  fields — the two should share one pattern rather than inventing two.
- **A8.** A raw restic repository string is always accepted, for a backend ferrum does not list.
  Same rule, same reason, as R15/A5's raw WireGuard config: a preset list must never be a ceiling.
- **A9.** **Local-only is a legitimate choice and must be offered without nagging**, but the UI
  states what it does not protect against: a local backup on a disk in the same box does not
  survive the event most likely to destroy the box.
- **A10.** The destination is verified at setup — credentials work, the bucket is reachable and
  writable — and fails at the prompt rather than at 3am on the first scheduled run. Same principle
  as R1/A5's zone check.
- **A11.** Restore is proven against at least one remote backend, not only against local. A
  backend that backs up fine and cannot restore is the worst outcome this requirement has.

## R27 — migrating from Saltbox

**Why it is the biggest adoption lever.** Nobody with a working Saltbox rebuilds from scratch to
try an alternative. The switching cost *is* the adoption barrier.

**Acceptance criteria.**
- **A1.** ferrum reads an existing Saltbox install and reports what it found: apps, domain,
  storage layout, which of it ferrum can reproduce.
- **A2.** **The media is never moved or rewritten.** Same rule that chose mergerfs over btrfs
  multi-device in `modules/core/pool.nix`: never rearrange existing data.
- **A3.** What ferrum cannot migrate is said plainly, before the operator commits, not discovered
  afterwards.
- **A4.** The migration is reversible in the sense that matters — the Saltbox install is not
  destroyed as a side effect of looking at it.

## R28 — hardware transcoding

**Acceptance criteria.**
- **A1.** Intel QSV, NVIDIA NVENC and VAAPI passthrough for Plex and Jellyfin, detected from the
  hardware rather than configured by hand.
- **A2.** The installer's hardware inventory already detects the machine; it should say what
  transcoding it found and what that means.
- **A3.** Absent or unsupported hardware degrades to software transcoding with a clear statement,
  never a silent performance cliff.

## R29 — show the rollback

**Why.** ferrum's genuine differentiator — the system closure and application state rolling back
together, atomically — is invisible until something breaks. It cannot be argued, only shown.

**Acceptance criteria.**
- **A1.** A short recorded demo: a working box, a change that breaks it, one rollback, working
  again. Under two minutes.
- **A2.** Real, on real hardware, unedited in the parts that matter. The homelab community will
  spot a staged demo instantly and it would cost more credibility than it buys.
- **A3.** Linked from the README and from R24's front page.

---

## Operational task, not a requirement: the git history rewrite

Owner approved on 2026-09-21, with the inventory: **226 commits, 186 carrying an assistant trailer,
across `main`, `grounding-and-install-path` and 6 stale `worktree-agent-*` branches; 0 tags; 20+
commit SHAs referenced inside docs and evidence files.** Nobody else has cloned the repo.

Sequence, and it must not start early:
1. **Wait for the R1 pipeline run to finish and push.** Rewriting under a running agent that is
   committing would corrupt its work.
2. `git filter-repo` strips the trailer from every commit on every ref. Author and committer
   remain the owner's identity throughout.
3. Use the emitted old→new commit map to **repair the SHA references in docs and specs** as one
   follow-up commit, so the project's audit trail survives the rewrite rather than dangling.
4. Delete the 6 stale `worktree-agent-*` branches.
5. Force-push `main` and `grounding-and-install-path`.
6. Owner re-clones or resets: `git fetch && git reset --hard origin/<branch>`.

From this point on, **no commit or PR in this repository carries assistant attribution in any form.**

## Sequencing

R26 (backup) and R22 (comments) are cheap and can be pulled forward. R25 (extensible catalog) is
the highest-leverage and the largest. R24 (docs) depends on most things being settled. R29 (demo)
should be last, because it demonstrates the finished thing.

## Open questions

- **OQ1 (R25).** Does a third-party app live in the ferrum repo as a contribution, or in the
  operator's own flake as an overlay? Recommendation: **both** — the same definition shape, so a
  private app and a contributed one differ only in where the file sits.
- **OQ2 (R23).** Public issues on `syms-dev/ferrum`, or a private tracker until launch? Filing
  known defects publicly before the docs exist shapes first impressions.
- **OQ3 (R27).** How far does migration go — read-and-report, or actually reproduce the Saltbox
  config on ferrum? Recommendation: report first, reproduce second, because a wrong automatic
  migration of someone's working media server is unrecoverable trust.
