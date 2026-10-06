# Silo

> Analysed 2026-10-06 against the docs at commit-time `siloserver.org` (source cloned from
> [`Silo-Server/siloserver.org`](https://github.com/Silo-Server/siloserver.org), whose
> `src/data/docs-release.mjs` pins its own review baseline at `sourceReviewedAt: 2026-09-20`,
> server revision `cb0b8b75`). Every quotation below is from that tree. Silo is pre-1.0 and moving;
> re-check before relying on any claim here.

## What it is

[Silo](https://siloserver.org) is a self-hosted media server — a Plex and Jellyfin competitor.
Go 1.26, PostgreSQL 18 with pgvector, Redis, React, Docker Compose, AGPL-3.0-or-later, ~517 stars
and ~2,371 commits as of this writing. It transcodes with hardware acceleration, speaks the
Jellyfin protocol so existing clients work unmodified, and has first-party apps for Apple and
Android in beta.

It is well engineered and its documentation is genuinely good. A
[third-party writeup](https://zackreed.me/posts/setting-up-silo-server/) praises the docs as
exceeding what the project's stage would suggest, and that assessment is fair.

## Does it threaten ferrum? No — it is a tenant of the category, not a competitor to it

Silo is one application. ferrum is the machine. Silo occupies the Plex/Jellyfin slot *inside* a
ferrum stack, and its documentation assumes, as prerequisites the operator supplies by hand,
several of the things ferrum exists to build.

Its single-sign-on guide tells you to bring your own identity provider:

> OpenID Connect providers, such as authentik, **Authelia**, Keycloak, or Entra ID.
> […] At your provider, create a confidential client for Silo and add that URI as its redirect URL.

Its autoscan guide lists ferrum's own storage layer as something it reads from:

> FUSE mounts, such as **mergerfs** or Unraid user shares | Yes, for changes made through the mount.
> A change made directly on one of the pool's disks isn't seen.

And its guide to being reachable from the internet is, in full, manual:

> This example uses **an existing Caddy installation** […] Point your chosen hostname at your public
> address. Forward inbound TCP ports 80 and 443 to Caddy. Add this site to your existing Caddyfile
> […] In **Admin > Settings > General**, set **Silo public URL** […] review **Trusted proxies**.

Silo itself ships no TLS at all — "The three Silo ports listen on every host interface without
TLS" — and no DNS automation of any kind. The only Cloudflare integration in the docs is R2 object
storage for artwork, and even connecting a domain to that bucket is manual dashboard work.

**Honest step count, bare Docker host to a published, authenticated server: roughly 24 operator
actions**, plus prerequisites the docs decline to cover (an existing Caddy, a domain, a router you
can configure). Add about nine more for real SSO — which authenticates Silo and nothing else on the
box. For one application.

Searching the whole 82-page tree for the *arr applications returns two files, both describing Silo
as the receiving end of an integration with software somebody else installed. The clearest symptom
is a path-mapping chore:

> If Sonarr sees `/arr/tv/Example/Season 01` and Silo sees `/media/tv/Example/Season 01`,
> map `/arr/tv` to `/media/tv`.

That mapping problem exists precisely because nothing deployed both.

### What it *is* absorbing

Silo has taken over the standalone **Autoscan** daemon and ships an **Overseerr**-shaped request
queue. The direction of travel is swallowing the small satellites around a media server, not
swallowing the host. Worth watching; not a threat to this project.

## The finding that matters most: they have no rollback, and they say so plainly

Silo's own [1.0 migration notes](https://github.com/Silo-Server/silo-server/blob/main/docs/update-to-1.0.md):

> Silo's general release policy […] **does not guarantee downgrade or in-place rollback
> compatibility between releases.**

And the update guide:

> **Switching back to the old image doesn't undo migrations**, so don't alternate old and new images
> against the same database.
>
> The reliable way back is to **restore the pre-update backup with the old image** […] **That loses
> every change made after the backup.**

Their backup procedure is ten manual steps — `pg_dump`, copy `.env`, copy four data directories,
record the running image tag because "`latest` won't identify the old image once you've pulled a new
one" — followed by the instruction to test a restore on a different host before relying on it.

This is ferrum's thesis, written by a competent, modern, actively-developed project as a limitation
of its own architecture. It is the strongest external validation of atomic closure+state rollback
available, and the contrast belongs in ferrum's own README.

## Adding Silo to ferrum's catalog: a real architectural decision, not a packaging chore

ferrum has **no container support**. Every catalog app is a native nixpkgs service; there is no
`oci-containers`, no `virtualisation.docker`, no `podman` anywhere in `modules/`. Silo ships only as
a container image and needs PostgreSQL 18 with pgvector and Redis beside it, with optional
Meilisearch, optional S3, and an optional transcode-node fleet sharing one `SECRET_KEY` across hosts.

So adopting it means either packaging a Go + React + pgvector stack in Nix, or introducing an OCI
path to ferrum. The second weakens the central guarantee: a container image is not in the Nix store,
so a generation would no longer fully describe the system it names. The application *state* would
still be covered by the existing subvolume snapshot, which makes this less bad than it first looks —
but it is a decision to take deliberately, with the cost written down, rather than to discover later.

One counter-intuitive consequence: **Silo makes ferrum's problem bigger, not smaller.** It is a
harder thing to install correctly and roll back atomically than Jellyfin is, which is an argument
*for* ferrum and makes a future ferrum Silo module worth more than its Jellyfin one.

## What is worth copying

Ranked by value to ferrum. The surprise is that the most transferable artifact is not the prose but
the machinery that forces the prose.

### 1. Two health endpoints, three body statuses, and a written list of what is *not* checked

ferrumd today exposes thirteen routes and not one of them is a health check; the only health logic
in the project lives inside `apply.rs` and ceases to exist when the apply ends. There is no
steady-state way to ask the box whether it is well.

Silo splits the question:

> `/api/v1/health` answers as soon as Silo's web server is running. […] `/api/v1/ready` also checks
> PostgreSQL and storage […] A **degraded** answer still returns HTTP 200, so read the body.
> **Readiness doesn't check Redis or playback.**

Three separable decisions, all correct. Liveness and readiness are different questions on different
URLs. **Degraded is 200, not 503** — a partial failure must not look like a dead process to a
watcher whose reflex is to restart you, because restarting is the wrong move for a missing artwork
bucket. And the documentation names what readiness does *not* cover, which is the whole value: an
undocumented health endpoint manufactures false confidence rather than removing it.

ferrum can do better than the original on one axis. Silo has no explicit "starting" state; the
operator infers it from "`/health` up, `/ready` 503, go read the logs". ferrum does not have to
infer, because `AppState.interlock` already holds the UUID of the job that owns the system, so it
can report `"status":"applying"` honestly and let a watcher distinguish *broken* from *mid-switch*
without reading anything.

The matching hazard is already live here: `main.rs` documents "a ferrumd restarted mid-apply by its
own generation switch". No watchdog or restart policy should ever point at readiness. Silo spends a
paragraph on exactly this failure.

### 2. Staleness is a state, and it is not the same as a healthy reading

> A mount that stops answering keeps its last good numbers. A path the node can't see shows as
> unavailable, not as an empty disk.
>
> **A volume that stopped answering at 40% and kept filling never trips the fill alert, because its
> numbers stay at 40%.**

This lands harder on ferrum than on Silo, because ferrum pools disks with mergerfs and routes a
torrent client through a VPN. A branch that drops out of the pool must render as *unavailable* or
*last measured three days ago*, never as free space. "qBittorrent is bound to the tunnel" is a
last-known assertion and needs a timestamp: a kill switch whose last successful verification
predates the last reboot is not a verified kill switch.

ferrum has already caught this bug's sibling once — `apply.rs` records that an empty
`systemctl list-dependencies` must not read as health, and `modules/apps/sonarr/meta.nix` probes
`/ping` rather than trusting `systemctl is-active`. The instinct exists at apply time; it needs to
extend to steady state. This is a data-model decision (`Option<T>` plus a timestamp plus a reason,
not a bare number) and so is nearly free before the health view exists and expensive afterwards.

### 3. The disclosure policy — the single most transferable paragraph they wrote

From their internal editorial record:

> The maintainer approved removing temporary app limitations, bug workarounds, and repeated
> source-review or certification disclaimers from public guides. **Prerequisites, access controls,
> storage requirements, format dependencies, and supported platform differences remain explicit.
> Removing a qualification is not evidence that a bug was fixed or acceptance passed.**

Permanent constraints belong in public documentation; transient bugs belong in an internal ledger. A
document full of "this is currently broken" rots into noise and reads as a sick project. A document
full of "this requires X" reads as a careful one. The findings are not discarded — they stay in
internal review files.

ferrum should split the same way, and additionally publish a short, dated **Known issues** page,
which Silo lacks. At first release, early adopters will hit rough edges and the only question they
have is whether we already know.

### 4. Four files before any prose

The quality of Silo's documentation is downstream of four mechanisms, not of good intentions:

- **`src/data/docs-release.mjs`** — about fifteen lines pinning the exact source SHAs the docs were
  reviewed against, with a test asserting that `prerelease` implies no version number and that every
  revision is a real forty-character SHA. The docs cannot claim "stable" without naming a version.
- **A content schema with `beta: boolean`**, so beta status is enforced rather than remembered. It
  also defines a version-floor field with the comment that it may be populated "only when
  established by source/release evidence" — a field you may only fill in with proof.
- **`scripts/test-docs-structure.mjs`**, which asserts the information architecture itself: group
  names, slug shape, sidebar-to-file bijection, no orphans, no reachable drafts. You cannot land an
  orphan page.
- **Flat `/docs/<slug>` URLs decoupled from directory layout.** Silo is paying for this retroactively
  with redirect machinery. ferrum is pre-public and can have the stability without the cost.

### 5. Preflight should refuse an apply that leaves no way in

> Silo keeps password sign-in for break-glass admins, so someone can still get in if the provider is
> down. […] **Silo won't turn passwords off unless at least one break-glass admin can still sign in
> with a password.**

The innovation is not the recovery path, it is the refusal at the moment of the dangerous change.
And this is the clearest case where ferrum can implement the idea *better than the project it came
from*: Silo can only check at the moment the switch is flipped, whereas ferrum evaluates the entire
resulting configuration before activating it. `preflight` can hard-fail an apply whose resulting
generation would leave no reachable authentication path — SSO on, no console password, daemon
published, no tunnel route — with rollback still available and nothing yet changed. That is a
preflight check only a declarative system can write.

Silo also offers a URL that forces the local login form (`/login?local=1`) when the provider is
broken but the proxy is fine. ferrum should confirm the equivalent is reachable on a published host.

### 6. Settings should distinguish inherited from overridden, and reset should *delete*

Their admin troubleshooting guide is mostly about impersonating a user, which does not map — ferrum
has one operator and the apps own their own accounts. The valuable part is underneath:

> Compare the affected value with the inherited value before changing it. […] **Reset a wrong value
> rather than typing in a replacement**, and leave unrelated settings alone.

An operator who cannot see that a value is overridden "fixes" it by typing in what they believe the
default is, and now there are two overrides where there was one. Reset restores a relationship;
retyping freezes a guess. ferrum knows its defaults exactly — they are in the Nix module — so it can
render origin with certainty Silo cannot. The distinction between *delete the override* and *write
the default back as a new override* is invisible in a UI unless it is built in deliberately.

### 7. Writing conventions, adoptable immediately

- **Task-shaped titles.** "Update Silo safely", "Plan and test your backups" — never "Updates".
- **`description:` frontmatter as the page's three-beat promise**: "Back up, pull the new image, and
  check the server after an update." It reads like a test plan.
- **Caveats as negations of a plausible false belief**, placed at the step that causes them rather
  than in a callout box: "Keep that output. `latest` won't identify the old image once you've pulled
  a new one." Most of these exist because someone assumed the opposite.
- **`:::caution` rationed to two uses across 82 pages**, so the box still means something.
- **A predictable `## If it fails` section** at the foot of a page, written symptom-first, sometimes
  naming the fix that will *not* work.
- **Separate the two audiences at the root**, with deliberately paired pages for shared topics and
  "ask whoever runs your server" as a standing instruction in every household-member page. ferrum has
  the same two audiences and currently addresses neither.

## What is not worth copying

- **A plugin ABI.** Silo needs one because third-party code must run inside its process to reach
  TMDB or federate an identity. ferrum's catalog is already a declarative data surface on top of
  NixOS modules — a second, worse extension system layered on a good one. Worse, code installed at
  runtime is state no generation describes and no rollback undoes, which breaks the exact claim that
  differentiates ferrum. Their own docs concede the limit of the mitigation: a catalog checksum
  "confirms the download matches the catalog entry; it tells you nothing about what the plugin does."
  Copy the three-tier trust model (first-party, approved-community, unreviewed) as catalog
  provenance instead. **Worth recording as a deliberate non-goal, because someone will ask.**
- **Tailscale sign-in.** Their own documentation makes the case against it: "Anyone who can edit your
  tailnet policy can make themselves a Silo admin." A second identity source whose compromise is an
  ACL edit, to save one password prompt for one person, is a bad trade. (Tailscale as *transport* is
  a different question and is interesting — a tailnet HTTPS address is a secure context, so the
  `__Host-` session cookie works from a phone with no SSH client. An optional module, never the only
  route, since adding a third party to the break-glass path contradicts the point above.)
- **Prometheus, Grafana, OpenTelemetry, pprof.** Wrong audience. Someone who would run a Prometheus
  stack would run Saltbox. The sub-ideas are worth taking — fail-closed config validation, and a
  sidecar manifest marking a truncated capture `"valid": false` so nobody debugs a partial capture as
  though it were whole — but not the stack.
- **Access groups, profiles, parental controls, per-user API keys.** ferrum's users are the apps'
  users; there is no surface to put these on.

## Two things this analysis surfaced about ferrum itself

Neither came from Silo having them. Both came from reading their docs carefully enough to notice
what ferrum does not say.

**ferrum has no egress disclosure, and self-hosters self-host for exactly that reason.** Silo
publishes a four-column table — service, when it is contacted, what is sent, on by default — and
states plainly that it has no analytics or usage telemetry. ferrum's table writes itself: the
Cloudflare API, Let's Encrypt, plex.tv, the update check, and each app's own outbound traffic, marked
by whether the call is ferrum's or the app's. It costs a day and is the highest trust-per-byte
document the project could publish.

**ferrum leaks its stack into Certificate Transparency and discloses it nowhere.** `acme.nix` issues
"one `security.acme.certs` entry per public vhost", so `sonarr.`, `radarr.`, `qbittorrent.` and the
rest land in public, permanently searchable CT logs, advertising precisely what runs at that domain.
Silo's Tailscale page warns about the equivalent — "The server's name appears in public certificate
logs, so choose one you don't mind others seeing" — and ferrum makes no such warning. Because ferrum
uses DNS-01 rather than HTTP-01 it has an option Silo does not: a single wildcard `*.<baseDomain>`
puts only the base domain in CT. **This is currently a design decision made by accident**, and it
should be made on purpose, documented either way.

## Verification

The category conclusion and every quotation above were spot-checked against the cloned documentation
tree rather than taken from a summary. The two claims about ferrum in the previous section were
checked against this repository: `crates/ferrumd/src/main.rs` (thirteen routes, no health endpoint)
and `modules/proxy/acme.nix` (per-vhost certificates).
