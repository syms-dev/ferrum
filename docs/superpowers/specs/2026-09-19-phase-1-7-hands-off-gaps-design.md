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

### Developer Documentation — R1

This section resolves the blind planning panel's generation-1 findings (`.ckit/state/evidence/phase-1-7-r1-panel-register.md`) as consolidated and adjudicated by the EM
(`.ckit/state/evidence/phase-1-7-r1-em-decision-gen1.md`). It is additive to A1-A8 above — no
acceptance-criterion text, user story, or "why this is not optional" paragraph in this document is
edited by this section.

#### Architecture overview & plane ownership (UF-13, UF-16)

The reused pattern in this repo is: Nix computes desired state as data, serializes it to JSON baked
into the system closure, and a small Rust binary applies it with `ureq` against the target's own
HTTP API (`modules/core/reconciler.nix` -> `crates/ferrum-reconcile/src/main.rs`). R1 follows the
same shape, with Cloudflare as the thing being reconciled.

New crate: **`crates/ferrum-dns/`** (library, new workspace member -- `crates/Cargo.toml:3`'s
`members` list gains `"ferrum-dns"`). This is the one seam OQ1 asks for: it owns every Cloudflare
HTTP call and all zone/ownership logic, and it is the only crate in the workspace that talks to
Cloudflare. Three call sites consume it and none re-implements its logic:

1. **`ferrum-install`** (operator's machine, before the disk is erased) -- A5's `verify_zone_access`
   at token-collection time, and A7's dry-run.
2. **`ferrum-apply apply`** (on-host, in-process) -- A1/A4's create/update/delete, invoked as a
   direct function call inside `run_inner`, not as a separate systemd unit.
3. **A new systemd timer** (on-host, scheduled) -- A8's optional DDNS updater, invoking a new
   `ferrum-apply reconcile-dns` subcommand as a separate process.

Why (2) is a step inside `ferrum-apply apply` rather than its own systemd unit, unlike
`ferrum-reconcile`: decision D-08 requires DNS failure to surface through the *existing*
`ApplyResult`/`classify()` in `crates/ferrum-apply/src/apply.rs:39-56` -- the function that already
decides one `ferrum-apply apply` invocation's verdict from the switch exit code and
`all_managed_units_active()` (`apply.rs:103-139`). Folding DNS into a separate systemd unit and
letting `all_managed_units_active()` absorb it would collapse the per-record breakdown D-08 also
requires into a single boolean. So DNS reconciliation is a plain Rust call inside `run_inner`, after
the switch and health-check (`apply.rs:361-363`), and its per-record outcome is folded into the same
`ApplyResult` the switch/health-check already produce (see "Apply-result semantics" below).

This also answers R1-BE-05's question about `modules/core/reconciler.nix:145` directly. Re-confirmed
against HEAD (the panel's own citation held): `systemd.services.ferrum-reconcile = lib.mkIf (pairs !=
[ ] || rootFolders != [ ] || downloadPaths != [ ] || plexConfig != { }) { ... }` really does gate that
unit on those four predicates, so a host publishing one app with no download-client pairing, root
folder, or Plex config never gets the reconcile unit at all. DNS reconciliation does not reuse that
unit or that gate: because it runs as a step inside `ferrum-apply apply` itself, it runs on every
apply regardless of `pairs`/`rootFolders`/`plexConfig`, so a DNS-only host is never skipped.

#### The seam (OQ1, frozen)

`crates/ferrum-dns/src/lib.rs` exposes:

```rust
pub struct Client { /* token + an ureq::Agent + a base_url, the base_url
                        overridable only under #[cfg(test)] -- see UF-19 */ }

impl Client {
    pub fn new(token: Secret) -> Self;                          // real Cloudflare endpoint
    #[cfg(test)]
    pub fn with_base_url(token: Secret, base_url: String) -> Self;

    pub fn resolve_zone(&self, base_domain: &str) -> Result<Zone, CloudflareError>;
    pub fn verify_zone_access(&self, base_domain: &str) -> Result<(), CloudflareError>;
    pub fn list_records(&self, zone: &Zone) -> Result<Vec<DnsRecord>, CloudflareError>;
    pub fn create_record(&self, zone: &Zone, name: &str, target: &RecordTarget) -> Result<DnsRecord, CloudflareError>;
    pub fn update_record(&self, zone: &Zone, record_id: &str, target: &RecordTarget) -> Result<DnsRecord, CloudflareError>;
    pub fn delete_record(&self, zone: &Zone, record_id: &str) -> Result<(), CloudflareError>;
    pub fn verify_authoritative(&self, zone: &Zone, name: &str, expected: &RecordTarget) -> Result<bool, std::io::Error>;
}

pub struct Zone { pub id: String, pub name: String, pub nameservers: Vec<String> }
pub enum RecordTarget { A(std::net::Ipv4Addr), Cname(String) }
pub struct DnsRecord { pub id: String, pub name: String, pub target: RecordTarget, pub proxied: bool, pub owned_by_ferrum: bool }
```

`verify_zone_access` is a distinct method from the CRUD group, not a call-site convenience: it runs
at **token-collection time** (`crates/ferrum-install/src/answers.rs`, inside `collect()`), before a
target exists, and it answers a narrower question ("can this token see a zone that covers this
domain at all") than `resolve_zone` ("which exact zone, with which nameservers"). Today it is
implemented as `resolve_zone(base_domain).map(|_| ())`, kept as a separate name because A5's
prompt-time error must be worded for "the token can't see your domain," not for a caller that
already has a `Zone` in hand.

#### Ownership model (UF-01, Critical -- decision D-01)

Authority is a **ferrum marker in the Cloudflare record's own `comment` field**, never
`/var/lib/ferrum/state` -- that directory is on the OS disk (`modules/core/options.nix:35`, default
`/var/lib/ferrum/state`) and this same document's R2 (lines 96-98) establishes that a reinstall's
wipe discards it, which is exactly the event A4 must survive.

- **Marker.** The literal string `"ferrum-managed"` written into `comment` on every `create_record`
  call. Exact-match comparison on `list()` -- no version tag, no JSON blob in the comment -- kept
  minimal because D-01's own reopen trigger names "operator-editable without ferrum noticing" as a
  real risk, and a longer marker is more of that surface, not less.
- **Rebuild on a cache-less host.** `list_records(zone)` is the only source of truth. A fresh or
  reinstalled host has no local cache and needs none: every apply calls `list_records` and
  partitions the result by `owned_by_ferrum`.
- **Conflict rule.** A record with **no** ferrum marker is **foreign** (A3) -- never overwritten,
  never deleted, only reported. A record **with** the marker is ferrum's and is freely
  updated/removed as the desired-record list changes (A4).
- **The verification D-01 explicitly still owes**, and this document cannot close it -- it requires
  a live call against the real Cloudflare API, which this desk has no access to: confirm the
  `comment` field (a) persists across reads, (b) is long enough for the marker, (c) is returned by
  `list` without a second API call, and (d) is not silently stripped on a reduced-scope token. This
  is the **first thing** the implementer verifies when `crates/ferrum-dns` is built, before writing
  the rest of the ownership logic against an assumption. If any of (a)-(d) is false, the fallback is
  a **local cache keyed by record id, advisory only** -- never authoritative (D-01 already rejected
  an authoritative local ledger) -- used only to avoid re-deriving ownership from a `list` call on
  every single operation.

#### Zone resolution (UF-02 -- decision D-06)

`modules/core/options.nix:182-186` documents `baseDomain` with `example = "home.example.com"` -- a
subdomain of an apex, not the apex itself. A naive `GET /zones?name=<baseDomain>` looks for a zone
literally named `home.example.com` and returns empty against a token correctly scoped to
`example.com`, rejecting a **correct** token at the A5 prompt.

`resolve_zone` instead calls `GET /zones` (every zone visible to the token) and picks the visible
zone name that is the **longest matching suffix** of `baseDomain`. If no visible zone is a suffix, or
an NS lookup for `baseDomain` shows delegation away from the resolved zone's own nameservers,
`resolve_zone` returns an error naming the mismatch, and A5's prompt refuses on that error rather
than accepting the token. The only real-world case this repo has evidence for (`thesyms.ca`) is an
apex; a subdomain zone is untested in production and should be the first integration-test case for
this function, not just a unit test against the fake server (see "Testability" below).

#### Which names get records (UF-04 -- decision D-03)

The desired-record set is **`publicApps`** (`exposure == "public"`, `modules/proxy/lib.nix:10-12`),
plus `auth.<baseDomain>` when `ferrum.auth.enable && publicApps != { }` -- mirroring exactly the set
`modules/proxy/acme.nix:108` already issues certificates for
(`lib.optionalAttrs (ferrum.auth.enable && publicApps != { }) { "auth.${ferrum.proxy.baseDomain}" = ...; }`).
`lan` apps are excluded: they get an nginx vhost and an IP allow-list but no ACME cert
(`modules/proxy/nginx.nix:25-28`'s `lanRestriction`), so a public record would hand an external
client a self-signed TLS handshake before nginx denies them -- publishing exactly what the LAN
restriction exists to prevent. The resulting "the `lan` hostname doesn't resolve from the LAN either"
gap is what A6's frozen split-horizon disclaimer already covers; R1 introduces no new gap here.

`modules/lib/app-submodule.nix:55-57` is worth noting for the installer path specifically: `exposure`
already defaults to `"public"` whenever `ferrum.proxy.enable` is true, and the installer's own
`Answers.apps` (`crates/ferrum-install/src/answers.rs`) has no per-app exposure question today. So
for every install run through the current CLI, `publicApps` and `answers.apps` are the same set --
the Nix-side `publicApps` filter is still the authority (an operator can always set `lan` by hand in
`settings.json`), but the installer-side dry-run (A7) can reasonably show `answers.apps` as its
working set without waiting on a settings round-trip.

New Nix module **`modules/proxy/dns.nix`** computes this list, reusing `proxyLib.publicApps` and
`vhostNameFor` from `modules/proxy/lib.nix:1-30` exactly as `acme.nix` and `nginx.nix` already do --
no new filtering logic, so the DNS record set cannot drift from the certificate set the same way
`modules/proxy/lib.nix:7-9`/`modules/proxy/nginx.nix:138` already keep the vhost set and the
`exposedApps` filter from drifting apart.

#### `proxied: false` (UF-09 -- decision D-05)

Every record `ferrum-dns` creates or updates carries Cloudflare's `proxied: false` (grey cloud).
Orange-cloud proxying makes every request arrive from a Cloudflare edge address, which inverts
`modules/proxy/nginx.nix:25-28`'s `allow ${net}; deny all;` against `ferrum.proxy.trustedNetworks`
(`modules/core/options.nix:209-211`, RFC1918 by default) into a **total outage** for the exact
restriction meant to protect `lan` apps, and it is a bandwidth/ToS problem for Plex/Jellyfin
streaming through Cloudflare's edge. A managed record later found `proxied: true` (an operator
toggled it in the Cloudflare dashboard) is **drift** -- reported and corrected the same way any other
desired-vs-actual mismatch is (A4).

#### Credential handling (UF-06, UF-07 -- decision D-09)

**Materialization (UF-06).** `modules/proxy/acme.nix:83-89` currently gates
`sops.secrets."${credentialSecret}"` on `lib.mkIf (publicApps != { } && credentialProvided)`. Widen
this at `acme.nix:83` to also cover "DNS-record management wants a record" (any entry in
`dns.nix`'s desired-record list, independent of ACME) OR "the DDNS updater is enabled" -- an `||`
extension of the existing predicate. Ownership stays `owner = "acme"; group = "acme"`
(`acme.nix:86-87`) -- no new principal. A host with only `lan` apps, or only the daemon record
(pending H-01 below), needs no ACME cert but still needs this secret materialized so both
`ferrum-apply apply`'s in-process DNS step and the DDNS-updater unit can read it.

**The prefix trap (UF-07).** `crates/ferrum-apply/src/put_secret.rs:100-107` documents that
`acme-dns.sops` deliberately stores the literal systemd `EnvironmentFile=` line
`CLOUDFLARE_DNS_API_TOKEN=<token>`, byte-for-byte, because `modules/proxy/acme.nix` hands the
decrypted file to systemd as an `EnvironmentFile=`. `crates/ferrum-reconcile/src/main.rs:118-128`'s
`read_api_key` -- which trims and returns a secret file's content verbatim -- is the **wrong**
function for this one secret: it would return `CLOUDFLARE_DNS_API_TOKEN=abc123`, not `abc123`.
Wherever `ferrum-dns::Client` is constructed on-host, the token is read with a dedicated helper that
strips the exact `CLOUDFLARE_DNS_API_TOKEN=` prefix and **refuses** (rather than silently using the
un-stripped value) when the prefix is absent. The token stays in the `Authorization: Bearer <token>`
header only -- never a URL, never a log line, never process argv -- matching
`crates/ferrum-install/src/answers.rs:33-49`'s `Secret` newtype discipline, which extends unchanged
to this crate.

#### A5's verification and the live bypass (UF-20, High)

`crates/ferrum-install/src/answers.rs:282-314`'s `validate_cloudflare_token` (charset + length) is
the first half of A5; the second half -- actually calling Cloudflare to prove the token can list a
zone -- is new, and both halves must run through **one function**,
`answers::validate_and_verify_cloudflare_token`, so there is exactly one place a future change to
either check has to be made.

Two call sites must both reach it:
- **First run**: `crates/ferrum-install/src/answers.rs:218-229`, inside `collect()`, immediately
  after `io.ask_secret(...)`.
- **Resumed run**: `crates/ferrum-install/src/main.rs:246-254`. **This is a live defect at HEAD, not
  a hypothetical.** This code path calls `prompt::PromptIo::ask_secret` directly and passes the raw
  result straight into `answers::Secret::new(...)`, reaching neither `validate_cloudflare_token`'s
  charset check nor (once added) `verify_zone_access`. A resumed install today can carry a token with
  the exact zsh-trailing-`%` defect the charset check exists to catch. The fix routes
  `main.rs:250-253`'s `prompt::PromptIo::ask_secret(...)` result through
  `answers::validate_and_verify_cloudflare_token` before it is wrapped in `Secret::new`.

`verify_zone_access` needs network access from wherever `ferrum-install` runs (the operator's Docker
container) -- already true for every other outbound call this binary makes (SSH to the target), so
this adds no new network posture, only a new outbound HTTPS destination (`api.cloudflare.com`).

#### Cloudflare error semantics (UF-15)

Cloudflare's v4 API can answer **HTTP 200** with `{"success": false, "errors": [...]}` for a
permission or validation failure. The house idiom this repo uses everywhere else --
`ureq::get/post(...).call().map_err(...)` (`crates/ferrum-reconcile/src/main.rs:276-281, 306-309,
543-554`) -- only inspects HTTP status, so it would read that response as success. Every
`ferrum-dns` method that calls Cloudflare checks the JSON body's own `success` field independent of
HTTP status, and folds a `false` into a `CloudflareError` carrying Cloudflare's own
`errors[].code`/`errors[].message` so the caller reports the real cause instead of "it worked."

#### Apply-result semantics (UF-12 -- decision D-08)

`crates/ferrum-apply/src/apply.rs`'s `run_inner` gains a step after `wait_for_healthy`
(`apply.rs:361-363`): call into `ferrum-dns` with the current closure's desired-record JSON (see
"Nix wiring summary" below), reconcile create/update/delete against `list_records`, then run D-07's
post-apply verification (next section) for every record just written. The per-record outcomes are
folded into the existing `ApplyResult`: any record failure (create/update/delete error, or a D-07
verification mismatch) makes the overall result **`ApplyResult::Degraded`** with a per-record
breakdown appended to the reason string -- even when the switch and app health-check were otherwise
`Succeeded`. A later `ferrum-apply apply` re-attempts only the records that failed or are missing,
using the same idempotent create-if-absent/update-if-drifted logic, and never touches a record
`list_records` reports as foreign.

#### Post-apply verification (UF-03 -- decision D-07)

This is the check the parent incident (`auth.thesyms.ca` not resolving, this document's lines 38-41)
is really about, and the one every sibling requirement already has (R5/A1 checks the certificate
issuer; R8/A6 does create-link-compare-inode-remove) while R1 had none.

`Client::verify_authoritative(zone, name, expected)` queries `name`'s record **directly against
`zone.nameservers`** -- the authoritative servers `resolve_zone` already returned -- never the host's
local/recursive resolver, which can hold a negative-cache entry from an earlier lookup for up to the
zone's SOA minimum-TTL and would report a freshly-created record as absent. This is a plain DNS
query (not an HTTP call), issued with a short bounded poll/retry (a few attempts over a handful of
seconds) before a mismatch is treated as real. A mismatch or persistent failure is a per-record
failure folded into `ApplyResult::Degraded` per D-08 above.

#### A8: address detection, reachability proof, and updater observability (UF-08)

**Detection runs on the target, not the operator's machine.** `crates/ferrum-install/src/
preconditions.rs:141-190` (`find_ssh_auth`) and every remote command in this binary confirm that
`ferrum-install` runs **from the operator's own machine over SSH** -- a VPN'd or corporate-NAT'd
laptop, or a residential CGNAT connection, would report an address that is not the target's.
Detection is a new remote command executed the same way `verify_host` already executes checks
(`collect::run(&pre.target, &pre.ssh_auth, ...)`), running an outbound IPv4-only HTTP call from the
target to a public address-echo endpoint. It runs before the DNS record is created, and the
candidate is shown to the operator for confirmation (A8's existing text) -- never written silently.

**A shown address is not a verified one.** DA-R1-07's point stands even with detection fixed: CGNAT,
a transparent proxy, or a misconfigured echo response can still yield an address that is not
reachable *as this host*. So after the record is created and D-07's authoritative-nameserver check
passes, a **new, distinct verification category** -- `verify::external_reachability_checks`,
alongside the existing `auth_checks`/`unauthenticated_checks` in
`crates/ferrum-install/src/verify.rs` -- issues its HTTPS request **from the `ferrum-install` process
itself**, not via `collect::run`/SSH. This is the one check in this binary that must NOT run over SSH
to the target, because the entire point is to prove reachability from a network path other than the
target's own. It reuses the exact assertion `auth_checks` already makes (a redirect, or a 200
depending on SSO) but from a genuinely independent vantage point. This does not fully solve CGNAT for
an operator whose own machine shares the same egress as the target -- that residual risk is recorded
here rather than papered over.

**Updater observability.** A8's own rationale -- "the operator cannot observe the failure it
prevents" -- applies unchanged to the updater's own failure mode: a timer erroring silently for six
weeks looks, from outside, identical to one that has never needed to do anything. The updater (see
"Nix wiring summary" below) writes a Unix timestamp to
`/var/lib/ferrum/state/dns-updater-last-success` after every successful reconcile cycle, success or
no-op alike. This file's age is the "first-class value" the Devil's Advocate's premortem asks for;
surfacing it in a dashboard is out of R1's scope (this document's own "Out of scope" section defers
the visual/dashboard surface), but the file itself is what that future work reads, and its absence or
staleness is exactly the earliest signal the premortem names.

#### Adoption UX and timing (UF-10)

A7's dry-run and A3's adopt/decline decision are surfaced at **one gate, before the disk is erased**
-- inside `plan_install` (`crates/ferrum-install/src/main.rs:450-469`), after `confirm::confirm` and
before `recheck`/the disk-serial write, matching R2/A4's identical timing lesson (offer or decision
before the point of no return). The dry-run needs no host contact: it evaluates the generated flake's
`system.build.ferrumDnsConfig` (via the same eval-only mechanism `preflight::tier1` already uses for
Tier 1 -- `nix eval`, never `nix build`) to get the desired-record list, then calls
`ferrum-dns::list_records` directly from the installer process against the real zone using the
in-memory, not-yet-written-anywhere token. A **decline** on a foreign record is recorded and threaded
into `final_report` (`crates/ferrum-install/src/main.rs:769-806`) as a named unreachable app -- the
same place credentials and URLs are already reported.

#### A6 placement (UF-14, UF-17)

Unlike R4/A1-A2 (`crates/ferrum-install/src/main.rs:238-239`) and R5/A3 (line 260), A6 as written
names no placement. It appears in **both**:
- A7's dry-run output, immediately after the create/update/skip/foreign summary, and
- `final_report` (`crates/ferrum-install/src/main.rs:769`), immediately after the `urls:` block
  (`main.rs:780-787`).

Fixed wording, so a test can assert on it verbatim (this is UF-17's "no form given" finding closed):
*"records point at the public address; reaching them from inside your LAN depends on your router's
NAT hairpin, which many do not support -- this is expected, not a failure."*

#### IPv4-only (UF-18)

`RecordTarget` above has no `AAAA`/IPv6 variant. This is a scoped decision for R1, not an oversight:
a dual-stack host advertises no IPv6 record, and an IPv6-only host is unsupported. Revisit if a
future requirement needs it.

#### Testability (UF-19)

No HTTP-mocking pattern exists anywhere in this workspace today, and the Nix sandbox running
`workspace-tests` has no network access -- tests must never call Cloudflare for real.
`crates/ferrum-dns/src/testing.rs` provides a hand-rolled fake: a `std::net::TcpListener` bound to
`127.0.0.1:0`, a small single-threaded HTTP/1.1 responder serving recorded, Cloudflare-shaped JSON
bodies (including `{"success": false, "errors": [...]}` for UF-15's case), and
`Client::with_base_url` pointed at it. A5's `verify_zone_access` and A7's dry-run are tested against
this fake; nothing in the test suite makes a real outbound call.

#### Dependency wiring

`ureq = { version = "2", features = ["json"] }` -- the identical line already at
`crates/ferrum-reconcile/Cargo.toml:10` -- is added to `crates/ferrum-dns/Cargo.toml` only.
`crates/ferrum-install/Cargo.toml` and `crates/ferrum-apply/Cargo.toml` each gain a **path
dependency on `ferrum-dns`** (`ferrum-dns = { path = "../ferrum-dns" }`), not a direct `ureq`
dependency -- this is the literal shape of "one seam": both call sites share one HTTP-client
dependency through one library crate rather than each vendoring their own. This satisfies
R1-BE-01's underlying requirement (`ferrum-install` must be able to make Cloudflare calls) without
duplicating the dependency. **No new package is added to `Cargo.lock`**: `ureq` v2 with
`features=["json"]` is already resolved in the workspace lockfile via `ferrum-reconcile`. If any
part of this design turns out to need a crate not already in the lockfile, that is a
**stop-and-report** condition for the implementer, not a decision to make unilaterally.

#### Nix wiring summary

- **`modules/proxy/dns.nix`** (new): computes the desired-record list (see "Which names get
  records" above) as `config.system.build.ferrumDnsConfig`, a `pkgs.writeText` JSON (same pattern as
  `reconciler.nix`'s `reconcileConfigFile`, `modules/core/reconciler.nix:134-137`), exposed at
  `/etc/ferrum-dns-config.json` inside the closure (`environment.etc."ferrum-dns-config.json".source
  = ...`) so both a fresh build (`{toplevel}/etc/ferrum-dns-config.json`, read directly by
  `ferrum-apply apply`'s in-process step) and the currently-running system
  (`/etc/ferrum-dns-config.json`, read by the updater timer) find it without any systemd
  `Environment=` plumbing. Also declares `ferrum.proxy.dns.ddnsUpdater.{enable,intervalMinutes}` and
  wires `systemd.timers.ferrum-dns-updater` / `systemd.services.ferrum-dns-updater` (gated on
  `ddnsUpdater.enable`), running `ferrum-apply reconcile-dns --config /etc/ferrum-dns-config.json`.
- **`modules/proxy/acme.nix:83`** (modified): widen the materialization `mkIf` per D-09, described
  above.
- **`modules/core/options.nix`** (modified): add `ferrum.proxy.dns.recordMode` (enum `["a"
  "cname"]`, A2), `ferrum.proxy.dns.staticAddress`/`cnameTarget` (str, A2),
  `ferrum.proxy.dns.ddnsUpdater.{enable,intervalMinutes}` (A8).
- **The daemon record (H-01, below) is a single named toggle**, e.g.
  `ferrum.daemon.dns.includeRecord`, read by `dns.nix` when building the desired-record list, so
  whichever of options A/B/C the owner picks is a one-line change to that option's default plus (for
  option B only) a new vhost module.

#### OPEN -- needs the owner (blocks the planning gate)

**H-01 / UF-05, High.** A1 literally requires a record for `ferrum.<baseDomain>` (the daemon's own
subdomain). But `crates/ferrumd/src/main.rs:248-250` states outright, in its own security-invariant
comment on `session_handler`, that "nginx builds vhosts solely from `exposedApps`, and
`ferrum.daemon.subdomain` is declared but unused" -- correcting the panel's own citation of
`main.rs:250-252` for this quote; the exact sentence spans `248-250`, not `250-252` -- and
`modules/proxy/nginx.nix:132-136`'s catch-all (`_ferrum_unmatched`, `default = true`,
`locations."/".return = "444"`) answers that hostname with a closed connection and no response.
Creating the record turns a clean NXDOMAIN into a resolving hostname that silently dies, on the one
name an operator would actually visit.

Three options, unchanged from the EM's decision register:
- **A** -- drop the daemon-subdomain clause from A1 for this pass. Requires editing approved
  acceptance-criterion text; reserved for the owner, never for an agent.
- **B** -- add a minimal `ferrumd` vhost now, in scope for R1. This expands the change into
  daemon-facing auth/CORS work that has had no review here, and `ferrumd/src/main.rs:246-253`'s own
  comment names this exact daemon-vhost scenario as the moment its `SameSite`/CORS posture becomes
  load-bearing rather than incidental.
- **C** *(EM recommendation)* -- create the record as A1 says, and disclose it honestly: the A7
  dry-run and `final_report` both state that `ferrum.<baseDomain>` resolves but returns a closed
  connection until daemon web access ships.

This document is written so any of the three is a small, localized change: the desired-record list
in `modules/proxy/dns.nix` gates the daemon entry behind one named toggle (see "Nix wiring summary"
above), so option A is flipping that toggle's default, option C is leaving it as designed and adding
the one sentence above to the dry-run/report text, and option B is additionally standing up a vhost
this document does not otherwise specify. **Do not implement any part of R1 that depends on this
choice until the owner picks one** -- everything else in this section is independent of it.

**Strong dissent on D-02, for the owner's awareness.** The Devil's Advocate argued for one
`*.<baseDomain>` wildcard record instead of per-record management. `modules/proxy/nginx.nix:126-127`'s
own comment calls a wildcard "the normal way these subdomains get resolved," and the
`_ferrum_unmatched`/444 catch-all (`nginx.nix:132-136`) already exists partly to make a wildcard
safe. A wildcard would satisfy A3 **by construction** (a more-specific record always wins over a
wildcard) and would delete most of the ownership-marker machinery specified above. The EM ruled
per-record because A4's text ("one record per app... ownership is tracked so removal never deletes a
pre-existing record") describes per-name create/remove as the mechanism, and the owner's standing
instruction is not to reinterpret approved criteria. **Reopen trigger:** if the owner confirms that
A1/A4's "one record per app" describes the desired *outcome* (every hostname resolves correctly)
rather than the specific *mechanism* (N distinct Cloudflare records), the wildcard design becomes
available and would delete a substantial fraction of the work specified above (the ownership marker,
per-record create/update/delete, most of D-01's machinery) in favor of a single record maintained
once.

#### File-scope summary (for story boundaries)

```
crates/ferrum-dns/                       NEW crate (the seam)
  Cargo.toml, src/lib.rs, src/client.rs, src/zone.rs,
  src/ownership.rs, src/record.rs, src/testing.rs

crates/ferrum-install/
  Cargo.toml            MODIFIED (add ferrum-dns path dep)
  src/answers.rs         MODIFIED (validate_and_verify_cloudflare_token; A2/A8 prompts)
  src/main.rs            MODIFIED (fix UF-20 bypass; A7 dry-run + adopt/decline gate;
                                    A6 caveat in final_report)
  src/verify.rs          MODIFIED (external_reachability_checks; A6 caveat)
  src/dns.rs             NEW (install-time orchestration: dry-run diff, eval of
                               system.build.ferrumDnsConfig)
  src/address.rs         NEW (A8 target-side detection command)

crates/ferrum-apply/
  Cargo.toml             MODIFIED (add ferrum-dns path dep)
  src/apply.rs           MODIFIED (new step in run_inner; ApplyResult folding, D-08)
  src/dns_reconcile.rs   NEW (create/update/delete + D-07 verification, shared by
                               the in-process call and the `reconcile-dns` subcommand)
  src/main.rs            MODIFIED (new `reconcile-dns` subcommand)

crates/Cargo.toml        MODIFIED (workspace member: ferrum-dns)

modules/proxy/dns.nix     NEW (desired-state computation, updater timer/service)
modules/proxy/acme.nix    MODIFIED (D-09 gate widening, acme.nix:83)
modules/core/options.nix  MODIFIED (ferrum.proxy.dns.*, ferrum.daemon.dns.includeRecord)
```

#### Spec traceability

| Spec Req | Implementation approach | Files |
|---|---|---|
| A1 (create records for what's published) | `modules/proxy/dns.nix` computes the desired set (`publicApps` + `auth` + daemon-record toggle per H-01); `ferrum-apply apply`'s new step creates missing records via `ferrum-dns::create_record` | `modules/proxy/dns.nix`, `modules/proxy/lib.nix`, `crates/ferrum-apply/src/dns_reconcile.rs`, `crates/ferrum-dns/src/*` |
| A2 (A vs CNAME, a decision not a guess) | new `ferrum.proxy.dns.recordMode`/`staticAddress`/`cnameTarget` options, collected as a new installer prompt, rendered into settings; `RecordTarget` carries the choice through to Cloudflare | `modules/core/options.nix`, `crates/ferrum-install/src/answers.rs`, `crates/ferrum-install/src/render.rs`, `crates/ferrum-dns/src/record.rs` |
| A3 (never touch a foreign record) | ownership marker in `comment` (D-01); `list_records` partitions owned/foreign; foreign records only ever reported, in the A7 dry-run and (on decline) the final report | `crates/ferrum-dns/src/ownership.rs`, `crates/ferrum-install/src/dns.rs`, `crates/ferrum-install/src/main.rs` |
| A4 (reconciled, not created once; ownership tracked) | every `ferrum-apply apply` re-derives desired-vs-actual from `list_records` and converges (create/update/delete only owned records) | `crates/ferrum-apply/src/dns_reconcile.rs`, `crates/ferrum-apply/src/apply.rs` |
| A5 (credential scope verified at collection time) | `answers::validate_and_verify_cloudflare_token` calls `Client::verify_zone_access`; both collection sites (fresh + resumed) route through it, fixing UF-20 | `crates/ferrum-install/src/answers.rs`, `crates/ferrum-install/src/main.rs`, `crates/ferrum-dns/src/client.rs` |
| A6 (split-horizon disclosed) | fixed-wording caveat emitted in both the A7 dry-run and `final_report` | `crates/ferrum-install/src/main.rs`, `crates/ferrum-install/src/verify.rs` |
| A7 (dry-run before any change) | pre-disk-erasure diff of desired-vs-actual, evaluated via `nix eval` on `system.build.ferrumDnsConfig` plus a direct `ferrum-dns::list_records` call from the installer process | `crates/ferrum-install/src/dns.rs`, `crates/ferrum-install/src/main.rs`, `modules/proxy/dns.nix` |
| A8 (static address, optional DDNS updater, detected not guessed) | target-side detection (`collect::run`), operator-confirmed, written record; independent-vantage reachability proof (`verify::external_reachability_checks`); D-07 post-write authoritative-nameserver check; opt-in `ferrum-dns-updater` timer with a last-success timestamp file | `crates/ferrum-install/src/address.rs`, `crates/ferrum-install/src/verify.rs`, `crates/ferrum-apply/src/dns_reconcile.rs`, `modules/proxy/dns.nix` |

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
