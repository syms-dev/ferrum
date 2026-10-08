# Security review — Phase 1.7 R1 (ferrum manages its own Cloudflare DNS records)

**Gate: Security Clear. Verdict at HEAD `079e2a8`: CLEAR.** (At `0b6abc4` it was BLOCKED on one
Medium, SEC-M1; the fix landed in `079e2a8` and `policy-validator` re-checked it — see the
recheck section at the end.)
Scanners run in parallel: `secret-scanner`, `dependency-scanner`, `owasp-reviewer`,
`policy-validator`. `pentest-scanner` not applicable (no dynamic-pentest scope requested, no
authorized non-production target).

Diff reviewed: `git diff 339da0a..0b6abc4` scoped to `crates/ferrum-dns`,
`crates/ferrum-apply/src`, `crates/ferrum-install/src`, `crates/Cargo.{toml,lock}`,
`modules/proxy`, `modules/core/options.nix`, `modules/default.nix`, `nix/pkgs/ferrum-apply`,
`nix/modules/flake/checks.nix` — 34 files, +13578/-331.

**0 Critical · 0 High · 1 Medium · 3 Low · 1 Cosmetic.**

## Why this change warranted a real review
R1 gives ferrum write access to the operator's **real DNS zone** using a **live, long-lived
credential**. Unlike every other failure in this product, a bug here is **not recoverable by
reinstalling the box** — the damage is in someone else's zone.

## Findings

### SEC-M1 — Medium — BLOCKING — `modules/proxy/dns.nix:225-238`
`systemd.services.ferrum-dns-updater` sets only `Type = "oneshot"` and `ExecStart`. It runs as
**unconfined root**, on a recurring timer, reaching an **internet-facing API** while holding a live
`Zone:Read + DNS:Edit` credential. No `ProtectSystem`, `ProtectHome`, `PrivateTmp`,
`NoNewPrivileges`, or `CapabilityBoundingSet`.

The argument that makes this a real finding rather than a checklist item: the unit was modelled on
`modules/core/reconciler.nix`, which only ever talks to **localhost** — a materially different risk
profile. And this project already hardens a comparable unit: `modules/core/daemon.nix:181-207`
gives `ferrumd` exactly the directives missing here. This is an inconsistency with the codebase's
own standard, not an external rule imposed on it.

**Routed to the lane owning `modules/proxy/dns.nix`. Security cycle 1 of the 2-cycle budget.**
On the fix, re-dispatch **`policy-validator` only** — it is entirely that scanner's finding.
Note the fix must keep the unit able to read `/run/secrets/acme-dns`, reach the network, run `dig`,
and **write `/var/lib/ferrum/state/dns-updater-last-success`** (criterion A8 depends on that write,
and `ProtectSystem = "strict"` makes the filesystem read-only unless explicitly allowed). A hardened
unit that can no longer do its job would be a worse outcome than an unhardened one.

### SEC-L1 — Low — `modules/proxy/acme.nix:111-115`
The credential-materialization gate's third disjunct tests the **raw**
`ferrum.proxy.dns.ddnsUpdater.enable`, but `modules/proxy/dns.nix:70-71` computes
`ddnsEnabled = dnsEnabled && dns.ddnsUpdater.enable` and gates the timer on *that*. The timer
therefore cannot exist unless `dns.enable` is already true, so the disjunct is **provably
redundant** with the `|| ferrum.proxy.dns.enable` beside it — **and the in-line comment justifying
it describes a state that cannot occur.** A host with `dns.enable = false; ddnsUpdater.enable =
true` gets the token decrypted with no consumer at all. Not reachable from any installer-generated
`settings.json` (both default false). Fixed in the same cycle.

### SEC-L2 — Low — `crates/ferrum-dns/src/record.rs:210-215`, `client.rs:292-298`
`list_records` applies no type filter, but `into_model` silently drops every type other than
A/CNAME. An operator with an existing `AAAA` at a wanted name gets ferrum's `A` created beside it,
**with no disclosure in the dry run** — additive and reversible, not an ownership bypass, but silent,
and it produces an IPv4/IPv6 split brain. Fixed in the same cycle.

### SEC-L3 — Low — `crates/ferrum-dns/Cargo.toml:9`
`ureq` pinned at major line `2` (resolves 2.12.1); 3.4.2 is current. **Zero CVEs at either version**
— confirmed by a real `cargo-audit` run against the lockfile in a container (278 crates, zero
advisories) plus a fresh RustSec advisory-db clone; no `ureq` advisory exists at all. Pre-existing
pin, not introduced here, but the blast radius widens from 1 binary to 3. A 2→3 upgrade is a
breaking API change and belongs in its own approved dependency-bump story. Non-blocking.

### SEC-C1 — Cosmetic — `crates/ferrum-dns/src/client.rs` (several)
Cloudflare-issued zone/record ids (opaque hex, never operator input) are interpolated into URL paths
with no format assertion. No realistic attack path. Optional defence-in-depth for a future provider.

## Auto-Critical checklist — all PASS
- **Hardcoded secret:** none. The `Secret` newtype in both `ferrum-dns` and `ferrum-install` has a
  hand-written redacting `Debug` and **no `Display`**; there is a **single `.expose()` call site**,
  at `client.rs:585`, building only the `Authorization` header.
- **Secret in logs:** none. Every `CredentialError` / `CloudflareError` / `ReconcileError` `Display`
  names only paths, codes and zone names, never content.
- **Missing authz check:** none — see the ownership model below.
- **Error suppression hiding failures:** none. A panic-safety sweep across every untrusted-input
  parsing path (`dig` stdout, Cloudflare JSON, address-detection stdout, `/etc/ferrum-dns-config.json`)
  found **zero** `.unwrap()` / `.expect()` / `panic!` / `unreachable!` in non-test code.
- Tenant isolation and sync-in-async: **N/A** — not multi-tenant; no async runtime in these crates.

## The authorization model was attacked, not just read
`crates/ferrum-dns/src/ownership.rs` is the control preventing a write to a record ferrum does not
own. Both mints (`claim`, `adopt_by_operator`) are `pub(crate)`; the only public paths are
`record::plan` / `plan_with_adoptions`; the `#[cfg(test)]` `unchecked` escape hatch is gated on
`test` alone, so it is unreachable even from a crate enabling the `testing` feature.
**Eight named bypass attempts, all negative.** Independently corroborated by my own probe from
`ferrum-apply`: `error[E0451]: field 'name' of struct 'AdoptionDecision' is private`.

## A sub-scanner claim the reviewer overrode — recorded because it matters
`owasp-reviewer` reported `ureq` as a **new** dependency and therefore a hard stop needing the
owner's sign-off. **That is wrong**, and the security reviewer overrode it on evidence:
`git show 339da0a:crates/Cargo.lock:665` shows `ureq` already resolved via the pre-existing
`ferrum-reconcile` crate. The only lockfile change is the new `ferrum-dns` workspace-member block
plus two dependency edges. **No third-party package was added or bumped; no dependency-approval gate
is triggered.** A scanner being confidently wrong, caught and corrected with a command rather than
deferred to, is exactly what the aggregation step is for.

## What was executed vs. read
**Executed:** `cargo-audit` in a container against the real lockfile; a RustSec advisory-db clone
and spot-checks; the ownership bypass compile probe; `git show` against the pre-change lockfile.
**Read-derived (labelled as such):** the systemd hardening comparison, the credential flow trace,
the subprocess/argv construction review, and the panic-safety sweep. `systemd-analyze security
ferrum-dns-updater.service` **could not be run** — it needs a built system, which this sandbox has
no way to produce. That verification is owed when the SEC-M1 fix lands.


---

# Recheck at `079e2a8` — SEC-M1 RESOLVED, SEC-L1 RESOLVED

`policy-validator` re-dispatched alone, as the aggregating reviewer specified (SEC-M1 was entirely
its finding). Security cycle 1 of the 2-cycle budget; a second cycle was not needed.

## SEC-M1 — RESOLVED
`modules/proxy/dns.nix:247-297` now carries the full `daemon.nix`-style posture: `ProtectSystem =
"strict"`, `ReadWritePaths = [ ferrum.storage.stateDir ]`, `ProtectHome`, `PrivateTmp`,
`NoNewPrivileges`, `LockPersonality`, `RestrictSUIDSGID`, `RestrictRealtime`, `ProtectKernel*`,
`ProtectControlGroups`, `ProtectClock`, `SystemCallArchitectures = native`,
`SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ]` with
`SystemCallErrorNumber = EPERM`, and `RestrictAddressFamilies = [ AF_INET AF_INET6 AF_UNIX ]`.
Correctly adapted from `ferrumd`'s precedent rather than copied — one writable state dir instead of
ferrumd's four paths. **The original blocking condition — unconfined root, no confinement of any
kind, on a timer reaching the internet with a live write-scoped credential — no longer exists.**

## The `CAP_DAC_OVERRIDE` deviation — ruled acceptable, recorded as a Low residual
The brief asked for `CapabilityBoundingSet = ""`. The developer set `[ "CAP_DAC_OVERRIDE" ]` and
**measured why** rather than asserting it: the unit runs as root and must read
`/run/secrets/acme-dns`, mode `0400` owned by `acme:acme`. uid 0 bypasses another user's 0400 file
*only* via `CAP_DAC_OVERRIDE`, and systemd's `CapabilityBoundingSet=` also clears the effective set.
Its kernel probe, uid 0 against a real 0400 `acme:acme` file: empty set -> `Permission denied`;
`dac_override` only -> reads fine. The literal directive would have made the updater **fail every
cycle on the credential read** — worse than leaving it unhardened.

Both alternatives were correctly rejected, not merely dismissed:
- **`mode 0440` + `SupplementaryGroups = [ "acme" ]`** is strictly stronger *when the `acme` group
  exists* — but nixpkgs only defines that user/group when `security.acme.certs != {}`, and a
  DNS-only host (no public apps, therefore no certs) is a **supported ferrum topology**. The unit
  would hard-fail with "unknown group" on a supported configuration.
- **`LoadCredential=`** is the textbook answer, but the credential path is baked into the same JSON
  document `dns.nix` emits for the in-process apply path — a cross-cutting contract change, not a
  defect-loop fix.

**What the residual actually costs, scoped honestly:** `CAP_DAC_OVERRIDE` restores root's DAC bypass
for reads *and* writes, so a subverted unit could read any file regardless of owner or mode — other
services' secrets, other apps' state. The mitigation is that `ProtectSystem = "strict"` enforces
read-only at the **mount** level, which is independent of capabilities: `CAP_DAC_OVERRIDE` cannot
write through a read-only mount. So the blast radius is confined to **unauthorized reads**, outside
the single `ReadWritePaths` entry. That is stated plainly in the comment at `dns.nix:267-279` rather
than hidden behind the word "hardened".

**Revisit trigger:** only if the credential moves to `LoadCredential=`, or the `acme` group is made
unconditional.

## SEC-L1 — RESOLVED
`modules/proxy/acme.nix:117-126` is now `credentialProvided && (publicApps != { } ||
ferrum.proxy.dns.enable)`; the raw-`ddnsUpdater.enable` disjunct is gone. Traced against
`dns.nix:70-71` (`ddnsEnabled = ferrum.proxy.enable && dns.enable && dns.ddnsUpdater.enable`): a host
with `dns.enable = false; ddnsUpdater.enable = true` used to decrypt the token with **zero consumers
on the host**, and now does not. The rewritten comment at `acme.nix:84-116` states the reachability
chain accurately and no longer asserts the unreachable rationale it used to.

## What remains owed on a live host — stated, not glossed
`systemd-analyze security ferrum-dns-updater.service` needs a built system and **was not run**; the
recheck is static verification against the landed diff plus the prior build evidence. One item is
worth a first-real-run smoke check: **`RestrictAddressFamilies` excludes `AF_NETLINK`**, and this
unit genuinely resolves external hostnames twice (`ureq` reaching Cloudflare, and `dig` resolving
the `@server` NS hostname). glibc's `getaddrinfo` opens a netlink socket in `__check_pf()`; its
documented fallback on failure is to assume both families and proceed, and `daemon.nix:212` already
excludes it in production here — but that unit mostly *listens* where this one *resolves*, so the
precedent is close rather than identical. Cheap confirmation: `systemctl start ferrum-dns-updater`,
then check `/var/lib/ferrum/state/dns-updater-last-success` has a fresh mtime.

---

# Delta review at `8534190` (`079e2a8..8534190`) — SECURITY CLEAR

Four commits since the recheck: `e06bcfa` settings-schema + drift check · `2430c42` foreign-record
disclosure + catalog-subdomain invariant · `cc2a18a` Cloudflare zone-status parsing + apply-path
disclosures · `8534190` threading the zone warning to the final report. 10 files, +2067/−129.

**Delta: 0 Critical · 0 High · 0 Medium · 2 Low · 3 Cosmetic.**
**Whole feature, cumulative open: 0 Critical · 0 High · 0 Medium · Low and Cosmetic only.**

## Scanners run, and the one deliberately skipped
`secret-scanner` (three new operator-facing output surfaces), `owasp-reviewer` (new untrusted-input
parsing, a new `RecordAction` touching the ownership guard, new logging, a new CI step),
`policy-validator` (the `PUT /api/settings` input-validation contract gained three nested objects).
**`dependency-scanner` skipped, justified:** `git diff 079e2a8..8534190 -- crates/Cargo.lock` is
empty and no `Cargo.toml` appears in the delta — nothing for it to find beyond the full-R1
`cargo-audit` already recorded above. Running it anyway would have been ceremony.

## The five things I asked it to look at
1. **Parsing Cloudflare's `status`.** Only the literal `"active"` (trimmed, case-insensitive) and an
   **absent** field map to `Serving`; everything else — including Unicode-case variants and
   homoglyphs — falls to `Unrecognized` → `NotYetServing` and is **disclosed**. The
   `Unreported → Serving` choice, challenged by the Devil's Advocate and upheld, also holds under a
   security lens and for a sharper reason: **an on-path attacker able to strip the field from a TLS
   response could equally forge `"status":"active"`**, so this is a disclosure control, not an
   authorization control, and treating absence as hostile would buy nothing. No finding.
2. **The new disclosure surfaces** carry only zone name, status, nameservers, and record name/target
   — never a `Secret`. The single production `.expose()` call site is unchanged (its line moved only
   because doc comments were added above it).
3. **`.github/workflows/ci.yml`**: no `permissions:` change, no new or re-pinned `uses:`, and **no
   `${{ }}` GitHub Actions context interpolated into a `run:` script** — the classic injection sink.
   The meta-check's loop variable comes from the repo's own `nix eval` over its own `checks.nix`,
   not from a PR title or branch name.
4. **`settings-schema.json`**: `additionalProperties` count went 11 → 15, a delta of exactly the four
   new nested objects, **nothing pre-existing loosened**. Verified independently by two parties.
5. **`SkipForeignBeside` did not widen the ownership guard** — and is structurally incapable of doing
   so. It carries no `ManagedRecordId`, is never constructed in a `Delete`/`Update`/`Adopt` arm, and
   both call sites of `disclose_foreign_beside` draw from the `theirs` bucket, which by construction
   only holds records where `ManagedRecordId::claim()` already returned `None`.
   `ownership.rs` and `lib.rs` are **byte-for-byte unchanged** across the whole delta.

**Independently confirmed that `Client::with_base_url*` — the only route to a non-Cloudflare endpoint
— is compiled solely under `#[cfg(any(test, feature = "testing"))]`, with `testing` declared only in
`[dev-dependencies]` of both binary crates.** Proven by an executed `cargo tree -e normal` vs
`-e dev`: the production feature set is empty. I checked this myself too — every call site's line
number is past its file's `#[cfg(test)]`. A production binary cannot be pointed at another endpoint.

## New findings — all Low or Cosmetic, none blocking
| ID | Sev | Where | What |
|---|---|---|---|
| OWASP-001 | Low | `crates/ferrum-dns/src/record.rs:411-463` | `2430c42` inserted `disclose_foreign_beside` **between `plan_with_adoptions`'s doc comment and the function it documents**, so the adoption-boundary security invariant now renders against the wrong function. Worth fixing promptly — it documents the sole path to `ManagedRecordId` adoption. |
| OWASP-002 | Low (A09) | `crates/ferrum-apply/src/dns_reconcile.rs:1016` | `eprintln!` writes Cloudflare-sourced text to stderr with no control-character stripping; a value containing `\n` could forge a journald line. The JSONL sibling is already safe by construction (`serde_json::json!` escapes). Low-value: the source is TLS-authenticated data for the operator's own zone, and anyone who can inject here already controls it. |
| OWASP-003 | Cosmetic | `zone.rs:145-156` | `from_wire`'s docstring says `Unrecognized` carries the value "as Cloudflare sent it"; it carries the trimmed+lowercased value. |
| OWASP-004 | Cosmetic | `zone.rs:264-270` | Comment says an unknown status is disclosed rather than failing the listing — true for an unknown *string*, but a non-string `status` still fails deserialization. |
| OWASP-005 | Cosmetic (A05) | `.github/workflows/ci.yml` | `$name` interpolated unquoted into a `grep -E` pattern. Names are the repo's own Nix attributes, so robustness only. |

## Auto-Critical checklist (delta) — all PASS
No hardcoded secret · no secret in logs (every new `format!`/`progress.event`/`eprintln!` traced to
its interpolated types; none is a `Secret`) · no missing authz · no error suppression.
Tenant isolation and sync-in-async remain N/A.

## Still owed on a live host, unchanged and not glossed
`systemd-analyze security ferrum-dns-updater.service` needs a built system and **was not run** in this
delta either. The `AF_NETLINK`/`getaddrinfo` smoke check remains owed on first real deployment:
`systemctl start ferrum-dns-updater`, then confirm `/var/lib/ferrum/state/dns-updater-last-success`
has a fresh mtime. Nothing in this delta touches that unit.
