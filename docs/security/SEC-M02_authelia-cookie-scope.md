# SEC-M02 — Authelia's session cookie is shared across the whole base domain

**Status:** FIXED (2026-10-06, R5 first half) · **Severity:** Medium
**Found:** R13 security pass 3 · **Evidence:** `.ckit/state/evidence/phase-1-7c-r13-security-clear-3.md`
**Was:** ACCEPTED RISK (owner decision, 2026-09-23)
**Site:** `modules/proxy/authelia.nix`

## What it was

Authelia issued its session cookie scoped to `.<baseDomain>`, so one cookie covered every
published app. Some catalog apps deliberately carry unauthenticated bypass locations — API
paths that must work without an interactive login. R13 placed the control plane at
`ferrum.<baseDomain>`, behind that same cookie. A cookie obtained in the context of one app was
therefore presentable at the control plane's edge gate.

## Why it was accepted rather than fixed, in 2026-09

The fix is Authelia v4.38+ multi-domain `session.cookies`, isolating `ferrum.<baseDomain>` into
its own cookie. That forces a **second login** for the control plane, which cuts against ferrum's
hands-off, self-setup goal. The residual risk was bounded to Medium by a compensating control:
ferrumd did not trust the Authelia cookie for authorization, and required a session it had issued
itself under a `__Host-`-prefixed cookie no sibling subdomain can set or read.

## Why it is fixed now

The revisit trigger fired, by its own terms: R5 asks ferrumd to accept an Authelia-asserted
identity, which is precisely the second bullet of "Reopen this decision when…". The compensating
control cannot be spent while the risk it compensates for is still live, so the cookie scope is
narrowed **first**, as its own change, revertible on its own.

## The fix

`modules/proxy/authelia.nix` now emits a multi-domain `session.cookies` list instead of a single
`session.domain`:

| Cookie name | Scope | Portal |
|---|---|---|
| `ferrum_control_session` | `ferrum.<baseDomain>` | `auth.ferrum.<baseDomain>` |
| `authelia_session` | `<baseDomain>` | `auth.<baseDomain>` |

The control-plane entry is present only when `proxyLib.daemonPublished` holds — on an unpublished
(tunnel-only) dashboard nothing serves that name, and a cookie scope for it would name a portal
with no vhost.

Three properties of that list are load-bearing, and only two of them are enforced by Authelia.
All three were measured against the authelia 4.39.19 this repository pins, not recalled:

1. **`authelia_url` must sit inside its own entry's cookie scope.** A `ferrum.example.test` entry
   pointing at `https://auth.example.test` is refused: *"option 'authelia_url' does not share a
   cookie scope with domain 'ferrum.example.test'"*. This is why the control plane needs a portal
   hostname of its own, and therefore a vhost (`modules/proxy/nginx.nix`), a certificate
   (`modules/proxy/acme.nix`) and a DNS record (`modules/proxy/dns.nix`). That cost is the fix,
   not an extra.
2. **The more specific scope must be listed first.** Listing `example.test` before
   `ferrum.example.test` is refused: *"option 'domain' shares the same cookie domain scope as
   another configured session domain"*. List order is otherwise invisible to every other check in
   this repository.
3. **The two cookies must have different names — and Authelia does not check this.** Two entries
   both named `authelia_session` validate cleanly. A browser then sends both to
   `ferrum.<baseDomain>` under one name, and RFC 6265 does not say which the server reads: SEC-M02
   rebuilt inside its own fix. `ferrum` asserts the distinctness Authelia leaves open.

## Evidence

`nix/modules/flake/checks.nix`'s **`authelia-cookie-scope`**, wired into CI's cheap-checks job. It
takes the generated `authelia-main.service` unit as a build input, reads the binary and the config
path out of its `ExecStart` (the same discipline `nginx-config-parses` uses), asserts all three
properties above on the real generated file, and then runs Authelia's own `validate-config` over
it — for both a published-dashboard host and an unpublished control host.

Anti-vacuity, measured rather than argued. Five mutations, each applied in place and each caught:

| Mutation | Caught by |
|---|---|
| cookie entries listed base-domain-first | the ordering assertion |
| both entries named `authelia_session` | the distinct-name assertion (Authelia accepts this) |
| control-plane `authelia_url` pointed at `auth.<baseDomain>` | the cookie-scope assertion |
| control-plane entry emitted on an unpublished dashboard | the unpublished-host control |
| `same_site: bogus` on the apps' entry | Authelia's own `validate-config` leg |

The last one matters on its own: it is caught by **nothing in the check except the real validator**,
which is what proves that leg is live rather than decorative.

Three further mutations cover the files that must agree with the cookie list — the portal vhost
removed, the dashboard's 401 redirect pointed back at `auth.<baseDomain>`, and the portal's
certificate pointed at the wrong name — all caught by `daemon-vhost-enforced`; and the portal's DNS
record removed, caught by `dns-record-set`.

## What this fix does and does not buy

It buys exactly one thing: **passing the apps' edge gate no longer reaches the control plane's edge
gate.** A compromised sibling app holds an `authelia_session`, and that is not a
`ferrum_control_session`.

It does not change the apps' own situation. Every catalog app still shares one cookie with every
other catalog app, which was explicitly not what this finding was about.

## The cost, re-examined

The 2026-09 acceptance named the cost as "a second login at the control plane", and that is what
has now arrived. Counted honestly, for an operator who uses both the apps and the dashboard:

- **Before:** one Authelia login (apps + dashboard, shared cookie) + one ferrumd password = **2**.
- **After this change alone:** one Authelia login for the apps + one for the dashboard + one
  ferrumd password = **3**.
- **After R5's second half** (ferrumd accepting the Authelia-asserted identity, which is what this
  change exists to make safe): one Authelia login for the apps + one for the dashboard = **2**.

So the first half alone is a net cost of one login, and the pair is net neutral while isolating the
control plane. That is the trade the owner was told about, and it is the reason R5's two halves are
sequenced rather than independent. Shipping only the second half would have been a regression; the
first half alone is a security improvement that the operator pays for in one extra login until the
second lands.

## Residual

The multi-domain list does not solve the general shape of the original problem: every catalog app
still shares one cookie among themselves. That was never in SEC-M02's scope and is not claimed
here.
