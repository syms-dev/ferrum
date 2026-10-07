# Per-host certificates or one wildcard — the decision, and what it costs either way

> Written 2026-10-06 against this repository at `3137e05`. **This is analysis, not a change.**
> Nothing in the certificate strategy has been touched; the recommendation at the end is a
> recommendation. Let's Encrypt's published rate limits were re-read on the day of writing — they
> move, so re-check [letsencrypt.org/docs/rate-limits](https://letsencrypt.org/docs/rate-limits/)
> before relying on the arithmetic rather than on the shape of it.

## What ferrum does now

`modules/proxy/acme.nix` issues **one `security.acme.certs` entry per public vhost**: one for each
app whose `exposure` is `public` (`:161`), one for the dashboard (`:175`), one for the apps' Authelia
portal at `auth.<baseDomain>` (`:204`), and one for the control plane's own portal at
`auth.<daemon subdomain>.<baseDomain>` (`:195`). On a full stack with all seven catalog apps
published, that is **ten certificates for ten hostnames**, each ordered separately, each renewed
separately, all sharing one Cloudflare DNS-01 token and one ACME account.

`modules/proxy/nginx.nix` references them through `useACMEHost` at four places — `:99` for apps,
`:296` for the dashboard, `:634` and `:653` for the two portals — and in every one of them the cert
name and the vhost name happen to be the same string.

**Every one of those ten names goes into Certificate Transparency.** CT logs are public,
append-only and permanently searchable; submission is a condition of being trusted by browsers, not
a Let's Encrypt choice. Query any CT aggregator for a domain and you get back `sonarr.`, `radarr.`,
`prowlarr.`, `qbittorrent.`, `sabnzbd.`, `plex.`, `jellyfin.`, `ferrum.`, `auth.` and
`auth.ferrum.` — which is not merely "a server exists here" but a precise inventory of the software
running on it, its administrative interface, and its login portal, with issuance timestamps that
date the install.

Nobody is warned. That is the gap this document exists to close; the warning itself now lives in
[`docs/EGRESS.md`](EGRESS.md).

One mitigation already exists and is worth knowing: **an app at `exposure = "lan"` gets the shared
self-signed certificate instead** (`modules/proxy/nginx.nix:101`) and no public DNS record
(`modules/proxy/dns.nix:115`, built from `publicApps`). A LAN-exposed app is in no CT log at all.

## The alternative DNS-01 makes available

Because ferrum validates with DNS-01 and not HTTP-01, it can order a **wildcard**. HTTP-01 cannot
issue one at all, which is why most reverse-proxy projects in this space have no such option. A
single `*.<baseDomain>` certificate would put exactly one name into CT: the base domain, which an
observer already had, since they needed it to look anything up.

## The comparison

| | Ten per-host certificates (today) | One wildcard |
|---|---|---|
| **What CT publishes** | Every hostname, individually, with its issuance date. A full stack inventory | `*.<baseDomain>` — and, unavoidably, the base domain itself. Which apps exist is not disclosed |
| **Adding an app later** | A new `security.acme.certs` entry at the next apply, a new order, and **a new permanent CT entry**. Every app you ever toggle on is logged forever, even if you turn it off an hour later | Already covered. Nothing new is ordered and nothing new is logged |
| **Key compromise — in theory** | A stolen key is good for one hostname | A stolen key is good for every subdomain, including ones that do not exist yet |
| **Key compromise — on a real ferrum host** | Much less of a difference than it looks. `acme.nix` sets `group = nginxGroup` on **every** certificate (`:165`, `:178`, `:198`, `:207`) precisely so nginx can read them, so anything that compromises the nginx process already holds all ten keys. The per-host advantage is real only against an attacker who gets one key *file* without getting nginx — a narrow case, and it should be argued at its real size rather than its rhetorical one | Same reasoning; the gap narrows to "one key instead of ten" against an attacker who was going to get all of them anyway |
| **Renewal failure** | **Independent.** A failure to renew `sonarr.` breaks Sonarr. The dashboard, the SSO portal and every other app keep working, and you have a working control plane from which to see it | **Total and simultaneous.** One failed renewal breaks every app, the dashboard, **and both Authelia portals** — including the two things you would use to diagnose it. You are left with the console password and the SSH tunnel. This is the strongest argument against the wildcard and it is not a small one |
| **Who notices a renewal failure** | Nobody, in either column. Nothing in ferrum watches ACME: `/api/ready`'s own documented exclusions name ACME explicitly (README, "What readiness does **not** check"), and `crates/ferrumd/src/health.rs` contains no certificate check | Same — but the consequence of not noticing is a whole-host outage rather than one dead app |
| **Rate limit: certificates per registered domain** (50 per 7 days) | Ten certificates per full install. Five clean reinstalls in a week exhausts the budget for that domain — and reinstalling is exactly what someone does when things are going badly | One. Effectively unreachable |
| **Rate limit: duplicate certificate** (5 per *identical identifier set* per 7 days) | Ten separate identifier sets, so five reissues **each**. A loop that keeps re-ordering `sonarr.` leaves the other nine untouched | One identifier set. **Five reissues a week, total.** A host stuck in a re-issue loop — a bad apply repeated, a token rotated wrongly — burns the whole budget in five attempts and then has no path to a valid certificate for *anything* until the window rolls. The wildcard concentrates this limit the same way it concentrates renewal failure |
| **Rate limit: failed validation** (5 per identifier per hour) | Ten identifiers, so a misconfiguration has ten separate budgets and degrades app by app | One identifier, one budget, and a misconfigured DNS-01 token exhausts it in five tries for the whole host |
| **Cloudflare API traffic** | One `_acme-challenge` write-and-clean per certificate per renewal — ten round trips | One. A small win, and honestly a small one |
| **Does `security.acme` need structural change?** | — | **No. This is configuration.** `useACMEHost` names an entry in `security.acme.certs`, not a hostname, so pointing all four call sites at one shared entry needs no new mechanism — the four `useACMEHost` lines and the `mapAttrs'` in `acme.nix:161` are the whole surface. *Caveat, and it matters:* that `useACMEHost` can name an entry whose name differs from the vhost's is a **nixpkgs** property, not one this repository demonstrates — every existing call site happens to use matching strings. Confirm it against the pinned nixpkgs before writing code |
| **`auth.ferrum.<baseDomain>`** | Covered, as its own certificate | **Not covered.** `*.example.com` matches one label, and the control-plane portal is two deep (`modules/proxy/lib.nix:138` builds `auth.${scopeDomain}` over the dashboard's own vhost name). It needs either a second wildcard `*.ferrum.<baseDomain>` or a SAN naming it exactly. Either way **the string `ferrum.<baseDomain>` lands in CT**, which names the project if not the app list. That is a genuine partial defeat of the whole exercise — though "a ferrum host lives here" discloses considerably less than "here are its seven media apps". An operator who cares can already move it with `ferrum.daemon.subdomain` (`modules/core/options.nix:580`) |

## Recommendation

**Offer both. Default to per-host. Recommend the wildcard to operators who care about disclosure,
and do not change the default until something on the box watches certificate renewal.**

The shape: one option — `ferrum.proxy.acme.certificateStrategy`, enum `"per-host" | "wildcard"`,
default `"per-host"`. In `wildcard` mode `acme.nix` emits a single entry keyed on the base domain
with `domain = "*.<baseDomain>"`, plus `*.<daemon subdomain>.<baseDomain>` as an extra name when
`ferrum.auth.enable && daemonPublished`, and the four `useACMEHost` sites in `nginx.nix` name that
one entry instead of their own vhost. No new mechanism, no new secret, no new unit.

The reasoning, in the order it actually weighed:

1. **The disclosure argument is correct and the privacy win is real.** A permanent, public, searchable
   inventory of someone's home server is a worse default than it looks, and "every app you ever
   enabled, timestamped" is worse still. If this were the only axis, the wildcard would win outright.
2. **But the wildcard's failure mode is concentrated, and ferrum is currently blind to it.** The
   per-host design degrades one app at a time while leaving the control plane up. The wildcard turns
   a single expired certificate into a whole-host outage that also removes the dashboard and the SSO
   portal — and nothing in ferrum would have told the operator it was coming, because nothing in
   ferrum looks at ACME at all. Shipping a change whose downside is invisible until it is total is
   the shape of defect this project has already met more than once.
3. **The rate limits point the same way,** and against the intuition. The wildcard is far safer
   against the 50-per-registered-domain limit and strictly *more* fragile against the
   5-duplicates-per-week one, because it collapses ten independent budgets into one. In the exact
   situation where an operator is retrying — a bad install, a rotated token — the wildcard runs out
   of attempts first, and when it does, everything is down rather than one thing.
4. **The key-compromise argument is close to a wash and should not be used to decide this.** Every
   certificate on a ferrum host is already readable by nginx's group. Anyone citing blast radius
   here is comparing two outcomes that an attacker with the nginx process reaches identically.
5. **Changing the default silently would be worse than either option.** An existing host that moved
   from ten certificates to one would acquire a new single point of failure it did not ask for, and
   the CT entries it already has cannot be withdrawn — the privacy benefit for an existing host is
   partial at best. New installs are where a wildcard is worth most, which is an argument for an
   installer question, not for a silent default flip.

**The reopen trigger is specific:** when something on the box watches certificate expiry — a
readiness check, a dashboard reading, anything that turns "renewal has been failing for three
weeks" into a visible fact — the second objection above disappears and `wildcard` becomes the right
default for a new install. Until then it is the right *choice* for an operator who has read this
page, which is not the same thing.

One thing that should happen regardless of which way this goes: **the installer should say what it
is about to publish.** An operator choosing `public` exposure for seven apps is choosing to put
seven names in a permanent public log, and right now nothing tells them so at the moment they
decide. That is a disclosure fix, costs nothing, and does not depend on this decision at all.
