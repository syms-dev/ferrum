# Phase 1.7c — you can actually reach the thing that manages it

**Status:** R13 requirements settled 2026-09-21; OQ1 answered by the owner (SSO alone). R14 is **not new design** — it is the existing
Phase 1.6 updates spec, which is already through its planning gate and was never implemented.
Not yet through the planning review gate; no implementation until that runs, and not until the
Phase 1.7 R1 pipeline run finishes (one pipeline run per checkout).

## Why this exists

The owner asked a question with a short answer:

> Where is all of this managed from? We have the setup screens, but where can I go to to see
> everything? Run an update on Plex? It has one rn and I want to see. ferrum.thesyms.ca what?

`ferrum.thesyms.ca` does not exist, and ferrum cannot update Plex. Both were checked in the source
on 2026-09-21 rather than recalled:

| Claim | Evidence |
|---|---|
| The daemon has no vhost | `ferrum.daemon.subdomain` (default `"ferrum"`) is declared in `modules/core/options.nix:289` and consumed **nowhere**. `crates/ferrumd/src/main.rs:249` states it itself: *"nginx builds vhosts solely from `exposedApps`, and `ferrum.daemon.subdomain` is declared but unused"* |
| So the UI is loopback-only | `ferrum.daemon.listenAddress` defaults to `127.0.0.1`, port `7788`. The only way in today is an SSH tunnel |
| No update mechanism exists | ferrumd's routes are `/api/{catalog,settings,secrets,generations,jobs,login,logout,session,password}`. There is no update endpoint, no update job kind, and no version comparison anywhere |

The vhost gap is not an oversight so much as an unfinished handover: the Phase 1.4b plan deferred it
deliberately — *"Ferrumd doesn't exist yet (Phase 1.5), so there is no service for
`ferrum.daemon.subdomain` to proxy to, and creating a vhost that 502s forever isn't a working
deliverable"* — and named Phase 1.5 as its owner. Phase 1.5 built the daemon and did not pick the
vhost back up.

This matters more than its size suggests. Every phase since has added capability to a control plane
the operator cannot open, and the product's own framing is that *"the web UI is the point, not a
nicety"*.

---

## R13 — the dashboard is published at `ferrum.<baseDomain>`, behind SSO

**User story.** I open `ferrum.thesyms.ca`, log in the same way I log into Sonarr, and I can see
and manage the whole box.

**Why this is not optional.** ferrum is positioned against Saltbox, which gives the operator a
working published stack on their own domain. A control UI reachable only through an SSH tunnel is a
half-finished deployment by the project's own standard — and it is the *first* thing an operator
looks for.

### The security constraint this requirement must not break

`crates/ferrumd/src/main.rs:249` is a warning written in advance of exactly this change, and it is
the most important sentence in this spec:

> ferrumd is loopback-only today [...] but once a daemon vhost exists under
> `ferrum.proxy.baseDomain`, a sibling catalog-app subdomain is same-site — a compromised app WOULD
> have the browser attach `ferrumd_session` to a request here. What stops it reading the answer is
> purely the absence of CORS.

`SameSite` is scoped to the registrable **site**, not the origin. The moment the daemon is served
under the same base domain as the apps, `sonarr.<domain>` becomes same-site with `ferrum.<domain>`.
Every app in the catalog is a third-party web application ferrum does not control, and several of
them execute operator-supplied configuration. So this requirement deliberately *increases* the blast
radius of an app compromise, and the mitigations are part of the requirement rather than a follow-up.

### Acceptance criteria

- **A1.** With `ferrum.proxy.enable` and a `baseDomain`, nginx serves a vhost at
  `${ferrum.daemon.subdomain}.${baseDomain}` proxying to the daemon's real listen address and port.
  The option stops being decorative.
- **A2.** The daemon's vhost is gated by Authelia exactly like a catalog app, whenever
  `ferrum.auth.enable` is on. The control plane must not be *less* protected than Sonarr.
- **A3. CORS stays absent.** No route under `/api/*` may ever be served with
  `Access-Control-Allow-Origin`, and that must be enforced by a test that fails if one appears — not
  by the fact that nobody added one. This is the control the code comment identifies as load-bearing.
- **A4. `ferrumd_session` is hardened for a same-site world:** `Secure`, `HttpOnly`, and
  `SameSite=Strict` rather than `Lax`, since there is no legitimate cross-site navigation into a
  control plane. State-changing routes additionally require a header a cross-origin form cannot set.
- **A5.** The daemon keeps listening on loopback. Publishing means *nginx reaches it*, not that it
  binds a public interface. The SSH-tunnel path keeps working as the recovery route when the proxy
  or Authelia is broken — which is precisely when an operator needs the UI most.
- **A6.** A certificate is issued for the daemon hostname through the same ACME path as every other
  vhost, and the DNS record is created by Phase 1.7 R1 like any other published name. R13 must not
  invent a second mechanism for either.
- **A7.** It degrades honestly: with no `baseDomain`, or with the proxy disabled, there is no vhost
  and the UI states where it *is* reachable rather than advertising a hostname that will not resolve.
- **A8. The daemon's own hostname is reserved.** An operator must not be able to give a catalog app
  the subdomain `ferrum` and silently shadow the control plane. A collision is a configuration
  error, reported at evaluation time.

### Out of scope for R13

- Exposing the daemon on the public internet without SSO. `ferrum.auth.enable` off plus a public
  `baseDomain` is already a stated hazard elsewhere; R13 does not change that policy, and A2 means
  the control plane follows it.

---

## R14 — updates, as already specified

**This is not new design.** `docs/superpowers/specs/2026-09-16-phase-1-6-updates-design.md` is 760
lines covering discovery, the pin-advance authorization boundary, read-only preview, applying an
update as a generation, rollback, the UI surface, selective vs wholesale updates, and recording the
pin a generation was built from. It has an architect decision on its central open question, two
pre-implementation spikes that both passed, and its own note that the planning gate can close.

**The requirement here is therefore: implement Phase 1.6 as written.** Re-opening its design would
discard a completed review, and the owner's immediate need — *"Run an update on Plex? It has one rn
and I want to see"* — is satisfied by R1 (discovery), R3 (preview) and R6 (the UI surface) of that
spec, which is where implementation should start.

Two notes carried forward rather than re-decided:

- R14 depends on R13. An update UI on a dashboard nobody can open is the same mistake twice.
- Phase 1.6's spec predates the `ui-kit` component library. Its R6 UI surface should be built from
  those components (`AppTile`, `ApplyProgress`, `GenerationList`, `RollbackConfirm`, `StatusLine`)
  rather than new one-off markup. That is an implementation note, not a change to the spec.

---

## Sequencing

R13 before R14, and both after Phase 1.7 R1 — R1 creates the DNS record that A6 depends on, and
only one pipeline run may be active per checkout.

## Open questions — answered

- **OQ1 — ANSWERED: SSO alone. No `trustedNetworks` restriction on the daemon vhost.**
  The owner's call, matching the recommendation. Restricting the control plane to the LAN would
  reintroduce the SSH-tunnel problem exactly when remote management is worth most — away from home,
  when something has gone wrong. The defence is therefore Authelia (A2) plus the same-site
  mitigations (A3 enforced CORS absence, A4 `SameSite=Strict` and a header state-changing routes
  require), with the loopback listener (A5) as the recovery route when the proxy or Authelia is
  itself what broke.

  This is a deliberate exposure decision and should be revisited if the same-site mitigations ever
  weaken — not silently inherited.

---

## Developer Documentation — R13 implementation (post-panel)

Added after the blind planning panel and Engineering Manager adjudication of pipeline run
`31491fa3`. This section is **additive**: every acceptance criterion above, the out-of-scope
paragraph, and the answered OQ1 are unchanged and remain the settled contract. What follows states
*how* to implement them, because the panel's unanimous finding was not that the criteria are wrong
but that the obvious implementation of several of them is. Each decision carries a `[P-xx]`
back-reference to the panel finding that produced it; the finding register is at
`.ckit/state/evidence/phase-1-7c-r13-panel-register.md` and the adjudication at
`.ckit/state/evidence/phase-1-7c-r13-em-decision.md`.

### D0 — the daemon is a synthetic, non-catalog "app-shaped" value
Four mechanisms take a catalog app as their unit and silently exclude the daemon:
`modules/proxy/authelia.nix:73-93` (`access_control.rules` from `exposedApps`),
`crates/ferrum-install/src/sso.rs:47-53` (`apps_left_open`),
`modules/proxy/acme.nix:137-146` (`security.acme.certs` over `publicApps`),
and `modules/proxy/nginx.nix:16` / `modules/proxy/lib.nix:14-29` (`mkVhost` / `authGated`).
Do NOT patch each independently — that reproduces the failure class the panel found four times.
Construct one synthetic value satisfying all four call sites. It is an internal value, NOT a new
operator-facing option, so `modules/lib/settings-schema.json` does not change:

    daemonApp = {
      subdomain   = ferrum.daemon.subdomain;   # already exists
      port        = ferrum.daemon.port;        # 7788
      exposure    = "public";                  # real cert + public listener (A1, A6)
      auth.policy = "one_factor";              # forward-auth gated exactly like a catalog app (A2)
      auth.bypassPaths = [ ];                  # the daemon exempts no path from the edge gate
    }

Mirrors the existing precedent of hand-building the `auth.${baseDomain}` vhost outside `exposedApps`.

### D1 — Authelia rule for the daemon (A2) [P-01]
`access_control.default_policy = "deny"` (`authelia.nix:55`) + rules built only from `exposedApps`
means an `auth_request`-wired daemon vhost with no rule denies EVERYONE, always — a non-functional
ship. Add a dedicated `access_control.rules` entry for `daemonApp` alongside (never instead of) the
app-driven rules, using the identical rule shape so it stays in sync as that generator evolves.

### D2 — the unauthenticated-publish consent gate must see the daemon (A1/A2/Out-of-scope) [P-02]
`sso.rs:47-53` and `:122-128` compute "nothing would be left open" purely from the catalog selection.
After R13 an operator selecting only Plex+Jellyfin and declining SSO publishes the control plane on a
real certificate behind one password while being told the opposite. Ruling:
1. Always evaluate whether `proxy.enable && baseDomain != ""` holds, independent of app selection.
2. When it holds and SSO was declined, replace the "nothing would be left open" sentence with one
   naming the control plane and its concrete unauthenticated routes (`PUT /api/settings`,
   `POST /api/secrets/:name`, `POST /api/jobs`), and require the explicit additional confirmation
   already used for apps left open — extended to cover this case, not special-cased separately.
3. When the predicate does not hold, current behaviour is correct and unchanged.

### D3 — cookie name hardening (A4) [P-03]
A compromised sibling can return `Set-Cookie: ferrumd_session=X; Domain=<baseDomain>; Path=/` from its
own server response; `HttpOnly` blocks JS reads, not `Set-Cookie` headers, and RFC 6265 leaves the
choice between two same-named cookies unspecified while `main.rs:199` does a single `cookies.get`.
Rename to `__Host-ferrumd_session`: browsers reject any `__Host-` cookie carrying a `Domain`
attribute (and require `Secure` + `Path=/`), which structurally prevents the attack. Update every
reference — `main.rs:52-56`, `main.rs:199`, and the tests at `main.rs:600-690`.

### D4 — auth composition: ferrumd's session stays authoritative (A2/A4) [P-04]
ferrumd continues to require its own valid session cookie on EVERY request regardless of Authelia's
`auth_request` outcome. R13 introduces NO `Remote-User` trust, and the servarr native-login-disable
pattern is explicitly NOT applied to the daemon. Reason: neither `modules/core/daemon.nix` nor any
unit in `modules/apps/*` has network-namespace isolation, so any local process — a compromised or
SSRF'd catalog app — could otherwise forge `Remote-User` straight at `127.0.0.1:7788`, bypassing the
browser and every same-site mitigation. Header trust, if ever wanted, needs a compensating control
(Unix socket, or a secret only nginx can set) as its own separate change.

### D5 — CORS-absence test design (A3) [P-05]
A conforming CORS layer ECHOES the request `Origin`, emitting no `Access-Control-Allow-Origin` when
the request carries none — and every existing ferrumd test builds Origin-less requests, so a naive
header-absence assertion passes VACUOUSLY against exactly the reflected-origin configuration
`main.rs:268-273` names as fatal. After R13 the serving boundary is also nginx, which no crate test
observes. A3 is not covered until all three hold:
1. Every `/api/*` route, including 401/403/500 responses, exercised with
   `Origin: https://sonarr.<baseDomain>` on both a simple request and an `OPTIONS` preflight
   (with `Access-Control-Request-Method`), asserting no `Access-Control-*` header appears.
2. A companion assertion over the GENERATED nginx config that no vhost ever emits
   `Access-Control-Allow-Origin`, following the `auth-model-enforced` pattern.
3. A negative control: the same suite run against a deliberately CORS-enabled build MUST fail.

### D6 — ACME gating independent of `publicApps` (A6) [P-06]
`acme.nix:137-145` builds certs over `publicApps` only, and the `acme.email` (:48) and DNS-01
credential (:52) assertions are gated the same way. An operator publishing only the dashboard with
every app at `lan`/`local` — the safest configuration available — gets no cert and silently falls to
the self-signed branch with no assertion firing. Gate the daemon's cert entry and those assertions on
`daemon.enable && proxy.enable && baseDomain != ""`, OR'd in independently of `publicApps`. This names
A6's unstated precondition; it reuses the identical `security.acme.certs` shape, not a second mechanism.

### D7 — reserved-subdomain set (A8) [P-07]
`nginx.nix:132-147` merges vhosts with `//` so a later key silently wins — the jellyfin/plex failure
class. App subdomains are free-form `types.str` with no uniqueness assertion anywhere. One eval-time
assertion compares every app's configured subdomain against the reserved set
**{ the current value of `ferrum.daemon.subdomain`, the literal `"auth"` }** — never a hardcoded
`"ferrum"`. A collision fails evaluation naming the colliding app and the reserved name.

### D8 — SSE proxying (A1/A5) [P-08]
`jobs.rs:204-229` is a long-lived SSE stream and `apply.healthCheckTimeoutSec` defaults to 120s,
exceeding the `proxy_read_timeout 60s` that `recommendedProxySettings` supplies with `proxy_buffering`
left on. Separately `nginx.nix:100`'s `error_page 401 =302 https://auth.<domain>/...` turns an
expired-Authelia SPA `fetch()` into an opaque cross-origin redirect. The daemon vhost location block:
1. sets `proxy_buffering off` (or emits `X-Accel-Buffering: no` on the SSE path);
2. sets `proxy_read_timeout` comfortably above the longest apply (e.g. 300s);
3. overrides the site-wide `error_page 401 =302` for the `/api/` prefix so an expired edge session
   returns a plain `401` the SPA can detect.

### D9 — installer caveat becomes state-dependent (A7) [P-09]
`crates/ferrum-install/src/dns.rs:110-117`'s `daemon_record_caveat()` is a frozen string asserting the
name "will resolve, and then the connection will close with no response ... until daemon web access
ships in Phase 1.7c R13", asserted verbatim by tests at ~1191/1204/1453. Once A1 ships that is false.
`dns.rs` is IN SCOPE for A7. Make the caveat a pure function of
`{ proxy.enable, baseDomain, daemon.subdomain, auth.enable }`: when the answered configuration will
actually produce a reachable, correctly-gated vhost, state the real reachable URL; otherwise retain
language scoped to the actual reason. Replace the frozen-string tests with per-state assertions, one
per branch, each still an exact match.

### D10 — Secure cookie and the SSH tunnel (A4/A5) [P-10, adjudicated]
`http://127.0.0.1` and `http://localhost` are potentially-trustworthy origins under W3C Secure
Contexts, implemented uniformly by every major browser: a `Secure` cookie is stored and sent there
over plain HTTP. A4 and A5 are compatible as written; no code or criterion changes.
Operational note to carry into the recovery instructions: the tunnel must forward to the LOOPBACK
address specifically (`ssh -L 7788:127.0.0.1:7788 <host>`, then browse `http://127.0.0.1:7788`), not a
LAN IP. A non-loopback origin is not potentially-trustworthy and will correctly refuse the cookie —
that is expected, and must not be "fixed" by weakening A4.

### D11 — Authelia's actual defensive scope (advisory) [P-11]
`authelia.nix:56` sets `session.domain = ferrum.proxy.baseDomain`, so the SSO cookie is domain-wide
and a compromised sibling app's requests to `ferrum.<domain>` already carry it and pass `auth_request`.
Authelia defends against the unauthenticated internet stranger ONLY. A3 and A4 are the sole defence
against a compromised sibling app. Keep this explicit in any security writeup so Authelia is never
mistaken for load-bearing against the spec's own named threat.

### D12 — shared lockout table (advisory, backlog) [P-12]
`auth.rs:72-88` keys lockout on username in a shared table, so a sustained same-site attack holding
`admin` locked also locks the SSH-tunnel recovery route. Not required for R13; backlog candidate for a
per-listener exemption.

### D13 — only `Secure` is new (implementation note) [P-13]
`main.rs:52-56` already sets `SameSite=Strict`. A4's "rather than Lax" describes the end state, not a
diff. The only new cookie attribute is `Secure`, plus the D3 rename.

### Spec traceability
| Criterion | Approach | Files |
|---|---|---|
| A1 | D0 synthetic value -> `mkVhost`; gated on `proxy.enable && baseDomain` | `modules/proxy/nginx.nix` |
| A2 | D1 + D4 | `modules/proxy/authelia.nix`, `crates/ferrumd/src/main.rs` |
| A3 | D5 test matrix | `crates/ferrumd/src/main.rs`, `nix/modules/flake/checks.nix` |
| A4 | D3 + D13 + D10 | `crates/ferrumd/src/main.rs` |
| A5 | D10, D12 (non-blocking) | `crates/ferrumd/src/auth.rs` |
| A6 | D6 | `modules/proxy/acme.nix` |
| A7 | D9 | `crates/ferrum-install/src/dns.rs` |
| A8 | D7 | eval-time assertions module |
| Out-of-scope policy | D2 | `crates/ferrum-install/src/sso.rs` |
