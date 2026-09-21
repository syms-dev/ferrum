# Phase 1.7c — you can actually reach the thing that manages it

**Status:** R13 requirements drafted 2026-09-21. R14 is **not new design** — it is the existing
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

## Open questions for the owner

- **OQ1.** Should the daemon's vhost be restricted to `ferrum.proxy.trustedNetworks` as well as
  SSO — LAN-only by default, published only if the operator opts in? Recommendation: **no**.
  Locking the control plane to the LAN reintroduces the tunnel problem for the operator who is away
  from home, which is the case where remote management is worth most. SSO plus A3/A4 is the defence.
  Worth a deliberate answer rather than a default, because it is the one decision here that trades
  reach against exposure.
