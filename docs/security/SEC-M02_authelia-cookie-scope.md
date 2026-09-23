# SEC-M02 — Authelia's session cookie is shared across the whole base domain

**Status:** ACCEPTED RISK (owner decision, 2026-09-23) · **Severity:** Medium
**Found:** R13 security pass 3 · **Evidence:** `.ckit/state/evidence/phase-1-7c-r13-security-clear-3.md`
**Site:** `modules/proxy/authelia.nix:56`

## What it is

Authelia issues its session cookie scoped to `.<baseDomain>`, so one cookie covers every
published app. Some catalog apps deliberately carry unauthenticated bypass locations — API
paths that must work without an interactive login. R13 placed the control plane at
`ferrum.<baseDomain>`, behind that same cookie. A cookie obtained in the context of one app is
therefore presentable at the control plane's edge gate.

## Why it is accepted rather than fixed

The fix is Authelia v4.38+ multi-domain `session.cookies`, isolating `ferrum.<baseDomain>` into
its own cookie. That forces a **second login** for the control plane, which cuts directly against
ferrum's hands-off, self-setup goal — the operator would log in once for their apps and again for
the dashboard. It also does not solve the general shape of the problem: every catalog app would
still share one cookie among themselves.

## Compensating control — verified, not assumed

ferrumd does not trust the Authelia cookie for authorization. Its own session cookie is
`__Host-ferrumd_session` (`crates/ferrumd/src/main.rs:61`), and the `__Host-` prefix is enforced
by the browser: a cookie carrying a `Domain` attribute is refused outright. No sibling subdomain
can set or read it. **Passing Authelia's edge gate does not by itself grant control-plane API
access** — the caller still needs a session ferrumd itself issued.

This is what bounds the residual risk to Medium rather than High. The edge gate is defence in
depth here, not the only gate.

## Revisit trigger

Reopen this decision when **any** of the following happens:

- The dashboard revamp (ROAD-TO-PUBLIC item 8) reworks the control plane's auth story.
- ferrumd stops using a `__Host-`-prefixed session cookie, or begins trusting an Authelia-supplied
  header for authorization. The compensating control dies with either change.
- A catalog app gains a bypass location that can read or influence cookie state rather than merely
  skipping authentication.
- Authelia gains a way to scope per-app cookies without a second interactive login.
