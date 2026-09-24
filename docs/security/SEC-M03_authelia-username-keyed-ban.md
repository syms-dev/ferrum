# SEC-M03 — Authelia's ban is username-keyed, so a remote attacker can lock out the admin

**Status:** DEFERRED (owner decision, 2026-09-23) · **Severity:** Medium
**Found:** R13 security pass 3 · **Evidence:** `.ckit/state/evidence/phase-1-7c-r13-security-clear-3.md`
**Site:** `modules/proxy/authelia.nix:49-63`, with `modules/proxy/nginx.nix:441-449`

## What it is

Authelia's regulation bans on **username**, not on source. Anyone who can reach the login page
can therefore lock out a named account by failing logins against it. ferrum installs a single SSO
admin, so the account an attacker would target is the only one there is.

Proved during pass 3: eight wrong passwords produced a ban, and the **correct** password was then
refused with 401.

## Why it is deferred rather than fixed

This is a genuine security trade, not a mechanical fix. The only configuration that answers "no"
to *does tripping this deny the correct password* is to disable username-keyed regulation and make
per-source `limit_req` the primary axis. That trades away resistance to distributed brute force in
exchange for availability. Which side to land on is a product decision about who the realistic
attacker is, and it should be made deliberately rather than as a side effect of clearing a gate.

Proving either state also requires a **live Authelia** — both the RED (ban, then correct password
refused) and the GREEN need a running instance. No such instance exists on the development
machine, and standing one up belongs with the other unproven runtime behaviour.

## The pattern this belongs to

This is the **third** instance in this codebase of one defect: *a throttle keyed on an axis its
requesters share is a denial of service with extra steps.* The others were the earlier M-02 and
R13's SEC3-H01, where eleven failed logins from anywhere locked out every operator including one
typing the correct password. That one is now fixed, and the generalisation is recorded in
`coarse_axis_saturated`'s doc comment in `crates/ferrumd/src/auth.rs`.

Before adding any throttle, answer both: **who else shares this key**, and **does tripping it
refuse the correct password?**

## Revisit trigger

Group with ROAD-TO-PUBLIC item 9 — running the KVM-gated VM tests, where a live Authelia has to
exist anyway. Decide the axis at that point and prove it with the same harness pass 3 used.
