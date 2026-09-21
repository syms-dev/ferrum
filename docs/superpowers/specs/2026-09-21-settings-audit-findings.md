# Settings audit — does every setting in the ferrum dashboard make sense?

**Date:** 2026-09-21. **Method:** read every `ferrum.*` option, every app `settingsSchema`, the
hand-written `modules/lib/settings-schema.json` the daemon validates against, and the UI that
renders it. Every finding below cites the file and was checked, not recalled.

**Headline: one finding is a live defect on the owner's own host, proven with a real JSON Schema
validator.** The rest are judgement calls about what a control plane should let you change.

---

## F1 — HIGH, LIVE: the dashboard cannot save settings on a pooled host

`crates/ferrumd/src/settings.rs:42` validates every settings write against
`modules/lib/settings-schema.json`. That file is **hand-written** (the commit that added it says
so) and read verbatim by `nix/overlays/default.nix:25-28`. It has not been touched since.

Its `storage` block sets `additionalProperties: false` and allows exactly seven keys:
`stateDir`, `snapshotDir`, `journalDir`, `mediaDir`, `mediaGroup`, `minFreeGiB`, `keepGenerations`.

`storage.pool` is not among them — and `crates/ferrum-install/src/render.rs:544-551` **writes
`storage.pool` for any host with more than one data disk.** The owner's host has two.

Proven, not inferred, against the real schema with `Draft202012Validator`:

```
REJECTED - 1 error(s):
  at storage -> Additional properties are not allowed ('pool' was unexpected)
```

So on a pooled host, every settings write from the dashboard fails validation — not because of
what the operator changed, but because of what was already in the file. The same wall is waiting
for `proxy.dns.*` the moment Phase 1.7 R1 lands, and for `storage.pool.{minFreeGiB,policy}` which
`options.nix` also declares.

**Fix:** the schema must be derived from the option tree rather than maintained beside it. Failing
that, a check must fail the build when an option exists in `modules/core/options.nix` and not in
the schema.

## F2 — the root cause is a missing check of a kind this repo already has three of

`nix/modules/flake/checks.nix` already mechanically enforces exactly this shape of agreement in
three places: `schema-uniformity`, `installerOffersEveryCatalogApp` (the installer's app list vs
the catalog), and `uiRendersEverySchemaType` (the UI's renderers vs the schema's types). Each
exists because two lists that must agree will otherwise drift silently.

The option tree vs the settings schema is the same problem, and it is the one pairing with no
check. F1 is the predictable result.

---

## F3 — settings that should not be freely editable in a control plane

These are all currently in the schema and rendered. Each is a real option; the question is whether
a web UI is the right place to change it.

**Locks you out of the thing you are using.** `daemon.port`, `daemon.listenAddress`,
`daemon.subdomain`, `proxy.enable`, `auth.enable`. Changing any of these from the dashboard can
end with the dashboard unreachable and the fix only available over SSH. They need either a
confirmation that states the consequence, or read-only status with a documented CLI path.

**Orphans data.** `storage.stateDir`, `storage.snapshotDir`, `storage.journalDir`,
`storage.mediaDir`, `secretsDir`, `backup.repo`. Changing a path does not move what is at the old
one. ferrum would come up pointing at an empty directory with the operator's data still on disk
and invisible.

**Silently detaches a secret.** `proxy.acme.credentialSecret`, `backup.passwordSecret`. These name
a secret rather than hold one. Editing the name does not rename the secret, it points at one that
does not exist — and the failure surfaces later, at certificate renewal or at backup time.

**Not a setting at all.** `schemaVersion` is migration state. `modules/core/options.nix:25` and the
migration mechanism read it to decide what to migrate. An operator editing it does not change
anything about the system; it corrupts ferrum's record of its own shape. It should never be
editable.

**Needs a consequence, not just a toggle.** `proxy.acme.staging` silently swaps real certificates
for untrusted ones. It is a legitimate and useful setting — it is how you test without burning
Let's Encrypt rate limits — but flipping it in a UI with no warning produces browser warnings on
every app and no obvious cause.

**Genuinely good as they are.** `apply.autoRollbackOnFailure`, `apply.healthCheckTimeoutSec`,
`storage.keepGenerations`, `storage.minFreeGiB`, `proxy.trustedNetworks`, `auth.adminEmail`,
`backup.schedule`, `storage.pool.{minFreeGiB,policy}`. These are operator decisions with real
trade-offs and no hidden blast radius.

---

## F4 — a credential is living in the settings file

`modules/apps/plex/meta.nix:59-66` puts `claimToken` in Plex's `settingsSchema`, so it is written
to `settings.json`. That file is not a secret store: secrets are sops-encrypted at mode `0400`,
and `settings.json` is neither.

Mitigated by claim tokens being short-lived, and the file's own comment explains honestly why this
cannot be a declarative option — Plex only issues claim tokens to an authenticated plex.tv
session. But the mechanism for exactly this already exists: `put-secret` knows named payloads, and
`SecretField` in `ui-kit` was built for write-only values. This belongs there.

Worth noting it is the same class as the ferrumd admin password the owner had to `cat` and paste:
a credential living somewhere convenient rather than somewhere safe.

---

## F5 — the per-app settings pages have almost nothing to render

The owner asked the design agent for "the Settings pages for those apps". Across all seven
catalog apps, `settingsSchema` declares **three settings in total**: `plex.claimToken`,
`sonarr.urlBase`, `radarr.urlBase`. Jellyfin, Prowlarr, qBittorrent and SABnzbd declare nothing.

The real per-app surface is elsewhere — `modules/lib/app-submodule.nix` gives every app `enable`,
`port`, `subdomain`, `exposure`, `stateDir`, `auth.policy`, `auth.bypassPaths`, `mediaAccess`,
`resources.memoryMax` and `resources.cpuQuota`. Those are the settings an operator actually wants
per app, and `settings-schema.json` describes `apps` only as an untyped object with the note that
"deep per-app validation is deferred".

So the settings page is buildable and worth building — but it must render the app submodule's
options, not `settingsSchema`. That deferral is now the thing blocking the owner's ask.

---

## Recommended requirements

- **R17 (from F1/F2):** the settings schema is generated from, or mechanically checked against,
  the option tree. Highest priority — F1 is live and silent.
- **R18 (from F3):** every setting is classified — freely editable, editable with a stated
  consequence, or read-only with a CLI path. The UI renders the classification rather than
  presenting every option as equally safe.
- **R19 (from F4):** `plex.claimToken` moves from `settings.json` to the secret store.
- **R20 (from F5):** per-app settings pages render the app submodule's options; `apps` gains real
  schema instead of the deferral.

## Open questions

- **OQ1.** For F3's lock-you-out group, is "editable with a confirmation naming the consequence"
  enough, or should they be read-only in the UI entirely? Recommendation: confirmation, except
  `schemaVersion`, which should never be editable by anyone.
- **OQ2.** Should F1's fix generate the schema from Nix at build time (correct by construction,
  more machinery) or add a check that fails when the two disagree (cheaper, still allows a
  deliberate omission)? Recommendation: the check first, because it is small and closes the live
  hole today; generation later if the schema keeps drifting.
