# Settings schema migration — design

## Context

`ferrum.schemaVersion` already exists in `modules/core/options.nix` — a
`readOnly` integer, defaulting to `1`, documented as "Version of the ferrum
settings.json schema this module tree expects." Nothing in the codebase
reads or acts on it: it is a declared field with no consumer. Confirmed by
search — the only other places `schemaVersion` appears are the JSON Schema
it's validated against (`modules/lib/settings-schema.json`), the generated
catalog metadata, and example/test fixtures. No migration mechanism exists.

This gap matters because ferrum's core promise is that `settings.json` is
the *only* thing an operator (or the future UI) ever writes — never Nix.
That promise only holds if a breaking change to what `settings.json` is
expected to look like has a real, honest path forward for an operator who
is already running an older shape. Today there is none: a host with an old
`settings.json` would simply fail to evaluate against a newer module tree,
with whatever error Nix's own type system happens to produce — not
something this project would consider an acceptable failure mode for its
own stated audience.

This spec covers only the migration mechanism itself: how a schema change
is authored, how it runs, how an operator finds out about it before it
happens, and what happens when it can't be fully automatic. It does not
cover ferrum's release/CI process, nor does it design any specific future
migration's content.

## Versioning scheme

Two separate version numbers, deliberately not unified:

- **ferrum's own release version** follows real semver —
  `MAJOR.MINOR.PATCH`, with pre-release tags (`-rc.1`, `-beta.2`) where
  useful. This is the human-facing "what version of ferrum am I running"
  identity, shown in the UI's Updates screen. It replaces the placeholder
  calendar-style versioning (`2026.34`) used in this phase's earlier UI
  mockups.
- **`ferrum.schemaVersion`** stays exactly what it already is: a plain,
  sequential integer (`1`, `2`, `3`, …). This matches how real migration
  tooling actually versions schema changes — Rails, Django, and Flyway all
  use plain integers or timestamps for this, not semver strings, because
  the counter only needs strict, unambiguous ordering for automated
  tooling, not to express a compatibility promise to a human reader.

The two connect **by convention, not by mechanism**: per semver's own
definition, a MAJOR version bump is precisely "incompatible changes" — the
only time `settings.json`'s expected shape is allowed to change at all.
MINOR and PATCH releases (new catalog apps, bug fixes, dependency pin
bumps) never touch `schemaVersion`. A schema migration is only ever
authored alongside a MAJOR release.

## Where migrations run

A new `modules/lib/migrations.nix`: an ordered list of pure functions, one
per version step.

```nix
[
  { from = 1; to = 2;
    description = "Combined proxy.dnsProvider and proxy.dnsApiKeySecret into proxy.dns.{provider,credentialSecret}";
    migrate = settings: settings // {
      proxy = (settings.proxy or {}) // {
        dns = {
          provider = settings.proxy.dnsProvider or "cloudflare";
          credentialSecret = settings.proxy.dnsApiKeySecret or "acme-dns";
        };
      } // (removeAttrs (settings.proxy or {}) [ "dnsProvider" "dnsApiKeySecret" ]);
    };
  }
]
```

`currentSchemaVersion` (the value `options.ferrum.schemaVersion`'s
`readOnly` default resolves to) is exported from this same file, computed
directly from the migration list itself — `builtins.length migrations +
1` (schema version starts at 1; each listed step advances it by exactly
one) — never a separately-maintained literal. `options.nix`'s declared
default becomes `(import ../lib/migrations.nix { inherit lib; }).currentVersion`
rather than a hardcoded number, so there is exactly one place this value
is defined, not two that could drift apart.

**Why here, not in Rust or in `ferrumd`:** `ferrum.lib.mkHost` already
receives `settings.json` as an already-parsed attrset (its caller does
the `fromJSON`/`readFile`) before constructing the NixOS module config —
every host build already passes through this exact point, right after
that parsing happens and before `options.nix` ever sees the result.
Running the migration chain there reuses infrastructure that already
exists rather than adding a new one. It also gets a real safety
property for free: if a migration produces a shape `options.nix` doesn't
accept, the flake simply fails to evaluate — the same class of failure
every other type error in this module tree already produces, not a new
silent-failure mode. A Rust implementation (in `ferrum-apply`) or a
daemon-side implementation (in `ferrumd`) would each require the same
shape knowledge to be independently maintained in a second place, with no
mechanism keeping it in sync with what `options.nix` actually expects.

`mkHost` compares the on-disk `settings.json`'s own `schemaVersion` field
against `currentSchemaVersion` and, if behind, applies every migration
step in the chain in sequence — not just the single next step. A host
that hasn't updated in several major versions runs the full applicable
chain in one pass. This is the standard shape for migration chains in
every framework named above; the known cost (the chain only grows longer
over the project's lifetime) is recorded under Known Risks.

The migration check runs on **every** apply, not a separate "update"
mode — if `schemaVersion` already matches, it's a cheap no-op comparison.
This means there is no code path where an operator could end up applying
an old schema shape against a newer module tree by going through "just
change one app setting" instead of the dedicated Updates flow; both paths
converge on the same `mkHost` entry point.

`ferrum-apply` writes the migrated JSON back to `settings.json` (with the
bumped `schemaVersion`) after a successful apply, the same way it already
writes a journal entry per generation — so the on-disk file stays current
and the migration chain doesn't re-run on every subsequent apply once it's
been applied once.

## Showing the operator what's changing

Confirmed with the user: a migration that resolves automatically does
**not** get its own confirmation gate — it's shown as one more line in the
same "what's changing" review that already exists for every apply (app
version bumps, settings changes), not a special-cased extra step.

Computing what to show requires running the migration as a **preview**,
separate from a live apply: `ferrum-apply` gains a preview step that reads
the on-disk `settings.json` and, if its `schemaVersion` is behind
`currentSchemaVersion`, evaluates the same migration chain via `nix eval
--json` against the real flake (evaluation only, no write, no apply) to
get the migrated result.

The text shown to the operator is **not** an auto-generated diff of the
before/after JSON — that gets technical and noisy fast, exactly what this
project's own "simple, opinionated" stance argues against. Each migration
step's `description` field (see the `migrations.nix` shape above) is a
human-authored, one-line explanation, and that's what renders on the
Updates screen — visually identical to how an app version bump already
renders ("Sonarr 4.0.1 → 4.0.3"), just labeled "Settings" instead of an
app name. No new UI concept is introduced.

As actually shipped, the `ferrum-apply preview-migration` CLI command
(built in this plan's Task 3) does not yet surface `description` text in
its own JSON output (only `current_version`/`target_version`/
`would_migrate`) — wiring descriptions into a real UI-facing endpoint is
deferred to whichever future task actually builds the `ferrumd` Updates
API, since no real caller exists yet.

## When a migration can't be automatic

Some migrations genuinely can't produce a safe default — a field was
removed with no equivalent, or a value's meaning changed enough that only
the operator can decide. A migration function that hits this case
`throw`s a specific, actionable message instead of guessing:

```nix
migrate = settings:
  if (settings.auth.policy or null) == "none"
  then throw ''
    This update needs your input: ferrum.auth.policy no longer accepts
    "none" -- set it to "bypass" in Settings first, then retry.
  ''
  else settings // { ... };
```

Because this runs at real Nix eval time, the failure is loud by
construction — same as any other eval-time type error in this project.
The preview step surfaces the `throw`'s own message directly in the
Updates screen rather than a generic "migration failed," and the update
is blocked (not partially applied) until the operator resolves it. This
is deliberately the same shape as every other place this project already
prefers "refuse to evaluate" over "silently do something possibly wrong"
(`checks.schema-uniformity` is the existing precedent).

## Testing

- A real NixOS eval test (in the style of `checks.schema-uniformity`)
  that feeds a real, pre-migration `settings.json` fixture (schemaVersion
  1) through `mkHost` and asserts the resulting attrset matches the
  expected post-migration shape (schemaVersion 2) exactly — proving the
  migration function itself is correct, not just that it runs.
- A companion test asserting a `settings.json` already at
  `currentSchemaVersion` passes through `mkHost` completely unchanged
  (the no-op case is not accidentally mutating anything).
- A real test proving a `throw`-ing migration genuinely fails eval —
  confirming the loud-failure path actually triggers, not just that the
  Nix syntax is valid. This automated check can only prove failure
  occurs, not the exact content of the thrown message; message-text
  accuracy is a code-review discipline point (see Known Risk 2), the
  same as every other `throw()` message in this project.
- A real, `ferrum-apply`-level test (VM or eval, whichever proves it
  most directly) confirming the preview step's `nix eval --json` call
  returns the migrated JSON without ever writing to the real
  `settings.json` on disk — the preview must be provably read-only.

## Known risks

1. **The migration chain only grows over the project's lifetime.** Every
   major version that ever needed a schema change adds one more function
   to the chain, permanently (a host that hasn't updated since version 1
   must still be able to run the version-1-to-2 migration correctly even
   after the project reaches version 10). This is the same tradeoff every
   named precedent (Rails, Django, Flyway) accepts, not something unique
   to this design — noted here so it isn't rediscovered as a surprise.
2. **A migration author must remember to keep `description` honest and
   specific.** Nothing mechanically enforces that the human-authored
   one-line summary actually matches what the `migrate` function does —
   this is a code-review discipline question, not something this design
   can close structurally.
3. **The preview step's `nix eval` cost scales with flake evaluation
   time.** For a large catalog this could become a real, felt delay in
   the Updates screen. Not a blocker for the initial design, worth
   measuring once real migrations exist.
4. **The write-back step described under "Where migrations run" is not
   yet implemented.** This spec calls for `ferrum-apply` to write the
   migrated JSON back to settings.json (with the bumped schemaVersion)
   after a successful apply, so the migration chain doesn't re-run every
   time. No task in the implementing plan built this -- it was scoped
   out implicitly, not deliberately deferred with a tracked follow-up.
   It is harmless today (the migration list is still empty), but it
   does not yet compose with what already exists: `ferrumd`'s settings
   endpoint (`crates/ferrumd/src/settings.rs`) writes whatever JSON a
   client PUTs verbatim, with no schemaVersion bump logic, and
   `modules/lib/settings-schema.json` is version-blind (schemaVersion is
   an optional integer, and every object level uses
   `additionalProperties: false` describing only the CURRENT shape) --
   so once a real migration exists, an on-disk settings.json would stay
   at its old schema shape forever unless something writes the migrated
   result back. This must be built before any real migration ships, not
   discovered by a future author re-reading this file.
