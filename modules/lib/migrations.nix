# The ordered list of settings.json schema migrations. Empty today --
# ferrum is still at schema version 1, and no breaking change has ever
# shipped. A migration is only ever added alongside a MAJOR ferrum
# release (see docs/superpowers/specs/2026-08-23-settings-schema-
# migration-design.md for why schemaVersion itself stays a plain integer
# rather than tracking ferrum's own semver release number).
#
# Each entry: { from, to, description, migrate }. `from`/`to` must form
# an unbroken chain starting at 1 (enforced by the assertion below, not
# just assumed) -- `migrate` runs on the settings attrset at version
# `from` and must return one shaped for version `to`. A migration that
# cannot safely produce a value throws a specific, actionable message
# instead of guessing; that throw is a real eval-time failure, not
# something this file catches.
{ lib }:
let
  migrations = [ ];

  # currentVersion is computed, not a separately-maintained literal --
  # this is the ONE place "what version does this module tree expect"
  # is defined. modules/core/options.nix's own schemaVersion default
  # imports this file and reads .currentVersion rather than hardcoding
  # a number, so the two cannot drift apart.
  currentVersion = builtins.length migrations + 1;

  # Real chain-integrity check, not just an assumption: every migration
  # step's `from` must equal the previous step's `to` (or 1, for the
  # first step), and the last step's `to` must equal currentVersion.
  # A gap or an out-of-order entry is a real authoring mistake this
  # catches at eval time rather than silently mis-migrating a host.
  chainIsValid =
    let
      expectedFroms = lib.genList (i: i + 1) (builtins.length migrations);
      actualFroms = map (m: m.from) migrations;
      actualTos = map (m: m.to) migrations;
      expectedTos = lib.genList (i: i + 2) (builtins.length migrations);
    in
    actualFroms == expectedFroms && actualTos == expectedTos;

  # Parameterized on the migration list rather than closing over
  # `migrations` directly, so a test elsewhere (nix/modules/flake/checks.nix's
  # migrationMechanism check) can exercise this SAME real chaining algorithm
  # against a synthetic list -- never a second, independently-written copy
  # of the same recursion that could drift from this one and silently stop
  # testing anything real.
  migrateWith = migrationList: settings:
    let
      version = settings.schemaVersion or 1;
      step = lib.findFirst (m: m.from == version) null migrationList;
    in
    if step == null
    then settings
    else migrateWith migrationList (step.migrate settings // { schemaVersion = step.to; });
in
if !chainIsValid then
  throw "modules/lib/migrations.nix: migration chain is not a valid unbroken sequence from 1 to ${toString currentVersion} -- check each entry's from/to fields"
else
{
  inherit migrations currentVersion;
  migrate = migrateWith migrations;
  # Exposed specifically so tests can drive the real algorithm against a
  # synthetic chain -- not meant to be called outside a test context.
  inherit migrateWith;
}
