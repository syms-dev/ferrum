# Fix: enable `nix-command`/`flakes` on every ferrum host by default

## The gap

`ferrum-apply apply`'s first real step (`crates/ferrum-apply/src/apply.rs`,
around line 239) shells out to:

```
nix build --impure --no-link --print-out-paths $FERRUM_FLAKE_REF
```

`nix build` is part of Nix's new CLI, gated behind the `nix-command` and
`flakes` experimental features. Nothing in `modules/`, `nix/`, or
`examples/` enabled those features on a deployed ferrum host, so a freshly
provisioned host's very first real `apply` job would fail immediately with
"experimental Nix feature 'nix-command' is disabled" -- unless an operator's
own `custom/` config happened to enable it, which nothing in the project
asked them to do or documented.

`tests/daemon-apply-end-to-end.nix` (the VM test proving a real apply job
end to end) had been silently working around exactly this gap: its own test
node set `nix.settings.experimental-features = [ "nix-command" "flakes" ];`
directly, with a comment explicitly flagging it as "a real, separate gap
this test happens to surface". That override meant the test proved nothing
about whether a *real* host, with no such override, would actually work.

## The fix

Confirmed `nix.settings.experimental-features` is still the correct, current
NixOS option for this (checked against `flake.nix`'s pinned
`nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11"` -- the option is the
standard `nix.nix` module option, unchanged in shape/name on 25.11).

Added a new file, `modules/core/nix-settings.nix`:

```nix
# Base `nix` daemon settings every ferrum host needs, regardless of which
# apps are enabled.
#
# `ferrum-apply apply` (crates/ferrum-apply/src/apply.rs) shells out to
# `nix build --impure --no-link --print-out-paths ...` -- part of the new
# Nix CLI, which upstream Nix still gates behind these two experimental
# features. Nothing else in this module tree turned them on: a freshly
# provisioned host (nixos-anywhere, no operator-authored custom/ override)
# would fail its very first real apply job with "experimental Nix feature
# 'nix-command' is disabled". Enabling them here, unconditionally, for every
# ferrum host is what makes `ferrum-apply apply` work out of the box.
{ ... }:
{
  nix.settings.experimental-features = [ "nix-command" "flakes" ];
}
```

and registered it in `modules/default.nix`, alongside `./core/options.nix`
(the first import, so it applies unconditionally to every host regardless
of which apps/features are enabled -- it isn't gated behind any
`ferrum.apps.*` or `ferrum.*` option).

There was no existing `modules/core/nix.nix`-shaped file; `generations.nix`
turned out to be about the `ferrum-apps.target` rollback machinery
specifically, not base Nix daemon settings, so a small new dedicated file
was the cleaner fit rather than shoehorning an unrelated setting into it.

## Verification approach: (a)

Per the task's guidance, approach (a) was taken: the manual
`nix.settings.experimental-features` override was **removed** from
`tests/daemon-apply-end-to-end.nix`'s own test node (previously line 102),
with the surrounding comment updated to explain that the setting is now
expected to come from `modules/core/nix-settings.nix` (imported transitively
via `../modules`), not from the test itself.

This is the stronger proof: the test's own `nix build` step (inside the
real `ferrum-apply apply` job, inside the real VM) now only has the
module's own default to rely on. If the module fix were wrong or missing,
this test's `build` step would fail for real, with no override left to mask
it.

## Environment

All builds run for real on the project's NixOS dev VM (`ferrum-dev`,
`root@172.26.208.32`, still reachable at the address on file). The worktree
was synced to `/root/ferrum-repo` as a plain directory (tar/scp/extract,
excluding `.git`, `result*`, `target`), replacing whatever was there before.
Disk had 25G free on `/` (`/nix` is the same filesystem); no GC was needed.

## Verification 1: `nix eval` proving the option resolves on a real host

Evaluated `modules/lib`'s `mkHost` against the real `examples/hosts/minimal`
example host (same construction `nix/modules/flake/checks.nix` uses for
`checks.eval-example-hosts`), reading back
`config.nix.settings.experimental-features`:

```
$ nix eval --impure --expr '
let
  flake = builtins.getFlake (toString ./.);
  nixpkgs = flake.inputs.nixpkgs;
  ferrumLib = import ./modules/lib { inherit nixpkgs; sopsNix = flake.inputs.sops-nix; };
  host = ferrumLib.mkHost {
    system = "x86_64-linux";
    settings = builtins.fromJSON (builtins.readFile ./examples/hosts/minimal/settings.json);
    modules = [
      ./examples/hosts/minimal/configuration.nix
      { ferrum.secretsDir = toString ./examples/hosts/minimal/secrets; }
    ];
    revision = "ci";
  };
in host.config.nix.settings.experimental-features
'
[ "nix-command" "flakes" ]
```

Confirms the real, resolved option includes both `"nix-command"` and
`"flakes"` on a real example host config, with no per-host override
involved.

## Verification 2 (load-bearing): the real end-to-end apply test, with the test-node override removed

```
$ nix build .#checks.x86_64-linux.daemon-apply-end-to-end --print-build-logs
EXIT: 0
```

Full test script output (via `nix log` on the resulting derivation, since
`--print-build-logs` produces no incremental output for an already-built
derivation but the build genuinely ran -- confirmed fresh via the store
path's registration time, ~13:33 UTC, matching when this build command was
issued, vs. "now" ~13:55 UTC after the ~23s VM test plus eval/build
overhead):

```
=== the machine really boots on generation A ===
generation A toplevel: /nix/store/9vnp4bwf76bj9am34sdpf1a545h3h3lk-nixos-system-machine-test
generation A profile:  system-1-link
=== the second closure really is present in the guest store, offline ===
=== real login with the real bootstrap password ===
PASS: real login
=== THE request this test exists for: a real apply over the real HTTP API ===
job response: {"id":"557bffa9-f2ff-455e-9903-8184581f2ac9"}
PASS: the real apply job was accepted as 557bffa9-f2ff-455e-9903-8184581f2ac9
=== the real job really reaches a real terminal 'complete' line ===
real apply progress log:
{"detail":"ensuring generated secrets exist","event":"secrets","ts":1787405610}
{"detail":"building the new system closure","event":"build","ts":1787405610}
{"detail":"checking free space and snapshot subvolumes","event":"preflight","ts":1787405611}
{"detail":"stopping ferrum-apps.target (downtime starts)","event":"stop-apps","ts":1787405611}
{"detail":"snapshotting @state","event":"snapshot","ts":1787405611}
{"detail":"pointing the system profile at the new closure","event":"set-profile","ts":1787405611}
{"detail":"running switch-to-configuration switch","event":"switch","ts":1787405611}
{"detail":"restarting ferrum-apps.target","event":"start-apps","ts":1787405612}
{"detail":"waiting for every managed unit to become active","event":"health-check","ts":1787405612}
{"detail":"succeeded: ","event":"complete","ts":1787405612}

terminal line detail: 'succeeded: '
PASS: the real apply job completed with a real success
=== ...and it really was root, via the real privileged unit ===
=== THE assertion this test exists for: the system really switched ===
/run/current-system now: /nix/store/v5sknhci8qccg3lfb6pl6p99nifx4al5-nixos-system-machine-test
system profile now: system-2-link
PASS: a real generation switch really happened, driven entirely by a real HTTP request
=== the real apply really did its real state bookkeeping ===
snapshots after the real apply: ['1787405611-gen1']
journal entries after the real apply: ['1787405611-gen1.json']
journal entry: {'snapshot': '1787405611-gen1', 'generation': 1, 'toplevel': '/nix/store/9vnp4bwf76bj9am34sdpf1a545h3h3lk-nixos-system-machine-test', 'taken_at': '1787405611', 'quiesced': True}
PASS: the real apply really snapshotted state and really journalled it
=== ferrumd really survived the switch and really serves the log back ===
real SSE stream of the real apply:
event: progress
data: {"detail":"ensuring generated secrets exist","event":"secrets","ts":1787405610}

event: progress
data: {"detail":"building the new system closure","event":"build","ts":1787405610}

event: progress
data: {"detail":"checking free space and snapshot subvolumes","event":"preflight","ts":1787405611}

event: progress
data: {"detail":"stopping ferrum-apps.target (downtime starts)","event":"stop-apps","ts":1787405611}

event: progress
data: {"detail":"snapshotting @state","event":"snapshot","ts":1787405611}

event: progress
data: {"detail":"pointing the system profile at the new closure","event":"set-profile","ts":1787405611}

event: progress
data: {"detail":"running switch-to-configuration switch","event":"switch","ts":1787405611}

event: progress
data: {"detail":"restarting ferrum-apps.target","event":"start-apps","ts":1787405612}

event: progress
data: {"detail":"waiting for every managed unit to become active","event":"health-check","ts":1787405612}

event: progress
data: {"detail":"succeeded: ","event":"complete","ts":1787405612}

PASS: the real SSE stream really carried the real apply through to completion
=== the interlock really cleared, and the spent request file is really gone ===
PASS: a real apply really released the real single-job interlock
=== a real second apply is correctly a real no-op, not a second switch ===
second apply progress:
{"detail":"ensuring generated secrets exist","event":"secrets","ts":1787405615}
{"detail":"building the new system closure","event":"build","ts":1787405615}
{"detail":"already on the target closure; checking health only","event":"health-check","ts":1787405615}
{"detail":"succeeded: ","event":"complete","ts":1787405615}

PASS: a real repeat apply really was a real no-op
(finished: run the VM test script, in 23.66 seconds)
test script finished in 23.74s
cleanup
kill machine (pid 9)
qemu-system-x86_64: terminating on signal 15 from pid 6 (/nix/store/vm6nxpp97fxgczw00bwkxdqdm2an3n95-python3-3.13.12/bin/python3.13)
kill vlan (pid 7)
(finished: cleanup, in 0.05 seconds)
```

Every assertion in the test passed, including the `"event":"build"` line --
the real `nix build --impure --no-link --print-out-paths $FERRUM_FLAKE_REF`
step inside the real `ferrum-apply apply` job, inside a VM whose test node
now carries **only** `modules/core/nix-settings.nix`'s default (the manual
override is gone from the test file). This is real, direct proof that the
module fix -- not a test-only workaround -- is what makes a real `apply`
job's first step succeed.

## Verification 3: the three cheap CI checks (no regression)

```
$ nix build .#checks.x86_64-linux.catalog-consistency .#checks.x86_64-linux.schema-uniformity .#checks.x86_64-linux.sopsfile-are-paths --print-build-logs
EXIT: 0

$ cat result   # ferrum-check-catalog-consistency
catalog-consistency: ok
$ cat result-1 # ferrum-check-schema-uniformity
schema-uniformity: ok
$ cat result-2 # ferrum-check-sopsfile-are-paths
sopsfile-are-paths: ok
```

All three pass cleanly; the new option lives entirely under `nix.settings`,
outside the `ferrum.*` namespace `schema-uniformity` walks, so it does not
touch JSON-schema uniformity, catalog consistency, or sops-file path
validation.

## Files changed

- `modules/core/nix-settings.nix` (new) -- the fix itself.
- `modules/default.nix` -- registers the new module, imported first
  alongside `./core/options.nix`.
- `tests/daemon-apply-end-to-end.nix` -- removed the test node's manual
  `nix.settings.experimental-features` override and its accompanying
  comment, replacing the comment with a note that the setting is now
  expected to come from the module default, and that this test would fail
  for real if that default regressed.
