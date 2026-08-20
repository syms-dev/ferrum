# tests/apply-generation-switch.nix
#
# tests/rollback.nix proves the STATE half of ferrum's central claim ("a
# rollback reverts app state, not just the closure") -- but by its own
# header comment, it deliberately never exercises a real generation switch:
# its "v1 -> v2 upgrade" is a hand-simulated binary swap on the VM's one and
# only Nix generation, not a real `nix-env --set` + `switch-to-configuration
# switch` between two genuinely different closures. That's a real,
# documented scope gap: nothing anywhere proved the CLOSURE half of the
# pair, i.e. that `ferrum-apply rollback` actually reverts
# /nix/var/nix/profiles/system to a different, earlier toplevel -- only
# that it can revert application state while (trivially) "reverting" to the
# same closure it started from.
#
# This test closes that gap, offline (no `nix build` inside the VM):
# `afterToplevel` below is a second, complete NixOS closure differing from
# the real VM's own closure only by a marker file in /etc. Its store path
# is injected into the VM's store via `virtualisation.additionalPaths` (the
# mechanism nixosTest itself uses to get the VM's OWN toplevel into its
# store -- confirmed by reading nixos/modules/virtualisation/vm-base.nix),
# so the whole switch is reproducible without network access.
#
# `afterToplevel` is built by calling pkgs.testers.runNixOSTest a SECOND
# time (as `afterTest`, never actually run -- only its
# `.nodes.machine.config.system.build.toplevel` is used) with the exact
# same node config as the real `nodes.machine` below, differing only by the
# marker. This is deliberate, and not incidental: an EARLIER version of
# this test built the second closure standalone via
# nixos/lib/eval-config.nix, which produces a closure with none of the VM
# test framework's own instrumentation units (backdoor.service in
# particular -- the Python test driver's only command channel into the
# guest). Switching to that closure correctly stopped backdoor.service
# (since the new config never defined it) and it never came back, hanging
# every subsequent machine.succeed() call indefinitely. Building both
# closures through the SAME runNixOSTest node config guarantees identical
# test instrumentation in both, so the switch never disrupts the driver's
# own connection to the guest.
{ pkgs, ... }:
let
  # The full node config shared between the real VM (generation A) and the
  # throwaway second closure (generation B) -- identical except for the
  # marker file, which is this test's entire point of comparison.
  mkNode = markerValue: { config, lib, pkgs, utils, ... }: {
    imports = [ ../modules ];
    environment.etc."ferrum-test-marker".text = markerValue;

    virtualisation.emptyDiskImages = [ 4096 ];
    virtualisation.useBootLoader = true;
    virtualisation.useEFIBoot = true;
    boot.loader.systemd-boot.enable = true;
    boot.loader.efi.canTouchEfiVariables = true;

    ferrum.storage = {
      stateDir = "/var/lib/ferrum/state";
      snapshotDir = "/var/lib/ferrum/snapshots";
    };

    # Same reasoning and same shape as tests/rollback.nix: plain
    # fileSystems.* is silently discarded by the VM test framework.
    virtualisation.fileSystems."/var/lib/ferrum/state" = {
      device = "/dev/vdb";
      fsType = "btrfs";
      options = [ "subvol=@state" "compress=zstd" "noatime" ];
    };
    virtualisation.fileSystems."/var/lib/ferrum/snapshots" = {
      device = "/dev/vdb";
      fsType = "btrfs";
      options = [ "subvol=@snapshots" "noatime" ];
    };

    # Identical fixture to tests/rollback.nix's -- see that file for the
    # full explanation of each line. This test needs a real @state/@snapshots
    # pair too: rollback::prepare (crates/ferrum-apply/src/rollback.rs) now
    # refuses to write an intent unless a snapshot directory genuinely
    # exists for the target generation, so a real (if trivial) snapshot and
    # journal entry are required for `ferrum-apply rollback` to do anything
    # at all here -- even though this test has no application state to
    # actually revert.
    systemd.services.ferrum-test-provision-btrfs = {
      description = "Test fixture: create @state/@snapshots on the second disk";
      unitConfig.DefaultDependencies = false;
      after = [ "local-fs-pre.target" "dev-vdb.device" ];
      requires = [ "dev-vdb.device" ];
      wants = [ "local-fs-pre.target" ];
      before = [
        "ferrum-state-restore.service"
        "${utils.escapeSystemdPath config.ferrum.storage.stateDir}.mount"
        "${utils.escapeSystemdPath config.ferrum.storage.snapshotDir}.mount"
        "local-fs.target"
      ];
      wantedBy = [ "local-fs.target" ];
      path = [ pkgs.btrfs-progs pkgs.util-linux ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        if ! blkid -t TYPE=btrfs /dev/vdb >/dev/null 2>&1; then
          mkfs.btrfs -f /dev/vdb
        fi
        mkdir -p /run/ferrum-test-provision
        mount -t btrfs -o subvolid=5 /dev/vdb /run/ferrum-test-provision
        for sv in @state @snapshots; do
          if [ ! -d "/run/ferrum-test-provision/$sv" ]; then
            btrfs subvolume create "/run/ferrum-test-provision/$sv"
          fi
        done
        umount /run/ferrum-test-provision
      '';
    };

    environment.systemPackages = [ pkgs.ferrum-apply ];
  };

  # Never actually run (no testScript logic beyond the empty default) --
  # only its node's evaluated toplevel is used. Nix's laziness means
  # referencing just `.config.system.build.toplevel` below does not force
  # building the "run the test" derivation, only this one node's closure.
  afterTest = pkgs.testers.runNixOSTest {
    name = "ferrum-apply-generation-switch-after";
    node.pkgsReadOnly = false;
    nodes.machine = mkNode "generation-B";
    testScript = ""; # never run -- only .nodes.machine.config is used
  };
  afterToplevel = afterTest.nodes.machine.system.build.toplevel;
in
pkgs.testers.runNixOSTest {
  name = "ferrum-apply-generation-switch";

  # See tests/rollback.nix's identical comment: modules/core/overlays.nix
  # sets nixpkgs.overlays, which pkgs.testers.runNixOSTest makes read-only
  # by default unless this is set.
  node.pkgsReadOnly = false;

  nodes.machine = {
    imports = [ (mkNode "generation-A") ];

    # Makes afterToplevel's closure available in the VM's store, offline --
    # see this file's header. Appends to (doesn't replace) the framework's
    # own default of [ config.system.build.toplevel ] (vm-base.nix).
    virtualisation.additionalPaths = [ afterToplevel ];
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest("boots on generation A's marker"):
        machine.succeed("grep -q generation-A /etc/ferrum-test-marker")

    with subtest(
        "record generation A's real toplevel and number, then take a state "
        "snapshot and journal entry for it -- the same bookkeeping "
        "ferrum-apply apply performs, done by hand here since this test's "
        "point is the switch itself (already covered from the other "
        "direction by tests/rollback.nix)"
    ):
        machine.succeed(
            "readlink /run/current-system > /tmp/toplevel-a\n"
            "readlink /nix/var/nix/profiles/system | "
            "grep -oP '(?<=system-)\\d+(?=-link)' > /tmp/gen-a\n"
            "GEN=$(cat /tmp/gen-a)\n"
            "TS=$(date +%s)\n"
            "SNAP=$TS-gen$GEN\n"
            "echo $SNAP > /tmp/snapshot-a\n"
            "btrfs subvolume snapshot -r /var/lib/ferrum/state /var/lib/ferrum/snapshots/$SNAP\n"
            "mkdir -p /var/lib/ferrum/journal\n"
            "cat > /var/lib/ferrum/journal/$SNAP.json <<JOURNAL\n"
            "{\"snapshot\":\"$SNAP\",\"generation\":$GEN,\"toplevel\":\"$(cat /tmp/toplevel-a)\",\"taken_at\":\"$TS\",\"quiesced\":true}\n"
            "JOURNAL"
        )

    with subtest(
        "real generation switch to closure B: nix-env --set + "
        "switch-to-configuration switch, the exact sequence "
        "ferrum-apply apply uses (Global Constraints) against a SECOND, "
        "genuinely different toplevel -- not the same closure tests/"
        "rollback.nix rolls back to"
    ):
        machine.succeed(
            "nix-env -p /nix/var/nix/profiles/system --set ${afterToplevel}\n"
            "${afterToplevel}/bin/switch-to-configuration switch"
        )
        machine.succeed("grep -q generation-B /etc/ferrum-test-marker")
        machine.succeed(
            "test \"$(readlink /run/current-system)\" = \"${afterToplevel}\""
        )

    with subtest(
        "call the REAL ferrum-apply rollback back to generation A, and "
        "survive the real reboot it triggers -- see tests/rollback.nix's "
        "identical subtest for the full explanation of the "
        "backgrounding/wait_for_shutdown/start idiom"
    ):
        machine.succeed(
            "GEN=$(cat /tmp/gen-a)\n"
            "ferrum-apply rollback --to $GEN > /var/log/ferrum-rollback.log 2>&1 &"
        )
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")

    with subtest("the boot-time state restore did not flag a failure"):
        machine.succeed("test ! -e /var/lib/ferrum/state-restore-failed")

    with subtest(
        "THE assertion this test exists for: /run/current-system resolves "
        "to generation A's EXACT original toplevel store path, byte for "
        "byte -- not just 'some earlier generation', and not merely the "
        "same closure it started from (that would also pass a rollback "
        "that never actually switched anything). This is the closure half "
        "of the atomic pair tests/rollback.nix proves the state half of"
    ):
        machine.succeed(
            "test \"$(readlink /run/current-system)\" = \"$(cat /tmp/toplevel-a)\""
        )
        machine.succeed("grep -q generation-A /etc/ferrum-test-marker")
  '';
}
