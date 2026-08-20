# tests/rollback.nix
#
# THE most important test in the project (see the plan's "Verification"
# section). Proves that a rollback restores state, not just the system
# closure: boots ferrum-testapp v1 under the real ferrum-apps.target, writes
# a "before" row, simulates an upgrade to v2 (which migrates the schema and
# can never be downgraded from -- see nix/pkgs/testapp/src/main.rs), writes
# an "after" row, then calls the REAL `ferrum-apply rollback --to <gen>`
# binary (Task 7) and survives the real reboot it triggers. Asserts the
# SECOND row is gone and the schema reverted -- proof the database, not just
# the binary, went back in time.
#
# Two deliberate deviations from a fully faithful reproduction of
# examples/hosts/homelab-btrfs/disko.nix, both explained where they occur
# below:
#   1. `/` and `/nix` stay on the VM test framework's normal, well-tested
#      auto-formatted root (virtualisation.useDefaultFilesystems' default),
#      the same path nixpkgs' own nixos/tests/systemd-boot.nix relies on for
#      real-bootloader tests. Only ferrum's own @state/@snapshots subvolumes
#      -- the only two mountpoints ferrum-apply/state-restore.nix actually
#      touch -- are built by hand, on a second disk. @root/@nix/@media from
#      the disko layout are approximated by that default root rather than
#      reproduced as literal extra subvolumes, since nothing under test
#      cares whether "/" itself is btrfs.
#   2. The v1->v2 upgrade is simulated by directly swapping the running
#      binary, not by a real `nix build` + generation switch. This is an
#      explicit, already-documented scope decision (see the plan's
#      Self-Review Notes): `ferrum-apply apply`'s build+switch orchestration
#      is exercised by unit tests only, in a different task. The Nix
#      generation this test rolls back to is therefore the VM's one and
#      only (current) generation -- `ferrum-apply rollback` doesn't care
#      whether its target is "older" than current, only that a state
#      snapshot exists for it, so this still genuinely exercises
#      rollback::run's real command sequence (nix-env --switch-generation,
#      switch-to-configuration boot, reboot).
{ pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "ferrum-rollback";

  # pkgs.testers.runNixOSTest makes the nixpkgs.* options read-only by
  # default (nixos/lib/testing/nodes.nix: node.pkgsReadOnly defaults to
  # true whenever node.pkgs is set, which this tester always does) --
  # evaluating with that default would make `imports = [ ../modules ]`
  # below throw "nixpkgs.overlays is set to read-only", since
  # modules/core/overlays.nix sets nixpkgs.overlays to wire up
  # pkgs.ferrum-apply/pkgs.ferrum-testapp. This is the documented escape
  # hatch (the option's own description names exactly this situation),
  # traded for slightly slower evaluation.
  node.pkgsReadOnly = false;

  nodes.machine = { config, lib, pkgs, utils, ... }: {
    imports = [ ../modules ];

    virtualisation.emptyDiskImages = [ 4096 ];
    virtualisation.useBootLoader = true;
    virtualisation.useEFIBoot = true;
    boot.loader.systemd-boot.enable = true;
    boot.loader.efi.canTouchEfiVariables = true;

    # ferrum.storage.stateDir/snapshotDir already default to these paths
    # (modules/core/options.nix); set explicitly so the fileSystems entries
    # below are self-evidently talking about the same paths.
    ferrum.storage = {
      stateDir = "/var/lib/ferrum/state";
      snapshotDir = "/var/lib/ferrum/snapshots";
    };

    # `virtualisation.fileSystems`, NOT plain `fileSystems`: the VM test
    # framework (nixos/modules/virtualisation/qemu-vm.nix) regenerates the
    # entire top-level `fileSystems` option itself, at VM-override priority,
    # from `virtualisation.fileSystems` plus its own defaults (/, /boot,
    # /tmp/shared, /tmp/xchg) -- a plain `fileSystems."/foo" = {...}`
    # declared here is silently discarded rather than merged in. Confirmed
    # by evaluating this exact test's config directly: with plain
    # `fileSystems.*`, `config.fileSystems` contained only the four
    # framework defaults, none of what's declared below.
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

    # virtualisation.emptyDiskImages only creates a raw, unformatted qcow2
    # disk (see nixos/modules/virtualisation/qemu-vm.nix) -- unlike a real
    # disko-provisioned box, nothing has created the @state/@snapshots
    # subvolumes declared above yet. This is that one-time provisioning
    # step, done the same way disko would (mkfs.btrfs, then create each
    # subvolume at the top-level subvolid=5 view), ordered before the two
    # mount units above so it runs early enough for them to succeed.
    # Idempotent -- skips creation if a subvolume already exists, which is
    # what happens on the post-rollback reboot later in this test.
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

    # A minimal stand-in for a real ferrum app service, wired under
    # ferrum-apps.target exactly the way a real app module would be
    # (modules/core/generations.nix). Always starts at v1; the testScript
    # below manages the v1<->v2 swap itself (stopping this unit and running
    # a second, transient v2 instance) rather than the module dynamically
    # switching, since a single NixOS module evaluation can't change
    # behavior mid-test.
    systemd.services.ferrum-testapp = {
      description = "ferrum-testapp (rollback test fixture)";
      wantedBy = [ "ferrum-apps.target" ];
      partOf = [ "ferrum-apps.target" ];
      after = [ "ferrum-apps.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${lib.getExe pkgs.ferrum-testapp} --app-version 1 --db-path /var/lib/ferrum/state/testapp/app.db --listen 127.0.0.1:8099";
      };
    };

    # ferrum-testapp included so the testScript's ad-hoc upgrade-simulation
    # invocation (below) can call it by bare command name -- referencing
    # `pkgs.ferrum-testapp` from testScript's own scope doesn't work, since
    # that string is built by the OUTER `{ pkgs, ... }:` function argument
    # (checks.nix's flake-level pkgs), which never has the ferrum overlay
    # applied. Only pkgs *inside* this NixOS module evaluation does
    # (modules/core/overlays.nix's nixpkgs.overlays only takes effect within
    # a NixOS system evaluation) -- confirmed by hand: the outer pkgs threw
    # "attribute 'ferrum-testapp' missing" when this test first ran for
    # real. environment.systemPackages sidesteps the scope mismatch
    # entirely by putting the binary on the VM's own PATH.
    environment.systemPackages = [ pkgs.ferrum-apply pkgs.ferrum-testapp pkgs.curl pkgs.sqlite ];
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("ferrum-apps.target")
    machine.wait_for_open_port(8099)

    with subtest("v1 accepts a fresh database and serves /ping"):
        machine.succeed("curl -sf http://127.0.0.1:8099/ping")

    with subtest("write the 'before' sentinel"):
        machine.succeed(
            "curl -sf -X POST -H 'Content-Type: application/json' "
            "-d '{\"text\":\"before\"}' http://127.0.0.1:8099/notes"
        )

    with subtest(
        "record the generation and take a manual snapshot, simulating what "
        "ferrum-apply apply would do before an upgrade"
    ):
        machine.succeed(
            "systemctl stop ferrum-apps.target\n"
            "TS=$(date +%s)\n"
            "GEN=$(readlink /nix/var/nix/profiles/system | grep -oP '(?<=system-)\\d+(?=-link)')\n"
            "echo $GEN > /tmp/gen\n"
            "SNAP=$TS-gen$GEN\n"
            "echo $SNAP > /tmp/snapshot_name\n"
            "btrfs subvolume snapshot -r /var/lib/ferrum/state /var/lib/ferrum/snapshots/$SNAP\n"
            "mkdir -p /var/lib/ferrum/journal\n"
            "cat > /var/lib/ferrum/journal/$SNAP.json <<JOURNAL\n"
            "{\"snapshot\":\"$SNAP\",\"generation\":$GEN,\"toplevel\":\"/nix/store/placeholder\",\"taken_at\":\"$TS\",\"quiesced\":true}\n"
            "JOURNAL\n"
            "systemctl start ferrum-apps.target"
        )
        machine.wait_for_open_port(8099)

    with subtest(
        "upgrade to v2 (the actual binary swap via `nix build` + a real "
        "generation switch is out of this test's scope -- see the file "
        "header. This simulates only the post-upgrade STATE, which is what "
        "proves the rollback half of the mechanism)"
    ):
        machine.succeed("systemctl stop ferrum-testapp")
        machine.succeed(
            "systemd-run --unit=ferrum-testapp-v2 --collect "
            "ferrum-testapp --app-version 2 "
            "--db-path /var/lib/ferrum/state/testapp/app.db --listen 127.0.0.1:8099"
        )
        machine.wait_for_open_port(8099)
        machine.succeed(
            "${pkgs.sqlite}/bin/sqlite3 /var/lib/ferrum/state/testapp/app.db "
            "'PRAGMA user_version;' | grep -q '^2$'"
        )

    with subtest("write the 'after' sentinel, then stop the v2 instance"):
        machine.succeed(
            "curl -sf -X POST -H 'Content-Type: application/json' "
            "-d '{\"text\":\"after\"}' http://127.0.0.1:8099/notes"
        )
        # A positive control: confirm the write actually persisted before
        # the rollback happens, so "after is gone" later can only mean the
        # rollback removed it -- not that it was never really there.
        machine.succeed("curl -sf http://127.0.0.1:8099/rows | grep -q after")
        machine.succeed("systemctl stop ferrum-testapp-v2")

    with subtest(
        "call the REAL ferrum-apply rollback (Task 7) -- not a hand-written "
        "intent file -- which validates the generation, writes the intent, "
        "runs nix-env --switch-generation, switch-to-configuration boot, "
        "and reboots for real. The command is backgrounded (with stdout/"
        "stderr redirected to a file, so the pipe back to the test driver "
        "closes cleanly) so this shell call returns before the VM actually "
        "goes down. wait_for_shutdown() then blocks on the underlying QEMU "
        "process actually exiting -- the default nixosTest machine passes "
        "-no-reboot to qemu, so a real in-guest `reboot` causes qemu to "
        "exit rather than reset, exactly like wait_for_shutdown()'s use of "
        "process.wait() expects. machine.start() then boots a fresh QEMU "
        "process against the same persistent disk images (guaranteed "
        "persistent here because of virtualisation.useBootLoader = true), "
        "which is the standard nixpkgs idiom for this -- see "
        "nixos/tests/hibernate.nix upstream for the same three-call shape"
    ):
        machine.succeed(
            "GEN=$(cat /tmp/gen)\n"
            "ferrum-apply rollback --to $GEN > /var/log/ferrum-rollback.log 2>&1 &"
        )
        machine.wait_for_shutdown()
        machine.start()
        machine.wait_for_unit("ferrum-apps.target")

    with subtest("the boot-time state restore did not flag a failure"):
        machine.succeed("test ! -e /var/lib/ferrum/state-restore-failed")

    with subtest(
        "the restore actually ran, against the specific snapshot this test "
        "took -- not just 'no failure marker', which is equally true if "
        "restore_state::run returned early because no intent existed at all"
    ):
        machine.succeed("test ! -e /var/lib/ferrum/rollback-intent.json")
        result_json = machine.succeed("cat /var/lib/ferrum/rollback-result.json")
        # Derived from the journal directory (on the persistent state disk,
        # unlike /tmp which this test never assumes survives the reboot)
        # rather than re-reading /tmp/snapshot_name post-reboot -- this test
        # only ever creates one journal entry, so its filename IS the
        # snapshot name this whole test revolves around.
        expected_snapshot = machine.succeed(
            "basename /var/lib/ferrum/journal/*.json .json"
        ).strip()
        assert '"ok": true' in result_json, result_json
        assert expected_snapshot in result_json, (
            f"rollback-result.json doesn't name the snapshot this test took "
            f"({expected_snapshot!r}): {result_json!r}"
        )

    with subtest(
        "v1 starts cleanly against the restored database -- via the REAL "
        "ferrum-testapp.service, which ferrum-apps.target brought back up "
        "automatically after the reboot, exactly as it would on a real box"
    ):
        machine.wait_for_open_port(8099)
        machine.succeed("curl -sf http://127.0.0.1:8099/ping")

    with subtest("schema reverted, not just the closure"):
        machine.succeed(
            "${pkgs.sqlite}/bin/sqlite3 /var/lib/ferrum/state/testapp/app.db "
            "'PRAGMA user_version;' | grep -q '^1$'"
        )
        machine.succeed(
            "${pkgs.sqlite}/bin/sqlite3 /var/lib/ferrum/state/testapp/app.db "
            "'PRAGMA integrity_check;' | grep -q '^ok$'"
        )

    with subtest("'before' sentinel survived"):
        machine.succeed("curl -sf http://127.0.0.1:8099/rows | grep -q before")

    with subtest("THE assertion that distinguishes ferrum: 'after' sentinel is GONE"):
        result = machine.succeed("curl -sf http://127.0.0.1:8099/rows")
        assert "after" not in result, (
            "the 'after' sentinel survived the rollback -- state was NOT "
            "actually restored, only appeared to be"
        )

    with subtest("the displaced pre-rollback subvolume was retained (undo of the undo)"):
        machine.succeed(
            "mkdir -p /run/ferrum/btrfs-check\n"
            "DEV=$(${pkgs.util-linux}/bin/findmnt -no SOURCE /var/lib/ferrum/state | sed 's/\\[.*\\]//')\n"
            "mount -t btrfs -o subvolid=5 $DEV /run/ferrum/btrfs-check\n"
            "ls /run/ferrum/btrfs-check/trash/ | grep -q '@state.replaced'\n"
            "umount /run/ferrum/btrfs-check"
        )
  '';
}
