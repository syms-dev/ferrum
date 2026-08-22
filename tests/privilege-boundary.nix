# Proves the privilege boundary Task 2 built actually works against the
# REAL ferrum-apply binary, not a stand-in: a real unprivileged user
# triggers a real ferrum-apply run-request via a real D-Bus StartUnit call,
# authorized by the real polkit rule in modules/core/daemon.nix, and the
# same user is denied starting an unrelated unit.
#
# Deviates from the brief's original literal test code in one load-bearing
# way, discovered by actually running this on ferrum-dev: importing only
# `../modules/core/daemon.nix` with a hand-rolled `options.ferrum` stub
# left `pkgs.ferrum-apply` undefined, since that binding is wired in by
# modules/core/overlays.nix's `nixpkgs.overlays`, not by daemon.nix itself
# (daemon.nix only CONSUMES `pkgs.ferrum-apply`, same as every other
# module under modules/core -- see overlays.nix's own header for why the
# overlay lives separately). The fix is the same escape hatch
# tests/rollback.nix already uses for exactly this reason: import the full
# `../modules` (which pulls in overlays.nix, options.nix, and daemon.nix
# together) and set `node.pkgsReadOnly = false` so `nixpkgs.overlays` is
# still settable inside a `pkgs.testers.runNixOSTest` node. Requesting a
# real `preflight` (below) then also requires state_dir/snapshot_dir to be
# real btrfs subvolumes -- provisioned here with the same second-disk
# pattern tests/rollback.nix uses, trimmed to skip the bootloader/reboot
# machinery this test never needs.
#
# A SECOND, separate gap found by actually running this (not present in
# the brief's literal code, and not scoped to fix project-wide here):
# `../modules` alone declares options like `modules/apps/qbittorrent/
# service.nix`'s `sops.secrets.*` entries (inert, behind their own
# `ferrum.apps.qbittorrent.enable` mkIf, but still merged as DEFINITIONS
# against an `sops.*` OPTION namespace that only exists once sops-nix's own
# NixOS module is imported). A real host gets that for free from
# modules/lib/default.nix's `mkHost`, which always puts
# `sopsNix.nixosModules.sops` in the module list alongside this same
# `../modules` -- `pkgs.testers.runNixOSTest` doesn't go through `mkHost`,
# so this test imports it directly instead. (This isn't unique to this
# test: `nix eval .#checks.x86_64-linux.rollback.drvPath` hits the
# identical "option `nodes.machine.sops' does not exist" error on this same
# ferrum-dev checkout, confirming it's a pre-existing gap in every VM test
# that imports `../modules` directly, not something this task introduced --
# out of scope to fix project-wide from here, so only this test's own
# import list is patched.)
{ pkgs, sopsNix, ... }:
pkgs.testers.runNixOSTest {
  name = "privilege-boundary";

  node.pkgsReadOnly = false;

  nodes.machine = { config, lib, pkgs, utils, ... }: {
    imports = [ ../modules sopsNix.nixosModules.sops ];

    virtualisation.emptyDiskImages = [ 4096 ];

    ferrum.daemon.enable = true;
    ferrum.storage = {
      stateDir = "/var/lib/ferrum/state";
      snapshotDir = "/var/lib/ferrum/snapshots";
      # The disk image above is 4GiB; the real 10GiB default would make
      # every real preflight run here fail on free space alone, which
      # would be testing the wrong thing. Must stay positive (see
      # modules/core/options.nix's own assertion) -- 1 is plenty given the
      # disk is freshly formatted and otherwise empty.
      minFreeGiB = 1;
    };

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

    # No /etc/ferrum stub files needed here: the ferrum-apply@ template
    # unit and polkit rule under test don't reference /etc/ferrum at all
    # -- that dependency belongs only to the ferrumd unit itself (added
    # in Task 6, which checks it via the real, activation-time
    # AssertPathExists=, not an eval-time assertion; see Task 6 Step 8's
    # own test for where those stub files are actually needed).
    users.users.testferrum = {
      isNormalUser = true;
    };
    system.stateVersion = "25.11";
  };
  # A THIRD gap found by actually running this (also not scoped to fix
  # project-wide): the brief's literal testScript used a doubled backslash
  # (`\\"`) before each embedded double-quote. Nix `''...''` strings don't
  # treat backslash specially at all, so that reached Python as a literal
  # `\\"` -- which Python parses as an escaped backslash followed by an
  # UNescaped quote, terminating the string early ("Unterminated string
  # literal", caught by the test driver's own Python type-checker before
  # the VM even boots). A single backslash (`\"`) is what actually produces
  # an escaped quote in the resulting Python source.
  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("polkit.service")

    valid_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    # A real request file, written as root here to simulate what ferrumd
    # (Task 6) will do for real -- this test's job is the privilege
    # boundary, not ferrumd itself.
    machine.succeed(
        f"mkdir -p /run/ferrum/requests && "
        f"echo '{{\"kind\":\"preflight\"}}' > /run/ferrum/requests/{valid_uuid}.json && "
        f"chown ferrum:ferrum /run/ferrum/requests/{valid_uuid}.json"
    )

    print("=== unprivileged user triggers a REAL ferrum-apply run-request via D-Bus ===")
    machine.succeed(
        f"su - testferrum -c \"busctl call --system org.freedesktop.systemd1 "
        f"/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss "
        f"'ferrum-apply@{valid_uuid}.service' replace\""
    )
    machine.wait_until_succeeds(
        f"systemctl show ferrum-apply@{valid_uuid}.service -p Result | grep -q 'Result=success'"
    )
    print("PASS: the real ferrum-apply binary really ran preflight, dispatched through the real polkit+D-Bus mechanism")

    print("=== unprivileged user tries an unrelated unit -- must be denied ===")
    machine.fail(
        "su - testferrum -c \"busctl call --system org.freedesktop.systemd1 "
        "/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss "
        "'sshd.service' replace\""
    )
    print("PASS: starting an unrelated unit was correctly denied")
  '';
}
