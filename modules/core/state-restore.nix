#
# Boot-time state-swap unit. Ordering validated by hand against real
# hardware (Phase 1.0 probe 0.3): this unit's ActiveEnterTimestamp measured
# a full second before the @state mount unit's. It needs no initrd
# integration -- @state is not neededForBoot, so a stage-2 unit ordered
# before its mount runs while @root is writable and @state is not yet
# mounted.
{ config, lib, pkgs, utils, ... }:
let
  ferrum = config.ferrum;
  stateMountUnit = "${utils.escapeSystemdPath ferrum.storage.stateDir}.mount";
  # `or null`, not a bare `.device`/`.options`: a dir with no matching
  # fileSystems entry, or one with a null device (e.g. a bind mount), must
  # not crash evaluation here -- the assertions below turn each case into a
  # clear ferrum-specific error instead of a bare "attribute missing".
  stateFs = config.fileSystems.${ferrum.storage.stateDir} or null;
  snapshotFs = config.fileSystems.${ferrum.storage.snapshotDir} or null;
  stateDevice = stateFs.device or null;
  snapshotDevice = snapshotFs.device or null;

  # crates/ferrum-apply/src/restore_state.rs's perform_swap hardcodes the
  # subvolume names `@state` and `@snapshots` under a single `subvolid=5`
  # mount of the top-level btrfs volume (Global Constraints: "btrfs swap
  # sequence"). That's only correct if stateDir and snapshotDir really are
  # those two subvolumes on the SAME device -- otherwise a rollback
  # validates, reboots, and then fails to find the subvolume it expected.
  # These assertions catch that at eval time instead.
  hasSubvolOption = fs: name:
    fs != null && lib.any (o: o == "subvol=${name}") (fs.options or [ ]);
in
{
  assertions = [
    {
      assertion = stateDevice != null;
      message = ''
        ferrum.storage.stateDir is set to "${ferrum.storage.stateDir}", but
        fileSystems."${ferrum.storage.stateDir}".device does not resolve to
        a real device (missing entry, or a device-less mount like a bind
        mount). ferrum-state-restore needs a concrete block device to mount
        the top-level btrfs volume when restoring state for a pending
        rollback -- add a fileSystems entry with a real `device`.
      '';
    }
    {
      assertion = snapshotDevice != null;
      message = ''
        ferrum.storage.snapshotDir is set to "${ferrum.storage.snapshotDir}",
        but fileSystems."${ferrum.storage.snapshotDir}".device does not
        resolve to a real device (missing entry, or a device-less mount).
        ferrum-apply snapshots state into this directory and
        ferrum-state-restore later reads a snapshot back out of it by name
        under the SAME top-level btrfs volume as stateDir -- add a
        fileSystems entry with a real `device`.
      '';
    }
    {
      assertion = stateDevice == null || snapshotDevice == null || stateDevice == snapshotDevice;
      message = ''
        ferrum.storage.stateDir ("${ferrum.storage.stateDir}", device
        "${toString stateDevice}") and ferrum.storage.snapshotDir
        ("${ferrum.storage.snapshotDir}", device "${toString snapshotDevice}")
        resolve to different devices. ferrum-state-restore mounts ONE
        top-level btrfs volume (subvolid=5) and expects to find both @state
        and @snapshots as subvolumes of it -- they must be on the same
        device, or a rollback will validate and reboot into a restore that
        cannot find the snapshot it needs.
      '';
    }
    {
      assertion = stateFs == null || hasSubvolOption stateFs "@state";
      message = ''
        fileSystems."${ferrum.storage.stateDir}" does not have the mount
        option "subvol=@state". ferrum-state-restore hardcodes that exact
        subvolume name when performing the snapshot-and-rename swap
        (crates/ferrum-apply/src/restore_state.rs) -- mount stateDir with
        `subvol=@state`, or the restore will look for a subvolume that
        doesn't exist under that name.
      '';
    }
    {
      assertion = snapshotFs == null || hasSubvolOption snapshotFs "@snapshots";
      message = ''
        fileSystems."${ferrum.storage.snapshotDir}" does not have the mount
        option "subvol=@snapshots". ferrum-state-restore hardcodes that
        exact subvolume name when performing the snapshot-and-rename swap
        (crates/ferrum-apply/src/restore_state.rs) -- mount snapshotDir with
        `subvol=@snapshots`, or the restore will look for a subvolume that
        doesn't exist under that name.
      '';
    }
  ];

  systemd.services.ferrum-state-restore = {
    description = "Restore ferrum state subvolume for a pending rollback";

    unitConfig.DefaultDependencies = false;
    after = [ "local-fs-pre.target" ];
    wants = [ "local-fs-pre.target" ];
    before = [ stateMountUnit "local-fs.target" "shutdown.target" ];
    conflicts = [ "shutdown.target" ];
    wantedBy = [ "local-fs.target" ];

    path = [ pkgs.btrfs-progs pkgs.util-linux pkgs.coreutils ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${lib.getExe pkgs.ferrum-apply} restore-state";
    };

    environment.FERRUM_ROOT_DEVICE = stateDevice;
  };
}
