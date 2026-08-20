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
  # `or null`, not a bare `.device`: a stateDir with no matching fileSystems
  # entry, or one with a null device (e.g. a bind mount), must not crash
  # evaluation here -- the assertion below turns it into a clear
  # ferrum-specific error instead of a bare "attribute missing".
  stateDevice = config.fileSystems.${ferrum.storage.stateDir}.device or null;
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
