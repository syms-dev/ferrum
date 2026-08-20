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
in
{
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

    environment.FERRUM_ROOT_DEVICE = config.fileSystems.${ferrum.storage.stateDir}.device;
  };
}
