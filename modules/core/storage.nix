# Directory scaffolding and invariants for the ferrum storage layout.
#
# The full disko subvolume layout (see examples/hosts/minimal/disko.nix)
# defines the actual @root/@nix/@state/@snapshots/@media boundaries; this
# module only asserts the invariants that layout depends on and creates the
# plain directories underneath each mount point. See the plan's "Storage
# layout" section for why each rule exists:
#
#   1. /var/lib/ferrum itself must live on @root (outside the snapshotted
#      tree), because ferrumd's own database and rollback journal must
#      survive the rollback they are reporting on.
#   2. downloads/library must be plain directories inside one subvolume,
#      never separate subvolumes -- btrfs forbids hardlinks across
#      subvolumes, and the *arr import workflow depends on hardlinks.
#   3. snapshotDir must not nest inside stateDir.
{ config, lib, ... }:
let
  cfg = config.ferrum.storage;

  # /var/lib/ferrum is ALSO ferrumd's own state directory (FERRUMD_STATE_DIR
  # in modules/core/daemon.nix): its SQLite database, its bootstrap password
  # file, and the per-job JSONL progress logs under jobs/ all live here,
  # written by the unprivileged ferrum user. So the directory is owned by
  # that user whenever the daemon is enabled. It has to be declared HERE
  # rather than in daemon.nix: two systemd.tmpfiles rules for the same path
  # with different arguments is a real conflict, not a merge. Everything
  # else that writes under this directory (ferrum-apply's journal, the
  # state-restore failure marker, the state/snapshot mount points) runs as
  # root and is unaffected by the ownership. Falls back to root:root on a
  # host with ferrum.daemon.enable = false, where the ferrum user does not
  # exist at all and naming it here would fail tmpfiles at boot.
  ferrumdOwner = if config.ferrum.daemon.enable then "ferrum" else "root";
in
{
  config = {
    users.groups.${cfg.mediaGroup} = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0750 root root - -"
      "d ${cfg.snapshotDir} 0750 root root - -"
      "d /var/lib/ferrum 0750 ${ferrumdOwner} ${ferrumdOwner} - -"
      "d ${cfg.mediaDir} 0775 root ${cfg.mediaGroup} - -"
      "d ${cfg.mediaDir}/downloads 0775 root ${cfg.mediaGroup} - -"
      "d ${cfg.mediaDir}/library 0775 root ${cfg.mediaGroup} - -"
    ];

    assertions = [
      {
        assertion = cfg.stateDir != "/var/lib/ferrum";
        message = ''
          ferrum.storage.stateDir must not be /var/lib/ferrum itself: that
          directory holds ferrumd's own database and rollback journal, which
          must survive a state rollback rather than be reverted by one.
        '';
      }
      {
        assertion = !(lib.hasInfix cfg.stateDir cfg.snapshotDir);
        message = "ferrum.storage.snapshotDir must not nest inside ferrum.storage.stateDir.";
      }
      {
        assertion = cfg.minFreeGiB > 0;
        message = "ferrum.storage.minFreeGiB must be positive.";
      }
    ];

    boot.supportedFilesystems = [ "btrfs" ];
  };
}
