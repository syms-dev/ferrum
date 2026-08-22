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

  # /var/lib/ferrum is SHARED between root-trusted state and ferrumd's own
  # state, so its OWNER stays root and only its GROUP is opened up.
  #
  # What lives here that root alone must control: `state-restore-failed`
  # (the fail-closed marker that every app unit and modules/core/
  # generations.nix gate on via ConditionPathExists), `rollback-intent.json`
  # (read as root at boot by modules/core/state-restore.nix), the `journal/`
  # directory, and the state/snapshot mount points. What ferrumd needs is
  # only its own `daemon/` subdirectory and the `jobs/` progress logs, both
  # declared as ferrum-owned subdirectories in modules/core/daemon.nix.
  #
  # This module owned the parent by the ferrum user until the branch-wide
  # final review of Phase 1.5a. That was a real hole, not a cosmetic one:
  # write permission on a DIRECTORY is create/delete/rename permission on
  # every name in it, whatever the individual files' own modes say -- so a
  # compromised ferrumd could simply `unlink` state-restore-failed to
  # defeat the fail-closed interlock, or replace rollback-intent.json with
  # a forged one naming an attacker-chosen (but generation-valid) snapshot.
  # Neither requires any Nix evaluation, which is exactly the class of
  # escalation this phase's security thesis says must not exist.
  #
  # `root:ferrum 0750` gives the ferrum group r-x: enough to TRAVERSE into
  # daemon/ and jobs/ (and to list this directory), and no write bit at
  # all. It has to be declared HERE rather than in daemon.nix -- two
  # systemd.tmpfiles rules for the same path with different arguments is a
  # real conflict, not a merge. Falls back to root:root on a host with
  # ferrum.daemon.enable = false, where the ferrum group does not exist at
  # all and naming it here would fail tmpfiles at boot.
  ferrumdGroup = if config.ferrum.daemon.enable then "ferrum" else "root";
in
{
  config = {
    users.groups.${cfg.mediaGroup} = { };

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0750 root root - -"
      "d ${cfg.snapshotDir} 0750 root root - -"
      "d /var/lib/ferrum 0750 root ${ferrumdGroup} - -"
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
