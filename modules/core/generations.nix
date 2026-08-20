# ferrum-apps.target -- the single point of control apply.nix stops and
# starts around every snapshot (see the plan's "Snapshot and rollback"
# section for why: switch-to-configuration only restarts units whose
# closure changed, so stopping this target explicitly before a switch is
# what guarantees everything comes back afterwards).
#
# Individual app modules put themselves under this target with
# `wantedBy = lib.mkForce [ "ferrum-apps.target" ];` so they are not also
# pulled in by multi-user.target directly.
{ ... }:
{
  systemd.targets.ferrum-apps = {
    description = "All ferrum-managed applications";
    wantedBy = [ "multi-user.target" ];
    after = [ "ferrum-state-restore.service" ];
    unitConfig.ConditionPathExists = "!/run/ferrum/state-restore-failed";
  };
}
