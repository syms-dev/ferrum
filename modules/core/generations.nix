# ferrum-apps.target -- the single point of control apply.nix stops and
# starts around every snapshot (see the plan's "Snapshot and rollback"
# section for why: switch-to-configuration only restarts units whose
# closure changed, so stopping this target explicitly before a switch is
# what guarantees everything comes back afterwards).
#
# Individual app modules put themselves under this target with
# `wantedBy = lib.mkForce [ "ferrum-apps.target" ]; partOf = [ "ferrum-apps.target" ];`
# so they are not also pulled in by multi-user.target directly, and so
# `systemctl stop ferrum-apps.target` genuinely stops them (partOf
# propagates stop/restart from the target down).
#
# The target's own ConditionPathExists below does NOT, by itself, stop app
# units from starting -- verified against real systemd
# (tests/state-restore-interlock.nix): WantedBy=/Wants= start-propagation
# from a target runs as an independent job in the same transaction and does
# not check the target's own condition result, so a unit merely WantedBy
# this target starts regardless of whether the target itself was skipped.
# Every app service must therefore carry the SAME
# `unitConfig.ConditionPathExists` itself (see modules/apps/sonarr/service.nix
# for the pattern) -- the condition here on the target is kept anyway so
# `systemctl is-active ferrum-apps.target` honestly reflects whether apps
# were cleared to run, but it is not what actually holds them down.
{ ... }:
{
  systemd.targets.ferrum-apps = {
    description = "All ferrum-managed applications";
    wantedBy = [ "multi-user.target" ];
    after = [ "ferrum-state-restore.service" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
  };
}
