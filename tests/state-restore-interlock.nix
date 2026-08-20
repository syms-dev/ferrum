# tests/state-restore-interlock.nix
#
# Proves the actual mechanism behind the fail-closed interlock, not just
# that the failure marker gets written. crates/ferrum-apply/src/
# restore_state.rs's unit tests already prove the marker is written under
# various failure conditions, and tests/rollback.nix's happy path asserts
# the marker is ABSENT after a successful restore -- but nothing anywhere
# proves that systemd actually holds ferrum-managed apps down when the
# marker IS present.
#
# This test caught a real bug on its first run: putting
# `ConditionPathExists` only on ferrum-apps.target (modules/core/
# generations.nix) does NOT stop app units from starting. WantedBy=/Wants=
# start-propagation from a target runs each dependent as an independent job
# in the same transaction and does not check the target's own condition
# result -- so a unit merely WantedBy the target starts regardless of
# whether the target itself was skipped as "unmet condition". The fix: every
# app service must carry the SAME `unitConfig.ConditionPathExists` itself
# (see modules/apps/sonarr/service.nix). This also depends on every app
# module using `wantedBy = lib.mkForce [ "ferrum-apps.target" ]` rather than
# being independently pulled in by multi-user.target -- a future app module
# that forgets either of these two things would silently bypass the
# interlock with nothing to catch it.
#
# Deliberately standalone from tests/rollback.nix (a long, already-passing,
# carefully-debugged 13-subtest integration test) -- this property needs
# neither a reboot nor the full rollback machinery to demonstrate: a plain
# `touch` of the marker path is enough, since what's under test is systemd's
# own condition-check behavior against generations.nix's unit definition,
# not ferrum-apply or btrfs at all.
{ pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "ferrum-state-restore-interlock";

  nodes.machine = { ... }: {
    imports = [ ../modules/core/generations.nix ];

    # A minimal stand-in for a real ferrum app service, wired under
    # ferrum-apps.target exactly the way a real app module is via
    # modules/apps/sonarr/service.nix's pattern: wantedBy + partOf the
    # target, AND its own ConditionPathExists (see this file's header for
    # why the target's condition alone doesn't gate it). No HTTP server or
    # real ferrum-testapp binary is needed here -- the property under test
    # is purely "does this unit start or not," which a trivial long-running
    # unit demonstrates just as well.
    systemd.services.ferrum-testapp = {
      description = "ferrum-testapp (interlock test fixture)";
      wantedBy = [ "ferrum-apps.target" ];
      partOf = [ "ferrum-apps.target" ];
      after = [ "ferrum-apps.target" ];
      unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
      serviceConfig = {
        Type = "simple";
        ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
      };
    };
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    with subtest(
        "negative control: with no marker present, starting ferrum-apps.target "
        "brings the app up normally -- proves the test's own setup is sound "
        "before testing the positive case below"
    ):
        machine.succeed("systemctl start ferrum-apps.target")
        machine.succeed("systemctl is-active --quiet ferrum-testapp")

    with subtest("stop the app and the target cleanly"):
        machine.succeed("systemctl stop ferrum-testapp ferrum-apps.target")

    with subtest(
        "with the failure marker present, the app's own ConditionPathExists "
        "blocks it from starting even though it's still being pulled in via "
        "ferrum-apps.target's WantedBy=. ConditionPathExists is evaluated at "
        "job-start time, so this issues a fresh start after having stopped "
        "the target above -- starting an already-active target would be a "
        "no-op that never re-evaluates the condition. A condition failure is "
        "not a job failure in systemd, so `systemctl start` itself still "
        "exits 0 here; what must fail is the app actually becoming active"
    ):
        machine.succeed("mkdir -p /var/lib/ferrum")
        machine.succeed("touch /var/lib/ferrum/state-restore-failed")
        machine.succeed("systemctl start ferrum-apps.target")
        machine.fail("systemctl is-active --quiet ferrum-testapp")

    with subtest(
        "clearing the marker resets the interlock cleanly -- it is sticky "
        "only because the marker file persists across reboots (see Fix 1), "
        "not because of anything sticky at the systemd level itself"
    ):
        machine.succeed("rm /var/lib/ferrum/state-restore-failed")
        machine.succeed("systemctl start ferrum-apps.target")
        machine.succeed("systemctl is-active --quiet ferrum-testapp")
  '';
}
