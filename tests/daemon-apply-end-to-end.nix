# tests/daemon-apply-end-to-end.nix
#
# The one thing nothing else in this repo proved: a real `{"kind":"apply"}`
# job, submitted over the real `POST /api/jobs` HTTP API, really performs a
# real NixOS generation switch.
#
# The two tests this sits between each prove half of that and disclose the
# other half as a gap:
#
#   * tests/daemon-end-to-end.nix drives the whole HTTP -> polkit/D-Bus ->
#     privileged-CLI chain for real, but only ever with `{"kind":"preflight"}`
#     -- a read-only check. Its interlock-race scenario simulates a
#     long-running job with a `/run` drop-in that replaces ExecStart with
#     `sleep 300`, which is a real systemd unit in a real `activating` state
#     but is not a real apply.
#   * tests/apply-generation-switch.nix proves a real switch between two
#     genuinely different closures, but performs it by hand (`nix-env --set`
#     + `switch-to-configuration switch` typed into the guest), with no
#     ferrumd, no D-Bus, and no `ferrum-apply apply` involved.
#
# So the HTTP path was proven only for a job that changes nothing, and the
# switch was proven only for a path that ferrumd never takes. This file
# joins them: the request enters as real HTTP, crosses the real polkit/D-Bus
# boundary, runs the real `ferrum-apply run-request` as root, and comes out
# the other end as a real, asserted change to /run/current-system.
#
# HOW THE SECOND CLOSURE GETS BUILT, AND WHY IT IS BUILT THIS WAY: exactly
# the mechanism tests/apply-generation-switch.nix already established, reused
# rather than reinvented. `afterToplevel` is a second, complete NixOS closure
# produced by calling pkgs.testers.runNixOSTest a SECOND time with the SAME
# node config, differing only by a marker file in /etc, and injected into the
# VM's store via `virtualisation.additionalPaths`. Building both closures
# through the same runNixOSTest node config is load-bearing, not incidental:
# that file's header records what happens otherwise (a closure built via
# eval-config.nix lacks backdoor.service, so switching to it severs the test
# driver's only channel into the guest and hangs every later command).
#
# WHAT MAKES THE APPLY ITSELF WORK OFFLINE. `ferrum-apply apply`'s first real
# step is `nix build --impure --no-link --print-out-paths $FERRUM_FLAKE_REF`
# (crates/ferrum-apply/src/apply.rs). FERRUM_FLAKE_REF is a real, existing
# environment variable of the real CLI (crates/ferrum-apply/src/main.rs's
# run_apply), defaulting to /etc/ferrum#nixosConfigurations.default...; this
# test points it at a real, tiny flake provisioned into the guest whose
# `nixosConfigurations.default.config.system.build.toplevel` is
# `builtins.storePath` of the already-injected `afterToplevel`. That keeps
# the shape of the real flake reference (a real flake, a real
# `nix build`, the real attribute path a real host uses) while needing no
# network and no nixpkgs evaluation inside a 4GiB VM. `builtins.storePath`
# is refused under pure evaluation -- which is fine and is precisely why
# apply.rs passes `--impure` for its own unrelated (and documented) reason.
#
# EVERY GENERATION-A-ONLY ADDITION IS DELIBERATELY /etc-ONLY, NEVER A UNIT
# CHANGE. The flake fixture and `virtualisation.additionalPaths` exist only
# on the running VM's own closure, not on `afterToplevel`. That asymmetry is
# safe only because none of it alters a systemd unit FRAGMENT: the
# FERRUM_FLAKE_REF environment entry is set in the SHARED node config with a
# constant path (so `ferrum-apply@.service` is byte-identical in both
# closures), and the fixture itself is a tmpfiles rule, which renders into
# /etc/tmpfiles.d rather than into a unit. This matters enormously: the unit
# executing the switch IS `ferrum-apply@<uuid>.service`, and a
# switch-to-configuration that saw that fragment change would stop or restart
# the very process performing the switch. The same reasoning protects
# ferrumd.service, which has to stay up to serve the SSE stream across its
# own system's generation switch.
{ pkgs, sopsNix, ... }:
let
  initialSettings = pkgs.writeText "ferrum-settings.json" (builtins.toJSON {
    schemaVersion = 1;
    secrets = { };
  });

  # The one constant both closures agree on -- see the header's note on why
  # this must NOT be interpolated from `afterToplevel`.
  testFlakeDir = "/var/lib/ferrum-test-flake";
  testFlakeRef = "${testFlakeDir}#nixosConfigurations.default.config.system.build.toplevel";

  mkNode = markerValue: { config, lib, pkgs, utils, ... }: {
    imports = [ ../modules sopsNix.nixosModules.sops ];

    # This test's entire point of comparison, and the cheapest possible
    # difference between two whole NixOS closures.
    environment.etc."ferrum-test-marker".text = markerValue;

    virtualisation.emptyDiskImages = [ 4096 ];
    # Mirrors tests/apply-generation-switch.nix, which proved a real
    # switch-to-configuration works in this exact shape. A real switch runs
    # the real bootloader installation step, and a VM with no bootloader at
    # all is a needlessly different situation from the real host this is
    # meant to be evidence about.
    virtualisation.useBootLoader = true;
    virtualisation.useEFIBoot = true;
    boot.loader.systemd-boot.enable = true;
    boot.loader.efi.canTouchEfiVariables = true;

    # `nix build` is the real first step of a real apply, and it is part of
    # the new CLI, which nix still gates behind these experimental features.
    # Enabled here explicitly rather than assumed: nothing in modules/ turns
    # them on today (see this test's companion note in the follow-up report
    # -- a real deployed ferrum host needs them for `ferrum-apply apply` to
    # get past its first step at all, which is a real, separate gap this
    # test happens to surface rather than one it invents).
    nix.settings.experimental-features = [ "nix-command" "flakes" ];

    ferrum.daemon = {
      enable = true;
      port = 7788;
      listenAddress = "127.0.0.1";
    };
    ferrum.secretsDir = "/etc/ferrum/secrets";
    ferrum.storage = {
      stateDir = "/var/lib/ferrum/state";
      snapshotDir = "/var/lib/ferrum/snapshots";
      # The second disk is 4GiB; the real 10GiB default would make the
      # preflight INSIDE the real apply fail on free space alone, so the
      # test would prove only that apply refuses to run.
      minFreeGiB = 1;
    };

    # The real flake reference the real apply will build. A constant string
    # in BOTH closures -- see the header.
    systemd.services."ferrum-apply@".environment.FERRUM_FLAKE_REF = testFlakeRef;

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

    # Identical fixture to tests/apply-generation-switch.nix's and
    # tests/daemon-end-to-end.nix's -- a real apply really snapshots @state
    # into @snapshots with real btrfs, so both really have to be real
    # subvolumes.
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

    # Exactly what tests/daemon-end-to-end.nix provisions, and what a real
    # host gets from nixos-anywhere's initial setup: a real, WRITABLE
    # settings.json (not an environment.etc symlink into the read-only
    # store) plus a real secrets directory. ferrumd's startup writability
    # self-check (crates/ferrumd/src/main.rs) refuses to start without both,
    # so a wrong mode here fails this test loudly rather than subtly.
    systemd.tmpfiles.rules = [
      "d /etc/ferrum 0755 root root - -"
      "C /etc/ferrum/settings.json 0664 root ferrum - ${initialSettings}"
      "z /etc/ferrum/settings.json 0664 root ferrum - -"
      "d /etc/ferrum/secrets 0750 ferrum ferrum - -"
    ];

    services.openssh.enable = true;
    environment.systemPackages = [ pkgs.curl ];
    system.stateVersion = "25.11";
  };

  # Never actually run -- only this node's evaluated toplevel is used. See
  # tests/apply-generation-switch.nix's header for why the throwaway test
  # wrapper is the right way to get a second closure here.
  afterTest = pkgs.testers.runNixOSTest {
    name = "daemon-apply-end-to-end-after";
    node.pkgsReadOnly = false;
    nodes.machine = mkNode "generation-B";
    testScript = ""; # never run -- only .nodes.machine.system.build.toplevel is used
  };
  afterToplevel = afterTest.nodes.machine.system.build.toplevel;

  # The real flake the real `nix build` inside the real apply evaluates.
  # Deliberately a real flake with a real attribute path rather than a bare
  # store path handed to `nix build`: the real deployed default is
  # `/etc/ferrum#nixosConfigurations.default.config.system.build.toplevel`,
  # and keeping that exact shape means this test exercises the real
  # flake-reference handling rather than a simpler substitute.
  testFlake = pkgs.writeText "flake.nix" ''
    {
      description = "Test fixture: a prebuilt second NixOS closure, offline";
      outputs = { self }: {
        nixosConfigurations.default.config.system.build.toplevel =
          builtins.storePath "${afterToplevel}";
      };
    }
  '';
in
pkgs.testers.runNixOSTest {
  name = "daemon-apply-end-to-end";

  node.pkgsReadOnly = false;

  nodes.machine = {
    imports = [ (mkNode "generation-A") ];

    # Generation A only, and /etc-only by construction -- see the header.
    virtualisation.additionalPaths = [ afterToplevel ];
    systemd.tmpfiles.rules = [
      "d ${testFlakeDir} 0755 root root - -"
      "C ${testFlakeDir}/flake.nix 0644 root root - ${testFlake}"
    ];
  };

  testScript = ''
    import json

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("polkit.service")
    machine.wait_for_unit("ferrumd.service")
    machine.wait_for_open_port(7788)

    print("=== the machine really boots on generation A ===")
    machine.succeed("grep -q generation-A /etc/ferrum-test-marker")
    toplevel_a = machine.succeed("readlink /run/current-system").strip()
    profile_a = machine.succeed("readlink /nix/var/nix/profiles/system").strip()
    print(f"generation A toplevel: {toplevel_a}")
    print(f"generation A profile:  {profile_a}")
    assert toplevel_a != "${afterToplevel}", (
        "the VM must NOT already be running the closure this test is about to "
        "switch it to -- otherwise apply's own 'already on the target closure' "
        "shortcut would make this test prove nothing"
    )

    print("=== the second closure really is present in the guest store, offline ===")
    machine.succeed("test -e ${afterToplevel}/bin/switch-to-configuration")

    print("=== real login with the real bootstrap password ===")
    password = machine.succeed("cat /var/lib/ferrum/daemon/ferrumd-setup-password").strip()
    login_response = machine.succeed(
        f"curl -s -c /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/login "
        f"-H 'Content-Type: application/json' "
        f"-d '{{\"username\":\"admin\",\"password\":\"{password}\"}}'"
    )
    csrf = json.loads(login_response)["csrf_token"]
    csrf_header = f"-H 'X-CSRF-Token: {csrf}'"
    print("PASS: real login")

    print("=== THE request this test exists for: a real apply over the real HTTP API ===")
    # Nothing about this call is special-cased anywhere: it is the same
    # POST /api/jobs endpoint, behind the same session + CSRF gate, that
    # tests/daemon-end-to-end.nix drives with a preflight. The only
    # difference is the kind -- and that kind really rebuilds and really
    # switches the running system.
    job_response = machine.succeed(
        f"curl -s -f -b /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/jobs "
        f"-H 'Content-Type: application/json' {csrf_header} -d '{{\"kind\":\"apply\"}}'"
    )
    print(f"job response: {job_response}")
    job_id = json.loads(job_response)["id"]
    assert job_id, f"the apply job must be accepted with a real id: {job_response}"
    print(f"PASS: the real apply job was accepted as {job_id}")

    print("=== the real job really reaches a real terminal 'complete' line ===")
    # A real apply does real work (a real nix build, a real preflight, a real
    # btrfs snapshot, a real switch-to-configuration, a real health check),
    # so this is generous where the preflight test could be tight.
    machine.wait_until_succeeds(
        f"grep -q '\"event\":\"complete\"' /var/lib/ferrum/jobs/{job_id}.jsonl",
        timeout=600,
    )
    progress = machine.succeed(f"cat /var/lib/ferrum/jobs/{job_id}.jsonl")
    print(f"real apply progress log:\n{progress}")

    # The real intermediate steps, which ONLY a real apply writes -- a
    # preflight-shaped job could never produce these lines. This is what
    # separates "a job ran" from "a real apply ran".
    for step in ("build", "preflight", "stop-apps", "snapshot", "set-profile", "switch", "start-apps", "health-check"):
        assert f'"event":"{step}"' in progress, (
            f"the real apply must have really performed the '{step}' step: {progress}"
        )

    # And it really SUCCEEDED, not merely really ran. apply.rs's own
    # classify() writes "succeeded" only for switch-to-configuration exit 0
    # AND every managed unit active afterwards; "degraded" or "failed" would
    # both still produce a terminal line.
    terminal = [
        json.loads(line)
        for line in progress.strip().splitlines()
        if line.strip() and json.loads(line).get("event") == "complete"
    ]
    assert len(terminal) == 1, f"exactly one terminal line, got {len(terminal)}: {progress}"
    detail = terminal[0]["detail"]
    print(f"terminal line detail: {detail!r}")
    assert detail.startswith("succeeded"), (
        f"the real apply must have really succeeded, got: {detail!r}"
    )
    print("PASS: the real apply job completed with a real success")

    print("=== ...and it really was root, via the real privileged unit ===")
    unit_result = machine.succeed(
        f"systemctl show ferrum-apply@{job_id}.service -p Result --value"
    ).strip()
    assert unit_result == "success", f"the real privileged unit must have succeeded, got: {unit_result}"

    print("=== THE assertion this test exists for: the system really switched ===")
    # Byte-for-byte against the exact toplevel the apply was pointed at --
    # the same assertion style tests/apply-generation-switch.nix uses for its
    # own hand-driven switch. "Some generation changed" would also pass for a
    # switch to the wrong thing.
    toplevel_now = machine.succeed("readlink /run/current-system").strip()
    print(f"/run/current-system now: {toplevel_now}")
    assert toplevel_now == "${afterToplevel}", (
        f"the running system must be the closure the apply built: expected "
        f"${afterToplevel}, got {toplevel_now}"
    )
    assert toplevel_now != toplevel_a, "the running system must really have CHANGED"

    # The marker file is the human-readable version of the same fact: the
    # guest's /etc genuinely came from the other closure.
    machine.succeed("grep -q generation-B /etc/ferrum-test-marker")
    machine.fail("grep -q generation-A /etc/ferrum-test-marker")

    # And the system PROFILE really advanced too -- `nix-env --set` really
    # ran, so this survives a reboot rather than being a live-only switch.
    profile_now = machine.succeed("readlink /nix/var/nix/profiles/system").strip()
    print(f"system profile now: {profile_now}")
    assert profile_now != profile_a, (
        f"the system profile must really have advanced a generation: still {profile_now}"
    )
    # `readlink -f`, not `readlink`: /nix/var/nix/profiles/system is a
    # RELATIVE symlink (it reads back as bare "system-2-link"), so a plain
    # readlink of that value resolves against the wrong directory. Found by
    # actually running this.
    # Not an f-string: Nix interpolates ${afterToplevel} before Python ever
    # sees this line, so an `f` prefix here leaves a placeholder-free
    # f-string, which the test driver's own linter rejects outright.
    machine.succeed(
        "test \"$(readlink -f /nix/var/nix/profiles/system)\" = \"${afterToplevel}\""
    )
    print("PASS: a real generation switch really happened, driven entirely by a real HTTP request")

    print("=== the real apply really did its real state bookkeeping ===")
    # A real apply snapshots @state and writes a journal entry for the
    # generation it is leaving -- the thing that makes a later rollback able
    # to revert state as well as closure. A switch that skipped this would
    # still pass every assertion above.
    snapshots = machine.succeed("ls /var/lib/ferrum/snapshots").split()
    print(f"snapshots after the real apply: {snapshots}")
    assert snapshots, "the real apply must have really taken a real @state snapshot"
    journal_entries = machine.succeed("ls /var/lib/ferrum/journal").split()
    print(f"journal entries after the real apply: {journal_entries}")
    assert journal_entries, "the real apply must have really written a real journal entry"
    entry = json.loads(
        machine.succeed(f"cat /var/lib/ferrum/journal/{journal_entries[0]}")
    )
    print(f"journal entry: {entry}")
    assert entry["toplevel"] == toplevel_a, (
        f"the journal must record the generation being LEFT ({toplevel_a}), got {entry}"
    )
    assert entry["snapshot"] in snapshots, entry
    print("PASS: the real apply really snapshotted state and really journalled it")

    print("=== ferrumd really survived the switch and really serves the log back ===")
    # ferrumd.service is byte-identical across the two closures, so the real
    # switch must NOT have restarted it -- and the real SSE endpoint must
    # still replay this real job's real progress, terminal line included.
    machine.succeed("systemctl is-active ferrumd.service")
    stream = machine.succeed(
        f"curl -s -N --max-time 60 -b /tmp/cookies.txt "
        f"http://127.0.0.1:7788/api/jobs/{job_id}/stream"
    )
    print(f"real SSE stream of the real apply:\n{stream}")
    assert "event: progress" in stream, stream
    assert "\"event\":\"switch\"" in stream, (
        f"the operator's own stream must carry the real switch step: {stream}"
    )
    assert "\"event\":\"complete\"" in stream, stream
    print("PASS: the real SSE stream really carried the real apply through to completion")

    print("=== the interlock really cleared, and the spent request file is really gone ===")
    machine.wait_until_succeeds(f"test ! -e /run/ferrum/requests/{job_id}.json", timeout=60)
    # A real second job is really admitted afterwards -- a real apply must
    # not wedge the daemon. Kept cheap on purpose (a preflight): the
    # expensive thing being proven here is that the interlock CLEARED, not a
    # second switch.
    machine.wait_until_succeeds(
        f"curl -s -o /dev/null -w '%{{http_code}}' -b /tmp/cookies.txt "
        f"-X POST http://127.0.0.1:7788/api/jobs {csrf_header} "
        f"-H 'Content-Type: application/json' -d '{{\"kind\":\"preflight\"}}' | grep -q 200",
        timeout=120,
    )
    print("PASS: a real apply really released the real single-job interlock")

    print("=== a real second apply is correctly a real no-op, not a second switch ===")
    # apply.rs's own "already on the target closure" shortcut: the real
    # health-check-only path. Worth proving because it is the difference
    # between an idempotent apply and one that churns a generation every
    # time an operator presses the button.
    # Retried by hand rather than via wait_until_succeeds on a curl pipeline:
    # a 409 creates nothing, but a retry loop that discarded a 200 response
    # body would leave a real apply running with no id to follow.
    import time
    second_id = None
    for _ in range(60):
        code = machine.succeed(
            f"curl -s -o /tmp/job2.json -w '%{{http_code}}' -b /tmp/cookies.txt "
            f"-X POST http://127.0.0.1:7788/api/jobs {csrf_header} "
            f"-H 'Content-Type: application/json' -d '{{\"kind\":\"apply\"}}'"
        ).strip()
        if code == "200":
            second_id = json.loads(machine.succeed("cat /tmp/job2.json"))["id"]
            break
        time.sleep(2)
    assert second_id, "the daemon never admitted the second apply job"
    machine.wait_until_succeeds(
        f"grep -q '\"event\":\"complete\"' /var/lib/ferrum/jobs/{second_id}.jsonl",
        timeout=600,
    )
    second_progress = machine.succeed(f"cat /var/lib/ferrum/jobs/{second_id}.jsonl")
    print(f"second apply progress:\n{second_progress}")
    assert '"event":"health-check"' in second_progress, second_progress
    assert '"event":"switch"' not in second_progress, (
        f"a second apply against the same closure must NOT switch again: {second_progress}"
    )
    assert machine.succeed("readlink /run/current-system").strip() == "${afterToplevel}"
    assert machine.succeed("readlink /nix/var/nix/profiles/system").strip() == profile_now, (
        "an idempotent apply must not have advanced the system profile again"
    )
    print("PASS: a real repeat apply really was a real no-op")
  '';
}
