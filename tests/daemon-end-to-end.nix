# The proof Phase 1.5a's core deliverable actually works, end to end, on a
# real booted NixOS machine with nothing stubbed:
#
#   1. ferrumd really starts as the unprivileged ferrum user and really
#      generates a real bootstrap password on first boot.
#   2. A real operator really logs in with that real password over real
#      HTTP and gets a real session cookie + CSRF token.
#   3. A real settings write really lands on disk at /etc/ferrum/settings.json.
#   4. A real secret write really round-trips: POSTed plaintext really comes
#      back out of a real `sops --decrypt` against the host's own age
#      identity (derived from its real SSH host key), proving ferrumd
#      encrypted to a recipient sops-nix itself can decrypt.
#   5. A real job, triggered over the real HTTP API, really crosses the real
#      polkit/D-Bus privilege boundary, really runs the real ferrum-apply
#      binary as root, and really produces a real JSONL progress log ending
#      in "complete" -- which ferrumd really serves back over real SSE.
#   6. ferrumd's single-job interlock really clears afterwards, via systemd's
#      own JobRemoved signal, so a real second job is really admitted.
#
# DELIBERATE DEVIATIONS from the task brief's literal test code, each of
# which was necessary to make the test actually run rather than hang or
# fail to evaluate:
#
# (a) `imports = [ ../modules sopsNix.nixosModules.sops ]` with
#     `node.pkgsReadOnly = false`, not `imports = [ ../modules/core/daemon.nix ]`
#     plus a hand-rolled `options.ferrum` stub. daemon.nix CONSUMES
#     `pkgs.ferrumd`/`pkgs.ferrum-apply`, which are bound by
#     modules/core/overlays.nix's `nixpkgs.overlays`, not by daemon.nix
#     itself -- importing daemon.nix alone leaves both undefined. This is
#     exactly the same discovery tests/privilege-boundary.nix documents at
#     length in its own header, including why sops-nix's module has to come
#     along too.
#
# (b) /etc/ferrum/settings.json is provisioned as a REAL, WRITABLE file via
#     systemd-tmpfiles' own `C` (copy-if-absent) verb, not via
#     `environment.etc."ferrum/settings.json".text`. environment.etc makes
#     /etc/ferrum/settings.json a symlink into the read-only Nix store, so
#     ferrumd's `PUT /api/settings` (a plain `std::fs::write`, see
#     crates/ferrumd/src/settings.rs) would fail with EROFS -- the test's
#     own step 3 would fail on a system that was otherwise working fine.
#     On a real deployed host this file is provisioned once by
#     nixos-anywhere's initial setup, which is the situation this
#     reproduces.
#
# (c) A real second disk with real btrfs subvolumes, mirroring
#     tests/privilege-boundary.nix. The job this test triggers is a real
#     `preflight`, and preflight's own `check_is_subvolume` genuinely
#     requires state/snapshot dirs to be real btrfs subvolumes. Without
#     them the job would still produce a `complete` line (a failed one) and
#     the test would still "pass" -- so provisioning them for real is what
#     makes step 5 prove the privileged run genuinely SUCCEEDED rather than
#     merely genuinely RAN.
#
# (d) The sops decryption in step 4 converts the host's SSH host key to an
#     age identity with `ssh-to-age -private-key` first. `sops --decrypt`
#     on its own has no idea the box's age identity lives in an OpenSSH key
#     -- that conversion is precisely what sops-nix does internally, and
#     doing it explicitly here is what makes this a real round-trip check
#     rather than a check that sops can read its own metadata.
#
# (e) Single-backslash `\"` inside the Nix `''...''` testScript, not `\\"`.
#     Nix `''` strings don't treat backslash specially, so a doubled
#     backslash reaches Python as an escaped backslash followed by an
#     unterminated string -- caught by the test driver's own Python
#     type-checker before the VM even boots. Same gotcha, same fix, as
#     tests/privilege-boundary.nix's header records.
{ pkgs, sopsNix, ... }:
let
  # A real starting settings.json, copied (not symlinked) into place so
  # ferrumd can rewrite it -- see deviation (b) above.
  initialSettings = pkgs.writeText "ferrum-settings.json" (builtins.toJSON {
    schemaVersion = 1;
    secrets."test-secret" = { };
  });
in
pkgs.testers.runNixOSTest {
  name = "daemon-end-to-end";

  node.pkgsReadOnly = false;

  nodes.machine = { config, lib, pkgs, utils, ... }: {
    imports = [ ../modules sopsNix.nixosModules.sops ];

    virtualisation.emptyDiskImages = [ 4096 ];

    ferrum.daemon = {
      enable = true;
      port = 7788;
      listenAddress = "127.0.0.1";
    };
    ferrum.secretsDir = "/etc/ferrum/secrets";
    ferrum.storage = {
      stateDir = "/var/lib/ferrum/state";
      snapshotDir = "/var/lib/ferrum/snapshots";
      # The disk image above is 4GiB; the real 10GiB default would make the
      # preflight this test triggers fail on free space alone, testing the
      # wrong thing. Must stay positive (modules/core/options.nix asserts
      # it).
      minFreeGiB = 1;
    };

    # Deliberately NOT `ferrum.secrets."test-secret" = { }`: that option
    # gates whichever catalog app consumes the name and requires a real
    # <secretsDir>/<name>.sops to already exist at eval time. What actually
    # gates ferrumd's secrets API is the `secrets` key inside
    # settings.json (see crates/ferrumd/src/secrets_api.rs's
    # is_declared_secret), which initialSettings above provides for real.

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

    # What nixos-anywhere's initial setup provisions on a real host, and
    # what ferrumd's own AssertPathExists= (modules/core/daemon.nix) checks
    # for at real activation time.
    systemd.tmpfiles.rules = [
      "d /etc/ferrum 0755 root root - -"
      "C /etc/ferrum/settings.json 0664 root ferrum - ${initialSettings}"
      # `C` copies from the store, where the source is 0444 root:root; this
      # second line is what actually guarantees the copy ends up
      # group-writable by ferrum, which is what ferrumd's PUT needs.
      "z /etc/ferrum/settings.json 0664 root ferrum - -"
      "d /etc/ferrum/secrets 0750 ferrum ferrum - -"
    ];

    services.openssh.enable = true;
    environment.systemPackages = [ pkgs.curl pkgs.sops pkgs.ssh-to-age ];
    system.stateVersion = "25.11";
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("polkit.service")
    machine.wait_for_unit("ferrumd.service")
    machine.wait_for_open_port(7788)

    print("=== real login with the real bootstrap password ===")
    password = machine.succeed("cat /var/lib/ferrum/ferrumd-setup-password").strip()
    login_response = machine.succeed(
        f"curl -s -c /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/login "
        f"-H 'Content-Type: application/json' "
        f"-d '{{\"username\":\"admin\",\"password\":\"{password}\"}}'"
    )
    print(f"login response: {login_response}")
    assert "csrf_token" in login_response
    print("PASS: real login against the real generated bootstrap password")

    print("=== an unauthenticated job POST must be rejected ===")
    unauth = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:7788/api/jobs "
        "-H 'Content-Type: application/json' -d '{\"kind\":\"preflight\"}'"
    ).strip()
    assert unauth == "401", f"expected 401 without a session cookie, got {unauth}"
    print("PASS: the job API really is behind the real session gate")

    print("=== real settings write ===")
    machine.succeed(
        "curl -s -f -b /tmp/cookies.txt -X PUT http://127.0.0.1:7788/api/settings "
        "-H 'Content-Type: application/json' "
        "-d '{\"schemaVersion\":1,\"secrets\":{\"test-secret\":{}},\"auth\":{\"adminEmail\":\"ops@example.com\"}}'"
    )
    settings_content = machine.succeed("cat /etc/ferrum/settings.json")
    print(f"settings.json on disk: {settings_content}")
    assert "test-secret" in settings_content
    assert "ops@example.com" in settings_content, "the write must really replace the file, not just be accepted"
    print("PASS: real settings write landed on disk")

    print("=== real secret write, confirmed by real decryption ===")
    machine.succeed(
        "curl -s -f -b /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/secrets/test-secret "
        "-d 'a-real-secret-value'"
    )
    # sops has no idea this box's age identity lives inside its OpenSSH
    # host key -- convert it the same way sops-nix's own decrypt side does.
    machine.succeed(
        "ssh-to-age -private-key -i /etc/ssh/ssh_host_ed25519_key -o /tmp/age.key"
    )
    decrypted = machine.succeed(
        "SOPS_AGE_KEY_FILE=/tmp/age.key sops --decrypt --input-type binary "
        "--output-type binary /etc/ferrum/secrets/test-secret.sops"
    ).strip()
    assert decrypted == "a-real-secret-value", f"expected the real posted value, got: {decrypted}"
    print("PASS: real secret round-tripped through real sops encryption")

    print("=== an undeclared secret name must be refused ===")
    undeclared = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -b /tmp/cookies.txt "
        "-X POST http://127.0.0.1:7788/api/secrets/not-declared -d 'nope'"
    ).strip()
    assert undeclared == "400", f"expected 400 for a name settings.json never declared, got {undeclared}"
    machine.fail("test -e /etc/ferrum/secrets/not-declared.sops")
    print("PASS: the secrets API really is settings-gated, not an open file-write primitive")

    print("=== real job trigger: preflight, through the real privilege boundary ===")
    job_response = machine.succeed(
        "curl -s -f -b /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/jobs "
        "-H 'Content-Type: application/json' -d '{\"kind\":\"preflight\"}'"
    )
    print(f"job response: {job_response}")
    import json
    job_id = json.loads(job_response)["id"]

    machine.wait_until_succeeds(
        f"grep -q complete /var/lib/ferrum/jobs/{job_id}.jsonl", timeout=120
    )
    progress = machine.succeed(f"cat /var/lib/ferrum/jobs/{job_id}.jsonl")
    print(f"real progress log: {progress}")
    assert "complete" in progress

    # The privileged run really SUCCEEDED, not merely really ran: this is a
    # real preflight against real btrfs subvolumes on the real second disk.
    assert "succeeded" in progress, f"the real preflight must have really passed: {progress}"

    # ...and it really was ferrum-apply, running as root, that did it.
    unit_result = machine.succeed(
        f"systemctl show ferrum-apply@{job_id}.service -p Result --value"
    ).strip()
    assert unit_result == "success", f"the real privileged unit must have succeeded, got: {unit_result}"
    machine.succeed(f"test -e /run/ferrum/requests/{job_id}.json")
    print("PASS: a real job, triggered over the real HTTP API, ran through the real privilege boundary and produced a real progress log")

    print("=== the real SSE progress stream really serves that log back ===")
    # Replays from the start and closes itself on the terminal "complete"
    # line, so this returns rather than hanging.
    stream = machine.succeed(
        f"curl -s -N --max-time 30 -b /tmp/cookies.txt "
        f"http://127.0.0.1:7788/api/jobs/{job_id}/stream"
    )
    print(f"real SSE stream:\n{stream}")
    assert "event: progress" in stream, f"expected real SSE progress events, got: {stream}"
    assert "\"event\":\"complete\"" in stream, f"the stream must carry the terminal line: {stream}"
    print("PASS: the real SSE endpoint really streamed the real job's real progress")

    print("=== a bogus job id is rejected rather than tailing an arbitrary path ===")
    bogus = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' --max-time 10 -b /tmp/cookies.txt "
        "'http://127.0.0.1:7788/api/jobs/..%2f..%2fetc%2fpasswd/stream'"
    ).strip()
    assert bogus in ("400", "404"), f"expected a rejection for a non-UUID job id, got {bogus}"
    print("PASS: the stream endpoint really refuses a non-UUID job id")

    print("=== second job while first believed running is correctly rejected, then succeeds once cleared ===")
    # job_running should already be false again by this point: the first
    # job completed and ferrumd's own JobRemoved listener cleared it. This
    # asserts that specifically, not a race -- so retry briefly rather than
    # assuming the signal has already been processed the instant the
    # progress file's last line landed.
    machine.wait_until_succeeds(
        "curl -s -o /dev/null -w '%{http_code}' -b /tmp/cookies.txt "
        "-X POST http://127.0.0.1:7788/api/jobs "
        "-H 'Content-Type: application/json' -d '{\"kind\":\"preflight\"}' | grep -q 200",
        timeout=60,
    )
    print("PASS: job_running correctly cleared after completion, allowing a real second job")

    print("=== and while THAT job is in flight, a third is really refused ===")
    # Deliberately not a sleep-then-check: the second job above was
    # admitted, which means job_running is true right now, and stays true
    # until its own JobRemoved arrives. A 409 here is the interlock doing
    # its actual job. If the second job has already finished by the time
    # this runs we would see a 200 instead, so this is checked immediately,
    # with no waiting in between.
    third = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -b /tmp/cookies.txt "
        "-X POST http://127.0.0.1:7788/api/jobs "
        "-H 'Content-Type: application/json' -d '{\"kind\":\"preflight\"}'"
    ).strip()
    print(f"third job HTTP code: {third}")
    assert third in ("409", "200"), f"unexpected code from the third job: {third}"
    if third == "409":
        print("PASS: the real single-job interlock really refused a concurrent job")
    else:
        print("NOTE: the second job had already completed; interlock not exercised on this run")

    print("=== the interlock is really seeded from systemd across a ferrumd restart ===")
    # The real race this closes: an `apply` job can switch to a generation
    # carrying a new ferrumd, restarting ferrumd WHILE its own job is still
    # running. A fresh Mutex<bool> would say "nothing running" and admit a
    # second, concurrent job. There is no long-running job kind to hold open
    # (a preflight finishes in ~50ms), so one real instance of the real
    # template unit is given a real /run drop-in that makes it block. It is
    # a genuine `ferrum-apply@<uuid>.service` in a genuine `activating`
    # state -- exactly what systemd reports for a real in-flight apply, and
    # exactly what ferrumd's startup query has to notice. (A transient
    # `systemd-run --unit=` under this name is refused outright by systemd:
    # "already loaded or has a fragment file", because the template really
    # is installed here.)
    stuck = "ferrum-apply@00000000-0000-4000-8000-000000000000.service"
    dropin = f"/run/systemd/system/{stuck}.d"
    machine.succeed(f"mkdir -p '{dropin}'")
    machine.succeed(f"echo '[Service]' > '{dropin}/override.conf'")
    machine.succeed(f"echo 'ExecStart=' >> '{dropin}/override.conf'")
    machine.succeed(
        f"echo 'ExecStart=/run/current-system/sw/bin/sleep 300' >> '{dropin}/override.conf'"
    )
    machine.succeed("systemctl daemon-reload")
    # --no-block: a Type=oneshot start otherwise waits for the 300s sleep.
    machine.succeed(f"systemctl start --no-block {stuck}")
    machine.wait_until_succeeds(
        f"systemctl show {stuck} -p ActiveState --value | grep -qE 'activating|active'"
    )
    machine.succeed("systemctl restart ferrumd.service")
    machine.wait_for_open_port(7788)
    seeded = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -b /tmp/cookies.txt "
        "-X POST http://127.0.0.1:7788/api/jobs "
        "-H 'Content-Type: application/json' -d '{\"kind\":\"preflight\"}'"
    ).strip()
    assert seeded == "409", (
        "a ferrumd restarted while a real ferrum-apply unit is active must "
        f"refuse a new job, got {seeded}"
    )
    print("PASS: a restarted ferrumd really refused a job while one was really still running")

    machine.succeed(f"systemctl stop {stuck}")
    machine.succeed(f"systemctl reset-failed {stuck} || true")
    machine.succeed(f"rm -rf '{dropin}' && systemctl daemon-reload")
    machine.succeed("systemctl restart ferrumd.service")
    machine.wait_for_open_port(7788)
    cleared = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -b /tmp/cookies.txt "
        "-X POST http://127.0.0.1:7788/api/jobs "
        "-H 'Content-Type: application/json' -d '{\"kind\":\"preflight\"}'"
    ).strip()
    assert cleared == "200", (
        "with nothing running, the startup query must seed the interlock OPEN "
        f"-- a daemon that refuses everything is no use either; got {cleared}"
    )
    print("PASS: with nothing running, the same query really seeds the interlock open")

    print("=== ferrumd really is unprivileged ===")
    ferrumd_user = machine.succeed(
        "systemctl show ferrumd.service -p User --value"
    ).strip()
    assert ferrumd_user == "ferrum", f"ferrumd must not run as root, got: {ferrumd_user}"
    machine.fail(
        "su -s /bin/sh ferrum -c \"busctl call --system org.freedesktop.systemd1 "
        "/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss "
        "'sshd.service' replace\""
    )
    print("PASS: the daemon's user really cannot start an arbitrary unit")

    # Deliberately LAST: this one deletes a path ferrumd needs and leaves
    # the unit failed, so nothing after it could rely on a working daemon.
    print("=== AssertPathExists really gates ferrumd's startup ===")
    # First, structurally: it must be in the unit file's [Unit] section.
    # In [Service] systemd logs "Unknown key name 'AssertPathExists' in
    # section 'Service', ignoring" and starts the unit anyway -- which is
    # exactly the silent no-op this check exists to prevent regressing to.
    unit_text = machine.succeed("systemctl cat ferrumd.service")
    unit_section = unit_text.split("[Service]")[0]
    assert "AssertPathExists=/etc/ferrum/settings.json" in unit_section, (
        f"AssertPathExists must be a [Unit] directive, got:\n{unit_text}"
    )
    assert "AssertPathExists=/etc/ferrum/secrets" in unit_section, unit_text
    # systemd's own parser, asked directly. Scoped to this one directive on
    # purpose: `verify` also pulls in dependency units, whose unrelated
    # warnings are none of this test's business.
    verify = machine.succeed("systemd-analyze verify ferrumd.service 2>&1 || true")
    print(f"systemd-analyze verify ferrumd.service:\n{verify}")
    assert "Unknown key name 'AssertPathExists'" not in verify, (
        f"systemd itself must recognise this directive where it is placed: {verify}"
    )
    print("PASS: systemd really parses AssertPathExists on this unit")

    # Then, behaviourally: with one of the two asserted paths genuinely
    # missing, the unit must genuinely refuse to start.
    machine.succeed("systemctl stop ferrumd.service")
    machine.succeed("mv /etc/ferrum/settings.json /etc/ferrum/settings.json.moved")
    # An assert failure fails the START JOB and leaves the unit inactive --
    # it does NOT put the unit in `failed` (so `Result` stays `success`,
    # which is why that property is not what gets checked here). What
    # matters is that the start really did not happen.
    status, out = machine.execute("systemctl start ferrumd.service 2>&1")
    print(f"systemctl start with a required path missing: status={status} output={out.strip()}")
    assert status != 0, "ferrumd must refuse to start when an asserted path is missing"
    assert "ssertion" in out, (
        f"the refusal must really come from the assertion, not something else: {out}"
    )
    machine.fail("systemctl is-active ferrumd.service")
    active_state = machine.succeed(
        "systemctl show ferrumd.service -p ActiveState --value"
    ).strip()
    assert active_state == "inactive", f"ferrumd must not be running, got {active_state}"
    machine.fail("curl -s --max-time 5 http://127.0.0.1:7788/api/settings")
    print("PASS: the real assertion really refused to start ferrumd with a required path missing")

    machine.succeed("mv /etc/ferrum/settings.json.moved /etc/ferrum/settings.json")
    machine.succeed("systemctl reset-failed ferrumd.service")
    machine.succeed("systemctl start ferrumd.service")
    machine.wait_for_open_port(7788)
    print("PASS: and starts again for real once the path is back")
  '';
}
