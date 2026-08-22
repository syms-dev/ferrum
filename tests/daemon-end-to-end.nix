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
# Added by the branch-wide final review of Phase 1.5a, all in the same
# "prove it on a real booted machine" spirit:
#
#   7. The real CSRF gate really refuses a real, session-authenticated
#      mutating request that carries no (or a wrong) X-CSRF-Token header,
#      with a real 403 and no write landing on disk -- and every mutating
#      call in this file really carries the real token the real login
#      handed out.
#   8. /var/lib/ferrum really stays root-owned: the real ferrum user really
#      cannot create or delete `state-restore-failed` or
#      `rollback-intent.json` beside its own state, while really being able
#      to write its own /var/lib/ferrum/daemon subdirectory.
#   9. The spent request file really is deleted once the job's real
#      JobRemoved signal arrives, and systemd really applied every
#      hardening directive on the unit -- with the whole rest of this test
#      having really run underneath them.
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

    print("=== /var/lib/ferrum's own permission model ===")
    # The parent directory is SHARED between root-trusted control files
    # (state-restore-failed, rollback-intent.json, journal/) and ferrumd's
    # own state, so root must keep it: directory write permission is
    # create/delete/rename permission on every name inside, whatever the
    # individual files' modes say. ferrumd gets a subdirectory instead.
    parent = machine.succeed("stat -c '%U %G %a' /var/lib/ferrum").strip()
    print(f"/var/lib/ferrum: {parent}")
    assert parent == "root ferrum 750", (
        f"/var/lib/ferrum must be root-owned with only group traverse, got: {parent}"
    )
    for sub in ("daemon", "jobs"):
        owned = machine.succeed(f"stat -c '%U %G %a' /var/lib/ferrum/{sub}").strip()
        print(f"/var/lib/ferrum/{sub}: {owned}")
        assert owned == "ferrum ferrum 750", f"/var/lib/ferrum/{sub} unexpected: {owned}"

    # Behaviourally, as the real daemon user: it can write its own
    # subdirectory and genuinely cannot create or delete anything in the
    # shared parent. The two named files are the real interlocks -- deleting
    # state-restore-failed would defeat the fail-closed gate on every app
    # unit, and forging rollback-intent.json would steer a real state
    # rollback.
    #
    # `rm -f`, not bare `rm`, throughout: coreutils' rm PROMPTS ("remove
    # write-protected regular empty file ...?") when the target is not
    # writable by the calling user, and the test driver's shell gives it a
    # stdin that never answers -- a bare `rm` here hangs the whole VM test
    # forever instead of failing. `-f` suppresses only the prompt, not the
    # unlink error: a denied unlink still exits non-zero, which is exactly
    # what machine.fail must observe. (Found by actually running this.)
    machine.succeed("su -s /bin/sh ferrum -c 'touch /var/lib/ferrum/daemon/.writable'")
    machine.succeed("su -s /bin/sh ferrum -c 'rm -f /var/lib/ferrum/daemon/.writable'")
    machine.fail("su -s /bin/sh ferrum -c 'touch /var/lib/ferrum/rollback-intent.json'")
    machine.fail("su -s /bin/sh ferrum -c 'touch /var/lib/ferrum/state-restore-failed'")
    machine.succeed("touch /var/lib/ferrum/state-restore-failed")
    machine.fail("su -s /bin/sh ferrum -c 'rm -f /var/lib/ferrum/state-restore-failed'")
    # Still there -- the denial above really denied, rather than `-f`
    # quietly swallowing a successful delete.
    machine.succeed("test -e /var/lib/ferrum/state-restore-failed")
    machine.succeed("rm -f /var/lib/ferrum/state-restore-failed")
    print("PASS: ferrumd really cannot create or delete root-trusted files beside its own state")

    print("=== real login with the real bootstrap password ===")
    password = machine.succeed("cat /var/lib/ferrum/daemon/ferrumd-setup-password").strip()
    login_response = machine.succeed(
        f"curl -s -c /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/login "
        f"-H 'Content-Type: application/json' "
        f"-d '{{\"username\":\"admin\",\"password\":\"{password}\"}}'"
    )
    print(f"login response: {login_response}")
    assert "csrf_token" in login_response
    import json
    csrf = json.loads(login_response)["csrf_token"]
    # Every mutating call below carries this. The daemon now requires it:
    # `SameSite=Strict` on the session cookie is a browser-enforced control,
    # and the server needs one of its own.
    csrf_header = f"-H 'X-CSRF-Token: {csrf}'"
    print("PASS: real login against the real generated bootstrap password")

    print("=== a mutating call WITHOUT the CSRF header must be refused ===")
    # Same valid session cookie, same valid body -- the ONLY difference from
    # the write two steps down is the missing header. 403, not 401: the
    # caller is authenticated, the request is not.
    no_csrf = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -b /tmp/cookies.txt "
        "-X PUT http://127.0.0.1:7788/api/settings "
        "-H 'Content-Type: application/json' "
        "-d '{\"schemaVersion\":1,\"secrets\":{\"test-secret\":{}}}'"
    ).strip()
    assert no_csrf == "403", f"expected 403 for a session-authenticated request with no CSRF header, got {no_csrf}"
    wrong_csrf = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -b /tmp/cookies.txt "
        "-X PUT http://127.0.0.1:7788/api/settings "
        "-H 'Content-Type: application/json' -H 'X-CSRF-Token: not-the-real-token' "
        "-d '{\"schemaVersion\":1,\"secrets\":{\"test-secret\":{}}}'"
    ).strip()
    assert wrong_csrf == "403", f"expected 403 for a wrong CSRF token, got {wrong_csrf}"
    # And the refusal really refused: nothing was written.
    machine.succeed("grep -q test-secret /etc/ferrum/settings.json")
    machine.fail("grep -q ops@example.com /etc/ferrum/settings.json")
    print("PASS: the real CSRF gate really refuses a cookie-only mutating request")

    print("=== an unauthenticated job POST must be rejected ===")
    unauth = machine.succeed(
        "curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:7788/api/jobs "
        "-H 'Content-Type: application/json' -d '{\"kind\":\"preflight\"}'"
    ).strip()
    assert unauth == "401", f"expected 401 without a session cookie, got {unauth}"
    print("PASS: the job API really is behind the real session gate")

    print("=== real settings write ===")
    machine.succeed(
        f"curl -s -f -b /tmp/cookies.txt -X PUT http://127.0.0.1:7788/api/settings "
        f"-H 'Content-Type: application/json' {csrf_header} "
        f"-d '{{\"schemaVersion\":1,\"secrets\":{{\"test-secret\":{{}}}},\"auth\":{{\"adminEmail\":\"ops@example.com\"}}}}'"
    )
    settings_content = machine.succeed("cat /etc/ferrum/settings.json")
    print(f"settings.json on disk: {settings_content}")
    assert "test-secret" in settings_content
    assert "ops@example.com" in settings_content, "the write must really replace the file, not just be accepted"
    print("PASS: real settings write landed on disk")

    print("=== real secret write, confirmed by real decryption ===")
    machine.succeed(
        f"curl -s -f -b /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/secrets/test-secret "
        f"{csrf_header} -d 'a-real-secret-value'"
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
        f"curl -s -o /dev/null -w '%{{http_code}}' -b /tmp/cookies.txt {csrf_header} "
        f"-X POST http://127.0.0.1:7788/api/secrets/not-declared -d 'nope'"
    ).strip()
    assert undeclared == "400", f"expected 400 for a name settings.json never declared, got {undeclared}"
    machine.fail("test -e /etc/ferrum/secrets/not-declared.sops")
    print("PASS: the secrets API really is settings-gated, not an open file-write primitive")

    print("=== real password rotation over the real API ===")
    # The whole point of the endpoint: an operator turns the generated
    # bootstrap password (which is sitting in a file on disk, and which
    # every one of these tests just read) into one of their own. Every
    # assertion below is made through the REAL login endpoint, not by
    # inspecting the database.
    def login_code(pw):
        return machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -c /dev/null "
            f"-X POST http://127.0.0.1:7788/api/login "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"username\":\"admin\",\"password\":\"{pw}\"}}'"
        ).strip()

    def change_password(current, new, extra_headers=csrf_header):
        return machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' -b /tmp/cookies.txt {extra_headers} "
            f"-X POST http://127.0.0.1:7788/api/password "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"current_password\":\"{current}\",\"new_password\":\"{new}\"}}'"
        ).strip()

    new_password = "a-real-rotated-password"

    # Same session cookie, no CSRF header: a password change is exactly the
    # kind of mutating request the gate exists for.
    no_csrf_rotate = change_password(password, new_password, extra_headers="")
    assert no_csrf_rotate == "403", f"expected 403 without a CSRF header, got {no_csrf_rotate}"

    # A wrong current password is a real 401 -- distinct from a 500, and it
    # must change nothing at all.
    wrong_current = change_password("definitely-not-the-password", new_password)
    assert wrong_current == "401", f"expected 401 for a wrong current password, got {wrong_current}"
    assert login_code(password) == "200", (
        "a refused rotation must leave the real current password working"
    )
    assert login_code(new_password) == "401", (
        "the password a REFUSED rotation proposed must never have been set"
    )

    # An empty new password is refused as malformed, not accepted.
    empty_new = change_password(password, "")
    assert empty_new == "400", f"expected 400 for an empty new password, got {empty_new}"
    assert login_code(password) == "200"

    # The real rotation.
    rotated = change_password(password, new_password)
    assert rotated == "200", f"the real rotation must be accepted, got {rotated}"
    assert login_code(new_password) == "200", (
        "a real login with the NEW password must really succeed"
    )
    assert login_code(password) == "401", (
        "the OLD password must really stop working -- otherwise the rotation "
        "added a credential instead of replacing one"
    )
    # The existing session is deliberately untouched by a rotation, so the
    # rest of this test keeps working with the cookie it already has.
    machine.succeed(
        "curl -s -f -b /tmp/cookies.txt http://127.0.0.1:7788/api/settings > /dev/null"
    )
    # Rotate back, so anything later in this file that uses the bootstrap
    # password still works.
    assert change_password(new_password, password) == "200"
    assert login_code(password) == "200"
    print("PASS: a real password rotation really replaced the real credential, and a wrong current password really changed nothing")

    print("=== real job trigger: preflight, through the real privilege boundary ===")
    job_response = machine.succeed(
        f"curl -s -f -b /tmp/cookies.txt -X POST http://127.0.0.1:7788/api/jobs "
        f"-H 'Content-Type: application/json' {csrf_header} -d '{{\"kind\":\"preflight\"}}'"
    )
    print(f"job response: {job_response}")
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
    print("PASS: a real job, triggered over the real HTTP API, ran through the real privilege boundary and produced a real progress log")

    print("=== the spent request file is really cleaned up ===")
    # It used to be left behind forever. A request file that outlives its
    # job is a replayable privileged trigger sitting in a tmpfs directory:
    # anything that can name the UUID (it is visible in `systemctl
    # list-units`) and reach the D-Bus StartUnit call could re-run it. The
    # polkit subject check is what actually stops that call; this is the
    # defence-in-depth half, shrinking the window in which there is
    # anything to replay. Retried rather than checked once: the deletion
    # happens when ferrumd processes systemd's JobRemoved signal, which is
    # asynchronous with respect to the progress file's last line.
    machine.wait_until_succeeds(f"test ! -e /run/ferrum/requests/{job_id}.json", timeout=60)
    print("PASS: ferrumd really deleted the spent request file after the job finished")

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
        f"curl -s -o /dev/null -w '%{{http_code}}' -b /tmp/cookies.txt "
        f"-X POST http://127.0.0.1:7788/api/jobs {csrf_header} "
        f"-H 'Content-Type: application/json' -d '{{\"kind\":\"preflight\"}}' | grep -q 200",
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
        f"curl -s -o /dev/null -w '%{{http_code}}' -b /tmp/cookies.txt "
        f"-X POST http://127.0.0.1:7788/api/jobs {csrf_header} "
        f"-H 'Content-Type: application/json' -d '{{\"kind\":\"preflight\"}}'"
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
        f"curl -s -o /dev/null -w '%{{http_code}}' -b /tmp/cookies.txt "
        f"-X POST http://127.0.0.1:7788/api/jobs {csrf_header} "
        f"-H 'Content-Type: application/json' -d '{{\"kind\":\"preflight\"}}'"
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
        f"curl -s -o /dev/null -w '%{{http_code}}' -b /tmp/cookies.txt "
        f"-X POST http://127.0.0.1:7788/api/jobs {csrf_header} "
        f"-H 'Content-Type: application/json' -d '{{\"kind\":\"preflight\"}}'"
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

    print("=== ...and really is confined by the unit's hardening directives ===")
    # Read back from systemd's OWN parsed view of the running unit, not from
    # the Nix source: a directive systemd did not accept (wrong section,
    # wrong spelling) would show its default here. Everything above in this
    # test already ran under these restrictions -- SQLite writes, the D-Bus
    # StartUnit, the TCP listener, and the sops/ssh-to-age subprocesses the
    # secrets API forks -- so this is the structural half of a property the
    # rest of the file has already proven behaviourally.
    for prop, expected in [
        ("PrivateTmp", "yes"),
        ("ProtectHome", "yes"),
        ("NoNewPrivileges", "yes"),
        ("LockPersonality", "yes"),
        ("RestrictSUIDSGID", "yes"),
        ("RestrictRealtime", "yes"),
        ("ProtectKernelTunables", "yes"),
        ("ProtectKernelModules", "yes"),
        ("ProtectControlGroups", "yes"),
        ("ProtectClock", "yes"),
        ("ProtectSystem", "strict"),
    ]:
        actual = machine.succeed(
            f"systemctl show ferrumd.service -p {prop} --value"
        ).strip()
        assert actual == expected, f"ferrumd.service {prop}: expected {expected}, got {actual}"

    families = machine.succeed(
        "systemctl show ferrumd.service -p RestrictAddressFamilies --value"
    ).strip()
    print(f"RestrictAddressFamilies: {families}")
    for needed in ("AF_UNIX", "AF_INET", "AF_INET6"):
        assert needed in families, f"{needed} is genuinely required by ferrumd: {families}"
    # A filter that allowed everything would satisfy the line above too.
    assert "AF_NETLINK" not in families, f"the filter must really be a filter: {families}"
    assert "AF_PACKET" not in families, f"the filter must really be a filter: {families}"

    # Two different questions, deliberately asked separately.
    #
    # (a) Is the directive WRITTEN the way this repo intends? Only the unit
    #     fragment can answer that: `systemctl show -p SystemCallFilter`
    #     does NOT echo "@system-service" back -- it RESOLVES the preset and
    #     returns the full expanded allow-list of individual syscall names.
    #     (Found by actually running this: an earlier version of this check
    #     asserted the preset name appeared in the property value and failed
    #     against a perfectly correct unit.)
    fragment = machine.succeed("systemctl cat ferrumd.service")
    assert "SystemCallFilter=@system-service" in fragment, (
        f"expected the standard preset in the unit fragment:\n{fragment}"
    )
    # Checked as two separate substrings because NixOS renders a
    # list-valued serviceConfig attribute as one `Key=value` line per
    # element -- this matches both that rendering and a single combined
    # `SystemCallFilter=~@privileged @resources` line.
    assert "SystemCallFilter=~@privileged" in fragment, (
        f"the privileged group must be subtracted:\n{fragment}"
    )
    assert "@resources" in fragment, (
        f"the resource-control group must be subtracted:\n{fragment}"
    )

    # (b) Did systemd really APPLY it, and is the result really a filter
    #     rather than an allow-everything? Asked of systemd's own expanded
    #     view. Word-split into a set rather than substring-matched --
    #     "mount" is a substring of the perfectly ordinary `listmount` and
    #     `statmount`, so `in` on the raw string would silently pass.
    allowed = set(
        machine.succeed("systemctl show ferrumd.service -p SystemCallFilter --value").split()
    )
    print(f"SystemCallFilter resolves to {len(allowed)} syscalls")
    assert allowed, "an empty SystemCallFilter is no filter at all"
    for needed in ("read", "write", "openat", "socket", "connect", "futex", "mmap"):
        assert needed in allowed, (
            f"{needed} is genuinely required by ferrumd and must not be filtered away"
        )
    # The whole point of @system-service minus @privileged/@resources: an
    # ordinary daemon has no business doing any of these.
    for forbidden in (
        "mount", "umount2", "pivot_root", "chroot", "reboot", "kexec_load",
        "init_module", "finit_module", "delete_module", "swapon", "swapoff",
        "bpf", "ptrace", "settimeofday", "setdomainname", "sethostname",
    ):
        assert forbidden not in allowed, (
            f"{forbidden} must not be reachable from ferrumd: the filter is too wide"
        )

    arches = machine.succeed(
        "systemctl show ferrumd.service -p SystemCallArchitectures --value"
    ).strip()
    assert arches == "native", f"expected native-only, got: {arches}"

    caps = machine.succeed(
        "systemctl show ferrumd.service -p CapabilityBoundingSet --value"
    ).strip()
    assert caps == "", f"ferrumd must hold no capabilities at all, got: {caps}"

    # The narrowed write surface: the shared parent must NOT be in it.
    rw = machine.succeed("systemctl show ferrumd.service -p ReadWritePaths --value").strip()
    print(f"ReadWritePaths: {rw}")
    assert "/var/lib/ferrum/daemon" in rw and "/var/lib/ferrum/jobs" in rw, rw
    for entry in rw.strip().split():
        assert entry != "/var/lib/ferrum", (
            f"the shared parent must not be writable by ferrumd: {rw}"
        )
    print("PASS: systemd really applied the hardening, and the daemon really worked under all of it")

    print("=== ferrumd's own startup writability check really refuses a mis-owned settings.json ===")
    # The real gap this closes: `AssertPathExists=` answers only "does this
    # path exist". A host provisioned BEFORE this phase has
    # /etc/ferrum/settings.json as root:root 0644 -- the assertion passes,
    # ferrumd starts, login works, GET /api/settings works, and the
    # operator's first real PUT dies with a bare "Permission denied" with
    # nothing anywhere explaining why. There is no systemd directive for
    # "this specific file must be writable by this specific user"
    # (AssertPathIsReadWrite= only checks the mount is not read-only), so
    # the check lives inside ferrumd itself, before the listener binds.
    machine.succeed("systemctl stop ferrumd.service")
    machine.succeed("chown root:root /etc/ferrum/settings.json")
    machine.succeed("chmod 0644 /etc/ferrum/settings.json")
    # Exactly the shape a pre-phase host has -- confirm the fixture really
    # is that shape before asserting anything about it.
    mis_owned = machine.succeed("stat -c '%U %G %a' /etc/ferrum/settings.json").strip()
    assert mis_owned == "root root 644", f"fixture is not the pre-phase shape: {mis_owned}"

    # Type=simple, so `systemctl start` returns as soon as the process is
    # FORKED -- a non-zero exit from systemctl is not what proves anything
    # here. What proves it: the daemon really dies, really never binds its
    # port, and really says why on every attempt. Restart=on-failure turns
    # that into a crash loop that hits systemd's start limit within a
    # second or so.
    machine.execute("systemctl start ferrumd.service")
    machine.wait_until_succeeds(
        "journalctl -u ferrumd.service -n 100 --no-pager | grep -q 'refusing to start'",
        timeout=60,
    )
    refusal = machine.succeed("journalctl -u ferrumd.service -n 40 --no-pager")
    print(f"real journal output from the refusing daemon:\n{refusal}")

    # The message has to be genuinely actionable, not merely present: it must
    # name the exact file and give the exact command that fixes it.
    assert "/etc/ferrum/settings.json is not writable" in refusal, refusal
    assert "Permission denied" in refusal, refusal
    assert "chown root:ferrum /etc/ferrum/settings.json" in refusal, refusal
    assert "chmod 0664 /etc/ferrum/settings.json" in refusal, refusal
    # It also reports what is really on disk right now, so an operator does
    # not have to go and look.
    assert "uid=0 gid=0 mode=0644" in refusal, refusal

    # It really did not start serving: no port, no API.
    machine.fail("curl -s --max-time 5 http://127.0.0.1:7788/api/settings")
    machine.wait_until_succeeds(
        "systemctl show ferrumd.service -p ActiveState --value | grep -qE 'failed|inactive'",
        timeout=90,
    )
    print("PASS: ferrumd really refused to start, with a real, actionable message, rather than failing later on the first write")

    # And the fix in the message really is the fix.
    machine.succeed("chown root:ferrum /etc/ferrum/settings.json")
    machine.succeed("chmod 0664 /etc/ferrum/settings.json")
    machine.succeed("systemctl reset-failed ferrumd.service")
    machine.succeed("systemctl start ferrumd.service")
    machine.wait_for_open_port(7788)
    print("PASS: running exactly the command the error message prints really makes ferrumd start")

    print("=== ...and the same check really covers the secrets directory ===")
    # Checked by really creating and removing a probe file, not by reading
    # mode bits: what POST /api/secrets/<name> needs is the ability to
    # CREATE a file here, which mode bits alone can be wrong about.
    machine.succeed("systemctl stop ferrumd.service")
    machine.succeed("chown root:root /etc/ferrum/secrets")
    machine.succeed("chmod 0755 /etc/ferrum/secrets")
    machine.execute("systemctl start ferrumd.service")
    machine.wait_until_succeeds(
        "journalctl -u ferrumd.service -n 100 --no-pager | grep -q 'secrets directory'",
        timeout=60,
    )
    secrets_refusal = machine.succeed("journalctl -u ferrumd.service -n 40 --no-pager")
    print(f"real journal output for the mis-owned secrets directory:\n{secrets_refusal}")
    assert "/etc/ferrum/secrets is not writable" in secrets_refusal, secrets_refusal
    assert "chown ferrum:ferrum /etc/ferrum/secrets" in secrets_refusal, secrets_refusal
    assert "chmod 0750 /etc/ferrum/secrets" in secrets_refusal, secrets_refusal
    machine.fail("curl -s --max-time 5 http://127.0.0.1:7788/api/settings")

    machine.succeed("chown ferrum:ferrum /etc/ferrum/secrets")
    machine.succeed("chmod 0750 /etc/ferrum/secrets")
    machine.succeed("systemctl reset-failed ferrumd.service")
    machine.succeed("systemctl start ferrumd.service")
    machine.wait_for_open_port(7788)
    print("PASS: the secrets directory is really covered by the same real check")

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
