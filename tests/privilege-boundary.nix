# Proves the privilege boundary Task 2 built actually works against the
# REAL ferrum-apply binary, not a stand-in, in BOTH directions:
#
#   * the real `ferrum` service account -- the one subject the polkit rule
#     in modules/core/daemon.nix names -- really triggers a real
#     ferrum-apply run-request via a real D-Bus StartUnit call, and the real
#     binary really runs;
#   * an ordinary unprivileged account (`testferrum`) is really DENIED the
#     identical call, and the privileged unit really never executes;
#   * and neither account may start an unrelated unit, so the grant is
#     scoped to the ferrum-apply@ pattern as well as to the subject.
#
# Both directions are load-bearing. A rule that denied everyone would
# satisfy the denial half on its own while leaving the daemon unable to
# work at all, and a rule that allowed everyone -- which is what this file
# used to assert as correct -- satisfies the allow half while handing a
# root trigger to every local process. See the long note above `testScript`.
#
# Deviates from the brief's original literal test code in one load-bearing
# way, discovered by actually running this on ferrum-dev: importing only
# `../modules/core/daemon.nix` with a hand-rolled `options.ferrum` stub
# left `pkgs.ferrum-apply` undefined, since that binding is wired in by
# modules/core/overlays.nix's `nixpkgs.overlays`, not by daemon.nix itself
# (daemon.nix only CONSUMES `pkgs.ferrum-apply`, same as every other
# module under modules/core -- see overlays.nix's own header for why the
# overlay lives separately). The fix is the same escape hatch
# tests/rollback.nix already uses for exactly this reason: import the full
# `../modules` (which pulls in overlays.nix, options.nix, and daemon.nix
# together) and set `node.pkgsReadOnly = false` so `nixpkgs.overlays` is
# still settable inside a `pkgs.testers.runNixOSTest` node. Requesting a
# real `preflight` (below) then also requires state_dir/snapshot_dir to be
# real btrfs subvolumes -- provisioned here with the same second-disk
# pattern tests/rollback.nix uses, trimmed to skip the bootloader/reboot
# machinery this test never needs.
#
# A SECOND, separate gap found by actually running this (not present in
# the brief's literal code, and not scoped to fix project-wide here):
# `../modules` alone declares options like `modules/apps/qbittorrent/
# service.nix`'s `sops.secrets.*` entries (inert, behind their own
# `ferrum.apps.qbittorrent.enable` mkIf, but still merged as DEFINITIONS
# against an `sops.*` OPTION namespace that only exists once sops-nix's own
# NixOS module is imported). A real host gets that for free from
# modules/lib/default.nix's `mkHost`, which always puts
# `sopsNix.nixosModules.sops` in the module list alongside this same
# `../modules` -- `pkgs.testers.runNixOSTest` doesn't go through `mkHost`,
# so this test imports it directly instead. (This isn't unique to this
# test: `nix eval .#checks.x86_64-linux.rollback.drvPath` hits the
# identical "option `nodes.machine.sops' does not exist" error on this same
# ferrum-dev checkout, confirming it's a pre-existing gap in every VM test
# that imports `../modules` directly, not something this task introduced --
# out of scope to fix project-wide from here, so only this test's own
# import list is patched.)
{ pkgs, sopsNix, ... }:
pkgs.testers.runNixOSTest {
  name = "privilege-boundary";

  node.pkgsReadOnly = false;

  nodes.machine = { config, lib, pkgs, utils, ... }: {
    imports = [ ../modules sopsNix.nixosModules.sops ];

    virtualisation.emptyDiskImages = [ 4096 ];

    ferrum.daemon.enable = true;
    ferrum.storage = {
      stateDir = "/var/lib/ferrum/state";
      snapshotDir = "/var/lib/ferrum/snapshots";
      # The disk image above is 4GiB; the real 10GiB default would make
      # every real preflight run here fail on free space alone, which
      # would be testing the wrong thing. Must stay positive (see
      # modules/core/options.nix's own assertion) -- 1 is plenty given the
      # disk is freshly formatted and otherwise empty.
      minFreeGiB = 1;
    };

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

    # No /etc/ferrum stub files needed here: the ferrum-apply@ template
    # unit and polkit rule under test don't reference /etc/ferrum at all
    # -- that dependency belongs only to the ferrumd unit itself (added
    # in Task 6, which checks it via the real, activation-time
    # AssertPathExists=, not an eval-time assertion; see Task 6 Step 8's
    # own test for where those stub files are actually needed).
    users.users.testferrum = {
      isNormalUser = true;
    };
    system.stateVersion = "25.11";
  };
  # A THIRD gap found by actually running this (also not scoped to fix
  # project-wide): the brief's literal testScript used a doubled backslash
  # (`\\"`) before each embedded double-quote. Nix `''...''` strings don't
  # treat backslash specially at all, so that reached Python as a literal
  # `\\"` -- which Python parses as an escaped backslash followed by an
  # UNescaped quote, terminating the string early ("Unterminated string
  # literal", caught by the test driver's own Python type-checker before
  # the VM even boots). A single backslash (`\"`) is what actually produces
  # an escaped quote in the resulting Python source.
  # WHAT THIS TEST ASSERTED BEFORE THE BRANCH-WIDE FINAL REVIEW, AND WHY
  # THAT WAS BACKWARDS: it created a plain `testferrum` normal user and
  # asserted that user's StartUnit call SUCCEEDED. It passed -- because the
  # polkit rule at the time had no `subject` clause at all and therefore
  # returned YES for every local subject on the box. The test was pinning
  # the hole in place as if it were the specification. It now asserts the
  # real intended property in both directions: the `ferrum` service account
  # is allowed, and an ordinary unprivileged account is denied.
  #
  # HOW "as this specific system user" IS DONE HERE: `su -s /bin/sh ferrum
  # -c ...`. `users.users.ferrum` is declared `isSystemUser = true` with no
  # shell (modules/core/daemon.nix), so its login shell is `nologin` and a
  # plain `su - ferrum` would exit before running anything -- `-s /bin/sh`
  # overrides the shell for this one invocation without changing the
  # account. What polkit sees is the only thing that matters: the busctl
  # process's real uid, which `su` has genuinely set to ferrum's, resolved
  # by polkit itself from the D-Bus caller's kernel-supplied credentials.
  # This is the same mechanism tests/daemon-end-to-end.nix already uses to
  # check the negative case for this account, and it agrees with how the
  # real daemon reaches the bus (a systemd unit with User=ferrum and no
  # login session at all -- `polkit.Result.YES` needs no session, which is
  # why the real ferrumd works).
  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("polkit.service")

    # The account the real ferrumd unit runs as must genuinely exist -- the
    # whole rule below is scoped to it by name.
    machine.succeed("id ferrum")

    print("=== the polkit rule really carries a subject restriction ===")
    # Structural, before any behaviour: a rule that matched only on the unit
    # name would authorize every local user, which is exactly the defect
    # this test previously enshrined. Checked against the real generated
    # rule file on the real booted machine, not against the Nix source.
    rules = machine.succeed(
        "cat /etc/polkit-1/rules.d/*.rules /run/polkit-1/rules.d/*.rules 2>/dev/null || true"
    )
    print(f"polkit rules on the machine:\n{rules}")
    assert 'subject.user == "ferrum"' in rules, (
        f"the ferrum-apply rule must be scoped to a subject, got:\n{rules}"
    )
    print("PASS: the rule really is subject-scoped")

    allowed_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    denied_uuid = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"

    # Real request files, written as root here to simulate what ferrumd
    # writes for real -- this test's job is the privilege boundary, not
    # ferrumd itself. Both are written, so the denied attempt below fails
    # for the ONE reason under test (polkit) and not because its input was
    # missing.
    machine.succeed("mkdir -p /run/ferrum/requests")
    for u in (allowed_uuid, denied_uuid):
        machine.succeed(
            f"echo '{{\"kind\":\"preflight\"}}' > /run/ferrum/requests/{u}.json && "
            f"chown ferrum:ferrum /run/ferrum/requests/{u}.json"
        )

    def start_unit_as(user, unit):
        return machine.execute(
            f"su -s /bin/sh {user} -c \"busctl call --system org.freedesktop.systemd1 "
            f"/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager StartUnit ss "
            f"'{unit}' replace\" 2>&1"
        )

    print("=== the real ferrum service account triggers a REAL ferrum-apply run via D-Bus ===")
    status, out = start_unit_as("ferrum", f"ferrum-apply@{allowed_uuid}.service")
    print(f"ferrum StartUnit: status={status} output={out.strip()}")
    assert status == 0, (
        "the ferrum account is the one subject this rule exists to authorize; "
        f"a denial here means the daemon itself cannot work: {out}"
    )
    machine.wait_until_succeeds(
        f"systemctl show ferrum-apply@{allowed_uuid}.service -p Result | grep -q 'Result=success'"
    )
    print("PASS: the real ferrum-apply binary really ran preflight for the real ferrum user, dispatched through the real polkit+D-Bus mechanism")

    print("=== an ORDINARY unprivileged user must be denied the very same call ===")
    status, out = start_unit_as("testferrum", f"ferrum-apply@{denied_uuid}.service")
    print(f"testferrum StartUnit: status={status} output={out.strip()}")
    assert status != 0, (
        "any local user being able to trigger a root ferrum-apply run is the "
        f"exact hole this rule's subject check closes; got a success: {out}"
    )
    # ...and denied for the right reason. A failure caused by, say, a typo in
    # the unit name would also be non-zero, and would prove nothing.
    lowered = out.lower()
    assert ("denied" in lowered) or ("not authorized" in lowered) or ("interactive authentication" in lowered), (
        f"the refusal must really come from polkit authorization: {out}"
    )
    # The privileged unit must genuinely never have executed. systemd leaves
    # ExecMainStartTimestamp empty for a unit whose ExecStart has never run,
    # so this is a real "it did not happen", not an inference from the error
    # text above.
    started = machine.succeed(
        f"systemctl show ferrum-apply@{denied_uuid}.service -p ExecMainStartTimestamp --value"
    ).strip()
    assert started == "", (
        f"the denied unit must never have executed, but systemd recorded a start at: {started}"
    )
    # Its request file is therefore still sitting there, unconsumed.
    machine.succeed(f"test -e /run/ferrum/requests/{denied_uuid}.json")
    print("PASS: an ordinary unprivileged user really cannot trigger a privileged ferrum-apply run")

    print("=== even the ferrum user may not start an unrelated unit ===")
    status, out = start_unit_as("ferrum", "sshd.service")
    print(f"ferrum StartUnit sshd: status={status} output={out.strip()}")
    assert status != 0, f"the rule authorizes one unit pattern, not this account generally: {out}"
    print("PASS: the authorization really is scoped to the ferrum-apply@ pattern, not to the account")

    print("=== and an ordinary user certainly may not ===")
    status, out = start_unit_as("testferrum", "sshd.service")
    assert status != 0, f"expected a denial, got: {out}"
    print("PASS: starting an unrelated unit was correctly denied")
  '';
}
