# Phase 1.6a story S12: the first test in this repository that starts from
# NOTHING.
#
# Every other VM test builds a host from a Nix expression and then drives
# it. The design doc's postmortem of the first real install is explicit
# about why that is not enough: ten defects, six of which no VM test could
# see, because "a test that never acts like a human never finds what a
# human hits" -- and "install-from-nothing is its own test target".
#
# So this is a TWO-NODE test. `operator` runs the real `ferrum-install`
# binary against `target`, whose disk starts blank, and afterwards asserts
# the things a human would type at a shell.
#
# WHAT THIS TEST DELIBERATELY DOES NOT COVER
#
# Stage 2 is absent, and cannot be here. `pkgs.testers.runNixOSTest` is
# sandboxed: no network, and no nixpkgs evaluation inside the guest. The
# existing workaround (inject a pre-built closure via
# `virtualisation.additionalPaths` and point a fixture flake at
# `builtins.storePath`, as tests/daemon-apply-end-to-end.nix does) works
# for stage 1 precisely because stage 1 has `apps: {}` and therefore ZERO
# sops.secrets -- its closure can be pre-built. It cannot work for stage 2,
# whose entire reason to exist is that each app's `sopsFile` is created at
# RUNTIME on the guest and so cannot be in a pre-built closure.
#
# Stage 2 therefore lives in the networked, KVM-capable CI jobs
# (tests/stage2/run.sh and tests/stage2/resume.sh, driven by the `stage2`
# and `stage2-resume` jobs in .github/workflows/vm-tests.yml). Splitting
# them is not a compromise; it is the only split that lets each half
# actually run.
{ pkgs, ferrumInstall }:
pkgs.testers.runNixOSTest {
  name = "ferrum-install-from-nothing";

  nodes = {
    # The operator's machine: has the installer, an SSH key, and nothing
    # else. Deliberately NOT a ferrum host.
    operator = { ... }: {
      environment.systemPackages = [ ferrumInstall pkgs.openssh pkgs.git ];
      # The host repository mount the real image expects, as a plain
      # directory here.
      systemd.tmpfiles.rules = [ "d /host 0755 root root - -" ];
    };

    # The machine being installed onto. Starts with a blank second disk
    # and no ferrum anything.
    target = { ... }: {
      services.openssh = {
        enable = true;
        settings.PermitRootLogin = "yes";
        settings.PasswordAuthentication = false;
      };
      virtualisation.emptyDiskImages = [ 4096 ];
    };
  };

  testScript = ''
    start_all()
    operator.wait_for_unit("multi-user.target")
    target.wait_for_unit("sshd.service")

    # Give the operator a key and authorise it on the target, the way a
    # real operator's ~/.ssh mount would.
    operator.succeed('mkdir -p /ssh && ssh-keygen -t ed25519 -N "" -f /ssh/id_ed25519')
    pub = operator.succeed("cat /ssh/id_ed25519.pub").strip()
    target.succeed("mkdir -p /root/.ssh")
    target.succeed(f"echo '{pub}' > /root/.ssh/authorized_keys")
    target.succeed("chmod 600 /root/.ssh/authorized_keys")
    operator.succeed(
        "mkdir -p /root/.ssh && ssh-keyscan -H target >> /root/.ssh/known_hosts"
    )

    with subtest("no target argument is a usage error, and contacts nothing"):
        operator.fail("ferrum-install")

    with subtest("a non-root target is refused before anything is contacted"):
        out = operator.fail("ferrum-install cs@target --host-dir /host --ssh-dir /ssh 2>&1")
        assert "must connect as root" in out, out

    with subtest("a missing host mount is refused, naming the docker flag"):
        out = operator.fail(
            "ferrum-install root@target --host-dir /nope --ssh-dir /ssh 2>&1"
        )
        assert "does not exist" in out, out
        assert "-v" in out, out

    with subtest("the inventory reads the target's real disks over SSH"):
        # A single blank line. This aborts at the FIRST question (hostname),
        # which is well before the disk gate -- an earlier comment here
        # claimed otherwise and was wrong. What it does prove is that the
        # installer reached the target, read its block devices and rendered
        # them, which is the read-only half this sandbox can cover.
        out = operator.fail(
            "printf '\\n' | ferrum-install root@target "
            "--host-dir /host --ssh-dir /ssh 2>&1"
        )
        assert "collecting inventory" in out, out
        # The real disks, not just the banner -- otherwise this passes on an
        # installer that printed the heading and then fell over.
        assert "vdb" in out, out
        assert "x86_64" in out, out

    with subtest("nothing on the target was modified by any refusal"):
        # The blank disk is still blank: no partition table was written.
        target.succeed("test -z \"$(lsblk -no FSTYPE /dev/vdb)\"")
  '';
}
