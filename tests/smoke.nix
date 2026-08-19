# Phase 1.0, probe 0.1: does a NixOS VM test run at all on a hosted GitHub
# runner? Deliberately trivial -- this is not testing ferrum, it is testing
# the CI environment itself. If this stops passing, treat it as a hard
# blocker on the whole testing strategy: the rollback test (the most
# important test in the project, see tests/rollback.nix once it exists)
# depends entirely on VM tests working in CI.
{ pkgs, ... }:
pkgs.testers.runNixOSTest {
  name = "ferrum-smoke";

  nodes.machine = { ... }: { };

  testScript = ''
    machine.wait_for_unit("multi-user.target")
    machine.succeed("echo ferrum-smoke-ok")
  '';
}
