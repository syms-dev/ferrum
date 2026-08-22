# The ferrum system user and the privilege boundary that lets it trigger
# real ferrum-apply runs without ever becoming root itself. ferrumd's own
# systemd unit is NOT defined here -- that needs the ferrumd binary to
# exist first (Phase 1.5a Task 6). This file is deliberately testable and
# usable standalone: an operator (or a test) can already trigger a real
# apply via a real D-Bus call before ferrumd itself exists, which is
# exactly what tests/privilege-boundary.nix does.
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
in
lib.mkIf ferrum.daemon.enable {
  users.users.ferrum = {
    isSystemUser = true;
    group = "ferrum";
    description = "ferrumd -- the unprivileged ferrum web daemon";
  };
  users.groups.ferrum = { };

  # Real, tested rule -- confirmed for real on ferrum-dev with a genuine
  # unprivileged D-Bus StartUnit call: a real "ferrum-apply@<uuid>.service"
  # start succeeded, a real "sshd.service" start was denied. The 36-char
  # class matches a standard UUID string (8-4-4-4-12 hex digits, 4
  # hyphens) -- ferrumd (Task 6) generates the UUID per job request; it is
  # NEVER parsed as data by this rule or by ferrum-apply itself, only
  # compared against this fixed pattern.
  security.polkit.enable = true;
  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if (action.id == "org.freedesktop.systemd1.manage-units" &&
          action.lookup("unit") &&
          /^ferrum-apply@[0-9a-f-]{36}\.service$/.test(action.lookup("unit")) &&
          action.lookup("verb") == "start") {
        return polkit.Result.YES;
      }
    });
  '';

  systemd.services."ferrum-apply@" = {
    description = "ferrum-apply, dispatched from a ferrumd-written request file";
    serviceConfig = {
      Type = "oneshot";
      # %i is systemd's own instance-name substitution -- the UUID from
      # the unit's own instance name becomes part of the request file
      # PATH here, never re-interpreted as a command or shell content.
      # /run/ferrum is tmpfs, root-readable regardless of the file's own
      # mode (root bypasses permission checks entirely), so ferrumd (Task
      # 6) needs no special permission dance beyond the directory being
      # writable by the ferrum user.
      ExecStart = "${pkgs.ferrum-apply}/bin/ferrum-apply run-request /run/ferrum/requests/%i.json";
    };
  };

  systemd.tmpfiles.rules = [
    "d /run/ferrum/requests 0750 ferrum ferrum - -"
  ];

  # /etc/ferrum's own carved-out permission model (settings.json and
  # secrets/ writable by ferrumd, everything else root-only) is provisioned
  # once by nixos-anywhere's own initial setup, not by this module.
  #
  # NOTE ON A REAL DESIGN CORRECTION MADE WHILE WRITING THIS PLAN: an
  # earlier draft of this module asserted these paths exist via a plain
  # NixOS `assertions = [ { assertion = builtins.pathExists ...; } ];`
  # block. That is wrong and was caught by this plan's own pre-flight
  # review, confirmed for real on ferrum-dev: `builtins.pathExists` on an
  # absolute path is evaluated against the MACHINE RUNNING THE NIX
  # EVALUATION, not the machine the resulting config will boot on. For a
  # real deployed host rebuilding itself locally (the normal
  # `nixos-rebuild switch` case ferrum-apply drives), evaluator and target
  # happen to be the same machine, so it would appear to "work" -- but for
  # THIS PLAN'S OWN VM TESTS (this task's Step 5, and Task 6's Step 8),
  # evaluation runs on the CI runner / ferrum-dev, which never has
  # /etc/ferrum/settings.json, so the assertion would fail before the VM
  # even boots, on every run, unconditionally. The correct mechanism for
  # "does this real path exist on the machine actually starting this
  # unit" is systemd's own AssertPathExists= (a real, standard, documented
  # systemd.exec directive -- confirmed via `man systemd.unit` on
  # ferrum-dev), which is evaluated at REAL activation time on the REAL
  # target machine, not at Nix-eval time -- see Task 6 Step 6, where it is
  # attached to the ferrumd unit itself (the actual thing that needs these
  # paths, rather than the whole daemon.nix module).
}
