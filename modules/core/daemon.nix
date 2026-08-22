# The ferrum system user, the privilege boundary that lets it trigger real
# ferrum-apply runs without ever becoming root itself, and (since Phase
# 1.5a Task 6) ferrumd's own systemd unit.
#
# The two halves stay independently exercisable on purpose: an operator (or
# a test) can trigger a real apply via a real D-Bus call with no ferrumd
# involved at all, which is exactly what tests/privilege-boundary.nix does,
# while tests/daemon-end-to-end.nix drives the whole stack through the real
# HTTP API.
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
  #
  # `subject.user == "ferrum"` IS LOAD-BEARING AND MUST NOT BE REMOVED.
  # Without it (the shape this rule shipped in until the branch-wide final
  # review caught it) the rule returns YES for EVERY local subject, which
  # means any unprivileged local account -- not just the daemon's own --
  # could start a real, root ferrum-apply run against any request file it
  # could name. That directly contradicts this phase's whole security
  # thesis ("compromising ferrumd only ever yields the power expressed by
  # the settings schema"), because it hands the same privileged trigger to
  # processes that never compromised ferrumd at all. `subject.user` is
  # polkit's own documented JS property (polkit(8), "Subject" object): the
  # UNIX user name of the process making the call, resolved by polkit from
  # the D-Bus caller's credentials, so it cannot be spoofed by the caller.
  # tests/privilege-boundary.nix proves BOTH halves for real: the `ferrum`
  # user is allowed, an ordinary `testferrum` user is denied.
  security.polkit.enable = true;
  security.polkit.extraConfig = ''
    polkit.addRule(function(action, subject) {
      if (action.id == "org.freedesktop.systemd1.manage-units" &&
          subject.user == "ferrum" &&
          action.lookup("unit") &&
          /^ferrum-apply@[0-9a-f-]{36}\.service$/.test(action.lookup("unit")) &&
          action.lookup("verb") == "start") {
        return polkit.Result.YES;
      }
    });
  '';

  systemd.services."ferrum-apply@" = {
    description = "ferrum-apply, dispatched from a ferrumd-written request file";
    # %i again -- systemd's own instance-name substitution, so FERRUM_JOB_ID
    # is always exactly the UUID ferrumd's D-Bus StartUnit call used, with no
    # second channel to keep in sync. crates/ferrum-apply/src/progress.rs
    # writes $FERRUM_JOBS_DIR/$FERRUM_JOB_ID.jsonl only when FERRUM_JOB_ID is
    # set, which is precisely "this run was dispatched by ferrumd" -- a bare
    # `ferrum-apply apply` over SSH still writes no progress file at all.
    # Without this block, ferrumd's SSE handler would tail a file that never
    # appears.
    environment = {
      FERRUM_JOB_ID = "%i";
      FERRUM_JOBS_DIR = "/var/lib/ferrum/jobs";
    };
    # REAL BUG, FOUND BY REALLY RUNNING A REAL APPLY THROUGH THIS UNIT
    # (tests/daemon-apply-end-to-end.nix, added alongside this line).
    #
    # `ferrum-apply apply` shells out to `nix build` and then `nix-env -p
    # /nix/var/nix/profiles/system --set` (crates/ferrum-apply/src/apply.rs
    # steps 1 and 5), resolving both through PATH. A NixOS systemd unit does
    # NOT inherit a login shell's PATH: `systemd.services.<name>.path`
    # defaults to just coreutils/findutils/gnugrep/gnused/systemd, so `nix`
    # and `nix-env` were simply absent here. Every real `{"kind":"apply"}`
    # job dispatched by ferrumd therefore died on its very first real step
    # with a bare, causeless `apply error: No such file or directory (os
    # error 2)` -- confirmed for real, in a real VM, as the first failure
    # this new test produced.
    #
    # It was invisible until now because the only path anything ever
    # exercised a real apply through was `ferrum-apply apply` typed by hand
    # over SSH, where the operator's own login shell puts nix on PATH. The
    # daemon's path never had one. `systemctl` comes from the default set
    # above, and `btrfs` is already wrapped into the ferrum-apply binary
    # itself by nix/pkgs/ferrum-apply's own postFixup -- nix is the one
    # genuine gap, and config.nix.package is this host's own real nix rather
    # than a second, possibly-different one from pkgs.
    path = [ config.nix.package ];
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

  # The unprivileged web daemon itself. Everything privileged it can reach
  # is the polkit rule above plus the ferrum-apply@ template unit -- this
  # process has no capabilities at all (CapabilityBoundingSet = "") and
  # cannot gain any (NoNewPrivileges = true).
  systemd.services.ferrumd = {
    description = "ferrumd -- the unprivileged ferrum web daemon";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];
    # sops and ssh-to-age are runtime dependencies of the SECRETS API, not
    # of the daemon's core: crates/ferrumd/src/secrets_api.rs shells out to
    # both (via ferrum-secrets) to derive this host's own age recipient and
    # encrypt an operator-provided value. nix/pkgs/ferrumd wraps them onto
    # PATH already; naming them here too means the unit still works if
    # someone points ExecStart at an unwrapped build.
    path = [ pkgs.sops pkgs.ssh-to-age ];
    # Real runtime check (systemd's own AssertPathExists=) that these two
    # pre-provisioned paths exist on THIS machine before ferrumd starts --
    # replaces an earlier, wrong Nix-eval-time `assertions = [...]` block in
    # this file that this plan's own pre-flight review caught and removed
    # (see the note at the bottom): a plain NixOS assertion using
    # builtins.pathExists checks the machine doing the Nix evaluation, not
    # the machine the unit actually starts on, which would have made every
    # VM test that enables ferrum.daemon fail to even evaluate on a fresh CI
    # runner. AssertPathExists= is checked at real activation time on the
    # real target machine instead -- it fails the unit loudly (logged,
    # visible via `systemctl status`) if nixos-anywhere's initial setup
    # never provisioned these paths, matching the original intended safety
    # property without depending on where evaluation happens to run.
    #
    # IT MUST LIVE IN unitConfig, NOT serviceConfig. AssertPathExists= is a
    # [Unit]-section directive (systemd.unit(5)), and NixOS emits
    # serviceConfig verbatim into [Service] -- where systemd logs "Unknown
    # key name 'AssertPathExists' in section 'Service', ignoring" and starts
    # the unit anyway, silently disabling the whole check. This was the
    # original form of this block and it did nothing at all; the repo's own
    # established idiom for Condition*/Assert* directives is unitConfig (see
    # modules/apps/sonarr/service.nix, modules/core/generations.nix,
    # modules/proxy/selfsigned-cert.nix). tests/daemon-end-to-end.nix now
    # proves the assertion really fires by removing one of these two paths
    # and confirming ferrumd genuinely refuses to start.
    unitConfig.AssertPathExists = [ "/etc/ferrum/settings.json" "/etc/ferrum/secrets" ];
    environment = {
      # NOT /var/lib/ferrum itself. That parent directory also holds
      # root-trusted control files from earlier phases --
      # `state-restore-failed` (the fail-closed marker every app unit and
      # modules/core/generations.nix gate on via ConditionPathExists) and
      # `rollback-intent.json` (read as root at boot by
      # modules/core/state-restore.nix) -- and directory-level write access
      # is delete/create/rename access to all of them regardless of the
      # individual files' own modes. Pointing ferrumd's state dir at a
      # dedicated subdirectory is what lets the parent stay root-owned; see
      # modules/core/storage.nix for the other half.
      FERRUMD_STATE_DIR = "/var/lib/ferrum/daemon";
      FERRUMD_LISTEN_ADDRESS = ferrum.daemon.listenAddress;
      FERRUMD_PORT = toString ferrum.daemon.port;
      FERRUM_SETTINGS_PATH = "/etc/ferrum/settings.json";
      FERRUM_SECRETS_DIR = ferrum.secretsDir;
      FERRUM_HOST_KEY_PUB = "/etc/ssh/ssh_host_ed25519_key.pub";
      FERRUM_JOBS_DIR = "/var/lib/ferrum/jobs";
      FERRUM_REQUESTS_DIR = "/run/ferrum/requests";
      FERRUM_SETTINGS_SCHEMA = "${pkgs.ferrum-settings-schema}/share/ferrum/settings-schema.json";
    };
    serviceConfig = {
      Type = "simple";
      User = "ferrum";
      Group = "ferrum";
      ExecStart = "${pkgs.ferrumd}/bin/ferrumd";
      ProtectSystem = "strict";
      # Exactly the four paths ferrumd genuinely writes, and no parent of
      # any of them. /var/lib/ferrum itself is deliberately absent: see the
      # FERRUMD_STATE_DIR comment above and modules/core/storage.nix -- the
      # parent holds root-trusted control files (state-restore-failed,
      # rollback-intent.json, journal/) that a compromised ferrumd must not
      # be able to create, delete or replace.
      ReadWritePaths = [
        "/var/lib/ferrum/daemon"
        "/var/lib/ferrum/jobs"
        "/etc/ferrum/settings.json"
        "/etc/ferrum/secrets"
        "/run/ferrum"
      ];
      CapabilityBoundingSet = "";
      NoNewPrivileges = true;
      # Containment hardening. None of this is what STOPS ferrumd doing
      # something privileged -- the polkit rule above and the closed
      # request enum in crates/ferrumd/src/jobs.rs are -- it is what limits
      # the blast radius if either is ever bypassed. Each directive below
      # was chosen against what ferrumd genuinely needs at runtime, and all
      # of it is exercised for real by tests/daemon-end-to-end.nix (SQLite
      # under /var/lib/ferrum/daemon, D-Bus over AF_UNIX, the HTTP listener
      # over AF_INET, and the sops/ssh-to-age subprocesses the secrets API
      # forks).
      PrivateTmp = true;
      ProtectHome = true;
      # AF_UNIX for the system D-Bus socket (src/dbus.rs), AF_INET/AF_INET6
      # for ferrumd's own TCP listener. Deliberately no AF_NETLINK and no
      # AF_PACKET: ferrumd has no business enumerating interfaces or
      # opening raw sockets.
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
      # systemd's own curated allow-list for ordinary long-running system
      # services. `~@privileged` and `~@resources` on top is the standard
      # belt-and-braces spelling: @system-service already excludes most of
      # both, and subtracting them explicitly means a future systemd
      # widening the preset doesn't silently widen this unit.
      SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      SystemCallErrorNumber = "EPERM";
      # A daemon that never needs a second personality; blocks a whole
      # class of exploit that flips to a 32-bit ABI to dodge the filter
      # above.
      SystemCallArchitectures = "native";
      LockPersonality = true;
      RestrictSUIDSGID = true;
      RestrictRealtime = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      Restart = "on-failure";
    };
  };

  systemd.tmpfiles.rules = [
    "d /run/ferrum/requests 0750 ferrum ferrum - -"
    # ferrumd's OWN state: its SQLite database (ferrumd.db) and the
    # first-boot bootstrap password file. A dedicated subdirectory, not
    # /var/lib/ferrum itself -- the parent stays root-owned so a
    # compromised ferrumd cannot delete the state-restore-failed marker or
    # forge rollback-intent.json. modules/core/storage.nix creates that
    # parent as `root:ferrum 0750`, which gives this user traverse access
    # to reach here and nothing more (no write bit on the parent means no
    # create, delete or rename of the root-trusted files beside it).
    "d /var/lib/ferrum/daemon 0750 ferrum ferrum - -"
    # Written by ferrum-apply (as root, via the template unit above) and
    # read by ferrumd (as the ferrum user) to serve the SSE progress
    # stream.
    "d /var/lib/ferrum/jobs 0750 ferrum ferrum - -"
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
  # systemd.unit(5) [Unit]-section directive -- NOT a [Service] one, which
  # is why it is set via `unitConfig` above), which is evaluated at REAL
  # activation time on the REAL target machine, not at Nix-eval time -- see
  # the ferrumd unit above, where it is attached to the actual thing that
  # needs these paths rather than to the whole daemon.nix module.
}
