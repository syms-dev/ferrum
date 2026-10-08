# Decluttarr, wired through the uniform ferrum.apps.decluttarr submodule onto
# pkgs.decluttarr (nix/pkgs/decluttarr -- not in nixpkgs, so ferrum builds it).
#
# ============================================================================
# WHY THIS FILE GENERATES THE WHOLE CONFIGURATION
# ============================================================================
#
# Decluttarr's own instructions are: write a config.yaml naming every *arr's
# URL and API key, every download client's URL and the NAME that client is
# registered under inside each *arr. On a ferrum host every one of those
# facts is already ferrum's: the ports come from ferrum.apps.<id>.port, the
# addresses from modules/lib/app-address.nix, the keys are sops secrets
# ferrum-apply generated before the build, and the download-client name is
# the literal ferrum-reconcile POSTs into Sonarr and Radarr. An operator
# asked to copy those into a YAML file is being asked to re-derive, by hand
# and without checking, things the machine already knows -- and to paste an
# API key into a file while doing it.
#
# So the operator writes nothing. `ferrum.apps.decluttarr.enable = true` is
# the whole interface.
#
# EVAL-TIME GENERATION (RECYCLARR), NOT integrations.consumes (RECONCILER).
#
# ferrum has exactly two existing mechanisms for "ferrum configures a tool on
# the operator's behalf", and this reuses the second rather than inventing a
# third:
#
#   * modules/core/reconciler.nix -- RUNTIME. It POSTs registrations into
#     other apps' APIs, driven by meta.nix's integrations.consumes/providesTo.
#     Wrong here on both halves. Decluttarr registers nothing into Sonarr,
#     and exposes no API for ferrum-reconcile to register anything into; a
#     `consumes` edge would make the reconciler POST a download-client body
#     at an endpoint that does not exist. It would also force a symmetric
#     `providesTo = [ "decluttarr" ]` into sonarr's and radarr's meta.nix,
#     because reconciler.nix asserts that symmetry across the WHOLE catalog
#     at eval time.
#
#   * modules/core/recyclarr.nix -- EVAL TIME. It builds a configuration
#     value out of ferrum.apps.<id>.port and a sops secret path, and hands
#     it to a unit. That is exactly this problem, so that is the pattern.
#
# The one place Recyclarr's shape does not carry over is the secret. nixpkgs'
# services.recyclarr has an `_secret` indirection that substitutes a file's
# contents at activation; Decluttarr has nothing equivalent, and a key
# interpolated into Nix would land in the WORLD-READABLE store -- including
# in `systemd.services.<n>.environment`, which is written into the unit file
# verbatim. Hence the split below: a secret-free template in the store, and
# a root-only ExecStartPre that inserts the keys into a tmpfs copy at start.
#
# THE FILE IS JSON, AND IS NAMED .yaml ON PURPOSE. YAML is a superset of
# JSON, Decluttarr parses the file with `yaml.load` (src/settings/
# _user_config.py), and builtins.toJSON gets every quoting and escaping
# question right for free. It also makes each API key an unambiguous JSON
# string: a 32-char hex key that happened to be all digits would be read as
# an INTEGER by a bare YAML scalar, which is a one-in-a-million silent auth
# failure that no amount of care at the insertion point would catch.
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.decluttarr or { enable = false; };
  catalog = import ../../lib/catalog.nix { inherit lib; };

  # Where an app ACTUALLY listens as seen from the root namespace. Read from
  # the shared helper rather than assuming 127.0.0.1, for the reason that
  # file's own header gives: qBittorrent is behind a veth pair whenever a
  # "qbittorrent-vpn" secret exists, and the one consumer that hand-copied
  # the loopback literal is the defect 2ec53b6 fixed. Decluttarr is the
  # third consumer, and it is the one that would be hardest to notice: it
  # does not 502, it just logs "not reachable" every half hour and quietly
  # stops protecting anything.
  appHost = (import ../../lib/app-address.nix { inherit lib; }).hostFor ferrum;

  enabled = id: ferrum.apps.${id}.enable or false;
  baseUrlFor = id: "http://${appHost id}:${toString ferrum.apps.${id}.port}";

  # The *arrs Decluttarr understands AND ferrum ships. Upstream also knows
  # lidarr, readarr, whisparr and sportarr; ferrum's catalog has none of
  # them, so listing them here would be describing a host that cannot exist.
  arrIds = builtins.filter enabled [ "sonarr" "radarr" ];

  # The bare-value API-key secret for each, matching the names
  # modules/apps/<id>/service.nix declares and modules/core/reconciler.nix
  # already reads. "-raw" is the bare key; the unsuffixed secret is an
  # environmentFile holding "SONARR__AUTH__APIKEY=<key>", which is not a key.
  keySecretOf = id: "${id}-apikey-raw";

  settings = app.settings or { };
  testRun = settings.testRun or false;
  intervalMinutes = settings.intervalMinutes or 30;
  maxStrikes = settings.maxStrikes or 5;
  logLevel = settings.logLevel or "VERBOSE";

  # ------------------------------------------------------------------
  # The generated configuration, minus the API keys.
  # ------------------------------------------------------------------
  #
  # Every default below is deliberately on the cautious side of the line,
  # because the failure modes are not symmetric: a stuck torrent left in the
  # queue costs the operator a little patience, and a wanted download deleted
  # by a tool they did not ask to be clever costs them the download, the
  # blocklist entry that stops it coming back, and their trust in the box.
  configWithoutKeys = {
    general = {
      # VERBOSE, not INFO. At INFO the journal records THAT a download was
      # removed and its title (src/jobs/removal_handler.py's
      # _remove_download); the per-item REASON -- the queue message that
      # matched, the strike count that was reached -- is logged one level
      # down, at VERBOSE. For a tool whose entire job is deleting things,
      # "what did it do" without "why" is not an audit trail. Measured on
      # the real binary: at VERBOSE a single pass prints the active job
      # list, every instance's reachability, and the reason line per item.
      log_level = logLevel;

      # false, so it actually solves the problem it was installed for.
      # `testRun = true` is one UI toggle away (meta.nix's settingsSchema)
      # for an operator who wants to watch it for a week first, and the
      # banner it prints in that mode is impossible to miss.
      test_run = testRun;

      # 30 minutes, not upstream's 10. The interval multiplies with
      # max_strikes to produce the only number that actually matters here --
      # how long something must look broken before it is deleted -- and 5
      # strikes at 30 minutes is about two and a half hours. At upstream's
      # 10/3 it is half an hour, which is comfortably inside the window a
      # real torrent can sit at zero peers before recovering, and inside the
      # window a slow *arr import can still be running.
      timer = intervalMinutes;

      # A torrent from a private tracker is one the operator may be seeding
      # for ratio, and on most private trackers losing it costs more than any
      # stuck queue entry. "remove_from_queue" unblocks the *arr -- the queue
      # item goes away and the release is blocklisted so a search finds a
      # different one -- while the torrent itself is left alone in
      # qBittorrent. Public trackers get the plain "remove", where deleting
      # the data is free.
      #
      # Both of these are only consulted when a qBittorrent client is
      # configured below; with none, src/settings/_download_clients.py
      # unsets them and everything is a plain remove.
      private_tracker_handling = "remove_from_queue";
      public_tracker_handling = "remove";

      # The operator's manual override, and the reason qBittorrent is
      # configured at all (see below). A torrent tagged "Keep" in
      # qBittorrent is filtered out of every job's candidate list before
      # any decision is made (src/jobs/removal_job.py's _ignore_protected).
      # Named explicitly rather than left to upstream's default so
      # README.md can tell an operator the exact string to type.
      protected_tag = "Keep";
    };

    job_defaults = {
      # 5, not upstream's 3. See `timer` above for the arithmetic. A strike
      # is one observation, and observations of a download client are noisy:
      # a seedbox pause, a tracker hiccup, or an *arr restart mid-pass all
      # look like "stalled" for one cycle.
      max_strikes = maxStrikes;
    };

    # Only jobs that are DISABLED by default upstream and that ferrum turns
    # on are listed; a job absent from this attrset stays off
    # (src/settings/_jobs.py sets every JobParams to enabled = false and
    # only a key present here flips it). The four below are the ones that
    # address the problem Decluttarr was asked for -- a download that cannot
    # be imported and sits in the client forever -- and nothing else.
    jobs = {
      # The download client itself reported the download as failed. There is
      # nothing to preserve and no judgement being made.
      remove_failed_downloads.enabled = true;

      # THE one that answers ".exe arrived instead of a video". The *arr has
      # finished downloading, tried to import, and refused with a reason.
      #
      # message_patterns is pinned to this explicit list rather than left at
      # upstream's `["*"]` default, and that is the single most important
      # conservative choice in this file: `*` means "remove on ANY import
      # warning", which includes transient ones like a disk being
      # temporarily unwritable or a path not yet mounted. These six are the
      # patterns upstream's own config_example.yaml ships, each of which
      # describes a release that will NEVER import however long it is left.
      remove_failed_imports = {
        enabled = true;
        message_patterns = [
          "Not a Custom Format upgrade for existing*"
          "Not an upgrade for existing*"
          "*Found potentially dangerous file with extension*"
          "Invalid video file*"
          "No files found are eligible for import*"
          "One or more episodes expected in this release were not imported or missing from the release"
        ];
      };

      # A magnet link whose metadata never arrives. It cannot progress and
      # it holds a queue slot.
      remove_metadata_missing.enabled = true;

      # "The download is stalled with no connections", for max_strikes
      # consecutive passes.
      remove_stalled.enabled = true;
    };

    instances = lib.listToAttrs (map
      (id: {
        name = id;
        # A list, because upstream supports several instances of each kind.
        # ferrum's catalog has exactly one of each, so exactly one entry.
        # api_key is inserted at start by the ExecStartPre below; the
        # placeholder is here so the jq path exists and so a leak of this
        # store file reveals nothing.
        value = [{
          base_url = baseUrlFor id;
          api_key = "";
        }];
      })
      arrIds);

    download_clients = lib.optionalAttrs (enabled "qbittorrent") {
      qbittorrent = [{
        base_url = baseUrlFor "qbittorrent";

        # MUST equal the name the download client is registered under in
        # Sonarr and Radarr, or Decluttarr cannot match a queue item to the
        # client holding it. crates/ferrum-reconcile/src/main.rs posts
        # `"name": provider_id` -- the literal catalog id -- so the correct
        # value is "qbittorrent", and it is spelled from the catalog here
        # rather than typed, so a future rename moves both ends at once.
        # nix/modules/flake/checks.nix's decluttarr-knows-the-client-ferrum-
        # registered holds the two together.
        name = catalog.qbittorrent.id;

        # No credential, and none is needed: modules/apps/qbittorrent/
        # service.nix sets WebUI\LocalHostAuth = false, and on a
        # VPN-namespaced host additionally whitelists the 10.200.1.0/30 veth
        # the root namespace reaches it over. Decluttarr's own login POST
        # with empty credentials is accepted on both paths for that reason.
      }];
    };

    # SABnzbd is deliberately NOT configured, and this is a decision rather
    # than an omission.
    #
    # None of the four jobs above needs it: each acts on the *arr's queue
    # and the *arr issues the removal through its own client connection.
    # What configuring it WOULD do is put the SABnzbd API key into the
    # journal -- upstream calls it as `/api?mode=version&apikey=<key>` and
    # logs the failing URL verbatim on any connection error. Measured
    # against the real binary during this work: one unreachable SABnzbd
    # printed the key three times in the first thirty seconds.
  };

  configTemplate = pkgs.writeText "decluttarr-config-template.json"
    (builtins.toJSON configWithoutKeys);

  # jq, not sed or shell interpolation. --rawfile reads a secret straight
  # off disk into a jq string with no quoting, globbing, word-splitting or
  # regex-metacharacter surface anywhere, and the result is re-serialised as
  # a JSON string. The only transformation is stripping trailing whitespace,
  # because a key written with a trailing newline would be sent as part of
  # the Authorization value.
  keyArgs = lib.concatMapStringsSep " "
    (id: "--rawfile ${id}_key ${lib.escapeShellArg config.sops.secrets.${keySecretOf id}.path}")
    arrIds;

  # Built by concatenation rather than as one interpolated string: the jq
  # VARIABLE reference needs a literal "$" immediately before an
  # interpolated app id, and `$${id}` inside a Nix string is not that -- it
  # renders the four characters `$${` and jq rejects the filter at compile
  # time. (Found by running the real pre-start script, which is the only
  # thing that would have: the filter is a string to Nix and to the shell,
  # so nothing before jq itself can object to it.)
  keyFilter = lib.concatMapStringsSep " | "
    (id: ".instances." + id + "[0].api_key = ($" + id + ''_key | sub("\\s+$"; ""))'')
    arrIds;

  # Runs with full privileges (the `+` prefix on the ExecStartPre line), for
  # the same reason modules/core/reconciler.nix runs as root: sops-nix's
  # default secret ownership is root:root 0400, and the per-app keys are
  # additionally owned by the app they belong to. Giving decluttarr read
  # access to Sonarr's and Radarr's keys instead would mean widening two
  # other apps' secrets for a process that only needs them for the one
  # second it takes to write this file.
  renderConfig = pkgs.writeShellScript "decluttarr-render-config" ''
    set -euo pipefail
    umask 077
    out="$RUNTIME_DIRECTORY/config.yaml"
    ${pkgs.jq}/bin/jq ${keyArgs} ${lib.escapeShellArg keyFilter} ${configTemplate} > "$out"
    chown decluttarr:decluttarr "$out"
    chmod 0400 "$out"
  '';
in
lib.mkIf app.enable {
  assertions = [
    {
      # Decluttarr acts on *arr queues and has no other input. With neither
      # Sonarr nor Radarr enabled its own startup check calls wait_and_exit()
      # (src/settings/_instances.py's check_any_arrs), so the unit would
      # fail on every start -- and `ferrum-apply apply` would report the
      # whole host Degraded, because every unit under ferrum-apps.target has
      # to be active.
      #
      # An assertion rather than quietly declining to enable the service,
      # the same call modules/core/recyclarr.nix makes and for the same
      # reason: those are different statements to the person who flipped the
      # switch. Reachable from PUT /api/settings, where enabling Decluttarr
      # and enabling an *arr are two toggles in either order.
      assertion = arrIds != [ ];
      message = ''
        ferrum.apps.decluttarr.enable is on, but neither ferrum.apps.sonarr
        nor ferrum.apps.radarr is enabled.

        Decluttarr works by reading those applications' download queues and
        acting on what it finds there; it has no other source of work. With
        neither of them present it refuses to start at all, which on a
        ferrum host means every apply reports Degraded -- ferrum-apps.target
        requires each of its members to be active.

        Enable ferrum.apps.sonarr or ferrum.apps.radarr, or set
        ferrum.apps.decluttarr.enable = false.
      '';
    }
    {
      # Below 5 minutes this stops being a janitor and becomes a load
      # generator: every pass is a full queue fetch against each *arr plus a
      # torrent listing from qBittorrent.
      #
      # The isInt term is not decoration and `&&` short-circuits in Nix, so
      # it has to come first: `ferrum.apps.<id>.settings` is typed
      # attrsOf (oneOf [ bool int str (listOf str) ]) -- deliberately, so
      # the UI can write any JSON scalar -- which means a hand-edited
      # settings.json can put a STRING here. Comparing a string with an
      # integer is a hard Nix evaluation error, raised far from this option
      # and naming neither it nor the file the value came from.
      assertion = builtins.isInt intervalMinutes && intervalMinutes >= 5;
      message = ''
        ferrum.apps.decluttarr.settings.intervalMinutes is
        ${builtins.toJSON intervalMinutes}, and it must be a whole number of
        minutes, at least 5.

        Each pass fetches the full queue from every *arr and the full
        torrent list from qBittorrent. Below five minutes that is a
        continuous load on the applications it is supposed to be tidying,
        and it shortens the patience window (intervalMinutes x maxStrikes)
        that stops a momentary stall being read as a dead download.
      '';
    }
    {
      # isInt first, for the reason above.
      assertion = builtins.isInt maxStrikes && maxStrikes >= 1;
      message = ''
        ferrum.apps.decluttarr.settings.maxStrikes is
        ${builtins.toJSON maxStrikes}, and it must be a whole number, at
        least 1.

        A strike is one observation. maxStrikes = 1 already means "delete on
        the first pass that looks wrong", with no second look; anything
        lower is not a weaker setting, it is a nonsensical one. The default
        is 5, which with the default interval is about two and a half hours
        of consecutive bad observations before anything is removed.
      '';
    }
  ];

  users.users.decluttarr = {
    isSystemUser = true;
    group = "decluttarr";
    description = "Decluttarr";
    home = app.stateDir;
  };
  users.groups.decluttarr = { };

  # Rotating an *arr's API key has to restart this too, or Decluttarr keeps
  # authenticating with the key it read at its last start and simply stops
  # working. sops-nix's decrypted-secret PATH is invariant under a content
  # change, so switch-to-configuration has nothing else to notice -- the
  # same mechanism, and the same reasoning, as the restartUnits in
  # modules/apps/sonarr/service.nix. These are list-valued merges onto the
  # secrets those modules declare, not re-declarations: the mkIf is what
  # keeps this from naming a secret that does not exist on a host without
  # the corresponding app.
  sops.secrets = lib.listToAttrs (map
    (id: { name = keySecretOf id; value.restartUnits = [ "decluttarr.service" ]; })
    arrIds);

  # 0750 and decluttarr-owned, matching every other app's stateDir under the
  # 0751 root modules/core/storage.nix creates for exactly this.
  #
  # The `config` entry is a SYMLINK into the runtime directory, which is the
  # join between two constraints that cannot both be satisfied in one place:
  # upstream resolves ./config/config.yaml and ./logs/logs.txt relative to
  # the working directory (src/settings/_constants.py's `Paths`, neither
  # path configurable), while the rendered config contains API keys and must
  # therefore never be written to stateDir -- which is btrfs-snapshotted
  # into every rollback point this product exists to provide. So logs live
  # in stateDir and are kept, and the config lives on tmpfs in
  # /run/decluttarr and is destroyed when the unit stops.
  systemd.tmpfiles.rules = [
    "d ${app.stateDir} 0750 decluttarr decluttarr - -"
    "d ${app.stateDir}/logs 0750 decluttarr decluttarr - -"
    "L+ ${app.stateDir}/config - - - - /run/decluttarr"
  ];

  systemd.services.decluttarr = {
    description = "Decluttarr -- clear stuck downloads out of the *arr queues";
    # Pulled in by ferrum-apps.target rather than multi-user.target, so
    # `systemctl stop ferrum-apps.target` (what apply does before every
    # snapshot) actually controls it.
    wantedBy = [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    # Every app service carries this itself, not just the target: start
    # propagation from a target does NOT consult the target's own
    # ConditionPathExists. See modules/core/generations.nix.
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";

    # Ordering only, never a dependency. Decluttarr marks an unreachable
    # instance degraded and retries it at the top of every cycle
    # (src/utils/startup.py's retry_degraded_instances) rather than failing,
    # so starting early costs one logged "not reachable" line and nothing
    # else -- confirmed against the real binary, which stayed alive through
    # a full cycle with every configured endpoint refusing connections.
    after = map (id: "${id}.service") arrIds
      ++ lib.optional (enabled "qbittorrent") "qbittorrent.service";

    serviceConfig = (lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    }) // {
      Type = "simple";
      User = "decluttarr";
      Group = "decluttarr";
      WorkingDirectory = app.stateDir;
      # Created before ExecStartPre runs and removed when the unit stops,
      # which is what makes the decrypted config short-lived rather than
      # merely hidden.
      RuntimeDirectory = "decluttarr";
      RuntimeDirectoryMode = "0750";
      # `+` runs this one step with full privileges while ExecStart stays as
      # the decluttarr user -- it is the only thing here that needs to read
      # another app's root-owned secret.
      ExecStartPre = "+${renderConfig}";
      ExecStart = lib.getExe pkgs.decluttarr;
      # It is a sleep loop around network calls; anything that kills it is
      # transient by construction, and the alternative to restarting is a
      # silently absent janitor.
      Restart = "on-failure";
      RestartSec = 30;
      # Upstream installs a SIGTERM handler that stops its filesystem
      # watchers and exits 0 (main.py's `terminate`), so the default
      # KillSignal is already the clean path.
      NoNewPrivileges = true;
      ProtectHome = true;
      PrivateTmp = true;
    };
  };
}
