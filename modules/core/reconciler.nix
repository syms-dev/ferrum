# Generates the JSON config crates/ferrum-reconcile reads (per-app
# connection info + a pre-validated, pre-computed list of registration
# pairs), and the systemd oneshot that runs it after every
# ferrum-apps.target start -- matching the spec's own "re-runs on any
# target restart, not only after an explicit config change" requirement,
# so a crash recovery or a rollback's state-restore cycle re-syncs
# registrations too.
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
  catalog = import ../lib/catalog.nix { inherit lib; };
  enabledApps = lib.filterAttrs (_: app: app.enable) ferrum.apps;

  # qBittorrent's real reachable address depends on whether the VPN kill
  # switch (Phase 1.3/1.4a) put it in an isolated network namespace --
  # confirmed by reading modules/apps/qbittorrent/service.nix's own
  # qbt-vpn-netns-setup script: the veth pair's host-reachable side is a
  # hardcoded 10.200.1.2. Every other app always runs in the root
  # namespace, always reachable at 127.0.0.1.
  vpnEnabled = ferrum.secrets ? "qbittorrent-vpn";
  appHost = id: if id == "qbittorrent" && vpnEnabled then "10.200.1.2" else "127.0.0.1";

  # Which apps have a reconciler-usable bare-value API key, and under what
  # secret name (Task 1). qBittorrent needs none (LocalHostAuth = false).
  appKeySecretName = id:
    if lib.elem id [ "sonarr" "radarr" "prowlarr" ] then "${id}-apikey-raw"
    else if id == "sabnzbd" then "sabnzbd-apikey"
    else null;

  appConnInfo = id: app: {
    host = appHost id;
    port = app.port;
    apiKeySecretPath =
      let name = appKeySecretName id;
      in if name != null then config.sops.secrets.${name}.path else null;
  };

  # Validates providesTo/consumes symmetry across the WHOLE catalog (every
  # app's meta.nix, not just enabled ones -- a metadata bug should fail
  # eval regardless of which subset of apps a given host happens to
  # enable). Extends the same "catch a real bug at eval time, not at
  # registration time" spirit as checks.catalog-consistency
  # (nix/modules/flake/checks.nix), for the metadata this plan is the
  # first thing to actually ACT on.
  symmetryErrors = lib.flatten (lib.mapAttrsToList
    (id: meta:
      (map
        (p: if !(lib.elem id (catalog.${p}.integrations.consumes or [ ])) then
          "modules/apps/${id}/meta.nix declares integrations.providesTo \"${p}\", but ${p}'s own meta.nix integrations.consumes does not list \"${id}\""
        else null)
        (meta.integrations.providesTo or [ ]))
      ++ (map
        (c: if !(lib.elem id (catalog.${c}.integrations.providesTo or [ ])) then
          "modules/apps/${id}/meta.nix declares integrations.consumes \"${c}\", but ${c}'s own meta.nix integrations.providesTo does not list \"${id}\""
        else null)
        (meta.integrations.consumes or [ ])))
    catalog);
  realSymmetryErrors = builtins.filter (x: x != null) symmetryErrors;

  # Two registration kinds (matching the spec's own "exactly two" scope
  # decision): Prowlarr registering Sonarr/Radarr is "application" (its
  # own indexer push-sync feature); every other consumes/providesTo edge
  # is "downloadClient".
  pairKind = consumer: provider:
    if consumer == "prowlarr" && lib.elem provider [ "sonarr" "radarr" ]
    then "application"
    else "downloadClient";

  pairs = lib.flatten (lib.mapAttrsToList
    (id: _:
      map
        (providerId: { kind = pairKind id providerId; consumer = id; provider = providerId; })
        (builtins.filter (p: enabledApps ? ${p}) (catalog.${id}.integrations.consumes or [ ])))
    enabledApps);

  reconcileConfigFile = pkgs.writeText "ferrum-reconcile-config.json" (builtins.toJSON {
    apps = lib.mapAttrs appConnInfo enabledApps;
    inherit pairs;
  });
in
{
  assertions = map (msg: { assertion = false; message = msg; }) realSymmetryErrors;

  systemd.services.ferrum-reconcile = lib.mkIf (pairs != [ ]) {
    description = "Register download clients and indexer applications across the catalog";
    after = [ "ferrum-apps.target" ];
    wantedBy = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    environment.FERRUM_RECONCILE_CONFIG = "${reconcileConfigFile}";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.ferrum-reconcile}/bin/ferrum-reconcile";
      # Runs as root: sops-nix's own default secret ownership is root:root,
      # and this oneshot's whole job is reading a handful of already-
      # decrypted secret files plus making HTTP calls to already
      # localhost-only-reachable services -- the same trust level
      # ferrum-apply and ferrum-state-restore already run at, for the
      # same reason (privileged coordination, not privilege escalation
      # over untrusted input). A deliberate scope decision, not an
      # oversight: giving this its own non-root user would mean adding
      # owner=/group= overrides to every secret Task 1 generates, for no
      # real security benefit given what this binary actually does.
    };
  };
}
