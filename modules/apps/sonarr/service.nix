# Sonarr, wired through the uniform ferrum.apps.sonarr submodule onto
# nixpkgs' services.sonarr (part of the shared servarr framework -- see
# nixos/modules/services/misc/servarr/ upstream).
#
# Phase 1.1 scope only: no ferrum.secrets/sops wiring yet (that lands with
# modules/core/secrets.nix in Phase 1.4), so services.sonarr.environmentFiles
# is left unset and Sonarr will generate its own API key on first start, the
# same as a stock install. Once secrets exist, ferrum chooses the API key
# up front instead -- see the plan's note on the servarr framework making
# declarative cross-app registration possible.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.sonarr or { enable = false; };
in
lib.mkIf app.enable {
  services.sonarr = {
    enable = true;
    dataDir = app.stateDir;
    user = "sonarr";
    group = "sonarr";
    openFirewall = false;
    settings = {
      server = {
        port = app.port;
        bindaddress = "127.0.0.1";
      } // lib.optionalAttrs (app.settings ? urlBase && app.settings.urlBase != "") {
        urlbase = app.settings.urlBase;
      };
      log.analyticsenabled = false;
      update.mechanism = "external";
    };
  };

  users.users.sonarr.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.sonarr = {
    # Pulled in by ferrum-apps.target instead of multi-user.target directly,
    # so `systemctl stop ferrum-apps.target` (what apply does before every
    # snapshot) actually controls it.
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
