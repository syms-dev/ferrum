# Prowlarr, wired through the uniform ferrum.apps.prowlarr submodule onto
# nixpkgs' services.prowlarr. Unlike Sonarr/Radarr, the upstream module
# uses DynamicUser -- there is no persistent "prowlarr" user, so (correctly,
# since mediaAccess defaults to "none" for this app) there is no media-group
# wiring here.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.prowlarr or { enable = false; };
in
lib.mkIf app.enable {
  services.prowlarr = {
    enable = true;
    dataDir = app.stateDir;
    settings = {
      server = {
        port = app.port;
        bindaddress = "127.0.0.1";
      };
      log.analyticsenabled = false;
      update.mechanism = "external";
    };
  };

  systemd.services.prowlarr = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
