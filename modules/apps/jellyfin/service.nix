# Jellyfin, wired through the uniform ferrum.apps.jellyfin submodule onto
# nixpkgs' services.jellyfin. No API key / claim mechanism needed -- unlike
# Plex, Jellyfin has no external account requirement.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.jellyfin or { enable = false; };
in
lib.mkIf app.enable {
  services.jellyfin = {
    enable = true;
    dataDir = app.stateDir;
    user = "jellyfin";
    group = "jellyfin";
  };

  users.users.jellyfin.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.jellyfin = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
