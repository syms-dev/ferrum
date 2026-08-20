# qBittorrent, wired through the uniform ferrum.apps.qbittorrent submodule
# onto nixpkgs' services.qbittorrent. VPN gating (Task 7) extends this
# same file -- this version runs qBittorrent on the host's normal network,
# no isolation yet.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.qbittorrent or { enable = false; };
in
lib.mkIf app.enable {
  services.qbittorrent = {
    enable = true;
    profileDir = app.stateDir;
    user = "qbittorrent";
    group = "qbittorrent";
    webuiPort = app.port;
  };

  users.users.qbittorrent.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.qbittorrent = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
