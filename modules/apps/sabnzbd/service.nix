# SABnzbd, wired through the uniform ferrum.apps.sabnzbd submodule onto
# nixpkgs' services.sabnzbd. The upstream module hardcodes
# serviceConfig.StateDirectory = "sabnzbd" (always /var/lib/sabnzbd, no
# relocation option) -- overridden here via lib.mkForce null so SABnzbd's
# actual data lives under app.stateDir like every other app in this
# catalog, participating in the rollback mechanism the same way. Since
# removing StateDirectory means systemd no longer creates that directory
# for us, this module provisions app.stateDir itself via tmpfiles, the
# same way modules/core/storage.nix provisions ferrum.storage.stateDir.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.sabnzbd or { enable = false; };
in
lib.mkIf app.enable {
  services.sabnzbd = {
    enable = true;
    user = "sabnzbd";
    group = "sabnzbd";
    configFile = "${app.stateDir}/sabnzbd.ini";
  };

  systemd.tmpfiles.rules = [
    "d ${app.stateDir} 0750 sabnzbd sabnzbd - -"
  ];

  users.users.sabnzbd.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.sabnzbd = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = (lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    }) // {
      StateDirectory = lib.mkForce null;
    };
  };
}
