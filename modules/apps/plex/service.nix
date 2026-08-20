# Plex, wired through the uniform ferrum.apps.plex submodule onto nixpkgs'
# services.plex. The claim-token mechanism (see this file's meta.nix
# comment) sets PLEX_CLAIM only when a token has been pasted -- an
# already-claimed server keeps running fine with an empty or stale token
# present, since Plex only consumes PLEX_CLAIM during the initial claim.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.plex or { enable = false; };
  claimToken = app.settings.claimToken or "";
in
lib.mkIf app.enable {
  # nixpkgs' plexmediaserver package is licensed unfree; without this, the
  # ENTIRE host config fails to evaluate the moment ferrum.apps.plex.enable
  # is true, on any real host. Scoped to just this one package, not a
  # blanket `nixpkgs.config.allowUnfree = true`.
  nixpkgs.config.allowUnfreePredicate = pkg:
    builtins.elem (lib.getName pkg) [ "plexmediaserver" ];

  services.plex = {
    enable = true;
    dataDir = app.stateDir;
    user = "plex";
    group = "plex";
  };

  users.users.plex.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.plex = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    # Merges into the base plex module's own environment (PLEX_DATADIR,
    # PLEX_PLUGINS, etc.) rather than replacing it -- environment is an
    # attrsOf option, and NixOS merges definitions from multiple modules.
    environment = lib.mkIf (claimToken != "") {
      PLEX_CLAIM = claimToken;
    };
    serviceConfig = lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    };
  };
}
