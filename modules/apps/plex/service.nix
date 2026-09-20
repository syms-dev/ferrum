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
  # The plex.tv claim token, when the operator supplied one.
  #
  # A secret rather than a settings value: it associates this server with
  # a Plex account, and settings.json is world-readable by design. Read
  # once by ferrum-reconcile, which claims the server if it is unclaimed;
  # inert afterwards. Claim tokens expire four minutes after issue, so a
  # stale one here is normal and is reported rather than fatal.
  sops.secrets = lib.mkIf (ferrum.secrets ? "plex-claim") {
    "plex-claim" = {
      sopsFile = /. + "${ferrum.secretsDir}/plex-claim.sops";
      format = "binary";
    };
  };

  # Unfree-package allowance for plexmediaserver lives centrally in
  # modules/core/overlays.nix (aggregated from every catalog app's
  # meta.nix `unfreePackages`), not here -- see that file's comment.
  # Setting it per-app doesn't compose once a second unfree app exists.
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
