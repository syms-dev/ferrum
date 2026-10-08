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
    } // lib.optionalAttrs (app.mediaAccess != "none") {
      # The other half of the shared-tree recipe modules/core/storage.nix's
      # tmpfiles rules carry the setgid half of. Same predicate as the
      # media-group membership above, because it is the same fact: a unit in
      # that group creates files in the shared tree, and 0002 is what keeps
      # them group-WRITABLE -- systemd's default 0022 leaves them group-read-
      # only, so another app can import from them and then never delete
      # them. See storage.nix for the whole failure.
      # mkForce because nixpkgs' own jellyfin module sets UMask = "0077",
      # which is stricter than systemd's default and makes Jellyfin's writes
      # into the shared tree unreadable by the group entirely.
      UMask = lib.mkForce "0002";
    };
  };
}
