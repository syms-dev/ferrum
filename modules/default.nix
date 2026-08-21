# The ferrum NixOS module. Import this once from a host flake (normally via
# ferrum.lib.mkHost) to get the whole ferrum.* option namespace plus every
# app in the catalog, each gated on its own ferrum.apps.<id>.enable.
{ ... }:
{
  imports = [
    ./core/options.nix
    ./core/storage.nix
    ./core/overlays.nix
    ./core/generations.nix
    ./core/state-restore.nix
    ./core/secrets.nix
    ./core/recyclarr.nix
    ./proxy/acme.nix
    ./proxy/nginx.nix
    ./proxy/selfsigned-cert.nix
    ./proxy/authelia.nix
    ./apps/sonarr/service.nix
    ./apps/radarr/service.nix
    ./apps/prowlarr/service.nix
    ./apps/jellyfin/service.nix
    ./apps/plex/service.nix
    ./apps/sabnzbd/service.nix
    ./apps/qbittorrent/service.nix
  ];
}
