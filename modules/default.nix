# The ferrum NixOS module. Import this once from a host flake (normally via
# ferrum.lib.mkHost) to get the whole ferrum.* option namespace plus every
# app in the catalog, each gated on its own ferrum.apps.<id>.enable.
{ ... }:
{
  imports = [
    ./core/options.nix
    ./core/storage.nix
    ./core/generations.nix
    ./apps/sonarr/service.nix
  ];
}
