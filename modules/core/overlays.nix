# Wire the ferrum overlay into nixpkgs so that pkgs.ferrum-apply and
# pkgs.ferrum-testapp are available to the modules.
{ config, ... }:
{
  config.nixpkgs.overlays = [ config.flake.overlays.default ];
}
