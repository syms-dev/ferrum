# Wire the ferrum overlay into nixpkgs so that pkgs.ferrum-apply and
# pkgs.ferrum-testapp are available to the other modules in this tree.
#
# Defined directly rather than reusing nix/modules/flake/overlays.nix's
# `flake.overlays.default`: that value lives in flake-parts' own `config`,
# a different module system evaluated at the flake level -- there is no
# `config.flake` inside a NixOS configuration (this module's `config` is
# the system configuration tree, e.g. `config.systemd.services...`, not
# the flake's own outputs), so a NixOS module can't reach it that way.
{ ... }:
{
  nixpkgs.overlays = [
    (final: prev: {
      ferrum-apply = final.callPackage ../../nix/pkgs/ferrum-apply { };
      ferrum-testapp = final.callPackage ../../nix/pkgs/testapp { };
    })
  ];
}
