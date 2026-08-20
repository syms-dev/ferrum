{ ... }:
{
  flake.overlays.default = final: prev: {
    ferrum-apply = final.callPackage ../../pkgs/ferrum-apply { };
    ferrum-testapp = final.callPackage ../../pkgs/testapp { };
  };
}
