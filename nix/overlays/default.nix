# The pure ferrum overlay: pkgs.ferrum-apply, pkgs.ferrum-reconcile,
# pkgs.ferrumd, and pkgs.ferrum-testapp.
#
# Single source of truth, imported from both nix/modules/flake/overlays.nix
# (the flake's own `overlays.default` output) and modules/core/overlays.nix
# (`nixpkgs.overlays` inside the NixOS module tree) so there is exactly one
# definition instead of two independently-maintained copies that can drift.
final: prev: {
  ferrum-apply = final.callPackage ../pkgs/ferrum-apply { };
  ferrum-reconcile = final.callPackage ../pkgs/ferrum-reconcile { };
  # modules/core/daemon.nix consumes this. Missing it here is the same
  # class of gap Phase 1.4c's Task 3 found for ferrum-reconcile: the
  # module tree references pkgs.<name> and only fails at eval time on a
  # real host, long after the package itself builds fine.
  ferrumd = final.callPackage ../pkgs/ferrumd { };
  ferrum-testapp = final.callPackage ../pkgs/testapp { };
  ferrum-settings-schema = final.writeTextFile {
    name = "ferrum-settings-schema.json";
    destination = "/share/ferrum/settings-schema.json";
    text = builtins.readFile ../../modules/lib/settings-schema.json;
  };
}
