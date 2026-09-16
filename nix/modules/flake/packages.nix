# Builds the catalog artifact the ferrumd daemon reads at runtime
# to render the UI from -- see the plan's "How the UI discovers the
# catalog" section. Consumed by ferrumd's GET /api/catalog (Phase 1.5b)
# via $FERRUM_CATALOG, wired in modules/core/daemon.nix;
# publishing it also keeps the catalog schema honest as apps are added.
{ inputs, ... }:
{
  perSystem = { pkgs, lib, ... }:
    let
      catalog = import ../../../modules/lib/catalog.nix { inherit lib; };
    in
    {
      packages = {
        ferrum-catalog = pkgs.writeTextFile {
          name = "ferrum-catalog.json";
          destination = "/share/ferrum/catalog.json";
          text = builtins.toJSON {
            schemaVersion = 1;
            ferrumVersion = inputs.self.shortRev or inputs.self.dirtyShortRev or "dev";
            apps = catalog;
          };
        };
        ferrum-testapp = pkgs.callPackage ../../../nix/pkgs/testapp { };
        ferrum-apply = pkgs.callPackage ../../../nix/pkgs/ferrum-apply { };
        ferrum-reconcile = pkgs.callPackage ../../../nix/pkgs/ferrum-reconcile { };
        ferrumd = pkgs.callPackage ../../../nix/pkgs/ferrumd { };
        ferrum-settings-schema = pkgs.writeTextFile {
          name = "ferrum-settings-schema.json";
          destination = "/share/ferrum/settings-schema.json";
          text = builtins.readFile ../../../modules/lib/settings-schema.json;
        };
      };
    };
}
