# Builds the catalog artifact the (future) ferrumd daemon reads at runtime
# to render the UI from -- see the plan's "How the UI discovers the
# catalog" section. Nothing consumes this yet (ferrumd is Phase 1.5), but
# publishing it now keeps the catalog schema honest as apps are added.
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
      };
    };
}
