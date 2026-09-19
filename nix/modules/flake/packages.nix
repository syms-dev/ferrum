# Builds the catalog artifact the ferrumd daemon reads at runtime
# to render the UI from -- see the plan's "How the UI discovers the
# catalog" section. Consumed by ferrumd's GET /api/catalog (Phase 1.5b)
# via $FERRUM_CATALOG, wired in modules/core/daemon.nix;
# publishing it also keeps the catalog schema honest as apps are added.
{ inputs, ... }:
{
  perSystem = { config, pkgs, lib, ... }:
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
        # Deliberately NOT in nix/overlays/default.nix, unlike every
        # package above it. The overlay exists so `pkgs.<name>` resolves
        # from inside the NixOS module tree; nothing in modules/ references
        # the installer and nothing can, because by the time a host is
        # being evaluated this binary's work is finished. See the package's
        # own header.
        ferrum-install = pkgs.callPackage ../../../nix/pkgs/ferrum-install {
          nixos-anywhere = inputs.nixos-anywhere.packages.${pkgs.stdenv.hostPlatform.system}.default;
          # Same source as ferrum-catalog's ferrumVersion above. A generated
          # host pins this exact revision, so the installed machine and the
          # tool that installed it provably agree.
          ferrumRev = inputs.self.rev or inputs.self.dirtyRev or "dev";
        };
        ferrum-install-image = pkgs.callPackage ../../../nix/pkgs/ferrum-install/image.nix {
          ferrum-install = config.packages.ferrum-install;
        };
        # Also present in nix/overlays/default.nix -- modules/core/daemon.nix
        # reads pkgs.ferrum-ui, and a package defined ONLY here builds fine
        # and then fails at host eval with "attribute missing". That has now
        # happened three times in this repo; see the package's own comment.
        ferrum-ui = pkgs.callPackage ../../../nix/pkgs/ferrum-ui {
          uiSrc = ../../../ui;
        };
        ferrum-settings-schema = pkgs.writeTextFile {
          name = "ferrum-settings-schema.json";
          destination = "/share/ferrum/settings-schema.json";
          text = builtins.readFile ../../../modules/lib/settings-schema.json;
        };
      };
    };
}
