# The guardrail checks that keep the architecture honest, plus the trivial
# smoke VM test that answers Phase 1.0 probe 0.1 (does a NixOS VM test even
# run on a hosted GitHub runner?).
#
# NOTE: written without access to a local nix install (see the plan's dev
# environment section) -- this has not been evaluated locally. The first
# `nix flake check` in CI is the first real test of this file.
{ inputs, ... }:
{
  perSystem = { system, pkgs, lib, ... }:
    let
      ferrumLib = import ../../../modules/lib { nixpkgs = inputs.nixpkgs; };
      catalog = import ../../../modules/lib/catalog.nix { inherit lib; };
      appsDir = ../../../modules/apps;

      exampleHosts = {
        minimal = ferrumLib.mkHost {
          inherit system;
          settings = builtins.fromJSON (builtins.readFile ../../../examples/hosts/minimal/settings.json);
          modules = [ ../../../examples/hosts/minimal/configuration.nix ];
          revision = "ci";
        };
      };

      # Every app directory with a meta.nix must also have a service.nix, or
      # the module system silently no-ops it while the UI still advertises
      # it as available -- this is the check that would have caught that.
      catalogConsistency =
        let
          dirNames = builtins.attrNames (builtins.readDir appsDir);
          appIds = builtins.filter (id: builtins.pathExists (appsDir + "/${id}/meta.nix")) dirNames;
          missingService = builtins.filter (id: !builtins.pathExists (appsDir + "/${id}/service.nix")) appIds;
          notInCatalog = lib.subtractLists (builtins.attrNames catalog) appIds;
        in
        {
          ok = missingService == [ ] && notInCatalog == [ ];
          inherit missingService notInCatalog;
        };

      # Every option reachable under ferrum.* must stay JSON-expressible,
      # because the web UI can only ever write JSON scalars back into
      # settings.json. A `path`, `package`, or function-typed option here
      # would be an option the UI could describe but never actually set.
      # Deliberately checks the *rendered* type description (the same
      # human-readable string nixosOptionsDoc produces) rather than trying
      # to pattern-match compound type values, since `attrsOf`/`submodule`/
      # `oneOf` wrappers don't preserve a stable identity to compare against.
      forbiddenTypeSubstrings = [ "path" "package" "function" ];

      schemaUniformity =
        let
          allDocs = lib.optionAttrSetToDocList exampleHosts.minimal.options;
          ferrumDocs = builtins.filter
            (o: lib.hasPrefix "ferrum" (lib.elemAt o.loc 0))
            allDocs;
          isForbidden = o:
            lib.any (bad: lib.hasInfix bad (lib.toLower (o.type or ""))) forbiddenTypeSubstrings;
          offenders = builtins.filter isForbidden ferrumDocs;
        in
        {
          ok = offenders == [ ];
          offenders = map (o: lib.concatStringsSep "." o.loc) offenders;
        };

      mkAssertionCheck = name: result:
        pkgs.runCommand "ferrum-check-${name}" { } (
          if result.ok then
            "echo '${name}: ok' > $out"
          else
            throw "ferrum check '${name}' failed: ${builtins.toJSON (removeAttrs result [ "ok" ])}"
        );
    in
    {
      checks = {
        catalog-consistency = mkAssertionCheck "catalog-consistency" catalogConsistency;
        schema-uniformity = mkAssertionCheck "schema-uniformity" schemaUniformity;

        # Pure eval, not a real build: forces .drvPath for each example host
        # so an option-type mistake fails in seconds, not after a full build.
        eval-example-hosts = pkgs.runCommand "ferrum-check-eval-example-hosts"
          {
            drvPaths = builtins.toJSON
              (lib.mapAttrsToList
                (name: host: { inherit name; drvPath = host.config.system.build.toplevel.drvPath; })
                exampleHosts);
          }
          "echo $drvPaths > $out";

        smoke-vm = import ../../../tests/smoke.nix { inherit pkgs; };

        cargo-test-ferrum-apply = pkgs.runCommand "ferrum-check-cargo-test-ferrum-apply"
          {
            nativeBuildInputs = [ pkgs.cargo pkgs.rustc ];
          }
          ''
            cp -r ${../../../crates} crates
            chmod -R u+w crates
            cd crates
            cargo test -p ferrum-apply --offline || cargo test -p ferrum-apply
            touch $out
          '';

        clippy-ferrum-apply = pkgs.runCommand "ferrum-check-clippy-ferrum-apply"
          {
            nativeBuildInputs = [ pkgs.cargo pkgs.rustc pkgs.clippy ];
          }
          ''
            cp -r ${../../../crates} crates
            chmod -R u+w crates
            cd crates
            cargo clippy -p ferrum-apply -- -D warnings
            touch $out
          '';
      };
    };
}
