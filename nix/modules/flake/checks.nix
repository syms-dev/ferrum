# The guardrail checks that keep the architecture honest, plus the trivial
# smoke VM test that answers Phase 1.0 probe 0.1 (does a NixOS VM test even
# run on a hosted GitHub runner?).
{ inputs, ... }:
{
  perSystem = { system, pkgs, lib, self', ... }:
    let
      ferrumLib = import ../../../modules/lib {
        nixpkgs = inputs.nixpkgs;
        sopsNix = inputs.sops-nix;
      };
      catalog = import ../../../modules/lib/catalog.nix { inherit lib; };
      appsDir = ../../../modules/apps;

      exampleHosts = {
        minimal = ferrumLib.mkHost {
          inherit system;
          settings = builtins.fromJSON (builtins.readFile ../../../examples/hosts/minimal/settings.json);
          modules = [
            ../../../examples/hosts/minimal/configuration.nix
            # This host is eval-only (see configuration.nix's own "NOT
            # BOOTABLE" comment) and has no real deployed box's
            # /etc/ferrum/secrets to read from. sops.validateSopsFiles
            # defaults to true and requires each sops.secrets.<name>.sopsFile
            # to be a genuine Nix path value pointing at a file that
            # physically exists at eval time (confirmed by reading
            # sops-nix's own source) -- disabling that check alone (an
            # earlier version of this override did just that) is NOT
            # sufficient, since Nix's own path-value semantics
            # independently require the referenced file to exist the
            # moment the value is touched, regardless of validateSopsFiles.
            # The real fix: point ferrum.secretsDir at real (throwaway,
            # non-production) placeholder secrets committed alongside this
            # example host, via a path LITERAL relative to this file's own
            # location -- that makes it part of ferrum's own flake source,
            # auto-imported into the store at parse time, genuinely
            # readable under pure evaluation (confirmed for real on
            # ferrum-dev: this exact override, with placeholders present,
            # makes checks.eval-example-hosts pass with the real default
            # validateSopsFiles = true, no override needed at all).
            { ferrum.secretsDir = toString ../../../examples/hosts/minimal/secrets; }
          ];
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

      # Regression guard for the bug documented in the plan's Global
      # Constraints (see docs/superpowers/plans/2026-08-20-phase-1-4a-
      # secrets-foundation.md): sops-nix's own assertion accepts sopsFile
      # if EITHER `builtins.isPath` is true OR it's a string already
      # prefixed with the Nix store dir -- and this host's own
      # `ferrum.secretsDir` override happens to evaluate to a `/nix/store`
      # string (a path literal converted via `toString`), which takes the
      # SECOND branch. That means a future edit reverting any
      # `sopsFile = /. + "${x}/y"` back to plain string interpolation
      # (`sopsFile = "${x}/y"`) would pass on THIS host and still break
      # every real deployed box, whose secretsDir is a plain
      # non-store path -- reading `.sops.secrets.*.sopsFile`'s own value
      # forces no realization (unlike system.build.toplevel below), so this
      # stays genuinely cheap.
      sopsFilesArePaths =
        let
          secrets = lib.attrValues exampleHosts.minimal.config.sops.secrets;
          offenders = builtins.filter (s: !builtins.isPath s.sopsFile) secrets;
        in
        {
          ok = offenders == [ ];
          offenders = map (s: s.sopsFile) offenders;
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
        sopsfile-are-paths = mkAssertionCheck "sopsfile-are-paths" sopsFilesArePaths;

        # Forces .drvPath for each example host so an option-type mistake
        # fails fast, without a full build -- true for the catalog apps
        # themselves. NOT true once any sops.secrets exist on a host
        # (which the example host's placeholder secrets under
        # examples/hosts/minimal/secrets/ now do, on purpose, to exercise
        # the real default sops.validateSopsFiles = true): sops-nix's own
        # system.activationScripts.setupSecrets needs sops-install-secrets
        # (a real Haskell program) actually realized to build its text,
        # not just referenced by hash. Confirmed for real, repeatedly, on
        # ferrum-dev (a 79GB VM): this now costs well beyond the original
        # ~1293-store-path/~8.7GB measurement -- three consecutive attempts
        # each hit ENOSPC after freeing 70+GB via `nix-store --gc`
        # immediately beforehand, meaning peak usage is somewhere north of
        # that freed amount. Standard GitHub-hosted runners do not
        # reliably have that much free disk, so this check is
        # DELIBERATELY NOT wired into any CI job (see .github/workflows/
        # ci.yml's "cheap checks" step, which used to include it and no
        # longer does) -- run it by hand, on ferrum-dev or an equivalent
        # real machine with disk to spare, when touching anything under
        # modules/apps/ or modules/core/secrets.nix. This is an accepted,
        # deliberate scope decision, not a silently-dropped check: the
        # regression it existed to catch for THIS branch's own bug
        # (sopsFile's isPath requirement) is covered instead by the
        # genuinely cheap sopsfile-are-paths check above, which needs no
        # realization at all.
        eval-example-hosts = pkgs.runCommand "ferrum-check-eval-example-hosts"
          {
            drvPaths = builtins.toJSON
              (lib.mapAttrsToList
                (name: host: { inherit name; drvPath = host.config.system.build.toplevel.drvPath; })
                exampleHosts);
          }
          "echo $drvPaths > $out";

        smoke-vm = import ../../../tests/smoke.nix { inherit pkgs; };

        # tests/rollback.nix is the plan's terminal proof: a real rollback
        # reverts application STATE. rollback-proves-necessity.nix is its
        # companion, proving the failure mode the mechanism exists to
        # prevent is real in the first place. apply-generation-switch.nix
        # (below) proves the other half of the pair: the CLOSURE reverts
        # too, against a genuinely different generation.
        rollback = import ../../../tests/rollback.nix { inherit pkgs; };
        rollback-proves-necessity = import ../../../tests/rollback-proves-necessity.nix { inherit pkgs; };

        # Closes the one gap tests/rollback.nix's own header discloses: a
        # real generation switch between two genuinely different closures,
        # not just application state, actually reverts on rollback.
        apply-generation-switch = import ../../../tests/apply-generation-switch.nix { inherit pkgs; };

        # Proves systemd itself honors ConditionPathExists and holds
        # ferrum-managed apps down when the (durable, per Fix 1) failure
        # marker is present -- the property the interlock actually depends
        # on, which neither rollback.nix nor the restore_state.rs unit tests
        # exercise directly.
        state-restore-interlock = import ../../../tests/state-restore-interlock.nix { inherit pkgs; };

        # Proves the real privilege boundary Task 2 built: an unprivileged
        # user really can trigger a real ferrum-apply run via D-Bus +
        # polkit (not just that the polkit rule text parses), and really
        # is denied starting an unrelated unit.
        privilege-boundary = import ../../../tests/privilege-boundary.nix { inherit pkgs; sopsNix = inputs.sops-nix; };

        # Not a separate runCommand: Nix's build sandbox has no network
        # access, so a hand-rolled `cd crates && cargo test` derivation can
        # never fetch crates.io and fails every time (verified: it does).
        # `rustPlatform.buildRustPackage` avoids this by vendoring
        # dependencies from Cargo.lock as a fixed-output derivation *before*
        # the sandboxed build; its default cargoCheckHook already runs
        # `cargo test` as part of building the package normally, so
        # `packages.ferrum-apply` itself IS the cargo-test check -- aliasing
        # it here just gives it a name under `checks`.
        cargo-test-ferrum-apply = self'.packages.ferrum-apply;

        # Clippy needs its own derivation (buildRustPackage's default check
        # phase runs `cargo test`, not clippy), but reuses the same
        # Cargo.lock-based vendoring so it builds offline too.
        clippy-ferrum-apply = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrum-apply-clippy";
          version = "0.1.0";
          src = lib.cleanSource ../../../crates;
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          buildAndTestSubdir = "ferrum-apply";
          nativeBuildInputs = [ pkgs.clippy ];
          buildPhase = "true";
          checkPhase = "cargo clippy --offline -- -D warnings";
          installPhase = "mkdir -p $out";
        };

        cargo-test-ferrum-reconcile = self'.packages.ferrum-reconcile;

        clippy-ferrum-reconcile = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrum-reconcile-clippy";
          version = "0.1.0";
          src = lib.cleanSource ../../../crates;
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          buildAndTestSubdir = "ferrum-reconcile";
          nativeBuildInputs = [ pkgs.clippy ];
          buildPhase = "true";
          checkPhase = "cargo clippy --offline -- -D warnings";
          installPhase = "mkdir -p $out";
        };

        cargo-test-ferrumd = self'.packages.ferrumd;

        clippy-ferrumd = pkgs.rustPlatform.buildRustPackage {
          pname = "ferrumd-clippy";
          version = "0.1.0";
          src = lib.cleanSource ../../../crates;
          cargoLock.lockFile = ../../../crates/Cargo.lock;
          buildAndTestSubdir = "ferrumd";
          nativeBuildInputs = [ pkgs.clippy ];
          buildPhase = "true";
          checkPhase = "cargo clippy --offline -- -D warnings";
          installPhase = "mkdir -p $out";
        };

        # The proof this whole phase's core deliverable works: a real
        # operator login with the real generated bootstrap password, a real
        # settings write, a real secret round-tripped through real sops
        # encryption, and a real job triggered over the real HTTP API that
        # crosses the real polkit/D-Bus privilege boundary and produces a
        # real JSONL progress log.
        daemon-end-to-end = import ../../../tests/daemon-end-to-end.nix { inherit pkgs; sopsNix = inputs.sops-nix; };
      };
    };
}
