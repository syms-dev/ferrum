# ferrum.lib -- helpers exposed to host flakes.
#
# Deliberately thin: a host flake imports the ferrum module itself, passes
# its settings.json in as a plain attrset, and lets NixOS's own module
# system do the type-checking. See modules/default.nix for the module this
# wraps and docs/superpowers/specs/... for why settings are threaded in at
# the host-flake level rather than read from a path inside config.ferrum
# (reading a path out of config.ferrum in order to define config.ferrum is
# infinite recursion).
{ nixpkgs, sopsNix }:
let
  inherit (nixpkgs) lib;
  ferrumModule = import ../default.nix;
in
{
  # mkHost turns a settings attrset (typically `builtins.fromJSON
  # (builtins.readFile ./settings.json)`) plus any hand-written modules
  # (typically hardware-configuration.nix, disko.nix, and everything under
  # custom/) into a full nixosSystem.
  mkHost =
    { system
    , settings
    , modules ? [ ]
    , revision ? "unknown"
    , stateVersion ? "25.11"
    }:
    lib.nixosSystem {
      inherit system;
      specialArgs = { inherit revision; };
      modules = [
        sopsNix.nixosModules.sops
        ferrumModule
        { config.ferrum = settings; }
        { system.stateVersion = lib.mkDefault stateVersion; }
      ] ++ modules;
    };

  # importDir lists the *.nix files directly inside a directory, for wiring
  # up /etc/ferrum/custom -- the directory ferrumd is never given write
  # access to (see modules/core/daemon.nix once it exists).
  importDir = dir:
    let
      names = builtins.attrNames (builtins.readDir dir);
      nixFiles = builtins.filter (n: lib.hasSuffix ".nix" n) names;
    in
    map (n: dir + "/${n}") nixFiles;
}
