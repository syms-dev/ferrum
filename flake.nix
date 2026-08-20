{
  description = "ferrum -- a rollback-safe, NixOS-based alternative to Saltbox";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-parts.url = "github:hercules-ci/flake-parts";

    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    sops-nix = {
      url = "github:Mic92/sops-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs@{ flake-parts, nixpkgs, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" ];

      imports = [
        ./nix/modules/flake/checks.nix
        ./nix/modules/flake/packages.nix
        ./nix/modules/flake/overlays.nix
        ./nix/modules/flake/devshells.nix
      ];

      flake = {
        nixosModules.default = import ./modules;

        lib = import ./modules/lib { inherit nixpkgs; };
      };
    };
}
