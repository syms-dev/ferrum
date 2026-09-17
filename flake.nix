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

    # Drives the Phase 1.6a installer's destructive step: kexec, disko,
    # install, and the --extra-files transfer that puts the host flake at
    # /etc/ferrum. Taken as a flake input rather than from nixpkgs so the
    # Docker image's contents are pinned by this repo's flake.lock, which
    # is what makes the image reproducible rather than merely built.
    nixos-anywhere = {
      url = "github:nix-community/nixos-anywhere";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.disko.follows = "disko";
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

        lib = import ./modules/lib { inherit nixpkgs; sopsNix = inputs.sops-nix; };
      };
    };
}
