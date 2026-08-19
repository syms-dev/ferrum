# Rust toolchain joins this shell once crates/ exists (Phase 1.5). For now
# it only needs to support editing and linting the Nix module tree.
{ ... }:
{
  perSystem = { pkgs, ... }: {
    devShells.default = pkgs.mkShell {
      name = "ferrum";
      packages = with pkgs; [
        nixpkgs-fmt
        statix
        deadnix
        nix-tree
      ];
    };
  };
}
