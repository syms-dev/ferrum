# Rust toolchain and Nix development tools.
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
        cargo
        rustc
        clippy
        rustfmt
        rage
        ssh-to-age
        sops
      ];
    };
  };
}
