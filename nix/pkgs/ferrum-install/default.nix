# The installer binary. Unlike every other package here it does NOT run on
# a ferrum host -- it runs on the operator's own machine (inside the Docker
# image built alongside it) and talks to a machine that is not yet a ferrum
# host at all.
#
# Deliberately NOT added to nix/overlays/default.nix. That overlay exists so
# that a package referenced as `pkgs.<name>` from inside the NixOS module
# tree resolves -- a gap that has bitten this repo four times. Nothing in
# modules/ references ferrum-install, and nothing can: by the time the
# module tree is being evaluated, this binary's job is already done. Adding
# it there would be repeating the shape of the rule without its reason.
{ rustPlatform
, lib
, makeWrapper
, nix
, nixos-anywhere
, openssh
, git
, coreutils
}:
rustPlatform.buildRustPackage {
  pname = "ferrum-install";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-install";

  nativeBuildInputs = [ makeWrapper ];

  # ferrum-install shells out rather than linking client libraries, which
  # is this repo's established convention (crates/ferrum-apply/src/apply.rs
  # drives nix, btrfs and systemctl the same way) and which keeps the Rust
  # dependency tree free of an SSH stack. That makes the wrapper PATH part
  # of the binary's contract, not a convenience:
  #
  #   nix             -- the Tier 1 preflight's evaluation (spec R5 A1)
  #   nixos-anywhere  -- kexec, disko, install, --extra-files (R6 A1)
  #   openssh         -- every target interaction: inventory, the ownership
  #                      repair, the stage-2 apply, verification
  #   git             -- `git init/add/commit` in the generated host repo.
  #                      Not optional: Nix silently ignores untracked files
  #                      inside a git tree, so an untracked disko.nix fails
  #                      the install with a message naming the wrong cause.
  postFixup = ''
    wrapProgram $out/bin/ferrum-install \
      --prefix PATH : ${lib.makeBinPath [ nix nixos-anywhere openssh git coreutils ]}
  '';

  meta = {
    description = "Installs ferrum onto a bare machine over SSH";
    mainProgram = "ferrum-install";
  };
}
