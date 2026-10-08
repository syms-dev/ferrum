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
, gnutar
  # The ferrum revision this installer pins generated hosts to (R3 A5).
  # Passed from nix/modules/flake/packages.nix, which is the only place
  # that can see the flake's own `self`.
, ferrumRev
  # Cargo features to compile in. EMPTY for the installer operators get --
  # `.#ferrum-install` and the Docker image built from it -- and that
  # default is load-bearing rather than tidy.
  #
  # The one caller that passes anything is `.#ferrum-install-testing`, which
  # asks for `test-cloudflare-endpoint` so that `tests/stage2/run.sh` can
  # point A5's Cloudflare check at a stand-in API. That feature compiles in
  # a whole second body for `answers::cloudflare_client`; with this list
  # empty, neither that body nor the environment variable it names exists in
  # the artifact. `production-installer-has-no-api-override` in
  # nix/modules/flake/checks.nix asserts exactly that against both binaries,
  # so the two packages are kept apart by a check rather than by convention.
, cargoFeatures ? [ ]
}:
rustPlatform.buildRustPackage {
  pname = "ferrum-install" + lib.optionalString (cargoFeatures != [ ]) "-testing";
  version = "0.1.0";

  # Also the check features: buildRustPackage defaults `checkFeatures` to
  # this list, so the testing build runs the unit suite with the feature on
  # and a `cfg`-gated body that stopped compiling would fail here rather
  # than in the CI job that consumes it.
  buildFeatures = cargoFeatures;
  # Unlike the other crates, this one's source root is the REPOSITORY, not
  # crates/. render.rs does include_str! on
  # examples/hosts/template/disko.nix so that a drift between the generated
  # btrfs subvolume layout and the template is a compile-linked test
  # failure rather than a comment nobody reads -- and that path escapes
  # crates/. Filtered to the two directories actually needed so an edit to
  # docs/ or ui/ does not rebuild the installer.
  src = lib.cleanSourceWith {
    src = ../../..;
    filter = path: type:
      let rel = lib.removePrefix (toString ../../.. + "/") (toString path); in
      lib.hasPrefix "crates" rel || lib.hasPrefix "examples" rel
      # flake.lock as well: render.rs include_str!s it in a test, so the
      # checkPhase needs it. Kept in step with the identical filter in
      # nix/modules/flake/checks.nix -- that pair has already drifted once.
      || rel == "flake.lock"
      || (type == "directory" && (rel == "crates" || rel == "examples"));
  };
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  # The workspace lives under crates/, but src is the repository root.
  cargoRoot = "crates";
  buildAndTestSubdir = "crates/ferrum-install";

  # R3 A5: the generated host flake pins ferrum to a specific revision, so
  # the installed host and the tool that built it provably agree. Read at
  # compile time; a binary built without it refuses to generate rather than
  # falling back to a branch.
  FERRUM_INSTALL_REV = ferrumRev;

  # render::write_repo shells out to git, so the checkPhase needs it on
  # PATH or those tests fail for an environment reason rather than a real
  # one -- the same trap ferrum-apply hits without btrfs-progs.
  nativeCheckInputs = [ git ];

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
      --prefix PATH : ${lib.makeBinPath [ nix nixos-anywhere openssh git coreutils gnutar ]}
  '';

  meta = {
    description = "Installs ferrum onto a bare machine over SSH";
    mainProgram = "ferrum-install";
  };
}
