{ rustPlatform, lib, makeWrapper, btrfs-progs }:
rustPlatform.buildRustPackage {
  pname = "ferrum-apply";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-apply";

  # ferrum-apply shells out to `btrfs` (preflight's check_is_subvolume, and
  # later apply/restore-state's snapshot/swap commands). nativeCheckInputs
  # alone only puts it on PATH during this derivation's own checkPhase --
  # it does NOT reach the installed binary at runtime, so it's paired here
  # with a wrapper that guarantees `btrfs` is on PATH wherever this binary
  # actually runs, independent of whether a consuming systemd unit (or a
  # test's environment.systemPackages) remembers to supply it too.
  nativeCheckInputs = [ btrfs-progs ];
  nativeBuildInputs = [ makeWrapper ];
  postFixup = ''
    wrapProgram $out/bin/ferrum-apply --prefix PATH : ${lib.makeBinPath [ btrfs-progs ]}
  '';
}
