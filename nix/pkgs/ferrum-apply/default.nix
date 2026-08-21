{ rustPlatform, lib, makeWrapper, btrfs-progs, sops, ssh-to-age, authelia }:
rustPlatform.buildRustPackage {
  pname = "ferrum-apply";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-apply";

  # ferrum-apply shells out to `btrfs` (preflight's check_is_subvolume, and
  # later apply/restore-state's snapshot/swap commands), `sops` and
  # `ssh-to-age` (secrets::ensure_all's encrypt-only secret generation),
  # and `authelia` (secrets::argon2id_hash, for the generated first-user
  # password). nativeCheckInputs alone only puts these on PATH during this
  # derivation's own checkPhase -- it does NOT reach the installed binary
  # at runtime, so it's paired here with a wrapper that guarantees they're
  # all on PATH wherever this binary actually runs, independent of whether
  # a consuming systemd unit remembers to supply them too.
  nativeCheckInputs = [ btrfs-progs sops ssh-to-age authelia ];
  nativeBuildInputs = [ makeWrapper ];
  postFixup = ''
    wrapProgram $out/bin/ferrum-apply --prefix PATH : ${lib.makeBinPath [ btrfs-progs sops ssh-to-age authelia ]}
  '';
}
