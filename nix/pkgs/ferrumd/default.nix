{ rustPlatform, lib, makeWrapper, sops, ssh-to-age }:
rustPlatform.buildRustPackage {
  pname = "ferrumd";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrumd";

  # Same reasoning as nix/pkgs/ferrum-apply: ferrumd's secrets API shells
  # out to `ssh-to-age` (to derive this host's public age recipient from
  # its SSH host key) and `sops` (to encrypt the operator-provided value)
  # via the shared ferrum-secrets crate. Without the wrapper, POST
  # /api/secrets/:name fails at runtime with a bare "No such file or
  # directory" from the spawn, on a box where nothing else put sops on
  # PATH.
  nativeCheckInputs = [ sops ssh-to-age ];
  nativeBuildInputs = [ makeWrapper ];
  postFixup = ''
    wrapProgram $out/bin/ferrumd --prefix PATH : ${lib.makeBinPath [ sops ssh-to-age ]}
  '';

  meta.mainProgram = "ferrumd";
}
