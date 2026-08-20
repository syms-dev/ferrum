{ rustPlatform, lib }:
rustPlatform.buildRustPackage {
  pname = "ferrum-testapp";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  cargoLock.lockFile = ./Cargo.lock;
}
