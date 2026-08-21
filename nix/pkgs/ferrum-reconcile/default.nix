{ rustPlatform, lib }:
rustPlatform.buildRustPackage {
  pname = "ferrum-reconcile";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-reconcile";
}
