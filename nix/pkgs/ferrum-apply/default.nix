{ rustPlatform, lib, btrfs-progs }:
rustPlatform.buildRustPackage {
  pname = "ferrum-apply";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-apply";

  # ferrum-apply shells out to `btrfs` at runtime (preflight's
  # check_is_subvolume, and later apply/restore-state's snapshot/swap
  # commands), and its unit tests exercise that path -- without btrfs-progs
  # on PATH during the sandboxed cargoCheckHook run,
  # is_subvolume_check_fails_on_a_plain_directory fails differently than it
  # does outside the sandbox (a "command not found" error instead of the
  # expected "not a btrfs subvolume" message).
  nativeCheckInputs = [ btrfs-progs ];
}
