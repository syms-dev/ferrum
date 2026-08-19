# homelab-btrfs (reference, not yet tested)

This directory documents the disko layout a real ferrum host is meant to use — see [`disko.nix`](disko.nix) and the design doc's "Storage layout" section.

It is deliberately **not** wired into `checks.eval-example-hosts`: unlike [`examples/hosts/minimal`](../minimal), it needs a real disk (or a disk image) to evaluate meaningfully, and the snapshot/rollback mechanics it exists to support are still Phase 1.0/1.2 work. Once `nixos-anywhere` provisioning is exercised against a real target, this becomes the starting point for that host's `flake.nix`.
