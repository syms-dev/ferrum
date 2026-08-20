# Stand-in for hardware-configuration.nix, used only so this example host
# evaluates cleanly for checks.eval-example-hosts and checks.schema-uniformity.
# EVAL-ONLY, NOT BOOTABLE: "/" (ext4) and the ferrum state/snapshot
# subvolumes below all claim the same /dev/disk/by-label/nixos device purely
# to satisfy modules/core/state-restore.nix's assertions during evaluation --
# a real device can't be both ext4 and btrfs at once. A real host gets a
# real hardware-configuration.nix and disko.nix written by the installer --
# see the plan's nixos-anywhere provisioning story, and
# examples/hosts/homelab-btrfs/disko.nix for a real btrfs subvolume layout.
{ ... }:
{
  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
  };

  # modules/core/state-restore.nix reads this entry's `device` to know which
  # block device to mount at subvolid=5 during a boot-time state restore,
  # and asserts it carries `subvol=@state` (crates/ferrum-apply/src/
  # restore_state.rs hardcodes that exact subvolume name).
  fileSystems."/var/lib/ferrum/state" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "btrfs";
    options = [ "subvol=@state" ];
  };

  # Must be on the SAME device as stateDir above, with `subvol=@snapshots`
  # -- state-restore.nix asserts both, since ferrum-state-restore mounts one
  # top-level btrfs volume and expects to find both subvolumes on it.
  fileSystems."/var/lib/ferrum/snapshots" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "btrfs";
    options = [ "subvol=@snapshots" ];
  };

  boot.loader.grub.enable = true;
  boot.loader.grub.device = "/dev/sda";
}
