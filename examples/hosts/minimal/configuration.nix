# Stand-in for hardware-configuration.nix, used only so this example host
# evaluates cleanly for checks.eval-example-hosts and checks.schema-uniformity.
# A real host gets a real hardware-configuration.nix and disko.nix written
# by the installer -- see the plan's nixos-anywhere provisioning story.
{ ... }:
{
  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "ext4";
  };

  # modules/core/state-restore.nix reads this entry's `device` to know which
  # block device to mount at subvolid=5 during a boot-time state restore --
  # it needs to exist for evaluation even on this bare-bones example host.
  # A real host's disko.nix (examples/hosts/homelab-btrfs/disko.nix) declares
  # the same path as part of a real btrfs subvolume layout.
  fileSystems."/var/lib/ferrum/state" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "btrfs";
    options = [ "subvol=@state" ];
  };

  boot.loader.grub.enable = true;
  boot.loader.grub.device = "/dev/sda";
}
