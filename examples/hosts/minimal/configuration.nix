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

  boot.loader.grub.enable = true;
  boot.loader.grub.device = "/dev/sda";
}
