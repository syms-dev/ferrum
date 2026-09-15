# Disko layout for a ferrum host whose OS disk is SEPARATE from its media
# disks. This is the layout to use when the machine has a dedicated OS drive
# (typically an NVMe) plus one or more data drives you want to keep.
#
# ############################################################
# #  THIS FILE DESTROYS EVERY BYTE ON THE DISK IT NAMES.     #
# #  disko repartitions unconditionally: no merge, no        #
# #  preserve, no prompt. Whatever is on `device` below is    #
# #  gone the moment nixos-anywhere runs.                    #
# ############################################################
#
# The protection for your media is structural, not procedural: media disks
# are NOT DECLARED IN THIS FILE AT ALL. disko only touches devices it is
# told about, so a disk absent from this layout is never opened, never
# partitioned, and never mounted during install. Mount them afterwards from
# custom/ (see custom/media.nix), where a mistake costs a failed mount rather
# than a wiped drive.
#
# Set `device` by /dev/disk/by-id/, never /dev/sda or /dev/nvme0n1. Kernel
# enumeration order is not stable across boots, and on a machine with three
# drives the difference between "the OS disk" and "the disk with your library
# on it" is one reboot's worth of luck. `ls -l /dev/disk/by-id/` on the
# target names them unambiguously; prefer the entry carrying the model and
# serial, and avoid the `-part<N>` and `wwn-` aliases.
{
  disko.devices.disk.main = {
    type = "disk";

    # CHANGE-ME. There is no sensible default and a wrong value here is
    # unrecoverable. Confirm with, on the target machine:
    #   lsblk -o NAME,SIZE,MODEL,SERIAL,MOUNTPOINT
    #   ls -l /dev/disk/by-id/
    device = "/dev/disk/by-id/CHANGE-ME";

    content = {
      type = "gpt";
      partitions = {
        ESP = {
          priority = 1;
          name = "ESP";
          start = "1M";
          end = "1G";
          type = "EF00";
          content = {
            type = "filesystem";
            format = "vfat";
            mountpoint = "/boot";
            mountOptions = [ "umask=0077" ];
          };
        };
        root = {
          size = "100%";
          content = {
            type = "btrfs";
            extraArgs = [ "-f" ];
            subvolumes = {
              # Never snapshotted: ferrumd's own database and the rollback
              # journal live here and must survive the rollback they report on.
              "@root" = {
                mountpoint = "/";
                mountOptions = [ "compress=zstd" "noatime" ];
              };
              "@nix" = {
                mountpoint = "/nix";
                mountOptions = [ "compress=zstd" "noatime" ];
              };

              # The ONLY subvolume the rollback mechanism touches. Must match
              # ferrum.storage.stateDir. crates/ferrum-apply/src/restore_state.rs
              # hardcodes the name "@state" -- do not rename it.
              "@state" = {
                mountpoint = "/var/lib/ferrum/state";
                mountOptions = [ "compress=zstd" "noatime" ];
              };

              # Read-only snapshots of @state. Must match
              # ferrum.storage.snapshotDir, and must be on the SAME btrfs
              # volume as @state -- modules/core/state-restore.nix asserts
              # both, because the boot-time restore mounts one top-level
              # volume and expects to find the pair on it.
              "@snapshots" = {
                mountpoint = "/var/lib/ferrum/snapshots";
                mountOptions = [ "noatime" ];
              };
            };
          };
        };
      };
    };
  };

  # DELIBERATELY NO @media SUBVOLUME, unlike examples/hosts/homelab-btrfs.
  # On this layout the media lives on its own disks, which this file must
  # never touch. ferrum.storage.mediaDir is pointed at those disks from
  # custom/media.nix instead.
}
