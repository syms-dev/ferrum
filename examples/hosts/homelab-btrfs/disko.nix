# Reference disko layout matching the design's "Storage layout" section:
# @root and @nix are never snapshotted; @state is the ONLY subvolume the
# rollback mechanism touches; @snapshots holds its read-only snapshots;
# @media holds downloads/library as plain directories, never separate
# subvolumes, because btrfs forbids hardlinks across subvolumes and the
# *arr import workflow depends on hardlinks.
#
# NOT wired into any CI check yet. The snapshot-and-rename swap and the
# boot-time mount ordering this layout depends on are Phase 1.0 probes that
# need a real disk or VM to run against -- see
# docs/design/2026-08-19-phase-1-design.md. Treat this file as documentation
# of the intended layout, not a tested one.
{
  disko.devices.disk.main = {
    type = "disk";
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
              "@root" = {
                mountpoint = "/";
                mountOptions = [ "compress=zstd" "noatime" ];
              };
              "@nix" = {
                mountpoint = "/nix";
                mountOptions = [ "compress=zstd" "noatime" ];
              };
              # Must match ferrum.storage.stateDir (see modules/core/options.nix).
              "@state" = {
                mountpoint = "/var/lib/ferrum/state";
                mountOptions = [ "compress=zstd" "noatime" ];
              };
              # Must match ferrum.storage.snapshotDir.
              "@snapshots" = {
                mountpoint = "/var/lib/ferrum/snapshots";
                mountOptions = [ "noatime" ];
              };
              # Must match ferrum.storage.mediaDir.
              "@media" = {
                mountpoint = "/srv/media";
                mountOptions = [ "compress=zstd" "noatime" ];
              };
            };
          };
        };
      };
    };
  };
}
