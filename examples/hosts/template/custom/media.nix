# Mounts the media disks that disko.nix deliberately does NOT touch, and
# points ferrum's media directory at them.
#
# This file lives in custom/ on purpose. custom/ is the directory the ferrum
# web UI is never given write access to and an update never rewrites -- it is
# the concrete thing the README means by "unlike Saltbox, your customisations
# survive an update". Machine-specific storage that ferrum's catalog has no
# opinion about is exactly what it is for.
#
# ferrum has NO mergerfs or rclone support of its own: the design doc puts
# "the rclone/mergerfs cloud tier" explicitly out of scope for Phase 1, as
# its own later phase. So a pool is assembled here, by hand, from nixpkgs'
# ordinary filesystem support rather than from any ferrum option.
{ config, lib, pkgs, ... }:
let
  # CHANGE-ME, both of them. Use /dev/disk/by-id/ (or by-uuid), never
  # /dev/sdX -- kernel enumeration order is not stable across boots, and
  # these are the disks whose contents you are keeping.
  #   lsblk -o NAME,SIZE,MODEL,SERIAL,FSTYPE,UUID
  internalDisk = "/dev/disk/by-id/CHANGE-ME-internal-hdd";
  externalDisk = "/dev/disk/by-id/CHANGE-ME-external-hdd";

  # CHANGE-ME. The filesystem already on those disks -- ferrum is not
  # creating it, only mounting what is there. Typically "ext4" or "xfs" on a
  # disk inherited from a Saltbox install.
  mediaFsType = "ext4";
in
{
  # The individual branch disks, mounted under /mnt. mergerfs pools these.
  #
  # nofail is deliberate and load-bearing for the external drive: without
  # it, a USB disk that is unplugged, asleep, or simply slow to enumerate
  # takes the whole boot into emergency mode. A media server that refuses to
  # boot because a drive is missing is a worse failure than one that boots
  # with a smaller pool.
  fileSystems."/mnt/media-internal" = {
    device = internalDisk;
    fsType = mediaFsType;
    options = [ "defaults" "nofail" "x-systemd.device-timeout=30s" ];
  };

  fileSystems."/mnt/media-external" = {
    device = externalDisk;
    fsType = mediaFsType;
    options = [ "defaults" "nofail" "x-systemd.device-timeout=30s" ];
  };

  # The pool itself.
  #
  # `category.create = "epff"` (existing path, first found) is the setting
  # that matters for an *arr workflow, and it is not the mergerfs default.
  # The *arr import step relies on HARDLINKING a completed download into the
  # library instead of copying it, and a hardlink cannot cross a filesystem
  # boundary -- so if the create policy is free-space-based (mergerfs's
  # usual default, `epmfs`), a download landing on the internal disk and a
  # library path living on the external one silently degrades every import
  # from an instant hardlink to a full copy, doubling disk usage and I/O.
  # `epff` keeps a new file on the branch that already holds its parent
  # directory, which keeps downloads/ and library/ together per-branch.
  #
  # This is the same hardlink constraint that makes modules/core/storage.nix
  # insist downloads/ and library/ be plain directories in ONE subvolume
  # rather than separate btrfs subvolumes; mergerfs just moves where the
  # constraint has to be honoured.
  fileSystems."/srv/media" = {
    device = "/mnt/media-internal:/mnt/media-external";
    fsType = "fuse.mergerfs";
    options = [
      "defaults"
      "allow_other"
      "use_ino"
      "cache.files=partial"
      "dropcacheonclose=true"
      "category.create=epff"
      "minfreespace=20G"
      "fsname=mediapool"
      "nofail"
      # Ordering, not decoration: without these the pool can be assembled
      # before its branches are mounted, producing an empty pool that then
      # looks like "all my media vanished".
      "x-systemd.requires=/mnt/media-internal"
      "x-systemd.requires=/mnt/media-external"
    ];
  };

  environment.systemPackages = [ pkgs.mergerfs ];

  # Point ferrum at the pool. modules/core/storage.nix creates downloads/ and
  # library/ underneath this as plain directories owned by the media group,
  # which is what every catalog app's mediaAccess is granted against.
  ferrum.storage.mediaDir = lib.mkForce "/srv/media";
}
