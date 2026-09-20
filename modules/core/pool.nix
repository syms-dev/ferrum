# Presents several data disks as one filesystem, so apps see one library.
#
# WHY THIS EXISTS. A media host with two disks has two libraries unless
# something unions them, and the operator then has to decide per show which
# disk it lives on -- which is exactly the kind of bookkeeping this product
# is supposed to remove. Saltbox solves it with mergerfs and so does this.
#
# WHY mergerfs RATHER THAN btrfs MULTI-DEVICE. The disks already hold the
# operator's media. mergerfs is a union VIEW over existing mounts, so it
# adds a path and changes nothing on disk; btrfs multi-device would rewrite
# them. "Never rearrange existing data" is a requirement, not a preference,
# and it rules the alternative out rather than merely disfavouring it.
{ config, lib, pkgs, ... }:
let
  cfg = config.ferrum.storage;
  pool = cfg.pool;
in
{
  config = lib.mkIf (pool.enable && pool.branches != [ ]) {
    assertions = [
      {
        assertion = builtins.length pool.branches >= 2;
        message = ''
          ferrum.storage.pool.enable is on with ${toString (builtins.length pool.branches)}
          branch(es). A pool of one disk is a mount, not a pool -- mount it
          at ferrum.storage.mediaDir directly instead.
        '';
      }
      {
        assertion = !(builtins.elem cfg.mediaDir pool.branches);
        message = ''
          ferrum.storage.mediaDir (${cfg.mediaDir}) is also listed as a pool
          branch. The pool is mounted AT mediaDir, so a branch at the same
          path would mount over itself.
        '';
      }
    ];

    # mount.fuse.mergerfs must be on PATH for the mount to work at boot.
    environment.systemPackages = [ pkgs.mergerfs ];

    fileSystems.${cfg.mediaDir} = {
      device = lib.concatStringsSep ":" pool.branches;
      fsType = "fuse.mergerfs";
      options = [
        "category.create=${pool.policy}"

        # The floor that stops epmfs filling a disk. Below it a branch is
        # skipped for NEW files, so a show whose disk is full continues on
        # another disk rather than failing to import.
        "minfreespace=${toString pool.minFreeGiB}G"

        # And the backstop for a write that runs out mid-file: mergerfs
        # relocates it to a branch with room instead of failing. Media
        # files are large enough that a check at open time is not enough on
        # its own.
        "moveonenospc=true"

        # Apps run as their own users and all share the media group; without
        # allow_other only the mounting user (root) could read the pool.
        "allow_other"

        # Stable inodes across the branches. The *arrs compare inodes to
        # detect hardlinks, so this is what makes a hardlinked import
        # recognisable as one rather than as a duplicate.
        "use_ino"

        # Same reasoning as the individual data-disk mounts: a media host
        # that boots with a smaller pool beats one that does not boot.
        "nofail"
      ]
      # The pool cannot mount before its branches do. Without this systemd
      # races them and the pool comes up empty -- which looks exactly like
      # an empty library rather than like a mount ordering problem.
      ++ map (b: "x-systemd.requires-mounts-for=${b}") pool.branches;
    };
  };
}
