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
  config = lib.mkMerge [
    # The checks are gated on pool.enable ALONE, and that is a fix rather
    # than a stylistic preference.
    #
    # Both of them used to sit inside the `lib.mkIf (pool.enable &&
    # pool.branches != [ ])` below -- inside the very condition they exist
    # to police. So `ferrum.storage.pool.enable = true` with `branches = [
    # ]` switched off the whole block, assertions included, and evaluated
    # with ZERO failed assertions and no fileSystems entry at mediaDir at
    # all: measured, not reasoned about. The operator gets a host that says
    # a pool is enabled, has no mergerfs mount, and quietly writes the whole
    # library to the OS disk while the data disks sit unused.
    #
    # `enable && branches != [ ]` remains the right guard for the
    # FILESYSTEM, which cannot be built from an empty branch list (`device`
    # would render as the empty string). It was never the right guard for
    # the checks, because "the operator asked for a pool and gave it nothing
    # to union" is exactly the state worth reporting.
    {
      assertions = lib.optionals pool.enable [
        {
          assertion = pool.branches != [ ];
          message = ''
            ferrum.storage.pool.enable is on and ferrum.storage.pool.branches
            is empty, so there is nothing to union and no pool is created.

            That is not a harmless no-op. With no mergerfs filesystem at
            ferrum.storage.mediaDir (${cfg.mediaDir}), that path is an
            ordinary directory on whatever filesystem already covers it --
            normally the OS disk -- and every app writes its library there
            while the data disks stay unused. Nothing else on the host
            reports this: the apps start, the imports succeed, and the disk
            fills.

            Either list the disk mount points to union in
            ferrum.storage.pool.branches, or set ferrum.storage.pool.enable
            = false and mount the single disk at mediaDir directly.
          '';
        }
        {
          # Guarded on the empty case so that a host with no branches gets
          # the message above -- which explains what actually happens --
          # rather than this one, which would read as "0 is fewer than 2"
          # and send the operator looking for a second disk they may not
          # have.
          assertion = pool.branches == [ ] || builtins.length pool.branches >= 2;
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
    }

    (lib.mkIf (pool.enable && pool.branches != [ ]) {
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
    })
  ];
}
