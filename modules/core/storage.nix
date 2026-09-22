# Directory scaffolding and invariants for the ferrum storage layout.
#
# The full disko subvolume layout (see examples/hosts/minimal/disko.nix)
# defines the actual @root/@nix/@state/@snapshots/@media boundaries; this
# module only asserts the invariants that layout depends on and creates the
# plain directories underneath each mount point. See the plan's "Storage
# layout" section for why each rule exists:
#
#   1. /var/lib/ferrum itself must live on @root (outside the snapshotted
#      tree), because ferrumd's own database and rollback journal must
#      survive the rollback they are reporting on.
#   2. downloads/library must be plain directories inside one subvolume,
#      never separate subvolumes -- btrfs forbids hardlinks across
#      subvolumes, and the *arr import workflow depends on hardlinks.
#   3. snapshotDir must not nest inside stateDir.
{ config, lib, ... }:
let
  cfg = config.ferrum.storage;

  # /var/lib/ferrum is SHARED between root-trusted state and ferrumd's own
  # state, so its OWNER stays root and only its GROUP is opened up.
  #
  # What lives here that root alone must control: `state-restore-failed`
  # (the fail-closed marker that every app unit and modules/core/
  # generations.nix gate on via ConditionPathExists), `rollback-intent.json`
  # (read as root at boot by modules/core/state-restore.nix), the `journal/`
  # directory, and the state/snapshot mount points. What ferrumd needs is
  # only its own `daemon/` subdirectory and the `jobs/` progress logs, both
  # declared as ferrum-owned subdirectories in modules/core/daemon.nix.
  #
  # This module owned the parent by the ferrum user until the branch-wide
  # final review of Phase 1.5a. That was a real hole, not a cosmetic one:
  # write permission on a DIRECTORY is create/delete/rename permission on
  # every name in it, whatever the individual files' own modes say -- so a
  # compromised ferrumd could simply `unlink` state-restore-failed to
  # defeat the fail-closed interlock, or replace rollback-intent.json with
  # a forged one naming an attacker-chosen (but generation-valid) snapshot.
  # Neither requires any Nix evaluation, which is exactly the class of
  # escalation this phase's security thesis says must not exist.
  #
  # `root:ferrum 0750` gives the ferrum group r-x: enough to TRAVERSE into
  # daemon/ and jobs/ (and to list this directory), and no write bit at
  # all. It has to be declared HERE rather than in daemon.nix -- two
  # systemd.tmpfiles rules for the same path with different arguments is a
  # real conflict, not a merge. Falls back to root:root on a host with
  # ferrum.daemon.enable = false, where the ferrum group does not exist at
  # all and naming it here would fail tmpfiles at boot.
  ferrumdGroup = if config.ferrum.daemon.enable then "ferrum" else "root";

  # The TRaSH layout, under ONE root. downloads and media are siblings
  # inside mediaDir rather than separate mounts, because the *arrs import by
  # hardlinking and a hardlink cannot cross a filesystem. The old layout put
  # downloads on the OS disk while media lived on the data disks, so imports
  # degraded to copies -- silently, and invisibly until a library was large
  # enough for the duplication to show.
  trashSubdirs =
    [ "torrents" "usenet" "usenet/incomplete" "usenet/complete" "media" ]
    ++ lib.concatMap
      (cat: [ "torrents/${cat}" "usenet/complete/${cat}" "media/${cat}" ])
      [ "movies" "tv" "music" "books" ];

  # WHERE THE TREE IS CREATED, and why it is not just mediaDir.
  #
  # With a pool, mediaDir is a mergerfs mount and `category.create=epmfs`
  # means "existing path, most free space": a branch is only a candidate for
  # a new file if it ALREADY HAS the parent directory. Creating the tree
  # THROUGH the mount therefore creates it on exactly one branch -- the
  # first mkdir picks one, and every mkdir under it has only that branch as
  # a candidate.
  #
  # Reproduced against real mergerfs with these options: two empty branches,
  # tree created through the pool, and the whole tree landed on d1 while d0
  # got nothing. A new show then wrote to d1. Adding a third empty disk left
  # it with zero entries -- permanently, because it never has the path.
  #
  # So a fresh multi-disk install put the entire library on one disk, and a
  # disk added later was inert. Creating the tree on each BRANCH makes every
  # branch a candidate, which is what lets epmfs balance by free space and
  # what makes an added disk usable. Without a pool, mediaDir is the real
  # directory and is the only root there is.
  pool = cfg.pool;
  pooled = pool.enable && pool.branches != [ ];
  treeRoots = if pooled then pool.branches ++ [ cfg.mediaDir ] else [ cfg.mediaDir ];
in
{
  config = {
    users.groups.${cfg.mediaGroup} = { };

    systemd.tmpfiles.rules = [
      # 0751, not 0750, on both of these: every catalog app's stateDir is
      # ${cfg.stateDir}/<app>, owned by that app's own user, and the app must
      # be able to TRAVERSE down to it. At 0750 root:root nothing but root
      # could, so plexmediaserver's prestart `mkdir -p` failed on the first
      # component with "cannot create directory '/var/lib/ferrum'" and the
      # unit hit its restart limit -- found on the first real hardware run of
      # any catalog app, 2026-09-16. /var/lib/ferrum needs it too: app users
      # are not in the ferrum group, so its group r-x does not help them.
      #
      # The extra bit is `x` WITHOUT `r` deliberately. Traversal into a known
      # path is all an app needs; it cannot list this directory, so one app
      # still cannot enumerate the others. daemon/ and jobs/ keep their own
      # 0750 root:ferrum and are unaffected.
      "d ${cfg.stateDir} 0751 root root - -"
      "d ${cfg.snapshotDir} 0750 root root - -"
      "d /var/lib/ferrum 0751 root ${ferrumdGroup} - -"
      # The TRaSH layout, under ONE root.
      #
      # downloads and media are siblings inside mediaDir rather than
      # separate mounts, and that is the whole point: the *arrs import by
      # hardlinking, a hardlink cannot cross a filesystem, and the old
      # layout put downloads on the OS disk while media lived on the data
      # disks. Imports degraded to copies -- silently, and invisibly until
      # a library is large enough to notice the duplication.
      #
      # The category directories are created rather than left to the apps
      # so that an operator pointing Plex at a library finds it already
      # there, and so every app agrees on where things go without anyone
      # configuring a path by hand.
      "d ${cfg.mediaDir} 0775 root ${cfg.mediaGroup} - -"
    ]
    ++ lib.concatMap
      (root: map (sub: "d ${root}/${sub} 0775 root ${cfg.mediaGroup} - -") trashSubdirs)
      treeRoots
    ++ [
      "d ${cfg.journalDir} 0750 root ${ferrumdGroup} - -"
    ];

    assertions = [
      {
        assertion = cfg.stateDir != "/var/lib/ferrum";
        message = ''
          ferrum.storage.stateDir must not be /var/lib/ferrum itself: that
          directory holds ferrumd's own database and rollback journal, which
          must survive a state rollback rather than be reverted by one.
        '';
      }
      {
        assertion = !(lib.hasInfix cfg.stateDir cfg.snapshotDir);
        message = "ferrum.storage.snapshotDir must not nest inside ferrum.storage.stateDir.";
      }
      {
        assertion =
          cfg.journalDir != "/var/lib/ferrum"
          && !(lib.any (dir: lib.hasInfix dir cfg.journalDir) [
            cfg.stateDir
            cfg.snapshotDir
            cfg.mediaDir
          ]);
        message = ''
          ferrum.storage.journalDir must not be /var/lib/ferrum itself, and
          must be neither equal to nor nested inside stateDir, snapshotDir or
          mediaDir. It is operator-settable and otherwise unconstrained, and
          this module declares a systemd.tmpfiles rule for whatever it is set
          to -- and as the note above says, two rules for one path with
          different arguments is a real conflict, not a merge. NixOS
          re-processes tmpfiles rules on every switch-to-configuration, not
          only at boot (see modules/proxy/authelia.nix:102-104), so a
          colliding value is not a one-time boot failure: it is re-applied in
          the middle of every apply, forever. journalDir = mediaDir would flip
          the media tree from 0775 root:${cfg.mediaGroup} to 0750
          root:${ferrumdGroup} and break every app; journalDir = stateDir
          would regroup the state subvolume root; journalDir =
          /var/lib/ferrum collides with the rule declared above. The default
          /var/lib/ferrum/journal lives under /var/lib/ferrum without being
          equal to it and nests inside none of the three, so it stays legal.
        '';
      }
      {
        assertion = cfg.minFreeGiB > 0;
        message = "ferrum.storage.minFreeGiB must be positive.";
      }
    ];

    boot.supportedFilesystems = [ "btrfs" ];
  };
}
