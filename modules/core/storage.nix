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
{ config, lib, options, ... }:
let
  cfg = config.ferrum.storage;

  # Is ferrum's media root actually backed by a mount, and does this host
  # look like one that has data disks at all?
  #
  # mediaDir is operator-settable through PUT /api/settings and, unlike
  # every other storage root, it was tied to nothing. Setting it to
  # "/srv/media2" evaluated with ZERO assertions and ZERO warnings while
  # producing eighteen new tmpfiles directories on the OS disk and
  # repointing every *arr root folder and download path
  # (modules/core/reconciler.nix reads it for both). The installer mounts
  # the data disks at mediaDir's default, so the library becomes invisible
  # and downloads land on the root filesystem -- the "7TB present, mounted,
  # and invisible" incident this file's own comments describe, replayed
  # through the UI.
  #
  # stateDir and snapshotDir are already bound to reality:
  # modules/core/state-restore.nix refuses a value with no fileSystems
  # entry. The one path with a silent failure mode was the one with no such
  # guard, so this follows that file's shape rather than inventing one.
  #
  # What it deliberately does NOT do is require mediaDir to be a mount
  # unconditionally, the way state-restore.nix requires it of stateDir.
  # mediaDir's own option documentation says the opposite in as many words:
  # "On a host with data disks this is where they are mounted (or where
  # their pool is presented); on a host without, it is a plain directory on
  # the OS disk." A blanket requirement would refuse that documented
  # single-disk host.
  #
  # So the condition is "does this host have data disks", and there are
  # exactly two signals for that at evaluation time: pool branches were
  # listed, or something is mounted at mediaDir's DEFAULT -- which is where
  # crates/ferrum-install/src/render.rs puts a single data disk, and the
  # place it is moved AWAY from when this goes wrong. Read off the option
  # rather than written out as "/data", so the two cannot drift.
  #
  # The gap that leaves, stated rather than hidden: a host whose disks were
  # hand-mounted at some third path, with mediaDir never having pointed at
  # the default, is not detected. Closing that would mean guessing which of
  # a host's mounts are "data" ones, and a wrong guess refuses a legitimate
  # host at apply time -- a worse failure than the one being closed here.
  # modules/core/storage.nix's ferrum-media-tree unit covers the runtime
  # half of the same question.
  # Path containment, which lib.hasInfix is not.
  #
  # Both storage collision assertions below used `lib.hasInfix a b`, a plain
  # SUBSTRING test, to ask a question about path nesting. It answers a
  # different question and it is wrong in both directions, proved by
  # evaluation:
  #
  #   * FALSE POSITIVE. snapshotDir = "/var/lib/ferrum/state-snaps" is a
  #     SIBLING of the default stateDir "/var/lib/ferrum/state" and was
  #     rejected as nested inside it, because the parent's string really is
  #     a substring of the child's. Same for journalDir = "/data-journal"
  #     against the default mediaDir "/data". Two legal layouts refused at
  #     apply time, with a message saying something untrue about them.
  #   * FALSE NEGATIVE. The reverse nesting was missed entirely: stateDir =
  #     "/var/lib/ferrum/snapshots/state" inside snapshotDir =
  #     "/var/lib/ferrum/snapshots" evaluated clean. That is the same
  #     hazard with the arguments swapped, and modules/core/state-restore.nix
  #     cares about it in both directions -- it swaps @state and @snapshots
  #     as two subvolumes of one volume, which one containing the other is
  #     not.
  #
  # `hasPrefix "${parent}/"` is the containment test: the trailing slash is
  # what makes "/data-journal" not start with "/data/" while "/data/journal"
  # does. Equality is folded in because a path contains itself for every
  # purpose these assertions care about -- two tmpfiles rules for one path
  # with different arguments is the conflict the journalDir check exists to
  # prevent, and stateDir == snapshotDir is a rollback that swaps a
  # subvolume with itself. Both were previously caught only as an artefact
  # of hasInfix, so folding equality in here is what stops this fix from
  # quietly removing coverage.
  containsPath = parent: child: parent == child || lib.hasPrefix "${parent}/" child;
  collide = a: b: containsPath a b || containsPath b a;

  defaultMediaDir = options.ferrum.storage.mediaDir.default;
  mediaDirIsMounted = config.fileSystems ? ${cfg.mediaDir};
  hostHasDataDisks =
    cfg.pool.branches != [ ] || config.fileSystems ? ${defaultMediaDir};

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

  # The tree roots this host declares an actual mount for.
  #
  # Only these can be raced, and only these can be waited for. A root with
  # no fileSystems entry is an ordinary directory on a filesystem that is
  # already up by the time tmpfiles runs, so there is nothing to order
  # against and nothing to re-create.
  mountedTreeRoots = builtins.filter (root: config.fileSystems ? ${root}) treeRoots;
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
        # Mutual, not one-way. modules/core/state-restore.nix mounts ONE
        # top-level btrfs volume and expects @state and @snapshots to be two
        # subvolumes of it; either one containing the other breaks that, and
        # only one direction was checked.
        assertion = !(collide cfg.stateDir cfg.snapshotDir);
        message = ''
          ferrum.storage.stateDir ("${cfg.stateDir}") and
          ferrum.storage.snapshotDir ("${cfg.snapshotDir}") must be
          separate paths, with neither equal to nor nested inside the other.
          modules/core/state-restore.nix swaps them as two subvolumes of one
          btrfs volume, which a path containing the other is not.
        '';
      }
      {
        assertion =
          cfg.journalDir != "/var/lib/ferrum"
          && !(lib.any (dir: collide dir cfg.journalDir) [
            cfg.stateDir
            cfg.snapshotDir
            cfg.mediaDir
          ]);
        message = ''
          ferrum.storage.journalDir must not be /var/lib/ferrum itself, and
          must be neither equal to, nested inside, nor a parent of stateDir,
          snapshotDir or mediaDir. It is operator-settable and otherwise
          unconstrained, and
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
      {
        # See `hostHasDataDisks` above for why this is conditional and what
        # it deliberately does not catch.
        assertion = !hostHasDataDisks || mediaDirIsMounted;
        message = ''
          ferrum.storage.mediaDir is set to "${cfg.mediaDir}", and nothing is
          mounted there -- but this host has data disks. fileSystems has no
          entry for that path, so it is an ordinary directory on whatever
          filesystem already covers it, which on a ferrum host is the OS
          disk.

          Nothing downstream reports this. This module would create the
          whole TRaSH tree under it, modules/core/reconciler.nix would point
          every *arr root folder and every download client path at it, and
          the apps would start and import happily -- onto the root
          filesystem, while the data disks sit mounted somewhere else,
          holding a library nothing can see. That is a disk filling up on a
          host that appears to be working.

          Either mount the data there (a fileSystems entry for
          "${cfg.mediaDir}", normally written into /etc/ferrum/custom/), or
          set ferrum.storage.pool.branches and ferrum.storage.pool.enable so
          modules/core/pool.nix presents the pool at that path, or set
          ferrum.storage.mediaDir back to where the disks actually are.
        '';
      }
    ];

    # Re-seed the media tree once the data mounts are actually up.
    #
    # The tree above is created by systemd.tmpfiles.rules, and
    # systemd-tmpfiles-setup.service is `After=local-fs.target`. Every
    # ferrum data mount carries `nofail` -- modules/core/pool.nix says why,
    # and the reason is good: a media host that boots with a smaller pool
    # beats one that does not boot. But per systemd.mount(5), `nofail` means
    # the mount is only WANTED by local-fs.target and is explicitly NOT
    # ordered before it. So tmpfiles may run first, create the whole TRaSH
    # tree on the ROOT filesystem underneath the mountpoint, and have the
    # mount then land on top and shadow it.
    #
    # What that costs is not cosmetic, and it is worst exactly where the
    # tree matters most. On pool branches, the per-branch seeding this file
    # exists to do (see treeRoots above) would be written to the root fs and
    # every branch would come up EMPTY -- which under mergerfs' epmfs create
    # policy is the "whole library on one disk" state that seeding per
    # branch was introduced to prevent.
    #
    # This unit is ordered after those mounts by RequiresMountsFor and
    # re-applies the SAME tmpfiles rules, scoped by --prefix to the media
    # roots. systemd-tmpfiles is idempotent, so on a host that did not race
    # this is a no-op costing one oneshot; on a host that did, it creates
    # the tree where it belongs -- on the disk rather than under it.
    #
    # It exists only when at least one tree root has a declared mount. On a
    # host with no data disks there is nothing to wait for and nothing to
    # race, so no unit is generated and behaviour is unchanged.
    #
    # RequiresMountsFor also turns the silent leg loud. `nofail` means a
    # disk that never arrives leaves the host booting clean and saying
    # nothing while apps write media to the OS root until it fills
    # (crates/ferrum-install/src/render.rs records that as a real incident).
    # A failed mount now fails THIS unit, which is visible in `systemctl
    # --failed`, without blocking the boot that nofail exists to protect.
    #
    # HONESTY ABOUT THE EVIDENCE: the race is argued from systemd's
    # documented ordering semantics and from the units' own After=
    # relationships. It has NOT been observed on a booting host, and this
    # repo has no VM test that could observe it -- a deterministic
    # reproduction needs a slow-arriving block device, which the test VMs do
    # not model. That is why the fix is additive and idempotent rather than
    # a restructuring of where the tree is created: it is correct whether or
    # not the race is real, and it removes nothing that works today.
    systemd.services.ferrum-media-tree = lib.mkIf (mountedTreeRoots != [ ]) {
      description = "Seed the ferrum media tree on its data mounts";
      wantedBy = [ "multi-user.target" ];
      # Matches the ordering idiom modules/core/generations.nix already uses
      # for this target. Note what it does and does not buy: the target's
      # members are pulled in by `wantedBy` and are not themselves ordered
      # against it, so this orders against the target being REACHED rather
      # than acting as a hard barrier in front of every app.
      before = [ "ferrum-apps.target" ];
      after = [ "local-fs.target" ];
      unitConfig.RequiresMountsFor = mountedTreeRoots;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      # --prefix scopes this to the media roots, so it re-applies the rules
      # written above and nothing else on the host. config.systemd.package
      # rather than pkgs.systemd: the same systemd the host actually runs.
      script = lib.concatMapStringsSep "\n"
        (root: "${config.systemd.package}/bin/systemd-tmpfiles --create --prefix=${root}")
        mountedTreeRoots;
    };

    boot.supportedFilesystems = [ "btrfs" ];
  };
}
