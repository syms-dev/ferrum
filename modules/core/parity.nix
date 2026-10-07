# Parity for the data disks: survive losing one, without striping.
#
# WHY THIS EXISTS. mergerfs has nothing whatsoever to do with redundancy.
# modules/core/pool.nix unions the data disks into one library; if one of
# them dies, everything that was on it is gone. What the union DOES buy is
# that the loss is confined to that disk and every survivor stays
# independently readable -- but "the failure costs you only one disk" is not
# the same property as "the failure costs you nothing", and until this file
# ferrum shipped only the first.
#
# WHY SnapRAID RATHER THAN btrfs RAID OR mdadm. The same reason pool.nix
# gives for mergerfs: the disks already hold the operator's media. SnapRAID
# computes parity over files that are already there and writes it to a
# separate disk; the data disks are not reformatted, not restriped, and stay
# individually mountable on any machine with no ferrum and no SnapRAID
# involved. Real RAID would rewrite them.
#
# WHAT THIS IS NOT. It is not a backup. Parity rebuilds a disk that FAILED.
# A deletion, a corruption that got synced before anyone noticed, ransomware,
# fire, theft and a power supply that takes the whole machine with it all
# reach the parity disk too, because the parity disk is in the same box. See
# ferrum.storage.parity.enable's own description and docs/storage/parity.md,
# which say this in the operator's own words rather than only here.
#
# WHAT IS UPSTREAM AND WHAT IS FERRUM'S. The heavy lifting is nixpkgs'
# services.snapraid (nixos/modules/services/backup/snapraid.nix): it renders
# /etc/snapraid.conf, puts pkgs.snapraid in environment.systemPackages, and
# generates two hardened oneshot units, snapraid-sync and snapraid-scrub.
# What this file adds is the three things that module cannot know:
#
#   1. WHICH disks (R1) -- and the assertion that a parity disk is never
#      also a pool branch.
#   2. WHAT TO SKIP (R2) -- an exclude list computed from ferrum's own
#      resolved storage options, not a copied literal.
#   3. WHEN (R3) -- timers in the self-healing shape modules/proxy/dns.nix
#      already uses, rather than the module's bare OnCalendar.
#
# No new flake input and no new Cargo dependency: pkgs.snapraid comes from
# the nixpkgs revision flake.lock already pins. It is a real addition to a
# parity-enabled host's closure (snapraid 12.4, which pulls smartmontools),
# and nothing on a host with ferrum.storage.parity.enable = false.
{ config, lib, pkgs, ... }:
let
  cfg = config.ferrum.storage;
  pool = cfg.pool;
  parity = cfg.parity;

  layout = import ./trash-layout.nix { inherit lib; };

  # Path containment, not substring containment. Identical reasoning to
  # modules/core/storage.nix's own `containsPath`, which this deliberately
  # mirrors rather than re-derives: `lib.hasInfix "/data" "/data-journal"`
  # is true and means nothing, while the trailing slash makes
  # "/data-journal" correctly NOT nested under "/data".
  containsPath = parent: child: parent == child || lib.hasPrefix "${parent}/" child;
  collide = a: b: containsPath a b || containsPath b a;

  # The roots SnapRAID protects.
  #
  # With a pool these are the branches, NOT the mergerfs mount: SnapRAID
  # must see the real per-disk filesystems, because "which disk is this file
  # on" is the whole question parity answers and the union deliberately hides
  # it. Without a pool there is one data root and it is mediaDir itself --
  # which is what makes parity meaningful on a single-data-disk host, the
  # common small-NAS shape.
  pooled = pool.enable && pool.branches != [ ];
  dataRoots = if pooled then pool.branches else [ cfg.mediaDir ];

  # SnapRAID names each data disk; the name is what `snapraid fix -d` takes
  # and what its reports are keyed by. Derived from position so the name is
  # stable for a given branch list rather than from the path, which would put
  # an operator-chosen string into the generated config's grammar.
  dataDisks = builtins.listToAttrs
    (lib.imap0 (i: root: lib.nameValuePair "d${toString i}" root) dataRoots);

  # SnapRAID's own naming: the first parity file is `parity`, the rest are
  # `2-parity` ... `6-parity`. The nixpkgs module supplies those keywords; the
  # filenames are ours, and matching the keyword keeps a disk recognisable
  # for what it is when somebody looks at it from a rescue shell.
  parityFileName = i: if i == 0 then "snapraid.parity" else "snapraid.${toString (i + 1)}-parity";
  parityFiles = lib.imap0 (i: disk: "${disk}/${parityFileName i}") parity.disks;

  # Where the off-disk copy of the content file lives.
  #
  # SnapRAID requires at least one more content file than parity files, on
  # DIFFERENT disks -- it refuses to run otherwise, confirmed against
  # snapraid 12.4. One per data root gets most of the way there; this one, on
  # the OS disk, is what makes a single-data-disk host legal too.
  contentDir = "/var/lib/ferrum/snapraid";
  contentFiles = [ "${contentDir}/snapraid.content" ]
    ++ map (root: "${root}/snapraid.content") dataRoots;

  # R4. Where a completed sync records that it happened, and how it went.
  #
  # WHY FERRUM RECORDS THIS AT ALL rather than asking snapraid: `snapraid
  # status` does not report a wall-clock last-sync time. It reports "days ago
  # of the last scrub/sync" as a histogram and a sentence, at DAY resolution
  # and about blocks rather than about a run -- confirmed by running it
  # against a freshly-synced array, where it said "the oldest block was
  # scrubbed 0 days ago, the median 0, the newest 0". A dashboard built on
  # that would say "last synced 0 days ago" for anything under 24 hours,
  # which is precisely the frozen gauge this requirement exists to prevent.
  #
  # ExecStopPost rather than ExecStart or a wrapper, because systemd runs it
  # whether the sync SUCCEEDED OR FAILED, and exports $SERVICE_RESULT to it
  # -- so one record covers both, and a failed sync cannot leave behind a
  # file that looks like a successful one. Two lines, epoch seconds then
  # systemd's own result word, written to a temporary name and renamed, so a
  # reader never sees half of one.
  #
  # Absolute store paths rather than bare `date`/`mv`: these units set no
  # `path`, so nothing guarantees coreutils is on PATH inside them.
  parityStateDir = "/var/lib/ferrum/parity";
  recordSync = pkgs.writeShellScript "ferrum-parity-record-sync" ''
    set -eu
    tmp=${parityStateDir}/last-sync.tmp
    ${pkgs.coreutils}/bin/printf '%s\n%s\n' \
      "$(${pkgs.coreutils}/bin/date +%s)" "''${SERVICE_RESULT:-unknown}" > "$tmp"
    ${pkgs.coreutils}/bin/mv -f "$tmp" ${parityStateDir}/last-sync
  '';

  # R2: what SnapRAID must NOT protect, computed from the live option values.
  #
  # THE PATH GRAMMAR, AND IT IS NOT THE OBVIOUS ONE. A SnapRAID `exclude`
  # path is relative to EACH data disk's own root, not absolute on the host.
  # So the per-branch absolute form -- `/mnt/ferrum-disk-0/torrents/**` --
  # excludes nothing at all: it is read as
  # `<disk>/mnt/ferrum-disk-0/torrents/**`, which matches no file that
  # exists. Measured against snapraid 12.4 on real loop-mounted ext4 disks:
  # with the absolute form every download file was still taken into the
  # array (7 added, including all of torrents/ and usenet/); with the
  # disk-root-relative form below exactly the two media/ files were taken.
  # The `/torrents/**` glob form is wrong too -- it also took the downloads
  # (5 added). Only the trailing-slash DIRECTORY form excludes a directory.
  #
  # This matters more than most generated text, because the failure is
  # silent and inverted: the host still syncs, still reports success, and
  # still says it is protected, while spending the entire sync on exactly the
  # data the exclusion existed to skip.
  excludeRelative = root: path:
    lib.optional (lib.hasPrefix "${root}/" path)
      "/${lib.removePrefix "${root}/" path}/";

  # The churn directories of the TRaSH layout, one entry each, named from
  # ./trash-layout.nix rather than spelled here -- see that file's header for
  # why a second copy is the hazard.
  churnExcludes = map (sub: "/${sub}/") layout.churn;

  # The defensive half. ferrum's own state, snapshot and journal roots live
  # on @root by default and SnapRAID never sees them -- but nothing stops an
  # operator relocating one under a pool branch, and modules/core/storage.nix
  # has no assertion forbidding it. Rather than assume the default, ask the
  # resolved values: an entry appears only when the path really does nest
  # under a data root, and names the path relative to that root.
  stateExcludes = lib.concatMap
    (path: lib.concatMap (root: excludeRelative root path) dataRoots)
    [ cfg.stateDir cfg.snapshotDir cfg.journalDir ];

  exclude = lib.unique (
    [
      # SnapRAID's own marker for a file a scrub declined to restore. Taking
      # those into the array would protect the marker, not the file.
      "*.unrecoverable"
      # SnapRAID's own content file, which it writes ONTO a data disk and
      # would otherwise take into the array as ordinary data on the next
      # pass -- confirmed against snapraid 12.4, which listed
      # `add snapraid.content` with every other exclusion already in place.
      "/snapraid.content"
    ]
    ++ churnExcludes
    ++ stateExcludes
  );

  # The disks parity must never collide with, and why each one is here:
  #   * pool branches and mediaDir -- a parity disk inside the pool is not
  #     extra capacity, it is capacity mergerfs and SnapRAID are both
  #     writing to (R1).
  #   * stateDir/snapshotDir/journalDir -- ferrum's own writable roots.
  reservedRoots = pool.branches ++ [ cfg.mediaDir cfg.stateDir cfg.snapshotDir cfg.journalDir ];

  overlappingBranches = builtins.filter (d: builtins.elem d pool.branches) parity.disks;
  collidingReserved = builtins.filter (d: lib.any (r: collide r d) reservedRoots) parity.disks;

  # NOT an assertion here: naming the OS disk itself -- `parity.disks = [ "/" ]`
  # -- is refused one layer earlier, by hostnames.absolutePath, whose pattern
  # requires at least one `/<segment>`. An assertion for it would be one that
  # can never fire, because evaluation stops at the type before any assertion
  # is read. Confirmed by evaluating a real host with that value: it fails
  # with `A definition for option 'ferrum.storage.parity.disks."[definition
  # 1-entry 1]"' is not of type 'string matching the pattern
  # (/[A-Za-z0-9_][A-Za-z0-9._-]*)+'`, naming the option and the value. This
  # repository has shipped three checks that could not fail in one week; a
  # fourth, added knowingly, would be worse than none.
in
{
  config = lib.mkMerge [
    # Gated on parity.enable ALONE, never on `enable && disks != []`.
    #
    # This is pool.nix's lesson copied on purpose rather than rediscovered:
    # both of its assertions once sat inside the very condition they existed
    # to police, so `enable = true` with an empty list switched the checks
    # off and evaluated clean. The same shape here would mean an operator who
    # turns parity on and names no disk is told nothing, gets no snapraid
    # configuration at all, and believes the library is protected.
    {
      assertions = lib.optionals parity.enable [
        {
          assertion = parity.disks != [ ];
          message = ''
            ferrum.storage.parity.enable is on and
            ferrum.storage.parity.disks is empty, so there is no disk to
            compute parity onto and no protection is created.

            That is not a harmless no-op: nothing else on this host reports
            it. No snapraid configuration is generated, no sync runs, and
            every status surface correctly says "not configured" -- while
            the setting that was meant to turn protection on reads as on.

            Either name the mount point of the disk dedicated to parity in
            ferrum.storage.parity.disks, or set
            ferrum.storage.parity.enable = false.
          '';
        }
        {
          assertion = overlappingBranches == [ ];
          message = ''
            ferrum.storage.parity.disks and ferrum.storage.pool.branches
            both contain ${lib.concatStringsSep ", " overlappingBranches}.

            A disk cannot be both. The pool would union it as one more
            branch and write library files to it, while SnapRAID would write
            a parity file across the whole of it -- two things claiming the
            same blocks, on the one disk whose entire job is to still be
            readable when another disk is not. The parity would be
            progressively invalidated by the library writes landing beside
            it, and the library files stored there would be the only ones on
            the host with no parity at all.

            Remove the path from one of the two lists. If this disk is meant
            to hold library content, take it out of
            ferrum.storage.parity.disks; if it is meant to hold parity, take
            it out of ferrum.storage.pool.branches and out of
            /etc/ferrum/custom/media.nix.
          '';
        }
        {
          # Deliberately AFTER the pool-overlap assertion and worded not to
          # duplicate it: an operator who put a branch in both lists should
          # read the message that explains what the pool does to a parity
          # disk, not this one.
          assertion = collidingReserved == overlappingBranches;
          message = ''
            ferrum.storage.parity.disks contains a path that is equal to,
            inside, or a parent of one of ferrum's own storage roots:
            ${lib.concatStringsSep ", " collidingReserved}.

            Reserved here are ferrum.storage.mediaDir (${cfg.mediaDir}),
            ferrum.storage.stateDir (${cfg.stateDir}),
            ferrum.storage.snapshotDir (${cfg.snapshotDir}),
            ferrum.storage.journalDir (${cfg.journalDir}) and every
            ferrum.storage.pool.branches entry. A parity disk holds one
            large file that SnapRAID rewrites on every sync and nothing
            else; pointing it at a directory ferrum already manages means
            the two write to the same place.

            Name the mount point of a disk dedicated to parity.
          '';
        }
      ];
    }

    (lib.mkIf (parity.enable && parity.disks != [ ]) {
      # The content file that does not live on a data disk needs a home that
      # exists before the first sync. 0750 root:root: it is SnapRAID's index
      # of every protected file, nothing unprivileged reads it, and
      # /var/lib/ferrum itself is already 0751 so root can traverse in.
      systemd.tmpfiles.rules = [
        "d ${contentDir} 0750 root root - -"
        # 0755, not 0750: the unprivileged daemon never reads this directly
        # -- `ferrum-apply parity-status` does, as root -- but a mode that
        # root alone can traverse would make the record unreadable from an
        # ordinary shell for no benefit. The file inside carries a timestamp
        # and the word "success"; there is nothing here to protect.
        "d ${parityStateDir} 0755 root root - -"
      ];

      services.snapraid = {
        enable = true;
        inherit dataDisks parityFiles contentFiles exclude;
      };

      # R3. The upstream module schedules both units with `startAt`, which is
      # sugar for a bare `OnCalendar`. That is the wrong shape for a host that
      # is not always on: a nightly OnCalendar that came due while the machine
      # was asleep is simply missed, and the array stays unprotected until the
      # same hour comes round again.
      #
      # The shape below is modules/proxy/dns.nix's, copied because it is the
      # one already proven here for a non-destructive self-healing background
      # task: a first run shortly after boot catches the common real case (the
      # library changed while the box was down), OnUnitActiveSec paces the
      # rest, and Persistent = true makes a missed run happen on resume rather
      # than a full interval later.
      #
      # mkForce because `startAt` has already populated timerConfig with
      # OnCalendar, and a merge would leave BOTH -- a timer that fires on the
      # interval and again at 01:00, which is not what either setting says.
      systemd.timers.snapraid-sync = {
        enable = parity.sync.enable;
        timerConfig = lib.mkForce {
          OnBootSec = "15min";
          OnUnitActiveSec = "${toString parity.sync.intervalMinutes}min";
          Persistent = true;
          Unit = "snapraid-sync.service";
        };
      };

      systemd.timers.snapraid-scrub = {
        enable = parity.scrub.enable;
        timerConfig = lib.mkForce {
          # Later than sync's, so a host that has just booted syncs what
          # changed while it was off before it spends I/O re-reading what
          # did not.
          OnBootSec = "45min";
          OnUnitActiveSec = "${toString parity.scrub.intervalMinutes}min";
          Persistent = true;
          Unit = "snapraid-scrub.service";
        };
      };

      # Both units already carry Nice = 19, IOSchedulingPriority = 7 and
      # CPUSchedulingPolicy = "batch" from the upstream module. What they do
      # NOT carry is an IOSchedulingClass, so that priority is a
      # best-effort priority: a sync still competes with a Plex transcode
      # reading off the same disk. "idle" is the class that means "only when
      # nothing else wants the disk", which is the correct relationship
      # between a background integrity job and somebody watching a film.
      systemd.services.snapraid-scrub.serviceConfig.IOSchedulingClass = "idle";

      systemd.services.snapraid-sync.serviceConfig = {
        IOSchedulingClass = "idle";

        # R4's timestamp, recorded by the run that earns it.
        #
        # ReadWritePaths is ADDITIVE here rather than a replacement: NixOS's
        # unit-option type merges list-valued directives by concatenation,
        # so this adds the state directory to the list the upstream module
        # computed from the configured disks rather than dropping it.
        # Confirmed by evaluating a real host and reading the generated unit
        # back, which matters because getting it wrong would silently leave
        # the sync unable to write to the data disks it exists to protect.
        ExecStopPost = "${recordSync}";
        ReadWritePaths = [ parityStateDir ];
      };
    })
  ];
}
