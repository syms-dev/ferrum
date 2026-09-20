# The cross-cutting ferrum.* namespaces, plus ferrum.apps -- the uniform
# app catalog built from modules/lib/app-submodule.nix.
#
# Every option under ferrum.* must stay JSON-expressible: this whole
# namespace is what a settings.json document can populate, and it is what
# checks.schema-uniformity (nix/modules/flake/checks.nix) walks to enforce
# that promise. Anything that needs a `path` or a `package` belongs in
# /etc/ferrum/custom/ instead, which the ferrum UI never touches.
{ config, lib, ... }:
let
  inherit (lib) mkOption mkEnableOption types;

  catalog = import ../lib/catalog.nix { inherit lib; };

  appsType = import ../lib/app-submodule.nix {
    inherit lib catalog;
    stateRoot = config.ferrum.storage.stateDir;
    # Threaded the same way stateRoot is, so the exposure default can depend on
    # whether this host actually has a reverse proxy to publish through.
    proxyEnabled = config.ferrum.proxy.enable;
  };
in
{
  options.ferrum = {
    schemaVersion = mkOption {
      type = types.int;
      default = (import ../lib/migrations.nix { inherit lib; }).currentVersion;
      readOnly = true;
      description = "Version of the ferrum settings.json schema this module tree expects.";
    };

    storage = {
      stateDir = mkOption {
        type = types.str;
        default = "/var/lib/ferrum/state";
        description = "Root of the btrfs subvolume that participates in snapshot/rollback.";
      };
      snapshotDir = mkOption {
        type = types.str;
        default = "/var/lib/ferrum/snapshots";
      };
      journalDir = mkOption {
        type = types.str;
        default = "/var/lib/ferrum/journal";
        description = "Where ferrum-apply records one entry per generation, correlating it to its state snapshot. Lives on @root (not the snapshotted @state subvolume) -- see the plan's storage-layout rule that /var/lib/ferrum itself must survive a rollback.";
      };
      mediaDir = mkOption {
        type = types.str;
        default = "/data";
        description = ''
          The single root under which downloads AND media both live.

          One root is not a stylistic choice. The *arr apps import by
          HARDLINKING from the download directory into the library, and a
          hardlink cannot cross a filesystem -- so if downloads and media
          sit on different mounts the import silently degrades to a copy:
          double the space while it runs, a long pause per import, and
          broken seeding when the original is moved rather than copied.
          That is the single most common misconfiguration the TRaSH guides
          exist to prevent, and ferrum had it by construction until this
          default changed: media on the data disks, downloads at
          /srv/media/downloads on the OS disk.

          `/data` follows the TRaSH convention, so an operator reading any
          *arr guide finds the paths where the guide says they are.

          On a host with data disks this is where they are mounted (or
          where their pool is presented); on a host without, it is a plain
          directory on the OS disk. The layout beneath it is the same
          either way, so a small install is not a different shape.
        '';
      };

      pool = {
        enable = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Present several data disks as one filesystem at mediaDir, so
            apps see a single library rather than one per disk.

            Set by the installer when it finds more than one data disk. A
            single disk needs no pool -- it is mounted at mediaDir
            directly.
          '';
        };

        branches = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "/mnt/ferrum-disk-0" "/mnt/ferrum-disk-1" ];
          description = ''
            The individual disk mount points the pool unions, in order.
            Their mounts are declared in /etc/ferrum/custom/, which is the
            operator's to edit; this list is what the pool is built from.
          '';
        };

        minFreeGiB = mkOption {
          type = types.int;
          default = 50;
          description = ''
            A branch with less than this free is skipped when placing a NEW
            file.

            This is what stops `epmfs` filling a disk. Without it, once a
            show lives on a disk every later season goes to that disk too,
            full or not, and the write fails inside an app that reports it
            badly or not at all. With it, the new seasons land elsewhere --
            the show is then split across disks, which is the honest trade:
            keeping a show together matters right up to the point where it
            would mean not writing it at all.
          '';
        };

        policy = mkOption {
          type = types.enum [ "epmfs" "mfs" ];
          default = "epmfs";
          description = ''
            Where a new file goes.

            epmfs -- existing path, most free space. Among the disks that
            already hold the target directory, pick the emptiest. Keeps a
            show's seasons on one disk, so losing a disk loses whole shows
            rather than gaps in every show, and idle disks can spin down.

            mfs -- most free space, ignoring what is already where.
            Balances new writes more evenly and scatters a series.

            NEITHER MOVES EXISTING DATA. This chooses where the next file
            is written; nothing rebalances what is already on the disks.
          '';
        };
      };
      mediaGroup = mkOption {
        type = types.str;
        default = "ferrum-media";
      };
      minFreeGiB = mkOption {
        type = types.int;
        default = 10;
        description = "Apply refuses to run below this much free space on the state filesystem.";
      };
      keepGenerations = mkOption {
        type = types.int;
        default = 10;
        description = ''
          How many application-state snapshots `ferrum-apply gc` keeps.
          Every apply takes one snapshot, so this is roughly "how many
          applies back can I roll to".

          The snapshot belonging to the currently-running generation is
          ALWAYS kept, even when it falls outside this window -- on a host
          that has been rebooted into an older generation it can easily be
          older than `keepGenerations` newer ones, and pruning it would
          remove the way back. See crates/ferrum-apply/src/gc.rs.

          Snapshots are not free: btrfs pins the extents they reference, so
          a SQLite-heavy app rewritten in place keeps historical extents
          alive for as long as any snapshot references them. Raising this a
          lot on a host with busy *arr databases costs real disk.
        '';
      };
    };

    secretsDir = mkOption {
      type = types.str;
      default = "/etc/ferrum/secrets";
      description = ''
        Where per-secret .sops files live on a real deployed box (this is
        NOT the decrypted output -- that's sops-nix's own /run/secrets/,
        entirely outside ferrum's control). /etc/ferrum is the host's own
        flake root (see the Phase 1.3 design doc), so paths under here get
        copied into the Nix store at eval time same as settings.json --
        that's fine, since only ciphertext ever lives here.
      '';
    };

    proxy = {
      enable = mkEnableOption "the ferrum reverse proxy (nginx + ACME)";

      baseDomain = mkOption {
        type = types.str;
        default = "";
        example = "home.example.com";
      };

      acme = {
        email = mkOption {
          type = types.str;
          default = "";
        };
        dnsProvider = mkOption {
          type = types.enum [ "cloudflare" ];
          default = "cloudflare";
        };
        # A ferrum.secrets key, never a path -- the UI can only ever name a
        # secret, not point at one on disk.
        credentialSecret = mkOption {
          type = types.str;
          default = "acme-dns";
        };
        staging = mkOption {
          type = types.bool;
          default = false;
        };
      };

      trustedNetworks = mkOption {
        type = types.listOf types.str;
        default = [ "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16" ];
      };
    };

    auth = {
      enable = mkEnableOption "Authelia forward-auth";
      adminEmail = mkOption {
        type = types.str;
        default = "";
      };
    };

    recyclarr = {
      enable = mkEnableOption "opinionated TRaSH-Guide quality-profile sync for Sonarr/Radarr via Recyclarr";
    };

    secrets = mkOption {
      type = types.attrsOf (types.submodule {
        options.description = mkOption {
          type = types.str;
          default = "";
        };
      });
      default = { };
      description = ''
        Names ferrumd is permitted to write a secret under. See
        modules/core/secrets.nix. Declaring a name here also gates whichever
        catalog app consumes it -- e.g. `qbittorrent-vpn` both permits that
        secret's existence AND enables qBittorrent's VPN-gated network
        namespace (see modules/apps/qbittorrent/service.nix's `vpnEnabled`).
        Declaring a name requires the corresponding
        `<ferrum.secretsDir>/<name>.sops` file to already exist on disk --
        this option does not create or generate one.
      '';
    };

    backup = {
      enable = mkEnableOption "scheduled state backups";
      repo = mkOption {
        type = types.str;
        default = "";
      };
      schedule = mkOption {
        type = types.str;
        default = "daily";
      };
      passwordSecret = mkOption {
        type = types.str;
        default = "restic-password";
      };
    };

    apply = {
      autoRollbackOnFailure = mkOption {
        type = types.bool;
        default = false;
        description = "Off by default: health checks aren't mature enough to trust with an automatic reboot yet.";
      };
      healthCheckTimeoutSec = mkOption {
        type = types.int;
        default = 120;
      };
    };

    daemon = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Whether ferrumd (the web UI) runs on this host.";
      };
      port = mkOption {
        type = types.port;
        default = 7788;
      };
      listenAddress = mkOption {
        type = types.str;
        default = "127.0.0.1";
      };
      subdomain = mkOption {
        type = types.str;
        default = "ferrum";
        description = "Hostname label under ferrum.proxy.baseDomain for the daemon's own web UI -- same mechanism as every app's own subdomain option, just not tied to the catalog since the daemon isn't a catalog app.";
      };
    };

    apps = mkOption {
      type = appsType;
      default = { };
      description = "The uniform application catalog. See modules/lib/app-submodule.nix.";
    };
  };
}
