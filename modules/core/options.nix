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
  };
in
{
  options.ferrum = {
    schemaVersion = mkOption {
      type = types.int;
      default = 1;
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
        default = "/srv/media";
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
