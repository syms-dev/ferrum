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

    secrets = mkOption {
      type = types.attrsOf (types.submodule {
        options.description = mkOption {
          type = types.str;
          default = "";
        };
      });
      default = { };
      description = "Names ferrumd is permitted to write a secret under. See modules/core/secrets.nix.";
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
    };

    apps = mkOption {
      type = appsType;
      default = { };
      description = "The uniform application catalog. See modules/lib/app-submodule.nix.";
    };
  };
}
