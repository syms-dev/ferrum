# The one uniform submodule type shared by every app in the catalog.
#
# This is the load-bearing piece of the whole "UI renders itself from the
# schema" design: because every ferrum.apps.<id> has the exact same option
# shape, the web UI needs exactly one form definition, not one per app.
# checks.schema-uniformity (nix/modules/flake/checks.nix) mechanically
# enforces that every option reachable here stays JSON-expressible -- no
# `path`, `package`, or function-typed option is allowed to sneak in, because
# the UI can only ever write JSON scalars back into settings.json.
{ lib, catalog, stateRoot }:
let
  inherit (lib) mkOption mkEnableOption types;
in
types.attrsOf (types.submodule ({ name, ... }:
  let
    meta = catalog.${name}
      or (throw "ferrum: '${name}' is not a known app -- no modules/apps/${name}/meta.nix exists");
  in
  {
    options = {
      enable = mkEnableOption meta.displayName;

      port = mkOption {
        type = types.port;
        default = meta.defaultPort;
        description = "Loopback port the service listens on.";
      };

      subdomain = mkOption {
        type = types.str;
        default = meta.defaultSubdomain;
        description = "Hostname label under ferrum.proxy.baseDomain.";
      };

      exposure = mkOption {
        type = types.enum [ "local" "lan" "public" ];
        default = "local";
        description = ''
          local  -- loopback only, reached through the ferrum UI's own proxying.
          lan    -- an nginx vhost restricted to ferrum.proxy.trustedNetworks.
          public -- an nginx vhost on the public listener with a real certificate.
        '';
      };

      stateDir = mkOption {
        type = types.str;
        default = "${stateRoot}/${name}";
        description = ''
          Must stay under ferrum.storage.stateDir to participate in the
          snapshot-and-rollback mechanism. Apps that write state elsewhere
          will not be rolled back with the rest of the system.
        '';
      };

      auth = {
        policy = mkOption {
          type = types.enum [ "bypass" "one_factor" "two_factor" ];
          default = meta.defaultAuthPolicy or "two_factor";
          description = "Forward-auth requirement once ferrum.auth.enable is true.";
        };

        bypassPaths = mkOption {
          type = types.listOf types.str;
          default = meta.authBypassPaths or [ ];
          description = ''
            Location prefixes served without forward-auth regardless of
            policy. Needed for API clients and for apps that cannot follow
            an auth redirect (e.g. Plex/Jellyfin native clients).
          '';
        };
      };

      mediaAccess = mkOption {
        type = types.enum [ "none" "read" "readwrite" ];
        default = meta.defaultMediaAccess or "none";
      };

      resources = {
        memoryMax = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "2G";
        };
        cpuQuota = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "200%";
        };
      };

      backup.enable = mkOption {
        type = types.bool;
        default = true;
      };

      # Deliberately restricted to JSON scalars -- no `package`, no `path`,
      # nothing the UI could not itself have produced. Cross-checked against
      # meta.settingsSchema by the UI before it ever reaches here.
      settings = mkOption {
        type = types.attrsOf (types.oneOf [
          types.bool
          types.int
          types.str
          (types.listOf types.str)
        ]);
        default = { };
        description = "App-specific knobs, validated against meta.settingsSchema by the UI.";
      };
    };
  }))
