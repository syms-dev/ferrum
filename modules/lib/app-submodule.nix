# The one uniform submodule type shared by every app in the catalog.
#
# This is the load-bearing piece of the whole "UI renders itself from the
# schema" design: because every ferrum.apps.<id> has the exact same option
# shape, the web UI needs exactly one form definition, not one per app.
# checks.schema-uniformity (nix/modules/flake/checks.nix) mechanically
# enforces that every option reachable here stays JSON-expressible -- no
# `path`, `package`, or function-typed option is allowed to sneak in, because
# the UI can only ever write JSON scalars back into settings.json.
{ lib, catalog, stateRoot, proxyEnabled ? false }:
let
  inherit (lib) mkOption mkEnableOption types;
  hostnames = import ./hostnames.nix { inherit lib; };
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
        # Same constraint, same reason, as ferrum.daemon.subdomain: this is
        # interpolated straight into server_name by modules/proxy/nginx.nix
        # via proxyLib.vhostNameFor. It is reachable from the settings API
        # even though the daemon's is now pattern-checked in
        # modules/lib/settings-schema.json, because that schema still defers
        # on the shape of `apps` entirely -- so for this option the module
        # system is the ONLY check there is.
        type = hostnames.dnsLabel;
        default = meta.defaultSubdomain;
        description = "Hostname label under ferrum.proxy.baseDomain.";
      };

      # Defaults to "public" once the proxy is on, because a published app is
      # what this product is for -- the comparison point is Saltbox, where
      # enabling a role puts it on your domain. An app reachable only from the
      # machine itself is a half-finished deployment, not a target state.
      #
      # This default used to be "local" unconditionally, and that caused a real
      # incident on a real host: Jellyfin was enabled, silently got no nginx
      # vhost, and jellyfin.<domain> was then served by whichever vhost nginx
      # treated as default -- Plex's. The operator read that as ferrum routing
      # one app to another. modules/proxy/nginx.nix now also has a catch-all so
      # an unmatched hostname is refused rather than misrouted, but the honest
      # fix is that enabling an app on a host with a proxy should publish it.
      #
      # "local" remains available and meaningful (an app reached only through
      # ferrum's own UI proxying, or a host with no domain); it just is not
      # what an operator gets by accident.
      #
      # Note for whoever enables many apps at once: each "public" app requests
      # its own certificate, and Let's Encrypt rate-limits per registered
      # domain. Staging first is the cheap way to find that out.
      exposure = mkOption {
        type = types.enum [ "local" "lan" "public" ];
        default = if proxyEnabled then "public" else "local";
        defaultText = lib.literalExpression ''if ferrum.proxy.enable then "public" else "local"'';
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
          # Not types.str, and for two grammars rather than one: each entry
          # becomes a `location ${path} {` NAME in modules/proxy/nginx.nix
          # AND the Authelia access_control REGEX `^${path}.*$` in
          # modules/proxy/authelia.nix. Its sibling `subdomain` above got a
          # constrained type one cycle before this one did, which is the
          # miss modules/lib/hostnames.nix's header now names.
          type = types.listOf hostnames.locationPath;
          default = meta.authBypassPaths or [ ];
          description = ''
            Location prefixes served without forward-auth regardless of
            policy. Needed for API clients and for apps that cannot follow
            an auth redirect (e.g. Plex/Jellyfin native clients).

            A prefix, so it starts with "/". nginx's other location forms
            (= exact, ~ regex, @named) are deliberately not expressible:
            none of them is a prefix, and an operator-supplied regex is
            exactly what the Authelia half of this must not accept.
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
