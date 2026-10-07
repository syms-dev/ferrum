# Catalog metadata for Decluttarr -- the first catalog app with NO web
# interface at all.
#
# `headless = true` is the whole of that difference, and it is declared here
# rather than inferred for the reason every other per-app capability
# (mediaCategory, downloadSubdir, portIsFixed, unfreePackages) is declared
# here: adding an app must stay "add a directory under modules/apps", and a
# second place to register one is a second place to forget.
#
# WHAT IT BUYS. modules/lib/app-submodule.nix defaults `exposure` to "local"
# for a headless app instead of to "public", and modules/core/options.nix
# refuses an enabled headless app that has been moved off it. "local" is the
# existing enum value that already means "no vhost", so the four consumers of
# modules/proxy/lib.nix's exposedApps/publicApps -- nginx's virtualHosts,
# Authelia's access_control rules, ACME's certs and dns.nix's records -- all
# exclude this app by construction, with no new code in any of them and no
# per-app name anywhere in modules/proxy/.
#
# WHY THAT MATTERS HERE RATHER THAN BEING A TIDINESS POINT. The default was
# "public", and a public app gets `proxy_pass http://127.0.0.1:<port>` built
# from an option nothing honours. That is exactly the defect fixed in
# 2ec53b6, where nginx proxied qBittorrent at an address nothing was bound
# to; Authelia answers the unauthenticated probe with a 302 first, so the
# vhost looks healthy and 502s on every real request. Giving a UI-less app a
# nominal port would reintroduce that by construction rather than by
# accident. nix/modules/flake/checks.nix's `headless-apps-get-no-front-door`
# is the mechanical half, derived from the evaluated host rather than from
# this field.
{
  id = "decluttarr";
  displayName = "Decluttarr";
  category = "media-automation";
  summary = "Clears stuck and failed downloads out of the Sonarr/Radarr queues.";

  # No listener, in any namespace, on any host. Decluttarr is an outbound
  # API client and a sleep loop -- `python3 main.py`, no server, no socket.
  headless = true;

  # 0, and not an arbitrary spare number, because the honest value of "which
  # port does this app listen on" is "none" and 0 is the one member of
  # types.port that can never be a listening port. The uniform submodule
  # requires SOME value (that uniformity is what lets the web UI render one
  # form for the whole catalog -- see modules/lib/app-submodule.nix), so the
  # choice is between a number that is false and a number that is visibly
  # not a port. modules/core/options.nix refuses any attempt to change it.
  defaultPort = 0;

  # Inert for a headless app: no vhost is generated, so no server_name is
  # built from this. It is still the app's id, which keeps
  # checks.installer-offers-every-catalog-app's subdomain invariant true for
  # the whole catalog rather than true-with-an-exception.
  defaultSubdomain = "decluttarr";

  # It reads *arr queues and tells qBittorrent to drop torrents. It never
  # touches the library or the download tree itself -- the *arr issues the
  # delete through its own download-client connection.
  defaultMediaAccess = "none";

  # Reachable from nothing, so the forward-auth policy is moot; "bypass" is
  # the honest spelling of "there is no door to put a lock on". Note that
  # modules/proxy/lib.nix's authGated already returns false for an
  # exposure = "local" app regardless of this value, so this is a statement
  # of intent rather than the mechanism.
  defaultAuthPolicy = "bypass";
  authBypassPaths = [ ];

  # No healthCheck: crates/ferrum-apply's post-apply health probe dials
  # http://<host>:<port><path>, and there is no such endpoint here. The
  # field is optional (modules/apps/*/meta.nix's own shape) and omitting it
  # is the correct answer, not a gap -- systemd is the liveness signal for
  # this unit, and `ferrum-apps.target` already requires it active.

  # Deliberately EMPTY, and this is a decision rather than an oversight.
  #
  # modules/core/reconciler.nix turns every consumes/providesTo edge into a
  # REGISTRATION: a `downloadClient` or `application` POSTed into the
  # consumer's own API. Decluttarr registers nothing in Sonarr and exposes
  # no API for Sonarr to be registered into -- it is a client of both, in
  # the plain HTTP sense, which is not what this field means here. Declaring
  # consumes = [ "sonarr" "radarr" ] would additionally force a symmetric
  # providesTo = [ "decluttarr" ] into two other apps' meta.nix (the
  # reconciler asserts that symmetry at eval time) and would then make
  # ferrum-reconcile POST a download-client registration at a decluttarr
  # API that does not exist.
  #
  # Its configuration is instead generated at EVAL time, the way
  # modules/core/recyclarr.nix generates Recyclarr's -- see
  # modules/apps/decluttarr/service.nix for the full argument.
  integrations = {
    providesTo = [ ];
    consumes = [ ];
  };

  # Four knobs, all of them about how patient and how loud it is. Everything
  # else -- which *arrs exist, where they listen, their API keys, which
  # download client is called what -- ferrum already knows and generates;
  # see the service module. The defaults here are the conservative ones and
  # the reasoning for each is in service.nix beside the value it produces.
  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = {
      testRun = {
        type = "boolean";
        default = false;
        description =
          "Log what would be removed and remove nothing. The way to watch it "
          + "for a few days before letting it act.";
      };
      intervalMinutes = {
        type = "integer";
        minimum = 5;
        maximum = 1440;
        default = 30;
        description = "Minutes between passes over the queues.";
      };
      maxStrikes = {
        type = "integer";
        minimum = 1;
        maximum = 50;
        default = 5;
        description =
          "Consecutive passes a download must look broken before it is acted "
          + "on. With the default interval, 5 strikes is about two and a half "
          + "hours of patience.";
      };
      logLevel = {
        type = "string";
        enum = [ "INFO" "VERBOSE" "DEBUG" ];
        default = "VERBOSE";
        description =
          "VERBOSE by default: at INFO the journal records THAT something was "
          + "removed, and the reason is logged one level down.";
      };
    };
  };

  docsUrl = "https://github.com/ManiMatter/decluttarr";
  iconSlug = "decluttarr";
}
