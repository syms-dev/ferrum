# Catalog metadata for Sonarr. Loaded by modules/lib/catalog.nix, and
# consumed by both the module system (as defaults for the uniform
# app-submodule) and the web UI (verbatim, via the generated catalog.json --
# see nix/modules/flake/packages.nix).
{
  id = "sonarr";
  displayName = "Sonarr";
  category = "media-automation";
  summary = "TV series collection manager for Usenet and BitTorrent.";

  defaultPort = 8989;
  defaultSubdomain = "sonarr";
  defaultMediaAccess = "readwrite";
  defaultAuthPolicy = "two_factor";

  # /api, /feed, /ping and /signalr must reach Sonarr without a forward-auth
  # redirect, or every API client (Prowlarr, mobile apps, ferrum's own
  # reconciler) breaks the moment ferrum.auth.enable flips on.
  authBypassPaths = [ "/api" "/feed" "/ping" "/signalr" ];

  healthCheck = {
    path = "/ping";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ "prowlarr" ];
    consumes = [ "qbittorrent" "sabnzbd" ];
  };

  # Validated against the app's `settings` attrset by the UI before it is
  # ever written into settings.json -- see modules/lib/app-submodule.nix.
  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties.urlBase = {
      type = "string";
      default = "";
    };
  };

  docsUrl = "https://wiki.servarr.com/sonarr";
  iconSlug = "sonarr";
}
