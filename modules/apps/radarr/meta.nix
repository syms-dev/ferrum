# Catalog metadata for Radarr. Mirrors modules/apps/sonarr/meta.nix exactly
# -- Radarr shares Sonarr's servarr framework (same settings-options.nix),
# so the same shape applies verbatim.
{
  id = "radarr";
  displayName = "Radarr";
  category = "media-automation";
  summary = "Movie collection manager for Usenet and BitTorrent.";

  defaultPort = 7878;
  defaultSubdomain = "radarr";
  defaultMediaAccess = "readwrite";
  defaultAuthPolicy = "two_factor";

  # /api, /feed, /ping must reach Radarr without a forward-auth redirect,
  # or every API client (Prowlarr, mobile apps, ferrum's own reconciler)
  # breaks the moment ferrum.auth.enable flips on. Same reasoning as
  # Sonarr's identical bypass list.
  authBypassPaths = [ "/api" "/feed" "/ping" ];

  healthCheck = {
    path = "/ping";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ "prowlarr" ];
    consumes = [ "qbittorrent" "sabnzbd" ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties.urlBase = {
      type = "string";
      default = "";
    };
  };

  docsUrl = "https://wiki.servarr.com/radarr";
  iconSlug = "radarr";
}
