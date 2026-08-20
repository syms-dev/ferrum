# Catalog metadata for Prowlarr. Same servarr framework as Sonarr/Radarr,
# but Prowlarr is an indexer manager -- it never touches media files, so
# mediaAccess is "none" and it has no media-group membership.
{
  id = "prowlarr";
  displayName = "Prowlarr";
  category = "media-automation";
  summary = "Indexer manager and proxy for Usenet and BitTorrent trackers.";

  defaultPort = 9696;
  defaultSubdomain = "prowlarr";
  defaultMediaAccess = "none";
  defaultAuthPolicy = "two_factor";

  # Same reasoning as Sonarr/Radarr -- Prowlarr shares the identical
  # Servarr web framework, which uses a SignalR hub for live updates
  # (indexer test results, task queue). Missing this breaks the web UI's
  # real-time updates once forward-auth is on (caught in Task 1's review;
  # fixed here before this task is dispatched).
  authBypassPaths = [ "/api" "/ping" "/signalr" ];

  healthCheck = {
    path = "/ping";
    expectStatus = 200;
    timeoutSec = 30;
  };

  # Every *arr app it registers indexers into -- Phase 1.4's reconciler
  # reads this list, unused until then.
  integrations = {
    providesTo = [ ];
    consumes = [ "radarr" "sonarr" "qbittorrent" "sabnzbd" ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = { };
  };

  docsUrl = "https://wiki.servarr.com/prowlarr";
  iconSlug = "prowlarr";
}
