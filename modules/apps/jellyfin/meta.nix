# Catalog metadata for Jellyfin. Unlike the servarr apps, Jellyfin's own
# NixOS module exposes no port option -- it always listens on 8096/8920,
# configured through Jellyfin's own web UI. defaultPort documents that
# fixed default rather than something ferrum actually wires through.
{
  id = "jellyfin";
  displayName = "Jellyfin";
  category = "media-server";
  summary = "Free media server for streaming movies, TV, and music.";

  defaultPort = 8096;
  defaultSubdomain = "jellyfin";
  defaultMediaAccess = "read";
  defaultAuthPolicy = "one_factor";

  # Jellyfin's native apps (Android TV, Roku, smart TVs, etc.) authenticate
  # with Jellyfin's own token, not a browser session -- they cannot follow
  # a forward-auth redirect. /System/Info/Public and /Users/AuthenticateByName
  # are Jellyfin's own documented unauthenticated endpoints; this list is
  # metadata only until Phase 1.4's proxy actually enforces it, and should
  # be validated against real native-client behavior at that point.
  authBypassPaths = [ "/System/Info/Public" "/Users/AuthenticateByName" "/Sessions" ];

  healthCheck = {
    path = "/health";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ ];
    consumes = [ ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = { };
  };

  docsUrl = "https://jellyfin.org/docs/";
  iconSlug = "jellyfin";
}
