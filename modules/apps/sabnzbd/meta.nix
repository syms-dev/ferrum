# Catalog metadata for SABnzbd. Its NixOS module exposes neither a
# relocatable data directory nor a port option -- see service.nix for the
# StateDirectory override this requires, and the spec's already-flagged
# gap around SABnzbd's own non-declarative sabnzbd.ini (Phase 1.4's
# problem, not this task's).
{
  id = "sabnzbd";
  displayName = "SABnzbd";
  category = "download-client";
  summary = "Usenet download client.";

  defaultPort = 8080;
  defaultSubdomain = "sabnzbd";
  defaultMediaAccess = "readwrite";
  defaultAuthPolicy = "two_factor";

  authBypassPaths = [ ];

  healthCheck = {
    path = "/api?mode=version";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ "radarr" "sonarr" "prowlarr" ];
    consumes = [ ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = { };
  };

  docsUrl = "https://sabnzbd.org/wiki/";
  iconSlug = "sabnzbd";
}
