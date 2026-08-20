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

  # SABnzbd's own package is free-licensed, but it depends on `unrar`
  # (to extract RAR archives from Usenet downloads), which is unfree --
  # without allowing it, the whole host config fails to evaluate the
  # moment this app is enabled. Collected centrally by
  # modules/core/overlays.nix -- see that file's comment for why (found
  # for real during this task's controller verification: enabling this
  # app alongside Plex, which has its own unfree dependency, is exactly
  # the scenario that would otherwise produce a conflicting-definitions
  # eval error if each app set its own predicate).
  unfreePackages = [ "unrar" ];

  # /api must reach SABnzbd without a forward-auth redirect, same reasoning
  # as Radarr/Sonarr/Prowlarr's identical bypass entry: SABnzbd's own
  # `integrations.providesTo` below lists exactly those three apps as
  # callers that push jobs into its API, so this app has the same real
  # need for the bypass they do, not just a stylistic match (caught during
  # Task 5's review -- the original brief left this empty).
  authBypassPaths = [ "/api" ];

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
