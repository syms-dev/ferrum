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
  # one_factor, not two_factor. Enforcing 2FA locked the operator out of
  # their own host on the first real install: Authelia demands TOTP
  # enrolment before the first login, and ferrum configures the FILESYSTEM
  # notifier, so the enrolment link is written to
  # /var/lib/authelia-main/notifications.txt -- a file nobody would think
  # to look in. SSO was therefore unusable out of the box on a correctly
  # installed, fully working system.
  #
  # Requiring SMTP instead would make a mail server a prerequisite for a
  # media box, which is worse. So the default is a password behind SSO,
  # which is what the gate is actually for: these apps ship with no real
  # authentication of their own, and one_factor closes that. An operator
  # who wants 2FA can set it per app, and that path should enrol them
  # during install rather than leaving a link in a file.
  defaultAuthPolicy = "one_factor";

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
