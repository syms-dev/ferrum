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

  # Which directory under <mediaDir>/media this app manages.
  #
  # Declared here rather than in the reconciler so that adding an app
  # stays "add a directory under modules/apps", which is the property
  # catalog-consistency exists to protect. An app with no library of its
  # own simply omits this.
  #
  # Without a root folder an *arr will not accept a single show or film --
  # it refuses the add outright and the operator has to type a path ferrum
  # already knows. That is the "log in and everything is pre-setup" gap.
  mediaCategory = "movies";
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

  # /api, /feed, /ping, /signalr must reach Radarr without a forward-auth
  # redirect, or every API client (Prowlarr, mobile apps, ferrum's own
  # reconciler) breaks the moment ferrum.auth.enable flips on, and the web
  # UI's live updates (SignalR) break too. Same reasoning as Sonarr's
  # identical bypass list.
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
