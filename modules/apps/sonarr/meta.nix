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
