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

  # Where this client writes, under <mediaDir>. Declared here for the same
  # reason mediaCategory is: adding an app stays "add a directory".
  #
  # It must be under the SAME root as the library. The *arrs import by
  # hardlinking and a hardlink cannot cross a filesystem, so a client
  # left on its own default -- somewhere under its state directory on the
  # OS disk -- turns every import into a silent copy.
  downloadSubdir = "usenet/complete";
  downloadIncompleteSubdir = "usenet/incomplete";
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
