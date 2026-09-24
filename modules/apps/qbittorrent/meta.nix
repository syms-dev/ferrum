# Catalog metadata for qBittorrent. defaultPort (8090) deliberately differs
# from qBittorrent's own upstream default (8080), which collides with
# SABnzbd's default port when both are enabled on the same host.
# vpnKillSwitch is consumed by settingsSchema below; the VPN config itself
# lives in ferrum.secrets."qbittorrent-vpn", a real sops secret, not here.
{
  id = "qbittorrent";
  displayName = "qBittorrent";
  category = "download-client";
  summary = "BitTorrent client.";

  defaultPort = 8090;
  defaultSubdomain = "qbittorrent";
  defaultMediaAccess = "readwrite";

  # Where this client writes, under <mediaDir>. Declared here for the same
  # reason mediaCategory is: adding an app stays "add a directory".
  #
  # It must be under the SAME root as the library. The *arrs import by
  # hardlinking and a hardlink cannot cross a filesystem, so a client
  # left on its own default -- somewhere under its state directory on the
  # OS disk -- turns every import into a silent copy.
  downloadSubdir = "torrents";
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

  # /api/v2 (qBittorrent's actual versioned API prefix, matching
  # healthCheck.path below) must reach it without a forward-auth redirect
  # -- Radarr/Sonarr/Prowlarr's own `integrations.consumes` all list
  # "qbittorrent", meaning they call into this API to push torrents, the
  # same reasoning as SABnzbd's identical fix (caught during Task 5's
  # review; fixed here before Task 6 is dispatched so it isn't repeated).
  authBypassPaths = [ "/api/v2" ];

  # LocalHostAuth = false (service.nix) makes this endpoint genuinely
  # return 200 unauthenticated from localhost -- confirmed for real on
  # ferrum-dev. NOTE: on a VPN-kill-switch-enabled host, a caller reaching
  # this app across the veth pair (a non-loopback address) needs the
  # AuthSubnetWhitelist service.nix also sets in that case for the same
  # 200 to hold -- this static catalog value can't express that
  # per-host-config distinction; nothing currently consumes this field
  # from that code path, so left as the non-VPN-host-accurate default
  # (found during the final whole-branch review).
  healthCheck = {
    path = "/api/v2/app/version";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ "radarr" "sonarr" "prowlarr" ];
    consumes = [ ];
  };

  # vpnKillSwitch: see docs/superpowers/specs/2026-08-20-phase-1-3-catalog-apps-
  # design.md's "qBittorrent VPN Kill Switch" section. The WireGuard config
  # itself moved to a real sops secret (ferrum.secrets."qbittorrent-vpn") in
  # Phase 1.4a -- see modules/apps/qbittorrent/service.nix. Nothing in
  # app.settings ever holds the config text anymore.
  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = {
      vpnKillSwitch = {
        type = "boolean";
        default = true;
      };
    };
  };

  docsUrl = "https://github.com/qbittorrent/qBittorrent/wiki";
  iconSlug = "qbittorrent";
}
