# Catalog metadata for qBittorrent. defaultPort (8090) deliberately differs
# from qBittorrent's own upstream default (8080), which collides with
# SABnzbd's default port when both are enabled on the same host.
# vpnWireguardConfig/vpnKillSwitch are added and consumed starting in
# Task 7 (this task's meta.nix does not yet declare them -- Task 7 adds
# them to this same file's settingsSchema).
{
  id = "qbittorrent";
  displayName = "qBittorrent";
  category = "download-client";
  summary = "BitTorrent client.";

  defaultPort = 8090;
  defaultSubdomain = "qbittorrent";
  defaultMediaAccess = "readwrite";
  defaultAuthPolicy = "two_factor";

  # /api/v2 (qBittorrent's actual versioned API prefix, matching
  # healthCheck.path below) must reach it without a forward-auth redirect
  # -- Radarr/Sonarr/Prowlarr's own `integrations.consumes` all list
  # "qbittorrent", meaning they call into this API to push torrents, the
  # same reasoning as SABnzbd's identical fix (caught during Task 5's
  # review; fixed here before Task 6 is dispatched so it isn't repeated).
  authBypassPaths = [ "/api/v2" ];

  # /api/v2/app/version requires an authenticated session (a valid SID
  # cookie) -- unauthenticated it returns 403, not 200. That still proves
  # the server is up and serving, which is all a health check needs (found
  # during the final whole-branch review: this was the one health check in
  # the whole phase that expected a 200 from an endpoint that never
  # returns one unauthenticated).
  healthCheck = {
    path = "/api/v2/app/version";
    expectStatus = 403;
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
