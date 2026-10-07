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

  # The VPN kill switch, declared as CATALOG DATA rather than known
  # separately by each consumer.
  #
  # Three things already had to agree about this app's tunnel and nothing
  # held them together: service.nix names the unit and the secret, the
  # settings schema above names the toggle, and now ferrumd's /api/vpn
  # reports the tunnel's state and ui/app.js renders a panel for pasting a
  # WireGuard config. Hard-coding "qbittorrent" into either of those last
  # two would end the property this catalog exists for -- that adding an app
  # is adding a directory -- and would put the unit name in a second place
  # where it could silently stop matching the unit service.nix defines.
  #
  # So the daemon reads the unit name from here and the UI renders a VPN
  # panel for whichever app declares this block. `vpn-metadata-matches-the-unit`
  # (nix/modules/flake/checks.nix) asserts each field really names what it
  # claims to: the systemd unit, the sops secret, and the settingsSchema key.
  vpn = {
    # The sops secret holding the WireGuard config. Write-only, through
    # POST /api/secrets/<name> -- there is no read path, which is what lets
    # the UI say "ferrumd can write this but can never read it back".
    secret = "qbittorrent-vpn";
    # The systemd unit whose completion IS the measurement. A RemainAfterExit
    # oneshot: `active` means its script ran all the way through, so the
    # namespace exists, wg0 was configured inside it from the operator's own
    # config, and the routes below it were installed. It does NOT mean the
    # tunnel is passing traffic -- WireGuard is connectionless and an
    # interface is "up" from the moment it is configured, peer or no peer.
    # See crates/ferrumd/src/vpn.rs for the full statement of what this can
    # and cannot establish.
    unit = "qbt-vpn-netns-setup.service";
    # The key under this app's `settings` that turns the kill switch on.
    setting = "vpnKillSwitch";
  };

  docsUrl = "https://github.com/qbittorrent/qBittorrent/wiki";
  iconSlug = "qbittorrent";
}
