# nginx virtualHosts generation, one per catalog app with exposure != "local",
# driven entirely by metadata the catalog already carries. "local" apps get
# no vhost at all -- reached only through ferrumd's own internal proxying
# (Phase 1.5), matching modules/lib/app-submodule.nix's own doc comment on
# the exposure option.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  proxyEnabled = ferrum.proxy.enable;
  proxyLib = import ./lib.nix { inherit lib; };
  vhostNameFor = proxyLib.vhostNameFor ferrum;
  exposedApps = proxyLib.exposedApps ferrum;
  publicApps = proxyLib.publicApps ferrum;
  selfSignedCertDir = proxyLib.selfSignedCertDir;

  mkVhost = _: app:
    let
      vhostName = vhostNameFor app;
      isPublic = app.exposure == "public";
      authRequestEnabled = proxyLib.authGated ferrum app;

      # The LAN restriction applies to every location, auth-gated or not.
      # Factored out so a bypass location cannot accidentally become the
      # one way around it.
      lanRestriction = lib.optionalString (app.exposure == "lan") ''
        ${lib.concatMapStringsSep "\n" (net: "allow ${net};") ferrum.proxy.trustedNetworks}
        deny all;
      '';

      # Locations served WITHOUT forward-auth even when the app is
      # auth-gated.
      #
      # `app.auth.bypassPaths` has existed since Phase 1.3 and every app's
      # meta.nix populates it, but until now NOTHING READ IT: locations."/"
      # carried `auth_request` and no other location was generated, so the
      # list was documentation. Jellyfin's own meta.nix said as much --
      # "metadata only until Phase 1.4's proxy actually enforces it" -- and
      # that enforcement was never written.
      #
      # What it breaks when missing is not cosmetic. `/api` behind
      # forward-auth takes out Prowlarr -> Sonarr/Radarr, every mobile
      # client, and ferrum's OWN reconciler, which performs the cross-app
      # registration that makes self-setup work. So enabling SSO disabled
      # the feature SSO exists to protect.
      bypassLocations = lib.listToAttrs (map
        (path: {
          name = path;
          value = {
            proxyPass = "http://127.0.0.1:${toString app.port}";
            proxyWebsockets = true;
            extraConfig = lanRestriction;
          };
        })
        (lib.optionals authRequestEnabled app.auth.bypassPaths));
    in
    {
      name = vhostName;
      value = {
        # "public" gets a real cert via modules/proxy/acme.nix's
        # security.acme.certs entry, keyed by this same vhost name. "lan"
        # gets the shared self-signed cert instead. Authelia's own
        # /api/verify hard-refuses a target URL whose scheme isn't
        # https/wss (confirmed via a real request against a real Authelia
        # instance: "Target URL ... has an insecure scheme 'http' ..."),
        # so EVERY vhost stays forceSSL = true once auth is involved --
        # there is no plain-HTTP path once ferrum.auth.enable is true.
        useACMEHost = lib.mkIf isPublic vhostName;
        forceSSL = true;
        sslCertificate = lib.mkIf (!isPublic) "${selfSignedCertDir}/cert.pem";
        sslCertificateKey = lib.mkIf (!isPublic) "${selfSignedCertDir}/key.pem";
        # One attrset, because `locations."/authelia"` and `locations =`
        # cannot both be assigned. Order of the merge matters only in that
        # a bypass path must never be able to shadow /authelia, which is
        # `internal` and unreachable from outside regardless.
        locations = bypassLocations // {
          "/authelia" = lib.mkIf authRequestEnabled {
            extraConfig = ''
              internal;
              proxy_pass http://127.0.0.1:9091/api/verify;
              proxy_pass_request_body off;
              proxy_set_header Content-Length "";
              proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
            '';
          };

          "/" = {
            proxyPass = "http://127.0.0.1:${toString app.port}";
            proxyWebsockets = true;
            extraConfig = lanRestriction + lib.optionalString authRequestEnabled ''
              auth_request /authelia;
              auth_request_set $target_url $scheme://$http_host$request_uri;
              auth_request_set $user $upstream_http_remote_user;
              auth_request_set $groups $upstream_http_remote_groups;
              auth_request_set $name $upstream_http_remote_name;
              auth_request_set $email $upstream_http_remote_email;
              proxy_set_header Remote-User $user;
              proxy_set_header Remote-Groups $groups;
              proxy_set_header Remote-Name $name;
              proxy_set_header Remote-Email $email;
              error_page 401 =302 https://auth.${ferrum.proxy.baseDomain}/?rd=$target_url;
            '';
          };
        };
      };
    };
in
lib.mkIf proxyEnabled {
  services.nginx = {
    enable = true;
    recommendedTlsSettings = true;
    recommendedProxySettings = true;
    recommendedGzipSettings = true;
    virtualHosts = {
      # A catch-all that refuses anything we did not explicitly publish.
      #
      # Without it nginx makes the FIRST vhost its default server, so any
      # hostname with no vhost of its own is silently served by whichever app
      # happens to sort first. Found on a real host: jellyfin was enabled but
      # left at exposure = "local" (so it correctly got no vhost), and
      # jellyfin.thesyms.ca then served Plex's login page. The operator
      # reasonably read that as ferrum routing one app to another.
      #
      # 444 -- nginx's own "close without a response" -- rather than 404,
      # because there is nothing useful to say to a request for a hostname
      # this box does not serve, and a body would only confirm that something
      # is listening. This also covers a wildcard DNS record pointed at the
      # host, which is the normal way these subdomains get resolved.
      #
      # `default_server` on a catch-all is only meaningful if it really is
      # the default: `default = true` is what makes nginx pick this one for
      # an unmatched Host, instead of the alphabetically-first app.
      "_ferrum_unmatched" = {
        default = true;
        rejectSSL = true;
        locations."/".return = "444";
      };
    }
      // lib.listToAttrs (lib.mapAttrsToList mkVhost exposedApps)
      // lib.optionalAttrs ferrum.auth.enable {
        "auth.${ferrum.proxy.baseDomain}" = {
          forceSSL = true;
          useACMEHost = lib.mkIf (publicApps != { }) "auth.${ferrum.proxy.baseDomain}";
          sslCertificate = lib.mkIf (publicApps == { }) "${selfSignedCertDir}/cert.pem";
          sslCertificateKey = lib.mkIf (publicApps == { }) "${selfSignedCertDir}/key.pem";
          locations."/".proxyPass = "http://127.0.0.1:9091";
        };
      };
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
