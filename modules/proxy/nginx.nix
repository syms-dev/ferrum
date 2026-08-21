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

  mkVhost = id: app:
    let
      vhostName = vhostNameFor app;
      isPublic = app.exposure == "public";
      authRequestEnabled = ferrum.auth.enable && app.auth.policy != "bypass";
    in
    {
      name = vhostName;
      value = {
        # "public" gets a real cert via modules/proxy/acme.nix's
        # security.acme.certs entry, keyed by this same vhost name.
        # "lan" apps get nginx's own self-signed default cert -- good
        # enough for a trusted-network-only vhost, and issuing a real
        # cert for every internal-only app would burn Let's Encrypt's
        # rate limits for no security benefit (nothing untrusted ever
        # sees it).
        useACMEHost = lib.mkIf isPublic vhostName;
        forceSSL = true;
        locations."/authelia" = lib.mkIf authRequestEnabled {
          extraConfig = ''
            internal;
            proxy_pass http://127.0.0.1:9091/api/verify;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
          '';
        };
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString app.port}";
          proxyWebsockets = true;
          extraConfig = lib.optionalString (app.exposure == "lan") ''
            ${lib.concatMapStringsSep "\n" (net: "allow ${net};") ferrum.proxy.trustedNetworks}
            deny all;
          '' + lib.optionalString authRequestEnabled ''
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
in
lib.mkIf proxyEnabled {
  services.nginx = {
    enable = true;
    recommendedTlsSettings = true;
    recommendedProxySettings = true;
    recommendedGzipSettings = true;
    virtualHosts = lib.listToAttrs (lib.mapAttrsToList mkVhost exposedApps)
      // lib.optionalAttrs ferrum.auth.enable {
        "auth.${ferrum.proxy.baseDomain}" = {
          forceSSL = true;
          useACMEHost = lib.mkIf (publicApps != { }) "auth.${ferrum.proxy.baseDomain}";
          locations."/".proxyPass = "http://127.0.0.1:9091";
        };
      };
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
