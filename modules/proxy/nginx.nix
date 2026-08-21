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

  mkVhost = id: app:
    let
      vhostName = vhostNameFor app;
      isPublic = app.exposure == "public";
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
        locations."/" = {
          proxyPass = "http://127.0.0.1:${toString app.port}";
          proxyWebsockets = true;
          extraConfig = lib.optionalString (app.exposure == "lan") ''
            ${lib.concatMapStringsSep "\n" (net: "allow ${net};") ferrum.proxy.trustedNetworks}
            deny all;
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
    virtualHosts = lib.listToAttrs (lib.mapAttrsToList mkVhost exposedApps);
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
