# A self-signed TLS certificate for "lan"-exposure vhosts and the auth
# vhost when no app is public. Not optional: Authelia's own forward-auth
# verify endpoint hard-refuses any target URL whose scheme isn't https/wss
# (confirmed via a real request against a real Authelia instance -- "Target
# URL ... has an insecure scheme 'http', only the 'https' and 'wss' schemes
# are supported so session cookies can be transmitted securely"), so
# auth_request-gated vhosts cannot serve plain HTTP once ferrum.auth.enable
# is true, regardless of exposure. "public" vhosts get a real cert via
# security.acme; this is the equivalent for "lan" vhosts, which never get
# a real cert (no public DNS to prove control of, and it would burn ACME
# rate limits for no benefit -- nothing untrusted ever sees it). One
# certificate, covering every subdomain under ferrum.proxy.baseDomain via
# a wildcard SAN, generated once and persisted on @root (infra state,
# like ACME's own /var/lib/acme -- must not roll back, matching that
# constraint). The path here (proxyLib.selfSignedCertDir) is shared with
# nginx.nix via modules/proxy/lib.nix, the same way vhostNameFor/
# exposedApps/publicApps already are.
{ config, lib, pkgs, ... }:
let
  ferrum = config.ferrum;
  proxyLib = import ./lib.nix { inherit lib; };
  certDir = proxyLib.selfSignedCertDir;
in
lib.mkIf ferrum.proxy.enable {
  systemd.services.ferrum-proxy-selfsigned-cert = {
    description = "Generate a self-signed TLS certificate for LAN-only ferrum vhosts";
    wantedBy = [ "nginx.service" ];
    before = [ "nginx.service" ];
    unitConfig.ConditionPathExists = "!${certDir}/cert.pem";
    serviceConfig.Type = "oneshot";
    path = [ pkgs.openssl ];
    script = ''
      set -euo pipefail
      mkdir -p -m 0755 ${certDir}
      openssl req -x509 -nodes -newkey rsa:2048 \
        -keyout ${certDir}/key.pem -out ${certDir}/cert.pem \
        -days 3650 -subj "/CN=*.${ferrum.proxy.baseDomain}" \
        -addext "subjectAltName=DNS:*.${ferrum.proxy.baseDomain},DNS:${ferrum.proxy.baseDomain}"
      # nginx runs as its own unprivileged user/group (default nginx:nginx),
      # not root -- this oneshot itself runs as root (default), so the key
      # it just wrote is root-owned 600 and unreadable to nginx unless
      # explicitly handed to nginx's own group here (found for real: nginx
      # failed to start with a permission-denied error reading this exact
      # file until this chown/chmod was added).
      chown root:${config.services.nginx.group} ${certDir}/key.pem
      chmod 640 ${certDir}/key.pem
      chmod 644 ${certDir}/cert.pem
    '';
  };
}
