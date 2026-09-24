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
    serviceConfig.Type = "oneshot";
    path = [ pkgs.openssl ];
    # The gate is the certificate's DOMAIN, not its mere existence.
    #
    # This unit used to carry `ConditionPathExists = "!${certDir}/cert.pem"`,
    # which asks "is there a certificate" and never "is it the right one".
    # Since the CN and both SANs are built from ferrum.proxy.baseDomain,
    # changing that option -- one field in the settings UI -- left every
    # lan-exposure vhost and, on a host with no public app, the auth vhost
    # itself serving a certificate for the OLD name. The browser refuses it,
    # and because the auth vhost is where Authelia's forward-auth redirect
    # lands, the failure is "SSO is broken on a host that just applied
    # cleanly" rather than anything that points at the certificate.
    #
    # The domain is recorded beside the certificate and compared on every
    # start. Recorded rather than read back out of the certificate with
    # `openssl x509 -noout -subject`: parsing a subject line to recover a
    # wildcard CN is a second grammar to get wrong, and the file we wrote
    # ourselves is the fact we actually want.
    #
    # ConditionPathExists is dropped rather than widened, because a
    # condition can only test paths and this is a comparison. The unit now
    # runs on every nginx start and exits immediately when nothing changed
    # -- a string compare against a small file, ordered before a service
    # that is already reading the certificate from the same directory.
    #
    # The old certificate is replaced in place. It is self-signed and
    # trusted by nobody, so there is nothing to preserve and no rollback
    # value in keeping it; the pair is written together, so nginx never sees
    # a new key beside an old certificate.
    script = ''
      set -euo pipefail
      mkdir -p -m 0755 ${certDir}

      if [ -f ${certDir}/cert.pem ] \
         && [ -f ${certDir}/key.pem ] \
         && [ "$(cat ${certDir}/domain 2>/dev/null || true)" = "${ferrum.proxy.baseDomain}" ]; then
        exit 0
      fi

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

      # Written LAST, and only after both halves of the pair are in place:
      # a marker recorded before a failed openssl run would claim a
      # certificate for this domain exists when it does not, and the next
      # start would take the early exit above and never retry.
      printf '%s' "${ferrum.proxy.baseDomain}" > ${certDir}/domain
      chmod 644 ${certDir}/domain
    '';
  };
}
