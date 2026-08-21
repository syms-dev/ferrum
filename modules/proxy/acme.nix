# ACME certificate issuance via Cloudflare DNS-01, for every catalog app
# (and, later, the daemon) exposed publicly. One security.acme.certs entry
# per public vhost, all sharing the same Cloudflare API token -- DNS-01,
# not HTTP-01, because it works even when the box isn't reachable on port
# 80/443 from the internet yet (e.g. behind NAT during initial setup) and
# because it's what makes wildcard-adjacent subdomain issuance simple.
#
# CLOUDFLARE_DNS_API_TOKEN (not CF_API_KEY/CF_API_EMAIL, the OLD Global-Key
# auth path) is lego's env var for a SCOPED Cloudflare API token -- the
# token needs Zone:Read + DNS:Edit permission on the zone that owns
# ferrum.proxy.baseDomain. Confirmed against go-acme/lego's own Cloudflare
# provider (the ACME client security.acme uses for DNS-01): this is the
# real, current env var name, not a guess -- Saltbox's own well-known
# weakness was defaulting to the Global API key, which this project set
# out from the start to avoid (see the spec's Global Constraints).
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  proxyEnabled = ferrum.proxy.enable;
  proxyLib = import ./lib.nix { inherit lib; };
  vhostNameFor = proxyLib.vhostNameFor ferrum;
  publicApps = proxyLib.publicApps ferrum;
  credentialSecret = ferrum.proxy.acme.credentialSecret;
  credentialProvided = ferrum.secrets ? "${credentialSecret}";
  # nginx (not "acme", security.acme.certs' own default group) is the
  # process that actually needs to read the issued certificate, since it's
  # nginx.nix's virtualHosts entries that reference these certs via
  # useACMEHost -- confirmed by reading nixos/modules/security/acme/default.nix,
  # whose real default is group = "acme", which nginx's own unprivileged
  # nginx:nginx user was never a member of (found during the final
  # whole-branch review's own re-verification via a real nix eval: any
  # host with a public app AND ferrum.auth.enable = true failed a hard
  # nixpkgs assertion -- "Certificate ... must be readable by
  # service(s) nginx.service (user=nginx groups=nginx)..." -- until this
  # group override was added).
  nginxGroup = config.services.nginx.group;
in
lib.mkIf proxyEnabled {
  security.acme.acceptTerms = true;
  security.acme.defaults.email = ferrum.proxy.acme.email;

  assertions = [
    {
      assertion = ferrum.proxy.baseDomain != "";
      message = "ferrum.proxy.enable is true but ferrum.proxy.baseDomain is empty -- every vhost name and the self-signed certificate's CN derive from it.";
    }
    {
      assertion = publicApps == { } || ferrum.proxy.acme.email != "";
      message = "ferrum.proxy has a public-exposure app but ferrum.proxy.acme.email is empty -- Let's Encrypt requires a real contact address.";
    }
    {
      assertion = publicApps == { } || credentialProvided;
      message = ''
        ferrum.proxy has a public-exposure app, which needs a real ACME
        certificate, but ferrum.secrets does not declare
        "${credentialSecret}". Add it to ferrum.secrets in settings.json
        and encrypt the Cloudflare DNS-01 token to this host's own age
        recipient -- see README.md's reverse-proxy section for the full
        procedure -- then re-apply.
      '';
    }
    {
      assertion = !credentialProvided || builtins.pathExists (/. + "${ferrum.secretsDir}/${credentialSecret}.sops");
      message = ''
        ferrum.secrets declares "${credentialSecret}" but
        ${ferrum.secretsDir}/${credentialSecret}.sops does not exist yet.
        Encrypt your Cloudflare DNS-01 token to this host's own age
        recipient first -- see README.md's reverse-proxy section for the
        full procedure -- then re-apply.
      '';
    }
  ];

  # The DNS-01 credential is operator-provided via `ferrum.secrets` -- same
  # zero-privilege sops-encrypt mechanism as qBittorrent's VPN config (see
  # modules/apps/qbittorrent/service.nix's own `ferrum.secrets ? "..."` +
  # pathExists pattern, mirrored here). Must go through sops-nix's own
  # decryption like every other secret in this codebase; environmentFile
  # cannot point at the raw .sops ciphertext directly. Gated on
  # credentialProvided too (not just publicApps != {}) so this never
  # attempts to decrypt a .sops file that was declared but never actually
  # written.
  sops.secrets."${credentialSecret}" = lib.mkIf (publicApps != { } && credentialProvided) {
    sopsFile = /. + "${ferrum.secretsDir}/${credentialSecret}.sops";
    format = "binary";
    owner = "acme";
    group = "acme";
  };

  # lego reads CLOUDFLARE_DNS_API_TOKEN from this file via systemd's
  # EnvironmentFile= mechanism (confirmed by reading
  # nixos/modules/security/acme/default.nix: `environmentFile` is passed
  # straight through as systemd's own `EnvironmentFile=`, exactly like
  # every other secret this project wires -- never Nix-interpolated).
  # ferrum.secrets."acme-dns" is the existing default from
  # ferrum.proxy.acme.credentialSecret; the operator writes this secret
  # via ferrumd (Phase 1.5) or by hand with sops, same as
  # qBittorrent's VPN config in Phase 1.4a.
  security.acme.certs = lib.mapAttrs'
    (_: app: lib.nameValuePair (vhostNameFor app) {
      dnsProvider = ferrum.proxy.acme.dnsProvider;
      environmentFile = config.sops.secrets."${credentialSecret}".path;
      group = nginxGroup;
      server = lib.mkIf ferrum.proxy.acme.staging
        "https://acme-staging-v02.api.letsencrypt.org/directory";
    })
    publicApps
  // lib.optionalAttrs (ferrum.auth.enable && publicApps != { }) {
    "auth.${ferrum.proxy.baseDomain}" = {
      dnsProvider = ferrum.proxy.acme.dnsProvider;
      environmentFile = config.sops.secrets."${credentialSecret}".path;
      group = nginxGroup;
      server = lib.mkIf ferrum.proxy.acme.staging
        "https://acme-staging-v02.api.letsencrypt.org/directory";
    };
  };
}
