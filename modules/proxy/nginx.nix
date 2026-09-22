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

  # The control plane's own vhost (R13/A1). See modules/proxy/lib.nix for why
  # the daemon is shaped like an app and why `daemonPublished` is one shared
  # predicate rather than a condition re-spelled in three files.
  daemonApp = proxyLib.daemonApp ferrum;
  daemonPublished = proxyLib.daemonPublished ferrum;
  daemonVhostName = vhostNameFor daemonApp;
  daemonAuthGated = proxyLib.authGated ferrum daemonApp;

  # A real certificate is needed for the auth vhost as soon as ANYTHING on
  # this host is published on a real name -- a public app, or now the
  # dashboard on its own. Without the daemon disjunct, the dashboard-only host
  # gets a real cert on ferrum.<domain> and a SELF-SIGNED one on
  # auth.<domain>, so the very first forward-auth redirect lands on a
  # certificate the browser refuses: SSO would be unusable on exactly the
  # configuration D6 exists to make work.
  realCertsNeeded = publicApps != { } || daemonPublished;

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

  # The daemon's vhost is hand-built rather than run through mkVhost, for the
  # same reason the auth.<baseDomain> vhost below is: mkVhost hardcodes
  # `http://127.0.0.1:${app.port}` as its upstream, and the daemon's listen
  # address is an operator-settable option (ferrum.daemon.listenAddress). It
  # is still the SAME shape -- same forceSSL, same /authelia subrequest, same
  # auth_request wiring -- because "gated exactly like a catalog app" (A2) is
  # the requirement.
  #
  # An IPv6 literal has to be bracketed on the way in. nginx splits a
  # proxy_pass authority at its LAST colon, so the naked interpolation this
  # line used to be rendered `proxy_pass http://::1:7788;` and nginx read the
  # port as "1:7788": `[emerg] invalid port in upstream "::1:7788"`. That is
  # not a hypothetical value -- modules/core/daemon.nix accepts `::1`
  # explicitly, nix/modules/flake/checks.nix asserts it MUST be accepted
  # (the SSH-tunnel recovery route A5 protects may be an IPv6 tunnel), and
  # modules/lib/settings-schema.json types the option as a bare string, so
  # ferrumd's own PUT /api/settings will write it. And nginx rejects the
  # whole FILE, not the one vhost: every catalog app, auth.<baseDomain> and
  # the catch-all go down together, at nginx.service start, on a host whose
  # apply reported success. checks.nix's nginx-config-parses now runs a real
  # `nginx -t` over every spelling daemon.nix accepts, which is the only
  # thing that could have caught this -- the generated attrset was correct
  # by inspection and wrong to the parser that consumes it.
  #
  # No "already bracketed?" branch: daemon.nix's A5 assertion refuses
  # "[::1]" (it is neither four dot-separated octets nor the literal "::1"),
  # so a bracketed value never reaches here to be bracketed twice. That is
  # a claim about a DIFFERENT module, so it is asserted rather than trusted:
  # nix/modules/flake/checks.nix's wronglyAcceptedBracketed fails
  # daemon-vhost-enforced the moment A5 is widened to admit "[::1]", which
  # is the edit that would otherwise make this line emit
  # `proxy_pass http://[[::1]]:7788` and take every vhost on the host down.
  daemonHost =
    if lib.hasInfix ":" ferrum.daemon.listenAddress
    then "[${ferrum.daemon.listenAddress}]"
    else ferrum.daemon.listenAddress;
  daemonUpstream = "http://${daemonHost}:${toString ferrum.daemon.port}";

  # A1/A5: nginx reaches the daemon, the daemon does not bind a public
  # interface. This proxies to whatever loopback address ferrumd is actually
  # listening on, so the SSH-tunnel recovery route keeps working unchanged.
  daemonAuthConfig = lib.optionalString daemonAuthGated ''
    auth_request /authelia;
    auth_request_set $target_url $scheme://$http_host$request_uri;
  '';

  # Deliberately NOT forwarded here, unlike a catalog app's vhost above:
  # Remote-User / Remote-Groups / Remote-Name / Remote-Email. D4 is explicit
  # that R13 introduces no Remote-User trust -- ferrumd keeps requiring its
  # own session cookie on every request regardless of the Authelia outcome --
  # and nothing in modules/core/daemon.nix or modules/apps/* has network
  # namespace isolation, so any local process could otherwise forge those
  # headers straight at the daemon's loopback port and skip the browser
  # entirely. Sending headers the daemon must not believe would only invite a
  # later change to start believing them.

  # D8. crates/ferrumd/src/jobs.rs serves a long-lived SSE stream, and
  # ferrum.apply.healthCheckTimeoutSec defaults to 120s -- well past the 60s
  # proxy_read_timeout that recommendedProxySettings supplies. With buffering
  # left on (also its default) nginx would additionally batch the event
  # stream, so an apply would appear frozen and then be cut off mid-run.
  # Both directives are set on every daemon location rather than just the
  # stream path: the control plane has no throughput-sensitive route where
  # buffering buys anything, and scoping it to one path only invites the next
  # stream to be added somewhere it does not apply.
  daemonStreamConfig = ''
    proxy_buffering off;
    proxy_read_timeout 300s;
  '';

  daemonVhost = {
    # exposure is "public" (lib.nix's daemonApp), so this is the real ACME
    # cert modules/proxy/acme.nix creates under exactly this vhost name -- the
    # same mechanism every app uses, not a second one (A6).
    useACMEHost = daemonVhostName;
    forceSSL = true;
    locations = {
      "/authelia" = lib.mkIf daemonAuthGated {
        extraConfig = ''
          internal;
          proxy_pass http://127.0.0.1:9091/api/verify;
          proxy_pass_request_body off;
          proxy_set_header Content-Length "";
          proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
        '';
      };

      # D8, third leg. An expired Authelia session on an /api/ request must
      # come back as a plain 401 the SPA's fetch() can read. The `error_page
      # 401 =302 https://auth.<domain>/...` that the "/" location below uses
      # -- correct for a browser NAVIGATION -- turns an XHR into an opaque
      # cross-origin redirect instead: fetch() cannot see the status, cannot
      # read the body, and the SPA has no way to tell "your session expired,
      # log in again" apart from "the daemon is down".
      "@ferrum_api_401" = lib.mkIf daemonAuthGated {
        extraConfig = "return 401;";
      };

      "/" = {
        proxyPass = daemonUpstream;
        proxyWebsockets = true;
        extraConfig = daemonStreamConfig + daemonAuthConfig
          + lib.optionalString daemonAuthGated ''
          error_page 401 =302 https://auth.${ferrum.proxy.baseDomain}/?rd=$target_url;
        '';
      };

      "/api/" = {
        proxyPass = daemonUpstream;
        proxyWebsockets = true;
        extraConfig = daemonStreamConfig + daemonAuthConfig
          + lib.optionalString daemonAuthGated ''
          error_page 401 = @ferrum_api_401;
        '';
      };
    };
  };

  # D7/A8. virtualHosts is assembled below with `//`, so a later key silently
  # WINS -- this is the jellyfin/plex failure class the catch-all vhost's own
  # comment describes, except that here the loser would be the control plane
  # itself. App subdomains are free-form types.str with no uniqueness
  # constraint anywhere, so nothing but this stops an operator naming an app
  # "ferrum" and quietly replacing the dashboard with Sonarr.
  #
  # The reserved set is computed, never hardcoded: ferrum.daemon.subdomain is
  # an option, so an operator who moves the dashboard to "panel" reserves
  # "panel" and frees "ferrum". "auth" is the literal Authelia vhost name
  # built below, which has no option of its own.
  #
  # Checked for every ENABLED app rather than only the exposed ones: a
  # colliding app at exposure = "local" is a trap armed for whenever someone
  # publishes it, and reporting that at eval time costs nothing.
  reservedSubdomains = [ ferrum.daemon.subdomain "auth" ];
  reservedCollisions = lib.mapAttrsToList
    (name: app: "ferrum.apps.${name}.subdomain = \"${app.subdomain}\"")
    (lib.filterAttrs
      (_: app: app.enable && lib.elem app.subdomain reservedSubdomains)
      ferrum.apps);
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
      // lib.optionalAttrs daemonPublished { "${daemonVhostName}" = daemonVhost; }
      // lib.optionalAttrs ferrum.auth.enable {
        "auth.${ferrum.proxy.baseDomain}" = {
          forceSSL = true;
          useACMEHost = lib.mkIf realCertsNeeded "auth.${ferrum.proxy.baseDomain}";
          sslCertificate = lib.mkIf (!realCertsNeeded) "${selfSignedCertDir}/cert.pem";
          sslCertificateKey = lib.mkIf (!realCertsNeeded) "${selfSignedCertDir}/key.pem";
          locations."/".proxyPass = "http://127.0.0.1:9091";
        };
      };
  };

  assertions = [
    {
      assertion = reservedCollisions == [ ];
      message = ''
        A catalog app claims a subdomain ferrum reserves for its control plane,
        and would silently shadow it: ${lib.concatStringsSep "; " reservedCollisions}.
        Reserved on this host: ${lib.concatStringsSep ", " (map (s: "\"${s}\"") reservedSubdomains)}
        -- the first is ferrum.daemon.subdomain (the dashboard itself), the
        second is Authelia's own vhost. Give the app a different
        ferrum.apps.<name>.subdomain, or move the dashboard by setting
        ferrum.daemon.subdomain.
      '';
    }
  ];

  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
