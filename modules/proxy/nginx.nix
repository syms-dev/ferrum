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
              ${autheliaClientHeaders}
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

  # SEC-08. Who Authelia thinks is knocking.
  #
  # nixpkgs' recommendedProxySettings adds an `include
  # ...recommended-proxy_set_header-headers.conf` -- which carries X-Real-IP
  # and X-Forwarded-For -- only to a location it generates a proxy_pass FOR.
  # The /authelia subrequest writes its own proxy_pass inside extraConfig, so
  # it gets no include, and nginx's proxy_set_header inheritance is
  # all-or-nothing in the same way add_header is: the lines this block sets
  # itself REPLACE the inherited set rather than extending it. Confirmed
  # against the real generated file, not the docs -- the sibling "/" location
  # carries the include and this block carries nothing.
  #
  # The effect is not a missing header, it is a missing SUBJECT. Every
  # verification request arrives at Authelia from nginx's own loopback
  # connection with nothing saying otherwise, so Authelia's log line and its
  # regulation counter both attribute the attempt to 127.0.0.1. Its lockout
  # therefore counts one global bucket instead of one per source: an attacker
  # anywhere is indistinguishable from the operator at home, in the log that
  # would be read after the fact and in the mechanism meant to stop it
  # during.
  #
  # $proxy_add_x_forwarded_for rather than $remote_addr for the forwarded
  # chain, because it appends to any inbound header instead of discarding it;
  # X-Real-IP stays the single peer address, which is the one Authelia reads
  # when no trusted-proxy chain is configured.
  autheliaClientHeaders = ''
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
  '';

  # The two headers that are right for every vhost on this host, set once at
  # http level. Neither depends on what the vhost serves: nosniff turns off
  # content-type sniffing, which is only ever a way to get a response treated
  # as something it did not claim to be, and the referrer policy stops a
  # cross-origin link leaking the path it was clicked from -- a *arr URL
  # carries the library layout in it.
  #
  # `always` on both, because the interesting responses are the error ones. A
  # bare add_header applies to a fixed list of success-ish codes and skips
  # 401 and 500, which are exactly the responses an attacker is iterating
  # over. Measured: with `always` the 401 below carries all four headers;
  # without it, none.
  #
  # HSTS is deliberately NOT here. See the assertion block at the bottom of
  # this file for the certificate-issuance reason.
  generalSecurityHeaders = ''
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  '';

  # THE FOOTGUN, and the reason the two lines above are repeated below:
  # nginx's add_header is INHERITED ONLY WHEN THE CHILD SETS NONE. A server
  # or location block that adds even one header of its own REPLACES the
  # whole inherited set rather than extending it.
  #
  # Measured against a real nginx rather than taken from the docs, because
  # the failure is silent and points the wrong way. Two vhosts, the same
  # http-level pair above, one of them also setting the frame headers at
  # server level:
  #
  #   withserver.test -> X-Frame-Options, Content-Security-Policy
  #   noserver.test   -> X-Content-Type-Options, Referrer-Policy
  #
  # The vhost that asked for MORE protection got less, and the one that
  # would have lost nosniff is the control plane. Repeating the pair here is
  # what makes the daemon's set a superset instead of a swap; the daemon's
  # locations then set no add_header at all, so they inherit these four
  # (confirmed on both a 200 and a 401).
  daemonSecurityHeaders = generalSecurityHeaders + ''
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "frame-ancestors 'none'" always;
  '';

  # Bound once so the rate-limited login location below is the SAME
  # configuration as /api/ plus one directive, rather than a second copy of
  # it that can drift. A copy that lost `auth_request` would mean the rate
  # limiter had opened the hole it was added to narrow.
  daemonApiConfig = daemonStreamConfig + daemonAuthConfig
    + lib.optionalString daemonAuthGated ''
    error_page 401 = @ferrum_api_401;
  '';

  daemonVhost = {
    # exposure is "public" (lib.nix's daemonApp), so this is the real ACME
    # cert modules/proxy/acme.nix creates under exactly this vhost name -- the
    # same mechanism every app uses, not a second one (A6).
    useACMEHost = daemonVhostName;
    forceSSL = true;
    # Why the control plane and not every vhost: a sibling app on
    # <baseDomain> is SAME-SITE, so the browser attaches ferrumd's session
    # cookie to a framed ferrum.<baseDomain> and the real, authenticated
    # dashboard renders inside the attacker's page. The CSRF token does not
    # help -- the genuine page supplies it itself -- so a single framed click
    # reaches POST /api/jobs, which is apply and rollback. The spec's own
    # threat model enumerates compromised same-site siblings; framing is the
    # same-site vector it missed.
    #
    # Both spellings, because they are not redundant: X-Frame-Options is what
    # older browsers obey and frame-ancestors is what the standard defines,
    # and the cost of carrying both is two header lines.
    #
    # Scoped to the daemon rather than set at http level because a blanket
    # frame-ancestors 'none' would break anyone embedding Jellyfin or a *arr
    # in a dashboard, which is a thing people do and which this finding is
    # not about.
    extraConfig = daemonSecurityHeaders;
    locations = {
      "/authelia" = lib.mkIf daemonAuthGated {
        extraConfig = ''
          internal;
          proxy_pass http://127.0.0.1:9091/api/verify;
          proxy_pass_request_body off;
          proxy_set_header Content-Length "";
          proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
          ${autheliaClientHeaders}
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
        extraConfig = daemonApiConfig;
      };

      # M-02, the edge half. ferrumd's own lockout is keyed on the submitted
      # USERNAME, so a remote caller can hold the only `admin` account
      # locked out indefinitely at one attempt per 60s -- the lockout denies
      # the correct password too. That is the application's to fix; this is
      # the part nginx can do, which is to stop the attempts arriving.
      #
      # A longer prefix wins in nginx, so this shadows "/api/" above for the
      # one path that needs it and leaves the SSE stream and every other API
      # route untouched. It reuses daemonApiConfig rather than restating it:
      # a login location that quietly lost `auth_request` would be a hole
      # opened by a rate limiter, which is a poor trade.
      #
      # Deliberately mild, and that is a judgement not an oversight. This is
      # a single-operator appliance; a limit that locks the real operator out
      # while they retry a password they are sure about is worse than no
      # limit at all, because the failure is indistinguishable from the
      # daemon being broken. 20/minute with a burst of 10 taken immediately
      # means a human fumbling their password never meets it, while an
      # attacker goes from thousands of guesses a second to twenty a minute.
      "/api/login" = {
        proxyPass = daemonUpstream;
        proxyWebsockets = true;
        extraConfig = daemonApiConfig + ''
          limit_req zone=ferrum_login burst=10 nodelay;
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
    # The headers, plus the shared-memory zone the daemon's login location
    # draws on. limit_req_zone is an http-context directive and the zone has
    # to exist whether or not anything references it, so it is declared here
    # rather than beside its one consumer.
    #
    # Keyed on $binary_remote_addr -- the client address in 4 or 16 bytes
    # rather than the text form, which is what makes 1m hold roughly 16000
    # of them. 1m is far more than a home server will ever populate, and
    # nginx returns 503 to everyone once a zone fills, so undersizing it is
    # the failure worth avoiding.
    #
    # Returns 429 rather than nginx's default 503: the SPA can tell "you are
    # going too fast" from "the daemon fell over", and so can the operator
    # reading a log.
    commonHttpConfig = generalSecurityHeaders + ''
      limit_req_zone $binary_remote_addr zone=ferrum_login:1m rate=20r/m;
      limit_req_status 429;
    '';
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
      # Publication and gating are two predicates on purpose (see
      # modules/proxy/lib.nix), and before R13 the gap between them was
      # survivable: ferrum.daemon.subdomain was decorative, so a host with
      # auth off published catalog apps and nothing else. R13 shipped the
      # vhost, so the same gap now publishes settings, secrets, apply and
      # rollback on a real ACME certificate with auth_request absent
      # entirely.
      #
      # The spec put this out of scope on the ground that auth-off with a
      # public domain is an existing hazard and that R13 does not change the
      # policy. The policy is indeed unchanged; the BLAST RADIUS is not, and
      # the out-of-scope reasoning rests on a premise R13 itself falsified.
      #
      # An assertion rather than a warning, and an assertion rather than the
      # installer's typed consent, because of WHO gets caught. The installer
      # asks once, at first install; an operator upgrading an existing
      # auth-off host never sees that prompt, and a warning scrolls past in
      # the output of a command that succeeded. This stops EVERY apply until
      # it is answered, which is the only form that reaches the host the
      # finding is actually about.
      #
      # Note what it does NOT do: daemonPublished is untouched. Several
      # things read it, and making publication depend on auth would silently
      # unpublish the dashboard instead of reporting the problem -- the same
      # class of failure as issuing a certificate for a name nothing serves.
      assertion = !(daemonPublished && !ferrum.auth.enable);
      message = ''
        ferrum publishes its own control plane at ${daemonVhostName} on this
        host, and ferrum.auth.enable is false, so there is no login in front of it.

        Anyone who can reach that name gets the dashboard: this host's
        settings, its secrets API, and the apply and rollback buttons. It is
        on a real Let's Encrypt certificate and, if ferrum.proxy.dns is on,
        a real DNS record -- so "nobody knows the hostname" is not true
        either. ferrumd's own login still stands underneath, but it is one
        password on an internet-facing box with no rate limit in front of
        it, which is not what this design relies on.

        Two ways forward, and both are one line:

          ferrum.auth.enable = true;   -- turn Authelia on, which is what
                                          every other published app on this
                                          host is already behind.

          ferrum.daemon.enable = false;  -- or ferrum.proxy.baseDomain = "",
                                          if this host is not meant to
                                          publish anything at all.

        Reach the dashboard without publishing it by leaving
        ferrum.daemon.enable on and using an SSH tunnel to
        ferrum.daemon.listenAddress:${toString ferrum.daemon.port}, which is
        what that option exists for.
      '';
    }
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
