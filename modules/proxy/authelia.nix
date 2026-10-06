# Authelia forward-auth, one shared instance ("main") for every catalog
# app. access_control rules (which app needs which policy) are added by
# modules/proxy/nginx.nix's auth_request wiring in Task 3 -- this file
# only stands the instance up: its own secrets, its file-based user
# database, and the minimal settings confirmed against nixpkgs' own
# nixos/tests/authelia.nix (Step 1 above).
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  authEnabled = ferrum.auth.enable;
  stateDir = "/var/lib/authelia-main";
  proxyLib = import ./lib.nix { inherit lib; };

  # R5, first half -- the fix SEC-M02 deferred.
  #
  # This used to be `session.domain = ferrum.proxy.baseDomain`: ONE cookie
  # covering every published name on the host, including the control plane at
  # ferrum.<baseDomain>. Several catalog apps deliberately carry
  # unauthenticated bypass locations, so a cookie obtained in one app's
  # context was presentable at the dashboard's edge gate. That was accepted
  # as a Medium only because ferrumd's own `__Host-ferrumd_session` sat
  # underneath as a compensating control -- and R5's second half spends that
  # control, so this has to land first and does.
  #
  # Three properties of the list below are load-bearing, and the first two
  # are enforced by Authelia itself while the third is not. All three are
  # held by nix/modules/flake/checks.nix's authelia-cookie-scope, which runs
  # Authelia's own `validate-config` over the generated file:
  #
  #   1. Each entry's `authelia_url` must sit inside that entry's own cookie
  #      scope, which is why the control plane needs a portal hostname of its
  #      own. See modules/proxy/lib.nix's autheliaPortalFor.
  #   2. The more specific scope must be listed FIRST. Reversing these two is
  #      refused with "option 'domain' shares the same cookie domain scope as
  #      another configured session domain".
  #   3. The two cookies must have DIFFERENT names. Authelia accepts a
  #      duplicate name across scopes; a browser then sends both to
  #      ferrum.<baseDomain> under one name and RFC 6265 does not say which
  #      the server reads, which is SEC-M02 rebuilt inside its own fix.
  daemonPublished = proxyLib.daemonPublished ferrum;
  controlCookieDomain = proxyLib.controlPlaneCookieDomain ferrum;

  appsCookie = {
    domain = ferrum.proxy.baseDomain;
    authelia_url = "https://${proxyLib.autheliaPortalFor ferrum.proxy.baseDomain}";
    name = "authelia_session";
  };

  # Only on a host that actually publishes the dashboard. With
  # ferrum.daemon.publish = false -- the installer's stage-1 shape, and the
  # tunnel-only host -- nothing serves ferrum.<baseDomain>, so a scope for it
  # would name a portal URL with no vhost, no certificate and no record.
  controlCookie = {
    domain = controlCookieDomain;
    authelia_url = "https://${proxyLib.autheliaPortalFor controlCookieDomain}";
    name = "ferrum_control_session";
  };
in
lib.mkIf authEnabled {
  assertions = [
    {
      assertion = ferrum.proxy.enable;
      message = "ferrum.auth.enable is true but ferrum.proxy.enable is false -- Authelia has no reverse proxy in front of it to forward-auth for.";
    }
    {
      assertion = ferrum.auth.adminEmail != "";
      message = "ferrum.auth.enable is true but ferrum.auth.adminEmail is empty -- the generated first user needs a real email address.";
    }
  ];

  sops.secrets."authelia-jwt-secret" = {
    sopsFile = /. + "${ferrum.secretsDir}/authelia-jwt-secret.sops";
    format = "binary";
    owner = "authelia-main";
    restartUnits = [ "authelia-main.service" ];
  };
  sops.secrets."authelia-storage-key" = {
    sopsFile = /. + "${ferrum.secretsDir}/authelia-storage-key.sops";
    format = "binary";
    owner = "authelia-main";
    restartUnits = [ "authelia-main.service" ];
  };

  # Both auto-generated the same way Phase 1.4a generates servarr API
  # keys -- see crates/ferrum-apply/src/secrets.rs's ensure_all, extended
  # in this task's Step 3. Neither is operator-provided: nothing a human
  # would type in, exactly the "auto-generated secrets" path the spec
  # distinguishes from "operator-provided" ones.
  services.authelia.instances.main = {
    enable = true;
    secrets = {
      jwtSecretFile = config.sops.secrets."authelia-jwt-secret".path;
      storageEncryptionKeyFile = config.sops.secrets."authelia-storage-key".path;
    };
    settings = {
      authentication_backend.file.path = "${stateDir}/users_database.yml";
      # Every app's own access_control rule is added by Task 3; this is
      # the fallback for anything the catalog-driven rules don't
      # explicitly name (there shouldn't be any once Task 3 lands, but
      # Authelia requires SOME default_policy to start at all).
      access_control.default_policy = "deny";
      session.cookies = lib.optional daemonPublished controlCookie ++ [ appsCookie ];
      storage.local.path = "${stateDir}/db.sqlite3";
      # Filesystem notifier, not SMTP -- ferrum assumes no mail server.
      # Password-reset/notification emails just aren't a Phase 1
      # feature; this satisfies Authelia's own requirement for SOME
      # notifier to be configured.
      notifier.filesystem.filename = "${stateDir}/notifications.txt";
    };
  };

  # One rule per app matching its vhost domain with policy = app.auth.policy
  # (Authelia's own policy enum is literally bypass/one_factor/two_factor/deny
  # -- the same names ferrum chose when this option was first scaffolded, no
  # translation needed), plus a higher-priority bypass rule per entry in
  # app.auth.bypassPaths. Higher priority = listed FIRST: Authelia evaluates
  # access_control.rules in order and uses the first match, so bypass rules
  # must precede the app's own general-policy rule.
  services.authelia.instances.main.settings.access_control.rules =
    let
      exposedAppsAuth = proxyLib.exposedApps ferrum;
      vhostNameFor = proxyLib.vhostNameFor ferrum;

      bypassRules = _: app: map
        (path: {
          domain = vhostNameFor app;
          resources = [ "^${path}.*$" ];
          policy = "bypass";
        })
        app.auth.bypassPaths;

      appRule = _: app: {
        domain = vhostNameFor app;
        policy = app.auth.policy;
      };

      # D1/A2. The control plane needs a rule of its own, because the
      # generator above is driven by exposedApps and the daemon is not a
      # catalog app. Without this, access_control.default_policy = "deny"
      # above applies to ferrum.<baseDomain>, and an auth_request-wired
      # daemon vhost then denies EVERYONE, ALWAYS -- the dashboard would be
      # unopenable rather than merely weakly gated, which is a non-functional
      # ship rather than a security finding.
      #
      # Built by calling the SAME appRule on lib.nix's synthetic daemonApp,
      # deliberately, rather than by writing the rule shape out a second time:
      # when that generator grows a field, the daemon gets it too instead of
      # drifting. Appended alongside the app rules, never in place of them.
      # No bypass rules accompany it -- daemonApp's bypassPaths is empty by
      # design (D4), so the daemon exempts no path from the edge gate.
      daemonRules = lib.optional
        (proxyLib.daemonPublished ferrum)
        (appRule null (proxyLib.daemonApp ferrum));
    in
    lib.concatLists (lib.mapAttrsToList bypassRules exposedAppsAuth)
    ++ lib.mapAttrsToList appRule exposedAppsAuth
    ++ daemonRules;

  systemd.tmpfiles.rules = [
    "d '${stateDir}' 0750 authelia-main authelia-main - -"
    # 'Z' fixes ownership/mode on an EXISTING path without requiring it to
    # exist when the rule is first evaluated -- needed because
    # users_database.yml is created by ferrum-apply's Step 0 (secrets.rs's
    # ensure_first_authelia_user), root-owned by whatever process ran
    # ferrum-apply, before the authelia-main user necessarily exists on a
    # first-ever apply. NixOS activation re-processes tmpfiles.d rules on
    # every switch-to-configuration, so this corrects ownership on every
    # subsequent apply too, including a later password change Authelia
    # itself writes back (found during the final whole-branch review --
    # without this, the file stays root-owned 0644 forever and Authelia's
    # own process can never rewrite it).
    "Z '${stateDir}/users_database.yml' 0640 authelia-main authelia-main - -"
  ];
}
