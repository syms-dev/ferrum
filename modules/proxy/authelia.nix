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
in
lib.mkIf authEnabled {
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
      session.domain = ferrum.proxy.baseDomain;
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
      proxyLib = import ./lib.nix { inherit lib; };
      exposedAppsAuth = proxyLib.exposedApps ferrum;
      vhostNameFor = proxyLib.vhostNameFor ferrum;

      bypassRules = id: app: map
        (path: {
          domain = vhostNameFor app;
          resources = [ "^${path}.*$" ];
          policy = "bypass";
        })
        app.auth.bypassPaths;

      appRule = id: app: {
        domain = vhostNameFor app;
        policy = app.auth.policy;
      };
    in
    lib.concatLists (lib.mapAttrsToList bypassRules exposedAppsAuth)
    ++ lib.mapAttrsToList appRule exposedAppsAuth;

  systemd.tmpfiles.rules = [
    "d '${stateDir}' 0750 authelia-main authelia-main - -"
  ];
}
