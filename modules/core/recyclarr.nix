# Recyclarr: opinionated, optional TRaSH-Guide quality-definition sync for
# Sonarr and Radarr, reusing nixpkgs' own services.recyclarr module
# directly (confirmed present and packaged for both x86_64-linux and
# aarch64-linux against the pinned nixpkgs revision) rather than a bespoke
# ferrum wrapper -- that module already does exactly what's needed: a
# systemd timer running `recyclarr sync` on a schedule, with a
# secrets-substitution mechanism that composes directly with sops-nix's
# own decrypted-secret paths.
#
# Scoped to quality_definition only, not custom_formats -- quality_definition
# is real, documented, and self-contained (it pulls TRaSH's own bundled
# quality-size-limit tables via Recyclarr's `type` setting, no external
# lookup needed); custom_formats entries need real TRaSH-Guide trash_id
# GUIDs this plan has no way to verify without fabricating them. An
# operator who wants custom formats adds them via the same `custom/`
# override mechanism every other ferrum default supports (see
# services.recyclarr.configuration's own description).
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  recyclarrEnabled = ferrum.recyclarr.enable;

  sonarrEnabled = recyclarrEnabled && (ferrum.apps.sonarr.enable or false);
  radarrEnabled = recyclarrEnabled && (ferrum.apps.radarr.enable or false);

  # Recyclarr's own `_secret` mechanism reads the REFERENCED FILE'S RAW
  # CONTENT verbatim (confirmed against nixpkgs' real
  # utils.genJqSecretsReplacement source) -- the "-raw" secrets Task 1
  # added are exactly the bare-value representation this needs; the
  # original "<app>-apikey.sops" (environmentFiles format) would embed
  # the whole "SONARR__AUTH__APIKEY=<key>" line as the api_key value
  # instead, a real auth failure against Sonarr's real API.
  configuration =
    lib.optionalAttrs sonarrEnabled {
      sonarr.main = {
        base_url = "http://127.0.0.1:${toString ferrum.apps.sonarr.port}";
        api_key._secret = config.sops.secrets."sonarr-apikey-raw".path;
        quality_definition.type = "series";
      };
    }
    // lib.optionalAttrs radarrEnabled {
      radarr.main = {
        base_url = "http://127.0.0.1:${toString ferrum.apps.radarr.port}";
        api_key._secret = config.sops.secrets."radarr-apikey-raw".path;
        quality_definition.type = "movie";
      };
    };
in
lib.mkIf recyclarrEnabled {
  services.recyclarr = {
    enable = true;
    inherit configuration;
  };
}
