# Catalog metadata for Jellyfin. Unlike the servarr apps, Jellyfin's own
# NixOS module exposes no port option -- it always listens on 8096/8920,
# configured through Jellyfin's own web UI. defaultPort documents that
# fixed default rather than something ferrum actually wires through.
{
  id = "jellyfin";
  displayName = "Jellyfin";
  category = "media-server";
  summary = "Free media server for streaming movies, TV, and music.";

  defaultPort = 8096;
  defaultSubdomain = "jellyfin";
  defaultMediaAccess = "read";
  # "bypass", not one_factor, and this is a correctness matter rather than
  # a convenience one. Jellyfin's native clients (Android TV, Roku, smart TVs, mobile)
  # authenticate with Jellyfin's own token and have no browser to
  # complete an Authelia redirect with -- forward-auth in front of them does
  # not prompt for a login, it makes every native client fail to connect,
  # while a desktop browser still works. That asymmetry is what makes it
  # easy to misdiagnose.
  #
  # This app is NOT thereby unauthenticated: it ships its own login, which
  # is why crates/ferrum-install/src/sso.rs lists it in APPS_WITH_OWN_LOGIN
  # and does not count it among the apps left open when Authelia is off.
  # Keep those two facts in step.
  #
  # authBypassPaths below stays as documentation of the endpoints clients
  # hit before authenticating; with a bypass policy the whole vhost is
  # already unguarded, so it has no additional effect here.
  defaultAuthPolicy = "bypass";

  # Jellyfin's own documented pre-authentication endpoints.
  #
  # This list IS enforced now -- modules/proxy/nginx.nix generates a
  # location per entry, served without auth_request. The previous version
  # of this comment said it was "metadata only until Phase 1.4's proxy
  # actually enforces it", and that remained true for three more phases:
  # nothing read the list until the auth-bypass work. Still worth
  # validating against real native-client behaviour.
  authBypassPaths = [ "/System/Info/Public" "/Users/AuthenticateByName" "/Sessions" ];

  healthCheck = {
    path = "/health";
    expectStatus = 200;
    timeoutSec = 30;
  };

  integrations = {
    providesTo = [ ];
    consumes = [ ];
  };

  settingsSchema = {
    type = "object";
    additionalProperties = false;
    properties = { };
  };

  docsUrl = "https://jellyfin.org/docs/";
  iconSlug = "jellyfin";
}
