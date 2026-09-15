# The ferrum NixOS module. Import this once from a host flake (normally via
# ferrum.lib.mkHost) to get the whole ferrum.* option namespace plus every
# app in the catalog, each gated on its own ferrum.apps.<id>.enable.
{ lib, ... }:
{
  # The settings document a host was built from, consumed by
  # ./core/bootstrap.nix to seed /etc/ferrum/settings.json on a brand-new
  # machine. ferrum.lib.mkHost overrides this with the real value.
  #
  # It MUST be declared here with mkDefault rather than relying on a
  # `ferrumSettingsSeed ? null` default in bootstrap.nix's own function
  # signature. That does not work for NixOS module arguments, and the
  # failure is not obvious: the module system resolves an argument by
  # looking up `config._module.args.<name>` and errors with "attribute
  # 'ferrumSettingsSeed' missing" if it is absent, never consulting the
  # function's default at all.
  #
  # Confirmed for real: with only the signature default, every test that
  # does `imports = [ ../modules ]` directly rather than going through
  # mkHost -- tests/rollback.nix, tests/apply-generation-switch.nix,
  # tests/privilege-boundary.nix and both daemon tests -- failed to
  # evaluate. mkHost's own plain assignment outranks this mkDefault.
  _module.args.ferrumSettingsSeed = lib.mkDefault null;

  imports = [
    ./core/options.nix
    ./core/nix-settings.nix
    ./core/bootstrap.nix
    ./core/storage.nix
    ./core/overlays.nix
    ./core/generations.nix
    ./core/state-restore.nix
    ./core/secrets.nix
    ./core/daemon.nix
    ./core/recyclarr.nix
    ./core/reconciler.nix
    ./proxy/acme.nix
    ./proxy/nginx.nix
    ./proxy/selfsigned-cert.nix
    ./proxy/authelia.nix
    ./apps/sonarr/service.nix
    ./apps/radarr/service.nix
    ./apps/prowlarr/service.nix
    ./apps/jellyfin/service.nix
    ./apps/plex/service.nix
    ./apps/sabnzbd/service.nix
    ./apps/qbittorrent/service.nix
  ];
}
