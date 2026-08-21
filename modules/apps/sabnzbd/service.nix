# SABnzbd, wired through the uniform ferrum.apps.sabnzbd submodule onto
# nixpkgs' services.sabnzbd. The upstream module hardcodes
# serviceConfig.StateDirectory = "sabnzbd" (always /var/lib/sabnzbd, no
# relocation option) -- overridden here via lib.mkForce null so SABnzbd's
# actual data lives under app.stateDir like every other app in this
# catalog, participating in the rollback mechanism the same way. Since
# removing StateDirectory means systemd no longer creates that directory
# for us, this module provisions app.stateDir itself via tmpfiles, the
# same way modules/core/storage.nix provisions ferrum.storage.stateDir.
{ config, lib, ... }:
let
  ferrum = config.ferrum;
  app = ferrum.apps.sabnzbd or { enable = false; };
in
lib.mkIf app.enable {
  assertions = [
    {
      assertion = !(builtins.pathExists (/. + "${app.stateDir}/sabnzbd.ini"))
                  || builtins.pathExists (/. + "${ferrum.secretsDir}/sabnzbd-apikey.sops");
      message = ''
        ${app.stateDir}/sabnzbd.ini exists but
        ${ferrum.secretsDir}/sabnzbd-apikey.sops does not -- this host's
        SABnzbd was bootstrapped before Recyclarr/reconciler support
        existed (or its state was rolled back to a snapshot predating this
        secret), and ferrum-apply cannot retroactively recover the
        already-generated key from the existing sabnzbd.ini without
        decrypt access it deliberately never holds. Delete both
        ${app.stateDir}/sabnzbd.ini and
        ${ferrum.secretsDir}/sabnzbd-apikey.sops and re-apply to generate
        a fresh matched pair -- see README.md's Secrets section for the
        same recovery procedure already documented for servarr keys.
      '';
    }
  ];

  sops.secrets."sabnzbd-apikey" = {
    sopsFile = /. + "${ferrum.secretsDir}/sabnzbd-apikey.sops";
    format = "binary";
    owner = "sabnzbd";
  };

  services.sabnzbd = {
    enable = true;
    user = "sabnzbd";
    group = "sabnzbd";
    configFile = "${app.stateDir}/sabnzbd.ini";
  };

  systemd.tmpfiles.rules = [
    "d ${app.stateDir} 0750 sabnzbd sabnzbd - -"
    # ferrum-apply's own ensure_sabnzbd_apikey (crates/ferrum-apply/src/
    # secrets.rs) writes this file directly, running as root, BEFORE the
    # sabnzbd system user necessarily exists (first-ever apply, before
    # activation has ever run) -- so it can't chown to "sabnzbd" itself.
    # 'Z' fixes ownership/mode on the existing path without requiring it
    # to exist when the rule is first evaluated, and NixOS activation
    # re-processes tmpfiles.d rules on every switch-to-configuration,
    # matching the exact same pattern modules/proxy/authelia.nix already
    # uses for users_database.yml. Without this, the file stays root-owned
    # 0644 forever and SABnzbd's own process (which needs to persist
    # settings changes back into this same file) can never write it
    # (found during the final whole-branch review).
    "Z '${app.stateDir}/sabnzbd.ini' 0640 sabnzbd sabnzbd - -"
  ];

  users.users.sabnzbd.extraGroups =
    lib.optional (app.mediaAccess != "none") ferrum.storage.mediaGroup;

  systemd.services.sabnzbd = {
    wantedBy = lib.mkForce [ "ferrum-apps.target" ];
    partOf = [ "ferrum-apps.target" ];
    unitConfig.ConditionPathExists = "!/var/lib/ferrum/state-restore-failed";
    serviceConfig = (lib.filterAttrs (_: v: v != null) {
      MemoryMax = app.resources.memoryMax;
      CPUQuota = app.resources.cpuQuota;
    }) // {
      StateDirectory = lib.mkForce null;
    };
  };
}
