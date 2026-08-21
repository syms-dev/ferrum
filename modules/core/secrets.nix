# Wires sops-nix's decrypt side (config.sops.*) into every ferrum host.
# The box's age identity is derived from its own SSH host key -- no
# separate key-provisioning step, no key to lose track of during
# nixos-anywhere install: sops.age.sshKeyPaths already defaults to
# config.services.openssh.hostKeys's ed25519 keys (confirmed by reading
# sops-nix's own source), so all this module needs to do is make sure
# openssh is actually enabled, since sops-nix's own assertion requires
# either that, an explicit sops.age.keyFile, or GPG -- and nothing in
# ferrum's module tree turns on openssh otherwise.
#
# The ENCRYPT side (turning a plaintext value into a new .sops file) is
# deliberately NOT here -- it needs only the box's PUBLIC age key
# (ssh-to-age on the host's own ssh_host_ed25519_key.pub), needs no
# privilege at all, and is implemented independently by whatever writes a
# given secret: modules/apps/*/service.nix's own commit for the
# auto-generated per-app API keys, or a later ferrumd change for
# operator-provided secrets (see the design spec). This module is decrypt
# plumbing only.
#
# services.openssh.enable also defaults services.openssh.openFirewall to
# true, opening TCP/22 -- an intended, not incidental, consequence: the
# design spec's first-user setup-token bootstrap is delivered "readable
# only over SSH", so a ferrum host is meant to be SSH-reachable out of the
# box. An operator who wants SSH closed can override
# services.openssh.openFirewall = false in custom/ without affecting the
# age-identity mechanism above, which only needs the host key to exist,
# not the port to be open.
{ config, lib, ... }:
{
  services.openssh.enable = lib.mkDefault true;

  assertions = [
    {
      assertion = lib.hasPrefix "/" config.ferrum.secretsDir
        && !lib.hasSuffix "/" config.ferrum.secretsDir;
      message = "ferrum.secretsDir must be an absolute path with no trailing slash (got: ${config.ferrum.secretsDir}) -- every sops.secrets.<name>.sopsFile in this tree is built by concatenating it with a filename via `/. + \"\${ferrum.secretsDir}/...\"`, and a relative or trailing-slash value produces a confusing eval error far from this option.";
    }
  ];
}
