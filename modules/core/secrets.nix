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
{ lib, ... }:
{
  services.openssh.enable = lib.mkDefault true;
}
