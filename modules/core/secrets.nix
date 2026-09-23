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
#
# ferrum.secretsDir's SHAPE is not checked here, and the assertion that
# used to check it has been deleted rather than moved.
#
# It read "must be an absolute path with no trailing slash", and justified
# itself with "a relative or trailing-slash value produces a confusing eval
# error far from this option". Both halves stopped being true when the
# option gained modules/lib/hostnames.nix's `absolutePath` type, whose
# pattern -- `(/[A-Za-z0-9_][A-Za-z0-9._-]*)+` -- requires a leading slash
# and forbids a trailing one at the OPTION. Confirmed by evaluating the type
# directly: "etc/ferrum/secrets" and "/etc/ferrum/secrets/" are both
# refused, "/etc/ferrum/secrets" is accepted.
#
# So the assertion could not fire, and the error it promised to prevent now
# arrives AT the option with the option's own name on it -- which is nearer
# than this module, not further. Deleted rather than rewritten because an
# assertion that cannot fail is indistinguishable from no assertion at all,
# except that it reads as coverage. The type is the control, and
# modules/lib/settings-schema.json's `pattern` on the same field is what
# stops ferrumd's PUT /api/settings composing a bad value in the first
# place.
{ lib, ... }:
{
  services.openssh.enable = lib.mkDefault true;
}
