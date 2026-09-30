{ rustPlatform, lib, makeWrapper, btrfs-progs, sops, ssh-to-age, authelia, dnsutils, shadow }:
rustPlatform.buildRustPackage {
  pname = "ferrum-apply";
  version = "0.1.0";
  src = lib.cleanSource ../../../crates;
  cargoLock.lockFile = ../../../crates/Cargo.lock;
  buildAndTestSubdir = "ferrum-apply";

  # ferrum-apply shells out to `btrfs` (preflight's check_is_subvolume, and
  # later apply/restore-state's snapshot/swap commands), `sops` and
  # `ssh-to-age` (secrets::ensure_all's encrypt-only secret generation),
  # and `authelia` (secrets::argon2id_hash, for the generated first-user
  # password).
  #
  # `dnsutils` provides `dig`, which ferrum-dns::dns_query shells out to for
  # decision D-07's post-apply check: every record ferrum writes is queried
  # against the zone's OWN authoritative nameservers, never the host's
  # recursive resolver, which can hold a negative-cache entry and report a
  # freshly created record as absent. Decision D-10 chose `dig` over a
  # hand-rolled DNS client precisely so no wire-format parser lives inside
  # this root-privileged binary. Only ferrum-apply needs it: verify_authoritative
  # is called from `apply` and from `reconcile-dns`, while ferrum-install's
  # two ferrum-dns call sites (verify_zone_access, list_records) are HTTPS --
  # so nix/pkgs/ferrum-install/* deliberately does NOT gain this input.
  #
  # `shadow` supplies `passwd` and `chpasswd`, which
  # secrets::ensure_root_password uses to ask whether root actually has a
  # usable password and, if it does not, to give it one. Every NixOS system
  # already ships shadow -- this input does not add a package to the host,
  # it only guarantees the two binaries are on PATH for THIS process
  # wherever it runs, which is the same guarantee the other five inputs get
  # and for the same reason: a systemd unit that forgot to supply them
  # would otherwise turn a real failure into an environment one.
  #
  # Deliberately NOT in nativeCheckInputs, unlike the rest. No test shells
  # out to `passwd` or `chpasswd`: setting a real account's password needs
  # real privilege, which a Nix sandbox does not have and a test must not
  # need. `ensure_root_password_for` takes the status line and the setter
  # as arguments precisely so the whole decision is testable without
  # either, so adding shadow here would be an unused input asserting a
  # coverage that does not exist.
  #
  # nativeCheckInputs alone only puts these on PATH during this
  # derivation's own checkPhase -- it does NOT reach the installed binary
  # at runtime, so it's paired here with a wrapper that guarantees they're
  # all on PATH wherever this binary actually runs, independent of whether
  # a consuming systemd unit remembers to supply them too.
  nativeCheckInputs = [ btrfs-progs sops ssh-to-age authelia dnsutils ];
  nativeBuildInputs = [ makeWrapper ];
  postFixup = ''
    wrapProgram $out/bin/ferrum-apply --prefix PATH : ${lib.makeBinPath [ btrfs-progs sops ssh-to-age authelia dnsutils shadow ]}
  '';
}
