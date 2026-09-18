# The Docker image that IS the installer's delivery vehicle (spec DEC-02):
# Docker is the only thing the operator's own machine must have.
#
# Built by Nix rather than from a Dockerfile, so its contents are pinned by
# this repo's flake.lock instead of by whatever `apt-get` resolved on the
# day it was built -- which is what makes R1 A2's claim true.
#
# One image is produced per system the flake declares. That matters for the
# architecture question: on an Apple-silicon machine the operator runs the
# aarch64 image NATIVELY, and the x86_64 closure for the target is never
# built here at all -- nixos-anywhere kexecs the target first and builds
# there (`--build-on remote`), which is already this project's practice for
# provisioning an x86_64 box from the aarch64 dev machine.
{ dockerTools
, ferrum-install
, cacert
, bashInteractive
, coreutils
, lib
}:
dockerTools.buildLayeredImage {
  name = "ferrum-install";
  tag = "latest";

  contents = [
    ferrum-install
    cacert
    # A shell and coreutils are present on purpose: an install that fails
    # partway leaves the operator needing to look around, and an image with
    # no shell turns a five-minute diagnosis into a rebuild.
    bashInteractive
    coreutils
  ];

  # `nix` inside the image needs flakes enabled and a writable store path
  # for its own evaluation; /tmp must exist for both nix and ssh's control
  # sockets.
  extraCommands = ''
    mkdir -p tmp etc root
    chmod 1777 tmp
    cat > etc/nix.conf <<EOF
    experimental-features = nix-command flakes
    EOF

    # /etc/passwd and /etc/group are NOT optional, and their absence is not
    # a cosmetic gap. OpenSSH refuses to start at all when it cannot resolve
    # the uid it is running as -- it exits with "No user exists for uid 0"
    # before it opens a connection. Since every single thing this installer
    # does to a target goes over ssh, an image without these files cannot
    # collect an inventory, let alone install: the very first command fails.
    #
    # dockerTools does not synthesise them, and nothing in the Rust test
    # suite or the NixOS VM tests can catch it, because both run the binary
    # outside this image. It was found by running the built image against a
    # target, which is the only place it is observable.
    cat > etc/passwd <<EOF
    root:x:0:0:root:/root:/bin/bash
    EOF
    cat > etc/group <<EOF
    root:x:0:
    EOF

    # ssh writes known_hosts relative to HOME. Without one it falls back to
    # a path that does not exist in this image.
    chmod 700 root
  '';

  config = {
    Entrypoint = [ (lib.getExe ferrum-install) ];
    Env = [
      "NIX_CONFIG=experimental-features = nix-command flakes"
      "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt"
      "PATH=/bin"
      # ssh resolves ~ from HOME; the installer also points
      # UserKnownHostsFile at the operator's mounted --ssh-dir, but ssh
      # still wants a usable HOME for its own defaults.
      "HOME=/root"
    ];
    # The host repository is written here and must outlive the container;
    # declaring it documents the mount the operator has to supply, and
    # preconditions::check_host_dir refuses with the exact -v flag if they
    # forget.
    Volumes = { "/host" = { }; };
    WorkingDir = "/host";
  };
}
