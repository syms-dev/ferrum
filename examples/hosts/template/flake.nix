# A real ferrum host flake. Copy this directory to its own git repository --
# NOT into the ferrum repo -- and edit the four CHANGE-ME values.
#
# This is the file nixos-anywhere and every later `ferrum-apply apply`
# evaluate. It lands on the host at /etc/ferrum/flake.nix, root-owned and
# unwritable by ferrumd, which is what makes "compromising the daemon does
# not yield arbitrary Nix evaluation as root" true.
#
# It must be a git repository, and every file must be tracked (`git add`).
# Nix silently ignores untracked files inside a git tree, so an untracked
# disko.nix produces a confusing "file does not exist" during install rather
# than an error naming the real cause.
{
  description = "ferrum host";

  inputs = {
    # CHANGE-ME if you forked ferrum. Pin to a tag or a commit for a real
    # host rather than tracking a branch: `ferrum-apply apply` re-evaluates
    # this flake, and an unpinned input means an update can arrive because
    # upstream moved, not because you asked for one.
    ferrum.url = "github:YOUR-USER/ferrum";

    disko.url = "github:nix-community/disko";
    disko.inputs.nixpkgs.follows = "ferrum/nixpkgs";
  };

  outputs = { self, ferrum, disko, ... }: {
    nixosConfigurations = {
      # CHANGE-ME to your hostname.
      ferrum-host = ferrum.lib.mkHost {
        system = "x86_64-linux";

        # The operator-facing settings document. ferrumd rewrites the copy at
        # /etc/ferrum/settings.json at runtime; THIS file is the one the host
        # is built from and the one modules/core/bootstrap.nix seeds the
        # runtime copy from on first activation.
        settings = builtins.fromJSON (builtins.readFile ./settings.json);

        # Surfaced in the UI and in ferrum-catalog's ferrumVersion, so an
        # operator can tell which revision a running host was built from.
        revision = self.shortRev or self.dirtyShortRev or "dirty";

        modules = [
          disko.nixosModules.disko
          ./disko.nix
          ./hardware-configuration.nix

          # Everything hand-written and machine-specific. ferrum never
          # rewrites anything in here; see custom/media.nix.
          ] ++ ferrum.lib.importDir ./custom ++ [

          ({ ... }: {
            networking.hostName = "ferrum-host"; # CHANGE-ME

            # CHANGE-ME. This is how you reach the machine after the install,
            # and on a headless box it is the ONLY way -- nixos-anywhere
            # replaces the entire OS, so any key Saltbox had authorised is
            # gone. Get this wrong and the machine boots fine and locks you
            # out permanently.
            users.users.root.openssh.authorizedKeys.keys = [
              "ssh-ed25519 AAAA...CHANGE-ME"
            ];

            services.openssh = {
              enable = true;
              settings.PasswordAuthentication = false;
              settings.PermitRootLogin = "prohibit-password";
            };

            # UEFI. On a legacy-BIOS target this is wrong and produces an
            # unbootable machine -- see disko.nix's ESP comment for how to
            # check, and use instead:
            #
            #   boot.loader.grub = {
            #     enable = true;
            #     devices = [ "/dev/disk/by-id/<the OS disk>" ];
            #     efiSupport = false;
            #   };
            boot.loader.systemd-boot.enable = true;
            boot.loader.efi.canTouchEfiVariables = true;

            # The ferrum daemon's own web UI. Bound to the LAN only by
            # default; it is deliberately never placed behind Authelia
            # (you need it to configure Authelia in the first place).
            ferrum.daemon.enable = true;
          })
        ];
      };
    };
  };
}
