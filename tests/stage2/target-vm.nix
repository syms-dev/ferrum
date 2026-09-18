# The machine the stage-2 CI job installs ONTO.
#
# Deliberately not a ferrum host and not a NixOS test node: just Linux with
# sshd, a root key, and a blank second disk. The whole point is that the
# installer turns an ordinary machine into a ferrum host, so the starting
# machine must not already be one.
#
# Built as a plain qemu-vm rather than through `runNixOSTest` because this
# job needs what the test sandbox cannot give it: a network. Stage 2 exists
# precisely so each app's `sopsFile` is created at runtime ON the guest,
# which means the stage-2 closure cannot be pre-built and injected the way
# tests/install-from-nothing.nix injects stage 1's.
{ nixpkgs, system, sshPublicKey }:
(import "${nixpkgs}/nixos/lib/eval-config.nix" {
  inherit system;
  modules = [
    ({ modulesPath, lib, ... }: {
      imports = [ "${modulesPath}/virtualisation/qemu-vm.nix" ];

      services.openssh = {
        enable = true;
        settings.PermitRootLogin = "yes";
        settings.PasswordAuthentication = false;
      };
      users.users.root.openssh.authorizedKeys.keys = [ sshPublicKey ];

      virtualisation = {
        graphics = false;
        # nixos-anywhere kexecs into its own installer and then the guest
        # builds its OWN closure (--build-on remote), so this needs real
        # room -- both are why the sandboxed test cannot do stage 2.
        memorySize = 6144;
        diskSize = 12288;
        cores = 2;
        # The disk the installer will erase. Separate from the VM's own
        # boot disk so the run genuinely starts from something blank.
        emptyDiskImages = [ 20480 ];
        forwardPorts = [{ from = "host"; host.port = 2222; guest.port = 22; }];
      };

      nix.settings.experimental-features = [ "nix-command" "flakes" ];
      documentation.enable = lib.mkForce false;
      system.stateVersion = "25.11";
    })
  ];
}).config.system.build.vm
