# Installing ferrum

> **This procedure destroys the target machine's operating system disk.**
> It has never been run to completion on real hardware. Read all of it before
> starting, and read [Before you start](#before-you-start) twice if the
> machine currently holds data.

ferrum is installed with [nixos-anywhere](https://github.com/nix-community/nixos-anywhere),
which kexecs a NixOS installer over SSH, repartitions the disk you name with
[disko](https://github.com/nix-community/disko), and installs your host
configuration. The target does not need to be running NixOS — any kexec-capable
Linux with root SSH works, which is what makes it possible to point this at an
existing Ubuntu or Debian server.

## Before you start

**disko repartitions unconditionally.** There is no merge, no preserve step and
no confirmation prompt. Every byte on the disk named in `disko.nix` is gone the
moment the install runs.

The protection for any disk you want to keep is *structural*: a disk that is
not declared in `disko.nix` is never opened, never partitioned and never
mounted during install. `examples/hosts/template/disko.nix` declares exactly
one device for this reason, and mounts the data disks afterwards from
`custom/media.nix`, where a mistake costs a failed mount instead of a wiped
drive.

You need all of these before you begin. Each one is something that is
painful or impossible to obtain after the OS is gone:

- [ ] **Out-of-band access** — IPMI, a KVM, or physical access with a monitor
      and keyboard. If the install fails partway the machine may not boot, and
      SSH will not be there to help you.
- [ ] **A backup of anything on the OS disk you care about.** Application
      configuration, databases, `docker-compose` files, `.env` files, cron
      jobs, anything under `/opt` or `/home`. ferrum's catalog is seven apps;
      anything else the machine ran does not come back.
- [ ] **Your SSH public key**, pasted into the host flake. nixos-anywhere
      replaces the whole OS, so every key previously authorised on the machine
      is erased. A host with no valid key boots perfectly and is unreachable.
- [ ] **The disk IDs**, gathered from the target itself (below).
- [ ] **A note of the machine's current IP** and whether it is static or from
      DHCP. A fresh NixOS install requests DHCP; if the machine had a static
      address configured in the OS you just replaced, it will come back on a
      different address.

## Step 1 — identify the disks, on the target

Run this **on the machine you are about to install onto**, and keep the output:

```bash
lsblk -o NAME,SIZE,MODEL,SERIAL,FSTYPE,MOUNTPOINT,UUID
ls -l /dev/disk/by-id/
```

Record, unambiguously:

- which device is the **OS disk** (the one that gets wiped);
- which devices are **data disks** (the ones to preserve), and what filesystem
  each already carries;
- for each, the stable `/dev/disk/by-id/` name.

**Always use `/dev/disk/by-id/`, never `/dev/sda` or `/dev/nvme0n1`.** Kernel
enumeration order is not stable across boots. On a multi-drive machine the
difference between "the OS disk" and "the disk holding your library" can come
down to one reboot's worth of luck. Prefer the `by-id` entry carrying the model
and serial; skip the `-part<N>` and `wwn-` aliases.

If the data disks are pooled (mergerfs, LVM, RAID, ZFS), record the pool's
layout too. **ferrum has no mergerfs or rclone support** — the design doc puts
that tier explicitly out of scope for Phase 1 — so any pool must be
reassembled by hand in `custom/`. See `examples/hosts/template/custom/media.nix`.

## Step 2 — create the host repository

```bash
cp -r examples/hosts/template ~/my-ferrum-host
cd ~/my-ferrum-host
git init && git add -A
```

`git add` is not optional. Nix silently ignores untracked files inside a git
tree, so an untracked `disko.nix` fails during install with a confusing "file
does not exist" rather than an error naming the real cause.

Then edit every `CHANGE-ME` in the four files:

| File | What to set |
|---|---|
| `flake.nix` | the ferrum input URL, hostname, **your SSH public key** |
| `disko.nix` | the OS disk's `/dev/disk/by-id/` name — *the disk that gets wiped* |
| `custom/media.nix` | the data disks' `by-id` names and their existing filesystem type |
| `settings.json` | which apps to enable, your domain, ACME email |

Confirm you have missed none:

```bash
grep -rn CHANGE-ME .
```

## Step 3 — generate `hardware-configuration.nix`

nixos-anywhere needs the target's real hardware configuration. Generate it from
the target and copy it into the host repository:

```bash
ssh root@TARGET nixos-generate-config --no-filesystems --show-hardware-config \
  > hardware-configuration.nix
git add hardware-configuration.nix
```

`--no-filesystems` is required: disko owns every `fileSystems` entry for the OS
disk, and a generated duplicate produces a conflicting definition that fails
evaluation.

If the target is not running NixOS, `nixos-generate-config` will not exist
there. Run the install with `--generate-hardware-config` instead, which
produces the file from inside the kexec'd installer:

```bash
nixos-anywhere --generate-hardware-config nixos-generate-config ./hardware-configuration.nix \
  --flake .#ferrum-host root@TARGET
```

## Step 4 — dry run

Build the configuration without touching the target. This catches every
evaluation error, every unset `CHANGE-ME` that Nix can see, and every missing
file, at zero cost:

```bash
nix build .#nixosConfigurations.ferrum-host.config.system.build.toplevel
```

It must succeed before you continue. A failure here is free; the same failure
after Step 5 has begun is a machine with no operating system.

## Step 5 — install

**This is the destructive step.**

```bash
nix run github:nix-community/nixos-anywhere -- \
  --flake .#ferrum-host \
  root@TARGET
```

On a machine whose CPU differs from your laptop's, add `--build-on remote` so
the target builds its own closure rather than having a foreign-architecture one
copied to it.

The machine reboots into ferrum when this completes.

## Step 6 — first boot

```bash
ssh root@TARGET

# ferrumd's own first-user password, generated once, root-readable only.
cat /var/lib/ferrum/daemon/ferrumd-setup-password

# Confirm /etc/ferrum was provisioned with the ownership ferrumd requires.
ls -la /etc/ferrum
#   settings.json  root:ferrum 0664
#   secrets/       ferrum:ferrum 0750
#   custom/        root:root 0755

systemctl status ferrumd
```

If `ferrumd` refuses to start, check `systemctl status ferrumd` for an
`AssertPathExists` failure — that means `/etc/ferrum/settings.json` or
`/etc/ferrum/secrets` is missing, which `modules/core/bootstrap.nix` should
have created at activation.

Verify the media disks mounted and that **the data is still there**:

```bash
mount | grep -E 'media|mergerfs'
ls /srv/media
```

Then reach the UI at `http://TARGET:8080` (or whatever `ferrum.daemon.port` is
set to) and log in as `admin` with the password above. Change it immediately.

## Step 7 — prove rollback works, before you rely on it

Do this while the machine is still empty and you do not care about it. It is
the one property ferrum exists to provide, and it has never been exercised on
real hardware:

```bash
ferrum-apply apply          # take a generation and a state snapshot
# make a visible change in settings.json, apply again
ferrum-apply rollback --to N
```

Confirm the system closure *and* the application state both revert, and that
the box comes back up. If this does not work on your hardware, nothing else
about ferrum matters.

## Recovering a failed install

The target's OS disk has been repartitioned; there is no undo. Options, in
order of preference:

1. **Re-run `nixos-anywhere`** after fixing the configuration. The disk is
   already in the right shape and the install is idempotent.
2. **Boot a NixOS installer ISO** over IPMI/USB and install by hand from the
   same flake.
3. **Reinstall the previous OS.** Your data disks are untouched if they were
   correctly kept out of `disko.nix` — which is the entire reason that file
   declares exactly one device.
