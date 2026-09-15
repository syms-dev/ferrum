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
      **and** keyboard. If the install fails partway the machine may not boot,
      and SSH will not be there to help you.

      A keyboard without a monitor is not out-of-band access. You cannot read
      a GRUB error, see which device failed to mount, or tell whether the
      machine got past POST — you would be typing blind into a box that
      cannot answer. Any HDMI television counts as a monitor. If you truly
      cannot attach a display, treat Step 5b's VM test as mandatory rather
      than recommended.
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

**Also record the boot mode.** Run on the target:

```bash
[ -d /sys/firmware/efi ] && echo UEFI || echo BIOS
```

This decides the partition table and the bootloader, and getting it wrong is
the worst failure available here: the install completes successfully and the
machine then does not boot, with the previous OS already gone. The template
ships a UEFI layout (a vfat ESP plus systemd-boot); a BIOS target needs an
`EF02` BIOS boot partition and GRUB instead. Both files say so at the point
of change.

The partition table is a second, independent tell: a UEFI system cannot boot
without a FAT32 ESP, so `lsblk -o NAME,FSTYPE` showing no `vfat` partition
anywhere means the machine is booting BIOS regardless of what its firmware
supports.

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

## Step 4 — install with NO apps enabled (this is not optional)

**The first install must have an empty `apps` block.** This is a real
bootstrap ordering constraint, not caution:

```json
{ "schemaVersion": 1, "apps": {} }
```

Every enabled app declares a sops secret, and sops-nix requires each
`sopsFile` to be a Nix path pointing at a file that **physically exists at
evaluation time** — `modules/core/secrets.nix` and
`nix/modules/flake/checks.nix` both document this. On a machine being
installed from scratch, `/etc/ferrum/secrets/` does not exist yet and neither
do those files. They are generated by `ferrum-apply` on the host, on its
first apply, encrypted to the host's own SSH key — which cannot happen before
the host exists.

So the sequence is: install an app-less host, let it generate its secrets,
then enable apps. Keep the full settings alongside as `settings.stage2.json`
and swap it in at Step 7.

## Step 5 — dry run

Build the configuration without touching the target. This catches every
evaluation error, every unset `CHANGE-ME` Nix can see, and every missing
file, at zero cost:

```bash
nix build .#nixosConfigurations.<hostname>.config.system.build.toplevel
```

A real ferrum host with apps enabled can only be built with `--impure`, for
the same sops reason above — which is why `crates/ferrum-apply/src/apply.rs`
passes `--impure` on every real apply, and says so at the call site. With an
empty `apps` block this step needs no such flag, which is a useful signal in
itself: **if the pure build fails, something other than secrets is wrong.**

It must succeed before you continue. A failure here is free; the same failure
after Step 6 has begun is a machine with no operating system.

## Step 5b — boot the configuration in a VM first

`nixos-anywhere` can build the system and boot the disk layout in a VM
without touching the target at all:

```bash
nix run github:nix-community/nixos-anywhere -- --flake .#<hostname> --vm-test
```

This is the single highest-value step in this document, and it is the one
that settles the question a dry run cannot: **does this disk layout actually
produce a machine that boots?** Partitioning, bootloader installation, the
subvolume layout and the mount ordering are all exercised for real. It is
also the only place a BIOS-versus-UEFI mistake shows up *before* it has cost
you an operating system.

**Run it on the target itself.** The VM test needs KVM and must match the
target's architecture, so a laptop of a different architecture cannot run it
— but the machine you are about to install onto is, by definition, the right
architecture, and it is about to be wiped anyway. Installing Nix on it for
this one check costs nothing:

```bash
# on the target, which is about to be replaced regardless
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

Do this especially if you do not have a monitor on the target. It does not
replace console access — a VM cannot reproduce the real firmware's boot
order, a USB disk that enumerates slowly, or a kexec that hangs — but it
converts the largest single unknown from a gamble into a tested fact.

## Step 6 — install

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

## Step 7 — first boot

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

### Now enable the apps

On the target, swap the full settings in and apply. This run is what generates
every app's sops secret for the first time:

```bash
cp settings.stage2.json settings.json   # in the host flake repo
ferrum-apply apply
```

`ferrum-apply` passes `--impure` itself, so this needs no flag from you. Watch
for each app's `.sops` file appearing under `/etc/ferrum/secrets/`.

## Step 8 — enable the apps, then prove rollback works

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
