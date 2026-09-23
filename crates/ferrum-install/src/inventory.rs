//! What is actually on the target, and which single disk the operator has
//! agreed to destroy.
//!
//! disko repartitions unconditionally: no merge, no preserve step, no
//! prompt. The protection for every disk the operator wants to keep is
//! *structural* -- a disk that is not named in the generated `disko.nix` is
//! never opened, never partitioned and never mounted. This module's job is
//! to produce an inventory accurate enough that the operator can identify
//! the right disk from it, and to refuse rather than guess whenever the
//! evidence is ambiguous.
//!
//! Everything here is pure: it parses text that was collected elsewhere.
//! That is deliberate, because it means every refusal below is testable
//! without a machine to destroy.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One partition or filesystem sitting on a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filesystem {
    pub name: String,
    pub fstype: Option<String>,
    pub mountpoint: Option<String>,
    /// The PARTITION's own stable `/dev/disk/by-id/` path.
    ///
    /// Distinct from the containing disk's, and that distinction is the
    /// whole point: the filesystem lives on the partition. Mounting the
    /// disk instead fails with "wrong fs type, bad superblock", which is
    /// exactly what happened on the first real install -- both data disks
    /// silently failed to mount because `custom/media.nix` named the disk.
    ///
    /// `#[serde(default)]` so an inventory written before this field
    /// existed still deserializes on a resume.
    #[serde(default)]
    pub by_id: Option<String>,
}

/// A whole block device, as the operator needs to see it to identify one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub size: String,
    pub model: Option<String>,
    pub serial: Option<String>,
    /// The stable `/dev/disk/by-id/` path. `None` when the target exposes
    /// no usable alias -- which is a refusal, not a fallback to `/dev/sdX`.
    pub by_id: Option<String>,
    pub children: Vec<Filesystem>,
}

impl Device {
    /// A device carrying no filesystem anywhere. Used by the firmware truth
    /// table: the "no ESP therefore BIOS" heuristic is only meaningful on a
    /// disk that has already been installed to.
    pub fn is_blank(&self) -> bool {
        self.children.is_empty()
    }

    pub fn has_vfat(&self) -> bool {
        self.children
            .iter()
            .any(|c| c.fstype.as_deref() == Some("vfat"))
    }

    pub fn mounted_at(&self) -> Vec<&str> {
        self.children
            .iter()
            .filter_map(|c| c.mountpoint.as_deref())
            .collect()
    }
}

// ---------------------------------------------------------------------
// lsblk parsing
// ---------------------------------------------------------------------

#[derive(Deserialize)]
struct LsblkRoot {
    blockdevices: Vec<LsblkDevice>,
}

#[derive(Deserialize)]
struct LsblkDevice {
    name: String,
    #[serde(default)]
    size: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    #[serde(rename = "type")]
    dev_type: Option<String>,
    #[serde(default)]
    fstype: Option<String>,
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default)]
    children: Vec<LsblkDevice>,
}

/// Normalises one `lsblk` field into `Some(real value)` or `None`.
///
/// Two separate jobs, both load-bearing.
///
/// `lsblk` renders absent values as JSON null and, on some versions, as an
/// empty string. Both mean "unknown", and treating `""` as a real value is
/// exactly how an empty serial becomes an identifier (R2 A8).
///
/// It also **strips control characters**. These strings come from `lsblk`
/// on a machine this installer does not control, and they are printed
/// straight into the disk table the operator reads to choose which disk to
/// DESTROY. A model or serial containing `\x1b[2K\r` erases and rewrites
/// the line on a real terminal, so a crafted device can make the table
/// show a different disk, size or serial than the one it is about to
/// select. Trimming alone does not touch interior control bytes.
///
/// Stripped rather than rejected: a control byte in a model string is a
/// cosmetic defect on a legitimate disk, and refusing to install because a
/// vendor put a stray byte in a product name would be its own failure. The
/// value stays usable and stops being able to lie about the line it is on.
///
/// # Arguments
/// * `v` - the raw field, as deserialized.
///
/// # Returns
/// `None` when absent, empty, or empty once cleaned; otherwise the cleaned
/// value.
/// The longest any lsblk-derived field may render.
///
/// Without a cap, one `model` rendered 200,161 bytes into the disk table.
/// Only a few short lines separate that table from the "Type the SERIAL of
/// the disk to erase" prompt, so a flood scrolls every real row off screen
/// and leaves attacker-composed text sitting immediately above the prompt.
/// That needs no control characters and no bidi -- it works on every
/// terminal. 64 is comfortably wider than any real model or serial.
const MAX_FIELD: usize = 64;

/// The most devices the disk table will render.
///
/// A machine with more real disks than this exists, so the overflow is
/// reported rather than hidden -- and selection is by serial, which is
/// unaffected by what the table shows.
const MAX_DEVICES: usize = 32;

/// The file a resume recovers its decisions from, named in every refusal
/// that can only happen after the disk is already erased.
const RECOVERY_FILE: &str = "install-inventory.json";

/// Reduces one untrusted `lsblk` field to something that cannot lie about
/// the line it is printed on.
///
/// **Allowlist, not denylist, and that distinction is the whole point.**
/// This used to filter `char::is_control()`, which is Unicode category
/// **Cc only**. Category **Cf** -- U+202E RIGHT-TO-LEFT OVERRIDE, the bidi
/// isolates U+2066-2069, U+200E/U+200F, the soft hyphen U+00AD, the
/// zero-width space U+200B -- is not `is_control()` and sailed straight
/// through, reproducing the exact attack the filter was added to stop: the
/// row shown as `sda` displaying a serial that genuinely belongs to `sdb`.
///
/// So this keeps only what it will vouch for: printable ASCII and the
/// space. Every real device model, serial, size and kernel name is already
/// within that set. A legitimate non-ASCII model loses characters, which
/// is a cosmetic cost on a disk table, and the thing it buys is that no
/// byte from the target can reposition the cursor, reverse the reading
/// order, or hide itself.
///
/// Truncation happens here too, so no caller can forget it.
///
/// # Arguments
/// * `s` - the raw field as reported by the target.
///
/// # Returns
/// The allowlisted, trimmed, length-capped value; may be empty.
fn strip_controls(s: &str) -> String {
    let kept: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect();
    // Runs of spaces collapse to one. Space has to stay in the allowlist
    // -- real models contain them -- but a run of them lets a <=64-char
    // model imitate the table's own columns on its own row, e.g.
    // "sda  1T  OS          8T  serial: MEDIA123". Real models never
    // contain runs, so collapsing costs nothing and removes the imitation.
    let kept = kept.split_whitespace().collect::<Vec<_>>().join(" ");
    let kept = kept.trim();
    if kept.chars().count() > MAX_FIELD {
        let head: String = kept.chars().take(MAX_FIELD - 3).collect();
        format!("{head}...")
    } else {
        kept.to_string()
    }
}

/// `clean` for a field that is always present, such as a device name.
///
/// `name` reaches the operator's table like every other field and was NOT
/// being cleaned at all. That is the whole of SEC-C1: see `clean`.
///
/// # Arguments
/// * `v` - the raw field.
///
/// # Returns
/// The value with control characters removed, or `"?"` if nothing is left
/// -- never an empty cell, which would be indistinguishable from a
/// rendering bug.
/// Makes a `Device` recovered from disk satisfy what `parse_lsblk` would
/// have established -- refusing where a field drives a decision, and
/// normalising where it only renders.
///
/// The resume path deserializes `Device` straight out of
/// `install-inventory.json`, which lives in the operator's writable bind
/// mount. That file is as forgeable as anything else there, and a
/// deserialize is not a validation -- a lesson already learned once here
/// for `by_id`, where only half of it was applied.
///
/// **Why two different treatments, and not refusal for everything.** An
/// earlier version refused any field that was not byte-identical to what
/// today's cleaner produces. That stranded legitimate resumes: real ATA
/// model strings are vendor-padded (`"WDC  WD40EFRX-68N32N0"`), so the
/// whitespace collapse added in the same cycle retroactively invalidated
/// every inventory file written before it. Past the wipe this is the ONLY
/// path -- `needs_disk_confirmation` is false -- so the refusal landed
/// with the disk already erased, and its advice to delete the inventory
/// file could not work, because this function's caller opens that file
/// first. The general form is what makes it worth avoiding: every future
/// tightening of `strip_controls` would invalidate every existing record.
///
/// So:
/// * `name` and `serial` are REFUSED if they do not survive cleaning.
///   `name` feeds `attach_by_id`, and `serial` is what the post-kexec
///   guard re-verifies before the partition table is destroyed. A
///   mismatch there is a wrong-disk risk, and refusing is right.
/// * `size`, `model`, `fstype` and `mountpoint` are NORMALISED in place.
///   Cleaning them removes the display-forgery risk without a refusal that
///   has no safe landing.
///
/// **These four are not "cosmetic" -- they decide nothing ON THIS PATH,
/// which is a different and much narrower claim.** `fstype` in particular
/// is decision-bearing elsewhere: it drives `has_vfat` -> `infer_firmware`
/// (UEFI versus BIOS, where the wrong answer boots to nothing on a
/// headless box whose previous OS is already gone) and it is emitted into
/// the installed host's real configuration as
/// `fileSystems."/mnt/media-N".fsType`. `mountpoint` feeds `mounted_at` ->
/// `confirm::propose`, and a non-empty `children` feeds `is_blank` ->
/// `infer_firmware`.
///
/// Normalising them is safe *here* only because of where "here" is: on a
/// resume `Approved.firmware` is deserialized rather than recomputed, so
/// `infer_firmware` never runs; `propose` and `confirm` run only on the
/// fresh path, and past the wipe `needs_disk_confirmation` is false. For
/// `fstype` reaching generated Nix, cleaning is strictly safer than
/// passing the raw value through, and it is `nix_str`-escaped at the sink
/// regardless.
///
/// So do not reuse this function on the fresh path on the strength of the
/// list above. The refusal/normalise split is a statement about the resume
/// path, not about the fields.
///
/// # Arguments
/// * `d` - a device recovered from disk, normalised in place.
///
/// # Errors
/// When `name` or `serial` does not survive cleaning.
pub fn check_recovered_device(d: &mut Device) -> anyhow::Result<()> {
    // Every refusal below happens AFTER the disk is erased, because past
    // the wipe this is the only path there is. So each one has to name a
    // way out that actually works -- see SEC-M6, where the advice given
    // could not succeed.
    let recovery = |e: anyhow::Error| -> anyhow::Error {
        e.context(format!(
            "reading the recorded inventory in {RECOVERY_FILE}. Correct that \
             file, or re-run with --fresh to discard the recorded state and \
             start over. Re-running the SAME command will hit this again."
        ))
    };
    check_device_name(&d.name).map_err(&recovery)?;
    if let Some(serial) = d.serial.as_deref() {
        if strip_controls(serial) != serial {
            anyhow::bail!(
                "the recovered inventory records a serial for {} that does not \
                 survive cleaning. That value is what the post-kexec guard \
                 re-verifies immediately before the partition table is \
                 destroyed, so it cannot be normalised away. Either correct \
                 the \"serial\" field for {} in {RECOVERY_FILE}, or re-run with \
                 --fresh to discard the recorded state and start over. \
                 Re-running the SAME command will hit this again.",
                d.name,
                d.name
            );
        }
    }
    // Display-only from here down: normalise, never refuse.
    d.size = clean_required(std::mem::take(&mut d.size));
    d.model = clean(d.model.take());
    for f in &mut d.children {
        check_device_name(&f.name).map_err(&recovery)?;
        f.fstype = clean(f.fstype.take());
        f.mountpoint = clean(f.mountpoint.take());
    }
    Ok(())
}

/// Validates a kernel device name, which must survive cleaning unchanged.
///
/// `attach_by_id` looks a device up by this name, so a name that CHANGES
/// under cleaning could be mapped onto a different disk's by-id path --
/// another route to the wrong disk. Real kernel names (`sda`, `nvme0n1`,
/// `vdb`, `mmcblk0`) are plain ASCII and never change here, so a name that
/// does is not a kernel name and this refuses rather than guesses.
///
/// # Arguments
/// * `name` - the raw `name` field from lsblk.
///
/// # Errors
/// When the name is empty or contains anything outside `[A-Za-z0-9._-]`.
fn check_device_name(name: &str) -> anyhow::Result<()> {
    // BOTH checks, because neither implies the other.
    //
    // The charset alone let a 70-character all-valid name through, which
    // then truncated to 64 -- so the name used for the by-id lookup still
    // differed from the one displayed, which is the whole thing this
    // guards. That is what the survives-cleaning invariant catches.
    //
    // But the invariant alone is WEAKER for spaces: " " is inside the
    // allowlist and a single space survives cleaning untouched, so "sd a"
    // would pass. A kernel device name never contains a space. Keeping the
    // charset check is what rejects it.
    let charset_ok = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !charset_ok || strip_controls(name) != name {
        // Deliberately says nothing about WHERE this came from. It is
        // reached from two paths -- fresh (the target's lsblk) and resume
        // (install-inventory.json) -- and the old wording asserted the
        // target had reported it, which is false on the resume path and
        // pointed the operator at the wrong thing to fix.
        anyhow::bail!(
            "a block device named {name:?} is not a kernel device name. \
             Refusing: this name matches the device against its \
             /dev/disk/by-id alias, so accepting a forged one risks \
             resolving to a different disk than the table shows."
        );
    }
    Ok(())
}

fn clean_required(v: String) -> String {
    let c = strip_controls(&v);
    if c.is_empty() {
        "?".to_string()
    } else {
        c
    }
}

fn clean(v: Option<String>) -> Option<String> {
    v.map(|s| strip_controls(&s)).filter(|s| !s.is_empty())
}

/// Parses `lsblk -O --json` output into whole devices.
///
/// Only `type == "disk"` entries become devices; loop, rom and lvm entries
/// are not installation targets and listing them would pad the one screen
/// the operator has to make a destructive decision from.
///
/// # Errors
/// Returns an error if the JSON does not parse or lacks `blockdevices`.
pub fn parse_lsblk(json: &str) -> anyhow::Result<Vec<Device>> {
    let root: LsblkRoot = serde_json::from_str(json)?;
    root.blockdevices
        .into_iter()
        .filter(|d| d.dev_type.as_deref() == Some("disk"))
        .map(|d| -> anyhow::Result<Device> {
            check_device_name(&d.name)
                .map_err(|e| e.context("the target's own lsblk reported this device"))?;
            Ok(Device {
                name: clean_required(d.name),
                size: clean(d.size).unwrap_or_else(|| "?".to_string()),
                model: clean(d.model),
                serial: clean(d.serial),
                by_id: None,
                children: d
                    .children
                    .into_iter()
                    .map(|c| Filesystem {
                        name: clean_required(c.name),
                        fstype: clean(c.fstype),
                        mountpoint: clean(c.mountpoint),
                        by_id: None,
                    })
                    .collect(),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()
}

// ---------------------------------------------------------------------
// /dev/disk/by-id
// ---------------------------------------------------------------------

/// The character allowlist every `by-id` alias must satisfy, whatever it
/// names.
///
/// udev builds these from model and serial strings, and on a resume the
/// stored value is deserialized from a file in the operator's writable bind
/// mount -- so a shell metacharacter here is not impossible, only unusual,
/// and it would reach a remote root shell. This is the security half of the
/// old `is_unusable_alias`, split out because the two predicates below
/// disagree about `-part` and must not be allowed to disagree about this.
fn alias_chars_ok(alias: &str) -> bool {
    !alias.is_empty()
        && alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-:".contains(c))
}

/// True for an alias that identifies nothing an operator could read off the
/// screen: `wwn-` and `nvme-eui.` carry no model or serial, and the mapper
/// prefixes name a virtual device rather than a drive.
fn is_opaque_alias(alias: &str) -> bool {
    alias.starts_with("wwn-")
        || alias.starts_with("nvme-eui.")
        || alias.starts_with("lvm-")
        || alias.starts_with("dm-")
        || alias.starts_with("md-")
}

/// True for a `by-id` entry this installer will never name as a WHOLE DISK
/// in `disko.nix`.
///
/// `-partN` aliases point at a partition rather than the whole disk, so
/// they are wrong here -- and right in
/// [`is_unusable_partition_alias`], which is the point of the split.
fn is_unusable_alias(alias: &str) -> bool {
    !alias_chars_ok(alias) || alias.contains("-part") || is_opaque_alias(alias)
}

/// True for a `by-id` entry this installer will never name as the source of
/// a data disk's MOUNT.
///
/// The mirror image of [`is_unusable_alias`]: a partition alias must carry
/// `-partN`, because that is how udev spells the thing the filesystem
/// actually lives on. Everything else -- the character allowlist, the
/// opaque prefixes -- is held in common, which is why both predicates are
/// built from the same two helpers rather than restating the rules.
fn is_unusable_partition_alias(alias: &str) -> bool {
    !alias_chars_ok(alias) || !alias.contains("-part") || is_opaque_alias(alias)
}

/// Validates a `/dev/disk/by-id/` path that did NOT come from
/// `parse_by_id` in this process.
///
/// `parse_by_id` allowlists alias characters on the way in, so a value
/// that came from a live inventory is already safe. A value recovered from
/// `install-inventory.json` on a resume has not been through it -- that
/// file sits in the operator's writable bind mount -- and it then flows
/// into generated Nix and into disko, which interpolates the device
/// UNQUOTED in one of its own loops.
///
/// Rather than re-derive an escaping argument at each of those sinks,
/// validate once here so "the by-id path is allowlisted" is true on every
/// path into the program. Three consecutive security findings on this
/// surface all came from re-deriving safety per call site instead.
///
/// # Errors
/// When the value is not `/dev/disk/by-id/<allowlisted alias>`.
pub fn validate_by_id_path(path: &str) -> anyhow::Result<()> {
    let Some(alias) = path.strip_prefix("/dev/disk/by-id/") else {
        anyhow::bail!(
            "{path:?} is not a /dev/disk/by-id/ path. Kernel names are not \
             stable across boots and this value is re-read on every apply."
        );
    };
    if alias.is_empty() || is_unusable_alias(alias) {
        anyhow::bail!(
            "{path:?} is not a usable /dev/disk/by-id/ alias. It may contain \
             only letters, digits and . _ - :"
        );
    }
    Ok(())
}

/// The same validation for a PARTITION's `/dev/disk/by-id/` path.
///
/// A partition alias is `-partN`-suffixed, which
/// [`validate_by_id_path`] refuses by design -- so recovered children could
/// not be validated by that function, and before this existed they were not
/// validated at all. A child's alias reaches `custom/media.nix` as a
/// `fileSystems.<mount>.device` string and reaches the verification
/// command that `ssh` hands to a remote shell, so it needs exactly the
/// character guarantee its parent already had.
///
/// # Arguments
/// * `path` - the recovered `/dev/disk/by-id/...-partN` value.
///
/// # Errors
/// When the value is not `/dev/disk/by-id/<allowlisted partition alias>`.
pub fn validate_partition_by_id_path(path: &str) -> anyhow::Result<()> {
    let Some(alias) = path.strip_prefix("/dev/disk/by-id/") else {
        anyhow::bail!(
            "{path:?} is not a /dev/disk/by-id/ path. Kernel names are not \
             stable across boots and this value is re-read on every apply."
        );
    };
    if is_unusable_partition_alias(alias) {
        anyhow::bail!(
            "{path:?} is not a usable /dev/disk/by-id/ partition alias. It \
             must carry -partN and may contain only letters, digits and \
             . _ - :"
        );
    }
    Ok(())
}

/// Parses `ls -l /dev/disk/by-id/` into kernel name -> alias.
///
/// Reads the symlink target's basename rather than trusting the alias's own
/// spelling, which is what makes this correct across the `../../sda` and
/// `../../nvme0n1` forms alike.
///
/// **Partition aliases are kept.** They used to be dropped here, which made
/// [`attach_by_id`]'s partition loop -- and the comment above it explaining
/// why partitions matter -- dead code: `Filesystem::by_id` was `None` on
/// every device the live pipeline produced. `render::media` refuses a data
/// disk whose partition has no by-id path, so every install that kept a
/// data disk aborted while rendering `custom/media.nix`. Keeping both kinds
/// in one map is safe because the map is keyed by KERNEL NAME, and `sdb`
/// and `sdb1` are different keys: a disk lookup can never return a
/// partition alias, nor the reverse.
pub fn parse_by_id(listing: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in listing.lines() {
        let Some((alias_part, target)) = line.split_once(" -> ") else {
            continue;
        };
        let Some(alias) = alias_part.split_whitespace().next_back() else {
            continue;
        };
        if is_unusable_alias(alias) && is_unusable_partition_alias(alias) {
            continue;
        }
        let Some(kernel) = target.rsplit('/').next() else {
            continue;
        };
        // A disk can have several usable aliases; prefer the longest, which
        // is the one carrying both model and serial.
        out.entry(kernel.to_string())
            .and_modify(|existing: &mut String| {
                if alias.len() > existing.len() {
                    *existing = alias.to_string();
                }
            })
            .or_insert_with(|| alias.to_string());
    }
    out
}

/// Attaches the stable `by-id` path to each device.
///
/// The map now carries whole-disk and partition aliases together, so each
/// lookup re-asserts the kind it wants rather than trusting the key space
/// to keep them apart. The keys ARE disjoint -- `sdb` and `sdb1` -- but a
/// malformed listing line is the one input that could pair a `-part` alias
/// with a disk's kernel name, and the cost of checking is a string scan.
pub fn attach_by_id(devices: &mut [Device], by_id: &BTreeMap<String, String>) {
    let path_for = |name: &str, want_partition: bool| {
        by_id
            .get(name)
            .filter(|alias| {
                if want_partition {
                    !is_unusable_partition_alias(alias)
                } else {
                    !is_unusable_alias(alias)
                }
            })
            .map(|alias| format!("/dev/disk/by-id/{alias}"))
    };
    for dev in devices.iter_mut() {
        dev.by_id = path_for(&dev.name, false);
        // Partitions too. The disk's path is what the operator confirms
        // and what disko is told to erase; the PARTITION's path is what a
        // data disk is mounted from, because that is where the filesystem
        // is. Conflating them mounts /dev/sdb instead of /dev/sdb1.
        for fs in dev.children.iter_mut() {
            fs.by_id = path_for(&fs.name, true);
        }
    }
}

// ---------------------------------------------------------------------
// R2 A8 -- a serial is only an identifier if it is unique and non-empty
// ---------------------------------------------------------------------

/// Refuses an inventory whose serials cannot identify a disk.
///
/// The confirmation gate asks the operator to type a serial. That is only
/// a gate if the serial names exactly one device. Empty and duplicate
/// serials are ordinary on virtio devices, on USB bridges that report the
/// enclosure's serial rather than the drive's, and across same-batch
/// drives.
///
/// # Errors
/// Names the colliding or unidentified devices, and says to use the full
/// `by-id` path instead.
pub fn check_serials_identify(devices: &[Device]) -> anyhow::Result<()> {
    // A device with no serial is simply **not selectable** -- the operator
    // confirms by typing a serial, so one that reports none can never be
    // named, and `match_serial` will never return it.
    //
    // It is NOT a reason to refuse the whole machine. The first CI run of
    // the stage-2 test found this the hard way: a QEMU guest reports a
    // floppy device `fd0` with no serial, and the installer declined to
    // proceed at all. Real machines do the same with an empty optical
    // drive or a card reader. Refusing there protects nothing and makes
    // the installer unusable on ordinary hardware.
    //
    // What genuinely breaks the gate is a serial that identifies more than
    // one device, or a machine where nothing can be named at all.
    let named: Vec<&Device> = devices.iter().filter(|d| d.serial.is_some()).collect();
    if named.is_empty() {
        anyhow::bail!(
            "no device on this machine reports a serial, so there is nothing \
             you could confirm by typing one, and the disk gate is the only \
             thing standing between a typo and an erased disk.\n\n\
             This is normal on virtual machines -- virtio disks report no \
             serial -- and unusual on physical hardware. If this IS a VM, \
             give the target disk a serial in the hypervisor (libvirt: \
             <serial> on the disk; QEMU: -drive serial=...; Proxmox: the \
             `serial=` option on the disk) and re-run. If it is physical, \
             the disks are likely behind a controller that hides them -- \
             check for an HBA in RAID mode.\n\n\
             There is deliberately no flag to bypass this."
        );
    }

    let mut seen: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for d in &named {
        if let Some(sn) = d.serial.as_deref() {
            seen.entry(sn).or_default().push(&d.name);
        }
    }
    let collisions: Vec<String> = seen
        .iter()
        .filter(|(_, names)| names.len() > 1)
        .map(|(serial, names)| format!("{serial:?} is reported by {}", names.join(" and ")))
        .collect();
    if !collisions.is_empty() {
        anyhow::bail!(
            "serials do not uniquely identify a disk: {}. Re-run naming the \
             full /dev/disk/by-id/ path instead",
            collisions.join("; ")
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------
// R2 A5 -- the firmware truth table
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Firmware {
    Uefi,
    Bios,
}

/// Decides the firmware mode for the generated host.
///
/// `/sys/firmware/efi` is **authoritative**; the vfat signal is
/// corroboration only, and only on a disk that already carries something.
///
/// The rule this deliberately does NOT use is `docs/INSTALL.md`'s "no vfat
/// anywhere therefore BIOS". That is correct for an already-installed
/// machine -- a running UEFI system cannot have booted without an ESP --
/// and false for the blank or live-booted target this installer exists to
/// install. Applying it here would silently generate a BIOS host for a
/// genuinely UEFI machine, which boots to nothing on a headless box with
/// the previous OS already gone.
///
/// # Errors
/// Returns an error when the two signals disagree, rather than picking one.
/// Both ambiguous cases refuse: neither can produce a silently unbootable
/// machine.
pub fn infer_firmware(efi_present: bool, target_disk: &Device) -> anyhow::Result<Firmware> {
    match (efi_present, target_disk.is_blank(), target_disk.has_vfat()) {
        // EFI firmware, nothing on the disk to corroborate with: trust the
        // firmware. A blank disk cannot have an ESP by definition.
        (true, true, _) => Ok(Firmware::Uefi),
        (true, false, true) => Ok(Firmware::Uefi),
        (true, false, false) => anyhow::bail!(
            "conflicting signals: the target booted with EFI firmware \
             (/sys/firmware/efi exists) but {} carries no vfat ESP. That is \
             normal when reinstalling a legacy-BIOS machine from a UEFI live \
             environment, and it changes which bootloader the host needs. \
             Re-run once you have confirmed which firmware this machine \
             actually boots with.",
            target_disk.name
        ),
        (false, _, false) => Ok(Firmware::Bios),
        (false, _, true) => anyhow::bail!(
            "conflicting signals: the target reports no EFI firmware, but {} \
             carries a vfat partition that looks like an ESP. Refusing to \
             guess the bootloader.",
            target_disk.name
        ),
    }
}

/// Renders the inventory the operator reads to identify their disk.
///
/// Every device is shown, not just the candidates, because the operator is
/// about to make an irreversible choice and the disks they want to KEEP are
/// as important to recognise as the one they are destroying. Mount points
/// and filesystems are included for the same reason: "the one with my media
/// on it" is how people actually identify a drive.
pub fn render(devices: &[Device]) -> String {
    let mut out = String::new();
    // SEC-L-N9. 5000 devices rendered 913,890 bytes across 25,000 lines,
    // which scrolls the table off screen just as effectively as an
    // oversized field did. Every rendered row stays faithful to its
    // device, so this is confusion rather than misdirection -- but the
    // confusion happens immediately above "type the SERIAL of the disk to
    // erase", so it is capped and the remainder is COUNTED rather than
    // silently dropped.
    let shown = devices.len().min(MAX_DEVICES);
    for d in &devices[..shown] {
        out.push_str(&format!(
            "  {:<10} {:>8}  {}\n",
            d.name,
            d.size,
            d.model.as_deref().unwrap_or("(no model reported)")
        ));
        out.push_str(&format!(
            "  {:<10} {:>8}  serial: {}\n",
            "",
            "",
            d.serial
                .as_deref()
                .unwrap_or("(none reported -- cannot be selected)")
        ));
        out.push_str(&format!(
            "  {:<10} {:>8}  {}\n",
            "",
            "",
            d.by_id
                .as_deref()
                .unwrap_or("(no stable /dev/disk/by-id path)")
        ));
        if d.children.is_empty() {
            out.push_str(&format!("  {:<10} {:>8}  empty -- no partitions\n", "", ""));
        } else {
            for c in &d.children {
                out.push_str(&format!(
                    "  {:<10} {:>8}    {} {}{}\n",
                    "",
                    "",
                    c.name,
                    c.fstype.as_deref().unwrap_or("(no filesystem)"),
                    c.mountpoint
                        .as_deref()
                        .map(|m| format!(" mounted at {m}"))
                        .unwrap_or_default()
                ));
            }
        }
        out.push('\n');
    }
    if devices.len() > shown {
        out.push_str(&format!(
            "  ... and {} more device(s) not shown.\n             Selection is by SERIAL, so a disk missing from this\n             list can still be named -- but check the machine if\n             you did not expect this many.\n",
            devices.len() - shown
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    /// Found by running the built image against a live SSH target: the
    /// message told the operator to "re-run naming the full
    /// /dev/disk/by-id/ path instead", and there is no flag that does
    /// that. `--help` offers only --host-dir, --ssh-dir, --ssh-port and
    /// --fresh. Same class as the post-wipe advice the security review
    /// caught: an instruction the operator cannot carry out.
    #[test]
    fn the_no_serial_refusal_does_not_promise_a_flag_that_does_not_exist() {
        let devices = vec![super::Device {
            name: "nbd0".into(),
            size: "0B".into(),
            model: None,
            serial: None,
            by_id: None,
            children: Vec::new(),
        }];
        let err = super::check_serials_identify(&devices)
            .expect_err("a machine where nothing can be named must refuse");
        let msg = format!("{err:#}");

        // The impossible instruction, gone.
        assert!(!msg.contains("Re-run naming"), "{msg}");
        // Replaced by causes an operator can actually act on.
        assert!(msg.contains("virtio"), "{msg}");
        assert!(msg.contains("serial="), "{msg}");
        // And it says plainly that there is no way around it, rather than
        // implying one exists.
        assert!(msg.contains("no flag to bypass"), "{msg}");
    }

    fn dev(name: &str, serial: Option<&str>) -> super::Device {
        super::Device {
            name: name.into(),
            size: "8T".into(),
            model: None,
            serial: serial.map(|s| s.into()),
            by_id: None,
            children: Vec::new(),
        }
    }

    /// SEC-L-N7 and SEC-M6 together: refuse where a field decides,
    /// normalise where it only renders.
    ///
    /// Mutation check: make `check_recovered_device` return `Ok(())` and
    /// the refusal half fails; drop either `clean` call and the
    /// normalisation half fails.
    #[test]
    fn a_recovered_device_is_refused_where_it_decides_and_cleaned_where_it_renders() {
        // REFUSED: name and serial drive attach_by_id and the post-kexec
        // guard respectively.
        let mut bad = dev("sda\u{1b}[2K\r", None);
        assert!(super::check_recovered_device(&mut bad).is_err());

        let mut bidi = dev("sda", Some("\u{202e}321AIDEM"));
        let err = super::check_recovered_device(&mut bidi)
            .expect_err("a recovered serial must survive cleaning");
        let msg = err.to_string();
        assert!(msg.contains("post-kexec guard"), "{msg}");
        // The advice it gives must be advice that WORKS. "Delete
        // install-inventory.json" does not: recover_plan opens that file
        // before this runs, so the operator would be stranded with an
        // erased disk following an instruction that cannot succeed.
        assert!(!msg.contains("Delete install-inventory.json"), "{msg}");
        assert!(msg.contains("install-inventory.json"), "{msg}");
        // It must name --fresh. "Re-run the install from the beginning"
        // sends an operator back to the SAME command, which hits the same
        // recorded state and the same error.
        assert!(msg.contains("--fresh"), "{msg}");

        // The OTHER post-wipe refusal -- a forged name -- must carry the
        // same working advice. It did not: its message claimed "the target
        // reported" a device that in fact came from the recorded file, and
        // it offered no way out at all.
        let mut bad_name = dev("sd a", Some("S1"));
        let e = format!(
            "{:#}",
            super::check_recovered_device(&mut bad_name).unwrap_err()
        );
        assert!(e.contains("install-inventory.json"), "{e}");
        assert!(e.contains("--fresh"), "{e}");
        assert!(
            !e.contains("the target reported"),
            "false on the resume path: {e}"
        );

        // NORMALISED, never refused: these render and decide nothing once
        // the disk is gone. Real ATA models are vendor-padded, so an
        // earlier refusal here stranded legitimate resumes -- after the
        // wipe, when recover_plan is the only path there is.
        for model in [
            "WDC  WD40EFRX-68N32N0",
            "ATA     ST4000VN008-2DR1",
            "Samsung SSD 870 EVO 4TB",
        ] {
            let mut d = dev("sda", Some("S1"));
            d.model = Some(model.to_string());
            super::check_recovered_device(&mut d)
                .unwrap_or_else(|e| panic!("legitimate model {model:?} refused: {e}"));
        }

        // ...and the normalisation actually happens, so a forged display
        // field cannot survive into the table either.
        let mut d = dev("sda", Some("S1"));
        d.model = Some("EVIL\u{202e}\u{1b}[2K\rsda   8T".into());
        d.size = "8T\u{202e}".into();
        d.children.push(super::Filesystem {
            name: "sda1".into(),
            fstype: Some("ext4\u{202e}".into()),
            mountpoint: Some("/mnt\u{1b}[2K\r".into()),
            by_id: None,
        });
        super::check_recovered_device(&mut d).unwrap();
        for v in [
            d.model.as_deref().unwrap(),
            d.size.as_str(),
            d.children[0].fstype.as_deref().unwrap(),
            d.children[0].mountpoint.as_deref().unwrap(),
        ] {
            assert!(
                v.chars().all(|c| c.is_ascii_graphic() || c == ' '),
                "{v:?} was not normalised"
            );
        }
        assert!(!d.model.as_deref().unwrap().contains("  "), "{:?}", d.model);
    }

    /// SEC-L-N9. 5000 devices rendered 913,890 bytes, scrolling the table
    /// off screen as effectively as one oversized field did.
    ///
    /// Mutation check: remove the `MAX_DEVICES` cap and this fails.
    #[test]
    fn the_disk_table_caps_how_many_devices_it_renders() {
        let many: Vec<super::Device> = (0..5000)
            .map(|i| dev(&format!("sd{i}"), Some(&format!("S{i}"))))
            .collect();
        let table = super::render(&many);
        let lines = table.lines().count();
        assert!(lines < 200, "{lines} lines is still a flood");
        // The remainder is REPORTED, never silently dropped -- a disk
        // missing from the table can still be named by serial.
        assert!(table.contains("more device(s) not shown"), "{table}");
        assert!(
            table.contains(&format!("{} more", 5000 - super::MAX_DEVICES)),
            "{table}"
        );

        // An ordinary machine is unaffected.
        let few = vec![dev("sda", Some("A")), dev("sdb", Some("B"))];
        assert!(!super::render(&few).contains("not shown"));
    }

    /// SEC-M3. The disk table is what the operator reads to choose which
    /// disk to erase, and every string in it comes from `lsblk` on a
    /// machine this installer does not control.
    ///
    /// Mutation check: drop the `is_control` filter from `clean` and this
    /// fails.
    #[test]
    fn a_device_whose_name_is_not_a_kernel_name_is_refused() {
        // `attach_by_id` matches a device to its /dev/disk/by-id alias BY
        // NAME, so a name that changed under cleaning could resolve to a
        // different disk's stable path. Real kernel names are plain ASCII
        // and never change, so anything else is refused rather than
        // guessed at.
        for bad in ["sda\u{1b}[2K\r", "sd a", "sda/../sdb", "\u{202e}adz", ""] {
            let json = format!(
                r#"{{"blockdevices":[{{"name":{},"type":"disk","size":"1T"}}]}}"#,
                serde_json::to_string(bad).unwrap()
            );
            let err = super::parse_lsblk(&json)
                .expect_err(&format!("{bad:?} is not a kernel device name"));
            // `{:#}` walks the context chain -- the fresh path now adds
            // "the target's own lsblk reported this device", so the root
            // cause is no longer what `to_string()` returns.
            assert!(format!("{err:#}").contains("kernel device name"), "{err:#}");
            assert!(format!("{err:#}").contains("lsblk"), "{err:#}");
        }
        // A name that is entirely valid CHARSET but does not survive
        // cleaning, because it exceeds MAX_FIELD and truncates. The
        // charset check alone passes it, and then the name used for the
        // by-id lookup differs from the one displayed -- which is the
        // whole thing this guards. Mutation check: delete the
        // `strip_controls(name) != name` clause and this fails. It
        // survived the first time, which is why it is here.
        let long = "a".repeat(70);
        let json = format!(r#"{{"blockdevices":[{{"name":"{long}","type":"disk","size":"1T"}}]}}"#);
        let err = super::parse_lsblk(&json)
            .expect_err("a name that truncates under cleaning must be refused");
        assert!(format!("{err:#}").contains("kernel device name"), "{err:#}");
        // Exactly at the cap is fine.
        let at_cap = "a".repeat(super::MAX_FIELD);
        let json =
            format!(r#"{{"blockdevices":[{{"name":"{at_cap}","type":"disk","size":"1T"}}]}}"#);
        assert_eq!(super::parse_lsblk(&json).unwrap()[0].name, at_cap);

        // Real names still parse.
        for good in ["sda", "nvme0n1", "vdb", "mmcblk0", "dm-0"] {
            let json =
                format!(r#"{{"blockdevices":[{{"name":"{good}","type":"disk","size":"1T"}}]}}"#);
            assert_eq!(super::parse_lsblk(&json).unwrap()[0].name, good);
        }
    }

    #[test]
    fn the_rendered_table_survives_bidi_and_flooding() {
        // The second half of SEC-C1, found only because the first fix was
        // verified against the attack that had been DESCRIBED (ESC[2K)
        // instead of the property it claimed. `is_control()` is Unicode
        // category Cc; U+202E RIGHT-TO-LEFT OVERRIDE is category Cf and
        // went straight through, reproducing the wrong-disk outcome with
        // every guard agreeing.
        let bidi = "\u{202e}321AIDEM"; // renders as MEDIA123 reversed
        let others = [
            "\u{200e}x",
            "\u{200f}x",
            "\u{2066}x",
            "\u{2067}x",
            "\u{2068}x",
            "\u{2069}x",
            "\u{00ad}x",
            "\u{200b}x",
            "\u{feff}x",
        ];
        for payload in std::iter::once(bidi).chain(others) {
            let got = super::clean(Some(payload.to_string())).unwrap_or_default();
            for c in got.chars() {
                assert!(
                    c.is_ascii_graphic() || c == ' ',
                    "{payload:?} left {c:?} ({:#x}) in the table",
                    c as u32
                );
            }
        }

        // And the flood: no control characters, no bidi, works on every
        // terminal. One field scrolled the real rows off screen and left
        // attacker-composed text directly above the "type the SERIAL"
        // prompt.
        let flood = "A".repeat(200_000);
        let capped = super::clean(Some(flood)).unwrap();
        assert!(
            capped.chars().count() <= super::MAX_FIELD,
            "{}",
            capped.chars().count()
        );
        assert!(
            capped.ends_with("..."),
            "truncation must be visible: {capped:?}"
        );

        // A realistic value is untouched by the cap.
        assert_eq!(
            super::clean(Some("Samsung SSD 870 EVO 4TB".into())),
            Some("Samsung SSD 870 EVO 4TB".into())
        );
    }

    #[test]
    fn the_rendered_table_can_never_contain_a_control_character() {
        // SEC-C1, asserted where it actually matters: not on one helper,
        // but on the exact text the operator reads before naming a disk to
        // destroy.
        //
        // The attack this blocks is NOT display-only. `ESC[2K` + CR erases
        // and rewrites the line, so the row shown as `sda` can be made to
        // display the serial that genuinely belongs to `sdb`. The operator
        // types the serial they were shown; `match_serial` then correctly
        // selects the device that really owns it -- sdb -- and the
        // post-kexec guard re-verifies that disk's serial and agrees,
        // because nothing is malfunctioning. Every control behaves as
        // designed and the wrong disk is erased. No later guard can catch
        // it, which is why it has to be stopped here.
        // A forged NAME is refused outright now -- see
        // `a_device_whose_name_is_not_a_kernel_name_is_refused`. Here the
        // name is real and every OTHER field is hostile, which is the case
        // that must still render safely rather than refuse.
        let json = r#"{"blockdevices":[
          {"name":"sda","type":"disk","size":"1T\u001b[2K\r",
           "model":"EVIL\u001b[2K\rsda  8T  My Media Disk","serial":"S\u001b[2K\rDECOY",
           "children":[{"name":"sda1","fstype":"ext4\u001b[2K\r",
                        "mountpoint":"/mnt\u001b[2K\r"}]}
        ]}"#;
        let devices = super::parse_lsblk(json).expect("hostile lsblk must still parse");
        let table = super::render(&devices);
        assert!(
            !table.chars().any(|c| c.is_control() && c != '\n'),
            "a control character reached the disk table: {table:?}"
        );
        // Every field, not just the ones that happened to be cleaned before.
        let d = &devices[0];
        for field in [&d.name, &d.size] {
            assert!(!field.chars().any(|c| c.is_control()), "{field:?}");
        }
        for field in [d.model.as_deref(), d.serial.as_deref()] {
            assert!(!field.unwrap().chars().any(|c| c.is_control()), "{field:?}");
        }
        let f = &d.children[0];
        assert!(!f.name.chars().any(|c| c.is_control()), "{:?}", f.name);
        for field in [f.fstype.as_deref(), f.mountpoint.as_deref()] {
            assert!(!field.unwrap().chars().any(|c| c.is_control()), "{field:?}");
        }
    }

    #[test]
    fn control_characters_cannot_reach_the_disk_table() {
        // ESC [ 2K CR -- erase-line then carriage-return, which on a real
        // terminal makes everything printed before it on that line vanish.
        let evil = Some("EVIL\u{1b}[2K\rsda  8T  My Media Disk".to_string());
        let got = super::clean(evil).unwrap();
        assert!(!got.chars().any(|c| c.is_control()), "{got:?}");
        // Runs of spaces are collapsed too (SEC-L-N6), so a model can no
        // longer imitate the table's own columns on its own row.
        assert_eq!(got, "EVIL[2Ksda 8T My Media Disk");

        // A serial that would otherwise redraw itself as a decoy.
        let decoy = super::clean(Some("S\u{1b}[2K\rDECOY".into())).unwrap();
        assert!(!decoy.chars().any(|c| c.is_control()), "{decoy:?}");

        // Ordinary values are untouched, and absent ones stay absent.
        assert_eq!(
            super::clean(Some("  WD-WCC4N5PJ  ".into())),
            Some("WD-WCC4N5PJ".into())
        );
        assert_eq!(super::clean(Some("   ".into())), None);
        // Stripping the ESC leaves the literal text "[2K", which is inert --
        // it cannot move a cursor or erase a line. A value that is ONLY
        // control bytes does become None.
        assert_eq!(super::clean(Some("\u{1b}[2K".into())), Some("[2K".into()));
        assert_eq!(
            super::clean(Some("\u{1b}\r\u{7}".into())),
            None,
            "control-only is not a value"
        );
        assert_eq!(super::clean(None), None);
    }

    use super::*;

    fn disk(name: &str, serial: Option<&str>, children: Vec<Filesystem>) -> Device {
        Device {
            name: name.into(),
            size: "1.8T".into(),
            model: Some("WDC WD20EZAZ".into()),
            serial: serial.map(str::to_string),
            by_id: None,
            children,
        }
    }

    fn fs(name: &str, fstype: Option<&str>) -> Filesystem {
        Filesystem {
            name: name.into(),
            fstype: fstype.map(str::to_string),
            mountpoint: None,
            by_id: None,
        }
    }

    const LSBLK: &str = r#"{
      "blockdevices": [
        {"name":"sda","size":"1.8T","model":"WDC WD20EZAZ","serial":"WD-ABC123","type":"disk",
         "children":[
           {"name":"sda1","size":"512M","fstype":"vfat","mountpoint":"/boot","type":"part"},
           {"name":"sda2","size":"1.8T","fstype":"ext4","mountpoint":"/","type":"part"}]},
        {"name":"sdb","size":"3.6T","model":"ST4000VN","serial":"ZDH9","type":"disk","children":[]},
        {"name":"loop0","size":"64M","type":"loop"},
        {"name":"sr0","size":"1024M","type":"rom"}
      ]}"#;

    #[test]
    fn parses_only_whole_disks() {
        let d = parse_lsblk(LSBLK).unwrap();
        assert_eq!(
            d.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
            vec!["sda", "sdb"],
            "loop and rom devices are not installation targets"
        );
    }

    #[test]
    fn keeps_the_detail_needed_to_identify_a_disk() {
        let d = parse_lsblk(LSBLK).unwrap();
        assert_eq!(d[0].serial.as_deref(), Some("WD-ABC123"));
        assert_eq!(d[0].model.as_deref(), Some("WDC WD20EZAZ"));
        assert_eq!(d[0].size, "1.8T");
        assert_eq!(d[0].children.len(), 2);
        assert_eq!(d[0].mounted_at(), vec!["/boot", "/"]);
    }

    /// An empty string is lsblk saying "unknown", not a serial. Treating it
    /// as a value is exactly how an empty serial becomes an identifier.
    #[test]
    fn empty_strings_are_unknown_not_values() {
        let json = r#"{"blockdevices":[{"name":"vda","size":"20G","serial":"","model":"  ","type":"disk"}]}"#;
        let d = parse_lsblk(json).unwrap();
        assert_eq!(d[0].serial, None);
        assert_eq!(d[0].model, None);
    }

    #[test]
    fn a_disk_with_no_children_is_blank() {
        let d = parse_lsblk(LSBLK).unwrap();
        assert!(!d[0].is_blank());
        assert!(d[1].is_blank());
        assert!(d[0].has_vfat());
        assert!(!d[1].has_vfat());
    }

    const BY_ID: &str = "\
total 0
lrwxrwxrwx 1 root root  9 Sep 17 10:00 ata-WDC_WD20EZAZ_WD-ABC123 -> ../../sda
lrwxrwxrwx 1 root root 10 Sep 17 10:00 ata-WDC_WD20EZAZ_WD-ABC123-part1 -> ../../sda1
lrwxrwxrwx 1 root root  9 Sep 17 10:00 wwn-0x5000c500a1b2c3d4 -> ../../sda
lrwxrwxrwx 1 root root  9 Sep 17 10:00 ata-ST4000VN_ZDH9 -> ../../sdb
lrwxrwxrwx 1 root root 13 Sep 17 10:00 nvme-eui.0025385991b1c2d3 -> ../../nvme0n1
lrwxrwxrwx 1 root root 13 Sep 17 10:00 nvme-Samsung_SSD_980_S5P2NG0N123456 -> ../../nvme0n1
";

    /// A disk's key never resolves to a partition alias, and vice versa.
    ///
    /// This test used to assert `!m.values().any(|v| v.contains("-part"))`
    /// -- that partition aliases were dropped outright. That was the
    /// defect, not the contract: dropping them left `Filesystem::by_id`
    /// `None` on every live inventory, and `render::media` refuses a data
    /// disk whose partition has no by-id path. What actually has to hold is
    /// that the two kinds do not bleed into each other's keys.
    #[test]
    fn separates_partition_from_whole_disk_aliases() {
        let m = parse_by_id(BY_ID);
        assert_eq!(
            m.get("sda").map(String::as_str),
            Some("ata-WDC_WD20EZAZ_WD-ABC123")
        );
        assert_eq!(m.get("sdb").map(String::as_str), Some("ata-ST4000VN_ZDH9"));
        // The partition is now reachable -- under its OWN kernel name.
        assert_eq!(
            m.get("sda1").map(String::as_str),
            Some("ata-WDC_WD20EZAZ_WD-ABC123-part1")
        );
        // ...and no whole-disk key carries one.
        assert!(!m["sda"].contains("-part"), "{m:?}");
        assert!(!m["sdb"].contains("-part"), "{m:?}");
        // wwn- still loses to the ata- alias.
        assert!(!m.values().any(|v| v.starts_with("wwn-")));
    }

    /// The end-to-end path that `render::media` depends on, exercised
    /// through the real `parse_by_id` + `attach_by_id` pair rather than by
    /// hand-constructing a `Filesystem` with its `by_id` already filled in.
    ///
    /// Every render test did the latter, which is why this never showed up:
    /// the pipeline that produces the value was never run in a test that
    /// asserted on it. On a real install it produced `None`, and the
    /// install aborted rendering `custom/media.nix`.
    #[test]
    fn a_partition_alias_survives_the_live_inventory_pipeline() {
        let json = r#"{"blockdevices":[
            {"name":"sdb","size":"7.3T","model":"ST8000DM004","serial":"ZR13ABCD","type":"disk",
             "children":[{"name":"sdb1","size":"7.3T","fstype":"ext4","type":"part"}]}]}"#;
        let listing = "\
lrwxrwxrwx 1 root root  9 x x x ata-ST8000DM004_ZR13ABCD -> ../../sdb
lrwxrwxrwx 1 root root 10 x x x ata-ST8000DM004_ZR13ABCD-part1 -> ../../sdb1
lrwxrwxrwx 1 root root 10 x x x wwn-0x5000c500a1b2c3d4-part1 -> ../../sdb1
";
        let mut d = parse_lsblk(json).unwrap();
        attach_by_id(&mut d, &parse_by_id(listing));
        assert_eq!(
            d[0].by_id.as_deref(),
            Some("/dev/disk/by-id/ata-ST8000DM004_ZR13ABCD")
        );
        assert_eq!(
            d[0].children[0].by_id.as_deref(),
            Some("/dev/disk/by-id/ata-ST8000DM004_ZR13ABCD-part1"),
            "the mount source render::media needs"
        );
    }

    /// A listing line pairing a `-part` alias with a DISK's kernel name is
    /// malformed, and `attach_by_id` must not hand it to disko as the thing
    /// to erase.
    #[test]
    fn a_partition_alias_is_never_attached_to_a_whole_disk() {
        let json = r#"{"blockdevices":[{"name":"sdb","size":"1T","type":"disk","children":[]}]}"#;
        let listing = "lrwxrwxrwx 1 root root 9 x x x ata-X_1-part1 -> ../../sdb\n";
        let mut d = parse_lsblk(json).unwrap();
        attach_by_id(&mut d, &parse_by_id(listing));
        assert_eq!(d[0].by_id, None, "{:?}", d[0].by_id);
    }

    /// An `nvme-eui.` alias carries no model or serial, so an operator
    /// cannot tell which drive it is by reading it.
    #[test]
    fn prefers_the_nvme_alias_that_names_the_drive() {
        let m = parse_by_id(BY_ID);
        assert_eq!(
            m.get("nvme0n1").map(String::as_str),
            Some("nvme-Samsung_SSD_980_S5P2NG0N123456")
        );
    }

    /// These strings reach a remote root shell on the verification path.
    #[test]
    fn an_alias_with_shell_metacharacters_is_not_usable() {
        let listing = "lrwxrwxrwx 1 root root 9 x x x ata-EVIL$(id) -> ../../sdz\n\
                       lrwxrwxrwx 1 root root 9 x x x ata-OK_123 -> ../../sda\n";
        let m = parse_by_id(listing);
        assert!(!m.values().any(|v| v.contains("$(")), "{m:?}");
        assert_eq!(m.get("sda").map(String::as_str), Some("ata-OK_123"));
    }

    #[test]
    fn attaches_full_by_id_paths() {
        let mut d = parse_lsblk(LSBLK).unwrap();
        attach_by_id(&mut d, &parse_by_id(BY_ID));
        assert_eq!(
            d[0].by_id.as_deref(),
            Some("/dev/disk/by-id/ata-WDC_WD20EZAZ_WD-ABC123")
        );
    }

    /// The resume path deserializes this straight out of a file in the
    /// operator's writable bind mount, and it reaches generated Nix and
    /// disko's own unquoted `for dev in ...` loop.
    #[test]
    fn a_recovered_by_id_path_is_validated_like_a_parsed_one() {
        validate_by_id_path("/dev/disk/by-id/ata-WDC_WD20EZAZ_WD-ABC123").unwrap();
        validate_by_id_path("/dev/disk/by-id/nvme-Samsung_SSD_980_S5P2").unwrap();

        for bad in [
            "/dev/sda",
            "/dev/disk/by-id/",
            "/dev/disk/by-id/ata-X$(touch /tmp/p)",
            "/dev/disk/by-id/ata-X;id",
            "/dev/disk/by-id/ata-X`id`",
            "/dev/disk/by-id/ata-X id",
            "/dev/disk/by-id/ata-X\nid",
            "/dev/disk/by-id/wwn-0x5000",
            "/dev/disk/by-id/ata-X-part1",
            "relative/ata-X",
        ] {
            assert!(validate_by_id_path(bad).is_err(), "accepted {bad:?}");
        }
    }

    /// The children of a recovered device reach the same two sinks -- the
    /// generated `fileSystems.<mount>.device` string and the `ssh` command
    /// that verifies the mount -- and until now nothing validated them.
    #[test]
    fn a_recovered_partition_by_id_path_is_validated_too() {
        validate_partition_by_id_path("/dev/disk/by-id/ata-WDC_WD20EZAZ_WD-ABC123-part1").unwrap();
        validate_partition_by_id_path("/dev/disk/by-id/nvme-Samsung_980_S5P2-part3").unwrap();

        for bad in [
            "/dev/sda1",
            "/dev/disk/by-id/",
            "/dev/disk/by-id/ata-X-part1$(touch /tmp/p)",
            "/dev/disk/by-id/ata-X-part1;id",
            "/dev/disk/by-id/ata-X-part1`id`",
            "/dev/disk/by-id/ata-X-part1 id",
            "/dev/disk/by-id/ata-X-part1\nid",
            "/dev/disk/by-id/wwn-0x5000-part1",
            // A WHOLE-DISK alias is wrong here for the same reason a
            // partition alias is wrong in the function above: mounting the
            // disk fails with "wrong fs type, bad superblock".
            "/dev/disk/by-id/ata-X",
            "relative/ata-X-part1",
        ] {
            assert!(
                validate_partition_by_id_path(bad).is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn unique_serials_are_accepted() {
        check_serials_identify(&parse_lsblk(LSBLK).unwrap()).unwrap();
    }

    /// A floppy, an empty optical drive or a card reader reports no
    /// serial. Refusing the whole machine over one was found by the first
    /// real CI run of the stage-2 test, on a QEMU guest whose `fd0` has
    /// none -- it made the installer unusable on ordinary hardware.
    #[test]
    fn a_device_with_no_serial_is_unselectable_not_disqualifying() {
        let devs = vec![disk("fd0", None, vec![]), disk("sda", Some("A1"), vec![])];
        check_serials_identify(&devs).unwrap();
        // ...and it still cannot be chosen, because nothing can name it.
        assert!(devs.iter().filter(|d| d.serial.is_none()).count() == 1);
    }

    /// But a machine where NOTHING can be named is a real refusal: there
    /// is no value the operator could type.
    #[test]
    fn a_machine_with_no_serials_at_all_is_refused() {
        let devs = vec![disk("fd0", None, vec![]), disk("vda", None, vec![])];
        let err = check_serials_identify(&devs).unwrap_err().to_string();
        assert!(err.contains("nothing you could confirm"), "{err}");
        // This used to assert the message contained "by-id", on the
        // grounds that "the fix should be in the message" -- so the test
        // was holding an IMPOSSIBLE instruction in place. There is no flag
        // that takes a by-id path; see
        // `the_no_serial_refusal_does_not_promise_a_flag_that_does_not_exist`.
        assert!(
            err.contains("virtio"),
            "the real cause should be named: {err}"
        );
    }

    /// Same-batch drives and USB bridges reporting the enclosure's serial.
    #[test]
    fn duplicate_serials_are_refused_naming_both_devices() {
        let devs = vec![
            disk("sda", Some("SAME"), vec![]),
            disk("sdb", Some("SAME"), vec![]),
            disk("sdc", Some("OTHER"), vec![]),
        ];
        let err = check_serials_identify(&devs).unwrap_err().to_string();
        assert!(err.contains("sda") && err.contains("sdb"), "{err}");
        assert!(
            !err.contains("sdc"),
            "should not implicate the unique one: {err}"
        );
    }

    // --- the firmware truth table, every row ---

    #[test]
    fn efi_firmware_and_a_blank_disk_is_uefi() {
        assert_eq!(
            infer_firmware(true, &disk("sda", Some("A"), vec![])).unwrap(),
            Firmware::Uefi
        );
    }

    #[test]
    fn efi_firmware_corroborated_by_an_esp_is_uefi() {
        let d = disk(
            "sda",
            Some("A"),
            vec![fs("sda1", Some("vfat")), fs("sda2", Some("ext4"))],
        );
        assert_eq!(infer_firmware(true, &d).unwrap(), Firmware::Uefi);
    }

    /// The row that refuses rather than guessing: reinstalling a BIOS-era
    /// box from a UEFI live environment is a real, common case.
    #[test]
    fn efi_firmware_on_a_used_disk_with_no_esp_refuses() {
        let d = disk("sda", Some("A"), vec![fs("sda1", Some("ext4"))]);
        let err = infer_firmware(true, &d).unwrap_err().to_string();
        assert!(err.contains("conflicting signals"), "{err}");
        assert!(err.contains("legacy-BIOS"), "{err}");
    }

    #[test]
    fn no_efi_and_no_esp_is_bios() {
        let blank = disk("sda", Some("A"), vec![]);
        let used = disk("sda", Some("A"), vec![fs("sda1", Some("ext4"))]);
        assert_eq!(infer_firmware(false, &blank).unwrap(), Firmware::Bios);
        assert_eq!(infer_firmware(false, &used).unwrap(), Firmware::Bios);
    }

    #[test]
    fn no_efi_but_an_esp_present_refuses() {
        let d = disk("sda", Some("A"), vec![fs("sda1", Some("vfat"))]);
        let err = infer_firmware(false, &d).unwrap_err().to_string();
        assert!(err.contains("conflicting signals"), "{err}");
    }

    #[test]
    fn the_render_shows_every_disk_with_what_identifies_it() {
        let mut d = parse_lsblk(LSBLK).unwrap();
        attach_by_id(&mut d, &parse_by_id(BY_ID));
        let out = render(&d);
        // The disk to keep is as important as the disk to destroy.
        assert!(out.contains("sda") && out.contains("sdb"), "{out}");
        assert!(out.contains("WD-ABC123"), "serial must be shown: {out}");
        assert!(out.contains("/dev/disk/by-id/ata-WDC"), "{out}");
        assert!(
            out.contains("mounted at /"),
            "mounts identify a drive: {out}"
        );
        assert!(out.contains("empty -- no partitions"), "{out}");
    }

    #[test]
    fn the_render_is_explicit_about_missing_identifiers() {
        let d = vec![Device {
            name: "vda".into(),
            size: "20G".into(),
            model: None,
            serial: None,
            by_id: None,
            children: vec![],
        }];
        let out = render(&d);
        assert!(out.contains("cannot be selected"), "{out}");
        assert!(out.contains("(no stable /dev/disk/by-id path)"), "{out}");
    }

    /// The defect this rule exists to prevent, stated as a test: the old
    /// "no vfat anywhere therefore BIOS" heuristic would have returned BIOS
    /// for an EFI machine with a blank disk, producing a host that installs
    /// and then boots to nothing.
    #[test]
    fn a_blank_disk_on_an_efi_machine_is_never_bios() {
        let d = disk("nvme0n1", Some("S5P2"), vec![]);
        assert!(!d.has_vfat(), "a blank disk has no ESP by definition");
        assert_eq!(
            infer_firmware(true, &d).unwrap(),
            Firmware::Uefi,
            "the absent ESP must not outvote the firmware"
        );
    }
}
