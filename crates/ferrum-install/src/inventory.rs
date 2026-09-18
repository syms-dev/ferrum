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
    if name.is_empty() || name.chars().any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))) {
        anyhow::bail!(
            "the target reported a block device named {name:?}, which is not a \
             kernel device name. Refusing: this name is used to match the \
             device against its /dev/disk/by-id alias, so accepting a forged \
             one risks resolving to a different disk than the table shows."
        );
    }
    Ok(())
}

fn clean_required(v: String) -> String {
    let c = strip_controls(&v);
    if c.is_empty() { "?".to_string() } else { c }
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
    Ok(root
        .blockdevices
        .into_iter()
        .filter(|d| d.dev_type.as_deref() == Some("disk"))
        .map(|d| -> anyhow::Result<Device> {
            check_device_name(&d.name)?;
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
                })
                .collect(),
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?)
}

// ---------------------------------------------------------------------
// /dev/disk/by-id
// ---------------------------------------------------------------------

/// True for a `by-id` entry this installer will never name in `disko.nix`.
///
/// `-partN` aliases point at a partition rather than the whole disk, and
/// `wwn-` aliases carry no model or serial, so an operator reading one off
/// the screen cannot tell which physical drive it is. `nvme-eui.` is the
/// same problem in NVMe's spelling.
fn is_unusable_alias(alias: &str) -> bool {
    // An allowlist first. udev builds these from model and serial strings,
    // and on a resume the stored value is deserialized from a file in the
    // operator's writable bind mount -- so a shell metacharacter here is
    // not impossible, only unusual, and it would reach a remote root shell.
    if !alias
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-:".contains(c))
    {
        return true;
    }
    alias.contains("-part")
        || alias.starts_with("wwn-")
        || alias.starts_with("nvme-eui.")
        || alias.starts_with("lvm-")
        || alias.starts_with("dm-")
        || alias.starts_with("md-")
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

/// Parses `ls -l /dev/disk/by-id/` into alias -> kernel name.
///
/// Reads the symlink target's basename rather than trusting the alias's own
/// spelling, which is what makes this correct across the `../../sda` and
/// `../../nvme0n1` forms alike.
pub fn parse_by_id(listing: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in listing.lines() {
        let Some((alias_part, target)) = line.split_once(" -> ") else {
            continue;
        };
        let Some(alias) = alias_part.split_whitespace().next_back() else {
            continue;
        };
        if is_unusable_alias(alias) {
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
pub fn attach_by_id(devices: &mut [Device], by_id: &BTreeMap<String, String>) {
    for dev in devices.iter_mut() {
        dev.by_id = by_id
            .get(&dev.name)
            .map(|alias| format!("/dev/disk/by-id/{alias}"));
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
             you could confirm by typing one. Re-run naming the full \
             /dev/disk/by-id/ path instead."
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
    for d in devices {
        out.push_str(&format!(
            "  {:<10} {:>8}  {}\n",
            d.name,
            d.size,
            d.model.as_deref().unwrap_or("(no model reported)")
        ));
        out.push_str(&format!(
            "  {:<10} {:>8}  serial: {}\n",
            "", "",
            d.serial
                .as_deref()
                .unwrap_or("(none reported -- cannot be selected)")
        ));
        out.push_str(&format!(
            "  {:<10} {:>8}  {}\n",
            "", "",
            d.by_id.as_deref().unwrap_or("(no stable /dev/disk/by-id path)")
        ));
        if d.children.is_empty() {
            out.push_str(&format!("  {:<10} {:>8}  empty -- no partitions\n", "", ""));
        } else {
            for c in &d.children {
                out.push_str(&format!(
                    "  {:<10} {:>8}    {} {}{}\n",
                    "", "",
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
    out
}

#[cfg(test)]
mod tests {
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
            assert!(err.to_string().contains("kernel device name"), "{err}");
        }
        // Real names still parse.
        for good in ["sda", "nvme0n1", "vdb", "mmcblk0", "dm-0"] {
            let json = format!(
                r#"{{"blockdevices":[{{"name":"{good}","type":"disk","size":"1T"}}]}}"#
            );
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
        let bidi = "\u{202e}321AIDEM";           // renders as MEDIA123 reversed
        let others = [
            "\u{200e}x", "\u{200f}x", "\u{2066}x", "\u{2067}x", "\u{2068}x",
            "\u{2069}x", "\u{00ad}x", "\u{200b}x", "\u{feff}x",
        ];
        for payload in std::iter::once(bidi).chain(others) {
            let got = super::clean(Some(payload.to_string())).unwrap_or_default();
            for c in got.chars() {
                assert!(
                    c.is_ascii_graphic() || c == ' ',
                    "{payload:?} left {c:?} ({:#x}) in the table", c as u32
                );
            }
        }

        // And the flood: no control characters, no bidi, works on every
        // terminal. One field scrolled the real rows off screen and left
        // attacker-composed text directly above the "type the SERIAL"
        // prompt.
        let flood = "A".repeat(200_000);
        let capped = super::clean(Some(flood)).unwrap();
        assert!(capped.chars().count() <= super::MAX_FIELD, "{}", capped.chars().count());
        assert!(capped.ends_with("..."), "truncation must be visible: {capped:?}");

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
        assert_eq!(got, "EVIL[2Ksda  8T  My Media Disk");

        // A serial that would otherwise redraw itself as a decoy.
        let decoy = super::clean(Some("S\u{1b}[2K\rDECOY".into())).unwrap();
        assert!(!decoy.chars().any(|c| c.is_control()), "{decoy:?}");

        // Ordinary values are untouched, and absent ones stay absent.
        assert_eq!(super::clean(Some("  WD-WCC4N5PJ  ".into())), Some("WD-WCC4N5PJ".into()));
        assert_eq!(super::clean(Some("   ".into())), None);
        // Stripping the ESC leaves the literal text "[2K", which is inert --
        // it cannot move a cursor or erase a line. A value that is ONLY
        // control bytes does become None.
        assert_eq!(super::clean(Some("\u{1b}[2K".into())), Some("[2K".into()));
        assert_eq!(super::clean(Some("\u{1b}\r\u{7}".into())), None, "control-only is not a value");
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

    #[test]
    fn drops_partition_and_opaque_aliases() {
        let m = parse_by_id(BY_ID);
        assert_eq!(m.get("sda").map(String::as_str), Some("ata-WDC_WD20EZAZ_WD-ABC123"));
        assert_eq!(m.get("sdb").map(String::as_str), Some("ata-ST4000VN_ZDH9"));
        // wwn- lost to the ata- alias; -part1 never considered at all.
        assert!(!m.values().any(|v| v.contains("-part")));
        assert!(!m.values().any(|v| v.starts_with("wwn-")));
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
        let devs = vec![
            disk("fd0", None, vec![]),
            disk("sda", Some("A1"), vec![]),
        ];
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
        assert!(err.contains("by-id"), "the fix should be in the message: {err}");
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
        assert!(!err.contains("sdc"), "should not implicate the unique one: {err}");
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
        let d = disk("sda", Some("A"), vec![fs("sda1", Some("vfat")), fs("sda2", Some("ext4"))]);
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
        assert!(out.contains("mounted at /"), "mounts identify a drive: {out}");
        assert!(out.contains("empty -- no partitions"), "{out}");
    }

    #[test]
    fn the_render_is_explicit_about_missing_identifiers() {
        let d = vec![Device {
            name: "vda".into(), size: "20G".into(), model: None,
            serial: None, by_id: None, children: vec![],
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
