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

/// `lsblk` renders absent values as JSON null and, on some versions, as an
/// empty string. Both mean "unknown", and treating `""` as a real value is
/// exactly how an empty serial becomes an identifier (R2 A8).
fn clean(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
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
        .map(|d| Device {
            name: d.name,
            size: clean(d.size).unwrap_or_else(|| "?".to_string()),
            model: clean(d.model),
            serial: clean(d.serial),
            by_id: None,
            children: d
                .children
                .into_iter()
                .map(|c| Filesystem {
                    name: c.name,
                    fstype: clean(c.fstype),
                    mountpoint: clean(c.mountpoint),
                })
                .collect(),
        })
        .collect())
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
    let missing: Vec<&str> = devices
        .iter()
        .filter(|d| d.serial.is_none())
        .map(|d| d.name.as_str())
        .collect();
    if !missing.is_empty() {
        anyhow::bail!(
            "these devices report no serial: {}. A serial is what you type to \
             confirm the disk to destroy, so it must identify exactly one \
             device -- re-run naming the full /dev/disk/by-id/ path instead",
            missing.join(", ")
        );
    }

    let mut seen: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for d in devices {
        if let Some(s) = d.serial.as_deref() {
            seen.entry(s).or_default().push(&d.name);
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
            d.serial.as_deref().unwrap_or("(none reported)")
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

    #[test]
    fn a_missing_serial_is_refused_by_name() {
        let devs = vec![disk("sda", Some("A1"), vec![]), disk("vda", None, vec![])];
        let err = check_serials_identify(&devs).unwrap_err().to_string();
        assert!(err.contains("vda"), "{err}");
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
        assert!(out.contains("(none reported)"), "{out}");
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
