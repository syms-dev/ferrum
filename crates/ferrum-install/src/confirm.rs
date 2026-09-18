//! The gate between an inventory and an irreversibly repartitioned disk.
//!
//! disko repartitions unconditionally: no merge, no preserve step, no
//! confirmation of its own. Every byte on the disk named in the generated
//! `disko.nix` is gone the moment the install runs.
//!
//! Two protections, and the weaker one is the one people notice. The
//! **structural** protection is that a disk which is not named in
//! `disko.nix` is never opened, partitioned or mounted -- so the generated
//! file declares exactly one device and the data disks are mounted later
//! from `custom/media.nix`, where a mistake costs a failed mount instead of
//! a wiped drive. The **procedural** protection is this module: the
//! operator types the serial of the disk they are destroying.
//!
//! Typing a serial is a real gate but a narrow one. It defeats a reflex
//! "y", and it proves the operator read the line they are typing from. It
//! cannot prove they read the *right* line, which is why the proposal is
//! never a default and why a typo is a refusal rather than a different
//! disk.
//!
//! **Two checks, at two different moments.** `verify_still` here runs
//! before `nixos-anywhere` is invoked, and catches a device that changed
//! while the operator was reading the inventory and typing -- minutes of
//! human time, and a real window in which a USB disk can be unplugged.
//!
//! The *post-kexec* check R2 A9 asks for lives somewhere else, because
//! `nixos-anywhere` performs kexec, disko, install and reboot as one
//! external process with no hook back into this code. disko's own
//! `preCreateHook` is the seam: `render::precreate_serial_guard` generates
//! the check INTO the host's `disko.nix`, so it runs inside the kexec'd
//! installer immediately before that disk is partitioned -- the one moment
//! a different driver set could legitimately re-enumerate devices and point
//! the approved `by-id` alias at a different physical disk. It fails closed,
//! and the serial it embeds is escaped for both the shell it runs in and
//! the Nix string it is spliced into.

use crate::inventory::{self, Device, Firmware};
use crate::prompt::PromptIo;

/// A disk the operator has explicitly approved for destruction.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Approved {
    pub device: Device,
    pub firmware: Firmware,
    /// Every device seen at approval time, so the post-install check can
    /// assert the data disks it was told to keep are still there and
    /// mounted (spec R6 A4).
    pub all_devices: Vec<Device>,
}

/// Suggests which disk is probably the OS disk, for the operator to check.
///
/// This is a **suggestion shown on screen**, never a default the operator
/// can accept by pressing enter. The disk currently carrying `/` is the one
/// being replaced, so it is the honest suggestion; when nothing is mounted
/// at `/` -- a target booted from rescue media, which is common -- there is
/// no suggestion at all rather than a guess.
pub fn propose(devices: &[Device]) -> Option<&Device> {
    devices
        .iter()
        .find(|d| d.mounted_at().contains(&"/"))
}

/// Finds the single device whose serial the operator typed.
///
/// # Errors
/// A serial matching no device, or more than one, is a **refusal**. It is
/// never resolved to "the closest" or "the first": the whole value of
/// typing a serial is that a mistyped one cannot select a disk.
pub fn match_serial<'a>(devices: &'a [Device], typed: &str) -> anyhow::Result<&'a Device> {
    let typed = typed.trim();
    if typed.is_empty() {
        anyhow::bail!("no serial typed -- nothing has been changed");
    }
    let hits: Vec<&Device> = devices
        .iter()
        .filter(|d| d.serial.as_deref() == Some(typed))
        .collect();
    match hits.len() {
        1 => Ok(hits[0]),
        0 => anyhow::bail!(
            "no disk on this machine reports serial {typed:?}. Nothing has been \
             changed. Check the serial against the list above -- it must match \
             exactly, including case and any dashes."
        ),
        n => anyhow::bail!(
            "{n} disks report serial {typed:?}, so it does not identify one. \
             Nothing has been changed."
        ),
    }
}

/// Runs the confirmation.
///
/// # Errors
/// Any refusal above, a device with no stable `by-id` path, or a firmware
/// conflict for the chosen disk.
pub fn confirm(
    devices: &[Device],
    efi_present: bool,
    io: &mut impl PromptIo,
) -> anyhow::Result<Approved> {
    match propose(devices) {
        Some(p) => io.say(&format!(
            "\n{} is currently mounted at / -- on a machine being reinstalled \
             that is usually the OS disk.\nCheck it against the list above \
             before you decide; it is a suggestion, not a default.",
            p.name
        )),
        None => io.say(
            "\nNo disk on this machine is mounted at /, so there is nothing to \
             suggest.\nThis is normal when the target is booted from rescue or \
             live media.",
        ),
    }

    io.say(
        "\nThe disk you name will be COMPLETELY ERASED. Every other disk is \
         left untouched\nand is not even named in the generated \
         configuration.",
    );

    let typed = io.ask("Type the SERIAL of the disk to erase (or press enter to abort):")?;
    let device = match_serial(devices, &typed)?;

    // A device with no stable alias cannot be named safely in disko.nix:
    // /dev/sdX is not stable across boots, and this file is re-evaluated on
    // every later apply.
    if device.by_id.is_none() {
        anyhow::bail!(
            "{} has no /dev/disk/by-id/ path, so it cannot be named stably in \
             disko.nix. Kernel names like /dev/{} are not stable across boots \
             and this file is re-read on every later apply. Nothing has been \
             changed.",
            device.name,
            device.name
        );
    }

    let firmware = inventory::infer_firmware(efi_present, device)?;

    let mounts = device.mounted_at();
    if !mounts.is_empty() {
        io.say(&format!(
            "\nNote: {} currently has filesystems mounted at {}.",
            device.name,
            mounts.join(", ")
        ));
    }

    Ok(Approved {
        device: device.clone(),
        firmware,
        all_devices: devices.to_vec(),
    })
}

/// Re-checks that the approved `by-id` path still resolves to a device
/// bearing the approved serial.
///
/// **This runs before `nixos-anywhere` is invoked, not inside the kexec'd
/// installer.** See the module header: spec R2 A9 asks for the latter and
/// there is no hook to hang it on. What this catches is a device that
/// changed between the inventory being printed and the serial being typed
/// -- a real window, since that is minutes of human reading, but not the
/// post-kexec re-enumeration R2 A9 names.
///
/// # Errors
/// Any mismatch, which must abort before disko touches anything.
pub fn verify_still(approved: &Approved, current: &[Device]) -> anyhow::Result<()> {
    let expected_by_id = approved
        .device
        .by_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("approved device has no by-id path"))?;

    let found = current
        .iter()
        .find(|d| d.by_id.as_deref() == Some(expected_by_id))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "after kexec, {expected_by_id} no longer exists on the target. \
                 Refusing to partition anything."
            )
        })?;

    if found.serial != approved.device.serial {
        anyhow::bail!(
            "after kexec, {expected_by_id} reports serial {:?} but you approved \
             {:?}. Device enumeration changed. Refusing to partition anything.",
            found.serial.as_deref().unwrap_or("(none)"),
            approved.device.serial.as_deref().unwrap_or("(none)")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Filesystem;
    use crate::prompt::testing::Scripted;

    fn dev(name: &str, serial: Option<&str>, by_id: Option<&str>, mount: Option<&str>) -> Device {
        Device {
            name: name.into(),
            size: "1.8T".into(),
            model: Some("WDC".into()),
            serial: serial.map(str::to_string),
            by_id: by_id.map(str::to_string),
            children: mount
                .map(|m| {
                    vec![Filesystem {
                        name: format!("{name}1"),
                        fstype: Some("ext4".into()),
                        mountpoint: Some(m.into()),
                    }]
                })
                .unwrap_or_default(),
        }
    }

    fn two_disks() -> Vec<Device> {
        vec![
            dev("sda", Some("OS-123"), Some("/dev/disk/by-id/ata-OS_123"), Some("/")),
            dev("sdb", Some("DATA-9"), Some("/dev/disk/by-id/ata-DATA_9"), Some("/srv/media")),
        ]
    }

    #[test]
    fn the_disk_mounted_at_root_is_suggested() {
        assert_eq!(propose(&two_disks()).unwrap().name, "sda");
    }

    /// Rescue media is a normal way to reach this point, and guessing
    /// there would be worse than saying nothing.
    #[test]
    fn nothing_is_suggested_when_no_disk_holds_root() {
        let d = vec![dev("sda", Some("A"), Some("/x"), None)];
        assert!(propose(&d).is_none());
    }

    #[test]
    fn a_typed_serial_selects_exactly_that_disk() {
        let d = two_disks();
        assert_eq!(match_serial(&d, "DATA-9").unwrap().name, "sdb");
        assert_eq!(match_serial(&d, "  OS-123  ").unwrap().name, "sda");
    }

    /// THE property of this gate: a typo refuses. It never resolves to the
    /// nearest match, the first disk, or the suggestion.
    #[test]
    fn a_typo_is_a_refusal_not_a_different_disk() {
        let d = two_disks();
        for typo in ["OS-124", "os-123", "OS123", "OS-12", "DATA9", "x"] {
            let err = match_serial(&d, typo).unwrap_err().to_string();
            assert!(err.contains("no disk"), "typo {typo:?} gave: {err}");
            assert!(err.contains("Nothing has been changed"), "{err}");
        }
    }

    #[test]
    fn an_empty_answer_aborts() {
        let err = match_serial(&two_disks(), "   ").unwrap_err().to_string();
        assert!(err.contains("nothing has been changed"), "{err}");
    }

    #[test]
    fn an_ambiguous_serial_refuses_rather_than_picking_one() {
        let d = vec![
            dev("sda", Some("SAME"), Some("/a"), None),
            dev("sdb", Some("SAME"), Some("/b"), None),
        ];
        let err = match_serial(&d, "SAME").unwrap_err().to_string();
        assert!(err.contains("does not identify one"), "{err}");
    }

    #[test]
    fn a_full_confirmation_approves_the_named_disk() {
        let mut io = Scripted::new(&["DATA-9"]);
        let a = confirm(&two_disks(), false, &mut io).unwrap();
        assert_eq!(a.device.name, "sdb");
        assert_eq!(a.firmware, Firmware::Bios);
        assert_eq!(a.all_devices.len(), 2, "the whole inventory is recorded");
    }

    /// The suggestion must not be selectable by pressing enter.
    #[test]
    fn pressing_enter_does_not_accept_the_suggestion() {
        let mut io = Scripted::new(&[""]);
        let err = confirm(&two_disks(), false, &mut io).unwrap_err().to_string();
        assert!(err.contains("nothing has been changed"), "{err}");
    }

    #[test]
    fn the_operator_is_told_the_suggestion_is_not_a_default() {
        let mut io = Scripted::new(&["OS-123"]);
        confirm(&two_disks(), false, &mut io).unwrap();
        let t = io.transcript();
        assert!(t.contains("suggestion, not a default"), "{t}");
        assert!(t.contains("COMPLETELY ERASED"), "{t}");
        assert!(t.contains("not even named"), "the structural protection: {t}");
    }

    /// /dev/sdX is not stable across boots and disko.nix is re-read on
    /// every later apply, so a device with no alias is refused outright.
    #[test]
    fn a_device_with_no_by_id_path_is_refused() {
        let d = vec![dev("vda", Some("V1"), None, None)];
        let mut io = Scripted::new(&["V1"]);
        let err = confirm(&d, false, &mut io).unwrap_err().to_string();
        assert!(err.contains("no /dev/disk/by-id/"), "{err}");
        assert!(err.contains("not stable across boots"), "{err}");
    }

    /// A firmware conflict must stop the run here, not be discovered after
    /// the disk is gone.
    #[test]
    fn a_firmware_conflict_refuses_at_the_gate() {
        let d = vec![dev("sda", Some("A"), Some("/x"), Some("/"))];
        let mut io = Scripted::new(&["A"]);
        let err = confirm(&d, true, &mut io).unwrap_err().to_string();
        assert!(err.contains("conflicting signals"), "{err}");
    }

    // --- the post-kexec re-verification (R2 A9) ---

    #[test]
    fn re_verification_passes_when_nothing_moved() {
        let mut io = Scripted::new(&["OS-123"]);
        let a = confirm(&two_disks(), false, &mut io).unwrap();
        verify_still(&a, &two_disks()).unwrap();
    }

    /// The case this exists for: kexec's different driver set renumbers the
    /// devices, and the by-id path now points at the data disk.
    #[test]
    fn re_verification_catches_a_swapped_serial() {
        let mut io = Scripted::new(&["OS-123"]);
        let a = confirm(&two_disks(), false, &mut io).unwrap();

        let after = vec![dev(
            "sdb",
            Some("DATA-9"),
            Some("/dev/disk/by-id/ata-OS_123"),
            None,
        )];
        let err = verify_still(&a, &after).unwrap_err().to_string();
        assert!(err.contains("Refusing to partition"), "{err}");
        assert!(err.contains("DATA-9") && err.contains("OS-123"), "{err}");
    }

    #[test]
    fn re_verification_catches_a_disappeared_device() {
        let mut io = Scripted::new(&["OS-123"]);
        let a = confirm(&two_disks(), false, &mut io).unwrap();
        let err = verify_still(&a, &[dev("sdb", Some("DATA-9"), Some("/other"), None)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no longer exists"), "{err}");
        assert!(err.contains("Refusing to partition"), "{err}");
    }

    /// The approved inventory is what the post-install check reads to
    /// assert the data disks it was told to keep are still mounted.
    #[test]
    fn the_approved_record_serialises_with_the_whole_inventory() {
        let mut io = Scripted::new(&["OS-123"]);
        let a = confirm(&two_disks(), false, &mut io).unwrap();
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("OS-123") && json.contains("DATA-9"), "{json}");
        assert!(json.contains("/srv/media"), "kept disks must be recorded: {json}");
    }
}
