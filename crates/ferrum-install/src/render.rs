//! Generating the operator's host repository.
//!
//! This is the file set `docs/INSTALL.md` asks a new user to hand-edit:
//! twelve `CHANGE-ME` values across three files plus a `settings.json`
//! whose placeholders are spelled `example.invalid` instead. None of it is
//! Nix anyone should have to write, and all of it is derivable from the
//! inventory and a handful of answers.
//!
//! Two things here are load-bearing rather than cosmetic:
//!
//! * The btrfs subvolume layout is reproduced **verbatim** from
//!   `examples/hosts/template/disko.nix`. `@state` is hardcoded in
//!   `crates/ferrum-apply/src/restore_state.rs` and
//!   `modules/core/state-restore.nix` asserts `@snapshots` shares its
//!   volume. A generated layout that drifts produces a host which installs,
//!   boots, looks perfectly healthy, and **silently cannot roll back** --
//!   the one property ferrum exists to provide. The template is
//!   `include_str!`d below so that drift is a failing test, not a comment
//!   nobody reads.
//! * Exactly one device is named in `disko.nix`. Every other disk is
//!   mounted from `custom/media.nix`, where a mistake costs a failed mount
//!   instead of a wiped drive.

use std::collections::BTreeMap;
use std::path::Path;

use crate::answers::{Answers, DnsDecision, RecordTarget};
use crate::confirm::Approved;
use crate::dns::Adoption;
use crate::inventory::{Device, Firmware};

/// The real template, linked at compile time purely so the test below can
/// prove the generated subvolume layout still matches it.
#[cfg(test)]
const TEMPLATE_DISKO: &str = include_str!("../../../examples/hosts/template/disko.nix");

/// The btrfs subvolumes, byte-identical to the template's.
///
/// Do not reformat. The test `the_subvolume_layout_matches_the_template`
/// compares this text against `examples/hosts/template/disko.nix`.
const SUBVOLUMES: &str = r#"            subvolumes = {
              "@root" = {
                mountpoint = "/";
                mountOptions = [ "compress=zstd" "noatime" ];
              };
              "@nix" = {
                mountpoint = "/nix";
                mountOptions = [ "compress=zstd" "noatime" ];
              };
              "@state" = {
                mountpoint = "/var/lib/ferrum/state";
                mountOptions = [ "compress=zstd" "noatime" ];
              };
              "@snapshots" = {
                mountpoint = "/var/lib/ferrum/snapshots";
                mountOptions = [ "noatime" ];
              };
            };"#;

/// Placeholder sentinels that must not survive into a generated file.
///
/// All four, not just `CHANGE-ME`: `settings.json`'s placeholders are
/// `example.invalid`, so asserting one sentinel would be structurally blind
/// to the file most likely to reach ACME with an unresolvable domain.
///
/// The last one is `AAAA...` **with the ellipsis**, which is how the
/// template spells it (`"ssh-ed25519 AAAA...CHANGE-ME"`). A bare `AAAA`
/// would reject every real key on earth: an ed25519 public key always
/// begins `AAAAC3NzaC1lZDI1NTE5AAAA`. Caught by
/// `a_real_ed25519_key_is_not_mistaken_for_a_placeholder`.
pub const PLACEHOLDERS: &[&str] = &["CHANGE-ME", "example.invalid", "YOUR-USER", "AAAA..."];

/// The marker identifying a `hardware-configuration.nix` that is still the
/// stand-in this installer wrote, not the real one `nixos-anywhere
/// --generate-hardware-config` reads off the target.
///
/// The stand-in exists so Tier 1 can evaluate the configuration before
/// anything is destroyed (the flake imports the file unconditionally). But
/// `{ ... }: { }` is a perfectly valid empty module, so if it ever survives
/// onto the installed host the machine evaluates and boots with NO
/// `availableKernelModules`, no microcode and no host hardware settings --
/// and reports success. An existence check cannot catch that, because this
/// file now always exists. Only a CONTENT check can.
pub const HARDWARE_CONFIG_SENTINEL: &str = "# PLACEHOLDER";

/// The generated repository's `.gitignore`.
///
/// A constant rather than a literal inside `render`, because `write_repo`
/// now guarantees it independently: `read_generated` reads only four
/// files, so a resume against a host directory generated before this
/// existed would otherwise run `git add -A` with no ignore file and commit
/// the operator's own files right back into the history that ships to the
/// host.
pub const GITIGNORE: &str = "# This installer's own working files. They are the OPERATOR's, not\n\
         # the host's: install-state.json tracks this run's progress,\n\
         # install-inventory.json holds every disk on the machine, and\n\
         # known_hosts records which hosts you manage and their\n\
         # fingerprints. install.rs excludes them from the copy; this stops\n\
         # `git add -A` committing them, because .git itself ships to the\n\
         # host and its history would carry them past that exclusion.\n\
         install-state.json\n\
         install-state.json.tmp\n\
         install-inventory.json\n\
         install-inventory.json.tmp\n\
         known_hosts\n";

/// The disko revision generated hosts pin.
///
/// disko's module is what partitions and formats the target, as root,
/// inside nixos-anywhere. Left as a bare `github:nix-community/disko` it
/// resolved to whatever upstream HEAD happened to be at install time --
/// an unpinned root-code-execution input on the destructive path, and a
/// failing R3 A5, which requires a revision. `ferrum.url` two lines above
/// it was already pinned with the comment "it should never move on its
/// own"; the same argument applies with more force here, because this
/// input runs before there is a system to roll back to.
///
/// Kept equal to this repository's own `flake.lock` by
/// `the_generated_disko_pin_matches_this_repos_lockfile`, so the host is
/// partitioned by the same disko ferrum is tested against.
pub const DISKO_REV: &str = "ff8702b4de27f72b4c78573dfb89ec74e36abdf1";

/// Writes the stand-in `hardware-configuration.nix` into `files`.
///
/// Its body begins with [`HARDWARE_CONFIG_SENTINEL`], which is what the
/// transfer step and post-install verification check for. Deliberately NOT
/// listed in [`PLACEHOLDERS`]: `check_no_placeholders` runs over this
/// function's own output, so listing it there would make `render` reject
/// itself.
///
/// # Arguments
/// * `files` - the generated file set to insert into.
pub fn insert_hardware_config_placeholder(files: &mut Files) {
    files.insert(
        "hardware-configuration.nix".into(),
        "# PLACEHOLDER -- replaced during the install by\n\
         # `nixos-anywhere --generate-hardware-config`, which writes the real\n\
         # hardware configuration read off the target itself.\n\
         #\n\
         # It exists so the preflight can evaluate this configuration before\n\
         # anything is destroyed. disko supplies every fileSystems entry for\n\
         # the OS disk, so an empty module evaluates cleanly here.\n\
         { ... }: { }\n"
            .into(),
    );
}

/// Escapes a value for use inside a Nix `"..."` string literal.
///
/// Device-derived strings -- `by_id`, `model`, `size`, `fstype` -- come
/// from `lsblk` on a machine this installer does not control, and on a
/// resume from a deserialized file in the operator's writable bind mount.
/// They are written into Nix source that is then evaluated and built as
/// root. A `"` ends the literal and `${` starts an antiquotation that Nix
/// will happily evaluate, so neither can be passed through raw.
fn nix_str(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace("${", "\\${")
        .replace('\n', "\\n")
        // \r matters even though it cannot terminate a Nix string: left
        // raw, Nix turns it INTO a newline, so a value that contained no
        // newline acquires one after evaluation. Anything downstream that
        // assumes "newline-free in, newline-free out" is then wrong.
        .replace('\r', "\\r")
}

/// A generated repository: relative path -> file contents.
pub type Files = BTreeMap<String, String>;

/// Data disks are *detected*, never asked for: every disk that is not the
/// one being erased and that already carries a filesystem.
pub fn data_disks<'a>(all: &'a [Device], target: &Device) -> Vec<&'a Device> {
    all.iter()
        .filter(|d| d.name != target.name)
        .filter(|d| d.by_id.is_some())
        .filter(|d| d.children.iter().any(|c| c.fstype.is_some()))
        .collect()
}

/// The R2 A9 re-verification, as a disko `preCreateHook`.
///
/// This is the check the spec always asked for and the installer could not
/// previously make: `disko` runs it **inside the kexec'd installer,
/// immediately before this disk is partitioned** -- the one moment a
/// different kernel's driver set could have re-enumerated devices and
/// pointed the approved `by-id` alias at a different physical disk.
///
/// It lives in the generated configuration rather than in the installer
/// because `nixos-anywhere` performs kexec, disko, install and reboot as
/// one external process with no hook back into this code. disko's own hook
/// is the seam.
///
/// Fails closed: an unreadable serial is a mismatch, not a pass.
///
/// **Two escaping layers, and both are required.** The values are first
/// made safe for the *shell* that runs inside the hook, then the whole
/// rendered script is made safe for the *Nix string* it is spliced into.
/// Getting only the first was a real injection: `shell_single_quote`
/// emits `'\''` for an apostrophe, and `''` is Nix's indented-string
/// terminator -- so a serial containing an apostrophe (plausible on real
/// hardware, not merely adversarial) broke the parse, and a crafted one
/// escaped the string into Nix that `nix build` then evaluates and
/// `nixos-anywhere` builds as root. Proven with `nix-instantiate`, not
/// inferred from the grammar.
///
/// The hook is emitted as a **double-quoted** Nix string precisely so that
/// `nix_str` -- which is already tested against `"`, `\`, `${` and
/// newlines -- can do the second layer, rather than inventing a second
/// escaper for indented strings.
fn precreate_serial_guard(os_disk: &str, serial: &str) -> String {
    // Each value is single-quoted ONCE, at a top-level assignment, and
    // referenced through a variable everywhere else.
    //
    // This shape is the fix for a real root-shell injection. Splicing the
    // quoted path directly into the messages -- `echo "  {disk}"` -- put a
    // `'...'` fragment inside DOUBLE quotes, where single quotes are inert,
    // so a `$(...)` in a by-id path executed as root inside the kexec'd
    // installer. Nix escaping does not help: `$(` is not antiquotation, so
    // it passes through the Nix layer verbatim and lands in the shell.
    //
    // The general rule, learned the expensive way: **shell-quoted is not
    // shell-safe -- what matters is the context the quoted text lands in.**
    // A `'...'` is inert inside `"..."`, inside a here-doc, inside `eval`,
    // and inside another `'...'`. Assigning once at top level is the only
    // placement where the quoting is actually doing anything.
    //
    // The by-id path is not hypothetical input: on a resume it comes from a
    // plain deserialize of install-inventory.json in the operator's
    // writable bind mount, which this codebase already documents as
    // untrusted in two other places.
    // The shared quoter. A second copy here would be the same
    // single-source-of-truth mistake `stage2.rs` already corrected -- and
    // in the one function that has needed three Critical fixes, a quoting
    // change that failed to propagate is exactly the likely next defect.
    let disk = crate::collect::sh_quote(os_disk);
    let want = crate::collect::sh_quote(serial);
    format!(
        r#"      # ferrum: R2 A9. Runs after kexec, immediately before this disk is
      # partitioned -- the one moment device enumeration can legitimately
      # change. An unreadable serial counts as a mismatch.
      ferrum_disk={disk}
      ferrum_want={want}
      ferrum_got="$(lsblk -no SERIAL "$ferrum_disk" 2>/dev/null | head -n1 | tr -d '[:space:]')"
      if [ "$ferrum_got" != "$ferrum_want" ]; then
        echo "ferrum: REFUSING TO PARTITION." >&2
        echo "  $ferrum_disk" >&2
        echo "  was approved with serial $ferrum_want" >&2
        echo "  but now reports '$ferrum_got'." >&2
        echo "  Device enumeration changed after kexec. Nothing has been written." >&2
        exit 1
      fi
"#
    )
}

fn disko(os_disk: &str, firmware: Firmware, serial: Option<&str>) -> anyhow::Result<String> {
    let boot_partition = match firmware {
        Firmware::Uefi => r#"        ESP = {
          priority = 1;
          name = "ESP";
          start = "1M";
          end = "1G";
          type = "EF00";
          content = {
            type = "filesystem";
            format = "vfat";
            mountpoint = "/boot";
            mountOptions = [ "umask=0077" ];
          };
        };"#
        .to_string(),
        Firmware::Bios => r#"        boot = {
          priority = 1;
          name = "bios-boot";
          size = "1M";
          type = "EF02";
        };"#
        .to_string(),
    };

    let os_disk_escaped = nix_str(os_disk);
    // REFUSE rather than render a disko file with no guard in it.
    //
    // This used to be `.unwrap_or_default()`, justified by a comment
    // claiming "R2 A8 refuses an inventory whose serials cannot identify a
    // disk, so in practice it always is". That refusal was REMOVED when a
    // serial-less device became unselectable rather than disqualifying
    // (a floppy drive was refusing whole machines), so the stated argument
    // became false while the code kept relying on it. The invariant does
    // still hold -- `confirm.rs` matches on `Some(typed)`, which no
    // serial-less device can satisfy -- but "the guard silently disappears
    // if that ever changes" is not a property worth keeping on the one
    // check standing between a typo and an erased disk.
    let sn = serial.ok_or_else(|| {
        anyhow::anyhow!(
            "refusing to generate a disko configuration for {os_disk} with no \
             serial: the preCreateHook that re-checks the disk's identity \
             after kexec cannot be written without one, and generating the \
             file without that guard would silently remove the last check \
             before the partition table is destroyed"
        )
    })?;
    let guard = format!(
        "\n    preCreateHook = \"{}\";\n",
        nix_str(&precreate_serial_guard(os_disk, sn))
    );
    Ok(format!(
        r#"# Generated by ferrum-install. The ONLY disk named here is the one you
# confirmed for erasure; disko never opens a device it is not told about,
# and that is the protection for every other disk in this machine. Data
# disks are mounted from custom/media.nix instead, where a mistake costs a
# failed mount rather than a wiped drive.
#
# Firmware was detected as {firmware:?} from the target itself.
{{
  disko.devices.disk.main = {{
    type = "disk";
    device = "{os_disk_escaped}";
{guard}
    content = {{
      type = "gpt";
      partitions = {{
{boot_partition}
        root = {{
          size = "100%";
          content = {{
            type = "btrfs";
            extraArgs = [ "-f" ];
{SUBVOLUMES}
          }};
        }};
      }};
    }};
  }};
}}
"#
    ))
}

fn flake(hostname: &str, ferrum_rev: &str, ssh_keys: &[String], firmware: Firmware) -> String {
    let disko_rev = DISKO_REV;
    // Escaped like every other value reaching generated Nix. On the
    // interactive path `validate_hostname` has already constrained this to
    // [a-z0-9-], but on a resume it is scraped back out of the operator's
    // own flake.nix -- so the validator is not the only way it can arrive.
    // Defence in depth: no privilege is gained by an attacker who can
    // already write the file being evaluated, but the escaping is a
    // one-liner and its absence here was the only gap left in render.rs.
    let hostname = &nix_str(hostname);
    let keys = ssh_keys
        .iter()
        .map(|k| format!("              \"{}\"", nix_str(k)))
        .collect::<Vec<_>>()
        .join("\n");

    let bootloader = match firmware {
        Firmware::Uefi => "            boot.loader.systemd-boot.enable = true;\n            boot.loader.efi.canTouchEfiVariables = true;".to_string(),
        // NOTE the absence of `devices`. disko sets
        // `boot.loader.grub.devices = [ config.device ]` itself whenever it
        // creates the EF02 bios-boot partition (its lib/types/gpt.nix), so
        // naming the same disk here puts it in the list twice and the host
        // fails to evaluate with "You cannot have duplicated devices in
        // mirroredBoots". Found by the stage-2 CI job; the host template's
        // own comment suggests doing it, and has the same defect.
        Firmware::Bios => "            boot.loader.grub = {\n              enable = true;\n              efiSupport = false;\n              # devices is set by disko from disko.nix's own `device`.\n            };".to_string(),
    };

    format!(
        r#"# Generated by ferrum-install. This is YOUR repository: ferrum will not
# rewrite it, and every later `ferrum-apply apply` evaluates it.
#
# Keep it a git repository with every file tracked. Nix silently ignores
# untracked files inside a git tree, so an untracked disko.nix fails with a
# message naming the wrong cause.
{{
  description = "ferrum host {hostname}";

  inputs = {{
    # Pinned to the exact revision the installer was built from, so this
    # host and the tool that built it provably agree. Changing this is how
    # you take an update -- it should never move on its own.
    ferrum.url = "github:syms-dev/ferrum/{ferrum_rev}";

    disko.url = "github:nix-community/disko/{disko_rev}";
    disko.inputs.nixpkgs.follows = "ferrum/nixpkgs";
  }};

  outputs = {{ self, ferrum, disko, ... }}: {{
    nixosConfigurations = {{
      {hostname} = ferrum.lib.mkHost {{
        system = "x86_64-linux";
        settings = builtins.fromJSON (builtins.readFile ./settings.json);
        revision = self.shortRev or self.dirtyShortRev or "dirty";

        modules = [
          disko.nixosModules.disko
          ./disko.nix
          ./hardware-configuration.nix
          ] ++ ferrum.lib.importDir ./custom ++ [

          ({{ ... }}: {{
            networking.hostName = "{hostname}";

            users.users.root.openssh.authorizedKeys.keys = [
{keys}
            ];

            services.openssh = {{
              enable = true;
              settings.PasswordAuthentication = false;
              settings.PermitRootLogin = "prohibit-password";
            }};

{bootloader}

            ferrum.daemon.enable = true;
          }})
        ];
      }};
    }};
  }};
}}
"#
    )
}

/// The one root downloads and media share, so imports can hardlink.
///
/// Must match `ferrum.storage.mediaDir`'s default in
/// modules/core/options.nix. They are two halves of one decision: this
/// side mounts the disks there, that side builds the TRaSH tree inside.
pub const MEDIA_ROOT: &str = "/data";

/// Where a pool branch is mounted when there is more than one data disk.
fn branch_path(i: usize) -> String {
    format!("/mnt/ferrum-disk-{i}")
}

fn media(disks: &[&Device]) -> anyhow::Result<String> {
    let single = disks.len() == 1;
    let mounts = disks
        .iter()
        .enumerate()
        .map(|(i, d)| -> anyhow::Result<String> {
            // THE PARTITION, not the disk.
            //
            // A data disk's filesystem lives on a partition, so mounting
            // the disk itself fails with "wrong fs type, bad option, bad
            // superblock". That is precisely what happened on the first
            // real install: both media disks named
            // /dev/disk/by-id/ata-ST8000DM004-..., the ext4 was on
            // ...-part1, and mnt-media-0.mount and mnt-media-1.mount both
            // failed. 7TB of media did not mount, and because the mounts
            // carry `nofail` the host booted cleanly and said nothing.
            //
            // Refusing rather than falling back to the disk path: a
            // generated config that cannot possibly mount is worse than a
            // generated config that is missing, because `nofail` hides it.
            let part = d
                .children
                .iter()
                .find(|c| c.fstype.is_some())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "data disk {} has no partition with a filesystem, so \
                         there is nothing to mount. Partition and format it \
                         first, or leave it out of this install.",
                        d.name
                    )
                })?;
            let by_id = part.by_id.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "partition {} on data disk {} has no stable \
                     /dev/disk/by-id path. Refusing to name it by kernel \
                     device instead: those are assigned in discovery order \
                     and can point at a different disk after a reboot.",
                    part.name,
                    d.name
                )
            })?;
            let fstype = nix_str(part.fstype.as_deref().unwrap_or("ext4"));
            // ONE disk mounts straight at /data; SEVERAL mount as pool
            // branches and modules/core/pool.nix unions them at /data.
            //
            // The mount point is never /mnt/media-N any more. That path
            // was disconnected from everything: ferrum.storage.mediaDir
            // was /srv/media, which is what the apps were pointed at, so
            // the data disks were mounted somewhere no app ever looked.
            let mount = if single {
                MEDIA_ROOT.to_string()
            } else {
                format!("/mnt/ferrum-disk-{i}")
            };
            Ok(format!(
                r#"  # {model}, {size} -- partition {part_name}
  fileSystems."{mount}" = {{
    device = "{by_id}";
    fsType = "{fstype}";
    # nofail is load-bearing: without it a disk that is unplugged, asleep
    # or slow to enumerate takes the whole boot into emergency mode. A
    # media server that boots with a smaller pool beats one that does not
    # boot at all.
    options = [ "defaults" "nofail" "x-systemd.device-timeout=30s" ];
  }};"#,
                model = nix_str(d.model.as_deref().unwrap_or("unknown model")),
                size = nix_str(&d.size),
                part_name = nix_str(&part.name),
                by_id = nix_str(by_id),
                mount = nix_str(&mount),
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?
        .join("\n\n");

    Ok(format!(
        r#"# Generated by ferrum-install, and yours to edit afterwards -- ferrum
# never rewrites anything under custom/.
#
# These disks are MOUNTED, never formatted. ferrum is not creating these
# filesystems, only mounting what the installer found already on them.
{{ ... }}:
{{
{mounts}
}}
"#
    ))
}

/// Renders R1 A2/A8's decision as `ferrum.proxy.dns`.
///
/// `enable` is written as `true` because that is the whole point of
/// collecting the answer: `modules/core/options.nix` defaults the option to
/// `false` only because no address can be guessed safely, and the installer
/// is what supplies the one thing that was missing. A host whose operator
/// answered these questions and still had to open a DNS console would have
/// gained nothing.
///
/// Only the fields the decision actually determines are written. The mode's
/// unused sibling (`cnameTarget` in A mode, `staticAddress` in CNAME mode)
/// and `ddnsUpdater.intervalMinutes` keep their module defaults, so an
/// operator changing their mind later edits one value rather than working
/// around this installer's opinion frozen into their settings.json.
///
/// # Arguments
/// * `decision` - what the operator chose at the prompt.
/// * `adoption` - R1 A3's outcome from the pre-erase gate. Only the adopted
///   names are written; a decline is a report line, not a setting, because
///   the absence of a name from this list already means "left alone".
///
/// # Returns
/// The `ferrum.proxy.dns` object.
fn dns_settings(decision: &DnsDecision, adoption: &Adoption) -> serde_json::Value {
    let mut dns = serde_json::Map::new();
    dns.insert("enable".into(), serde_json::json!(true));
    match &decision.target {
        RecordTarget::A(address) => {
            dns.insert("recordMode".into(), serde_json::json!("a"));
            dns.insert(
                "staticAddress".into(),
                serde_json::json!(address.to_string()),
            );
        }
        RecordTarget::Cname(hostname) => {
            dns.insert("recordMode".into(), serde_json::json!("cname"));
            dns.insert("cnameTarget".into(), serde_json::json!(hostname));
        }
    }
    // Written only when it is on. `answers::decide_dns` never offers the
    // updater in CNAME mode, so this cannot produce the combination
    // modules/proxy/dns.nix asserts against.
    if decision.ddns_updater {
        dns.insert("ddnsUpdater".into(), serde_json::json!({ "enable": true }));
    }
    // A3's opt-in half. Written only when the operator actually adopted
    // something, so a settings file carries no empty list to explain -- and
    // so an operator reading their own settings sees the names they typed
    // `adopt` for, and nothing else. This is the ONLY thing that turns the
    // gate's answer into a record ferrum will write; without it the operator
    // opts in and the host still leaves their record alone.
    let adopted = adoption.adopted_names();
    if !adopted.is_empty() {
        dns.insert("adoptedNames".into(), serde_json::json!(adopted));
    }
    serde_json::Value::Object(dns)
}

fn settings(
    answers: &Answers,
    stage: Stage,
    data_disks: usize,
    adoption: &Adoption,
) -> serde_json::Value {
    let mut root = serde_json::Map::new();
    root.insert("schemaVersion".into(), serde_json::json!(1));

    // More than one data disk means a pool, so the apps see one library
    // instead of one per disk. A single disk is mounted at mediaDir
    // directly and needs nothing here.
    //
    // Only the BRANCH LIST is written: policy and free-space floor keep
    // their module defaults, so an operator who wants to change them
    // changes one value rather than having the installer's opinion baked
    // into their settings.json forever.
    if data_disks > 1 {
        root.insert(
            "storage".into(),
            serde_json::json!({
                "pool": {
                    "enable": true,
                    "branches": (0..data_disks).map(branch_path).collect::<Vec<_>>(),
                }
            }),
        );
    }

    if let Some(domain) = &answers.base_domain {
        let mut proxy = serde_json::Map::new();
        proxy.insert("enable".into(), serde_json::json!(true));
        proxy.insert("baseDomain".into(), serde_json::json!(domain));
        if let Some(email) = &answers.acme_email {
            proxy.insert("acme".into(), serde_json::json!({ "email": email }));
        }
        // R1 A2/A8, and stage 2 only. modules/proxy/dns.nix asserts that
        // ferrum.proxy.dns.enable implies a declared credential, and stage 1
        // deliberately declares no secrets at all -- so writing this block
        // into stage 1 would make the first evaluation fail on an assertion
        // about a credential that cannot exist yet.
        if stage == Stage::Two {
            if let Some(decision) = &answers.dns {
                proxy.insert("dns".into(), dns_settings(decision, adoption));
            }
        }
        root.insert("proxy".into(), serde_json::Value::Object(proxy));
    }

    match stage {
        // Stage 1 carries NO apps and NO auth. Both declare sops secrets
        // whose files must exist at Nix evaluation time, and on a machine
        // being installed from nothing they cannot: they are generated on
        // the host, encrypted to a key the host does not have yet.
        Stage::One => {
            root.insert("apps".into(), serde_json::json!({}));
        }
        Stage::Two => {
            let apps: serde_json::Map<String, serde_json::Value> = answers
                .apps
                .iter()
                // Only `enable`. Writing any other value would freeze
                // today's default into this host forever.
                .map(|a| (a.clone(), serde_json::json!({ "enable": true })))
                .collect();
            root.insert("apps".into(), serde_json::Value::Object(apps));

            if answers.sso.enabled {
                if let Some(email) = &answers.sso.admin_email {
                    root.insert(
                        "auth".into(),
                        serde_json::json!({ "enable": true, "adminEmail": email }),
                    );
                }
            }

            // Declaring the name is required on its own: acme.nix checks
            // `ferrum.secrets ? acme-dns` as well as the .sops file's
            // existence, so a token delivered without this still fails.
            if answers.cloudflare_token.is_some() {
                root.insert(
                    "secrets".into(),
                    serde_json::json!({
                        "acme-dns": { "description": "Cloudflare DNS-01 API token" }
                    }),
                );
            }
        }
    }
    serde_json::Value::Object(root)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Stage {
    One,
    Two,
}

/// Renders the whole host repository for a run that adopted nothing.
///
/// **Test-only, deliberately.** R1-S11 made `main::generate` call
/// [`render_with_adoption`] directly, because this wrapper substitutes
/// [`Adoption::none`] -- so a production path routed through it produces a
/// host that ignores every name the operator typed `adopt` for. Keeping it
/// out of the non-test build is what stops that wire being undone by
/// someone reaching for the shorter signature; the tests below that do not
/// exercise adoption keep it for brevity.
///
/// # Arguments
/// * `answers` - the operator's answers.
/// * `approved` - the confirmed disk selection.
/// * `ssh_keys` - the operator's public keys.
/// * `ferrum_rev` - the revision this installer was built from.
///
/// # Errors
/// As [`render_with_adoption`].
#[cfg(test)]
pub fn render(
    answers: &Answers,
    approved: &Approved,
    ssh_keys: &[String],
    ferrum_rev: &str,
) -> anyhow::Result<Files> {
    render_with_adoption(answers, approved, ssh_keys, ferrum_rev, &Adoption::none())
}

/// Renders the whole host repository, carrying R1 A3's adoption decision
/// into `ferrum.proxy.dns.adoptedNames`.
///
/// # Arguments
/// * `answers` - the operator's answers.
/// * `approved` - the confirmed disk selection.
/// * `ssh_keys` - the operator's public keys.
/// * `ferrum_rev` - the revision this installer was built from.
/// * `adoption` - what `crate::dns::gate` recorded. An empty outcome is the
///   ordinary case: a host with no base domain, or a resume, which never
///   re-asks and therefore has nothing to carry.
///
/// # Errors
/// Returns an error if any generated file still contains a placeholder
/// sentinel -- asserted here rather than left to the operator.
pub fn render_with_adoption(
    answers: &Answers,
    approved: &Approved,
    ssh_keys: &[String],
    ferrum_rev: &str,
    adoption: &Adoption,
) -> anyhow::Result<Files> {
    let os_disk = approved
        .device
        .by_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("approved device has no by-id path"))?;

    let mut files = Files::new();
    files.insert(
        "disko.nix".into(),
        disko(
            os_disk,
            approved.firmware,
            approved.device.serial.as_deref(),
        )?,
    );
    files.insert(
        "flake.nix".into(),
        flake(&answers.hostname, ferrum_rev, ssh_keys, approved.firmware),
    );
    // Computed BEFORE the settings, which now depend on how many there
    // are: more than one means a pool.
    let disks = data_disks(&approved.all_devices, &approved.device);

    files.insert(
        "settings.json".into(),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&settings(answers, Stage::One, disks.len(), adoption))?
        ),
    );
    files.insert(
        "settings.stage2.json".into(),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&settings(answers, Stage::Two, disks.len(), adoption))?
        ),
    );

    if !disks.is_empty() {
        files.insert("custom/media.nix".into(), media(&disks)?);
    }

    // `custom/` must ALWAYS exist, even with nothing in it. The generated
    // flake calls `ferrum.lib.importDir ./custom` unconditionally, and
    // that does `builtins.readDir` -- so on a host with no data disks the
    // whole configuration failed to evaluate with "cannot read directory
    // .../custom". Found by the first stage-2 CI run that got far enough
    // to evaluate what it had generated.
    //
    // A placeholder file rather than an empty directory, for two reasons:
    // git does not track empty directories, and Nix ignores untracked
    // files inside a git tree -- so an untracked empty directory would
    // simply not be in the store copy the host evaluates.
    // A placeholder `hardware-configuration.nix`, for an ordering reason
    // rather than a cosmetic one.
    //
    // The generated flake imports this file unconditionally, but the real
    // one is produced by `nixos-anywhere --generate-hardware-config`
    // DURING the install -- which happens after Tier 1 preflight. So
    // without a placeholder, preflight's `nix build --dry-run` of the
    // configuration it just generated fails with "path
    // .../hardware-configuration.nix does not exist" on every fresh
    // install, and the check that exists to catch problems before anything
    // is destroyed could never run at all.
    //
    // `docs/INSTALL.md`'s manual path avoided this because its Step 3
    // generates and commits the file before Step 5's dry run. The
    // single-invocation design removed that step; this restores what it
    // provided. nixos-anywhere overwrites this file with the real one, and
    // R6 A2 then commits that back.
    // SEC-M5. `write_repo` runs `git add -A`, and `.git` travels to the
    // host by design (Nix ignores untracked files, so the tree must be a
    // real repository -- see install.rs). `copy_tree` excludes the
    // operator's files from the COPY, but that control is defeated if they
    // were committed before the copy: the history inside `.git` carries
    // them anyway. So they must never enter the repository in the first
    // place.
    //
    // NOT fixed by excluding `.git` from copy_tree, which was suggested:
    // that would break evaluation on the host outright.
    files.insert(".gitignore".into(), GITIGNORE.into());

    insert_hardware_config_placeholder(&mut files);

    files.insert(
        "custom/.gitkeep".into(),
        "# Hand-written host-specific Nix goes here; ferrum never rewrites it.\n\
         # This file only keeps the directory tracked -- the generated flake\n\
         # imports every *.nix in here, and readDir needs the directory to exist.\n"
            .into(),
    );

    check_no_placeholders(&files)?;
    Ok(files)
}

/// # Errors
/// Names the file and the sentinel it still contains.
pub fn check_no_placeholders(files: &Files) -> anyhow::Result<()> {
    for (path, body) in files {
        for p in PLACEHOLDERS {
            if body.contains(p) {
                anyhow::bail!("generated {path} still contains the placeholder {p:?}");
            }
        }
    }
    Ok(())
}

/// Writes the repository and makes it a git repository with everything
/// tracked.
///
/// # Errors
/// Any filesystem or git failure. `git` is on PATH because
/// `nix/pkgs/ferrum-install/default.nix` wraps this binary with it.
pub fn write_repo(dir: &Path, files: &Files) -> anyhow::Result<()> {
    // Written unconditionally, BEFORE `git add -A` below and regardless of
    // what the caller passed. `render()` includes it, but `read_generated`
    // -- the resume path -- reads only four files, so a resume against a
    // directory generated before this existed would commit the operator's
    // known_hosts, disk inventory and consent record into the history that
    // travels to the host. The control cannot depend on the caller
    // remembering it.
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(".gitignore"), GITIGNORE)?;

    for (rel, body) in files {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, body)?;
    }

    let git = |args: &[&str]| -> anyhow::Result<()> {
        let out = std::process::Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    };

    if !dir.join(".git").exists() {
        git(&["init", "-q"])?;
    }
    // Every file tracked: Nix silently ignores untracked files inside a git
    // tree, and an untracked disko.nix fails the install with a message
    // that names the wrong cause.
    git(&["add", "-A"])?;
    let staged = std::process::Command::new("git")
        .current_dir(dir)
        .args(["diff", "--cached", "--quiet"])
        .status()?;
    if !staged.success() {
        git(&[
            "-c",
            "user.name=ferrum-install",
            "-c",
            "user.email=ferrum-install@localhost",
            "commit",
            "-q",
            "-m",
            "ferrum-install: generated host configuration",
        ])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    /// One data disk mounts AT the media root, not beside it.
    ///
    /// The old layout mounted data disks at /mnt/media-N while
    /// ferrum.storage.mediaDir was /srv/media -- so the apps were pointed
    /// at an empty directory on the OS disk and the media was mounted
    /// somewhere nothing looked. On the first real install that meant 7TB
    /// present, mounted, and invisible to every app.
    #[test]
    fn a_single_data_disk_is_mounted_at_the_media_root() {
        let mut a = approved(Firmware::Uefi);
        a.all_devices.retain(|d| d.name != "sdc"); // leave one data disk
        let f = render(&answers(), &a, &keys(), "535acdf").unwrap();
        let m = &f["custom/media.nix"];
        assert!(m.contains(&format!("fileSystems.\"{MEDIA_ROOT}\"")), "{m}");
        assert!(
            !m.contains("/mnt/media-"),
            "the disconnected path must be gone:\n{m}"
        );

        // One disk needs no pool.
        let st: serde_json::Value = serde_json::from_str(&f["settings.json"]).unwrap();
        assert!(
            st.get("storage").is_none(),
            "a single disk is not a pool: {st}"
        );
    }

    /// Several disks become pool branches, and the pool is turned on.
    #[test]
    fn several_data_disks_become_pool_branches() {
        let mut a = approved(Firmware::Uefi);
        // Give the second data disk a filesystem so it counts.
        a.all_devices = vec![
            dev("sda", "/dev/disk/by-id/ata-OS_1", None),
            dev("sdb", "/dev/disk/by-id/ata-DATA_1", Some("ext4")),
            dev("sdc", "/dev/disk/by-id/ata-DATA_2", Some("ext4")),
        ];
        a.device = a.all_devices[0].clone();
        let f = render(&answers(), &a, &keys(), "535acdf").unwrap();
        let m = &f["custom/media.nix"];
        assert!(m.contains("/mnt/ferrum-disk-0"), "{m}");
        assert!(m.contains("/mnt/ferrum-disk-1"), "{m}");
        // The pool is mounted at the root by the module, so media.nix must
        // NOT also mount a disk there -- that would mount over the pool.
        assert!(!m.contains(&format!("fileSystems.\"{MEDIA_ROOT}\"")), "{m}");

        let st: serde_json::Value = serde_json::from_str(&f["settings.json"]).unwrap();
        let pool = &st["storage"]["pool"];
        assert_eq!(pool["enable"], serde_json::json!(true), "{st}");
        assert_eq!(
            pool["branches"],
            serde_json::json!(["/mnt/ferrum-disk-0", "/mnt/ferrum-disk-1"]),
            "{st}"
        );
    }

    /// A data disk is mounted from its PARTITION, never from the disk.
    ///
    /// The first real install generated
    /// `device = "/dev/disk/by-id/ata-ST8000DM004-2CX188_ZCT18WX0"` for a
    /// filesystem that lives on `...-part1`. Both media mounts failed with
    /// "wrong fs type, bad option, bad superblock", 7TB did not mount --
    /// and because the mounts carry `nofail`, the host booted cleanly and
    /// said nothing about it.
    ///
    /// Mutation check: use `d.by_id` instead of the partition's and this
    /// fails.
    #[test]
    fn data_disks_are_mounted_from_the_partition_not_the_disk() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "535acdf").unwrap();
        let m = &f["custom/media.nix"];
        assert!(
            m.contains("/dev/disk/by-id/ata-DATA_1-part1"),
            "must name the partition:\n{m}"
        );
        assert!(
            !m.contains("device = \"/dev/disk/by-id/ata-DATA_1\""),
            "must NOT name the whole disk -- mounting it fails with bad \
             superblock, silently, because of nofail:\n{m}"
        );
    }

    /// A data disk whose partition has no stable path is refused rather
    /// than named by kernel device: /dev/sdb is assigned in discovery
    /// order and can be a different disk after a reboot.
    #[test]
    fn a_data_partition_with_no_stable_path_is_refused() {
        let mut a = approved(Firmware::Uefi);
        for d in a.all_devices.iter_mut() {
            for c in d.children.iter_mut() {
                c.by_id = None;
            }
        }
        let err = render(&answers(), &a, &keys(), "535acdf")
            .expect_err("no stable partition path must be refused");
        let msg = err.to_string();
        assert!(msg.contains("by-id"), "{msg}");
        assert!(msg.contains("discovery order"), "{msg}");
    }

    /// SEC-L-N3. `render()` includes `.gitignore`, but the RESUME path
    /// does not go through `render()` -- `read_generated` reads four files
    /// and hands them straight to `write_repo`. So the guarantee has to
    /// live in `write_repo`, not in its caller.
    ///
    /// Mutation check: delete the unconditional write in `write_repo` and
    /// this fails. It survived the first time this was written, which is
    /// why the test exists.
    #[test]
    fn write_repo_guarantees_the_gitignore_even_when_the_caller_omits_it() {
        let dir = tempfile::tempdir().unwrap();
        // Exactly what a resume passes: no .gitignore anywhere in it.
        let mut files = Files::new();
        files.insert("flake.nix".into(), "{ }\n".into());
        assert!(
            !files.contains_key(".gitignore"),
            "the caller must not supply it"
        );

        write_repo(dir.path(), &files).unwrap();

        let written = std::fs::read_to_string(dir.path().join(".gitignore"))
            .expect("write_repo must write it regardless of the caller");
        for name in [
            "install-state.json",
            "install-inventory.json",
            "known_hosts",
        ] {
            assert!(written.contains(name), "{name} not ignored:\n{written}");
        }

        // And it actually takes effect: a file created afterwards is not
        // picked up by the `git add -A` of a second write_repo.
        std::fs::write(dir.path().join("install-inventory.json"), "{}").unwrap();
        write_repo(dir.path(), &files).unwrap();
        let out = std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["ls-files", "install-inventory.json"])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&out.stdout).trim().is_empty(),
            "install-inventory.json was committed despite the .gitignore"
        );
    }

    /// SEC-M5 at the source. `install.rs`'s end-to-end test proves the
    /// history is clean, but it supplies its own `.gitignore` -- so on its
    /// own it would still pass if `render` stopped emitting one. That is
    /// the same gap SEC-L1 was.
    ///
    /// Mutation check: delete the `.gitignore` insertion in `render` and
    /// this fails.
    #[test]
    fn the_generated_repo_ignores_the_operators_own_files() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "535acdf").unwrap();
        let ignore = f
            .get(".gitignore")
            .expect("without this, `git add -A` commits them and .git ships to the host");
        for name in [
            "install-state.json",
            "install-inventory.json",
            "known_hosts",
        ] {
            assert!(ignore.contains(name), "{name} is not ignored:\n{ignore}");
        }
    }

    /// SEC-H2. disko partitions and formats the target as root; an
    /// unpinned input there is remote code execution on the destructive
    /// path, before any generation exists to roll back to.
    ///
    /// Pinned is not enough on its own -- pinned to something ferrum has
    /// never evaluated would be its own hazard. This asserts the generated
    /// host uses the SAME disko this repository locks and tests against.
    #[test]
    fn the_generated_disko_pin_matches_this_repos_lockfile() {
        let lock: serde_json::Value =
            serde_json::from_str(include_str!("../../../flake.lock")).unwrap();
        let locked = lock["nodes"]["disko"]["locked"]["rev"].as_str().unwrap();
        assert_eq!(
            DISKO_REV, locked,
            "the generated host would be partitioned by a different disko \
             than this repository is tested against"
        );

        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "535acdf").unwrap();
        assert!(
            f["flake.nix"].contains(&format!("github:nix-community/disko/{DISKO_REV}")),
            "{}",
            f["flake.nix"]
        );
        assert!(
            !f["flake.nix"].contains("\"github:nix-community/disko\""),
            "an unpinned disko input survived"
        );
    }

    /// SEC-M4. `disko()` used to `.unwrap_or_default()` the serial guard,
    /// so a device with no serial produced a disko file with NO
    /// preCreateHook at all -- silently losing the check that re-verifies
    /// the disk's identity after kexec, immediately before the partition
    /// table is destroyed.
    ///
    /// Its comment justified this with "R2 A8 refuses an inventory whose
    /// serials cannot identify a disk", but that refusal was removed when a
    /// serial-less device became unselectable rather than disqualifying.
    /// The argument was false while the code still leaned on it.
    ///
    /// Mutation check: restore `.unwrap_or_default()` and this fails.
    #[test]
    fn disko_refuses_to_generate_without_the_serial_guard() {
        let err = disko("/dev/disk/by-id/ata-OS_1", Firmware::Uefi, None)
            .expect_err("no serial must be refused, never silently unguarded");
        let msg = err.to_string();
        assert!(
            msg.contains("no \\\n             serial") || msg.contains("no serial"),
            "{msg}"
        );
        assert!(msg.contains("preCreateHook"), "{msg}");

        // With a serial, the guard is present.
        let ok = disko("/dev/disk/by-id/ata-OS_1", Firmware::Uefi, Some("S1")).unwrap();
        assert!(ok.contains("preCreateHook"), "the guard must be emitted");
    }

    /// The transfer guard and the verify check both look for
    /// [`HARDWARE_CONFIG_SENTINEL`] in this file's body. If the placeholder
    /// stopped containing it, both guards would silently pass a stand-in
    /// through onto a real host.
    ///
    /// Mutation check: change either the sentinel or the placeholder text
    /// and this fails.
    #[test]
    fn the_placeholder_hardware_config_carries_the_sentinel_the_guards_look_for() {
        let mut files = Files::new();
        insert_hardware_config_placeholder(&mut files);
        let body = &files["hardware-configuration.nix"];
        assert!(
            body.contains(HARDWARE_CONFIG_SENTINEL),
            "the transfer step refuses on this exact substring; without it a \
             host installs with no kernel modules and no microcode, and boots \
             looking fine"
        );
        // It must still be a valid empty module, or Tier 1 cannot evaluate
        // before the disk is touched -- which is the whole reason it exists.
        assert!(body.contains("{ ... }: { }"));
    }

    /// The sentinel must NOT be in `PLACEHOLDERS`: that list is checked
    /// against render's own output, so listing it would make `render`
    /// reject every configuration it generates.
    #[test]
    fn the_hardware_config_sentinel_is_not_in_the_placeholder_list() {
        assert!(!PLACEHOLDERS.contains(&HARDWARE_CONFIG_SENTINEL));
        let mut files = Files::new();
        insert_hardware_config_placeholder(&mut files);
        check_no_placeholders(&files).expect("render must not reject its own placeholder file");
    }
    use super::*;
    use crate::inventory::Filesystem;
    use crate::sso::SsoDecision;

    fn dev(name: &str, by_id: &str, fstype: Option<&str>) -> Device {
        Device {
            name: name.into(),
            size: "3.6T".into(),
            model: Some("ST4000VN".into()),
            serial: Some(format!("{name}-serial")),
            by_id: Some(by_id.into()),
            children: fstype
                .map(|f| {
                    vec![Filesystem {
                        name: format!("{name}1"),
                        fstype: Some(f.into()),
                        mountpoint: None,
                        // The PARTITION's own path, which is what a data
                        // disk is mounted from -- "-part1", not the disk.
                        by_id: Some(format!("{by_id}-part1")),
                    }]
                })
                .unwrap_or_default(),
        }
    }

    fn approved(firmware: Firmware) -> Approved {
        let os = dev("sda", "/dev/disk/by-id/ata-OS_1", None);
        Approved {
            device: os.clone(),
            firmware,
            all_devices: vec![
                os,
                dev("sdb", "/dev/disk/by-id/ata-DATA_1", Some("ext4")),
                dev("sdc", "/dev/disk/by-id/ata-EMPTY_1", None),
            ],
        }
    }

    fn answers() -> Answers {
        Answers {
            hostname: "saltbox".into(),
            base_domain: Some("thesyms.ca".into()),
            acme_email: Some("me@thesyms.ca".into()),
            sso: SsoDecision {
                enabled: true,
                unauthenticated_accepted_for: Vec::new(),
                admin_email: Some("admin@thesyms.ca".into()),
            },
            apps: vec!["sonarr".into(), "plex".into()],
            cloudflare_token: Some(crate::answers::Secret::new("tok".into())),
            dns: Some(DnsDecision {
                target: RecordTarget::A("203.0.113.10".parse().expect("a literal address")),
                ddns_updater: true,
            }),
        }
    }

    fn keys() -> Vec<String> {
        vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAreal me@mac".into()]
    }

    /// THE test of this module. `@state` is hardcoded in
    /// restore_state.rs and state-restore.nix asserts `@snapshots` shares
    /// its volume; drift produces a host that installs, boots, looks
    /// healthy and cannot roll back.
    #[test]
    fn the_subvolume_layout_matches_the_template() {
        let normalise = |s: &str| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let template = normalise(TEMPLATE_DISKO);
        for line in normalise(SUBVOLUMES).lines() {
            assert!(
                template.contains(line),
                "generated subvolume layout has drifted from \
                 examples/hosts/template/disko.nix -- line not found there: {line:?}"
            );
        }
        for sub in ["\"@root\"", "\"@nix\"", "\"@state\"", "\"@snapshots\""] {
            assert!(
                SUBVOLUMES.contains(sub),
                "{sub} missing from the generated layout"
            );
        }
    }

    /// These values come from lsblk on a machine we do not control, and
    /// on a resume from a file in the operator's writable bind mount. They
    /// are written into Nix source that is evaluated and built as root.
    #[test]
    fn device_strings_cannot_break_out_of_the_generated_nix() {
        let mut a = approved(Firmware::Uefi);
        a.device.by_id =
            Some(r#"/dev/disk/by-id/evil"; boot.loader.grub.device = "/dev/sda"#.into());
        a.all_devices[0] = a.device.clone();
        a.all_devices[1].model = Some("Model ${builtins.currentSystem}".into());

        let f = render(&answers(), &a, &keys(), "abc").unwrap();
        let d = &f["disko.nix"];
        // The quote is escaped, so the injected attribute never becomes Nix.
        assert!(d.contains(r#"\""#), "quote not escaped:\n{d}");
        assert!(
            !d.contains("\n    boot.loader.grub.device"),
            "broke out:\n{d}"
        );
        // And an antiquotation is inert rather than evaluated. Checking
        // for an UNESCAPED occurrence: `\${builtins` trivially contains
        // `${builtins`, so a substring test alone proves nothing.
        let m = &f["custom/media.nix"];
        assert!(m.contains(r"\${builtins"), "not escaped:\n{m}");
        let unescaped = m
            .match_indices("${builtins")
            .any(|(i, _)| i == 0 || !m[..i].ends_with('\\'));
        assert!(!unescaped, "an unescaped antiquotation survived:\n{m}");
    }

    #[test]
    fn nix_str_escapes_what_nix_actually_treats_as_special() {
        assert_eq!(nix_str(r#"a"b"#), r#"a\"b"#);
        assert_eq!(nix_str("a${b}"), "a\\${b}");
        assert_eq!(nix_str(r"a\b"), r"a\\b");
    }

    #[test]
    fn only_the_approved_disk_is_named_in_disko() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let d = &f["disko.nix"];
        assert!(d.contains("/dev/disk/by-id/ata-OS_1"));
        assert!(
            !d.contains("ata-DATA_1"),
            "a data disk must never appear in disko.nix:\n{d}"
        );
        assert!(!d.contains("ata-EMPTY_1"), "{d}");
    }

    /// R2 A9, finally real: the check the installer could not make runs
    /// inside the kexec'd installer, before this disk is partitioned.
    #[test]
    fn the_generated_disko_reverifies_the_serial_before_partitioning() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc").unwrap();
        let d = &f["disko.nix"];
        assert!(d.contains("preCreateHook"), "no pre-partition hook:\n{d}");
        assert!(
            d.contains("sda-serial"),
            "the approved serial must be baked in:\n{d}"
        );
        assert!(d.contains("REFUSING TO PARTITION"), "{d}");
        // Fails closed: the comparison is against the read value, so an
        // unreadable serial is an empty string and therefore a mismatch.
        // The quotes are Nix-escaped, because the hook is a double-quoted
        // Nix string -- see a_serial_containing_an_apostrophe_... for why.
        assert!(
            d.contains(r#"[ \"$ferrum_got\" != \"$ferrum_want\" ]"#),
            "{d}"
        );
        assert!(d.contains("exit 1"), "{d}");
    }

    /// **Executes** the generated guard rather than substring-matching it.
    ///
    /// Three consecutive security cycles found an injection in this one
    /// function, and every time the test beside it asserted "the quoted
    /// form appears in the output" -- which is true of text that is inert
    /// where it sits AND of text that is not. The only assertion that
    /// distinguishes them is running the thing.
    /// Inverts `nix_str` the way Nix's own parser does, so a test can
    /// exercise the text that ACTUALLY reaches the shell rather than the
    /// text before escaping. Kept deliberately literal; the round-trip
    /// property below is what makes it trustworthy.
    #[cfg(test)]
    fn nix_unescape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        }
        out
    }

    /// `nix_str` must be exactly invertible, or the string the installer
    /// generates is not the string the host runs.
    #[test]
    fn nix_escaping_round_trips_byte_for_byte() {
        for raw in [
            "plain",
            "a\"b",
            "a\\b",
            "a${b}",
            "a\nb",
            "a\rb",
            "a\r\nb",
            "trailing\\",
            "a\\\"b",
            "a'b'\\''c",
            "$(id)`id`",
            "''indented''",
        ] {
            assert_eq!(
                nix_unescape(&nix_str(raw)),
                raw,
                "nix_str is not invertible for {raw:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_generated_guard_cannot_be_made_to_execute_anything() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("OWNED");
        let payload = format!("$(touch {})", marker.display());

        for (disk, serial) in [
            (format!("/dev/disk/by-id/ata-X{payload}"), "SER".to_string()),
            ("/dev/disk/by-id/ata-X".to_string(), format!("SER{payload}")),
            (
                format!("/dev/disk/by-id/`touch {}`", marker.display()),
                "SER".into(),
            ),
            (
                format!("/dev/disk/by-id/ata-X'; touch {}; '", marker.display()),
                "SER".into(),
            ),
        ] {
            // Execute BOTH the raw guard and the text as it emerges from
            // the Nix layer. Those are not always the same string, and the
            // one the host actually runs is the second.
            let raw = precreate_serial_guard(&disk, &serial);
            let through_nix = nix_unescape(&nix_str(&raw));
            for (label, script) in [("raw", &raw), ("post-nix", &through_nix)] {
                // The guard is expected to FAIL (the serial will not match a
                // device that does not exist); what must not happen is the
                // payload running.
                let _ = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(script)
                    .output();
                assert!(
                    !marker.exists(),
                    "the {label} guard executed an injected payload.\n  \
                     disk: {disk}\n  serial: {serial}\n\n{script}"
                );
            }
        }
    }

    /// One quoter, not two. The duplicate lived in the function that has
    /// needed three Critical fixes, where a quoting change failing to
    /// propagate is the obvious next defect.
    #[test]
    fn the_guard_uses_the_shared_quoter() {
        for v in ["a'b", "a\"b", "plain", "a b", "", "a$(id)b"] {
            assert!(
                precreate_serial_guard("/d", v).contains(&crate::collect::sh_quote(v)),
                "the guard must quote {v:?} exactly as collect::sh_quote does"
            );
        }
        // ...and the device path too, not only the serial.
        let d = "/dev/disk/by-id/a'b";
        assert!(precreate_serial_guard(d, "S").contains(&crate::collect::sh_quote(d)));
    }

    /// Each untrusted value must appear exactly once, at a top-level
    /// assignment -- anywhere else the single-quoting is inert.
    #[test]
    fn untrusted_values_are_quoted_once_at_top_level() {
        let g = precreate_serial_guard("/dev/disk/by-id/DISK", "SERIAL");
        assert_eq!(
            g.matches("'/dev/disk/by-id/DISK'").count(),
            1,
            "the device path must be spliced once, not repeated into messages:\n{g}"
        );
        assert!(g.contains("ferrum_disk='/dev/disk/by-id/DISK'"), "{g}");
        assert!(
            g.contains("\"$ferrum_disk\""),
            "later uses must go through the variable:\n{g}"
        );
        assert_eq!(g.matches("'SERIAL'").count(), 1, "{g}");
    }

    /// The serial is device-derived, exactly like the fields
    /// `device_strings_cannot_break_out_of_the_generated_nix` covers -- and
    /// it was the one field that reached generated Nix with only SHELL
    /// quoting. `shell_single_quote` emits `'\''` for an apostrophe, and
    /// `''` terminates a Nix indented string.
    /// Writes a real generated disko.nix carrying an adversarial serial,
    /// so it can be parsed by an actual Nix. Reading the grammar is not
    /// proof; this defect was found and fixed by running nix-instantiate.
    #[test]
    fn dump_adversarial_disko_for_nix_parsing() {
        let Ok(dest) = std::env::var("FERRUM_DUMP_DISKO") else {
            return;
        };
        let mut a = approved(Firmware::Uefi);
        a.device.serial = Some("abc'def\"x${builtins.currentSystem}".into());
        let f = render(&answers(), &a, &keys(), "abc").unwrap();
        std::fs::write(dest, &f["disko.nix"]).unwrap();
    }

    #[test]
    fn a_serial_containing_an_apostrophe_cannot_break_the_generated_nix() {
        let mut a = approved(Firmware::Uefi);
        a.device.serial = Some("abc'def".into());
        let f = render(&answers(), &a, &keys(), "abc").unwrap();
        let d = &f["disko.nix"];

        // The hook is a double-quoted string, so the shell's `'\''` is
        // inert; what must never appear is an unescaped `"` closing it.
        let hook_start = d.find("preCreateHook = \"").expect("hook present");
        let rest = &d[hook_start + "preCreateHook = \"".len()..];
        let end = rest.find("\";").expect("the hook string must be closed");
        let body = &rest[..end];
        assert!(
            body.contains("abc"),
            "the serial must still be there: {body}"
        );
        // No unescaped double quote inside the body.
        let unescaped_quote = body
            .match_indices('"')
            .any(|(i, _)| i == 0 || !body[..i].ends_with('\\'));
        assert!(
            !unescaped_quote,
            "an unescaped quote closes the hook early: {body}"
        );
    }

    /// A serial crafted to inject Nix must be inert.
    #[test]
    fn a_serial_cannot_inject_an_antiquotation() {
        let mut a = approved(Firmware::Uefi);
        a.device.serial = Some("s${builtins.currentSystem}".into());
        let f = render(&answers(), &a, &keys(), "abc").unwrap();
        let d = &f["disko.nix"];
        let unescaped = d
            .match_indices("${builtins")
            .any(|(i, _)| i == 0 || !d[..i].ends_with('\\'));
        assert!(!unescaped, "an unescaped antiquotation survived:\n{d}");
    }

    #[test]
    fn uefi_gets_an_esp_and_systemd_boot() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        assert!(f["disko.nix"].contains("EF00") && f["disko.nix"].contains("vfat"));
        assert!(f["flake.nix"].contains("systemd-boot"));
        assert!(!f["flake.nix"].contains("grub"));
    }

    /// Getting this wrong installs cleanly and then does not boot, with the
    /// previous OS already gone.
    #[test]
    fn bios_gets_a_bios_boot_partition_and_grub_on_the_right_disk() {
        let f = render(&answers(), &approved(Firmware::Bios), &keys(), "abc1234").unwrap();
        assert!(f["disko.nix"].contains("EF02"), "{}", f["disko.nix"]);
        assert!(!f["disko.nix"].contains("EF00"));
        assert!(f["flake.nix"].contains("boot.loader.grub"));
        // disko already sets grub.devices from disko.nix's `device`.
        // Setting it here too duplicates the entry and the host refuses to
        // evaluate: "You cannot have duplicated devices in mirroredBoots".
        assert!(
            !f["flake.nix"].contains("devices = ["),
            "grub.devices must be left to disko:\n{}",
            f["flake.nix"]
        );
        assert!(!f["flake.nix"].contains("systemd-boot"));
    }

    /// Only disks that already carry a filesystem, and never the one being
    /// erased.
    #[test]
    fn data_disks_are_detected_not_asked_for() {
        let a = approved(Firmware::Uefi);
        let d = data_disks(&a.all_devices, &a.device);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "sdb");
    }

    #[test]
    fn data_disks_are_mounted_from_custom_never_disko() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let m = &f["custom/media.nix"];
        assert!(m.contains("ata-DATA_1") && m.contains("ext4"));
        assert!(
            m.contains("nofail"),
            "a missing disk must not break boot: {m}"
        );
        assert!(
            !m.contains("ata-EMPTY_1"),
            "an empty disk is not a data disk: {m}"
        );
    }

    /// `importDir ./custom` is unconditional in the generated flake, and
    /// `readDir` on a missing directory is a hard evaluation error -- so a
    /// host with no data disks produced a configuration that could not be
    /// evaluated at all.
    /// Preflight evaluates the generated flake BEFORE the install runs,
    /// and the flake imports hardware-configuration.nix unconditionally --
    /// but nixos-anywhere only writes the real one during the install. A
    /// placeholder is what lets the pre-destructive check run at all.
    #[test]
    fn a_placeholder_hardware_config_exists_so_preflight_can_evaluate() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc").unwrap();
        let hw = f
            .get("hardware-configuration.nix")
            .expect("preflight cannot evaluate the flake without this file");
        assert!(
            hw.contains("PLACEHOLDER"),
            "it must be obviously temporary: {hw}"
        );
        assert!(
            hw.contains("{ ... }: { }"),
            "it must be a valid empty module: {hw}"
        );
        assert!(f["flake.nix"].contains("./hardware-configuration.nix"));
    }

    #[test]
    fn custom_always_exists_even_with_no_data_disks() {
        let mut a = approved(Firmware::Uefi);
        a.all_devices.retain(|d| d.name == "sda");
        let f = render(&answers(), &a, &keys(), "abc").unwrap();
        assert!(!f.contains_key("custom/media.nix"), "nothing to mount");
        assert!(
            f.keys().any(|k| k.starts_with("custom/")),
            "custom/ must still be created, or importDir cannot readDir it: {:?}",
            f.keys().collect::<Vec<_>>()
        );
    }

    /// git does not track empty directories and Nix ignores untracked
    /// files, so the placeholder has to be a real tracked file.
    #[test]
    fn the_custom_placeholder_is_written_and_tracked() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = approved(Firmware::Uefi);
        a.all_devices.retain(|d| d.name == "sda");
        let f = render(&answers(), &a, &keys(), "abc").unwrap();
        write_repo(dir.path(), &f).unwrap();

        let tracked = std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["ls-files"])
            .output()
            .unwrap();
        let list = String::from_utf8(tracked.stdout).unwrap();
        assert!(list.contains("custom/"), "custom/ is untracked:\n{list}");
    }

    #[test]
    fn no_media_file_when_there_is_nothing_to_mount() {
        let mut a = approved(Firmware::Uefi);
        a.all_devices.retain(|d| d.name == "sda");
        let f = render(&answers(), &a, &keys(), "abc1234").unwrap();
        assert!(!f.contains_key("custom/media.nix"));
    }

    /// Stage 1 must carry no apps and no auth: both declare sops secrets
    /// whose files cannot exist before the host does.
    #[test]
    fn stage_one_has_no_apps_and_no_auth() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.json"]).unwrap();
        assert_eq!(s["apps"], serde_json::json!({}));
        assert!(s.get("auth").is_none(), "stage 1 must not enable auth: {s}");
        assert!(s.get("secrets").is_none(), "{s}");
        // The proxy IS configured in stage 1 -- it declares no secret.
        assert_eq!(s["proxy"]["baseDomain"], "thesyms.ca");
    }

    #[test]
    fn stage_two_carries_the_apps_auth_and_the_secret_declaration() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.stage2.json"]).unwrap();
        assert_eq!(s["apps"]["sonarr"]["enable"], true);
        assert_eq!(s["apps"]["plex"]["enable"], true);
        assert_eq!(s["auth"]["enable"], true);
        assert_eq!(s["auth"]["adminEmail"], "admin@thesyms.ca");
        // acme.nix checks `ferrum.secrets ? acme-dns` as well as the file,
        // so the token alone is not enough.
        assert!(s["secrets"]["acme-dns"].is_object(), "{s}");
    }

    /// R1 A2. The record target the operator chose has to arrive in the
    /// settings under the names modules/core/options.nix declares, and
    /// `enable` has to be flipped on -- it defaults to false there only
    /// because no address can be guessed, and this installer is what
    /// supplies the missing answer. A host whose operator answered the
    /// question and still had to open a DNS console gained nothing.
    #[test]
    fn a_mode_renders_the_address_and_nothing_of_the_other_mode() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.stage2.json"]).unwrap();
        let dns = &s["proxy"]["dns"];
        assert_eq!(dns["enable"], true, "{s}");
        assert_eq!(dns["recordMode"], "a", "{s}");
        assert_eq!(dns["staticAddress"], "203.0.113.10", "{s}");
        assert!(
            dns.get("cnameTarget").is_none(),
            "the other mode's target must not be written: {s}"
        );
        assert_eq!(dns["ddnsUpdater"]["enable"], true, "{s}");
        // The interval keeps its module default rather than freezing
        // today's value into this host forever.
        assert!(dns.pointer("/ddnsUpdater/intervalMinutes").is_none(), "{s}");
    }

    /// R1 A2 and A8. CNAME mode is the mirror image, and the updater must
    /// be absent entirely: modules/proxy/dns.nix asserts the combination is
    /// invalid, so rendering it would produce a host that cannot evaluate.
    #[test]
    fn cname_mode_renders_the_hostname_and_never_the_updater() {
        let mut a = answers();
        a.dns = Some(DnsDecision {
            target: RecordTarget::Cname("saltbox.dynamic-dns.example.net".into()),
            ddns_updater: false,
        });
        let f = render(&a, &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.stage2.json"]).unwrap();
        let dns = &s["proxy"]["dns"];
        assert_eq!(dns["enable"], true, "{s}");
        assert_eq!(dns["recordMode"], "cname", "{s}");
        assert_eq!(dns["cnameTarget"], "saltbox.dynamic-dns.example.net", "{s}");
        assert!(dns.get("staticAddress").is_none(), "{s}");
        assert!(
            dns.get("ddnsUpdater").is_none(),
            "the updater is meaningless for a CNAME and dns.nix asserts \
             against it: {s}"
        );
    }

    /// Stage 1 declares no secrets at all, and modules/proxy/dns.nix
    /// asserts that dns.enable implies a declared credential. Writing the
    /// block into stage 1 would fail the FIRST evaluation -- the one that
    /// happens before the disk is erased -- on an assertion about a
    /// credential that cannot exist yet.
    #[test]
    fn stage_one_carries_no_dns_block() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.json"]).unwrap();
        assert!(s["proxy"].get("dns").is_none(), "{s}");
        // ... while the rest of the proxy is configured as before.
        assert_eq!(s["proxy"]["baseDomain"], "thesyms.ca");
    }

    /// A host with no domain publishes nothing, so there is no record to
    /// create and no block to write.
    #[test]
    fn no_dns_decision_means_no_dns_block() {
        let mut a = answers();
        a.dns = None;
        let f = render(&a, &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.stage2.json"]).unwrap();
        assert!(s["proxy"].get("dns").is_none(), "{s}");
    }

    /// Writing a value that still equals its default freezes today's
    /// default into this host forever.
    #[test]
    fn apps_are_written_with_nothing_but_enable() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.stage2.json"]).unwrap();
        assert_eq!(s["apps"]["sonarr"], serde_json::json!({ "enable": true }));
        assert!(!f["settings.stage2.json"].contains("exposure"));
    }

    #[test]
    fn the_ferrum_input_is_pinned_to_a_revision_not_a_branch() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "535acdf").unwrap();
        assert!(
            f["flake.nix"].contains("github:syms-dev/ferrum/535acdf"),
            "{}",
            f["flake.nix"]
        );
    }

    #[test]
    fn the_operators_ssh_key_is_in_the_flake() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc").unwrap();
        assert!(f["flake.nix"].contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAreal me@mac"));
    }

    /// R3 A3: all four sentinels, because settings.json's placeholders are
    /// `example.invalid` rather than CHANGE-ME.
    #[test]
    fn no_generated_file_contains_any_placeholder() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc").unwrap();
        for (path, body) in &f {
            for p in PLACEHOLDERS {
                assert!(!body.contains(p), "{path} contains {p}");
            }
        }
    }

    /// Every ed25519 public key begins AAAAC3NzaC1lZDI1NTE5AAAA, so a bare
    /// "AAAA" sentinel would reject every real key. The template spells its
    /// placeholder "AAAA..." with the ellipsis, and that is what must be
    /// matched.
    #[test]
    fn a_real_ed25519_key_is_not_mistaken_for_a_placeholder() {
        let real = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIdz0kygj48zqJh cs@mac".to_string();
        let f = render(
            &answers(),
            &approved(Firmware::Uefi),
            std::slice::from_ref(&real),
            "abc",
        )
        .unwrap();
        assert!(f["flake.nix"].contains(&real));

        // ...while the template's actual placeholder is still caught.
        let mut bad = Files::new();
        bad.insert(
            "flake.nix".into(),
            "\"ssh-ed25519 AAAA...CHANGE-ME\"".into(),
        );
        assert!(check_no_placeholders(&bad).is_err());
    }

    #[test]
    fn the_placeholder_check_names_the_file_and_the_sentinel() {
        let mut f = Files::new();
        f.insert("settings.json".into(), "{\"d\":\"example.invalid\"}".into());
        let err = check_no_placeholders(&f).unwrap_err().to_string();
        assert!(
            err.contains("settings.json") && err.contains("example.invalid"),
            "{err}"
        );
    }

    #[test]
    fn the_repository_is_written_and_fully_tracked() {
        let dir = tempfile::tempdir().unwrap();
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc").unwrap();
        write_repo(dir.path(), &f).unwrap();

        assert!(dir.path().join("disko.nix").is_file());
        assert!(dir.path().join("custom/media.nix").is_file());
        assert!(dir.path().join(".git").is_dir());

        // Nix ignores untracked files inside a git tree, so "tracked" is
        // the property that matters, not "written".
        let tracked = std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["ls-files"])
            .output()
            .unwrap();
        let list = String::from_utf8(tracked.stdout).unwrap();
        for expected in [
            "disko.nix",
            "flake.nix",
            "settings.json",
            "custom/media.nix",
        ] {
            assert!(list.contains(expected), "{expected} is untracked:\n{list}");
        }
    }

    #[test]
    fn writing_twice_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc").unwrap();
        write_repo(dir.path(), &f).unwrap();
        write_repo(dir.path(), &f).unwrap();
    }
    // ---- R1 A3: the adoption decision has to reach the host -----------

    fn adoption_of(names: &[&str]) -> crate::dns::Adoption {
        crate::dns::Adoption {
            adopted: names
                .iter()
                .map(|name| crate::dns::ForeignName {
                    name: (*name).to_string(),
                    current: "198.51.100.9".to_string(),
                    wanted: "203.0.113.10".to_string(),
                })
                .collect(),
            declined: Vec::new(),
        }
    }

    /// The whole point of the gate. An operator who typed `adopt` and got
    /// nothing in their settings has opted in to a takeover that will never
    /// happen -- which is the "reported and left alone" behaviour they
    /// explicitly declined.
    #[test]
    fn an_adopted_name_reaches_the_host_settings() {
        let f = render_with_adoption(
            &answers(),
            &approved(Firmware::Uefi),
            &keys(),
            "abc1234",
            &adoption_of(&["plex.thesyms.ca"]),
        )
        .unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.stage2.json"]).unwrap();
        assert_eq!(
            s["proxy"]["dns"]["adoptedNames"],
            serde_json::json!(["plex.thesyms.ca"]),
            "{s}"
        );
    }

    /// Per name, all the way to settings: adopting one does not write the
    /// other, even though both were offered at the same gate.
    #[test]
    fn only_the_names_the_operator_adopted_are_written() {
        let mut adoption = adoption_of(&["plex.thesyms.ca"]);
        adoption.declined.push(crate::dns::ForeignName {
            name: "sonarr.thesyms.ca".to_string(),
            current: "198.51.100.9".to_string(),
            wanted: "203.0.113.10".to_string(),
        });
        let f = render_with_adoption(
            &answers(),
            &approved(Firmware::Uefi),
            &keys(),
            "abc1234",
            &adoption,
        )
        .unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.stage2.json"]).unwrap();
        let adopted = s["proxy"]["dns"]["adoptedNames"]
            .as_array()
            .expect("the adopted list is an array");
        assert_eq!(adopted, &[serde_json::json!("plex.thesyms.ca")], "{s}");
        assert!(
            !f["settings.stage2.json"].contains("sonarr.thesyms.ca"),
            "a declined name must not be written as adopted"
        );
    }

    /// The ordinary run. No adoption means no key at all, rather than an
    /// empty list an operator would have to interpret.
    #[test]
    fn a_run_that_adopted_nothing_writes_no_adopted_list() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc1234").unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.stage2.json"]).unwrap();
        assert!(s["proxy"]["dns"].get("adoptedNames").is_none(), "{s}");
    }

    /// Stage 1 declares no credential and therefore no dns block at all, so
    /// an adoption must not smuggle one in and fail the first evaluation on
    /// modules/proxy/dns.nix's credential assertion.
    #[test]
    fn stage_one_carries_no_adopted_list_either() {
        let f = render_with_adoption(
            &answers(),
            &approved(Firmware::Uefi),
            &keys(),
            "abc1234",
            &adoption_of(&["plex.thesyms.ca"]),
        )
        .unwrap();
        let s: serde_json::Value = serde_json::from_str(&f["settings.json"]).unwrap();
        assert!(s["proxy"].get("dns").is_none(), "{s}");
    }
}
