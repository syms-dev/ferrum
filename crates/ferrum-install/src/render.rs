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

use crate::answers::Answers;
use crate::confirm::Approved;
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

fn disko(os_disk: &str, firmware: Firmware, serial: Option<&str>) -> String {
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
    // Only emitted when a serial is known. R2 A8 refuses an inventory
    // whose serials cannot identify a disk, so in practice it always is.
    let guard = serial
        .map(|sn| {
            format!(
                "\n    preCreateHook = \"{}\";\n",
                nix_str(&precreate_serial_guard(os_disk, sn))
            )
        })
        .unwrap_or_default();
    format!(
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
    )
}

fn flake(hostname: &str, ferrum_rev: &str, ssh_keys: &[String], firmware: Firmware, os_disk: &str) -> String {
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

    let os_disk = nix_str(os_disk);
    let bootloader = match firmware {
        Firmware::Uefi => "            boot.loader.systemd-boot.enable = true;\n            boot.loader.efi.canTouchEfiVariables = true;".to_string(),
        Firmware::Bios => format!(
            "            boot.loader.grub = {{\n              enable = true;\n              devices = [ \"{os_disk}\" ];\n              efiSupport = false;\n            }};"
        ),
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

    disko.url = "github:nix-community/disko";
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

fn media(disks: &[&Device]) -> String {
    let mounts = disks
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let fstype = nix_str(
                d.children
                    .iter()
                    .find_map(|c| c.fstype.as_deref())
                    .unwrap_or("ext4"),
            );
            format!(
                r#"  # {model}, {size}
  fileSystems."/mnt/media-{i}" = {{
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
                by_id = nix_str(d.by_id.as_deref().unwrap_or("MISSING")),
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    format!(
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
    )
}

fn settings(answers: &Answers, stage: Stage) -> serde_json::Value {
    let mut root = serde_json::Map::new();
    root.insert("schemaVersion".into(), serde_json::json!(1));

    if let Some(domain) = &answers.base_domain {
        let mut proxy = serde_json::Map::new();
        proxy.insert("enable".into(), serde_json::json!(true));
        proxy.insert("baseDomain".into(), serde_json::json!(domain));
        if let Some(email) = &answers.acme_email {
            proxy.insert("acme".into(), serde_json::json!({ "email": email }));
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

/// Renders the whole host repository.
///
/// # Errors
/// Returns an error if any generated file still contains a placeholder
/// sentinel -- asserted here rather than left to the operator.
pub fn render(
    answers: &Answers,
    approved: &Approved,
    ssh_keys: &[String],
    ferrum_rev: &str,
) -> anyhow::Result<Files> {
    let os_disk = approved
        .device
        .by_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("approved device has no by-id path"))?;

    let mut files = Files::new();
    files.insert(
        "disko.nix".into(),
        disko(os_disk, approved.firmware, approved.device.serial.as_deref()),
    );
    files.insert(
        "flake.nix".into(),
        flake(&answers.hostname, ferrum_rev, ssh_keys, approved.firmware, os_disk),
    );
    files.insert(
        "settings.json".into(),
        format!("{}\n", serde_json::to_string_pretty(&settings(answers, Stage::One))?),
    );
    files.insert(
        "settings.stage2.json".into(),
        format!("{}\n", serde_json::to_string_pretty(&settings(answers, Stage::Two))?),
    );

    let disks = data_disks(&approved.all_devices, &approved.device);
    if !disks.is_empty() {
        files.insert("custom/media.nix".into(), media(&disks));
    }

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
            "-c", "user.name=ferrum-install",
            "-c", "user.email=ferrum-install@localhost",
            "commit", "-q", "-m", "ferrum-install: generated host configuration",
        ])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
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
            assert!(SUBVOLUMES.contains(sub), "{sub} missing from the generated layout");
        }
    }

    /// These values come from lsblk on a machine we do not control, and
    /// on a resume from a file in the operator's writable bind mount. They
    /// are written into Nix source that is evaluated and built as root.
    #[test]
    fn device_strings_cannot_break_out_of_the_generated_nix() {
        let mut a = approved(Firmware::Uefi);
        a.device.by_id = Some(r#"/dev/disk/by-id/evil"; boot.loader.grub.device = "/dev/sda"#.into());
        a.all_devices[0] = a.device.clone();
        a.all_devices[1].model = Some("Model ${builtins.currentSystem}".into());

        let f = render(&answers(), &a, &keys(), "abc").unwrap();
        let d = &f["disko.nix"];
        // The quote is escaped, so the injected attribute never becomes Nix.
        assert!(d.contains(r#"\""#), "quote not escaped:\n{d}");
        assert!(!d.contains("\n    boot.loader.grub.device"), "broke out:\n{d}");
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
        assert!(!d.contains("ata-DATA_1"), "a data disk must never appear in disko.nix:\n{d}");
        assert!(!d.contains("ata-EMPTY_1"), "{d}");
    }

    /// R2 A9, finally real: the check the installer could not make runs
    /// inside the kexec'd installer, before this disk is partitioned.
    #[test]
    fn the_generated_disko_reverifies_the_serial_before_partitioning() {
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "abc").unwrap();
        let d = &f["disko.nix"];
        assert!(d.contains("preCreateHook"), "no pre-partition hook:\n{d}");
        assert!(d.contains("sda-serial"), "the approved serial must be baked in:\n{d}");
        assert!(d.contains("REFUSING TO PARTITION"), "{d}");
        // Fails closed: the comparison is against the read value, so an
        // unreadable serial is an empty string and therefore a mismatch.
        // The quotes are Nix-escaped, because the hook is a double-quoted
        // Nix string -- see a_serial_containing_an_apostrophe_... for why.
        assert!(d.contains(r#"[ \"$ferrum_got\" != \"$ferrum_want\" ]"#), "{d}");
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
            (format!("/dev/disk/by-id/`touch {}`", marker.display()), "SER".into()),
            (format!("/dev/disk/by-id/ata-X'; touch {}; '", marker.display()), "SER".into()),
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
                let _ = std::process::Command::new("sh").arg("-c").arg(script).output();
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
        assert!(g.contains("\"$ferrum_disk\""), "later uses must go through the variable:\n{g}");
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
        let Ok(dest) = std::env::var("FERRUM_DUMP_DISKO") else { return };
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
        assert!(body.contains("abc"), "the serial must still be there: {body}");
        // No unescaped double quote inside the body.
        let unescaped_quote = body
            .match_indices('"')
            .any(|(i, _)| i == 0 || !body[..i].ends_with('\\'));
        assert!(!unescaped_quote, "an unescaped quote closes the hook early: {body}");
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
        assert!(
            f["flake.nix"].contains("devices = [ \"/dev/disk/by-id/ata-OS_1\" ]"),
            "grub must be installed to the disk being erased:\n{}",
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
        assert!(m.contains("nofail"), "a missing disk must not break boot: {m}");
        assert!(!m.contains("ata-EMPTY_1"), "an empty disk is not a data disk: {m}");
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
        let f = render(&answers(), &approved(Firmware::Uefi), &keys(), "9656ab2").unwrap();
        assert!(
            f["flake.nix"].contains("github:syms-dev/ferrum/9656ab2"),
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
        let f = render(&answers(), &approved(Firmware::Uefi), std::slice::from_ref(&real), "abc").unwrap();
        assert!(f["flake.nix"].contains(&real));

        // ...while the template's actual placeholder is still caught.
        let mut bad = Files::new();
        bad.insert("flake.nix".into(), "\"ssh-ed25519 AAAA...CHANGE-ME\"".into());
        assert!(check_no_placeholders(&bad).is_err());
    }

    #[test]
    fn the_placeholder_check_names_the_file_and_the_sentinel() {
        let mut f = Files::new();
        f.insert("settings.json".into(), "{\"d\":\"example.invalid\"}".into());
        let err = check_no_placeholders(&f).unwrap_err().to_string();
        assert!(err.contains("settings.json") && err.contains("example.invalid"), "{err}");
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
        for expected in ["disko.nix", "flake.nix", "settings.json", "custom/media.nix"] {
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
}
