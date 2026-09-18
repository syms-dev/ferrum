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

fn disko(os_disk: &str, firmware: Firmware) -> String {
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
    files.insert("disko.nix".into(), disko(os_disk, approved.firmware));
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
