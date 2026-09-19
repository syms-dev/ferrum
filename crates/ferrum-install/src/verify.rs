//! What the installer checks on the finished machine, and what it tells the
//! operator (spec R6 A3-A8, R9 A4).
//!
//! The design doc's postmortem of the first real install found ten defects,
//! six invisible to the VM suite, and its conclusion was that *a test that
//! never acts like a human never finds what a human hits*. Three of those
//! six were found by typing a bare command at a shell. So the checks below
//! deliberately use the operator's own interface -- `ferrum-apply` resolved
//! from `PATH`, a `curl` against the real hostname -- rather than a store
//! path or an internal query.

use crate::inventory::Device;

/// One thing asserted on the finished host.
pub struct Check {
    pub what: &'static str,
    pub command: String,
    /// Substring the output must contain for the check to pass.
    pub expect: String,
}

/// The ownership `modules/core/bootstrap.nix` documents and `ferrumd`
/// depends on.
pub fn ownership_checks() -> Vec<Check> {
    vec![
        Check {
            what: "settings.json is writable by ferrumd",
            command: "stat -c '%U:%G %a' /etc/ferrum/settings.json".into(),
            expect: "root:ferrum 664".into(),
        },
        Check {
            what: "the secrets directory belongs to ferrumd",
            command: "stat -c '%U:%G %a' /etc/ferrum/secrets".into(),
            expect: "ferrum:ferrum 750".into(),
        },
        Check {
            what: "custom/ is never writable by ferrumd",
            command: "stat -c '%U:%G %a' /etc/ferrum/custom".into(),
            expect: "root:root 755".into(),
        },
        // The last line of defence for the defect that made this check
        // necessary. The installer writes a stand-in
        // hardware-configuration.nix so Tier 1 can evaluate before
        // anything is destroyed, and `{ ... }: { }` is a valid empty
        // module -- so a host that ends up with the stand-in boots, runs,
        // and passes every other check here while having NO initrd kernel
        // modules and no microcode. The transfer step refuses to send it;
        // this proves it did not arrive by some other route.
        Check {
            what: "the host has a real hardware configuration, not the stand-in",
            // `expect` is matched with `contains`, so a COUNT is the wrong
            // shape here: "0" is a substring of "10" and "100", and the
            // check would pass on a file full of sentinels. Emit a word
            // instead, and build the pattern from the one constant.
            // Three outcomes, not two. `grep -q ... && echo STANDIN || echo
            // REAL` prints REAL when the file is ABSENT, which is the one
            // state that must never pass -- the flake imports this file
            // unconditionally, so a missing one is a host that cannot
            // evaluate at all. The count form this replaced failed closed
            // on absence by accident; this does it on purpose.
            command: hardware_config_command("/etc/ferrum/hardware-configuration.nix"),
            expect: "REAL".into(),
        },
    ]
}

/// Builds the shell command behind the hardware-configuration check.
///
/// Split out so its THREE outcomes can be executed in a test. They were
/// not pinned: reverting this to the two-outcome form -- which prints
/// REAL for a file that does not exist -- passed the entire suite. The fix
/// was live and nothing held it, which is the third time that has happened
/// in this feature.
///
/// # Arguments
/// * `path` - the file to inspect on the target.
///
/// # Returns
/// A command printing exactly one of `REAL`, `STANDIN` or `MISSING`. None
/// is a substring of another, because `Check::expect` is matched with
/// `contains`.
pub fn hardware_config_command(path: &str) -> String {
    format!(
        "test -f {path} && {{ grep -q '{s}' {path} && echo STANDIN || echo REAL; }} || echo MISSING",
        s = crate::render::HARDWARE_CONFIG_SENTINEL
    )
}

/// The service and operator-interface checks.
///
/// `command -v ferrum-apply` is the important one and is not a formality:
/// on the first real install `ferrum-apply` existed only as a store path
/// inside a unit's `ExecStart`, so it was "command not found" at a shell.
/// Nothing that invokes it by store path or through systemd can catch that.
pub fn service_checks() -> Vec<Check> {
    vec![
        Check {
            what: "ferrumd is running",
            command: "systemctl is-active ferrumd".into(),
            expect: "active".into(),
        },
        Check {
            what: "ferrum-apply resolves as a bare command",
            command: "command -v ferrum-apply".into(),
            expect: "ferrum-apply".into(),
        },
    ]
}

/// Asserts Authelia is really in front of the apps.
///
/// `modules/proxy/nginx.nix` emits
/// `error_page 401 =302 https://auth.<domain>/?rd=$target_url`, so an
/// unauthenticated request returns a redirect. One line and one round trip,
/// and it is the earliest signal that would catch an app published with no
/// login at all.
pub fn auth_checks(domain: &str, apps: &[String], sso_enabled: bool) -> Vec<Check> {
    if !sso_enabled {
        return Vec::new();
    }
    let url = |host: String| {
        // Quoted at the sink even though `domain` is allowlist-validated on
        // the way in: the validator is three modules away from here.
        format!(
            "curl -sS -o /dev/null -w '%{{http_code}}' {}",
            crate::collect::sh_quote(&host)
        )
    };
    let mut checks = vec![Check {
        what: "the authentication host answers",
        command: url(format!("https://auth.{domain}/")),
        expect: "200".into(),
    }];
    for app in crate::sso::apps_left_open(apps) {
        checks.push(Check {
            what: "the app redirects to authentication",
            command: url(format!("https://{app}.{domain}/")),
            expect: "302".into(),
        });
    }
    checks
}

/// R9 A4's other half: when the operator **declined** SSO, the assertion
/// inverts. A published app with no authentication in front of it must
/// answer directly, and a redirect to an auth host would mean something
/// other than what they asked for is happening.
///
/// Returning no checks at all for the decline path -- as an earlier version
/// did -- meant the one configuration the operator had to type a phrase to
/// reach was the only one verified by nothing.
pub fn unauthenticated_checks(domain: &str, apps: &[String]) -> Vec<Check> {
    crate::sso::apps_left_open(apps)
        .into_iter()
        .map(|app| Check {
            what: "the app answers directly, as the operator accepted",
            command: format!(
                "curl -sS -o /dev/null -w '%{{http_code}}' {}",
                crate::collect::sh_quote(&format!("https://{app}.{domain}/"))
            ),
            expect: "200".into(),
        })
        .collect()
}

/// Asserts every data disk the operator kept is still mounted with the
/// filesystem the inventory recorded.
///
/// A data disk that failed to mount should be a loud failure now, not a
/// missing directory discovered weeks later when a library looks empty.
pub fn data_disk_checks(kept: &[&Device]) -> Vec<Check> {
    kept.iter()
        .filter_map(|d| {
            let by_id = d.by_id.as_deref()?;
            let fstype = d.children.iter().find_map(|c| c.fstype.as_deref())?;
            Some(Check {
                what: "a kept data disk is mounted",
                // Quoted like every other remote interpolation. On a resume
                // this value comes from a plain deserialize of
                // install-inventory.json, which sits in the operator's
                // writable bind mount -- so "it came from lsblk" is not
                // true on every path that reaches here.
                command: format!(
                    "findmnt -no FSTYPE --source {}",
                    crate::collect::sh_quote(by_id)
                ),
                expect: fstype.to_string(),
            })
        })
        .collect()
}

/// Where the two one-time credentials live.
///
/// There are two, not one. `ferrumd-setup-password` is generated by
/// `ensure_first_user` in `crates/ferrumd/src/auth.rs`;
/// `authelia-setup-password` is written by `ferrum-apply` during the very
/// stage-2 apply, whenever SSO is on. Printing only the first would report
/// success while leaving the operator locked out of every app.
pub fn credential_paths(sso_enabled: bool) -> Vec<(&'static str, &'static str)> {
    let mut v = vec![(
        "ferrum UI",
        "/var/lib/ferrum/daemon/ferrumd-setup-password",
    )];
    if sso_enabled {
        v.push((
            "single sign-on",
            "/var/lib/authelia-main/authelia-setup-password",
        ));
    }
    v
}

#[cfg(test)]
mod tests {
    /// SEC-L-N5. Executes the real command against real files, because the
    /// bug being guarded is a SHELL semantics bug -- `grep -q ... && A ||
    /// B` prints B when the file is absent -- and no amount of reading the
    /// string catches that.
    #[test]
    fn the_hardware_config_check_distinguishes_real_standin_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hardware-configuration.nix");
        let run = || {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(super::hardware_config_command(path.to_str().unwrap()))
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };

        // Absent -- the state that must never pass. The two-outcome form
        // this replaced printed REAL here.
        assert_eq!(run(), "MISSING");

        let mut files = crate::render::Files::new();
        crate::render::insert_hardware_config_placeholder(&mut files);
        std::fs::write(&path, &files["hardware-configuration.nix"]).unwrap();
        assert_eq!(run(), "STANDIN");

        std::fs::write(&path, "{ ... }:\n{ boot.initrd.availableKernelModules = [ \"nvme\" ]; }\n").unwrap();
        assert_eq!(run(), "REAL");

        // `expect` is matched with `contains`, so the three words must not
        // shadow each other.
        for (a, b) in [("REAL", "STANDIN"), ("REAL", "MISSING"), ("STANDIN", "MISSING")] {
            assert!(!b.contains(a) && !a.contains(b), "{a} / {b}");
        }
    }

    use super::*;
    use crate::inventory::Filesystem;

    fn disk(by_id: &str, fstype: Option<&str>) -> Device {
        Device {
            name: "sdb".into(),
            size: "3.6T".into(),
            model: None,
            serial: Some("S".into()),
            by_id: Some(by_id.into()),
            children: fstype
                .map(|f| {
                    vec![Filesystem {
                        name: "sdb1".into(),
                        fstype: Some(f.into()),
                        mountpoint: None,
                             by_id: None,
                         }]
                })
                .unwrap_or_default(),
        }
    }

    #[test]
    fn the_ownership_checks_match_what_bootstrap_nix_documents() {
        let c = ownership_checks();
        assert_eq!(c[0].expect, "root:ferrum 664");
        assert_eq!(c[1].expect, "ferrum:ferrum 750");
        assert_eq!(c[2].expect, "root:root 755");
    }

    /// Three of the first install's ten defects were found by typing a bare
    /// command. Nothing that goes through systemd or a store path can.
    #[test]
    fn ferrum_apply_is_checked_as_a_bare_command_not_a_store_path() {
        let c = service_checks();
        let check = c.iter().find(|c| c.what.contains("bare command")).unwrap();
        assert_eq!(check.command, "command -v ferrum-apply");
        assert!(!check.command.contains("/nix/store"));
        assert!(!check.command.contains("systemctl"));
    }

    #[test]
    fn auth_checks_expect_a_redirect_for_every_unprotected_app() {
        let apps = vec!["sonarr".to_string(), "plex".to_string()];
        let c = auth_checks("thesyms.ca", &apps, true);
        assert!(c.iter().any(|c| c.command.contains("auth.thesyms.ca")));
        let sonarr = c.iter().find(|c| c.command.contains("sonarr.thesyms.ca")).unwrap();
        assert_eq!(sonarr.expect, "302");
        // plex carries its own login, so ferrum does not put Authelia in
        // front of it and a redirect would be the wrong expectation.
        assert!(!c.iter().any(|c| c.command.contains("plex.thesyms.ca")));
    }

    /// R9 A4: declining does not mean verifying nothing -- it means the
    /// assertion inverts.
    #[test]
    fn declining_sso_inverts_the_assertion_rather_than_skipping_it() {
        let apps = vec!["sonarr".to_string(), "plex".to_string()];
        assert!(auth_checks("d.com", &apps, false).is_empty());

        let inverted = unauthenticated_checks("d.com", &apps);
        let sonarr = inverted.iter().find(|c| c.command.contains("sonarr")).unwrap();
        assert_eq!(sonarr.expect, "200", "a redirect would mean SSO is on after all");
        assert!(
            !inverted.iter().any(|c| c.command.contains("plex")),
            "plex has its own login and is not part of this claim"
        );
    }

    #[test]
    fn remote_urls_are_shell_quoted_at_the_sink() {
        let c = auth_checks("d.com", &["sonarr".into()], true);
        assert!(c.iter().all(|c| c.command.contains("'https://")), "{:?}", c[0].command);
    }

    #[test]
    fn a_kept_disk_is_checked_for_its_recorded_filesystem() {
        let d = disk("/dev/disk/by-id/ata-DATA_1", Some("ext4"));
        let c = data_disk_checks(&[&d]);
        assert_eq!(c.len(), 1);
        assert!(c[0].command.contains("ata-DATA_1"));
        assert!(c[0].command.contains("'/dev/disk/by-id/ata-DATA_1'"), "must be quoted: {}", c[0].command);
        assert_eq!(c[0].expect, "ext4");
    }

    #[test]
    fn a_disk_with_no_recorded_filesystem_is_not_checked() {
        let d = disk("/dev/disk/by-id/ata-EMPTY", None);
        assert!(data_disk_checks(&[&d]).is_empty());
    }

    /// Reporting only ferrumd's password would claim success while leaving
    /// the operator locked out of every app.
    #[test]
    fn both_credentials_are_reported_when_sso_is_on() {
        let c = credential_paths(true);
        assert_eq!(c.len(), 2);
        assert!(c.iter().any(|(_, p)| p.contains("ferrumd-setup-password")));
        assert!(c.iter().any(|(_, p)| p.contains("authelia-setup-password")));
    }

    #[test]
    fn only_ferrumds_credential_is_reported_without_sso() {
        assert_eq!(credential_paths(false).len(), 1);
    }
}
