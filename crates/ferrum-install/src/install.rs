//! The destructive step, and the transfer that makes stage 2 possible.
//!
//! `nixos-anywhere` kexecs the target into an installer environment, runs
//! disko, builds the closure **on the target** (`--build-on remote`, which
//! is why an aarch64 operator machine can install an x86_64 host at all),
//! installs, and reboots.
//!
//! `--extra-files` is not an optimisation here. Nothing in the module tree
//! puts the host flake at `/etc/ferrum`: `modules/core/bootstrap.nix`
//! creates only the directory, a seeded `settings.json`, `secrets/` and
//! `custom/`, and `nixos-anywhere` installs a closure rather than a source
//! tree. Without this transfer `ferrum-apply` cannot resolve
//! `FERRUM_FLAKE_REF` (`/etc/ferrum#nixosConfigurations.<hostname>`) and
//! stage 2 cannot run at all. `docs/INSTALL.md` has the same hole: its
//! Step 8 tells the operator to edit "the host flake repo" on the target,
//! which no earlier step ever puts there.

use std::path::{Path, PathBuf};

/// Builds the `nixos-anywhere` argument list.
///
/// `--generate-hardware-config` is always used, so the target is not
/// required to already run NixOS -- which removes `docs/INSTALL.md`'s
/// Step 3 fork entirely.
pub fn args(target: &str, hostname: &str, extra_files: &Path, port: u16) -> Vec<String> {
    let mut a = vec![
        "--flake".into(),
        format!(".#{hostname}"),
        "--build-on".into(),
        "remote".into(),
        "--generate-hardware-config".into(),
        "nixos-generate-config".into(),
        "./hardware-configuration.nix".into(),
        "--extra-files".into(),
        extra_files.display().to_string(),
    ];
    if port != 22 {
        a.push("--ssh-port".into());
        a.push(port.to_string());
    }
    a.push(target.into());
    a
}

/// Lays out the tree `--extra-files` copies onto the new root.
///
/// The host repository lands at `/etc/ferrum`, `.git` included: the flake
/// must be a git repository with every file tracked, because Nix silently
/// ignores untracked files inside a git tree.
///
/// # Errors
/// Any filesystem failure.
pub fn stage_extra_files(scratch: &Path, host_dir: &Path) -> anyhow::Result<PathBuf> {
    let root = scratch.join("extra-files");
    let dest = root.join("etc/ferrum");
    std::fs::create_dir_all(&dest)?;
    copy_tree(host_dir, &dest)?;
    Ok(root)
}

fn copy_tree(from: &Path, to: &Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        let src = entry.path();
        let dst = to.join(&name);

        // The install record is the OPERATOR's, not the host's: it tracks
        // this run's progress and has no meaning on the installed machine.
        if name == "install-state.json"
            || name == "install-state.json.tmp"
            || name == crate::collect::KNOWN_HOSTS
        {
            continue;
        }
        // Refuse rather than follow. `file_type()` does not follow a
        // symlink, but the `fs::copy` below WOULD dereference one -- so a
        // link planted in the operator's own bind mount (by a compromised
        // earlier run, or another local process) could copy the content of
        // anything readable, including their private SSH key, onto the new
        // host. render.rs never produces a symlink, so any symlink here is
        // anomalous by construction and worth stopping for.
        if entry.file_type()?.is_symlink() {
            anyhow::bail!(
                "{} is a symlink. Nothing this installer generates is a \
                 symlink, so refusing to copy it rather than following it to \
                 whatever it points at.",
                src.display()
            );
        }
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&dst)?;
            copy_tree(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

/// The name nixos-anywhere writes, and the generated flake imports.
pub const HARDWARE_CONFIG: &str = "hardware-configuration.nix";

/// Commands that put the generated hardware configuration into the
/// target's `/etc/ferrum` and commit it there.
///
/// **This is a separate step from `--extra-files`, and it has to be.**
/// `stage_extra_files` snapshots the host repository into a static tree
/// *before* `nixos-anywhere` is invoked, while
/// `--generate-hardware-config` writes `hardware-configuration.nix`
/// *during* that same invocation. So the file cannot possibly be in the
/// transferred tree, no matter how nixos-anywhere orders its internal
/// steps -- and the generated `flake.nix` imports it unconditionally.
///
/// Left out, `/etc/ferrum#nixosConfigurations.<hostname>` fails to
/// evaluate, which breaks **every** later `ferrum-apply apply` including
/// the stage-2 apply this same run performs. The manual path in
/// `docs/INSTALL.md` avoided this only because it generated and committed
/// the file in a step of its own before building the extra-files tree; the
/// single-invocation design removed that ordering without replacing what
/// it provided.
pub fn hardware_config_commands() -> Vec<String> {
    vec![
        format!("cat > /etc/ferrum/{HARDWARE_CONFIG}"),
        format!(
            "cd /etc/ferrum && git add {HARDWARE_CONFIG} && \
             (git diff --cached --quiet || git -c user.name=ferrum-install \
              -c user.email=ferrum-install@localhost commit -q -m \
              'ferrum-install: hardware configuration')"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_build_happens_on_the_target() {
        let a = args("root@saltbox", "saltbox", Path::new("/tmp/x"), 22);
        let i = a.iter().position(|x| x == "--build-on").unwrap();
        assert_eq!(a[i + 1], "remote", "an aarch64 operator machine cannot build x86_64");
    }

    /// Always used, so the target need not already run NixOS.
    #[test]
    fn the_hardware_config_is_always_generated() {
        let a = args("root@saltbox", "saltbox", Path::new("/tmp/x"), 22);
        assert!(a.contains(&"--generate-hardware-config".to_string()));
        assert!(a.contains(&"./hardware-configuration.nix".to_string()));
    }

    #[test]
    fn the_flake_attribute_is_the_hostname() {
        let a = args("root@saltbox", "saltbox", Path::new("/tmp/x"), 22);
        assert!(a.contains(&".#saltbox".to_string()));
        assert_eq!(a.last().unwrap(), "root@saltbox");
    }

    /// Without this the host flake never reaches the target and stage 2
    /// cannot run.
    #[test]
    fn the_host_repository_is_transferred() {
        let a = args("root@saltbox", "saltbox", Path::new("/tmp/extra"), 22);
        let i = a.iter().position(|x| x == "--extra-files").unwrap();
        assert_eq!(a[i + 1], "/tmp/extra");
    }

    #[test]
    fn a_non_default_port_reaches_nixos_anywhere() {
        let a = args("root@h", "h", Path::new("/x"), 2222);
        let i = a.iter().position(|x| x == "--ssh-port").unwrap();
        assert_eq!(a[i + 1], "2222");
        assert_eq!(a.last().unwrap(), "root@h", "the target stays last");
    }

    /// The common case must not grow a redundant flag.
    #[test]
    fn port_22_adds_no_flag() {
        assert!(!args("root@h", "h", Path::new("/x"), 22).contains(&"--ssh-port".to_string()));
    }

    #[test]
    fn the_staged_tree_puts_the_repository_at_etc_ferrum_with_its_git_dir() {
        let scratch = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::write(host.path().join("flake.nix"), "{}").unwrap();
        std::fs::create_dir_all(host.path().join("custom")).unwrap();
        std::fs::write(host.path().join("custom/media.nix"), "{}").unwrap();
        std::fs::create_dir_all(host.path().join(".git")).unwrap();
        std::fs::write(host.path().join(".git/HEAD"), "ref: refs/heads/main").unwrap();

        let root = stage_extra_files(scratch.path(), host.path()).unwrap();
        assert!(root.join("etc/ferrum/flake.nix").is_file());
        assert!(root.join("etc/ferrum/custom/media.nix").is_file());
        assert!(
            root.join("etc/ferrum/.git/HEAD").is_file(),
            "Nix ignores untracked files, so .git must travel with the tree"
        );
    }

    /// The file nixos-anywhere generates DURING its run cannot be in the
    /// tree staged BEFORE it. Proving that here so the separate transfer
    /// step is never mistaken for redundant.
    #[test]
    fn the_staged_tree_cannot_contain_the_generated_hardware_config() {
        let scratch = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::write(host.path().join("flake.nix"), "./hardware-configuration.nix").unwrap();

        // The state of host_dir at staging time: nixos-anywhere has not
        // run, so the file does not exist yet.
        let root = stage_extra_files(scratch.path(), host.path()).unwrap();
        assert!(
            !root.join("etc/ferrum").join(HARDWARE_CONFIG).exists(),
            "if this ever passes, the separate transfer step may be removable"
        );
        // ...and the flake that DID travel imports it unconditionally.
        let flake = std::fs::read_to_string(root.join("etc/ferrum/flake.nix")).unwrap();
        assert!(flake.contains("hardware-configuration.nix"));
    }

    #[test]
    fn the_hardware_config_is_written_then_committed_on_the_target() {
        let c = hardware_config_commands();
        assert!(c[0].contains("cat > /etc/ferrum/hardware-configuration.nix"));
        assert!(c[1].contains("git add hardware-configuration.nix"));
        // A resumed run must not fail because the first attempt committed.
        assert!(c[1].contains("git diff --cached --quiet ||"));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_host_directory_is_refused_not_followed() {
        let scratch = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        let secret = host.path().join("pretend-private-key");
        std::fs::write(&secret, "PRIVATE").unwrap();
        std::os::unix::fs::symlink(&secret, host.path().join("innocent.nix")).unwrap();

        let err = stage_extra_files(scratch.path(), host.path()).unwrap_err().to_string();
        assert!(err.contains("is a symlink"), "{err}");
    }

    #[test]
    fn the_operators_known_hosts_is_not_copied_to_the_host() {
        let scratch = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::write(host.path().join("flake.nix"), "{}").unwrap();
        std::fs::write(host.path().join("known_hosts"), "target ssh-ed25519 AAA").unwrap();
        let root = stage_extra_files(scratch.path(), host.path()).unwrap();
        assert!(!root.join("etc/ferrum/known_hosts").exists());
    }

    /// The install record tracks this RUN, not the host, and would be
    /// meaningless (and confusing) on the installed machine.
    #[test]
    fn the_operators_install_record_is_not_copied_to_the_host() {
        let scratch = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::write(host.path().join("flake.nix"), "{}").unwrap();
        std::fs::write(host.path().join("install-state.json"), "{}").unwrap();

        let root = stage_extra_files(scratch.path(), host.path()).unwrap();
        assert!(root.join("etc/ferrum/flake.nix").is_file());
        assert!(!root.join("etc/ferrum/install-state.json").exists());
    }
}
