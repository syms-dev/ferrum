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
pub fn args(target: &str, hostname: &str, extra_files: &Path) -> Vec<String> {
    vec![
        "--flake".into(),
        format!(".#{hostname}"),
        "--build-on".into(),
        "remote".into(),
        "--generate-hardware-config".into(),
        "nixos-generate-config".into(),
        "./hardware-configuration.nix".into(),
        "--extra-files".into(),
        extra_files.display().to_string(),
        target.into(),
    ]
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
        if name == "install-state.json" || name == "install-state.json.tmp" {
            continue;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_build_happens_on_the_target() {
        let a = args("root@saltbox", "saltbox", Path::new("/tmp/x"));
        let i = a.iter().position(|x| x == "--build-on").unwrap();
        assert_eq!(a[i + 1], "remote", "an aarch64 operator machine cannot build x86_64");
    }

    /// Always used, so the target need not already run NixOS.
    #[test]
    fn the_hardware_config_is_always_generated() {
        let a = args("root@saltbox", "saltbox", Path::new("/tmp/x"));
        assert!(a.contains(&"--generate-hardware-config".to_string()));
        assert!(a.contains(&"./hardware-configuration.nix".to_string()));
    }

    #[test]
    fn the_flake_attribute_is_the_hostname() {
        let a = args("root@saltbox", "saltbox", Path::new("/tmp/x"));
        assert!(a.contains(&".#saltbox".to_string()));
        assert_eq!(a.last().unwrap(), "root@saltbox");
    }

    /// Without this the host flake never reaches the target and stage 2
    /// cannot run.
    #[test]
    fn the_host_repository_is_transferred() {
        let a = args("root@saltbox", "saltbox", Path::new("/tmp/extra"));
        let i = a.iter().position(|x| x == "--extra-files").unwrap();
        assert_eq!(a[i + 1], "/tmp/extra");
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
