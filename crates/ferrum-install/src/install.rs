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
pub fn args(
    target: &str,
    hostname: &str,
    extra_files: &Path,
    port: u16,
    auth: &crate::preconditions::SshAuth,
) -> Vec<String> {
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

    // THE credential, passed explicitly. Without it nixos-anywhere cannot
    // authenticate to the target AT ALL, and it does not fail -- it retries
    // ssh-copy-id forever.
    //
    // This is not a hypothetical. It burned two CI runs at three hours
    // each and one real install: the inventory phase works, because
    // collect.rs passes `-i` to its own ssh, so everything looks healthy
    // right up to the destructive step. Then nixos-anywhere spawns ITS own
    // ssh and ssh-copy-id, which know nothing about `--ssh-dir`, fall back
    // to ~/.ssh inside the container -- which is empty, because the
    // operator's keys are mounted at /ssh -- and loop on "Permission
    // denied (publickey,keyboard-interactive)" with no timeout.
    //
    // The tell in the log is the line before the first denial:
    // "Identity file /tmp/tmp.XXXX/nixos-anywhere not accessible".
    //
    // An agent is passed through the environment rather than argv, so
    // there is nothing to add for that case -- SSH_AUTH_SOCK is already
    // inherited by the child.
    if let crate::preconditions::SshAuth::Key(path) = auth {
        a.push("-i".into());
        a.push(path.display().to_string());
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
            || name == "install-inventory.json"
            || name == "install-inventory.json.tmp"
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
/// **The target does not need git, and must not be assumed to have it.**
///
/// This used to run `git add && git commit` over SSH on the target. A real
/// install failed there with "bash: line 1: git: command not found" --
/// nothing in the module tree put git on a ferrum host. Worse, the failure
/// left the REAL hardware-configuration.nix written into /etc/ferrum but
/// UNTRACKED, which for Nix means it does not exist: the host kept a flake
/// importing a file Nix could not see.
///
/// git is being added to the host for other reasons (an operator editing
/// custom/ needs it), but this step must not DEPEND on that, because it is
/// the step that has to work before the host can be rebuilt to gain it.
///
/// So the commit happens on the OPERATOR's side, where git is guaranteed
/// (this binary is wrapped with it), and the resulting objects travel as a
/// tar of `.git` plus the file itself. base64 because the payload is
/// binary and the transport takes a string.
pub fn extract_into_etc_ferrum() -> String {
    "base64 -d | tar -C /etc/ferrum -xf -".to_string()
}

/// Commits everything currently in the OPERATOR's copy.
///
/// # Arguments
/// * `host_dir` - the operator's host repository.
///
/// # Errors
/// If git fails. Its output is included, because "git failed" on its own
/// has wasted enough time in this feature already.
pub fn commit_all(host_dir: &Path, message: &str) -> anyhow::Result<()> {
    let git = |args: &[&str]| -> anyhow::Result<std::process::Output> {
        let out = std::process::Command::new("git")
            .current_dir(host_dir)
            .args(args)
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "git {} failed in {}: {}",
                args.join(" "),
                host_dir.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(out)
    };
    git(&["add", "-A"])?;
    // Nothing staged means it was already committed -- a resume, which is
    // not an error.
    if git(&["diff", "--cached", "--quiet"]).is_err() {
        git(&[
            "-c",
            "user.name=ferrum-install",
            "-c",
            "user.email=ferrum-install@localhost",
            "commit",
            "-q",
            "-m",
            message,
        ])?;
    }
    Ok(())
}

/// Tars `.git` and the hardware configuration, base64-encoded for a
/// string transport.
///
/// # Arguments
/// * `host_dir` - the operator's host repository, already committed.
///
/// # Errors
/// If tar or base64 fails.
pub fn tar_payload(host_dir: &Path, paths: &[&str]) -> anyhow::Result<String> {
    let mut cmd = std::process::Command::new("tar");
    cmd.arg("-C").arg(host_dir).arg("-cf").arg("-");
    for path in paths {
        cmd.arg(path);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        anyhow::bail!(
            "tar of {:?} in {} failed: {}",
            paths,
            host_dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(base64_encode(&out.stdout))
}

/// Minimal base64, so this does not pull a dependency for one call.
fn base64_encode(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::preconditions::SshAuth;

    /// The bug that hung two 3-hour CI runs and one real install.
    ///
    /// nixos-anywhere spawns its own ssh and ssh-copy-id. They do not know
    /// about `--ssh-dir`, so without an explicit `-i` they look in ~/.ssh
    /// inside the container -- empty -- and nixos-anywhere then retries
    /// ssh-copy-id FOREVER rather than failing.
    ///
    /// The inventory phase passing proves nothing about this: collect.rs
    /// passes `-i` to its own ssh, so the whole run looks healthy right up
    /// to the destructive step.
    ///
    /// Mutation check: drop the `-i` push and this fails.
    #[test]
    fn the_operators_key_is_handed_to_nixos_anywhere() {
        let key = std::path::PathBuf::from("/ssh/id_ed25519");
        let a = args(
            "root@saltbox",
            "ferrum",
            std::path::Path::new("/tmp/extra"),
            22,
            &SshAuth::Key(key.clone()),
        );
        let i = a.iter().position(|x| x == "-i").expect(
            "without -i, nixos-anywhere cannot authenticate and loops on ssh-copy-id forever",
        );
        assert_eq!(a[i + 1], "/ssh/id_ed25519");
        // The target stays last, where nixos-anywhere expects it.
        assert_eq!(a.last().unwrap(), "root@saltbox");
    }

    /// An agent needs no argument: SSH_AUTH_SOCK is inherited by the child.
    #[test]
    fn an_agent_needs_no_identity_argument() {
        let a = args(
            "root@saltbox",
            "ferrum",
            std::path::Path::new("/tmp/extra"),
            22,
            &SshAuth::Agent(std::path::PathBuf::from("/tmp/agent.sock")),
        );
        assert!(!a.contains(&"-i".to_string()), "{a:?}");
        assert_eq!(a.last().unwrap(), "root@saltbox");
    }

    /// SEC-M5, asserted through the real git history rather than the file
    /// list.
    ///
    /// `copy_tree` excludes the operator's files, and there was a test for
    /// that. But `.git` ships to the host by design, and `write_repo` runs
    /// `git add -A` -- so anything committed BEFORE the copy travels inside
    /// the history regardless, and the exclusion proves nothing. This
    /// reaches for the content the way an attacker on the installed host
    /// would: `git show HEAD:<file>` against the staged `.git`.
    #[test]
    fn the_operators_own_files_are_unreachable_in_the_shipped_git_history() {
        use std::process::Command;
        let host = tempfile::tempdir().unwrap();
        let h = host.path();

        let mut files = crate::render::Files::new();
        files.insert("flake.nix".into(), "{ }\n".into());
        crate::render::insert_hardware_config_placeholder(&mut files);
        // The .gitignore is what has to do the work.
        files.insert(
            ".gitignore".into(),
            "install-state.json\ninstall-inventory.json\nknown_hosts\n".into(),
        );
        crate::render::write_repo(h, &files).unwrap();

        // Written by the installer into the same directory, then committed
        // again -- exactly the real ordering.
        std::fs::write(h.join("install-inventory.json"), "{\"secret\":\"disks\"}").unwrap();
        std::fs::write(
            h.join(crate::collect::KNOWN_HOSTS),
            "saltbox ssh-ed25519 AAAA",
        )
        .unwrap();
        crate::render::write_repo(h, &files).unwrap();

        let scratch = tempfile::tempdir().unwrap();
        let root = stage_extra_files(scratch.path(), h).unwrap();
        let git_dir = root.join("etc/ferrum/.git");
        assert!(
            git_dir.is_dir(),
            ".git must travel, or the host cannot evaluate"
        );

        for name in ["install-inventory.json", "known_hosts"] {
            // Not in the working tree...
            assert!(
                !root.join("etc/ferrum").join(name).exists(),
                "{name} was copied into the staged tree"
            );
            // ...and not reachable through the history that DID travel.
            let out = Command::new("git")
                .arg("--git-dir")
                .arg(&git_dir)
                .arg("show")
                .arg(format!("HEAD:{name}"))
                .output()
                .expect("git must be available");
            assert!(
                !out.status.success(),
                "{name} is readable from the shipped .git history: {}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
    }

    use super::*;

    #[test]
    fn the_build_happens_on_the_target() {
        let a = args(
            "root@saltbox",
            "saltbox",
            Path::new("/tmp/x"),
            22,
            &SshAuth::Key(std::path::PathBuf::from("/ssh/id_ed25519")),
        );
        let i = a.iter().position(|x| x == "--build-on").unwrap();
        assert_eq!(
            a[i + 1],
            "remote",
            "an aarch64 operator machine cannot build x86_64"
        );
    }

    /// Always used, so the target need not already run NixOS.
    #[test]
    fn the_hardware_config_is_always_generated() {
        let a = args(
            "root@saltbox",
            "saltbox",
            Path::new("/tmp/x"),
            22,
            &SshAuth::Key(std::path::PathBuf::from("/ssh/id_ed25519")),
        );
        assert!(a.contains(&"--generate-hardware-config".to_string()));
        assert!(a.contains(&"./hardware-configuration.nix".to_string()));
    }

    #[test]
    fn the_flake_attribute_is_the_hostname() {
        let a = args(
            "root@saltbox",
            "saltbox",
            Path::new("/tmp/x"),
            22,
            &SshAuth::Key(std::path::PathBuf::from("/ssh/id_ed25519")),
        );
        assert!(a.contains(&".#saltbox".to_string()));
        assert_eq!(a.last().unwrap(), "root@saltbox");
    }

    /// Without this the host flake never reaches the target and stage 2
    /// cannot run.
    #[test]
    fn the_host_repository_is_transferred() {
        let a = args(
            "root@saltbox",
            "saltbox",
            Path::new("/tmp/extra"),
            22,
            &SshAuth::Key(std::path::PathBuf::from("/ssh/id_ed25519")),
        );
        let i = a.iter().position(|x| x == "--extra-files").unwrap();
        assert_eq!(a[i + 1], "/tmp/extra");
    }

    #[test]
    fn a_non_default_port_reaches_nixos_anywhere() {
        let a = args(
            "root@h",
            "h",
            Path::new("/x"),
            2222,
            &SshAuth::Key(std::path::PathBuf::from("/ssh/id_ed25519")),
        );
        let i = a.iter().position(|x| x == "--ssh-port").unwrap();
        assert_eq!(a[i + 1], "2222");
        assert_eq!(a.last().unwrap(), "root@h", "the target stays last");
    }

    /// The common case must not grow a redundant flag.
    #[test]
    fn port_22_adds_no_flag() {
        assert!(!args(
            "root@h",
            "h",
            Path::new("/x"),
            22,
            &SshAuth::Key(std::path::PathBuf::from("/ssh/id_ed25519"))
        )
        .contains(&"--ssh-port".to_string()));
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

    /// The staged tree carries only the PLACEHOLDER hardware config, never
    /// a real one -- which is why the separate transfer step exists.
    ///
    /// This test used to assert the file was ABSENT from the staged tree,
    /// and it built its own `host_dir` containing just a flake, so it kept
    /// passing after `render()` started writing the placeholder
    /// unconditionally. The property it claimed had become false for real
    /// render output, and it would not have caught shipping the placeholder
    /// to the host. It now asserts the thing that is actually true and
    /// actually load-bearing: what travels is still the stand-in.
    #[test]
    fn the_staged_tree_carries_only_the_placeholder_hardware_config() {
        let scratch = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        std::fs::write(
            host.path().join("flake.nix"),
            "./hardware-configuration.nix",
        )
        .unwrap();
        // Exactly what render() writes at this point in the run.
        let mut files = crate::render::Files::new();
        crate::render::insert_hardware_config_placeholder(&mut files);
        std::fs::write(host.path().join(HARDWARE_CONFIG), &files[HARDWARE_CONFIG]).unwrap();

        let root = stage_extra_files(scratch.path(), host.path()).unwrap();
        let staged = std::fs::read_to_string(root.join("etc/ferrum").join(HARDWARE_CONFIG))
            .expect("the placeholder travels -- the flake imports it unconditionally");
        assert!(
            staged.contains(crate::render::HARDWARE_CONFIG_SENTINEL),
            "the staged tree must carry the STAND-IN, never a real hardware \
             configuration: nixos-anywhere generates the real one during its \
             own run, which is after this tree is built. If this ever fails, \
             something is staging a real config and the transfer step's \
             sentinel check will reject the install."
        );
        let flake = std::fs::read_to_string(root.join("etc/ferrum/flake.nix")).unwrap();
        assert!(flake.contains("hardware-configuration.nix"));
    }

    /// The target must not be assumed to have git. A real install failed
    /// with "bash: line 1: git: command not found" and left the real
    /// hardware configuration UNTRACKED -- which, for Nix, is the same as
    /// absent.
    ///
    /// Mutation check: put `git` back in the remote command and this
    /// fails.
    #[test]
    fn the_transfer_does_not_require_git_on_the_target() {
        let cmd = extract_into_etc_ferrum();
        assert!(!cmd.contains("git"), "the target may not have git: {cmd}");
        assert!(cmd.contains("tar"), "{cmd}");
        assert!(cmd.contains("base64 -d"), "the payload is binary: {cmd}");
        assert!(cmd.contains("-C /etc/ferrum"), "{cmd}");
    }

    /// The commit happens on the operator's side, and a resume must not
    /// fail because the first attempt already committed.
    #[test]
    fn committing_the_hardware_config_is_idempotent() {
        let host = tempfile::tempdir().unwrap();
        let mut files = crate::render::Files::new();
        files.insert("flake.nix".into(), "{ }\n".into());
        crate::render::write_repo(host.path(), &files).unwrap();
        std::fs::write(
            host.path().join(HARDWARE_CONFIG),
            "{ ... }: { boot.initrd.availableKernelModules = [ \"ahci\" ]; }\n",
        )
        .unwrap();

        commit_all(host.path(), "test").expect("first commit");
        commit_all(host.path(), "test").expect("a resume must not fail here");

        // And the payload really carries the objects plus the file.
        let payload = tar_payload(host.path(), &[".git", HARDWARE_CONFIG]).unwrap();
        assert!(!payload.is_empty());
        assert!(
            payload
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c)),
            "payload must be transport-safe base64"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_in_the_host_directory_is_refused_not_followed() {
        let scratch = tempfile::tempdir().unwrap();
        let host = tempfile::tempdir().unwrap();
        let secret = host.path().join("pretend-private-key");
        std::fs::write(&secret, "PRIVATE").unwrap();
        std::os::unix::fs::symlink(&secret, host.path().join("innocent.nix")).unwrap();

        let err = stage_extra_files(scratch.path(), host.path())
            .unwrap_err()
            .to_string();
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
