//! Everything `ferrum-install` checks *before* it contacts the target.
//!
//! The ordering is the point. This installer's next steps are destructive
//! and, once `nixos-anywhere` has kexec'd, only partly reversible -- so
//! every condition that can be decided from the operator's own machine is
//! decided here, while a failure still costs nothing. A missing bind mount
//! discovered after the disk is gone is a different kind of problem to the
//! same mount discovered before a single packet is sent.
//!
//! Nothing in this module opens a socket, and the tests assert the things
//! that would otherwise be easy to regress: that the SSH private key is
//! never *read*, only located, and that each refusal names the specific
//! thing that is wrong rather than failing generically.

use std::path::{Path, PathBuf};

/// Where the installer will write the host repository. It is a bind mount
/// from the operator's machine (`-v ~/ferrum-host:/host`) precisely so the
/// repository outlives the container -- the operator owns it afterwards
/// and needs it for every later `ferrum-apply apply`.
pub const DEFAULT_HOST_DIR: &str = "/host";

/// The read-only mount the operator's SSH material arrives on
/// (`-v ~/.ssh:/ssh:ro`).
pub const DEFAULT_SSH_DIR: &str = "/ssh";

/// Private key filenames worth looking for, in the order OpenSSH itself
/// prefers them.
const KEY_NAMES: &[&str] = &["id_ed25519", "id_ecdsa", "id_rsa"];

/// A parsed `user@host` install target.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub user: String,
    pub host: String,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.user, self.host)
    }
}

/// How the installer will authenticate to the target.
///
/// The agent is preferred over a key file, and not only as a convenience:
/// a passphrase-protected key cannot be used non-interactively, so an
/// operator with an encrypted key and a running agent must get the agent.
#[derive(Debug, PartialEq, Eq)]
pub enum SshAuth {
    /// Forwarded `SSH_AUTH_SOCK`.
    Agent(PathBuf),
    /// A private key file on the read-only mount. Only ever its *path* --
    /// this process does not read the bytes.
    Key(PathBuf),
}

#[derive(Debug)]
pub struct Preconditions {
    pub target: Target,
    pub host_dir: PathBuf,
    pub ssh_auth: SshAuth,
}

/// Parses `user@host`.
///
/// # Errors
/// Returns an error when the target has no `@`, either side is empty, or
/// the user is not `root`. nixos-anywhere needs root on the target, and a
/// non-root target fails much later with a far less obvious message.
pub fn parse_target(raw: &str) -> anyhow::Result<Target> {
    let (user, host) = raw
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("target {raw:?} is not user@host -- try root@{raw}"))?;
    if user.is_empty() || host.is_empty() {
        anyhow::bail!("target {raw:?} is not user@host");
    }
    if host.contains('@') {
        anyhow::bail!("target {raw:?} has more than one '@'");
    }
    if user != "root" {
        anyhow::bail!(
            "target {raw:?} must connect as root -- nixos-anywhere replaces the \
             whole OS and needs root on the target"
        );
    }
    Ok(Target {
        user: user.to_string(),
        host: host.to_string(),
    })
}

/// Confirms the host-repository bind mount is present and usable.
///
/// # Errors
/// Names the missing or wrong mount explicitly, because the likeliest
/// cause is a forgotten `-v` on the `docker run` line and a generic
/// "cannot write" sends the operator looking in the wrong place.
pub fn check_host_dir(host_dir: &Path) -> anyhow::Result<()> {
    if !host_dir.exists() {
        anyhow::bail!(
            "{} does not exist -- mount the directory that will hold your host \
             repository, e.g. -v ~/ferrum-host:{}",
            host_dir.display(),
            host_dir.display()
        );
    }
    if !host_dir.is_dir() {
        anyhow::bail!("{} is not a directory", host_dir.display());
    }
    let meta = std::fs::metadata(host_dir)?;
    if meta.permissions().readonly() {
        anyhow::bail!(
            "{} is mounted read-only -- the host repository is written here and \
             must outlive the container",
            host_dir.display()
        );
    }
    Ok(())
}

/// Locates SSH credentials without reading them.
///
/// Prefers a forwarded agent, then the first private key present on the
/// read-only mount. **The key's contents are never read** -- only its
/// existence is checked, so that the private key never enters this
/// process's memory, its logs, or anything it writes. `ssh` itself reads
/// the file later, from the read-only mount.
///
/// # Errors
/// Returns an error when neither an agent nor a key is available, listing
/// the filenames that were looked for.
pub fn find_ssh_auth(ssh_dir: &Path, agent_sock: Option<&str>) -> anyhow::Result<SshAuth> {
    if let Some(sock) = agent_sock.filter(|s| !s.is_empty()) {
        let path = PathBuf::from(sock);
        if path.exists() {
            return Ok(SshAuth::Agent(path));
        }
    }
    for name in KEY_NAMES {
        let candidate = ssh_dir.join(name);
        // symlink_metadata, not exists(): a dangling symlink is a real
        // configuration mistake and should be reported as "no key" rather
        // than silently selected and failing inside ssh.
        if std::fs::symlink_metadata(&candidate).is_ok() && candidate.is_file() {
            return Ok(SshAuth::Key(candidate));
        }
    }
    anyhow::bail!(
        "no SSH credentials: no usable agent at SSH_AUTH_SOCK, and none of {} \
         found in {}. Mount your keys read-only with -v ~/.ssh:{}:ro, or \
         forward your agent",
        KEY_NAMES.join(", "),
        ssh_dir.display(),
        ssh_dir.display()
    )
}

/// Runs every local check, in the order that reports the most actionable
/// failure first.
///
/// # Errors
/// The first failing check's error, unchanged. No network call is made on
/// any path through this function, including the failing ones.
pub fn check_in(
    raw_target: &str,
    host_dir: &Path,
    ssh_dir: &Path,
    agent_sock: Option<&str>,
) -> anyhow::Result<Preconditions> {
    let target = parse_target(raw_target)?;
    check_host_dir(host_dir)?;
    let ssh_auth = find_ssh_auth(ssh_dir, agent_sock)?;
    Ok(Preconditions {
        target,
        host_dir: host_dir.to_path_buf(),
        ssh_auth,
    })
}

/// Collects the operator's PUBLIC keys for the generated flake.
///
/// Public keys are read; the private key never is (see `find_ssh_auth`).
/// These are what authorise access to the installed machine, and
/// nixos-anywhere replaces the whole OS -- so every key previously trusted
/// by the target is erased. A host with no valid key here boots perfectly
/// and is unreachable forever.
///
/// # Errors
/// Returns an error when the mount holds no public key at all.
pub fn find_public_keys(ssh_dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut keys = Vec::new();
    let Ok(entries) = std::fs::read_dir(ssh_dir) else {
        anyhow::bail!("cannot read {}", ssh_dir.display());
    };
    let mut paths: Vec<_> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pub"))
        .collect();
    paths.sort();

    for path in paths {
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue;
        };
        for line in body.lines() {
            let line = line.trim();
            // Only real key lines: a .pub file can hold comments, and a
            // malformed entry would fail the host build much later.
            if line.starts_with("ssh-") || line.starts_with("ecdsa-") {
                keys.push(line.to_string());
            }
        }
    }
    if keys.is_empty() {
        anyhow::bail!(
            "no SSH public key found in {}. nixos-anywhere replaces the whole \
             OS, so every key the target trusts today is erased -- a host with \
             no key here boots perfectly and is unreachable forever.",
            ssh_dir.display()
        );
    }
    keys.sort();
    keys.dedup();
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_key(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "PRIVATE-KEY-BYTES-THAT-MUST-NEVER-BE-READ").unwrap();
        p
    }

    #[test]
    fn parses_a_root_target() {
        assert_eq!(
            parse_target("root@192.168.2.50").unwrap(),
            Target {
                user: "root".into(),
                host: "192.168.2.50".into()
            }
        );
    }

    #[test]
    fn refuses_a_non_root_target_and_says_why() {
        let err = parse_target("cs@saltbox").unwrap_err().to_string();
        assert!(err.contains("must connect as root"), "{err}");
        assert!(err.contains("nixos-anywhere"), "{err}");
    }

    #[test]
    fn refuses_malformed_targets() {
        for bad in ["saltbox", "@saltbox", "root@", "", "root@a@b"] {
            let err = parse_target(bad).unwrap_err().to_string();
            assert!(
                err.contains("user@host") || err.contains("more than one"),
                "target {bad:?} gave: {err}"
            );
        }
    }

    /// The bare-hostname case is the likeliest typo, so the message should
    /// contain the corrected command rather than just describing the rule.
    #[test]
    fn a_bare_hostname_is_refused_with_the_fix_in_the_message() {
        let err = parse_target("saltbox").unwrap_err().to_string();
        assert!(err.contains("root@saltbox"), "{err}");
    }

    #[test]
    fn a_missing_host_mount_names_the_docker_flag() {
        let err = check_host_dir(Path::new("/definitely/not/here"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not exist"), "{err}");
        assert!(err.contains("-v"), "the message should show the mount flag: {err}");
    }

    #[test]
    fn a_host_mount_that_is_a_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("host");
        std::fs::write(&f, "").unwrap();
        let err = check_host_dir(&f).unwrap_err().to_string();
        assert!(err.contains("not a directory"), "{err}");
    }

    #[test]
    fn a_writable_host_mount_passes() {
        let dir = tempfile::tempdir().unwrap();
        check_host_dir(dir.path()).unwrap();
    }

    #[test]
    fn prefers_the_agent_over_a_key_file() {
        let dir = tempfile::tempdir().unwrap();
        write_key(dir.path(), "id_ed25519");
        let sock = dir.path().join("agent.sock");
        std::fs::write(&sock, "").unwrap();

        let auth = find_ssh_auth(dir.path(), Some(sock.to_str().unwrap())).unwrap();
        assert_eq!(auth, SshAuth::Agent(sock));
    }

    /// A passphrase-protected key cannot be used non-interactively, which
    /// is the reason the agent wins -- but only when the socket is real.
    #[test]
    fn a_stale_agent_socket_falls_back_to_a_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_key(dir.path(), "id_ed25519");
        let auth = find_ssh_auth(dir.path(), Some("/nonexistent/agent.sock")).unwrap();
        assert_eq!(auth, SshAuth::Key(key));
    }

    #[test]
    fn an_empty_agent_variable_is_not_an_agent() {
        let dir = tempfile::tempdir().unwrap();
        let key = write_key(dir.path(), "id_rsa");
        assert_eq!(find_ssh_auth(dir.path(), Some("")).unwrap(), SshAuth::Key(key));
    }

    #[test]
    fn keys_are_preferred_in_openssh_order() {
        let dir = tempfile::tempdir().unwrap();
        write_key(dir.path(), "id_rsa");
        let ed = write_key(dir.path(), "id_ed25519");
        assert_eq!(find_ssh_auth(dir.path(), None).unwrap(), SshAuth::Key(ed));
    }

    #[test]
    fn no_agent_and_no_key_is_refused_with_the_mount_flag() {
        let dir = tempfile::tempdir().unwrap();
        let err = find_ssh_auth(dir.path(), None).unwrap_err().to_string();
        assert!(err.contains("no SSH credentials"), "{err}");
        assert!(err.contains("id_ed25519"), "{err}");
        assert!(err.contains(":ro"), "the message should show the read-only mount: {err}");
    }

    /// The security property of R1 A5. A key whose bytes cannot be read at
    /// all still satisfies the precondition, which is only possible if this
    /// module never opens it. If someone later "improves" this by parsing
    /// the key to check its type, this test goes red.
    #[cfg(unix)]
    #[test]
    fn the_private_key_is_located_but_never_read() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let key = write_key(dir.path(), "id_ed25519");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Prove the bytes really are unreadable in this environment before
        // concluding anything from the success below. Running as root
        // bypasses the mode, so skip rather than assert a false negative.
        if std::fs::read(&key).is_ok() {
            eprintln!("skipping: running as root, file modes are not enforced");
            return;
        }

        let auth = find_ssh_auth(dir.path(), None).unwrap();
        assert_eq!(auth, SshAuth::Key(key));
    }

    /// A dangling symlink is a real mistake and must not be selected.
    #[cfg(unix)]
    #[test]
    fn a_dangling_key_symlink_is_not_a_key() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone"), dir.path().join("id_ed25519")).unwrap();
        let err = find_ssh_auth(dir.path(), None).unwrap_err().to_string();
        assert!(err.contains("no SSH credentials"), "{err}");
    }

    #[test]
    fn check_in_reports_the_target_problem_before_the_mount_problem() {
        // Both are wrong; the target is the one the operator typed, so it
        // is the one worth reporting first.
        let err = check_in("saltbox", Path::new("/definitely/not/here"), Path::new("/ssh"), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("user@host"), "{err}");
    }

    #[test]
    fn public_keys_are_collected_and_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("id_ed25519.pub"), "ssh-ed25519 AAAA me@mac\n").unwrap();
        std::fs::write(
            dir.path().join("id_rsa.pub"),
            "# a comment\nssh-rsa BBBB me@other\nssh-ed25519 AAAA me@mac\n",
        )
        .unwrap();
        // The private key must never be picked up as a public one.
        std::fs::write(dir.path().join("id_ed25519"), "PRIVATE").unwrap();

        let keys = find_public_keys(dir.path()).unwrap();
        assert_eq!(keys, vec!["ssh-ed25519 AAAA me@mac", "ssh-rsa BBBB me@other"]);
        assert!(!keys.iter().any(|k| k.contains("PRIVATE")));
        assert!(!keys.iter().any(|k| k.starts_with('#')));
    }

    /// A host with no authorised key boots perfectly and is unreachable.
    #[test]
    fn no_public_key_is_refused_with_the_consequence_spelled_out() {
        let dir = tempfile::tempdir().unwrap();
        let err = find_public_keys(dir.path()).unwrap_err().to_string();
        assert!(err.contains("unreachable forever"), "{err}");
    }

    #[test]
    fn check_in_accepts_a_fully_valid_setup() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        std::fs::create_dir(&host).unwrap();
        let ssh = dir.path().join("ssh");
        std::fs::create_dir(&ssh).unwrap();
        write_key(&ssh, "id_ed25519");

        let pre = check_in("root@192.168.2.50", &host, &ssh, None).unwrap();
        assert_eq!(pre.target.to_string(), "root@192.168.2.50");
        assert_eq!(pre.host_dir, host);
    }
}
