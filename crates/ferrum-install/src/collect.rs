//! Running commands on the target over SSH.
//!
//! Shelling out to `ssh` rather than linking a Rust SSH client is this
//! repo's established convention (`crates/ferrum-apply/src/apply.rs` drives
//! `nix`, `btrfs` and `systemctl` the same way) and it keeps an entire SSH
//! stack out of `Cargo.lock`. `ssh` is on PATH because
//! `nix/pkgs/ferrum-install/default.nix` wraps this binary with it.
//!
//! Every command here is read-only. Nothing in this module modifies the
//! target: the destructive step belongs to `nixos-anywhere`, later, after a
//! human has confirmed a specific disk.

use std::process::Command;

use crate::preconditions::{SshAuth, Target};

/// Options applied to every connection.
///
/// `BatchMode=yes` matters: without it a host whose key is unknown, or a
/// key needing a passphrase, makes `ssh` sit waiting on a prompt that
/// nobody is there to answer, and the installer hangs instead of failing.
fn base_args(auth: &SshAuth) -> Vec<String> {
    let mut args = vec![
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
    ];
    if let SshAuth::Key(path) = auth {
        // IdentitiesOnly stops ssh from silently trying agent keys when we
        // asked for a specific one, which otherwise makes a wrong-key
        // failure look like a succeeded-by-accident.
        args.push("-o".into());
        args.push("IdentitiesOnly=yes".into());
        args.push("-i".into());
        args.push(path.display().to_string());
    }
    args
}

/// Runs one command on the target and returns its stdout.
///
/// # Errors
/// Returns an error carrying ssh's own stderr. That is deliberate: the
/// failures here are almost always host-key, network or permission
/// problems, and ssh already words them better than a wrapper would.
pub fn run(target: &Target, auth: &SshAuth, command: &str) -> anyhow::Result<String> {
    let output = Command::new("ssh")
        .args(base_args(auth))
        .arg(target.to_string())
        .arg(command)
        .output()
        .map_err(|e| anyhow::anyhow!("could not run ssh: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "ssh {target} failed running {command:?}: {}",
            stderr.trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Runs a command on the target with `payload` on its stdin.
///
/// Used for `ferrum-apply put-secret`: the secret value goes over stdin
/// rather than in argv so it never appears in the target's `ps` output or
/// in any shell history.
///
/// # Errors
/// Returns an error carrying ssh's own stderr. The payload is never
/// included in an error message.
pub fn run_with_stdin(
    target: &Target,
    auth: &SshAuth,
    command: &str,
    payload: &str,
) -> anyhow::Result<String> {
    use std::io::Write;

    let mut child = Command::new("ssh")
        .args(base_args(auth))
        .arg(target.to_string())
        .arg(command)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("could not run ssh: {e}"))?;

    child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("ssh stdin unavailable"))?
        .write_all(payload.as_bytes())?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        anyhow::bail!(
            "ssh {target} failed running {command:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Everything the inventory needs, collected in one connection.
///
/// One `ssh` invocation rather than five: each connection costs a round
/// trip and, on a host whose key is not yet trusted, a separate chance to
/// fail differently. The parts are separated by a sentinel rather than
/// parsed positionally so that a command producing no output cannot shift
/// every later section.
#[derive(Debug)]
pub struct RawInventory {
    pub lsblk: String,
    pub by_id: String,
    pub efi_present: bool,
    pub arch: String,
}

const SENTINEL: &str = "@@FERRUM@@";

/// Collects the raw inventory in a single SSH round trip.
///
/// # Errors
/// Any ssh failure, or output that does not contain the expected sections.
pub fn collect(target: &Target, auth: &SshAuth) -> anyhow::Result<RawInventory> {
    let script = format!(
        "lsblk -O --json; echo {SENTINEL}; \
         ls -l /dev/disk/by-id/ 2>/dev/null || true; echo {SENTINEL}; \
         [ -d /sys/firmware/efi ] && echo UEFI || echo BIOS; echo {SENTINEL}; \
         uname -m"
    );
    let out = run(target, auth, &script)?;
    parse_collected(&out)
}

/// Splits one collected blob into its parts.
///
/// Separated from `collect` so the parsing is testable without a machine.
///
/// # Errors
/// Returns an error when the output has fewer sections than expected,
/// which means a command died rather than merely returning nothing.
pub fn parse_collected(out: &str) -> anyhow::Result<RawInventory> {
    let parts: Vec<&str> = out.split(SENTINEL).collect();
    if parts.len() != 4 {
        anyhow::bail!(
            "unexpected inventory output from the target: expected 4 sections, got {}",
            parts.len()
        );
    }
    Ok(RawInventory {
        lsblk: parts[0].trim().to_string(),
        by_id: parts[1].trim().to_string(),
        efi_present: parts[2].trim() == "UEFI",
        arch: parts[3].trim().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn target() -> Target {
        Target {
            user: "root".into(),
            host: "saltbox".into(),
        }
    }

    /// A hanging installer is worse than a failing one: it happens on a
    /// headless box, after the operator has walked away.
    #[test]
    fn every_connection_is_non_interactive() {
        let args = base_args(&SshAuth::Agent(PathBuf::from("/tmp/a.sock")));
        assert!(args.contains(&"BatchMode=yes".to_string()));
        assert!(args.contains(&"ConnectTimeout=10".to_string()));
    }

    #[test]
    fn an_explicit_key_is_used_exclusively() {
        let args = base_args(&SshAuth::Key(PathBuf::from("/ssh/id_ed25519")));
        assert!(args.contains(&"IdentitiesOnly=yes".to_string()));
        assert!(args.contains(&"/ssh/id_ed25519".to_string()));
    }

    /// With an agent, no -i is passed at all -- the agent decides.
    #[test]
    fn an_agent_connection_names_no_key_file() {
        let args = base_args(&SshAuth::Agent(PathBuf::from("/tmp/a.sock")));
        assert!(!args.contains(&"-i".to_string()));
        assert!(!args.contains(&"IdentitiesOnly=yes".to_string()));
    }

    #[test]
    fn splits_a_real_collection_into_its_parts() {
        let out = format!(
            "{{\"blockdevices\":[]}}\n{SENTINEL}\ntotal 0\n{SENTINEL}\nUEFI\n{SENTINEL}\nx86_64\n"
        );
        let raw = parse_collected(&out).unwrap();
        assert_eq!(raw.lsblk, "{\"blockdevices\":[]}");
        assert_eq!(raw.by_id, "total 0");
        assert!(raw.efi_present);
        assert_eq!(raw.arch, "x86_64");
    }

    #[test]
    fn a_bios_target_is_read_as_such() {
        let out = format!("{{}}\n{SENTINEL}\n\n{SENTINEL}\nBIOS\n{SENTINEL}\nx86_64\n");
        assert!(!parse_collected(&out).unwrap().efi_present);
    }

    /// An empty by-id listing is legitimate; a missing SECTION is not.
    /// Positional parsing would have conflated the two.
    #[test]
    fn an_empty_section_is_fine_but_a_missing_one_is_an_error() {
        let ok = format!("{{}}\n{SENTINEL}\n{SENTINEL}\nBIOS\n{SENTINEL}\naarch64\n");
        assert_eq!(parse_collected(&ok).unwrap().by_id, "");

        let truncated = format!("{{}}\n{SENTINEL}\ntotal 0\n{SENTINEL}\nUEFI\n");
        let err = parse_collected(&truncated).unwrap_err().to_string();
        assert!(err.contains("expected 4 sections"), "{err}");
    }

    #[test]
    fn the_target_renders_as_user_at_host() {
        assert_eq!(target().to_string(), "root@saltbox");
    }
}
