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

use std::path::Path;
use std::process::Command;

use crate::preconditions::{SshAuth, Target};

/// Options applied to every connection.
///
/// `BatchMode=yes` matters: without it a host whose key is unknown, or a
/// key needing a passphrase, makes `ssh` sit waiting on a prompt that
/// nobody is there to answer, and the installer hangs instead of failing.
/// Where trusted host keys are remembered.
///
/// Inside the `/host` bind mount, deliberately: the container is run with
/// `--rm`, so anywhere else the trust decision would evaporate and every
/// run would be a first contact. Excluded from `install::copy_tree`, since
/// it is the operator's record and has no meaning on the installed host.
pub const KNOWN_HOSTS: &str = "known_hosts";

/// Options applied to every connection.
///
/// `BatchMode=yes` matters: without it a host whose key is unknown, or a
/// key needing a passphrase, makes `ssh` sit waiting on a prompt that
/// nobody is there to answer, and the installer hangs instead of failing.
///
/// The host-key policy is **explicit and persisted**, which it has to be
/// for two separate reasons. Left unset, `BatchMode=yes` makes ssh *refuse*
/// an unknown host outright -- and this installer's whole job is to contact
/// a freshly-imaged machine it has never seen, so the first connection of
/// every real run would fail. `accept-new` trusts a genuinely new host once
/// and records it; a host whose key later *changes* is still refused, which
/// is the case worth catching. Writing the file into `/host` is what makes
/// "later" mean anything across a `--rm` container.
fn base_args_in(auth: &SshAuth, port: u16, host_dir: Option<&Path>) -> Vec<String> {
    let mut args = vec![
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-p".into(),
        port.to_string(),
    ];
    if let Some(dir) = host_dir {
        args.push("-o".into());
        args.push(format!("UserKnownHostsFile={}", dir.join(KNOWN_HOSTS).display()));
    }
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

/// Quotes a value for safe interpolation into a remote shell command.
///
/// Defence in depth. Every value that reaches here is already validated by
/// an allowlist at its entry point, but those allowlists live far from the
/// sinks and a future one could be loosened without anyone noticing the
/// connection. Wrapping in single quotes and escaping embedded single
/// quotes is the whole of it.
pub fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Runs one command on the target and returns its stdout.
///
/// # Errors
/// Returns an error carrying ssh's own stderr. That is deliberate: the
/// failures here are almost always host-key, network or permission
/// problems, and ssh already words them better than a wrapper would.
pub fn run(target: &Target, auth: &SshAuth, command: &str) -> anyhow::Result<String> {
    let output = Command::new("ssh")
        .args(base_args_in(auth, target.port, target.known_hosts_dir.as_deref()))
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
/// Runs a command on the target with its output going STRAIGHT to the
/// operator's terminal.
///
/// `run` captures output and returns it, which is right for the short
/// commands whose result is inspected. It is wrong for the stage-2 apply:
/// that builds an entire NixOS system on the target and can run for tens
/// of minutes, during which a captured-output runner shows the operator a
/// single static line and no evidence anything is alive.
///
/// That is not a cosmetic difference. Every long silence in this
/// feature's history turned out to be either a real hang or a build, and
/// nothing on screen distinguished them -- a three-hour CI timeout and a
/// working install looked identical until the logs were dug out
/// afterwards.
///
/// # Arguments
/// * `target` - the machine to run on.
/// * `auth` - the operator's credential.
/// * `command` - the remote command.
///
/// # Errors
/// If ssh cannot start, or the remote command exits non-zero.
pub fn run_streaming(target: &Target, auth: &SshAuth, command: &str) -> anyhow::Result<()> {
    let status = Command::new("ssh")
        .args(base_args_in(auth, target.port, target.known_hosts_dir.as_deref()))
        .arg(target.to_string())
        .arg(command)
        .status()
        .map_err(|e| anyhow::anyhow!("could not run ssh: {e}"))?;
    if !status.success() {
        anyhow::bail!("ssh {target} failed running {command:?} ({status})");
    }
    Ok(())
}

pub fn run_with_stdin(
    target: &Target,
    auth: &SshAuth,
    command: &str,
    payload: &str,
) -> anyhow::Result<String> {
    use std::io::Write;

    let mut child = Command::new("ssh")
        .args(base_args_in(auth, target.port, target.known_hosts_dir.as_deref()))
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
            port: 22,
            known_hosts_dir: None,
        }
    }

    /// Left unset, BatchMode=yes makes ssh REFUSE an unknown host, so the
    /// installer could never reach a freshly-imaged machine at all.
    #[test]
    fn a_new_host_is_accepted_once_and_remembered() {
        let args = base_args_in(&SshAuth::Agent(PathBuf::from("/s")), 22, Some(Path::new("/host")));
        assert!(args.contains(&"StrictHostKeyChecking=accept-new".to_string()));
        assert!(args.contains(&"UserKnownHostsFile=/host/known_hosts".to_string()),
                "trust must persist across a --rm container: {args:?}");
    }

    /// accept-new trusts a NEW host; a CHANGED key is still refused. That
    /// distinction is the whole reason not to use `no`.
    #[test]
    fn the_policy_is_accept_new_never_disabled() {
        let args = base_args_in(&SshAuth::Agent(PathBuf::from("/s")), 22, None);
        assert!(!args.iter().any(|a| a.contains("StrictHostKeyChecking=no")));
    }

    #[test]
    fn sh_quote_neutralises_every_metacharacter_that_matters() {
        for raw in ["a;id", "a`id`", "a$(id)", "a|id", "a&id", "a>f", "a<f", "a\nb"] {
            let q = sh_quote(raw);
            assert!(q.starts_with('\'') && q.ends_with('\''), "{q}");
        }
        // The one character that can end the quoting is escaped.
        assert_eq!(sh_quote("a'b"), r"'a'\''b'");
    }

    #[test]
    fn a_non_default_port_is_passed_to_ssh() {
        let args = base_args_in(&SshAuth::Agent(PathBuf::from("/s")), 2222, None);
        let i = args.iter().position(|a| a == "-p").unwrap();
        assert_eq!(args[i + 1], "2222");
    }

    /// A hanging installer is worse than a failing one: it happens on a
    /// headless box, after the operator has walked away.
    #[test]
    fn every_connection_is_non_interactive() {
        let args = base_args_in(&SshAuth::Agent(PathBuf::from("/tmp/a.sock")), 22, None);
        assert!(args.contains(&"BatchMode=yes".to_string()));
        assert!(args.contains(&"ConnectTimeout=10".to_string()));
    }

    #[test]
    fn an_explicit_key_is_used_exclusively() {
        let args = base_args_in(&SshAuth::Key(PathBuf::from("/ssh/id_ed25519")), 22, None);
        assert!(args.contains(&"IdentitiesOnly=yes".to_string()));
        assert!(args.contains(&"/ssh/id_ed25519".to_string()));
    }

    /// With an agent, no -i is passed at all -- the agent decides.
    #[test]
    fn an_agent_connection_names_no_key_file() {
        let args = base_args_in(&SshAuth::Agent(PathBuf::from("/tmp/a.sock")), 22, None);
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
