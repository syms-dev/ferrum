//! `ferrum-install` -- takes a machine you can SSH into as root and turns it
//! into a working ferrum host.
//!
//! It replaces `docs/INSTALL.md`'s eight manual steps: identifying disks by
//! `/dev/disk/by-id/`, determining the firmware mode, hand-editing twelve
//! placeholders across the host template, generating a hardware
//! configuration, installing once with no apps, keeping a second settings
//! document alongside, and swapping it in afterwards.
//!
//! It ships as a Docker image so that Docker is the only thing the
//! operator's own machine needs (see the Phase 1.6a spec, DEC-02), with the
//! heavy x86_64 build happening on the target itself via nixos-anywhere's
//! remote build rather than under emulation here.
//!
//! This binary is deliberately staged: the destructive step is not the last
//! step, so its progress is recorded and it is resumable (spec R7). What is
//! implemented so far is the part that runs before anything is contacted.

mod answers;
mod collect;
mod confirm;
mod inventory;
mod preconditions;
mod render;
mod prompt;
mod sso;

use clap::Parser;

/// Install ferrum onto a target machine.
#[derive(Parser, Debug)]
#[command(name = "ferrum-install")]
#[command(about = "Install ferrum onto a bare machine over SSH", long_about = None)]
struct Cli {
    /// The machine to install onto, as `root@host`. nixos-anywhere replaces
    /// the entire OS, so this must be root.
    target: String,

    /// Directory holding the generated host repository. Bind-mounted from
    /// the operator's machine so it outlives the container.
    #[arg(long, default_value = preconditions::DEFAULT_HOST_DIR)]
    host_dir: std::path::PathBuf,

    /// Read-only mount holding the operator's SSH keys.
    #[arg(long, default_value = preconditions::DEFAULT_SSH_DIR)]
    ssh_dir: std::path::PathBuf,

    /// Discard any existing install state and start over, re-running the
    /// disk confirmation in full. Never implied by a stale directory: a
    /// resume that silently restarted would re-run the destructive step.
    #[arg(long)]
    fresh: bool,
}

fn main() {
    let cli = Cli::parse();

    let agent_sock = std::env::var("SSH_AUTH_SOCK").ok();
    let pre = match preconditions::check_in(
        &cli.target,
        &cli.host_dir,
        &cli.ssh_dir,
        agent_sock.as_deref(),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ferrum-install: {e}");
            std::process::exit(1);
        }
    };

    // Only the credential's *kind and location* are ever printed. The key
    // itself is never read by this process (see preconditions::find_ssh_auth).
    let auth = match &pre.ssh_auth {
        preconditions::SshAuth::Agent(p) => format!("ssh agent at {}", p.display()),
        preconditions::SshAuth::Key(p) => format!("key {}", p.display()),
    };
    println!("target:        {}", pre.target);
    println!("host repo:     {}", pre.host_dir.display());
    println!("credentials:   {auth}");
    if cli.fresh {
        println!("mode:          --fresh (existing install state will be discarded)");
    }

    let (devices, efi_present) = match inventory_phase(&pre) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ferrum-install: {e}");
            std::process::exit(1);
        }
    };

    let answers = match answers::collect(&mut prompt::stdio()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("\nferrum-install: {e}");
            std::process::exit(1);
        }
    };

    println!(
        "\nplanned host: {}\n  domain:  {}\n  apps:    {}\n  sso:     {}",
        answers.hostname,
        answers.base_domain.as_deref().unwrap_or("(none -- not published)"),
        if answers.apps.is_empty() { "(none)".to_string() } else { answers.apps.join(", ") },
        if answers.sso.enabled {
            format!("on, admin {}", answers.sso.admin_email.as_deref().unwrap_or("?"))
        } else {
            "OFF".to_string()
        }
    );

    let mut io = prompt::stdio();
    let approved = match confirm::confirm(&devices, efi_present, &mut io) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("\nferrum-install: {e}");
            std::process::exit(1);
        }
    };

    // Minutes can pass between the inventory being printed and the serial
    // being typed, and a USB disk can be unplugged or a device renumbered
    // in that window. Re-read and re-check before recording the approval.
    // This is the same check S7 runs again after kexec, which is the other
    // moment enumeration can legitimately change.
    match recheck(&pre, &approved) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("\nferrum-install: {e}");
            std::process::exit(1);
        }
    }

    // Written BEFORE anything destructive runs (spec R2 A7). The
    // post-install check re-reads it to assert every data disk it was told
    // to keep is still mounted with the filesystem recorded here -- a disk
    // that failed to mount should be a loud failure, not a missing
    // directory discovered weeks later.
    let inventory_path = pre.host_dir.join("install-inventory.json");
    if let Err(e) = write_inventory(&inventory_path, &approved) {
        eprintln!("ferrum-install: could not record the approved inventory: {e}");
        std::process::exit(1);
    }

    println!(
        "\napproved for erasure: {} ({})\n  bootloader:  {:?}\n  recorded in: {}",
        approved.device.name,
        approved.device.by_id.as_deref().unwrap_or("?"),
        approved.firmware,
        inventory_path.display()
    );

    match generate(&pre, &cli, &answers, &approved) {
        Ok(paths) => {
            println!("\ngenerated host repository in {}:", pre.host_dir.display());
            for p in paths {
                println!("  {p}");
            }
        }
        Err(e) => {
            eprintln!("\nferrum-install: {e}");
            std::process::exit(1);
        }
    }

    eprintln!(
        "\nferrum-install: host repository generated and committed. NOTHING on \n\
         the target has been modified. The remaining phases (preflight, \n\
         install, stage 2, verification) are not implemented yet -- see the \n\
         Phase 1.6a story breakdown."
    );
    std::process::exit(2);
}

/// The ferrum revision this installer was built from.
///
/// Injected by nix/pkgs/ferrum-install/default.nix. Absent means this
/// binary was built outside Nix, and there is no honest revision to pin --
/// R3 A5 requires a specific revision, never a branch, so a fallback like
/// "main" would be worse than refusing.
fn ferrum_revision() -> anyhow::Result<&'static str> {
    option_env!("FERRUM_INSTALL_REV").ok_or_else(|| {
        anyhow::anyhow!(
            "this ferrum-install was built without FERRUM_INSTALL_REV, so it \
             cannot pin the host to the revision it came from. Use the Docker \
             image, which is built by Nix and always carries one."
        )
    })
}

/// Renders and commits the host repository.
fn generate(
    pre: &preconditions::Preconditions,
    cli: &Cli,
    answers: &answers::Answers,
    approved: &confirm::Approved,
) -> anyhow::Result<Vec<String>> {
    let keys = preconditions::find_public_keys(&cli.ssh_dir)?;
    let rev = ferrum_revision()?;
    let files = render::render(answers, approved, &keys, rev)?;
    render::write_repo(&pre.host_dir, &files)?;
    Ok(files.keys().cloned().collect())
}

/// Re-reads the target and confirms the approved disk is still the disk.
fn recheck(
    pre: &preconditions::Preconditions,
    approved: &confirm::Approved,
) -> anyhow::Result<()> {
    let raw = collect::collect(&pre.target, &pre.ssh_auth)?;
    let mut devices = inventory::parse_lsblk(&raw.lsblk)?;
    inventory::attach_by_id(&mut devices, &inventory::parse_by_id(&raw.by_id));
    confirm::verify_still(approved, &devices)
}

/// Records the approved inventory, atomically.
///
/// Temp file then rename: a partially-written record of which disk was
/// approved is worse than none at all, because the next phase reads it.
fn write_inventory(path: &std::path::Path, approved: &confirm::Approved) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(approved)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Collects and reports the target's inventory. Read-only throughout.
fn inventory_phase(
    pre: &preconditions::Preconditions,
) -> anyhow::Result<(Vec<inventory::Device>, bool)> {
    println!("\ncollecting inventory from {} ...", pre.target);
    let raw = collect::collect(&pre.target, &pre.ssh_auth)?;

    // Refuse an architecture the catalog is not built for, before the
    // operator invests any more attention in this run.
    if raw.arch != "x86_64" {
        anyhow::bail!(
            "target reports architecture {:?}; ferrum's catalog is built for \
             x86_64-linux only",
            raw.arch
        );
    }

    let mut devices = inventory::parse_lsblk(&raw.lsblk)?;
    if devices.is_empty() {
        anyhow::bail!("the target reports no whole block devices to install onto");
    }
    inventory::attach_by_id(&mut devices, &inventory::parse_by_id(&raw.by_id));

    println!(
        "\nfirmware: {}\narchitecture: {}\n\ndisks:\n{}",
        if raw.efi_present { "EFI (/sys/firmware/efi present)" } else { "legacy BIOS" },
        raw.arch,
        inventory::render(&devices)
    );

    // Report the firmware consequence PER DISK, before anything is chosen.
    // Getting this wrong is the worst failure available here -- the install
    // completes and the machine then does not boot, with the previous OS
    // already gone -- so the operator should see a conflicting-signals
    // refusal now, while it costs a question, rather than after they have
    // committed to a disk.
    println!("if you install to ...");
    for d in &devices {
        match inventory::infer_firmware(raw.efi_present, d) {
            Ok(fw) => println!("  {:<10} -> {fw:?} bootloader", d.name),
            Err(e) => println!("  {:<10} -> REFUSED: {e}", d.name),
        }
        let mounts = d.mounted_at();
        if !mounts.is_empty() {
            println!(
                "  {:<10}    currently mounted at {} -- destroying this disk \
                 unmounts them",
                "",
                mounts.join(", ")
            );
        }
    }

    // Checked after rendering on purpose: if the serials cannot identify a
    // disk, the operator still needs to see the inventory to understand
    // why, and to find the by-id path the error tells them to use.
    inventory::check_serials_identify(&devices)?;
    Ok((devices, raw.efi_present))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// R1 A3: no target argument means usage and a non-zero exit, with
    /// nothing contacted. `try_parse_from` returning an error is what
    /// produces both.
    #[test]
    fn no_target_is_a_usage_error() {
        let err = Cli::try_parse_from(["ferrum-install"]).unwrap_err();
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::MissingRequiredArgument,
            "{err}"
        );
    }

    #[test]
    fn the_defaults_are_the_documented_mount_points() {
        let cli = Cli::parse_from(["ferrum-install", "root@saltbox"]);
        assert_eq!(cli.target, "root@saltbox");
        assert_eq!(
            cli.host_dir,
            std::path::PathBuf::from(preconditions::DEFAULT_HOST_DIR)
        );
        assert_eq!(
            cli.ssh_dir,
            std::path::PathBuf::from(preconditions::DEFAULT_SSH_DIR)
        );
        assert!(!cli.fresh, "--fresh must never be the default");
    }

    #[test]
    fn fresh_is_opt_in() {
        let cli = Cli::parse_from(["ferrum-install", "root@saltbox", "--fresh"]);
        assert!(cli.fresh);
    }

    #[test]
    fn the_mounts_are_overridable_for_testing_outside_a_container() {
        let cli = Cli::parse_from([
            "ferrum-install",
            "root@saltbox",
            "--host-dir",
            "/tmp/h",
            "--ssh-dir",
            "/tmp/s",
        ]);
        assert_eq!(cli.host_dir, std::path::PathBuf::from("/tmp/h"));
        assert_eq!(cli.ssh_dir, std::path::PathBuf::from("/tmp/s"));
    }

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
