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
mod install;
mod inventory;
mod preconditions;
mod preflight;
mod render;
mod stage2;
mod state;
mod verify;
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
    if let Err(e) = run(&cli) {
        eprintln!("\nferrum-install: {e}");
        std::process::exit(1);
    }
}

/// The whole install, phase by phase.
///
/// Each phase records that it happened *before* the next begins, and the
/// destructive one records that it has STARTED rather than that it
/// finished -- the wipe happens inside `nixos-anywhere`, so a crash
/// mid-invocation must never leave the disk gone with the record still
/// saying nothing was touched.
fn run(cli: &Cli) -> anyhow::Result<()> {
    let agent = std::env::var("SSH_AUTH_SOCK").ok();
    let pre = preconditions::check_in(&cli.target, &cli.host_dir, &cli.ssh_dir, agent.as_deref())?;
    report_preconditions(&pre, cli.fresh);

    if cli.fresh {
        state::clear(&pre.host_dir)?;
    }
    let prior = state::read(&pre.host_dir)?;
    let resume = state::plan(prior.as_ref(), &cli.target, cli.fresh);
    if let state::Resume::Conflict(message) = &resume {
        anyhow::bail!("{message}");
    }
    let reached = match &resume {
        state::Resume::ContinueAfter(p) => {
            println!("\nresuming: this directory already reached '{}'", p.describe());
            Some(*p)
        }
        _ => None,
    };

    // The disk gate is re-run only when nothing has been written yet.
    // Past `Installing` the named disk is already gone, so re-confirming
    // protects nothing and only trains the operator to retype a serial.
    let (mut answers, approved) = if state::needs_disk_confirmation(&resume) {
        plan_install(&pre)?
    } else {
        recover_plan(&pre)?
    };

    let mut st = state::InstallState {
        phase: state::Phase::Generated,
        target: cli.target.clone(),
        hostname: answers.hostname.clone(),
        approved_disk: approved.device.by_id.clone().unwrap_or_default(),
    };

    if reached.is_none() {
        let files = generate(&pre, cli, &answers, &approved)?;
        println!("\ngenerated host repository in {}:", pre.host_dir.display());
        for f in files.keys() {
            println!("  {f}");
        }
        state::write(&pre.host_dir, &st)?;
    }

    // --- Tier 1 preflight. Target still untouched. ---
    let evidence = if reached.unwrap_or(state::Phase::Generated) < state::Phase::PreflightPassed {
        println!("\npreflight: evaluating the generated configuration ...");
        let files = read_generated(&pre.host_dir)?;
        let e = preflight::tier1(&pre.host_dir, &files, &answers.hostname)?;
        st.phase = state::Phase::PreflightPassed;
        state::write(&pre.host_dir, &st)?;
        e
    } else {
        preflight::Evidence { evaluated: true, booted: false }
    };
    println!("preflight: {}", evidence.describe());

    // --- The destructive step. ---
    if reached.unwrap_or(state::Phase::Generated) < state::Phase::Installed {
        let scratch = tempfile::tempdir()?;
        let extra = install::stage_extra_files(scratch.path(), &pre.host_dir)?;

        st.phase = state::Phase::Installing;
        state::write(&pre.host_dir, &st)?;

        println!("\ninstalling. THIS ERASES {}.", st.approved_disk);
        run_streaming(
            "nixos-anywhere",
            &install::args(&cli.target, &answers.hostname, &extra),
            &pre.host_dir,
        )?;

        st.phase = state::Phase::Installed;
        state::write(&pre.host_dir, &st)?;
        println!("installed. waiting for the host to come back ...");
        wait_for_ssh(&pre)?;
    }

    // --- Stage 2. The host exists now, so the things that could not exist
    //     before it can be created. ---
    if reached.unwrap_or(state::Phase::Generated) < state::Phase::Stage2Applied {
        if answers.cloudflare_token.is_none()
            && answers::token_still_needed(&answers, acme_secret_present(&pre)?)
        {
            let mut io = prompt::stdio();
            answers.cloudflare_token = Some(prompt::PromptIo::ask(
                &mut io,
                "\nCloudflare API token (not recoverable from the generated files):",
            )?);
        }

        println!("\nenabling apps and authentication ...");
        for command in stage2::commands(&answers) {
            if command.contains("put-secret") {
                let token = answers.cloudflare_token.as_deref().unwrap_or_default();
                collect::run_with_stdin(
                    &pre.target,
                    &pre.ssh_auth,
                    &command,
                    &stage2::acme_payload(token),
                )?;
            } else {
                collect::run(&pre.target, &pre.ssh_auth, &command)?;
            }
        }
        st.phase = state::Phase::Stage2Applied;
        state::write(&pre.host_dir, &st)?;
    }

    // --- Verification, then the report. ---
    println!("\nverifying ...");
    let failures = verify_host(&pre, &answers, &approved)?;
    if !failures.is_empty() {
        anyhow::bail!(
            "the host is installed, but {} check(s) failed:\n  {}",
            failures.len(),
            failures.join("\n  ")
        );
    }
    st.phase = state::Phase::Verified;
    state::write(&pre.host_dir, &st)?;

    final_report(&pre, &answers, &evidence)?;
    Ok(())
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
) -> anyhow::Result<render::Files> {
    let keys = preconditions::find_public_keys(&cli.ssh_dir)?;
    let rev = ferrum_revision()?;
    let files = render::render(answers, approved, &keys, rev)?;
    render::write_repo(&pre.host_dir, &files)?;
    Ok(files)
}

/// Re-reads the target and confirms the approved disk is still the disk.
///
/// Minutes pass between the inventory being printed and the serial being
/// typed, and a USB disk can be unplugged in that window. This is the same
/// check that runs again after kexec.
fn recheck(
    pre: &preconditions::Preconditions,
    approved: &confirm::Approved,
) -> anyhow::Result<()> {
    let raw = collect::collect(&pre.target, &pre.ssh_auth)?;
    let mut devices = inventory::parse_lsblk(&raw.lsblk)?;
    inventory::attach_by_id(&mut devices, &inventory::parse_by_id(&raw.by_id));
    confirm::verify_still(approved, &devices)
}

/// Collects and reports the target's inventory. Read-only throughout.
fn inventory_phase(
    pre: &preconditions::Preconditions,
) -> anyhow::Result<(Vec<inventory::Device>, bool)> {
    println!("\ncollecting inventory from {} ...", pre.target);
    let raw = collect::collect(&pre.target, &pre.ssh_auth)?;

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

    println!("if you install to ...");
    for d in &devices {
        match inventory::infer_firmware(raw.efi_present, d) {
            Ok(fw) => println!("  {:<10} -> {fw:?} bootloader", d.name),
            Err(e) => println!("  {:<10} -> REFUSED: {e}", d.name),
        }
        let mounts = d.mounted_at();
        if !mounts.is_empty() {
            println!("  {:<10}    currently mounted at {}", "", mounts.join(", "));
        }
    }

    inventory::check_serials_identify(&devices)?;
    Ok((devices, raw.efi_present))
}

fn report_preconditions(pre: &preconditions::Preconditions, fresh: bool) {
    // Only the credential's KIND and LOCATION are ever printed; the key
    // itself is never read by this process.
    let auth = match &pre.ssh_auth {
        preconditions::SshAuth::Agent(p) => format!("ssh agent at {}", p.display()),
        preconditions::SshAuth::Key(p) => format!("key {}", p.display()),
    };
    println!("target:        {}", pre.target);
    println!("host repo:     {}", pre.host_dir.display());
    println!("credentials:   {auth}");
    if fresh {
        println!("mode:          --fresh (any existing install record is discarded)");
    }
}

/// The interactive half: inventory, answers, and the disk gate.
fn plan_install(
    pre: &preconditions::Preconditions,
) -> anyhow::Result<(answers::Answers, confirm::Approved)> {
    let (devices, efi_present) = inventory_phase(pre)?;
    let mut io = prompt::stdio();
    let answers = answers::collect(&mut io)?;
    let approved = confirm::confirm(&devices, efi_present, &mut io)?;

    recheck(pre, &approved)?;
    let path = pre.host_dir.join("install-inventory.json");
    write_json(&path, &approved)?;
    println!(
        "\napproved for erasure: {} ({})\n  bootloader:  {:?}\n  recorded in: {}",
        approved.device.name,
        approved.device.by_id.as_deref().unwrap_or("?"),
        approved.firmware,
        path.display()
    );
    Ok((answers, approved))
}

/// The resume half: recover what was decided, never re-ask.
fn recover_plan(
    pre: &preconditions::Preconditions,
) -> anyhow::Result<(answers::Answers, confirm::Approved)> {
    let approved: confirm::Approved = serde_json::from_str(&std::fs::read_to_string(
        pre.host_dir.join("install-inventory.json"),
    )?)?;
    let stage2 = std::fs::read_to_string(pre.host_dir.join("settings.stage2.json"))?;
    let hostname = read_hostname(&pre.host_dir)?;
    let answers = answers::from_stage2(&stage2, &hostname)?;
    Ok((answers, approved))
}

fn read_hostname(dir: &std::path::Path) -> anyhow::Result<String> {
    let flake = std::fs::read_to_string(dir.join("flake.nix"))?;
    flake
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("networking.hostName = \"")
                .and_then(|r| r.split('"').next())
                .map(str::to_string)
        })
        .ok_or_else(|| anyhow::anyhow!("could not read the hostname back from flake.nix"))
}

fn read_generated(dir: &std::path::Path) -> anyhow::Result<render::Files> {
    let mut files = render::Files::new();
    for rel in ["flake.nix", "disko.nix", "settings.json", "settings.stage2.json"] {
        let p = dir.join(rel);
        if p.exists() {
            files.insert(rel.to_string(), std::fs::read_to_string(p)?);
        }
    }
    Ok(files)
}

fn write_json<T: serde::Serialize>(path: &std::path::Path, value: &T) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(value)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Runs a long command with its output streaming through, so the operator
/// sees nixos-anywhere working rather than a silent terminal.
fn run_streaming(program: &str, args: &[String], cwd: &std::path::Path) -> anyhow::Result<()> {
    let status = std::process::Command::new(program)
        .current_dir(cwd)
        .args(args)
        .status()
        .map_err(|e| anyhow::anyhow!("could not run {program}: {e}"))?;
    if !status.success() {
        anyhow::bail!("{program} failed ({status})");
    }
    Ok(())
}

/// Polls for the host to answer SSH again.
///
/// Polls the observable condition rather than sleeping a fixed time: a
/// fixed wait is either too short on slow hardware or wastes minutes on
/// fast hardware, and this runs on real machines with real POST times.
fn wait_for_ssh(pre: &preconditions::Preconditions) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
    while std::time::Instant::now() < deadline {
        if collect::run(&pre.target, &pre.ssh_auth, "true").is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    anyhow::bail!(
        "the host did not answer SSH within 10 minutes. It is installed; check \
         it on the console before re-running -- a resume will not repartition."
    )
}

fn acme_secret_present(pre: &preconditions::Preconditions) -> anyhow::Result<bool> {
    Ok(collect::run(
        &pre.target,
        &pre.ssh_auth,
        "test -f /etc/ferrum/secrets/acme-dns.sops && echo yes || echo no",
    )
    .map(|o| o.trim() == "yes")
    .unwrap_or(false))
}

/// Runs every check and returns the ones that failed.
fn verify_host(
    pre: &preconditions::Preconditions,
    answers: &answers::Answers,
    approved: &confirm::Approved,
) -> anyhow::Result<Vec<String>> {
    let kept = render::data_disks(&approved.all_devices, &approved.device);
    let mut checks = verify::ownership_checks();
    checks.extend(verify::service_checks());
    checks.extend(verify::data_disk_checks(&kept));
    if let Some(domain) = &answers.base_domain {
        checks.extend(verify::auth_checks(domain, &answers.apps, answers.sso.enabled));
    }

    let mut failures = Vec::new();
    for check in checks {
        match collect::run(&pre.target, &pre.ssh_auth, &check.command) {
            Ok(out) if out.contains(&check.expect) => println!("  ok: {}", check.what),
            Ok(out) => failures.push(format!(
                "{}: expected {:?}, got {:?}  [{}]",
                check.what,
                check.expect,
                out.trim(),
                check.command
            )),
            Err(e) => failures.push(format!("{}: {e}", check.what)),
        }
    }
    Ok(failures)
}

/// Everything the operator needs to actually use the machine.
fn final_report(
    pre: &preconditions::Preconditions,
    answers: &answers::Answers,
    evidence: &preflight::Evidence,
) -> anyhow::Result<()> {
    println!("\n{}", "=".repeat(64));
    println!("{} is installed.", answers.hostname);
    println!("{}", "=".repeat(64));
    println!("\nproof: {}", evidence.describe());

    if let Some(domain) = &answers.base_domain {
        println!("\nurls:");
        println!("  ferrum        https://ferrum.{domain}");
        if answers.sso.enabled {
            println!("  sign-in       https://auth.{domain}");
        }
        for app in &answers.apps {
            println!("  {app:<13} https://{app}.{domain}");
        }
    }

    // Printed once, to the terminal, and written to no file.
    println!("\nfirst-run credentials -- shown ONCE, stored nowhere by this installer:");
    for (what, path) in verify::credential_paths(answers.sso.enabled) {
        match collect::run(&pre.target, &pre.ssh_auth, &format!("cat {path}")) {
            Ok(value) => println!("  {what:<15} {}", value.trim()),
            Err(e) => println!("  {what:<15} (could not read {path}: {e})"),
        }
    }

    println!(
        "\nyour host repository is {}. It is yours: ferrum never rewrites it,\n\
         and every later `ferrum-apply apply` on the host evaluates its copy\n\
         at /etc/ferrum.",
        pre.host_dir.display()
    );
    Ok(())
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
