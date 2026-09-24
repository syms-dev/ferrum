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

mod address;
mod answers;
mod collect;
mod confirm;
mod dns;
mod install;
mod inventory;
mod preconditions;
mod preflight;
mod prompt;
mod render;
mod sso;
mod stage2;
mod state;
mod verify;

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

    /// SSH port on the target, when it is not 22.
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,

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
    let pre = preconditions::check_in(
        &cli.target,
        cli.ssh_port,
        &cli.host_dir,
        &cli.ssh_dir,
        agent.as_deref(),
    )?;
    report_preconditions(&pre, cli.fresh);

    if cli.fresh {
        state::clear(&pre.host_dir)?;
    }
    let prior = state::read(&pre.host_dir)?;
    let resume = state::plan(prior.as_ref(), &cli.target, cli.fresh);
    if let state::Resume::Conflict(message) = &resume {
        anyhow::bail!("{message}");
    }
    if let state::Resume::ContinueAfter(p) = &resume {
        println!(
            "\nresuming: this directory already reached '{}'",
            p.describe()
        );
    }

    // The disk gate is re-run only when nothing has been written yet.
    // Past `Installing` the named disk is already gone, so re-confirming
    // protects nothing and only trains the operator to retype a serial.
    let asked_fresh = state::needs_disk_confirmation(&resume);

    // **If this run collected answers, it also regenerates the repository,
    // so nothing the PREVIOUS run validated applies any more.** Carrying
    // its recorded phase forward would skip the checks that validate the
    // content -- and resuming from exactly `PreflightPassed` did precisely
    // that: it regenerated from new answers and then skipped Tier 1,
    // because `PreflightPassed < PreflightPassed` is false. The evidence
    // even claimed `evaluated: true`.
    //
    // Reachable by the most ordinary sequence there is: interrupt right
    // after the preflight line prints and before the erase warning -- the
    // natural place to pause and double-check -- then run it again.
    //
    // This is the same shape as the resume that skipped the authentication
    // backstop. A phase recorded by a run whose content this run replaced
    // is not evidence about this run. `state::effective_reached` owns that
    // rule so it is unit-testable rather than implicit here.
    let reached = state::effective_reached(&resume);
    // `adoption` carries R1 A3's decision from the pre-erase gate all the
    // way to the final report, and `zone_not_serving_yet` carries the other
    // half of what that gate learned: whether Cloudflare answers for this
    // domain at all. Both are needed at the end, not only at the gate --
    // the URL list is the last thing on screen, and a pending zone means
    // not one line of it resolves. A resume never re-runs that gate -- it
    // never re-asks anything -- so it carries an empty outcome, and the
    // report then says nothing about a state it did not check rather than
    // inventing one.
    let (
        mut answers,
        approved,
        dns::GateOutcome {
            adoption,
            zone_not_serving_yet,
        },
    ) = if asked_fresh {
        plan_install(&pre)?
    } else {
        recover_plan(&pre)?
    };

    let mut st = state::InstallState {
        phase: state::Phase::Generated,
        target: cli.target.clone(),
        hostname: answers.hostname.clone(),
        approved_disk: approved.device.by_id.clone().unwrap_or_default(),
        // Consent from THIS run wins whenever this run actually asked.
        // Preferring the stored value unconditionally -- as the first
        // version did -- meant a resume that re-ran the interactive flow
        // discarded the operator's live answer in favour of a boolean
        // sitting in a writable file. The stored value is reused only on
        // the path that deliberately does not re-prompt.
        unauthenticated_accepted_for: if asked_fresh {
            answers.sso.unauthenticated_accepted_for.clone()
        } else {
            prior
                .as_ref()
                .map(|p| p.unauthenticated_accepted_for.clone())
                .unwrap_or_default()
        },
    };

    // Regenerate whenever this run collected answers -- not only on a
    // fresh run. A resume before the wipe re-runs the whole interactive
    // flow, so skipping regeneration installed a host from the PREVIOUS
    // run's settings while reporting the new ones. Both phases here are
    // pre-destructive, so re-rendering costs nothing.
    if asked_fresh {
        let files = generate(&pre, cli, &answers, &approved, &adoption)?;
        println!("\ngenerated host repository in {}:", pre.host_dir.display());
        for f in files.keys() {
            println!("  {f}");
        }
        state::write(&pre.host_dir, &st)?;
    }

    // --- Tier 1 preflight. Target still untouched. ---
    //
    // The authentication backstop is re-checked on EVERY invocation,
    // including resumes that skip the expensive evaluation. settings.
    // stage2.json lives in the operator's bind mount and they are told the
    // repository is theirs, so between an interrupted run and a resume it
    // can legitimately have changed. Skipping this on resume meant the one
    // guard against publishing an unauthenticated admin panel could be
    // stepped around by the most ordinary sequence there is: get
    // interrupted, run the same command again.
    let files = read_generated(&pre.host_dir)?;
    preflight::check_published_apps_are_authenticated(&files, &st.unauthenticated_accepted_for)?;

    // ALWAYS evaluate, including on a resume. The old code skipped Tier 1
    // once `PreflightPassed` had been reached and then hardcoded
    // `Evidence { evaluated: true }`, so `describe()` printed "evaluation
    // verified here" on a run that evaluated nothing -- the exact dishonesty
    // Evidence's own doc comment says it exists to prevent. Tier 1 is
    // eval-only and needs no builder, which is precisely what makes it
    // cheap enough to re-run; and re-running is not just honesty, it also
    // re-checks a host_dir the operator can legitimately have edited
    // between an interrupted run and this one -- the same reasoning as the
    // authenticated-apps check directly above.
    println!("\npreflight: evaluating the generated configuration ...");
    let evidence = preflight::tier1(
        &pre.host_dir,
        &files,
        &answers.hostname,
        &st.unauthenticated_accepted_for,
    )?;
    if reached.unwrap_or(state::Phase::Generated) < state::Phase::PreflightPassed {
        st.phase = state::Phase::PreflightPassed;
        state::write(&pre.host_dir, &st)?;
    }
    println!("preflight: {}", evidence.describe());

    // --- The destructive step. ---
    if reached.unwrap_or(state::Phase::Generated) < state::Phase::Installed {
        // EVERY invocation, not just resumes.
        //
        // nixos-anywhere's key upload is `until ssh-copy-id ...; do sleep
        // 3; done` -- an unbounded retry, in its own source. If it cannot
        // authenticate it does not fail, it loops silently forever. That
        // burned two three-hour CI runs and one real install before the
        // cause was found, and not one of them produced an error.
        //
        // We cannot fix that loop, but we can decline to enter it. The
        // probe costs one SSH round-trip against a target we are about to
        // erase anyway.
        check_target_still_reachable_before_reinstalling(&pre)?;
        let scratch = tempfile::tempdir()?;
        let extra = install::stage_extra_files(scratch.path(), &pre.host_dir)?;

        st.phase = state::Phase::Installing;
        state::write(&pre.host_dir, &st)?;

        println!("\ninstalling. THIS ERASES {}.", st.approved_disk);
        run_streaming(
            "nixos-anywhere",
            &install::args(
                &cli.target,
                &answers.hostname,
                &extra,
                cli.ssh_port,
                &pre.ssh_auth,
            ),
            &pre.host_dir,
        )?;

        // Recorded IMMEDIATELY, while still inside this block: from here
        // the disk is written, and a resume must never repartition it.
        st.phase = state::Phase::Installed;
        state::write(&pre.host_dir, &st)?;
    }

    // Deliberately its OWN block, not the tail of the one above. Both steps
    // are idempotent and neither touches the partition table, so a resume
    // can safely repeat them -- whereas leaving them inside the destructive
    // block meant an interruption in this window skipped them forever and
    // left the placeholder hardware configuration installed for good.
    if needs_hardware_config_transfer(reached) {
        println!("installed. waiting for the host to come back ...");
        wait_for_ssh(&pre)?;
        transfer_hardware_config(&pre)?;
        st.phase = state::Phase::HardwareConfigured;
        state::write(&pre.host_dir, &st)?;
    }

    // --- Stage 2. The host exists now, so the things that could not exist
    //     before it can be created. ---
    // Carried out of the stage-2 block and into the final report. An install
    // that finished with a degraded apply is still an install, but the closing
    // screen must not describe it as a clean one: the operator would otherwise
    // read "is installed" and have no way to know their apps have no DNS
    // records yet. Declared here rather than inside the block because a
    // resumed run skips the block entirely and must still report honestly.
    let mut degraded_apply = false;
    if reached.unwrap_or(state::Phase::Generated) < state::Phase::Stage2Applied {
        ensure_cloudflare_token(
            &mut answers,
            acme_secret_present(&pre)?,
            &mut prompt::stdio(),
            &answers::cloudflare_client,
        )?;

        // R4 A5, and now also a precondition of the transfer below: the
        // repository the operator keeps must hold the settings the host is
        // actually running. Left at stage 1, a later reinstall from this
        // same directory would silently produce an app-less machine.
        //
        // Done BEFORE the remote commands, because the target no longer
        // copies or commits anything itself -- it receives the result.
        let stage2_path = pre.host_dir.join("settings.stage2.json");
        let stage1_path = pre.host_dir.join("settings.stage1.json");
        let live = pre.host_dir.join("settings.json");
        if stage2_path.exists() {
            if !stage1_path.exists() {
                std::fs::rename(&live, &stage1_path)?;
            }
            std::fs::copy(&stage2_path, &live)?;
            let mut files = render::Files::new();
            files.insert("settings.json".into(), std::fs::read_to_string(&live)?);
            files.insert(
                "settings.stage1.json".into(),
                std::fs::read_to_string(&stage1_path)?,
            );
            render::write_repo(&pre.host_dir, &files)?;
        }
        install::commit_all(&pre.host_dir, "stage 2: enable apps")?;

        println!("\nenabling apps and authentication ...");
        for command in stage2::commands(&answers) {
            if command == install::extract_into_etc_ferrum() {
                let payload = install::tar_payload(&pre.host_dir, &[".git", "settings.json"])?;
                collect::run_with_stdin(&pre.target, &pre.ssh_auth, &command, &payload)?;
            } else if command.contains("put-secret") {
                let token = answers
                    .cloudflare_token
                    .as_ref()
                    .map(answers::Secret::expose)
                    .unwrap_or_default();
                collect::run_with_stdin(
                    &pre.target,
                    &pre.ssh_auth,
                    &command,
                    &stage2::acme_payload(token),
                )?;
            } else if command.contains("ferrum-apply apply") {
                // The long one: it builds the whole system on the target.
                // Streamed, so the operator can see it working rather than
                // watching one static line for twenty minutes and having to
                // guess whether it has hung -- which, in this feature's
                // history, it sometimes had.
                println!("  (building on the host -- this is the long step)");
                let code = collect::run_streaming_code(&pre.target, &pre.ssh_auth, &command)?;
                // Exit 3 is not a failed install. See
                // stage2::interpret_apply_exit -- the host has switched and is
                // running the new generation; something ferrum-apply manages,
                // most often the DNS reconcile, did not come up. Cloudflare
                // being rate-limited during an install is not a reason to tell
                // the operator their machine is broken.
                if stage2::interpret_apply_exit(code)? == stage2::ApplyOutcome::Degraded {
                    degraded_apply = true;
                    println!(
                        "\n  The system switched, but the apply reported a problem (its own \n                           output is above). The host is running the new generation.\n                           Re-run `ferrum-apply apply` on it once the cause is cleared."
                    );
                }
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

    report_external_reachability(&answers);
    final_report(
        &pre,
        &answers,
        &evidence,
        &adoption,
        zone_not_serving_yet.as_deref(),
        degraded_apply,
    )?;
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
///
/// **The adoption decision has to arrive here, not merely be reported.**
/// R1 A3 lets the operator type `adopt` at the pre-erase gate to hand a
/// record ferrum did not create over to ferrum; the host acts on that only
/// through `ferrum.proxy.dns.adoptedNames` in the settings this function
/// renders. Rendering without it -- which is what calling
/// [`render::render`] here does, since that wrapper substitutes
/// [`dns::Adoption::none`] -- produces an install where the gate said the
/// name was adopted and the host then leaves it alone: the "reported and
/// left alone" behaviour the operator explicitly opted out of.
///
/// # Arguments
/// * `pre` - the checked-in preconditions, for the host directory.
/// * `cli` - for the SSH directory the operator's public keys come from.
/// * `answers` - the operator's answers.
/// * `approved` - the confirmed disk selection.
/// * `adoption` - what `dns::gate` recorded at the pre-erase gate. Empty on
///   a resume, which never re-asks.
///
/// # Returns
/// The rendered files, also written to the host directory.
///
/// # Errors
/// If the installer carries no pinned revision, if no public key is
/// readable, or if rendering or writing fails.
fn generate(
    pre: &preconditions::Preconditions,
    cli: &Cli,
    answers: &answers::Answers,
    approved: &confirm::Approved,
    adoption: &dns::Adoption,
) -> anyhow::Result<render::Files> {
    let keys = preconditions::find_public_keys(&cli.ssh_dir)?;
    let rev = ferrum_revision()?;
    let files = render::render_with_adoption(answers, approved, &keys, rev, adoption)?;
    render::write_repo(&pre.host_dir, &files)?;
    Ok(files)
}

/// Re-reads the target and confirms the approved disk is still the disk.
///
/// Minutes pass between the inventory being printed and the serial being
/// typed, and a USB disk can be unplugged in that window.
///
/// This is the pre-invocation half. The post-kexec half is generated into
/// the host's `disko.nix` as a `preCreateHook` -- see
/// `render::precreate_serial_guard` -- because nixos-anywhere exposes no
/// hook back into this code.
fn recheck(pre: &preconditions::Preconditions, approved: &confirm::Approved) -> anyhow::Result<()> {
    let raw = collect::collect(&pre.target, &pre.ssh_auth)?;
    let mut devices = inventory::parse_lsblk(&raw.lsblk)?;
    inventory::attach_by_id(&mut devices, &inventory::parse_by_id(&raw.by_id));
    confirm::verify_still(approved, &devices)
}

/// Refuses a target whose architecture ferrum has no catalog for.
///
/// Every app in the catalog is built for `x86_64-linux`. Installing onto an
/// aarch64 box would get as far as a flake evaluation that cannot produce a
/// single service, so this refuses while the target is still untouched.
///
/// # Arguments
/// * `arch` - the `uname -m` the target reported.
///
/// # Errors
/// Returns an error naming the reported architecture when it is not `x86_64`.
fn check_arch(arch: &str) -> anyhow::Result<()> {
    if arch != "x86_64" {
        anyhow::bail!(
            "target reports architecture {:?}; ferrum's catalog is built for \
             x86_64-linux only",
            arch
        );
    }
    Ok(())
}

/// Collects and reports the target's inventory. Read-only throughout.
fn inventory_phase(
    pre: &preconditions::Preconditions,
) -> anyhow::Result<(Vec<inventory::Device>, bool)> {
    println!("\ncollecting inventory from {} ...", pre.target);
    let raw = collect::collect(&pre.target, &pre.ssh_auth)?;

    check_arch(&raw.arch)?;

    let mut devices = inventory::parse_lsblk(&raw.lsblk)?;
    if devices.is_empty() {
        anyhow::bail!("the target reports no whole block devices to install onto");
    }
    inventory::attach_by_id(&mut devices, &inventory::parse_by_id(&raw.by_id));

    println!(
        "\nfirmware: {}\narchitecture: {}\n\ndisks:\n{}",
        if raw.efi_present {
            "EFI (/sys/firmware/efi present)"
        } else {
            "legacy BIOS"
        },
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

/// The interactive half: inventory, answers, the disk gate, and the DNS
/// gate.
///
/// **The DNS gate's position is a requirement, not a detail** (R1 A7/A3).
/// It runs here, after the disk has been named and before anything has
/// been erased, because that is the last moment an answer about the
/// operator's zone can still change the outcome. Discovering after the
/// install that `plex.<domain>` points at the operator's old box means
/// ferrum publishes Plex, the name still answers from the old machine, and
/// the operator is handed a manual step -- reported, unreachable, and
/// exactly the hands-off failure R1 exists to remove. R2/A4 learned the
/// same lesson about the same window.
///
/// # Returns
/// The answers, the approved disk, and the gate's whole outcome -- what the
/// operator decided about the DNS names ferrum does not own, and whether
/// Cloudflare is serving the zone yet.
fn plan_install(
    pre: &preconditions::Preconditions,
) -> anyhow::Result<(answers::Answers, confirm::Approved, dns::GateOutcome)> {
    let (devices, efi_present) = inventory_phase(pre)?;
    let mut io = prompt::stdio();
    // R1 A8: the address is found ON THE TARGET, over the same SSH path
    // every other remote check uses. Detecting it from this process would
    // report the operator's own machine's address -- correct-looking,
    // wrong, and indistinguishable from the right answer afterwards.
    let mut detect = || address::detect(|cmd| collect::run(&pre.target, &pre.ssh_auth, cmd));
    let answers = answers::collect(&mut io, &answers::cloudflare_client, &mut detect)?;
    let approved = confirm::confirm(&devices, efi_present, &mut io)?;

    // Still pre-destructive: a refusal here costs a re-run, and every later
    // moment is a worse one to learn that ferrum cannot publish a record.
    let gate_outcome = dns::gate(&answers, &answers::cloudflare_client, &mut io)?;

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
    Ok((answers, approved, gate_outcome))
}

/// The resume half: recover what was decided, never re-ask.
///
/// The DNS gate is deliberately absent here. It is a pre-erase decision and
/// a resume runs after the erase, so re-asking would invite a different
/// answer against a half-installed machine -- the same reason the disk
/// question is not re-asked. The returned [`dns::GateOutcome`] is therefore
/// empty, and the final report stays silent about names this run never put
/// to the operator, and about a zone status this run never looked up,
/// rather than asserting a state it cannot know.
fn recover_plan(
    pre: &preconditions::Preconditions,
) -> anyhow::Result<(answers::Answers, confirm::Approved, dns::GateOutcome)> {
    let mut approved: confirm::Approved = serde_json::from_str(&std::fs::read_to_string(
        pre.host_dir.join("install-inventory.json"),
    )?)?;

    // Re-validate everything recovered from the bind mount, exactly as a
    // fresh run validates it. A deserialize is not a validation, and this
    // file is as writable as anything else in host_dir -- the by-id path
    // flows on into generated Nix and into disko's own unquoted device
    // loop, so "it came from lsblk" has to be made true on this path too.
    for device in std::iter::once(&mut approved.device).chain(approved.all_devices.iter_mut()) {
        if let Some(by_id) = device.by_id.as_deref() {
            inventory::validate_by_id_path(by_id)?;
        }
        // The CHILDREN's aliases too. Only the disk's was re-checked here,
        // and that was survivable exactly as long as a child's alias
        // reached no sink -- which is to say, as long as
        // `Filesystem::by_id` was always `None`. It no longer is: it now
        // renders into `custom/media.nix` as a `fileSystems.<mount>.device`
        // string, and it is now the value `verify::data_disk_checks`
        // interpolates into a command that `ssh` hands to a remote root
        // shell. A recovered value has not been through `parse_by_id`'s
        // allowlist, so it is allowlisted here instead -- the same "make it
        // true on every path in" argument as the line above, applied one
        // level down.
        for fs in device.children.iter_mut() {
            if let Some(by_id) = fs.by_id.as_deref() {
                inventory::validate_partition_by_id_path(by_id)?;
            }
        }
        // ...and the fields that RENDER, not just the one that reaches
        // Nix. Only by_id was re-checked here, so a recovered record could
        // still display as a different disk than it is -- the same
        // property SEC-C1 was about, arriving by the other ingress.
        // Refuses on name/serial, normalises the display-only fields; see
        // that function for why the two are treated differently.
        inventory::check_recovered_device(device)?;
    }

    let stage2 = std::fs::read_to_string(pre.host_dir.join("settings.stage2.json"))?;
    let hostname = read_hostname(&pre.host_dir)?;
    let answers = answers::from_stage2(&stage2, &hostname)?;
    Ok((answers, approved, dns::GateOutcome::none()))
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
    for rel in [
        "flake.nix",
        "disko.nix",
        "settings.json",
        "settings.stage2.json",
    ] {
        let p = dir.join(rel);
        if p.exists() {
            files.insert(rel.to_string(), std::fs::read_to_string(p)?);
        }
    }
    Ok(files)
}

/// Writes `install-inventory.json`, the record of which disk the operator
/// approved for erasure.
///
/// Delegates to [`state::write_json_atomically`] rather than repeating
/// temp-write-and-rename here. The two copies had drifted into the same
/// gap -- both called the result atomic, neither fsynced -- and one
/// implementation is how they stop drifting. This file matters for the same
/// reason `install-state.json` does: a resume reads it to decide what has
/// already been destroyed.
///
/// # Errors
/// Any serialization or filesystem failure.
fn write_json<T: serde::Serialize>(path: &std::path::Path, value: &T) -> anyhow::Result<()> {
    state::write_json_atomically(path, value)
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

/// Puts the generated hardware configuration onto the target and commits
/// it, then commits it locally too (R6 A2).
///
/// Separate from `--extra-files` of necessity: see
/// `install::hardware_config_commands`. Without this, `/etc/ferrum`'s
/// flake imports a file that is not there and every later apply -- stage 2
/// included -- fails to evaluate.
/// Whether this run still owes the host its real `hardware-configuration.nix`.
///
/// Split out so the CONTROL FLOW is pinned by a test, not just the phase
/// constants. A security re-scan showed that reverting the comparison here
/// to `< Phase::Installed` -- which is exactly the SEC-H1 defect -- left
/// all 205 tests passing, because the existing tests asserted the ordering
/// of the enum rather than the decision made from it.
///
/// # Arguments
/// * `reached` - the phase a previous run got to, or `None` for a fresh run
///   (or a resume that re-asked and therefore regenerated).
///
/// # Returns
/// `true` when the transfer must still run.
fn needs_hardware_config_transfer(reached: Option<state::Phase>) -> bool {
    reached.unwrap_or(state::Phase::Generated) < state::Phase::HardwareConfigured
}

/// Refuses a `hardware-configuration.nix` body that is still the stand-in.
///
/// Content, never existence: `render()` always writes this file now, so
/// its presence proves nothing. `{ ... }: { }` evaluates and boots
/// perfectly well, which is what makes shipping it silent.
///
/// # Arguments
/// * `body` - the file's contents as read from the host directory.
/// * `local` - the path, for the error message.
///
/// # Errors
/// When `body` still carries [`render::HARDWARE_CONFIG_SENTINEL`].
fn check_hardware_config_body(body: &str, local: &std::path::Path) -> anyhow::Result<()> {
    if body.contains(render::HARDWARE_CONFIG_SENTINEL) {
        anyhow::bail!(
            "{} is still the placeholder this installer wrote -- \
             `nixos-anywhere --generate-hardware-config` never replaced it. \
             Transferring it would install a host with no hardware \
             configuration: no initrd kernel modules, no microcode. Re-run \
             the install rather than continuing from here.",
            local.display()
        );
    }
    Ok(())
}

fn transfer_hardware_config(pre: &preconditions::Preconditions) -> anyhow::Result<()> {
    let local = pre.host_dir.join(install::HARDWARE_CONFIG);
    let body = std::fs::read_to_string(&local).map_err(|e| {
        anyhow::anyhow!(
            "nixos-anywhere did not leave {} behind ({e}). The generated flake \
             imports it unconditionally, so the host cannot evaluate its own \
             configuration without it.",
            local.display()
        )
    })?;

    // The file always EXISTS now -- render() writes a placeholder so the
    // preflight can evaluate. So existence proves nothing; only the content
    // does. Shipping the placeholder to the host would install a machine
    // with no hardware configuration at all, and it would boot and look
    // fine.
    check_hardware_config_body(&body, &local)?;

    // R6 A2 first, and on THIS side: the repository the operator keeps is
    // the one that built the machine. Committing here rather than on the
    // target is also what removes the target's git dependency -- see
    // install::extract_into_etc_ferrum.
    let mut files = render::Files::new();
    files.insert(install::HARDWARE_CONFIG.to_string(), body);
    render::write_repo(&pre.host_dir, &files)?;
    install::commit_all(&pre.host_dir, "ferrum-install: hardware configuration")?;

    // Then ship the objects, so the file is TRACKED on the target too.
    // Untracked is not a lesser state for Nix -- it is invisible.
    let payload = install::tar_payload(&pre.host_dir, &[".git", install::HARDWARE_CONFIG])?;
    collect::run_with_stdin(
        &pre.target,
        &pre.ssh_auth,
        &install::extract_into_etc_ferrum(),
        &payload,
    )?;
    println!("hardware configuration transferred and committed");
    Ok(())
}

/// Polls for the host to answer SSH again.
///
/// Polls the observable condition rather than sleeping a fixed time: a
/// fixed wait is either too short on slow hardware or wastes minutes on
/// fast hardware, and this runs on real machines with real POST times.
/// Refuses to re-enter `nixos-anywhere` when the target can no longer be
/// authenticated to.
///
/// Found by S13's resume test, and it is the defect that test exists for.
/// After the first run kexecs the target, the machine in RAM accepts only
/// the keys that run installed. A second `nixos-anywhere` invocation
/// generates a FRESH keypair and calls `ssh-copy-id` to install it -- using
/// the operator's credentials, which that environment no longer accepts.
/// `ssh-copy-id` then fails with "Permission denied
/// (publickey,keyboard-interactive)" and nixos-anywhere **retries it
/// forever**. Observed: 150 minutes of silent looping, killed by a
/// timeout, with no output of any kind for the operator to act on.
///
/// The retry loop is inside nixos-anywhere and not ours to remove, so this
/// refuses to hand control to it in the state where it cannot succeed. A
/// bounded window first, because a target mid-kexec or mid-reboot is
/// legitimately unreachable for a while and that is not this failure.
///
/// # Arguments
/// * `pre` - the target and credentials.
///
/// # Errors
/// When the target cannot be authenticated to within the window, with the
/// recovery an operator can actually carry out.
fn check_target_still_reachable_before_reinstalling(
    pre: &preconditions::Preconditions,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(300);
    while std::time::Instant::now() < deadline {
        if collect::run(&pre.target, &pre.ssh_auth, "true").is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    Err(cannot_reauthenticate(&pre.target.to_string()))
}

/// The error for a resume that can no longer reach its half-installed
/// target. Split out so its guidance is pinned by a test rather than
/// asserted by a comment.
///
/// # Arguments
/// * `target` - the `root@host` this run was pointed at.
fn cannot_reauthenticate(target: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "cannot authenticate to {target}, so refusing to start the install.\n\n\
         nixos-anywhere uploads its key with `until ssh-copy-id ...; do \
         sleep 3; done` -- an unbounded retry, in its own source. If it \
         cannot get in it does not fail, it loops silently forever. Handing \
         it an unreachable target means a hang with no error at all, so \
         this stops here instead.\n\n\
         Worth checking, commonest first:\n\
         - sshd may be rate-limiting you. OpenSSH 9.8+ penalises a source \
         IP after repeated auth failures, so an earlier failed attempt can \
         earn one. It expires by itself, usually within minutes.\n\
         - the target must accept your key as ROOT: ssh -i <key> \
         root@<target> true\n\
         - if an earlier run already kexec'd the target, the system now in \
         its RAM accepts only the keys THAT run installed. Power-cycle it \
         (the kexec'd system lives only in RAM), then re-run with --fresh, \
         accepting that the disk may already be partially written."
    )
}

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

/// Asks the target whether an earlier attempt already delivered the
/// encrypted Cloudflare secret.
///
/// # Errors
/// When the target cannot be asked. See [`interpret_acme_probe`] for why
/// that is an error rather than a `false`.
fn acme_secret_present(pre: &preconditions::Preconditions) -> anyhow::Result<bool> {
    interpret_acme_probe(collect::run(
        &pre.target,
        &pre.ssh_auth,
        "test -f /etc/ferrum/secrets/acme-dns.sops && echo yes || echo no",
    ))
}

/// Turns the probe's outcome into an answer, and refuses to invent one.
///
/// This used to end `.unwrap_or(false)`, which collapsed "the secret is not
/// there" and "I could not ask" into the same answer. The two lead to
/// opposite places. A `false` makes `ensure_cloudflare_token` re-prompt for
/// a Cloudflare token -- and a resume is the path taken after the very
/// failure that loses a credential, so the operator may no longer have it.
/// An SSH blip is also exactly the condition a resume exists to recover
/// from, which makes this the one place that failure was most likely to
/// occur and least affordable.
///
/// The command always prints `yes` or `no` on a connection that worked, so
/// anything else -- an error, or unexpected output -- means the question was
/// not answered, and the run stops rather than guessing. A stopped resume
/// costs a re-run; a wrong guess costs a credential the operator may not be
/// able to produce again.
///
/// # Arguments
/// * `outcome` - what `collect::run` returned for the probe command.
///
/// # Returns
/// `true` for `yes`, `false` for `no`.
///
/// # Errors
/// When the command failed, or printed anything else.
fn interpret_acme_probe(outcome: anyhow::Result<String>) -> anyhow::Result<bool> {
    let output = outcome.map_err(|e| {
        anyhow::anyhow!(
            "could not ask the target whether the Cloudflare secret is \
             already installed: {e}. Refusing to assume it is absent -- \
             that would re-prompt for a token this resume may not be able \
             to obtain again. Re-run once the target answers SSH."
        )
    })?;
    match output.trim() {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => anyhow::bail!(
            "the target answered {other:?} when asked whether the Cloudflare \
             secret is installed, which is neither \"yes\" nor \"no\". \
             Refusing to guess."
        ),
    }
}

/// Re-asks for the Cloudflare token on a resumed run, and checks it the
/// same way the first run does.
///
/// **This is the fix for a live defect (UF-20), not a refactor.** The token
/// is the one answer a resume cannot recover -- it was deliberately never
/// written anywhere -- so it is the one answer re-asked after the disk has
/// been erased. Until this function existed that second prompt took the
/// operator's input straight into `Secret`, reaching neither the charset
/// check that exists because a zsh trailing `%` once broke every
/// certificate order, nor the zone check A5 asks for. A resume is the
/// likeliest path after the very failure that loses a credential, so the
/// verification was absent exactly where it was needed most.
///
/// Both prompts now reach `answers::validate_and_verify_cloudflare_token`,
/// which is the only thing in this binary that produces a token-bearing
/// `answers::Secret`.
///
/// # Arguments
/// * `answers` - the recovered answers; its `cloudflare_token` is filled
///   in when one is needed and absent.
/// * `already_on_host` - whether an earlier attempt already delivered the
///   encrypted secret, in which case nothing is asked.
/// * `io` - the question-and-answer channel with the operator.
/// * `make_client` - how the token is checked; see
///   [`answers::ClientFactory`].
///
/// # Errors
/// An input failure, or a token that is malformed or cannot manage records
/// for the recovered base domain. Failing here costs a re-run; failing
/// later costs an install that finishes and publishes nothing.
fn ensure_cloudflare_token(
    answers: &mut answers::Answers,
    already_on_host: bool,
    io: &mut impl prompt::PromptIo,
    make_client: answers::ClientFactory<'_>,
) -> anyhow::Result<()> {
    // A host with no base domain publishes nothing and needs no token --
    // the same condition `token_still_needed` checks, taken first so the
    // domain the verification needs is in hand without an unreachable
    // branch to handle its absence.
    let Some(domain) = answers.base_domain.clone() else {
        return Ok(());
    };
    if answers.cloudflare_token.is_some() || !answers::token_still_needed(answers, already_on_host)
    {
        return Ok(());
    }

    let raw =
        io.ask_secret("\nCloudflare API token (not recoverable from the generated files):")?;
    answers.cloudflare_token = Some(answers::validate_and_verify_cloudflare_token(
        &raw,
        &domain,
        make_client,
    )?);
    Ok(())
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
        if answers.sso.enabled {
            checks.extend(verify::auth_checks(domain, &answers.apps, true));
        } else {
            // R9 A4: declining inverts the assertion rather than skipping it.
            checks.extend(verify::unauthenticated_checks(domain, &answers.apps));
        }
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

/// R1 A8's last step: prove the published address is where traffic arrives.
///
/// Every other check in this binary runs on the target, over SSH. This one
/// must not, and the distinction is the whole value of it -- a host asking
/// itself whether the world can reach it can only ever answer yes. So the
/// probe is made by this process, from the operator's own machine, across
/// the public internet, with no `Target` and no `SshAuth` anywhere in
/// reach: see [`verify::external_reachability_checks`].
///
/// **Reported, never fatal.** An operator legitimately installs before the
/// port forward exists, and failing the install at this point would destroy
/// a working host over a router setting. It runs after verification, so
/// nothing it says can be confused with the host being unhealthy.
///
/// # Arguments
/// * `answers` - for the base domain, the SSO choice, the app list and the
///   address the operator confirmed.
fn report_external_reachability(answers: &answers::Answers) {
    let Some(domain) = answers.base_domain.as_deref() else {
        return;
    };
    let checks = verify::external_reachability_checks(
        domain,
        &answers.apps,
        answers.sso.enabled,
        answers.dns.as_ref(),
    );
    if checks.is_empty() {
        return;
    }

    println!("\nchecking from HERE, over the internet -- not from the server:");
    for outcome in verify::assess(&checks, verify::tcp_probe, verify::outbound_control) {
        println!("{}", outcome.summary());
    }
}

/// The report's URL block and everything that qualifies it.
///
/// A pure function rather than a run of `println!` inside [`final_report`]
/// for one reason: the two caveats it emits are the only warning an
/// operator gets about hostnames that resolve and then do not answer, and a
/// warning nothing can assert is a warning a later edit deletes silently.
/// Returning lines makes both emissions testable without a host.
///
/// # Arguments
/// * `answers` - for the base domain, the SSO choice and the app list.
/// * `adoption` - R1 A3's outcome, appended as named unreachable apps.
/// * `zone_not_serving_yet` - the pre-erase gate's zone-status finding,
///   emitted **above** the urls rather than below them: this is the one
///   caveat that disqualifies every line in the list, so the operator has
///   to read it before the names, not after.
///
/// # Returns
/// The lines to print, or none at all for a host with no base domain --
/// which publishes nothing, so there is no URL and no caveat to qualify.
fn url_report(
    answers: &answers::Answers,
    adoption: &dns::Adoption,
    zone_not_serving_yet: Option<&str>,
) -> Vec<String> {
    let Some(domain) = answers.base_domain.as_deref() else {
        return Vec::new();
    };

    let mut lines = Vec::new();
    // First, because the alternative is the install's last screen offering
    // a list of hostnames that resolve for nobody with nothing qualifying
    // them -- which is R1's originating incident, restated by an installer
    // that had already worked out the answer and then threw it away.
    if let Some(detail) = zone_not_serving_yet {
        lines.push(String::new());
        lines.extend(dns::not_published_yet_lines(detail));
    }
    lines.extend([
        "\nurls:".to_string(),
        format!("  ferrum        https://{}.{domain}", dns::DAEMON_SUBDOMAIN),
    ]);
    if answers.sso.enabled {
        lines.push(format!("  sign-in       https://auth.{domain}"));
    }
    for app in &answers.apps {
        lines.push(format!("  {app:<13} https://{app}.{domain}"));
    }

    // A6, immediately after the urls block. The owner spent real time
    // concluding an install had failed because every one of these returned
    // HTTP 000 from inside the LAN while working perfectly from outside.
    lines.push(format!("\nnote: {}", dns::SPLIT_HORIZON_CAVEAT));
    // A7: the first url above is the one an operator visits first, so it
    // is the one that has to be described accurately. What is true of it
    // depends on how this host was answered, which is why the caveat takes
    // the SSO decision rather than being a fixed sentence.
    lines.push(format!(
        "note: {}",
        dns::daemon_record_caveat(domain, answers.sso.enabled)
    ));

    let contested = dns::report_lines(adoption);
    if !contested.is_empty() {
        lines.push(String::new());
        lines.extend(contested);
    }
    lines
}

/// Everything the operator needs to actually use the machine.
///
/// **Two caveats are printed here as well as in the pre-erase dry run**
/// (R1 A6 and the owner's H-01 option-C ruling), and the duplication is the
/// point. The dry run is read before the install and is far up the
/// scrollback by the time a hostname does not answer; this report is what
/// is still on screen. Both are fixed strings so a test can assert them
/// and a regression cannot quietly reword one out of existence.
///
/// # Arguments
/// * `pre` - the checked-in preconditions, for reading the credentials off
///   the host.
/// * `answers` - the operator's answers, for the hostname and URL list.
/// * `evidence` - what the preflight actually proved.
/// * `adoption` - R1 A3's outcome. A declined name is reported here as a
///   **named unreachable app**, because the alternative -- a line in a log
///   the operator scrolled past before the install began -- is how that
///   fact turns into an unexplained failure hours later.
/// * `zone_not_serving_yet` - the gate's zone-status finding, for exactly
///   the same reason and one door further out: a zone Cloudflare does not
///   serve yet makes **every** hostname below unreachable, not just one.
fn final_report(
    pre: &preconditions::Preconditions,
    answers: &answers::Answers,
    evidence: &preflight::Evidence,
    adoption: &dns::Adoption,
    zone_not_serving_yet: Option<&str>,
    degraded_apply: bool,
) -> anyhow::Result<()> {
    println!("\n{}", "=".repeat(64));
    // The headline tells the truth about which of the two endings this was.
    // "is installed" over a degraded apply is the false-success shape this
    // project keeps finding: a host that looks finished and has published
    // nothing, with the one line that could have said so spent on
    // congratulation.
    if degraded_apply {
        println!("{} is installed, with one thing unfinished.", answers.hostname);
    } else {
        println!("{} is installed.", answers.hostname);
    }
    println!("{}", "=".repeat(64));
    println!("\nproof: {}", evidence.describe());

    if degraded_apply {
        println!(
            "\nThe apply reported a problem and its output is above. The host \n\
             switched and is running the new generation, so this is not a \n\
             half-installed machine -- but something ferrum manages did not \n\
             come up, most often the DNS records for the addresses below. If \n\
             a hostname does not resolve, that is why.\n\n  \
             Fix the cause, then on the host:  ferrum-apply apply"
        );
    }

    for line in url_report(answers, adoption, zone_not_serving_yet) {
        println!("{line}");
    }

    // Printed once, to the terminal, and written to no file.
    println!("\nfirst-run credentials -- shown ONCE, stored nowhere by this installer:");
    for (what, path) in verify::credential_paths(answers.sso.enabled) {
        match collect::run(&pre.target, &pre.ssh_auth, &verify::read_credential_command(path)) {
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
    /// "The secret is not on the host" and "I could not ask" must not be
    /// the same answer.
    ///
    /// The probe ended `.unwrap_or(false)`, so an SSH failure -- the very
    /// condition a resume exists to recover from -- was reported as the
    /// secret being absent, and `ensure_cloudflare_token` then re-prompted
    /// for a Cloudflare token the operator may no longer hold.
    #[test]
    fn an_unreachable_target_is_not_an_absent_secret() {
        let err = interpret_acme_probe(Err(anyhow::anyhow!("ssh: connect: timed out")))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("could not ask"),
            "the failure has to name itself: {err}"
        );
        assert!(
            err.contains("timed out"),
            "and carry the underlying cause: {err}"
        );
    }

    /// The two answers the probe can actually give still work, so refusing
    /// an error cannot be satisfied by refusing everything.
    #[test]
    fn the_probes_two_real_answers_are_read_as_themselves() {
        assert!(interpret_acme_probe(Ok("yes\n".to_string())).unwrap());
        assert!(!interpret_acme_probe(Ok("no\n".to_string())).unwrap());
    }

    /// A connection that worked always prints one of those two words.
    /// Anything else means something answered that was not the probe.
    #[test]
    fn an_unrecognised_answer_is_not_guessed_at() {
        assert!(interpret_acme_probe(Ok(String::new())).is_err());
        assert!(interpret_acme_probe(Ok("Permission denied".to_string())).is_err());
    }

    /// S13's resume test found nixos-anywhere looping on `ssh-copy-id`
    /// for 150 minutes with no output after a kill mid-install. The retry
    /// is inside nixos-anywhere; what we control is refusing to hand it
    /// control in the state where it cannot succeed -- and saying
    /// something the operator can act on.
    #[test]
    fn the_resume_refusal_explains_the_hang_and_names_a_real_recovery() {
        let raw = super::cannot_reauthenticate("root@saltbox").to_string();
        // Lowercased: these assertions are about the ADVICE being present,
        // not about how a sentence happens to be capitalised.
        let msg = raw.to_lowercase();
        assert!(msg.contains("root@saltbox"), "{msg}");
        // Why it refuses rather than trying: the alternative is a silent
        // hang, which is what an operator actually experienced.
        assert!(msg.contains("forever"), "{msg}");
        // The rate-limit cause, which is what actually bit on the first
        // real install: hundreds of failed ssh-copy-id attempts earned the
        // operator's own IP an OpenSSH per-source penalty, and the next
        // run then could not connect for reasons nothing explained.
        assert!(msg.contains("rate-limiting"), "{msg}");
        assert!(msg.contains("root@<target> true"), "{msg}");
        // The cause, so it is not mistaken for a network problem.
        assert!(msg.contains("kexec"), "{msg}");
        // A recovery that works, and both halves of it.
        assert!(msg.contains("power-cycle"), "{msg}");
        assert!(msg.contains("--fresh"), "{msg}");
        // And the honest warning about what --fresh means here.
        assert!(msg.contains("partially written"), "{msg}");
    }

    use super::{
        check_hardware_config_body, ensure_cloudflare_token, needs_hardware_config_transfer,
        url_report,
    };
    use crate::prompt::testing::Scripted;
    use crate::state::Phase;
    use ferrum_dns::testing::{CannedResponse, FakeCloudflare, Route, TEST_TOKEN};

    /// A fake Cloudflare that resolves `thesyms.ca` with no delegation.
    fn healthy_cloudflare() -> FakeCloudflare {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "thesyms.ca",
                "name_servers": ["amber.ns.cloudflare.com"],
            }])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );
        fake
    }

    fn verifying_against(
        fake: &FakeCloudflare,
    ) -> impl Fn(ferrum_dns::Secret) -> ferrum_dns::client::Client + '_ {
        let base_url = fake.base_url().to_string();
        move |token| ferrum_dns::client::Client::with_base_url(token, base_url.clone())
    }

    /// Answers as a resume recovers them: everything except the token,
    /// which was deliberately never written anywhere.
    fn recovered_answers() -> answers::Answers {
        answers::from_stage2(
            &serde_json::json!({
                "proxy": { "enable": true, "baseDomain": "thesyms.ca" },
                "apps": { "sonarr": { "enable": true } },
            })
            .to_string(),
            "saltbox",
        )
        .expect("the stage-2 document is well formed")
    }

    /// UF-20, the defect this story exists to fix.
    ///
    /// The resumed run is the second of the installer's two token prompts,
    /// and until now it took the operator's input straight into `Secret`,
    /// reaching neither the charset check nor A5's zone check. It is the
    /// likelier prompt after the failure that loses a credential, so the
    /// verification was missing precisely where it was needed most.
    ///
    /// Mutation check: put the bare `ask_secret` wrapped in `answers`'
    /// `Secret` constructor back at the call site in the stage-2 block and
    /// this test's sibling
    /// `the_resume_call_site_cannot_mint_an_unverified_token` fails; revert
    /// the verification inside `ensure_cloudflare_token` and this one does.
    #[test]
    fn a_resumed_run_refuses_a_token_the_zone_check_rejects() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );
        let mut answers = recovered_answers();
        let mut io = Scripted::new(&[TEST_TOKEN]);

        let err = ensure_cloudflare_token(&mut answers, false, &mut io, &verifying_against(&fake))
            .expect_err("a resumed run must check the token, not just take it")
            .to_string();

        assert!(err.contains("9109"), "{err}");
        assert!(err.contains("/run/secrets/acme-dns"), "{err}");
        assert!(
            answers.cloudflare_token.is_none(),
            "a refused token must not be kept"
        );
    }

    /// The charset check, at the prompt the resume uses. A zsh trailing
    /// `%` once broke every certificate order on a real install, and it
    /// reported itself as a DNS zone problem hours later.
    #[test]
    fn a_resumed_run_refuses_a_token_carrying_a_shell_artifact_without_calling_out() {
        let fake = healthy_cloudflare();
        let mut answers = recovered_answers();
        let mut io = Scripted::new(&["abcdefghij1234567890abcdefghij1234567890%"]);

        let err = ensure_cloudflare_token(&mut answers, false, &mut io, &verifying_against(&fake))
            .expect_err("a trailing % cannot go in an HTTP header")
            .to_string();

        assert!(err.contains("Authorization"), "{err}");
        assert!(
            fake.requests().is_empty(),
            "a malformed token is refused before it is sent anywhere"
        );
    }

    /// D-11(b), on the resume path: an empty answer is an error with a
    /// message, never an empty success and never an unauthenticated
    /// request whose blank response reads as "unsupported".
    #[test]
    fn a_resumed_run_refuses_an_empty_token_rather_than_proceeding_silently() {
        let fake = healthy_cloudflare();
        let mut answers = recovered_answers();
        let mut io = Scripted::new(&[""]);

        let err = ensure_cloudflare_token(&mut answers, false, &mut io, &verifying_against(&fake))
            .expect_err("an unset credential must fail loudly")
            .to_string();

        assert!(err.contains("required"), "{err}");
        assert!(answers.cloudflare_token.is_none());
        assert!(fake.requests().is_empty());
    }

    /// The happy path, and the proof the verification really ran: the fake
    /// saw the zone listing, and the token went out only as a header.
    #[test]
    fn a_resumed_run_accepts_and_actually_checks_a_good_token() {
        let fake = healthy_cloudflare();
        let mut answers = recovered_answers();
        let mut io = Scripted::new(&[TEST_TOKEN]);

        ensure_cloudflare_token(&mut answers, false, &mut io, &verifying_against(&fake))
            .expect("a token scoped to the zone is accepted");

        assert_eq!(
            answers
                .cloudflare_token
                .as_ref()
                .map(answers::Secret::expose),
            Some(TEST_TOKEN)
        );
        assert_eq!(
            io.secret_asks.len(),
            1,
            "the token must use the non-echoing prompt"
        );
        let requests = fake.requests();
        assert!(!requests.is_empty(), "no request means no verification");
        for request in requests {
            assert_eq!(
                request.header("authorization"),
                Some(format!("Bearer {TEST_TOKEN}").as_str())
            );
            assert!(!request.path.contains(TEST_TOKEN) && !request.query.contains(TEST_TOKEN));
        }
    }

    /// Nothing is asked when nothing is owed -- a token already delivered
    /// to the host on an earlier attempt, or a host that publishes nothing.
    #[test]
    fn a_resumed_run_asks_for_nothing_it_does_not_need() {
        let fake = FakeCloudflare::start();
        let mut delivered = recovered_answers();
        let mut io = Scripted::new(&[]);
        ensure_cloudflare_token(&mut delivered, true, &mut io, &verifying_against(&fake))
            .expect("the secret is already on the host");

        let mut no_domain = answers::from_stage2(
            &serde_json::json!({ "apps": { "sonarr": { "enable": true } } }).to_string(),
            "saltbox",
        )
        .unwrap();
        ensure_cloudflare_token(&mut no_domain, false, &mut io, &verifying_against(&fake))
            .expect("a host with no base domain publishes nothing");

        assert!(io.secret_asks.is_empty(), "nothing should have been asked");
        assert!(
            fake.requests().is_empty(),
            "nothing should have been checked"
        );
    }

    /// The other half of the UF-20 guard, and the reason it is written
    /// against the source text rather than against behaviour.
    ///
    /// The tests above pin what `ensure_cloudflare_token` *does*. They
    /// cannot pin that the stage-2 block still *calls* it: re-introducing
    /// the bare prompt at the call site leaves every one of them passing
    /// while the live defect is back. In a binary crate there is no seam to
    /// observe the call site through, so the call site is asserted
    /// directly. The repo already does this shape of check -- `nix/modules/
    /// flake/checks.nix` does a line lookup against `CATALOG_APPS` for the
    /// same reason.
    ///
    /// Mutation check: restore the bare `ask_secret` -> `Secret::new` at
    /// the stage-2 call site and this fails on both assertions.
    #[test]
    fn the_resume_call_site_cannot_mint_an_unverified_token() {
        let source = include_str!("main.rs");
        // Built at runtime so the needle is not itself a match in this file.
        let bare_constructor = format!("{}::{}(", "Secret", "new");
        assert!(
            !source.contains(&bare_constructor),
            "this binary must not construct a token-bearing Secret directly: the \
             only legitimate producer is answers::validate_and_verify_cloudflare_token, \
             which is what makes A5's zone check unavoidable on both prompts"
        );
        let production_factory = format!("&{}::{}", "answers", "cloudflare_client");
        assert_eq!(
            source.matches(production_factory.as_str()).count(),
            3,
            "the two token-collection sites -- the first interactive run via \
             answers::collect, and the stage-2 resume via ensure_cloudflare_token -- \
             must hand the real Cloudflare client to the verification; the third is \
             R1 A7's pre-erase dry run in plan_install, which reads the zone with the \
             same credential and mints no Secret of its own"
        );
    }

    /// SEC-H1, pinned at the decision rather than the enum.
    ///
    /// Mutation check: revert the comparison in
    /// `needs_hardware_config_transfer` to `< Phase::Installed` and this
    /// fails. Before this test that mutation was silent.
    #[test]
    fn a_run_recorded_at_installed_still_owes_the_hardware_config_transfer() {
        assert!(
            needs_hardware_config_transfer(Some(Phase::Installed)),
            "this is SEC-H1: a run interrupted between nixos-anywhere \
             returning and the transfer records Installed, and must still \
             transfer on the next run -- otherwise the placeholder becomes \
             the host's permanent hardware configuration"
        );
        // Fresh runs and every earlier phase also owe it.
        for p in [
            None,
            Some(Phase::Generated),
            Some(Phase::PreflightPassed),
            Some(Phase::Installing),
        ] {
            assert!(needs_hardware_config_transfer(p), "{p:?}");
        }
        // ...and once done, it is not repeated.
        for p in [
            Phase::HardwareConfigured,
            Phase::Stage2Applied,
            Phase::Verified,
        ] {
            assert!(!needs_hardware_config_transfer(Some(p)), "{p:?}");
        }
    }

    /// Mutation check: replace the body of `check_hardware_config_body`
    /// with `Ok(())` and this fails. Before this test that mutation was
    /// silent.
    #[test]
    fn the_placeholder_hardware_config_is_refused_at_the_transfer() {
        let path = std::path::Path::new("/etc/ferrum/hardware-configuration.nix");
        let mut files = render::Files::new();
        render::insert_hardware_config_placeholder(&mut files);
        let err = check_hardware_config_body(&files["hardware-configuration.nix"], path)
            .expect_err("the stand-in must never be transferred to the host");
        let msg = err.to_string();
        assert!(msg.contains("still the placeholder"), "{msg}");
        assert!(msg.contains("no microcode"), "{msg}");

        // A real generated config passes.
        check_hardware_config_body(
            "{ config, lib, modulesPath, ... }:\n{\n  boot.initrd.availableKernelModules = [ \"nvme\" ];\n}\n",
            path,
        )
        .expect("a real hardware configuration must be accepted");
    }

    use super::check_arch;

    #[test]
    fn an_x86_64_target_is_accepted() {
        assert!(check_arch("x86_64").is_ok());
    }

    #[test]
    fn a_non_x86_64_target_is_refused_by_name() {
        // Refused BEFORE the disk gate, so an operator who points the
        // installer at an ARM box is told why rather than watching a flake
        // evaluation fail after the disks are already partitioned.
        let err = check_arch("aarch64").unwrap_err().to_string();
        assert!(err.contains("aarch64"), "{err}");
        assert!(err.contains("x86_64-linux"), "{err}");
    }

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

    /// SEC-CRIT-001 was "the backstop is skipped on resume", and it was
    /// reintroducible precisely because no test pinned the call. This reads
    /// the source of `run()` and asserts the call happens before every
    /// destructive branch -- crude, but it fails if someone deletes or
    /// moves it, which is the property that was missing.
    #[test]
    fn the_authentication_backstop_runs_before_anything_destructive() {
        let src = include_str!("main.rs");
        let body = &src[src.find("fn run(cli: &Cli)").expect("run() exists")..];

        let backstop = body
            .find("check_published_apps_are_authenticated")
            .expect("the authentication backstop call has been REMOVED from run()");
        for destructive in ["stage_extra_files", "Phase::Installing", "nixos-anywhere"] {
            let at = body.find(destructive).unwrap_or(usize::MAX);
            assert!(
                backstop < at,
                "the backstop must run before {destructive:?}; SEC-CRIT-001 was \
                 exactly this call being skipped"
            );
        }
        // ...and it must not be inside the phase-gated block, or a resume
        // skips it again.
        let gated = body
            .find("< state::Phase::PreflightPassed")
            .unwrap_or(usize::MAX);
        assert!(backstop < gated, "the backstop must not be phase-gated");
    }

    // ---- R1-S11 Part 1: the adoption wire -----------------------------

    /// **The wire, pinned at the call site.**
    ///
    /// R1-S12 built adoption end to end -- the gate, the settings field, the
    /// Nix option, the reconciler -- and could not connect the last hop,
    /// because `main.rs` belonged to another lane. The result was an
    /// installer where the operator typed `adopt`, was told the record was
    /// adopted, and the host then left it alone.
    ///
    /// `generate` cannot be called from a test: it needs `ferrum_revision`,
    /// a compile-time `option_env!` that is absent outside Nix. So this
    /// reads its source, the way
    /// `the_authentication_backstop_runs_before_anything_destructive` does.
    /// Crude, and it is exactly the property that was missing.
    ///
    /// Mutation check: put `render::render` back in `generate`, or drop the
    /// `adoption` argument at either end, and this fails.
    #[test]
    fn generate_renders_with_the_adoption_decision_the_gate_returned() {
        let src = include_str!("main.rs");
        let body = &src[src.find("\nfn generate(").expect("generate() exists")..];
        let body = &body[..body.find("\n}\n").expect("generate() ends")];

        assert!(
            body.contains("render::render_with_adoption("),
            "generate() must render WITH the adoption decision; render::render \
             substitutes Adoption::none() and the host then ignores every name \
             the operator adopted:\n{body}"
        );
        assert!(
            body.contains("rev, adoption)"),
            "the gate's own adoption value must reach the render call:\n{body}"
        );
        assert!(
            !body.contains("Adoption::none"),
            "keeping the parameter and passing an empty adoption is the same \
             bug wearing the right signature:\n{body}"
        );

        // ...and the caller must hand it the live value from the gate. A
        // freshly-constructed empty one would satisfy the assertions above
        // and still ship the bug.
        let run = &src[src.find("fn run(cli: &Cli)").expect("run() exists")..];
        assert!(
            run.contains("generate(&pre, cli, &answers, &approved, &adoption)"),
            "run() must pass the gate's own Adoption to generate()"
        );
    }

    /// **The behaviour, from the operator's keystroke to the settings file.**
    ///
    /// The gate is driven with a real prompt answering `adopt`, and the
    /// `Adoption` it returns goes through the very call `generate` now
    /// makes. Adopting must put the name in `adoptedNames`; declining must
    /// leave the key absent entirely -- an empty array would read to
    /// `modules/proxy/dns.nix` as "adopt nothing", which is the same outcome
    /// but asserts something the operator never said.
    ///
    /// Mutation check: have `Adoption::adopted_names` include the declined
    /// names, or have `dns::gate` record a decline as an adoption, and the
    /// halves swap and both assertions fail.
    #[test]
    fn an_adopted_name_reaches_the_settings_and_a_declined_one_does_not() {
        let settings_for = |answer: &str| {
            let fake = contested_cloudflare();
            let base_url = fake.base_url().to_string();
            let client =
                move |token| ferrum_dns::client::Client::with_base_url(token, base_url.clone());
            let mut io = Scripted::new(&[answer]);
            // Minted through the one sanctioned producer, because
            // `the_resume_call_site_cannot_mint_an_unverified_token` forbids
            // this file from constructing a token-bearing Secret directly --
            // and a test is not an exception to that, or the guard has a
            // hole in the shape of a test helper.
            let mut answers = adoption_answers();
            answers.cloudflare_token = Some(
                answers::validate_and_verify_cloudflare_token(TEST_TOKEN, "thesyms.ca", &client)
                    .expect("the fake accepts the test token"),
            );

            let adoption = dns::gate(&answers, &client, &mut io)
                .expect("the gate runs")
                .adoption;
            let files = render::render_with_adoption(
                &answers,
                &adoption_approved(),
                &["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAreal me@mac".to_string()],
                "535acdf",
                &adoption,
            )
            .expect("the repository renders");
            serde_json::from_str::<serde_json::Value>(&files["settings.stage2.json"])
                .expect("settings.stage2.json is JSON")
        };

        let adopted = settings_for("adopt");
        assert_eq!(
            adopted["proxy"]["dns"]["adoptedNames"],
            serde_json::json!(["plex.thesyms.ca"]),
            "the operator typed 'adopt' and the host must be told which name:\n{adopted:#}"
        );
        println!(
            "--- settings.stage2.json, proxy.dns -- operator typed 'adopt' ---\n{}",
            serde_json::to_string_pretty(&adopted["proxy"]["dns"]).unwrap()
        );

        let declined = settings_for("");
        assert!(
            declined["proxy"]["dns"].get("adoptedNames").is_none(),
            "a decline must leave the record alone and say nothing about it:\n{declined:#}"
        );
        println!(
            "--- settings.stage2.json, proxy.dns -- operator pressed enter (decline) ---\n{}",
            serde_json::to_string_pretty(&declined["proxy"]["dns"]).unwrap()
        );
    }

    /// Answers that reach the DNS gate: a base domain, a stated address,
    /// and an app whose record the zone below already holds.
    fn adoption_answers() -> answers::Answers {
        answers::Answers {
            hostname: "saltbox".into(),
            base_domain: Some("thesyms.ca".into()),
            acme_email: Some("me@thesyms.ca".into()),
            sso: crate::sso::SsoDecision {
                enabled: true,
                unauthenticated_accepted_for: Vec::new(),
                admin_email: Some("me@thesyms.ca".into()),
            },
            apps: vec!["plex".into()],
            // Filled in by the caller through
            // `answers::validate_and_verify_cloudflare_token`.
            cloudflare_token: None,
            dns: Some(answers::DnsDecision {
                target: answers::RecordTarget::A("203.0.113.10".parse().expect("a literal")),
                ddns_updater: true,
            }),
        }
    }

    /// A zone in which `plex.thesyms.ca` already exists and is not ferrum's
    /// -- the only situation in which the gate asks anything at all.
    ///
    /// `/zones` is scripted twice and the records route three times because
    /// this test makes two zone resolutions -- one for A5's token check, one
    /// inside the dry run -- and each reads the records once for `NS`
    /// delegations before `plan_records` reads it for the listing.
    fn contested_cloudflare() -> FakeCloudflare {
        let fake = FakeCloudflare::start();
        let zone = || {
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "thesyms.ca",
                "name_servers": ["amber.ns.cloudflare.com"],
            }]))
        };
        fake.script(Route::get("/zones"), zone());
        fake.script(Route::get("/zones"), zone());
        for _ in 0..2 {
            fake.script(
                Route::get("/zones/z1/dns_records"),
                CannedResponse::ok(serde_json::json!([])),
            );
        }
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([{
                "id": "r2",
                "name": "plex.thesyms.ca",
                "type": "A",
                "content": "198.51.100.9",
                "proxied": false,
            }])),
        );
        fake
    }

    /// A disk selection good enough to render a repository from.
    fn adoption_approved() -> confirm::Approved {
        let device = inventory::Device {
            name: "sda".into(),
            size: "500G".into(),
            model: Some("TEST".into()),
            serial: Some("SER123".into()),
            by_id: Some("/dev/disk/by-id/ata-TEST_SER123".into()),
            children: Vec::new(),
        };
        confirm::Approved {
            device: device.clone(),
            firmware: inventory::Firmware::Uefi,
            all_devices: vec![device],
        }
    }

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    /// Answers for a host that publishes something, so the report has a
    /// url block to qualify.
    fn published_answers() -> answers::Answers {
        answers::from_stage2(
            &serde_json::json!({
                "proxy": { "enable": true, "baseDomain": "thesyms.ca" },
                "auth": { "enable": true, "adminEmail": "me@thesyms.ca" },
                "apps": { "sonarr": { "enable": true } },
            })
            .to_string(),
            "saltbox",
        )
        .expect("the stage-2 document is well formed")
    }

    /// R1 A6, at the **second** of its two required emission sites.
    ///
    /// The dry run carries it too, and the duplication is deliberate: by
    /// the time a hostname does not answer, the dry run is far up the
    /// scrollback and this report is what is on screen. The owner spent
    /// real time concluding an install had failed because every hostname
    /// returned HTTP 000 from inside the LAN while working from outside.
    ///
    /// Mutation check: delete the `SPLIT_HORIZON_CAVEAT` push in
    /// `url_report` and this test fails; delete the one in `dns::render`
    /// and `dns::tests::the_dry_run_carries_the_split_horizon_caveat_verbatim`
    /// fails. Neither covers the other.
    #[test]
    fn the_final_report_carries_the_split_horizon_caveat_verbatim() {
        let report = url_report(&published_answers(), &dns::Adoption::none(), None).join("\n");
        assert!(report.contains(dns::SPLIT_HORIZON_CAVEAT), "{report}");
        // Immediately after the urls block, where A6 places it.
        let urls = report.find("urls:").expect("the url block is present");
        let caveat = report
            .find(dns::SPLIT_HORIZON_CAVEAT)
            .expect("the caveat is present");
        assert!(urls < caveat, "{report}");
    }

    /// A7, at the second of the caveat's two emission sites. By the time a
    /// hostname behaves unexpectedly the dry run is far up the scrollback
    /// and this report is what is on screen, so it carries the same
    /// state-accurate sentence rather than a generic one.
    ///
    /// `published_answers` keeps single sign-on, so this is the gated
    /// state; the ungated and unpublished states are covered per branch in
    /// `dns.rs`, which owns the sentence.
    ///
    /// Mutation check: delete the `daemon_record_caveat` push in
    /// `url_report` and this fails.
    #[test]
    fn the_final_report_describes_the_daemon_hostname_as_it_will_behave() {
        let answers = published_answers();
        assert!(answers.sso.enabled, "this test's premise");
        let report = url_report(&answers, &dns::Adoption::none(), None).join("\n");
        assert!(
            report.contains("https://ferrum.thesyms.ca"),
            "the url is offered: {report}"
        );
        assert!(
            report.contains(&dns::daemon_record_caveat("thesyms.ca", true)),
            "and it is qualified: {report}"
        );
    }

    /// The same site, the other published state -- and the gap the test
    /// above could not see.
    ///
    /// `the_final_report_describes_the_daemon_hostname_as_it_will_behave`
    /// asserts only the gated state, so replacing `answers.sso.enabled`
    /// with a literal `true` in `url_report` left every test in this crate
    /// green. An operator who declined single sign-on would then be told,
    /// on the last screen of the install, that the dashboard "asks for the
    /// single sign-on login at auth.<domain>" -- A7's defect pointed the
    /// wrong way, at the emission site this function's own docstring calls
    /// the one still on screen when a hostname misbehaves.
    ///
    /// `dns.rs` owns the sentence and covers each of its branches; what is
    /// covered here is that THIS site passes the real answer through.
    #[test]
    fn the_final_report_says_plainly_when_the_dashboard_will_be_ungated() {
        let mut answers = published_answers();
        answers.sso.enabled = false;
        let report = url_report(&answers, &dns::Adoption::none(), None).join("\n");

        assert!(
            report.contains(&dns::daemon_record_caveat("thesyms.ca", false)),
            "{report}"
        );
        assert!(
            report.contains("NO login"),
            "the ungated state must be stated, not implied: {report}"
        );
        assert!(
            !report.contains("single sign-on login at"),
            "and must not claim a gate that is not there: {report}"
        );
        assert!(
            !report.contains("sign-in "),
            "there is no sign-in url on a host with no Authelia: {report}"
        );
    }

    /// A3's decline, surfaced where the operator will actually see it
    /// rather than in a log line from before the disk was erased.
    #[test]
    fn a_declined_name_is_reported_as_a_named_unreachable_app() {
        let adoption = dns::Adoption {
            adopted: Vec::new(),
            declined: vec![dns::ForeignName {
                name: "plex.thesyms.ca".to_string(),
                current: "198.51.100.9".to_string(),
                wanted: "203.0.113.7".to_string(),
            }],
        };
        let report = url_report(&published_answers(), &adoption, None).join("\n");
        assert!(report.contains("NOT reachable"), "{report}");
        assert!(report.contains("plex.thesyms.ca"), "{report}");
        assert!(report.contains("198.51.100.9"), "{report}");
    }

    /// The zone's own status, at the **second** of its two emission sites.
    ///
    /// The dry run already shouts about a `pending` zone, and that is not
    /// enough: it is printed before the disk is erased and is far up the
    /// scrollback by the time the install finishes. What is left on screen
    /// is this list of hostnames -- none of which resolve for anyone --
    /// and until this test existed nothing qualified them. That is R1's
    /// originating incident ("auth.thesyms.ca did not resolve after the
    /// install, while the installer reported success") restated by an
    /// installer that had worked the answer out and then dropped it.
    ///
    /// Mutation check: delete the `not_published_yet_lines` extend in
    /// `url_report` and this test fails; delete the one in `dns::render`
    /// and `dns::tests::a_pending_zone_is_shouted_about_in_the_plan_rather\
    /// _than_passing_green` fails. Neither covers the other.
    #[test]
    fn the_final_report_says_the_hostnames_do_not_resolve_yet_before_listing_them() {
        let detail = "Cloudflare reports this zone as pending -- point your registrar at \
                      amber.ns.cloudflare.com.";
        let report = url_report(&published_answers(), &dns::Adoption::none(), Some(detail));
        let joined = report.join("\n");

        assert!(joined.contains("NOT PUBLISHED YET"), "{joined}");
        assert!(joined.contains(detail), "the advisory is carried: {joined}");
        assert!(
            joined.contains("none of these hostnames will resolve"),
            "{joined}"
        );

        // Above the list, not below it. A caveat printed after the urls is
        // read after the operator has already copied one into a browser.
        let warning = joined
            .find("NOT PUBLISHED YET")
            .expect("the warning is present");
        let urls = joined.find("urls:").expect("the url block is present");
        assert!(
            warning < urls,
            "the warning must precede the urls: {joined}"
        );
    }

    /// The ordinary case stays quiet. A caveat printed on every install is
    /// a caveat nobody reads on the one install that needed it.
    #[test]
    fn a_serving_zone_adds_no_warning_to_the_final_report() {
        let report = url_report(&published_answers(), &dns::Adoption::none(), None).join("\n");
        assert!(!report.contains("NOT PUBLISHED YET"), "{report}");
    }

    /// A host with no base domain publishes nothing, so there is no url
    /// block and nothing to qualify.
    #[test]
    fn a_host_with_no_base_domain_gets_no_url_block_and_no_caveats() {
        let answers =
            answers::from_stage2(&serde_json::json!({ "apps": {} }).to_string(), "saltbox")
                .expect("the stage-2 document is well formed");
        assert!(url_report(&answers, &dns::Adoption::none(), None).is_empty());
    }
}
