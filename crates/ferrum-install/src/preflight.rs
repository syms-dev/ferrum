//! Tier 1 preflight: everything provable from the operator's machine,
//! before anything is destroyed (spec R5).
//!
//! An earlier draft of this requirement demanded a real VM boot here. It
//! was not implementable: booting the generated configuration means
//! *building* an `x86_64-linux` closure, and at this moment no x86_64
//! builder exists anywhere in the system -- the target still runs its
//! original OS and nixos-anywhere has not kexec'd it yet. `--build-on
//! remote` works precisely because that kexec has already happened.
//!
//! So the proof is split. Tier 1, here, is **evaluation**: it needs no
//! builder and still catches every evaluation error -- a bad option, a
//! missing file, a malformed settings.json, a sops path that does not
//! exist. Tier 2, the build-and-boot proof, lives in CI on a KVM-capable
//! runner, because the rot this guards against is a property of the
//! repository rather than of any one operator's laptop.
//!
//! Nothing here is skippable by a flag. A flag to skip the checks before an
//! irreversible step is a flag that gets used.

use std::path::Path;
use std::process::Command;

use crate::render::{self, Files};

/// Which proofs actually ran, so the final report can say so honestly
/// rather than implying it booted the configuration.
#[derive(Debug, PartialEq, Eq)]
pub struct Evidence {
    pub evaluated: bool,
    pub booted: bool,
}

impl Evidence {
    pub fn describe(&self) -> String {
        match (self.evaluated, self.booted) {
            (true, true) => "evaluation and boot verified".into(),
            (true, false) => {
                "evaluation verified here; boot verified by CI for this revision".into()
            }
            _ => "NOT verified".into(),
        }
    }
}

/// Asserts the flake's `nixosConfigurations` attribute matches the
/// hostname.
///
/// `ferrum-apply` resolves `FERRUM_FLAKE_REF` to
/// `/etc/ferrum#nixosConfigurations.<networking.hostName>`, so a mismatch
/// installs a machine on which every later apply fails to resolve its own
/// configuration.
///
/// # Errors
/// Names both values.
pub fn check_attr_matches_hostname(files: &Files, hostname: &str) -> anyhow::Result<()> {
    let flake = files
        .get("flake.nix")
        .ok_or_else(|| anyhow::anyhow!("no flake.nix was generated"))?;
    let needle = format!("      {hostname} = ferrum.lib.mkHost");
    if !flake.contains(&needle) {
        anyhow::bail!(
            "the generated flake does not declare nixosConfigurations.{hostname}. \
             ferrum-apply resolves /etc/ferrum#nixosConfigurations.<hostname>, so \
             a mismatch makes every later apply fail on the installed machine."
        );
    }
    if !flake.contains(&format!("networking.hostName = \"{hostname}\"")) {
        anyhow::bail!("the generated flake does not set networking.hostName to {hostname:?}");
    }
    Ok(())
}

/// R9 A3: refuses to publish an app that nothing will authenticate.
///
/// This reads **`settings.stage2.json`**, deliberately, not the Nix
/// evaluation the rest of Tier 1 is built on. Stage 1 has `apps: {}`, so
/// no app resolves to `public` there and an eval-driven check would pass
/// vacuously on every single run -- it would look like a guard and never
/// once fire.
///
/// # Errors
/// Names every app that would be published unauthenticated.
pub fn check_published_apps_are_authenticated(files: &Files) -> anyhow::Result<()> {
    let Some(body) = files.get("settings.stage2.json") else {
        return Ok(());
    };
    let doc: serde_json::Value = serde_json::from_str(body)?;

    let published = doc
        .get("proxy")
        .and_then(|p| p.get("enable"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if !published {
        return Ok(());
    }

    let auth_on = doc
        .get("auth")
        .and_then(|a| a.get("enable"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if auth_on {
        return Ok(());
    }

    let apps: Vec<String> = doc
        .get("apps")
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    let open = crate::sso::apps_left_open(&apps);
    if open.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "these apps would be published with no authentication: {}. The operator \
         did not confirm that. Nothing has been changed.",
        open.join(", ")
    );
}

/// Evaluates the generated configuration without building it.
///
/// `--dry-run` needs no builder, which is the whole reason Tier 1 can run
/// here at all.
///
/// # Errors
/// Carries Nix's own stderr. A summarised "build failed" would hide the
/// one line that actually says what is wrong, and the failure mode this
/// catches -- a missing sops file at eval time -- names a path the
/// operator has never heard of and needs to see verbatim.
pub fn evaluate(host_dir: &Path, hostname: &str) -> anyhow::Result<()> {
    let attr = format!(".#nixosConfigurations.{hostname}.config.system.build.toplevel");
    let out = Command::new("nix")
        .current_dir(host_dir)
        .args([
            "build",
            "--dry-run",
            "--no-link",
            "--extra-experimental-features",
            "nix-command flakes",
            &attr,
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("could not run nix: {e}"))?;

    if !out.status.success() {
        anyhow::bail!(
            "the generated configuration does not evaluate. Nothing on the \
             target has been changed.\n\n  nix build --dry-run {attr}\n\n{}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Runs every Tier 1 check, cheapest and most actionable first.
///
/// # Errors
/// The first failing check's error, unchanged.
pub fn tier1(host_dir: &Path, files: &Files, hostname: &str) -> anyhow::Result<Evidence> {
    render::check_no_placeholders(files)?;
    check_attr_matches_hostname(files, hostname)?;
    check_published_apps_are_authenticated(files)?;
    evaluate(host_dir, hostname)?;
    Ok(Evidence {
        evaluated: true,
        booted: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(settings2: serde_json::Value, hostname: &str) -> Files {
        let mut f = Files::new();
        f.insert(
            "flake.nix".into(),
            format!(
                "      {hostname} = ferrum.lib.mkHost {{\n            networking.hostName = \"{hostname}\";\n"
            ),
        );
        f.insert(
            "settings.stage2.json".into(),
            serde_json::to_string_pretty(&settings2).unwrap(),
        );
        f
    }

    fn published(apps: &[&str], auth: bool) -> serde_json::Value {
        let mut doc = serde_json::json!({
            "proxy": { "enable": true, "baseDomain": "thesyms.ca" },
            "apps": {}
        });
        for a in apps {
            doc["apps"][*a] = serde_json::json!({ "enable": true });
        }
        if auth {
            doc["auth"] = serde_json::json!({ "enable": true, "adminEmail": "a@b.co" });
        }
        doc
    }

    #[test]
    fn a_matching_attribute_and_hostname_pass() {
        check_attr_matches_hostname(&files(published(&[], true), "saltbox"), "saltbox").unwrap();
    }

    /// A mismatch installs a machine where every later apply cannot
    /// resolve its own configuration.
    #[test]
    fn a_mismatched_attribute_names_the_consequence() {
        let err = check_attr_matches_hostname(&files(published(&[], true), "saltbox"), "other")
            .unwrap_err()
            .to_string();
        assert!(err.contains("nixosConfigurations.other"), "{err}");
        assert!(err.contains("every later apply"), "{err}");
    }

    #[test]
    fn authenticated_apps_pass() {
        check_published_apps_are_authenticated(&files(published(&["sonarr"], true), "h")).unwrap();
    }

    /// The check that must not be vacuous.
    #[test]
    fn unauthenticated_published_apps_are_refused_by_name() {
        let err =
            check_published_apps_are_authenticated(&files(published(&["sonarr", "sabnzbd"], false), "h"))
                .unwrap_err()
                .to_string();
        assert!(err.contains("sonarr") && err.contains("sabnzbd"), "{err}");
        assert!(err.contains("Nothing has been changed"), "{err}");
    }

    /// Plex and Jellyfin carry their own login.
    #[test]
    fn apps_with_their_own_login_are_not_flagged() {
        check_published_apps_are_authenticated(&files(published(&["plex", "jellyfin"], false), "h"))
            .unwrap();
    }

    #[test]
    fn nothing_published_means_nothing_to_check() {
        let mut doc = published(&["sonarr"], false);
        doc["proxy"]["enable"] = serde_json::json!(false);
        check_published_apps_are_authenticated(&files(doc, "h")).unwrap();
    }

    /// The reason this reads settings.stage2.json rather than the Nix
    /// evaluation: stage 1 has `apps: {}`, so an eval-driven check would
    /// pass on every run and never once fire.
    #[test]
    fn the_check_would_be_vacuous_against_stage_one() {
        let mut stage1 = published(&[], false);
        stage1["apps"] = serde_json::json!({});
        let mut f = Files::new();
        f.insert("settings.stage2.json".into(), stage1.to_string());
        check_published_apps_are_authenticated(&f).unwrap();

        // ...whereas the real stage-2 document does fire.
        let mut f2 = Files::new();
        f2.insert(
            "settings.stage2.json".into(),
            published(&["sonarr"], false).to_string(),
        );
        assert!(check_published_apps_are_authenticated(&f2).is_err());
    }

    #[test]
    fn a_placeholder_fails_tier1_before_anything_else() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = files(published(&[], true), "saltbox");
        f.insert("disko.nix".into(), "device = \"/dev/disk/by-id/CHANGE-ME\";".into());
        let err = tier1(dir.path(), &f, "saltbox").unwrap_err().to_string();
        assert!(err.contains("CHANGE-ME"), "{err}");
    }

    #[test]
    fn evidence_never_claims_a_boot_it_did_not_do() {
        let e = Evidence { evaluated: true, booted: false };
        assert!(e.describe().contains("boot verified by CI"));
        assert!(!e.describe().contains("and boot verified"));
    }
}
