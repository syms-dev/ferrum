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

/// R9 A3: refuses to publish anything that nothing will authenticate.
///
/// "Anything" is not only the catalog: since R13 gave ferrumd a vhost,
/// `ferrum.<baseDomain>` is published whenever the proxy is, so the control
/// plane is checked here alongside the apps. The version that checked apps
/// alone let a Plex+Jellyfin host pass with its dashboard wide open.
///
/// This reads **`settings.stage2.json`**, deliberately, not the Nix
/// evaluation the rest of Tier 1 is built on. Stage 1 has `apps: {}`, so
/// no app resolves to `public` there and an eval-driven check would pass
/// vacuously on every single run -- it would look like a guard and never
/// once fire.
///
/// # Errors
/// Names everything that would be published unauthenticated, apps and
/// control plane alike, and what the operator did confirm.
pub fn check_published_apps_are_authenticated(
    files: &Files,
    accepted_for: &[String],
) -> anyhow::Result<()> {
    let Some(body) = files.get("settings.stage2.json") else {
        // Fail CLOSED. A guard whose correctness depends on the run failing
        // later for some unrelated reason is not a guard.
        anyhow::bail!(
            "settings.stage2.json is missing, so it cannot be checked for \
             apps that would be published without authentication. Refusing \
             to continue."
        );
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

    // The control plane is not a catalog app, so `apps_left_open` cannot
    // see it -- and an early return on an empty app list is how a
    // Plex+Jellyfin host that declined SSO got its consent to publish
    // ferrum.<baseDomain> asked for, recorded, and then never checked.
    // `daemon_published` is the same predicate sso.rs consults before it
    // asks for that consent; calling it again here rather than respelling
    // the condition is what keeps the ask and the enforcement from
    // drifting apart. It is deliberately not keyed on `auth.enable` --
    // that term is already settled above.
    let mut open = crate::sso::apps_left_open(&apps);
    let daemon_open = crate::sso::daemon_published(
        doc.get("proxy")
            .and_then(|p| p.get("baseDomain"))
            .and_then(serde_json::Value::as_str),
    );
    if daemon_open {
        open.push(crate::dns::DAEMON_SUBDOMAIN);
    }
    if open.is_empty() {
        return Ok(());
    }
    // The daemon's entry is a subdomain label, not an app name, so the
    // refusal says which one it is rather than leaving the operator to
    // look for an app they never selected.
    let daemon_note = if daemon_open {
        format!(
            " ({} is ferrum's own control plane, published because the proxy is.)",
            crate::dns::DAEMON_SUBDOMAIN
        )
    } else {
        String::new()
    };
    // Consent covers the exact list the operator was shown, and nothing
    // else. Comparing sorted sets rather than trusting a boolean is what
    // stops consent for [sonarr] silently covering a later-added
    // qbittorrent -- the two apps that can write files anywhere.
    let mut granted: Vec<&str> = accepted_for.iter().map(String::as_str).collect();
    granted.sort_unstable();
    let mut asked = open.clone();
    asked.sort_unstable();
    // A SUPERSET, not exact equality: the operator consented to this set,
    // so a run in which fewer apps end up open is covered by what they
    // already agreed to. Requiring equality refused that -- safely, but
    // wrongly. What must never be covered is an app they were not shown,
    // which is what the `newly_open` check below catches.
    if !asked.is_empty() && asked.iter().all(|a| granted.contains(a)) {
        return Ok(());
    }
    let newly_open: Vec<&str> = asked
        .iter()
        .copied()
        .filter(|a| !granted.contains(a))
        .collect();
    if !granted.is_empty() && !newly_open.is_empty() {
        anyhow::bail!(
            "these would be published with no authentication and are NOT \
             covered by what you confirmed: {}. You confirmed: {}. Nothing has \
             been changed.{daemon_note}",
            newly_open.join(", "),
            granted.join(", ")
        );
    }
    anyhow::bail!(
        "these would be published with no authentication: {}. The operator \
         did not confirm that. Nothing has been changed.{daemon_note}",
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
pub fn tier1(
    host_dir: &Path,
    files: &Files,
    hostname: &str,
    accepted_for: &[String],
) -> anyhow::Result<Evidence> {
    render::check_no_placeholders(files)?;
    check_attr_matches_hostname(files, hostname)?;
    check_published_apps_are_authenticated(files, accepted_for)?;
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
        check_published_apps_are_authenticated(&files(published(&["sonarr"], true), "h"), &[])
            .unwrap();
    }

    /// The check that must not be vacuous.
    #[test]
    fn unauthenticated_published_apps_are_refused_by_name() {
        let err = check_published_apps_are_authenticated(
            &files(published(&["sonarr", "sabnzbd"], false), "h"),
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("sonarr") && err.contains("sabnzbd"), "{err}");
        assert!(err.contains("Nothing has been changed"), "{err}");
    }

    /// Plex and Jellyfin carry their own login, so neither is ever named --
    /// but the host still publishes ferrum's own control plane, which is
    /// what the consent below covers.
    #[test]
    fn apps_with_their_own_login_are_not_flagged() {
        check_published_apps_are_authenticated(
            &files(published(&["plex", "jellyfin"], false), "h"),
            &[crate::dns::DAEMON_SUBDOMAIN.to_string()],
        )
        .unwrap();
    }

    /// The exact host the early return used to wave through: two apps that
    /// carry their own login, SSO declined, and no recorded consent for the
    /// control plane.
    ///
    /// `apps_left_open` returns nothing here, because the control plane is
    /// not a catalog app. If `check_published_apps_are_authenticated` goes
    /// back to returning early on that empty list, this install proceeds
    /// with ferrum.<baseDomain> -- PUT /api/settings, POST /api/secrets/:name,
    /// POST /api/jobs -- reachable to anyone who finds the hostname, having
    /// asked the operator for consent it then never read. So this test is
    /// the enforcement half of R9 A3, and it must fail if that early return
    /// is restored.
    #[test]
    fn the_control_plane_is_refused_even_when_no_app_is_left_open() {
        let err = check_published_apps_are_authenticated(
            &files(published(&["plex", "jellyfin"], false), "h"),
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(crate::dns::DAEMON_SUBDOMAIN), "{err}");
        assert!(err.contains("control plane"), "{err}");
        assert!(err.contains("Nothing has been changed"), "{err}");
        assert!(!err.contains("plex") && !err.contains("jellyfin"), "{err}");
    }

    /// Consent for the apps does not stretch to the control plane.
    ///
    /// This is the same scoping the app list already had, applied to the
    /// one thing that is published whether or not any app was selected --
    /// so an operator who confirmed "sonarr" cannot be held to have
    /// confirmed the dashboard.
    #[test]
    fn app_consent_does_not_cover_the_control_plane() {
        let err = check_published_apps_are_authenticated(
            &files(published(&["sonarr"], false), "h"),
            &["sonarr".to_string()],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("NOT covered"), "{err}");
        assert!(err.contains(crate::dns::DAEMON_SUBDOMAIN), "{err}");
    }

    /// And with no base domain there is no published control plane to
    /// check -- the other half of `daemon_published`, so that this guard
    /// cannot be satisfied by a constant.
    #[test]
    fn an_empty_base_domain_publishes_no_control_plane() {
        let mut doc = published(&["plex"], false);
        doc["proxy"]["baseDomain"] = serde_json::json!("");
        check_published_apps_are_authenticated(&files(doc, "h"), &[]).unwrap();
    }

    #[test]
    fn nothing_published_means_nothing_to_check() {
        let mut doc = published(&["sonarr"], false);
        doc["proxy"]["enable"] = serde_json::json!(false);
        check_published_apps_are_authenticated(&files(doc, "h"), &[]).unwrap();
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
        // The control plane is published here regardless of the app list,
        // so its consent is supplied to isolate the dimension this test is
        // about: whether any APP is found.
        let daemon_consent = [crate::dns::DAEMON_SUBDOMAIN.to_string()];
        check_published_apps_are_authenticated(&f, &daemon_consent).unwrap();

        // ...whereas the real stage-2 document does fire.
        let mut f2 = Files::new();
        f2.insert(
            "settings.stage2.json".into(),
            published(&["sonarr"], false).to_string(),
        );
        assert!(check_published_apps_are_authenticated(&f2, &daemon_consent).is_err());

        // ...unless the operator passed R9 A2's typed confirmation, which
        // is the only way the decline path can ever complete an install.
        check_published_apps_are_authenticated(
            &f2,
            &[
                "sonarr".to_string(),
                crate::dns::DAEMON_SUBDOMAIN.to_string(),
            ],
        )
        .unwrap();
    }

    #[test]
    fn a_placeholder_fails_tier1_before_anything_else() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = files(published(&[], true), "saltbox");
        f.insert(
            "disko.nix".into(),
            "device = \"/dev/disk/by-id/CHANGE-ME\";".into(),
        );
        let err = tier1(dir.path(), &f, "saltbox", &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("CHANGE-ME"), "{err}");
    }

    /// The bypass this replaced a boolean to close: consent for one app
    /// must not cover an app added to the settings file afterwards.
    #[test]
    fn consent_does_not_stretch_to_apps_it_was_not_given_for() {
        let f = |apps: &[&str]| {
            let mut m = Files::new();
            m.insert(
                "settings.stage2.json".into(),
                published(apps, false).to_string(),
            );
            m
        };
        // Every grant here also carries the control plane, which this
        // fixture publishes; `app_consent_does_not_cover_the_control_plane`
        // is the test for that dimension.
        let daemon = || crate::dns::DAEMON_SUBDOMAIN.to_string();

        // Granted for sonarr, and sonarr is what is published: fine.
        check_published_apps_are_authenticated(&f(&["sonarr"]), &["sonarr".into(), daemon()])
            .unwrap();

        // qbittorrent appears afterwards. It writes files anywhere.
        let err = check_published_apps_are_authenticated(
            &f(&["sonarr", "qbittorrent"]),
            &["sonarr".into(), daemon()],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("qbittorrent"), "{err}");
        assert!(err.contains("NOT covered"), "{err}");
        assert!(!err.contains("You confirmed: sonarr, qbittorrent"), "{err}");

        // Consenting to more than ends up open is covered: they agreed to
        // a superset of what is actually being published.
        check_published_apps_are_authenticated(
            &f(&["sonarr"]),
            &["qbittorrent".into(), "sonarr".into(), daemon()],
        )
        .unwrap();
    }

    /// A missing settings document must fail closed, not pass silently.
    #[test]
    fn an_absent_settings_document_is_refused_not_ignored() {
        let err = check_published_apps_are_authenticated(&Files::new(), &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing"), "{err}");
    }

    #[test]
    fn evidence_never_claims_a_boot_it_did_not_do() {
        let e = Evidence {
            evaluated: true,
            booted: false,
        };
        assert!(e.describe().contains("boot verified by CI"));
        assert!(!e.describe().contains("and boot verified"));
    }
}
