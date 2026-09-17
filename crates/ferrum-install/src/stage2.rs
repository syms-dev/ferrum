//! Stage 2: everything that cannot exist until the host does.
//!
//! App secrets, Authelia's two secrets, the Cloudflare token and correct
//! file ownership are one idea, not four. Each is a fact about a machine
//! that does not exist while the first build is being evaluated, and every
//! place the spec failed to model that produced a defect.
//!
//! The constraint underneath all of them: sops-nix requires each
//! `sops.secrets.<name>.sopsFile` to be a Nix path pointing at a file that
//! **physically exists at evaluation time**. On a machine being installed
//! from nothing, `/etc/ferrum/secrets/` does not exist and neither do those
//! files -- they are generated on the host, encrypted to the host's own
//! key, which cannot happen before the host exists.
//!
//! So stage 1 installs with no apps and no auth, and stage 2 turns both on.

use crate::answers::Answers;

/// The `--set-default` variables in `modules/core/overlays.nix` that are
/// derived from `ferrum.apps.*` or `ferrum.auth.*`, and therefore differ
/// between the two stages.
///
/// This is the whole list, walked rather than sampled. Of the fourteen
/// variables baked into the `ferrum-apply` wrapper, nine come from storage
/// or host configuration that is identical in both stages and one
/// (`FERRUM_AUTHELIA_STATE_DIR`) is a hardcoded literal. These five are the
/// remainder, and every one of them silently breaks stage 2 if left at its
/// stage-1 value:
///
/// | variable | left alone |
/// |---|---|
/// | `FERRUM_SERVARR_APPS` | baked empty; `main.rs`'s `unwrap_or_else` fires only when **unset**, so an empty string survives to `.filter(!is_empty)` and collects to an empty list. `ensure_all` generates nothing and sonarr/radarr/prowlarr's `sopsFile` is missing at eval. |
/// | `FERRUM_AUTH_ENABLED` | `ensure_authelia_secrets` skipped; both Authelia `sopsFile`s missing. |
/// | `FERRUM_ADMIN_EMAIL` | the generated Authelia user has no address. |
/// | `FERRUM_SABNZBD_STATE_DIR` | baked `""`, mapped to `None`, `ensure_sabnzbd_apikey` skipped, while the app declares its `sopsFile` unconditionally. |
/// | `FERRUM_SABNZBD_PORT` | falls back to 8080 and writes the wrong port into sabnzbd's ini. |
///
/// This works at all only because `overlays.nix` uses `--set-default`
/// rather than `--set`: the caller's environment wins over the value baked
/// in at build time.
///
/// **If a future phase adds any `--set-default` derived from `apps.*` or
/// `auth.*`, it belongs in this list.**
pub const STAGE2_OVERRIDDEN: &[&str] = &[
    "FERRUM_SERVARR_APPS",
    "FERRUM_AUTH_ENABLED",
    "FERRUM_ADMIN_EMAIL",
    "FERRUM_SABNZBD_STATE_DIR",
    "FERRUM_SABNZBD_PORT",
];

/// The three servarr apps `ferrum-apply`'s `secrets.rs` generates keys for.
/// qBittorrent, Plex, Jellyfin and SABnzbd have their own mechanisms and
/// are deliberately excluded, matching `overlays.nix`'s own list.
const SERVARR: &[&str] = &["sonarr", "radarr", "prowlarr"];

/// sabnzbd's default state directory and port, matching the module tree.
const SABNZBD_STATE_DIR: &str = "/var/lib/ferrum/state/sabnzbd";
const SABNZBD_PORT: &str = "8080";

/// Builds the environment the stage-2 apply must carry.
///
/// Driven FROM `STAGE2_OVERRIDDEN` rather than alongside it, so the list is
/// the single source of truth. Adding a name there without giving it a
/// value here fails to compile the match's exhaustiveness in spirit and
/// fails `every_documented_variable_is_emitted` in fact -- which is the
/// point, because the failure mode of a forgotten variable is a stage-2
/// build dying on a `.sops` path the operator has never heard of.
pub fn env(answers: &Answers) -> Vec<(String, String)> {
    let servarr: Vec<&str> = SERVARR
        .iter()
        .copied()
        .filter(|a| answers.apps.iter().any(|x| x == a))
        .collect();
    let sabnzbd_on = answers.apps.iter().any(|a| a == "sabnzbd");

    STAGE2_OVERRIDDEN
        .iter()
        .map(|&name| {
            let value = match name {
                "FERRUM_SERVARR_APPS" => servarr.join(","),
                "FERRUM_AUTH_ENABLED" => {
                    if answers.sso.enabled { "1" } else { "0" }.to_string()
                }
                "FERRUM_ADMIN_EMAIL" => answers.sso.admin_email.clone().unwrap_or_default(),
                "FERRUM_SABNZBD_STATE_DIR" => {
                    if sabnzbd_on { SABNZBD_STATE_DIR.to_string() } else { String::new() }
                }
                "FERRUM_SABNZBD_PORT" => SABNZBD_PORT.to_string(),
                other => unreachable!(
                    "{other} is listed in STAGE2_OVERRIDDEN but has no value here"
                ),
            };
            (name.to_string(), value)
        })
        .collect()
}

/// Renders the environment as a shell prefix, quoted.
pub fn env_prefix(answers: &Answers) -> String {
    env(answers)
        .into_iter()
        .map(|(k, v)| format!("{k}='{}'", v.replace('\'', r"'\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Repairs `/etc/ferrum/settings.json`'s ownership after first boot.
///
/// `nixos-anywhere --extra-files` copies everything **root-owned**, and it
/// cannot do better by name because the `ferrum` group does not exist at
/// copy time. The tmpfiles rule will not repair it either:
/// `modules/core/bootstrap.nix` uses `C`, which copies **only if the path
/// does not already exist**, so after a transfer it is a permanent no-op.
/// The only other code that looks at this merely warns.
///
/// Left unfixed, `ferrumd` cannot write settings.json and the dashboard
/// renders correctly while silently saving nothing.
pub fn ownership_repair() -> &'static str {
    "chown root:ferrum /etc/ferrum/settings.json && chmod 0664 /etc/ferrum/settings.json"
}

/// The commands stage 2 runs on the host, in order.
pub fn commands(answers: &Answers) -> Vec<String> {
    let mut cmds = vec![ownership_repair().to_string()];

    if answers.cloudflare_token.is_some() {
        // The payload is the systemd EnvironmentFile line, not a bare
        // token: modules/proxy/acme.nix hands the decrypted file to systemd
        // as an EnvironmentFile=, so a bare token produces a file ACME
        // cannot use. The value arrives on stdin, never in argv.
        cmds.push("ferrum-apply put-secret acme-dns".into());
    }

    cmds.push("cp /etc/ferrum/settings.stage2.json /etc/ferrum/settings.json".into());
    cmds.push(ownership_repair().to_string());
    cmds.push(
        "cd /etc/ferrum && git add -A && \
         (git diff --cached --quiet || git -c user.name=ferrum-install \
          -c user.email=ferrum-install@localhost commit -q -m 'stage 2: enable apps')"
            .into(),
    );
    cmds.push(format!("{} ferrum-apply apply", env_prefix(answers)));
    cmds
}

/// The stdin payload for `put-secret acme-dns`.
pub fn acme_payload(token: &str) -> String {
    format!("CLOUDFLARE_DNS_API_TOKEN={token}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sso::SsoDecision;

    fn answers(apps: &[&str], sso: bool) -> Answers {
        Answers {
            hostname: "saltbox".into(),
            base_domain: Some("thesyms.ca".into()),
            acme_email: Some("me@thesyms.ca".into()),
            sso: SsoDecision {
                enabled: sso,
                admin_email: sso.then(|| "admin@thesyms.ca".to_string()),
            },
            apps: apps.iter().map(|s| s.to_string()).collect(),
            cloudflare_token: Some("tok".into()),
        }
    }

    fn get(answers: &Answers, key: &str) -> String {
        env(answers)
            .into_iter()
            .find(|(k, _)| k == key)
            .unwrap_or_else(|| panic!("{key} not in the stage-2 environment"))
            .1
    }

    /// Every variable in the documented list must actually be emitted.
    /// Missing one is silent: the stage-2 build fails much later on a
    /// missing .sops path the operator has never heard of.
    #[test]
    fn every_documented_variable_is_emitted() {
        let e = env(&answers(&["sonarr"], true));
        let emitted: Vec<&str> = e.iter().map(|(k, _)| k.as_str()).collect();
        for expected in STAGE2_OVERRIDDEN {
            assert!(emitted.contains(expected), "{expected} is missing from {emitted:?}");
        }
        assert_eq!(e.len(), STAGE2_OVERRIDDEN.len(), "no extras either");
    }

    /// The nastiest of the five: an EMPTY string is not the same as unset.
    /// main.rs's unwrap_or_else fires only when unset, so the baked empty
    /// value survives the filter and collects to an empty list.
    #[test]
    fn servarr_apps_lists_only_the_selected_servarr_apps() {
        assert_eq!(get(&answers(&["sonarr", "plex"], true), "FERRUM_SERVARR_APPS"), "sonarr");
        assert_eq!(
            get(&answers(&["prowlarr", "radarr", "sonarr"], true), "FERRUM_SERVARR_APPS"),
            "sonarr,radarr,prowlarr",
            "order follows overlays.nix's own list"
        );
        assert_eq!(get(&answers(&["plex", "jellyfin"], true), "FERRUM_SERVARR_APPS"), "");
    }

    /// qbittorrent and sabnzbd have their own mechanisms and must not be
    /// treated as servarr apps, matching overlays.nix.
    #[test]
    fn non_servarr_apps_never_appear_in_the_servarr_list() {
        let v = get(&answers(&["qbittorrent", "sabnzbd", "jellyfin", "plex"], true), "FERRUM_SERVARR_APPS");
        assert_eq!(v, "");
    }

    #[test]
    fn auth_variables_track_the_sso_decision() {
        let on = answers(&["sonarr"], true);
        assert_eq!(get(&on, "FERRUM_AUTH_ENABLED"), "1");
        assert_eq!(get(&on, "FERRUM_ADMIN_EMAIL"), "admin@thesyms.ca");

        let off = answers(&["sonarr"], false);
        assert_eq!(get(&off, "FERRUM_AUTH_ENABLED"), "0");
        assert_eq!(get(&off, "FERRUM_ADMIN_EMAIL"), "");
    }

    /// sabnzbd declares its sopsFile unconditionally, so a stage-1 empty
    /// state dir means ensure_sabnzbd_apikey is skipped and the build
    /// fails on the missing file.
    #[test]
    fn sabnzbd_gets_a_state_dir_only_when_selected() {
        assert_eq!(
            get(&answers(&["sabnzbd"], true), "FERRUM_SABNZBD_STATE_DIR"),
            "/var/lib/ferrum/state/sabnzbd"
        );
        assert_eq!(get(&answers(&["sonarr"], true), "FERRUM_SABNZBD_STATE_DIR"), "");
        assert_eq!(get(&answers(&["sabnzbd"], true), "FERRUM_SABNZBD_PORT"), "8080");
    }

    #[test]
    fn the_prefix_quotes_every_value() {
        let p = env_prefix(&answers(&["sonarr"], true));
        assert!(p.contains("FERRUM_SERVARR_APPS='sonarr'"), "{p}");
        assert!(p.contains("FERRUM_AUTH_ENABLED='1'"), "{p}");
        assert!(p.contains("FERRUM_SABNZBD_STATE_DIR=''"), "empty must still be set: {p}");
    }

    /// An empty value must be EXPORTED as empty, not omitted -- omitting it
    /// would let the stage-1 baked value stand, which is the entire defect.
    #[test]
    fn empty_values_are_still_exported() {
        let p = env_prefix(&answers(&["plex"], false));
        for k in STAGE2_OVERRIDDEN {
            assert!(p.contains(&format!("{k}=")), "{k} was omitted from: {p}");
        }
    }

    #[test]
    fn a_quote_in_a_value_cannot_break_out_of_the_shell_word() {
        let mut a = answers(&["sonarr"], true);
        a.sso.admin_email = Some("wei'rd@example.com".into());
        let p = env_prefix(&a);
        assert!(p.contains(r"'\''"), "single quote must be escaped: {p}");
    }

    #[test]
    fn the_ownership_repair_is_what_bootstrap_nix_tells_you_to_run() {
        let c = ownership_repair();
        assert!(c.contains("chown root:ferrum /etc/ferrum/settings.json"));
        assert!(c.contains("chmod 0664"));
    }

    /// Ownership is repaired BEFORE and AFTER the settings swap: whether it
    /// survives depends on the copy mechanism, and `cp` over an existing
    /// file preserves ownership only if it truncates in place.
    #[test]
    fn ownership_is_repaired_on_both_sides_of_the_swap() {
        let c = commands(&answers(&["sonarr"], true));
        let swap = c.iter().position(|x| x.contains("settings.stage2.json")).unwrap();
        assert!(c[..swap].iter().any(|x| x.contains("chown root:ferrum")));
        assert!(c[swap..].iter().any(|x| x.contains("chown root:ferrum")));
    }

    #[test]
    fn the_token_is_delivered_before_the_apply() {
        let c = commands(&answers(&["sonarr"], true));
        let put = c.iter().position(|x| x.contains("put-secret acme-dns")).unwrap();
        let apply = c.iter().position(|x| x.contains("ferrum-apply apply")).unwrap();
        assert!(put < apply, "the .sops file must exist before the build evaluates");
    }

    #[test]
    fn no_token_means_no_put_secret() {
        let mut a = answers(&["sonarr"], true);
        a.cloudflare_token = None;
        assert!(!commands(&a).iter().any(|c| c.contains("put-secret")));
    }

    /// acme.nix hands the decrypted file to systemd as an EnvironmentFile,
    /// so a bare token produces a file ACME cannot use.
    #[test]
    fn the_acme_payload_is_an_environment_file_line() {
        assert_eq!(acme_payload("abc123"), "CLOUDFLARE_DNS_API_TOKEN=abc123");
    }

    #[test]
    fn the_apply_carries_the_whole_environment() {
        let c = commands(&answers(&["sonarr", "sabnzbd"], true));
        let apply = c.iter().find(|x| x.contains("ferrum-apply apply")).unwrap();
        for k in STAGE2_OVERRIDDEN {
            assert!(apply.contains(k), "{k} missing from: {apply}");
        }
    }

    /// Nix ignores untracked files inside a git tree, so the swapped
    /// settings must be committed before the apply re-evaluates /etc/ferrum.
    #[test]
    fn the_swapped_settings_are_committed_before_the_apply() {
        let c = commands(&answers(&["sonarr"], true));
        let commit = c.iter().position(|x| x.contains("git add -A")).unwrap();
        let apply = c.iter().position(|x| x.contains("ferrum-apply apply")).unwrap();
        assert!(commit < apply);
    }

    /// A resumed stage 2 must not fail because the first attempt committed.
    #[test]
    fn the_commit_is_a_no_op_when_nothing_changed() {
        let c = commands(&answers(&["sonarr"], true));
        let git = c.iter().find(|x| x.contains("git add -A")).unwrap();
        assert!(git.contains("git diff --cached --quiet ||"), "{git}");
    }
}
