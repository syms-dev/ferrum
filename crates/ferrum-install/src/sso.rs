//! Whether the apps this install publishes will require a login.
//!
//! The gap this closes is between two defaults in the module tree.
//! `ferrum.auth.enable` is an `mkEnableOption`, so it defaults to **false**
//! (`modules/core/options.nix`), while an app's `exposure` defaults to
//! `"public"` whenever the proxy is enabled, and `modules/proxy/nginx.nix`
//! emits its `auth_request` block only when Authelia is on.
//!
//! An installer that simply took those defaults would publish Sonarr,
//! Radarr, Prowlarr, SABnzbd and qBittorrent admin interfaces on real
//! Let's Encrypt certificates with **no login at all** -- and then print
//! those URLs as its success report. qBittorrent and SABnzbd accept
//! arbitrary download paths, so that is a remote-code-execution surface,
//! not an information leak.
//!
//! So SSO is on by default here, and turning it off costs a second,
//! deliberately different confirmation that names what is about to be
//! exposed.

use crate::prompt::{confirm_exact, PromptIo};

/// Apps that ship their own login and are therefore not left open by an
/// absent Authelia. This is a property of those two apps, recorded
/// explicitly -- never a reason to weaken the default for the others.
pub const APPS_WITH_OWN_LOGIN: &[&str] = &["plex", "jellyfin"];

/// The phrase an operator must type to publish without authentication.
///
/// Deliberately a different *shape* from the disk gate's typed serial: an
/// operator who has just typed a serial must not be able to clear this one
/// with the same reflex, and the phrase itself states what they are doing.
pub const PUBLISH_UNAUTHENTICATED_PHRASE: &str = "publish without authentication";

#[derive(Debug, PartialEq, Eq)]
pub struct SsoDecision {
    pub enabled: bool,
    /// The operator passed R9 A2's typed confirmation to publish apps with
    /// no authentication. Carried so preflight can distinguish informed
    /// consent from an accidental default -- without it, declining is a
    /// path the operator can enter and never complete.
    pub unauthenticated_accepted: bool,
    /// Required by `modules/proxy/authelia.nix`, which asserts it is
    /// non-empty whenever auth is on.
    pub admin_email: Option<String>,
}

/// Apps that would be reachable from the internet with no login of any
/// kind if Authelia were off.
pub fn apps_left_open(apps: &[String]) -> Vec<&str> {
    apps.iter()
        .map(String::as_str)
        .filter(|a| !APPS_WITH_OWN_LOGIN.contains(a))
        .collect()
}

/// Rejects an address Authelia would refuse or that is obviously a typo.
///
/// Deliberately permissive about the exotic middle of the RFC and strict
/// about the shapes that are certainly wrong: the cost of a false reject
/// is one retyped answer, and the cost of a false accept is discovering it
/// after the host is built.
pub fn validate_email(raw: &str) -> anyhow::Result<String> {
    let email = raw.trim();
    let Some((local, domain)) = email.split_once('@') else {
        anyhow::bail!("{email:?} is not an email address");
    };
    if local.is_empty() || domain.is_empty() || email.matches('@').count() != 1 {
        anyhow::bail!("{email:?} is not an email address");
    }
    if !domain.contains('.') || domain.starts_with('.') || domain.ends_with('.') {
        anyhow::bail!("{email:?} has no usable domain part");
    }
    // An allowlist, not a denylist. This value is interpolated into
    // commands that run as root on the target, so "no whitespace" is not a
    // safety property -- backticks, $, ;, |, & and quotes all pass that.
    if !email
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._%+-@".contains(c))
    {
        anyhow::bail!(
            "{email:?} contains characters that are not allowed in an address \
             here (letters, digits and . _ % + - @ only)"
        );
    }
    Ok(email.to_string())
}

/// Decides whether this host gets SSO, asking the operator.
///
/// With no base domain nothing is published at all, so the question does
/// not arise and Authelia is left off -- there is no exposure to protect
/// and enabling it would only add a login to a host reachable from
/// nowhere.
///
/// # Errors
/// Input failures, and an operator who declines SSO but then fails the
/// second confirmation: that is a refusal to proceed, not a fallback to
/// the safe option, because continuing would silently contradict what they
/// just asked for.
pub fn decide(
    base_domain: Option<&str>,
    apps: &[String],
    io: &mut impl PromptIo,
) -> anyhow::Result<SsoDecision> {
    let Some(domain) = base_domain.filter(|d| !d.is_empty()) else {
        return Ok(SsoDecision {
            enabled: false,
            unauthenticated_accepted: false,
            admin_email: None,
        });
    };

    io.say(&format!(
        "\nSingle sign-on puts every app behind one login at auth.{domain}.\n\
         Without it, each app is reachable from the internet with whatever \
         login it has of its own -- and most have none."
    ));

    let answer = io.ask("Enable single sign-on? [Y/n]")?;
    let wants_sso = !matches!(answer.to_lowercase().as_str(), "n" | "no");

    if !wants_sso {
        let open = apps_left_open(apps);
        if open.is_empty() {
            io.say(
                "\nNo app you selected relies on ferrum for authentication, so \
                 nothing would be left open. Continuing without single sign-on.",
            );
            return Ok(SsoDecision {
                enabled: false,
                unauthenticated_accepted: false,
                admin_email: None,
            });
        }

        io.say(&format!(
            "\nThese will be published on {domain} with NO login:\n  {}\n\n\
             Anyone who finds the hostname can use them. qbittorrent and \
             sabnzbd can write files anywhere the service can reach.",
            open.join("\n  ")
        ));
        let confirmed = confirm_exact(
            io,
            &format!("Type '{PUBLISH_UNAUTHENTICATED_PHRASE}' to continue anyway:"),
            PUBLISH_UNAUTHENTICATED_PHRASE,
        )?;
        if !confirmed {
            anyhow::bail!(
                "not confirmed -- nothing has been changed. Re-run and answer \
                 yes to single sign-on, or select fewer apps."
            );
        }
        return Ok(SsoDecision {
            enabled: false,
            unauthenticated_accepted: true,
            admin_email: None,
        });
    }

    // Authelia asserts a non-empty admin email, so keep asking rather than
    // failing the whole run on one typo.
    for attempt in 0..3 {
        let raw = io.ask("Admin email address for single sign-on:")?;
        match validate_email(&raw) {
            Ok(email) => {
                return Ok(SsoDecision {
                    enabled: true,
                    unauthenticated_accepted: false,
                    admin_email: Some(email),
                })
            }
            Err(e) if attempt < 2 => io.say(&format!("  {e}")),
            Err(e) => return Err(e),
        }
    }
    unreachable!("the loop returns or errors on its last iteration")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::testing::Scripted;

    fn apps(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn sso_is_on_by_default_when_a_domain_is_configured() {
        let mut io = Scripted::new(&["", "admin@thesyms.ca"]);
        let d = decide(Some("thesyms.ca"), &apps(&["sonarr"]), &mut io).unwrap();
        assert_eq!(
            d,
            SsoDecision {
                enabled: true,
                unauthenticated_accepted: false,
                admin_email: Some("admin@thesyms.ca".into())
            },
            "an empty answer must take the safe path"
        );
    }

    #[test]
    fn an_explicit_yes_also_enables_it() {
        for yes in ["y", "Y", "yes", "YES"] {
            let mut io = Scripted::new(&[yes, "a@b.co"]);
            assert!(decide(Some("d.com"), &apps(&["sonarr"]), &mut io).unwrap().enabled);
        }
    }

    /// With no domain nothing is published, so there is nothing to protect.
    #[test]
    fn no_domain_means_the_question_never_arises() {
        for domain in [None, Some("")] {
            let mut io = Scripted::new(&[]);
            let d = decide(domain, &apps(&["sonarr"]), &mut io).unwrap();
            assert!(!d.enabled);
            assert!(io.asked.is_empty(), "must not ask: {:?}", io.asked);
        }
    }

    /// The core of R9 A2: declining is not a single keystroke.
    #[test]
    fn declining_requires_a_second_typed_confirmation() {
        let mut io = Scripted::new(&["n", PUBLISH_UNAUTHENTICATED_PHRASE]);
        let d = decide(Some("thesyms.ca"), &apps(&["sonarr", "sabnzbd"]), &mut io).unwrap();
        assert!(!d.enabled);
        assert_eq!(io.asked.len(), 2, "expected a second confirmation");
        assert!(
            d.unauthenticated_accepted,
            "the consent must be RECORDED, or preflight refuses the very state \
             the operator just typed a phrase to reach"
        );
    }

    /// Consent is only recorded when it was actually given.
    #[test]
    fn consent_is_not_recorded_on_any_other_path() {
        let mut io = Scripted::new(&["", "a@b.co"]);
        assert!(!decide(Some("d.com"), &apps(&["sonarr"]), &mut io).unwrap().unauthenticated_accepted);

        let mut io = Scripted::new(&["n"]);
        assert!(!decide(Some("d.com"), &apps(&["plex"]), &mut io).unwrap().unauthenticated_accepted,
                "nothing was left open, so nothing was consented to");

        let mut io = Scripted::new(&[]);
        assert!(!decide(None, &apps(&["sonarr"]), &mut io).unwrap().unauthenticated_accepted);
    }

    #[test]
    fn the_decline_warning_names_every_app_left_open() {
        let mut io = Scripted::new(&["n", PUBLISH_UNAUTHENTICATED_PHRASE]);
        decide(
            Some("thesyms.ca"),
            &apps(&["sonarr", "radarr", "qbittorrent"]),
            &mut io,
        )
        .unwrap();
        let t = io.transcript();
        for app in ["sonarr", "radarr", "qbittorrent"] {
            assert!(t.contains(app), "{app} missing from the warning:\n{t}");
        }
    }

    /// A reflex "y" must not clear the second gate -- that is the whole
    /// point of it being a different shape from the disk gate's serial.
    #[test]
    fn a_reflex_answer_does_not_clear_the_second_gate() {
        for reflex in ["y", "yes", "n", "DESTROY", ""] {
            let mut io = Scripted::new(&["n", reflex]);
            let err = decide(Some("d.com"), &apps(&["sonarr"]), &mut io).unwrap_err();
            assert!(err.to_string().contains("not confirmed"), "{reflex:?}: {err}");
        }
    }

    /// Failing the second gate stops the run. It does NOT quietly re-enable
    /// SSO: continuing would contradict what the operator just asked for.
    #[test]
    fn failing_the_second_gate_stops_rather_than_falling_back() {
        let mut io = Scripted::new(&["n", "nope"]);
        let err = decide(Some("d.com"), &apps(&["sonarr"]), &mut io)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing has been changed"), "{err}");
    }

    /// R9 A5: these two carry their own login, so declining with only
    /// those selected leaves nothing open and needs no second gate.
    #[test]
    fn apps_with_their_own_login_do_not_trigger_the_second_gate() {
        let mut io = Scripted::new(&["n"]);
        let d = decide(Some("thesyms.ca"), &apps(&["plex", "jellyfin"]), &mut io).unwrap();
        assert!(!d.enabled);
        assert_eq!(io.asked.len(), 1, "no second gate was needed");
    }

    #[test]
    fn one_unprotected_app_among_protected_ones_still_triggers_it() {
        assert_eq!(
            apps_left_open(&apps(&["plex", "jellyfin", "sonarr"])),
            vec!["sonarr"]
        );
    }

    #[test]
    fn a_bad_email_is_retried_not_fatal() {
        let mut io = Scripted::new(&["", "not-an-email", "admin@thesyms.ca"]);
        let d = decide(Some("thesyms.ca"), &apps(&["sonarr"]), &mut io).unwrap();
        assert_eq!(d.admin_email.as_deref(), Some("admin@thesyms.ca"));
        assert!(io.transcript().contains("not an email address"));
    }

    #[test]
    fn three_bad_emails_give_up() {
        let mut io = Scripted::new(&["", "a", "b", "c"]);
        assert!(decide(Some("d.com"), &apps(&["sonarr"]), &mut io).is_err());
    }

    #[test]
    fn email_validation_rejects_the_shapes_that_are_certainly_wrong() {
        for bad in ["a", "@b.com", "a@", "a@b", "a b@c.com", "a@@b.com", "a@.com", "a@b."] {
            assert!(validate_email(bad).is_err(), "accepted {bad:?}");
        }
        for good in ["a@b.co", "admin@thesyms.ca", "first.last+tag@sub.example.com"] {
            validate_email(good).unwrap_or_else(|e| panic!("rejected {good:?}: {e}"));
        }
    }
}
