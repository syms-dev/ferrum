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
//!
//! **The apps are not the only thing exposed.** Phase 1.7c R13 gave
//! ferrum's own control plane a vhost, so `ferrum.<baseDomain>` is now
//! published on a real certificate whenever the proxy is -- independently
//! of which apps were selected. Everything below therefore evaluates the
//! control plane separately from the catalog (see [`daemon_published`]),
//! because the version that did not was able to tell an operator "nothing
//! would be left open" about a host whose settings, secrets and system
//! generations were reachable to anyone who found the hostname.

use crate::dns::DAEMON_SUBDOMAIN;
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
    /// Exactly the apps the operator was shown when they typed R9 A2's
    /// phrase. A bare boolean was an authorization bypass: unscoped
    /// consent for one app silently covered any app added later.
    pub unauthenticated_accepted_for: Vec<String>,
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

/// Whether this host will publish ferrum's own control plane on a real
/// hostname: the installer's side of `daemonPublished` in
/// `modules/proxy/lib.nix`.
///
/// That predicate is `daemon.enable && proxy.enable && baseDomain != ""`,
/// and this installer settles the first two terms rather than asking about
/// them. `ferrum.daemon.enable` defaults to true in
/// `modules/core/options.nix` and nothing here ever writes it; `render.rs`
/// emits `proxy.enable = true` exactly when a base domain was answered. So
/// the only term left to evaluate is the base domain.
///
/// It is still spelled out as a predicate rather than folded into its one
/// caller, for two reasons. It is the join point where independently
/// written Rust and Nix describe the same runtime fact and can silently
/// drift, so it is worth being able to point at. And if a later question
/// ever turns the proxy or the daemon off, there is exactly one place that
/// has to learn about it.
///
/// Note what this is NOT keyed on: the app selection. That is the whole of
/// D2 -- the control plane is published because the proxy is, not because
/// any app was chosen.
///
/// # Arguments
/// * `base_domain` - `ferrum.proxy.baseDomain` as answered, if any.
///
/// # Returns
/// `true` when `ferrum.<base_domain>` will be a real, published vhost.
#[must_use]
pub fn daemon_published(base_domain: Option<&str>) -> bool {
    base_domain.is_some_and(|d| !d.is_empty())
}

/// The control plane's state-changing routes, listed literally in the
/// decline warning rather than summarised.
///
/// "The dashboard would have no login" reads like a lost convenience.
/// These three write secrets, rewrite this host's `settings.json`, and
/// apply system generations, so the warning names them and lets the
/// operator draw the conclusion. They are served by `crates/ferrumd`.
pub const DAEMON_OPEN_ROUTES: &[&str] = &[
    "PUT /api/settings",
    "POST /api/secrets/:name",
    "POST /api/jobs",
];

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
            unauthenticated_accepted_for: Vec::new(),
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
        // D2. This used to be answered from `open` alone, and that answer
        // stopped being true the moment R13 gave the control plane a vhost:
        // an operator selecting only the two apps that carry their own
        // login was told "nothing would be left open" about a host whose
        // ferrum.<domain> was going up on a real Let's Encrypt certificate
        // behind one password. The control plane is published because the
        // proxy is, so it is evaluated independently of the selection.
        let daemon_open = daemon_published(Some(domain));

        if open.is_empty() && !daemon_open {
            io.say(
                "\nNo app you selected relies on ferrum for authentication, so \
                 nothing would be left open. Continuing without single sign-on.",
            );
            return Ok(SsoDecision {
                enabled: false,
                unauthenticated_accepted_for: Vec::new(),
                admin_email: None,
            });
        }

        // One list and one confirmation covering all of it. Consent here is
        // scoped to exactly what the operator was shown (see
        // `unauthenticated_accepted_for`), so the control plane has to
        // appear both in what is printed and in what is recorded. A second
        // separate gate for the daemon would be a second unscoped grant,
        // which is the bypass the scoping exists to prevent.
        let mut shown: Vec<String> = open.iter().map(|a| (*a).to_string()).collect();

        if !open.is_empty() {
            io.say(&format!(
                "\nThese will be published on {domain} with NO login:\n  {}\n\n\
                 Anyone who finds the hostname can use them. qbittorrent and \
                 sabnzbd can write files anywhere the service can reach.",
                open.join("\n  ")
            ));
        }

        if daemon_open {
            shown.push(DAEMON_SUBDOMAIN.to_string());
            io.say(&format!(
                "\nferrum's own control plane will be published on {domain} with \
                 NO login:\n  {DAEMON_SUBDOMAIN}.{domain}\n\n\
                 It is not one of the apps above, and selecting fewer apps does \
                 not remove it -- it is published because the proxy is. Anyone \
                 who finds that hostname can call:\n  {}\n\n\
                 Those write secrets, rewrite this host's settings, and apply \
                 system generations. That is control of the machine, not access \
                 to a media library.",
                DAEMON_OPEN_ROUTES.join("\n  ")
            ));
        }

        let confirmed = confirm_exact(
            io,
            &format!("Type '{PUBLISH_UNAUTHENTICATED_PHRASE}' to continue anyway:"),
            PUBLISH_UNAUTHENTICATED_PHRASE,
        )?;
        if !confirmed {
            // Selecting fewer apps is only a real remedy when an app is
            // what is open; it does nothing about the control plane.
            let remedy = if open.is_empty() {
                "."
            } else {
                ", or select fewer apps."
            };
            anyhow::bail!(
                "not confirmed -- nothing has been changed. Re-run and answer \
                 yes to single sign-on{remedy}"
            );
        }
        return Ok(SsoDecision {
            enabled: false,
            unauthenticated_accepted_for: shown,
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
                    unauthenticated_accepted_for: Vec::new(),
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
                unauthenticated_accepted_for: Vec::new(),
                admin_email: Some("admin@thesyms.ca".into())
            },
            "an empty answer must take the safe path"
        );
    }

    #[test]
    fn an_explicit_yes_also_enables_it() {
        for yes in ["y", "Y", "yes", "YES"] {
            let mut io = Scripted::new(&[yes, "a@b.co"]);
            assert!(
                decide(Some("d.com"), &apps(&["sonarr"]), &mut io)
                    .unwrap()
                    .enabled
            );
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
        assert_eq!(
            d.unauthenticated_accepted_for,
            vec!["sonarr", "sabnzbd", "ferrum"],
            "consent must record WHICH apps were shown, not merely that it \
             was given -- an unscoped bit silently covers apps added later. \
             The control plane is on the end because D2 made it one of the \
             things shown."
        );
    }

    /// Consent is only recorded when it was actually given.
    ///
    /// The case that used to sit in the middle here -- declining with only
    /// plex selected, recording nothing -- moved to
    /// `declining_with_only_self_login_apps_still_gates_on_the_control_plane`
    /// when D2 established that that host does leave something open.
    #[test]
    fn consent_is_not_recorded_on_any_other_path() {
        let mut io = Scripted::new(&["", "a@b.co"]);
        assert!(decide(Some("d.com"), &apps(&["sonarr"]), &mut io)
            .unwrap()
            .unauthenticated_accepted_for
            .is_empty());

        let mut io = Scripted::new(&[]);
        assert!(decide(None, &apps(&["sonarr"]), &mut io)
            .unwrap()
            .unauthenticated_accepted_for
            .is_empty());
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
            assert!(
                err.to_string().contains("not confirmed"),
                "{reflex:?}: {err}"
            );
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

    /// R9 A5 still holds about the apps themselves: neither of these is
    /// left open by an absent Authelia, so neither appears in the warning.
    #[test]
    fn apps_with_their_own_login_are_never_listed_as_left_open() {
        assert!(apps_left_open(&apps(&["plex", "jellyfin"])).is_empty());
    }

    /// D2, and the exact host the planning panel's premortem named as the
    /// likeliest way R13 fails in the field.
    ///
    /// This is the one selection where every catalog app carries its own
    /// login, so the pre-R13 installer said "nothing would be left open"
    /// and asked nothing further -- while publishing ferrum.<domain>, which
    /// writes secrets and applies system generations, on a real Let's
    /// Encrypt certificate behind a single password.
    ///
    /// Mutation check: make the control plane invisible to the gate again
    /// -- replace the `daemon_published(Some(domain))` call in `decide`
    /// with `false` -- and this test fails, because the scripted answers
    /// run out at a gate that no longer happens.
    #[test]
    fn declining_with_only_self_login_apps_still_gates_on_the_control_plane() {
        let mut io = Scripted::new(&["n", PUBLISH_UNAUTHENTICATED_PHRASE]);
        let d = decide(Some("thesyms.ca"), &apps(&["plex", "jellyfin"]), &mut io).unwrap();

        assert!(!d.enabled);
        assert_eq!(io.asked.len(), 2, "the second gate must still be asked");

        let t = io.transcript();
        assert!(
            !t.contains("nothing would be left open"),
            "the sentence that is now false must not be printed:\n{t}"
        );
        assert!(
            t.contains("ferrum.thesyms.ca"),
            "the control plane must be named by hostname:\n{t}"
        );
        assert_eq!(
            d.unauthenticated_accepted_for,
            vec!["ferrum"],
            "consent is scoped to what was shown, and the control plane was \
             what was shown"
        );
    }

    /// The warning has to be specific enough to be alarming. "No login on
    /// the dashboard" reads like a lost convenience; these three routes
    /// read like what they are.
    #[test]
    fn the_control_plane_warning_names_its_state_changing_routes() {
        let mut io = Scripted::new(&["n", PUBLISH_UNAUTHENTICATED_PHRASE]);
        decide(Some("thesyms.ca"), &apps(&["plex"]), &mut io).unwrap();
        let t = io.transcript();
        for route in DAEMON_OPEN_ROUTES {
            assert!(t.contains(route), "{route} missing from the warning:\n{t}");
        }
    }

    /// Both kinds of exposure, one list, ONE confirmation. A second gate
    /// for the control plane would be a second unscoped grant.
    #[test]
    fn open_apps_and_the_control_plane_share_a_single_confirmation() {
        let mut io = Scripted::new(&["n", PUBLISH_UNAUTHENTICATED_PHRASE]);
        let d = decide(
            Some("thesyms.ca"),
            &apps(&["sonarr", "qbittorrent", "plex"]),
            &mut io,
        )
        .unwrap();

        assert_eq!(io.asked.len(), 2, "exactly one confirmation, not two");
        let t = io.transcript();
        for named in ["sonarr", "qbittorrent", "ferrum.thesyms.ca"] {
            assert!(t.contains(named), "{named} missing:\n{t}");
        }
        assert_eq!(
            d.unauthenticated_accepted_for,
            vec!["sonarr", "qbittorrent", "ferrum"],
            "everything shown is recorded, and nothing else is"
        );
    }

    /// The other side of D2's predicate, and the branch whose behaviour is
    /// deliberately unchanged: with no base domain the proxy is never
    /// enabled, so the control plane is not published and the question
    /// genuinely does not arise.
    #[test]
    fn the_control_plane_is_not_published_without_a_base_domain() {
        assert!(!daemon_published(None));
        assert!(!daemon_published(Some("")));
        assert!(daemon_published(Some("thesyms.ca")));
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
        for bad in [
            "a",
            "@b.com",
            "a@",
            "a@b",
            "a b@c.com",
            "a@@b.com",
            "a@.com",
            "a@b.",
        ] {
            assert!(validate_email(bad).is_err(), "accepted {bad:?}");
        }
        for good in [
            "a@b.co",
            "admin@thesyms.ca",
            "first.last+tag@sub.example.com",
        ] {
            validate_email(good).unwrap_or_else(|e| panic!("rejected {good:?}: {e}"));
        }
    }
}
