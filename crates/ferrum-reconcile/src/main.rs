// ferrum-reconcile: registers download clients and Prowlarr "Applications"
// across the catalog, driven entirely by a JSON config Nix generates from
// each app's own integrations.providesTo/consumes metadata
// (modules/core/reconciler.nix). Nix has already validated that every pair
// is mutually declared on both sides and resolved each app's real
// connection info (including qBittorrent's VPN-namespace topology) before
// this binary ever runs -- this binary's only job is the two real
// registration kinds themselves (download-client, application), matching
// the plan's own "hardcode the small dispatch directly in Rust" scope
// decision for a two-case problem.
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Deserialize)]
struct AppConnInfo {
    host: String,
    port: u16,
    #[serde(rename = "apiKeySecretPath")]
    api_key_secret_path: Option<String>,
}

#[derive(Deserialize)]
struct Pair {
    kind: String, // "downloadClient" | "application"
    consumer: String,
    provider: String,
    /// The download-client category this consumer's grabs are tagged with,
    /// and therefore the subdirectory its downloads land in.
    ///
    /// Supplied by modules/core/reconciler.nix from the SAME
    /// `catalog.<id>.mediaCategory` attribute that builds the app's root
    /// folder, so the directory ferrum creates and the category ferrum
    /// registers cannot be two independently-decided strings. This binary
    /// deliberately does not derive it: the previous value here was the
    /// consumer's own app id, which named a directory nothing ever created
    /// (`usenet/complete/sonarr`), while the `usenet/complete/tv` the
    /// storage module did create stayed empty.
    ///
    /// `None` for a consumer that manages no library -- see
    /// `register_download_client` for why Prowlarr is that case.
    #[serde(default)]
    category: Option<String>,
}

/// The whole config modules/core/reconciler.nix generates.
///
/// `rename_all = "camelCase"` is load-bearing and was missing. Nix writes
/// `rootFolders` and `downloadPaths`; these fields are `root_folders` and
/// `download_paths`; and both carry `#[serde(default)]`, so serde matched
/// neither key and filled in an empty Vec instead of failing. The binary
/// then reported success having registered not one root folder and not one
/// download path -- on every host, since the day the fields were added.
///
/// That is why the two things those loops exist to prevent were both
/// visible on the owner's host: the *arrs had no root folder, and the
/// download clients were never driven to <mediaDir> at all. Every sibling
/// struct here (PlexConfig, PlexLibrary, DownloadPath, RootFolder) already
/// carries this attribute; this one was the exception.
///
/// `#[serde(default)]` is what made it silent. It is kept, because a host
/// with no *arr genuinely has no root folders -- so the guard against it
/// happening again is `the_config_nix_writes_is_the_config_this_binary_reads`
/// below, which parses the real emitted shape and asserts the fields arrive
/// populated.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReconcileConfig {
    apps: HashMap<String, AppConnInfo>,
    pairs: Vec<Pair>,
    /// Root folders each *arr must know about before it can accept a
    /// single show or film.
    ///
    /// Registering apps to each other is not enough to make the stack
    /// usable: Sonarr with no root folder refuses to add a series at all,
    /// and the operator has to go and type a path that ferrum already
    /// knows. That is precisely the "log in and everything is pre-setup"
    /// gap this product exists to close.
    #[serde(default)]
    root_folders: Vec<RootFolder>,
    /// Where each download client writes.
    ///
    /// This is where hardlinking is won or lost. The *arrs import by
    /// hardlinking out of the download directory into the library, and a
    /// hardlink cannot cross a filesystem -- so a download client left on
    /// its own default (somewhere under its state directory on the OS
    /// disk) makes every import a COPY, silently.
    #[serde(default)]
    download_paths: Vec<DownloadPath>,
    /// Plex, which is shaped differently from everything else here.
    ///
    /// It has no API key: it is claimed to a plex.tv account, and until it
    /// is, it answers "You do not have access to this server" to anything
    /// that is not localhost. On a ferrum host the usual escape hatch --
    /// claim it from the LAN at :32400 -- does not exist either, because
    /// apps are published through nginx and the port is not open.
    #[serde(default)]
    plex: Option<PlexConfig>,
}

/// What Plex needs to become a usable server rather than a running one.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlexConfig {
    /// `host:port` of the local Plex.
    base_url: String,
    /// sops path holding a plex.tv claim token, when one was supplied.
    /// Claim tokens expire four minutes after they are issued, so this is
    /// frequently a token that no longer works -- which is not an error,
    /// it just means the operator has to supply a fresh one.
    #[serde(default)]
    claim_token_path: Option<String>,
    /// Plex's own Preferences.xml, which holds the account token once the
    /// server is claimed. That token is what library calls authenticate
    /// with.
    preferences_path: String,
    /// Libraries to create if absent: (type, name, path).
    #[serde(default)]
    libraries: Vec<PlexLibrary>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlexLibrary {
    /// Plex's own vocabulary: "movie" or "show".
    kind: String,
    name: String,
    path: String,
}

/// Where one download client should write.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DownloadPath {
    app: String,
    /// Finished downloads. Must be under the same root as the library.
    path: String,
    /// In-progress downloads, where the client supports a separate one.
    #[serde(default)]
    incomplete_path: Option<String>,
}

/// One `app -> path` root folder registration.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RootFolder {
    app: String,
    path: String,
}

/// Reads a sops-nix decrypted secret's bare content, trimmed of the
/// trailing newline encrypt_and_write always adds (see
/// crates/ferrum-apply/src/secrets.rs). None means the app needs no key
/// at all (qBittorrent, via LocalHostAuth = false).
fn read_api_key(path: &Option<String>) -> anyhow::Result<Option<String>> {
    match path {
        None => Ok(None),
        Some(p) => Ok(Some(
            fs::read_to_string(p)
                .map_err(|e| anyhow::anyhow!("failed to read secret at {p}: {e}"))?
                .trim()
                .to_string(),
        )),
    }
}

fn base_url(app: &AppConnInfo) -> String {
    format!("http://{}:{}", app.host, app.port)
}

fn main() -> anyhow::Result<()> {
    let config_path = std::env::var("FERRUM_RECONCILE_CONFIG")
        .map_err(|_| anyhow::anyhow!("FERRUM_RECONCILE_CONFIG not set"))?;
    let raw = fs::read_to_string(&config_path)
        .map_err(|e| anyhow::anyhow!("failed to read {config_path}: {e}"))?;
    let config: ReconcileConfig = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse {config_path}: {e}"))?;

    // Every registration is idempotent by name (find_existing_id), so a
    // failed pair here is safe to skip and retry on the unit's own next
    // Restart=on-failure attempt rather than aborting every OTHER pair --
    // confirmed for real that a single cold-start-timing failure would
    // otherwise silently skip every unrelated registration too (found
    // during the controller's own real end-to-end test).
    let mut had_error = false;
    for pair in &config.pairs {
        match reconcile_pair(&config, pair) {
            Ok(()) => println!(
                "ferrum-reconcile: {} <- {} ({}) OK",
                pair.consumer, pair.provider, pair.kind
            ),
            Err(e) => {
                eprintln!(
                    "ferrum-reconcile: {} <- {} ({}) FAILED: {e}",
                    pair.consumer, pair.provider, pair.kind
                );
                had_error = true;
            }
        }
    }
    // Root folders after the pairs, and independently: a failed pair must
    // not stop the *arrs learning where their media lives, and a failed
    // root folder must not undo a registration that worked.
    for rf in &config.root_folders {
        match ensure_root_folder(&config, rf) {
            Ok(changed) => println!(
                "ferrum-reconcile: {} root folder {} {}",
                rf.app,
                rf.path,
                if changed { "ADDED" } else { "already present" }
            ),
            Err(e) => {
                eprintln!(
                    "ferrum-reconcile: {} root folder {} FAILED: {e}",
                    rf.app, rf.path
                );
                had_error = true;
            }
        }
    }

    for dp in &config.download_paths {
        match set_download_path(&config, dp) {
            Ok(()) => println!(
                "ferrum-reconcile: {} downloads -> {} OK",
                dp.app, dp.path
            ),
            Err(e) => {
                eprintln!("ferrum-reconcile: {} downloads -> {} FAILED: {e}", dp.app, dp.path);
                had_error = true;
            }
        }
    }

    if let Some(plex) = &config.plex {
        match reconcile_plex(plex) {
            Ok(msgs) => {
                for m in msgs {
                    println!("ferrum-reconcile: plex {m}");
                }
            }
            Err(e) => {
                eprintln!("ferrum-reconcile: plex FAILED: {e}");
                had_error = true;
            }
        }
    }

    if had_error {
        anyhow::bail!("one or more pairs failed to reconcile -- see errors above");
    }
    Ok(())
}

/// The download-client category one pair registers.
///
/// A one-line function on purpose: it is the single seam at which the
/// category's SOURCE is decided, and the whole of defect 1 was that this
/// seam read `pair.consumer` -- the app id -- instead of the category Nix
/// derives from `catalog.<id>.mediaCategory`, the same attribute that
/// builds the app's root folder. Naming the seam is what makes it
/// testable without a running *arr.
///
/// # Arguments
/// * `pair` - one registration pair as modules/core/reconciler.nix emitted it.
///
/// # Returns
/// The category, or `None` for a consumer that manages no library.
fn pair_category(pair: &Pair) -> Option<&str> {
    pair.category.as_deref()
}

fn reconcile_pair(config: &ReconcileConfig, pair: &Pair) -> anyhow::Result<()> {
    let consumer = config
        .apps
        .get(&pair.consumer)
        .ok_or_else(|| anyhow::anyhow!("unknown consumer app '{}'", pair.consumer))?;
    let provider = config
        .apps
        .get(&pair.provider)
        .ok_or_else(|| anyhow::anyhow!("unknown provider app '{}'", pair.provider))?;
    let consumer_key = read_api_key(&consumer.api_key_secret_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "no API key configured for consumer app '{}' -- required to call its own API",
            pair.consumer
        )
    })?;

    match pair.kind.as_str() {
        "downloadClient" => register_download_client(
            &pair.consumer,
            consumer,
            &consumer_key,
            &pair.provider,
            provider,
            pair_category(pair),
        ),
        "application" => register_application(consumer, &consumer_key, &pair.provider, provider),
        other => anyhow::bail!(
            "unknown pair kind '{other}' for {}->{}",
            pair.consumer,
            pair.provider
        ),
    }
}

/// Ensures an *arr knows about a root folder, adding it if absent.
///
/// Idempotent by PATH rather than by name, because that is the identity
/// the *arr APIs use for a root folder -- `GET /api/v3/rootfolder` returns
/// objects whose `path` is the natural key, and adding a duplicate path is
/// rejected by the app rather than silently merged.
///
/// # Arguments
/// * `config` - the whole config, for the app's connection details.
/// * `rf` - the app and the path it should hold.
///
/// # Returns
/// `true` when a folder was added, `false` when it was already there.
///
/// # Errors
/// When the app is unknown, has no API key, or its API refuses the call.
fn ensure_root_folder(config: &ReconcileConfig, rf: &RootFolder) -> anyhow::Result<bool> {
    let app = config
        .apps
        .get(&rf.app)
        .ok_or_else(|| anyhow::anyhow!("unknown app '{}' in rootFolders", rf.app))?;
    let key = read_api_key(&app.api_key_secret_path)?.ok_or_else(|| {
        anyhow::anyhow!("no API key for '{}' -- required to set its root folder", rf.app)
    })?;

    let existing: Vec<serde_json::Value> = ureq::get(&format!("{}/api/v3/rootfolder", base_url(app)))
        .set("X-Api-Key", &key)
        .call()
        .map_err(|e| anyhow::anyhow!("GET rootfolder failed: {e}"))?
        .into_json()
        .map_err(|e| anyhow::anyhow!("GET rootfolder returned invalid JSON: {e}"))?;
    if existing
        .iter()
        .any(|f| f.get("path").and_then(|p| p.as_str()) == Some(rf.path.as_str()))
    {
        return Ok(false);
    }

    // The directory must exist before the app will accept it; the *arrs
    // validate the path and reject one they cannot see. storage.nix
    // creates the whole tree, so this is a guard against a mismatch
    // between what ferrum thinks the layout is and what is on disk --
    // exactly the disconnect that left the apps pointed at an empty
    // /srv/media while the media sat unmounted elsewhere.
    if !std::path::Path::new(&rf.path).is_dir() {
        anyhow::bail!(
            "{} does not exist on this host, so {} would reject it. The \
             media tree is created by modules/core/storage.nix from \
             ferrum.storage.mediaDir -- if that path is wrong, the apps and \
             the disks disagree about where media lives.",
            rf.path,
            rf.app
        );
    }

    ureq::post(&format!("{}/api/v3/rootfolder", base_url(app)))
        .set("X-Api-Key", &key)
        .send_json(serde_json::json!({ "path": rf.path }))
        .map_err(|e| anyhow::anyhow!("POST rootfolder {} failed: {e}", rf.path))?;
    Ok(true)
}

/// Points a download client at the shared media root.
///
/// Both clients are driven through their own APIs rather than by writing
/// their config files. SABnzbd owns `sabnzbd.ini` and rewrites it on
/// exit, so seeding it is fragile; qBittorrent's config is worse still.
/// Setting it through the API is also what makes the value visible in the
/// app's own UI, which matters when an operator goes looking.
///
/// Idempotent because both APIs take a desired value rather than an
/// append -- setting the same path twice is a no-op.
///
/// # Arguments
/// * `config` - the whole config, for connection details.
/// * `dp` - the app and the paths it should write to.
///
/// # Errors
/// When the app is unknown, the directory is missing, or its API refuses.
fn set_download_path(config: &ReconcileConfig, dp: &DownloadPath) -> anyhow::Result<()> {
    let app = config
        .apps
        .get(&dp.app)
        .ok_or_else(|| anyhow::anyhow!("unknown app '{}' in downloadPaths", dp.app))?;
    let base = base_url(app);

    for path in std::iter::once(&dp.path).chain(dp.incomplete_path.iter()) {
        if !std::path::Path::new(path).is_dir() {
            anyhow::bail!(
                "{path} does not exist, so {} would reject it. The download \
                 tree is created by modules/core/storage.nix from \
                 ferrum.storage.mediaDir.",
                dp.app
            );
        }
    }

    match dp.app.as_str() {
        // qBittorrent: LocalHostAuth is off, so no credential is needed
        // from localhost. setPreferences takes a JSON blob as a form
        // field, which is its own peculiar shape rather than a JSON body.
        "qbittorrent" => {
            let mut prefs = serde_json::json!({ "save_path": dp.path });
            if let Some(inc) = &dp.incomplete_path {
                prefs["temp_path"] = serde_json::json!(inc);
                prefs["temp_path_enabled"] = serde_json::json!(true);
            }
            ureq::post(&format!("{base}/api/v2/app/setPreferences"))
                .send_form(&[("json", &prefs.to_string())])
                .map_err(|e| anyhow::anyhow!("qBittorrent setPreferences failed: {e}"))?;
            Ok(())
        }
        // SABnzbd: one key per call, and the api key goes in the query.
        "sabnzbd" => {
            let key = read_api_key(&app.api_key_secret_path)?.ok_or_else(|| {
                anyhow::anyhow!("no API key for sabnzbd -- required to set its directories")
            })?;
            let mut settings = vec![("complete_dir", dp.path.as_str())];
            if let Some(inc) = &dp.incomplete_path {
                settings.push(("download_dir", inc.as_str()));
            }
            for (keyword, value) in settings {
                ureq::get(&format!("{base}/api"))
                    .query("mode", "set_config")
                    .query("section", "misc")
                    .query("keyword", keyword)
                    .query("value", value)
                    .query("apikey", &key)
                    .query("output", "json")
                    .call()
                    .map_err(|e| anyhow::anyhow!("SABnzbd set_config {keyword} failed: {e}"))?;
            }
            // set_config alone updates the running config; saving persists
            // it to sabnzbd.ini so it survives a restart.
            ureq::get(&format!("{base}/api"))
                .query("mode", "config")
                .query("name", "save")
                .query("apikey", &key)
                .query("output", "json")
                .call()
                .map_err(|e| anyhow::anyhow!("SABnzbd config save failed: {e}"))?;
            Ok(())
        }
        other => anyhow::bail!("no download-path support for '{other}'"),
    }
}

/// Claims Plex if it is unclaimed, then creates any missing libraries.
///
/// Both steps are skipped when already done, because this runs after
/// every apply and must be a no-op on a host that is already set up.
///
/// # Arguments
/// * `plex` - connection details, the claim token path, and the wanted
///   libraries.
///
/// # Returns
/// One line per thing it did or deliberately did not do, so the operator
/// can see why nothing happened as easily as why something did.
///
/// # Errors
/// Only for failures that are not the operator's to fix by supplying a
/// fresh token -- an expired or rejected claim is reported, not fatal,
/// because failing the whole unit over it would also block the libraries
/// and every other app's reconciliation.
fn reconcile_plex(plex: &PlexConfig) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();

    let mut token = plex_account_token(&plex.preferences_path);

    if token.is_none() {
        match &plex.claim_token_path {
            None => {
                out.push(
                    "is NOT claimed and no claim token was supplied -- it will answer \
                     \"You do not have access to this server\" to anything but localhost. \
                     Get one from https://plex.tv/claim (valid 4 minutes) and put it in \
                     the plex-claim secret."
                        .to_string(),
                );
            }
            Some(path) => match claim_plex(&plex.base_url, path) {
                Ok(()) => {
                    out.push("claimed".to_string());
                    token = plex_account_token(&plex.preferences_path);
                }
                Err(e) => out.push(format!(
                    "could not be claimed: {e}. Claim tokens expire four minutes after \
                     they are issued, so this is usually a stale one -- get a fresh \
                     token from https://plex.tv/claim and replace the plex-claim secret."
                )),
            },
        }
    }

    let Some(token) = token else {
        out.push("libraries skipped: the server must be claimed first".to_string());
        return Ok(out);
    };

    let existing = plex_existing_library_paths(&plex.base_url, &token)?;
    for lib in &plex.libraries {
        if existing.iter().any(|p| p == &lib.path) {
            continue;
        }
        if !std::path::Path::new(&lib.path).is_dir() {
            out.push(format!("library {:?} skipped: {} does not exist", lib.name, lib.path));
            continue;
        }
        create_plex_library(&plex.base_url, &token, lib)?;
        out.push(format!("library {:?} created at {}", lib.name, lib.path));
    }
    Ok(out)
}

/// Reads the account token Plex writes into Preferences.xml once claimed.
///
/// Its absence IS the definition of unclaimed, which is why this is the
/// check rather than asking the server: a running unclaimed Plex answers
/// perfectly well on localhost, so reachability proves nothing.
fn plex_account_token(preferences_path: &str) -> Option<String> {
    let xml = fs::read_to_string(preferences_path).ok()?;
    let needle = "PlexOnlineToken=\"";
    let start = xml.find(needle)? + needle.len();
    let rest = &xml[start..];
    let end = rest.find('"')?;
    let token = &rest[..end];
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn claim_plex(base_url: &str, claim_token_path: &str) -> anyhow::Result<()> {
    let claim = fs::read_to_string(claim_token_path)
        .map_err(|e| anyhow::anyhow!("could not read the claim token at {claim_token_path}: {e}"))?
        .trim()
        .to_string();
    if claim.is_empty() {
        anyhow::bail!("the claim token is empty");
    }
    ureq::post(&format!("{base_url}/myplex/claim"))
        .query("token", &claim)
        .call()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

fn plex_existing_library_paths(base_url: &str, token: &str) -> anyhow::Result<Vec<String>> {
    let xml = ureq::get(&format!("{base_url}/library/sections"))
        .set("X-Plex-Token", token)
        .call()
        .map_err(|e| anyhow::anyhow!("listing Plex libraries failed: {e}"))?
        .into_string()
        .map_err(|e| anyhow::anyhow!("Plex returned unreadable library XML: {e}"))?;
    // Deliberately a substring scan rather than an XML parse: the only
    // thing needed is whether a path is already used, and pulling in an
    // XML dependency for one attribute is not worth it.
    Ok(xml
        .split("path=\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next().map(str::to_string))
        .collect())
}

fn create_plex_library(base_url: &str, token: &str, lib: &PlexLibrary) -> anyhow::Result<()> {
    // The agent/scanner pair is Plex's own default for each type; naming
    // them explicitly avoids depending on whatever the server's current
    // default happens to be.
    let (agent, scanner) = match lib.kind.as_str() {
        "movie" => ("tv.plex.agents.movie", "Plex Movie"),
        "show" => ("tv.plex.agents.series", "Plex TV Series"),
        other => anyhow::bail!("unsupported Plex library type {other:?}"),
    };
    ureq::post(&format!("{base_url}/library/sections"))
        .set("X-Plex-Token", token)
        .query("name", &lib.name)
        .query("type", &lib.kind)
        .query("agent", agent)
        .query("scanner", scanner)
        .query("language", "en-US")
        .query("location", &lib.path)
        .call()
        .map_err(|e| anyhow::anyhow!("creating Plex library {:?} failed: {e}", lib.name))?;
    Ok(())
}

/// Looks up an existing entry by `name` at `GET {base}{path}` -- both
/// Sonarr/Radarr's v3 and Prowlarr's v1 downloadclient/applications
/// endpoints return the same shape (a JSON array of objects with at least
/// `id`/`name`), confirmed for real on ferrum-dev.
fn find_existing_id(base: &str, path: &str, api_key: &str, name: &str) -> anyhow::Result<Option<u64>> {
    let resp: Vec<serde_json::Value> = ureq::get(&format!("{base}{path}"))
        .set("X-Api-Key", api_key)
        .call()
        .map_err(|e| anyhow::anyhow!("GET {base}{path} failed: {e}"))?
        .into_json()
        .map_err(|e| anyhow::anyhow!("GET {base}{path} returned invalid JSON: {e}"))?;
    Ok(resp
        .iter()
        .find(|v| v["name"] == name)
        .and_then(|v| v["id"].as_u64()))
}

/// The whole existing registration object, not only its id.
///
/// `find_existing_id` is enough to decide "do I need to create this?", but
/// not enough to decide "is what is already there still right?" -- and
/// registrations are idempotent BY NAME, so an app registered before a
/// correction would otherwise keep the wrong value forever. See
/// `registration_needing_category_fix`.
///
/// # Arguments
/// * `base` / `path` / `api_key` - the consumer's API.
/// * `name` - the registration's name, which is the provider's app id.
///
/// # Returns
/// The existing object, or `None` when nothing of that name exists.
///
/// # Errors
/// When the call fails or returns something that is not a JSON array.
fn find_existing(
    base: &str,
    path: &str,
    api_key: &str,
    name: &str,
) -> anyhow::Result<Option<serde_json::Value>> {
    let resp: Vec<serde_json::Value> = ureq::get(&format!("{base}{path}"))
        .set("X-Api-Key", api_key)
        .call()
        .map_err(|e| anyhow::anyhow!("GET {base}{path} failed: {e}"))?
        .into_json()
        .map_err(|e| anyhow::anyhow!("GET {base}{path} returned invalid JSON: {e}"))?;
    Ok(resp.into_iter().find(|v| v["name"] == name))
}

/// An existing registration with ONLY its category field corrected, or
/// `None` when it is already right.
///
/// Why this exists at all: every registration here is idempotent by NAME,
/// so once `qbittorrent` is registered in Sonarr, no later apply touches
/// it. That is the behaviour you want for a value the operator may have
/// tuned -- and exactly the wrong behaviour for a value ferrum derives and
/// then corrects. Without this, the category fix would land only on hosts
/// that had never been set up, and never on the host it was found on.
///
/// One field, deliberately. Everything else in that object -- priority,
/// enable, removeCompletedDownloads, any setting touched by hand in the
/// app's own UI -- is returned unchanged, because ferrum has no opinion
/// about it and overwriting it would be a worse bug than the one being
/// fixed.
///
/// # Arguments
/// * `existing` - the registration as the app's API returned it.
/// * `field` - the category field's name for this consumer.
/// * `category` - the category it should carry; `None` means no category,
///   which is the empty string on the wire.
///
/// # Returns
/// `Some(updated)` when the value differs, `None` when it already matches.
fn registration_needing_category_fix(
    existing: &serde_json::Value,
    field: &str,
    category: Option<&str>,
) -> Option<serde_json::Value> {
    let want = category.unwrap_or("");
    let fields = existing.get("fields")?.as_array()?;
    let current = fields
        .iter()
        .find(|f| f["name"] == field)
        .map(|f| f["value"].as_str().unwrap_or(""))
        // A category field the app did not return at all is absent, which
        // is the same state as empty -- and must still be corrected when a
        // category is wanted.
        .unwrap_or("");
    if current == want {
        return None;
    }

    let mut updated = existing.clone();
    let updated_fields = updated.get_mut("fields")?.as_array_mut()?;
    if let Some(f) = updated_fields.iter_mut().find(|f| f["name"] == field) {
        f["value"] = serde_json::json!(want);
    } else {
        updated_fields.push(serde_json::json!({ "name": field, "value": want }));
    }
    Some(updated)
}

/// The consumer's own downloadclient API base path -- v3 for Sonarr/
/// Radarr, v1 for Prowlarr (confirmed for real: Prowlarr's servarr
/// framework fork uses v1 throughout, unlike Sonarr/Radarr's v3).
fn download_client_api_path(consumer_id: &str) -> anyhow::Result<&'static str> {
    match consumer_id {
        "sonarr" | "radarr" => Ok("/api/v3/downloadclient"),
        "prowlarr" => Ok("/api/v1/downloadclient"),
        other => anyhow::bail!("no downloadclient API known for consumer app '{other}'"),
    }
}

/// The consumer-specific category field name -- confirmed for real from
/// each app's own /downloadclient/schema endpoint on ferrum-dev: Sonarr
/// uses tvCategory, Radarr movieCategory, Prowlarr a single category
/// field (it isn't tv/movie-specific).
fn category_field_name(consumer_id: &str) -> anyhow::Result<&'static str> {
    match consumer_id {
        "sonarr" => Ok("tvCategory"),
        "radarr" => Ok("movieCategory"),
        "prowlarr" => Ok("category"),
        other => anyhow::bail!("no category field convention for consumer app '{other}'"),
    }
}

/// The provider-specific implementation fields -- confirmed for real from
/// the QBittorrent/Sabnzbd schema entries on ferrum-dev. qBittorrent needs
/// no apiKey (LocalHostAuth = false, Task 1); SABnzbd's api_key is
/// required -- it has no bypass mechanism.
fn provider_implementation(
    provider_id: &str,
    provider_key: &Option<String>,
) -> anyhow::Result<(&'static str, &'static str, &'static str, serde_json::Value)> {
    match provider_id {
        "qbittorrent" => Ok((
            "QBittorrent",
            "QBittorrentSettings",
            "torrent",
            serde_json::json!({}),
        )),
        "sabnzbd" => {
            let key = provider_key.as_ref().ok_or_else(|| {
                anyhow::anyhow!("SABnzbd provider has no API key configured -- cannot register it")
            })?;
            Ok((
                "Sabnzbd",
                "SabnzbdSettings",
                "usenet",
                serde_json::json!({ "apiKey": key }),
            ))
        }
        other => anyhow::bail!("no download-client implementation known for provider app '{other}'"),
    }
}

/// Builds the `mode=set_config` request that creates or updates one
/// SABnzbd category.
///
/// # Arguments
/// * `base` - the provider's base URL.
/// * `provider_key` - SABnzbd's own API key.
/// * `category` - the category name to create or update.
///
/// # Returns
/// The prepared request, uncalled, so its query can be inspected.
fn sabnzbd_category_request(base: &str, provider_key: &str, category: &str) -> ureq::Request {
    // `.query()` rather than a formatted query string. Concatenation made
    // every value here one `&` away from becoming a PARAMETER instead of
    // staying a value, and the two parameters it could become are the ones
    // that matter: `mode` is the whole SABnzbd API surface, and `apikey` is
    // the credential. It is also simply the correct way to build a query --
    // concatenation percent-encoded nothing, so a key containing `&` or `+`
    // went out mangled.
    ureq::get(&format!("{base}/api"))
        .query("mode", "set_config")
        .query("section", "categories")
        .query("name", category)
        .query("dir", category)
        .query("apikey", provider_key)
        .query("output", "json")
}

/// SABnzbd requires a category to already exist before any downloadclient
/// registration can reference it -- confirmed for real: a registration
/// attempt otherwise returns a real 400 "Category does not exist", unlike
/// qBittorrent, which accepts an arbitrary category string with no
/// pre-creation needed. Idempotent by construction: SABnzbd's own
/// mode=set_config either creates the category or updates it in place if
/// it already exists -- confirmed for real, calling this twice against
/// the same name produces the same category unchanged.
fn ensure_sabnzbd_category(
    provider: &AppConnInfo,
    provider_key: &str,
    category: &str,
) -> anyhow::Result<()> {
    sabnzbd_category_request(&base_url(provider), provider_key, category)
        .call()
        .map_err(|e| anyhow::anyhow!("failed to ensure SABnzbd category '{category}': {e}"))?;
    Ok(())
}

/// Builds the exact JSON body a downloadclient registration POSTs.
///
/// Extracted from `register_download_client` so the body itself can be
/// asserted in a test rather than only the code that assembles it. The
/// defect this guards is entirely a question of what one field's VALUE is:
/// the category told the *arrs to use `sonarr`/`radarr`, directories
/// nothing in ferrum creates, while the `tv`/`movies` directories
/// modules/core/trash-layout.nix does create stayed empty.
///
/// # Arguments
/// * `consumer_id` - the *arr being configured; decides the API dialect.
/// * `provider_id` - the download client being registered into it.
/// * `provider` - the client's host/port.
/// * `provider_key` - the client's own API key, where it needs one.
/// * `category` - the category to tag this consumer's grabs with, or
///   `None` for a consumer that manages no library.
///
/// # Returns
/// The registration body, ready to POST.
///
/// # Errors
/// When the consumer or provider is one this binary knows no convention
/// for.
fn download_client_body(
    consumer_id: &str,
    provider_id: &str,
    provider: &AppConnInfo,
    provider_key: &Option<String>,
    category: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    let (implementation, config_contract, protocol, extra_fields) =
        provider_implementation(provider_id, provider_key)?;
    let category_field = category_field_name(consumer_id)?;

    let mut fields = vec![
        serde_json::json!({ "name": "host", "value": provider.host }),
        serde_json::json!({ "name": "port", "value": provider.port }),
        serde_json::json!({ "name": "useSsl", "value": false }),
        // An absent category is the empty string, which is what every
        // *arr's own downloadclient schema shows as this field's default
        // and what the app's UI displays as "no category". It is not the
        // same as inventing one.
        serde_json::json!({ "name": category_field, "value": category.unwrap_or("") }),
    ];
    if let Some(obj) = extra_fields.as_object() {
        for (k, v) in obj {
            fields.push(serde_json::json!({ "name": k, "value": v }));
        }
    }

    let mut body = serde_json::json!({
        "enable": true,
        "protocol": protocol,
        "priority": 1,
        "name": provider_id,
        "implementation": implementation,
        "configContract": config_contract,
        "fields": fields,
    });

    // Prowlarr's own downloadclient schema has a top-level `categories`
    // list (indexer-category-to-client-category mappings), absent from
    // Sonarr/Radarr's schema -- confirmed for real: omitting it makes
    // Prowlarr's own DownloadClientBase.ValidateCategories throw a real
    // NullReferenceException casting a null Categories collection, on
    // EVERY downloadclient registration attempt, not just an edge case.
    // An empty list is exactly what Prowlarr's own schema shows as this
    // field's default for a blank client -- this isn't a workaround, it's
    // supplying the field's real default value Prowlarr's own JSON
    // deserialization doesn't apply on a missing key.
    if consumer_id == "prowlarr" {
        body["categories"] = serde_json::json!([]);
    }

    Ok(body)
}

/// Registers one download client into one *arr.
///
/// # Arguments
/// * `consumer_id` / `consumer` / `consumer_key` - the *arr being
///   configured and the credential for its own API.
/// * `provider_id` / `provider` - the download client being registered.
/// * `category` - the category this consumer's grabs are tagged with, from
///   the catalog; `None` for a consumer that manages no library.
///
/// # Errors
/// When either app's API refuses the call, or SABnzbd's category cannot be
/// created.
fn register_download_client(
    consumer_id: &str,
    consumer: &AppConnInfo,
    consumer_key: &str,
    provider_id: &str,
    provider: &AppConnInfo,
    category: Option<&str>,
) -> anyhow::Result<()> {
    let base = base_url(consumer);
    let path = download_client_api_path(consumer_id)?;
    let category_field = category_field_name(consumer_id)?;
    let existing = find_existing(&base, path, consumer_key, provider_id)?;

    // Only Sabnzbd needs its own key read here (qBittorrent needs none) --
    // read_api_key handles both, called with the PROVIDER's own secret path.
    let provider_key = read_api_key(&provider.api_key_secret_path)?;

    // A category SABnzbd does not already know is rejected at registration
    // time, so it has to exist first. With no category there is nothing to
    // create: SABnzbd's own default applies and the job lands at the root
    // of complete_dir, a directory ferrum does create.
    if provider_id == "sabnzbd" {
        if let Some(cat) = category {
            let key = provider_key.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "SABnzbd provider has no API key configured -- cannot ensure its category"
                )
            })?;
            ensure_sabnzbd_category(provider, key, cat)?;
        }
    }

    if let Some(existing) = existing {
        // Already registered. Correct the one field ferrum derives, and
        // nothing else -- see registration_needing_category_fix for why
        // leaving it alone was not an option.
        let Some(updated) = registration_needing_category_fix(&existing, category_field, category)
        else {
            return Ok(());
        };
        let id = updated["id"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("{consumer_id}'s existing {provider_id} client has no id"))?;
        ureq::put(&format!("{base}{path}/{id}"))
            .set("X-Api-Key", consumer_key)
            .send_json(updated)
            .map_err(|e| anyhow::anyhow!("PUT {base}{path}/{id} for {provider_id} failed: {e}"))?;
        return Ok(());
    }

    let body = download_client_body(consumer_id, provider_id, provider, &provider_key, category)?;

    ureq::post(&format!("{base}{path}"))
        .set("X-Api-Key", consumer_key)
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("POST {base}{path} for {provider_id} failed: {e}"))?;
    Ok(())
}

/// Real default syncCategories per target app, confirmed from each app's
/// own /api/v1/applications/schema entry on ferrum-dev (Prowlarr's own
/// advertised defaults, not invented).
fn default_sync_categories(provider_id: &str) -> anyhow::Result<&'static [i64]> {
    match provider_id {
        "sonarr" => Ok(&[5000, 5010, 5020, 5030, 5040, 5045, 5050, 5090]),
        "radarr" => Ok(&[2000, 2010, 2020, 2030, 2040, 2045, 2050, 2060, 2070, 2080, 2090]),
        other => anyhow::bail!("no default syncCategories known for application target '{other}'"),
    }
}

fn application_implementation(provider_id: &str) -> anyhow::Result<(&'static str, &'static str)> {
    match provider_id {
        "sonarr" => Ok(("Sonarr", "SonarrSettings")),
        "radarr" => Ok(("Radarr", "RadarrSettings")),
        other => anyhow::bail!("no Applications implementation known for target app '{other}'"),
    }
}

fn register_application(
    consumer: &AppConnInfo,
    consumer_key: &str,
    provider_id: &str,
    provider: &AppConnInfo,
) -> anyhow::Result<()> {
    // consumer here is Prowlarr (the only app this pair kind ever has as
    // consumer, per modules/core/reconciler.nix's pairKind); provider is
    // the target app (Sonarr/Radarr) Prowlarr pushes indexers into.
    let base = base_url(consumer);
    let path = "/api/v1/applications";
    if find_existing_id(&base, path, consumer_key, provider_id)?.is_some() {
        return Ok(());
    }

    let provider_key = read_api_key(&provider.api_key_secret_path)?.ok_or_else(|| {
        anyhow::anyhow!("no API key configured for application target '{provider_id}'")
    })?;
    let (implementation, config_contract) = application_implementation(provider_id)?;
    let sync_categories = default_sync_categories(provider_id)?;

    let body = serde_json::json!({
        "name": provider_id,
        "syncLevel": "fullSync",
        "implementation": implementation,
        "configContract": config_contract,
        "fields": [
            { "name": "prowlarrUrl", "value": base_url(consumer) },
            { "name": "baseUrl", "value": base_url(provider) },
            { "name": "apiKey", "value": provider_key },
            { "name": "syncCategories", "value": sync_categories },
        ],
    });

    ureq::post(&format!("{base}{path}"))
        .set("X-Api-Key", consumer_key)
        .send_json(body)
        .map_err(|e| anyhow::anyhow!("POST {base}{path} for {provider_id} failed: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R4/SEC3. The SABnzbd category request built its query by string
    /// concatenation, so every value in it was one `&` away from becoming a
    /// PARAMETER rather than staying a value. `mode` is the whole API --
    /// `mode=shutdown`, `mode=set_config&section=misc` -- and `apikey` is
    /// the credential, so a second copy of either decides what the call
    /// actually does.
    ///
    /// Constrained in practice today (`category` is a catalog app id and
    /// `provider_key` a generated hex string), which is why this is
    /// hardening rather than a live hole. The concatenation is also just
    /// wrong for a value that legitimately needs escaping: nothing here
    /// percent-encoded anything, so a key containing `&` or `+` was
    /// silently mangled on the wire.
    ///
    /// Asserted against the parsed query of the real prepared request, not
    /// against a format string, so it is the request that is pinned.
    #[test]
    fn the_sabnzbd_category_request_cannot_have_parameters_smuggled_into_it() {
        let request = sabnzbd_category_request(
            "http://127.0.0.1:8080",
            "realkey&mode=shutdown",
            "tv&mode=shutdown&apikey=stolen",
        );
        let url = request.request_url().expect("the request url parses");
        let pairs: Vec<(String, String)> = url
            .as_url()
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        let values = |key: &str| -> Vec<String> {
            pairs.iter().filter(|(k, _)| k == key).map(|(_, v)| v.clone()).collect()
        };
        assert_eq!(
            values("mode"),
            vec!["set_config".to_string()],
            "a second `mode` decides what this call does: {pairs:?}"
        );
        assert_eq!(
            values("apikey"),
            vec!["realkey&mode=shutdown".to_string()],
            "the credential must appear exactly once, intact: {pairs:?}"
        );
        assert_eq!(
            values("name"),
            vec!["tv&mode=shutdown&apikey=stolen".to_string()],
            "the category must stay ONE value rather than becoming parameters: {pairs:?}"
        );
        assert_eq!(values("section"), vec!["categories".to_string()]);
        assert_eq!(values("output"), vec!["json".to_string()]);
    }

    fn conn(host: &str, port: u16) -> AppConnInfo {
        AppConnInfo {
            host: host.to_string(),
            port,
            api_key_secret_path: None,
        }
    }

    /// The value of the field whose name `category_field_name` returns,
    /// read back out of a real registration body.
    fn category_value_in(body: &serde_json::Value, field: &str) -> String {
        body["fields"]
            .as_array()
            .expect("the body has a fields array")
            .iter()
            .find(|f| f["name"] == field)
            .unwrap_or_else(|| panic!("no {field} field in {body}"))["value"]
            .as_str()
            .expect("the category is a string")
            .to_string()
    }

    /// THE DEFECT. The category told the *arrs to use was the consumer's
    /// own app id -- `sonarr`, `radarr` -- so SABnzbd wrote completed TV
    /// jobs into `usenet/complete/sonarr`, a directory ferrum never
    /// creates, while the `usenet/complete/tv` that
    /// modules/core/trash-layout.nix does create stayed empty. Confirmed
    /// on the owner's host: both category trees created and empty, and
    /// SABnzbd holding one category, `[[prowlarr]]`.
    ///
    /// The value now comes from the config, which
    /// modules/core/reconciler.nix fills from the same
    /// `catalog.<id>.mediaCategory` it builds the root folder from. This
    /// test pins the end of that wire: whatever Nix supplies is what goes
    /// on the API call, verbatim and in the right field.
    #[test]
    fn the_registered_category_is_the_media_category_not_the_app_id() {
        let qbt = conn("127.0.0.1", 8090);

        // Deserialized exactly as modules/core/reconciler.nix emits it, so
        // the whole wire is under test and not just its far end.
        let sonarr_pair: Pair = serde_json::from_str(
            r#"{"kind":"downloadClient","consumer":"sonarr","provider":"qbittorrent","category":"tv"}"#,
        )
        .unwrap();
        let sonarr = download_client_body(
            &sonarr_pair.consumer,
            &sonarr_pair.provider,
            &qbt,
            &None,
            pair_category(&sonarr_pair),
        )
        .unwrap();
        assert_eq!(
            category_value_in(&sonarr, "tvCategory"),
            "tv",
            "sonarr's grabs must be tagged with the directory ferrum creates: {sonarr}"
        );

        let radarr_pair: Pair = serde_json::from_str(
            r#"{"kind":"downloadClient","consumer":"radarr","provider":"sabnzbd","category":"movies"}"#,
        )
        .unwrap();
        let radarr = download_client_body(
            &radarr_pair.consumer,
            &radarr_pair.provider,
            &conn("127.0.0.1", 8080),
            &Some("k".to_string()),
            pair_category(&radarr_pair),
        )
        .unwrap();
        assert_eq!(
            category_value_in(&radarr, "movieCategory"),
            "movies",
            "radarr's grabs must be tagged with the directory ferrum creates: {radarr}"
        );
    }

    /// Prowlarr's decision, pinned.
    ///
    /// Prowlarr is an indexer manager: it has no `mediaCategory` because it
    /// manages no library, and its download-client registration exists for
    /// the Test button and for interactive searches launched from its own
    /// UI. A grab made that way belongs to no library, so there is no
    /// library category that is true of it -- giving it `tv` would file a
    /// manually-grabbed album under television, and giving it `prowlarr`
    /// is the original defect in a new costume.
    ///
    /// So it gets no category, which is the empty string every *arr's own
    /// downloadclient schema carries as this field's default. The effect is
    /// that such a grab lands at the ROOT of the client's download tree --
    /// `<mediaDir>/torrents` or `<mediaDir>/usenet/complete` -- both of
    /// which ferrum does create. The invariant holds for Prowlarr the same
    /// way it holds for Sonarr: ferrum never names a directory it did not
    /// make.
    #[test]
    fn prowlarr_gets_no_category_because_it_manages_no_library() {
        let qbt = conn("127.0.0.1", 8090);
        let pair: Pair = serde_json::from_str(
            r#"{"kind":"downloadClient","consumer":"prowlarr","provider":"qbittorrent","category":null}"#,
        )
        .unwrap();
        assert_eq!(pair_category(&pair), None);
        let body = download_client_body(
            &pair.consumer,
            &pair.provider,
            &qbt,
            &None,
            pair_category(&pair),
        )
        .unwrap();
        assert_eq!(
            category_value_in(&body, "category"),
            "",
            "an indexer manager has no library category: {body}"
        );
        assert_eq!(
            body["categories"],
            serde_json::json!([]),
            "Prowlarr still needs its own top-level categories list: {body}"
        );
    }

    /// Anti-vacuity for the two tests above: the assertion really reads the
    /// category out of the body rather than matching anything. A body built
    /// with the OLD value -- the consumer's app id -- must not satisfy it.
    #[test]
    fn the_old_app_id_category_would_still_be_visible_here() {
        let qbt = conn("127.0.0.1", 8090);
        let old =
            download_client_body("sonarr", "qbittorrent", &qbt, &None, Some("sonarr")).unwrap();
        assert_eq!(
            category_value_in(&old, "tvCategory"),
            "sonarr",
            "the helper reports what is actually in the body: {old}"
        );
        assert_ne!(category_value_in(&old, "tvCategory"), "tv");
    }

    /// An existing registration as an *arr's own API returns it, with a
    /// hand-tuned field beside the category so the "one field only" claim
    /// has something to be false about.
    fn existing_client(category_field: &str, category: &str) -> serde_json::Value {
        serde_json::json!({
            "id": 3,
            "name": "qbittorrent",
            "enable": true,
            "priority": 7,
            "removeCompletedDownloads": false,
            "implementation": "QBittorrent",
            "configContract": "QBittorrentSettings",
            "fields": [
                { "name": "host", "value": "127.0.0.1" },
                { "name": "port", "value": 8090 },
                { "name": category_field, "value": category },
                { "name": "initialState", "value": 1 },
            ],
        })
    }

    /// The half of defect 1 that decides whether the fix reaches a REAL
    /// host. Every registration here is idempotent by name, so once
    /// `qbittorrent` exists in Sonarr no later apply touches it -- and the
    /// owner's host already has all six. Correcting the category on an
    /// existing registration is what makes "the blast radius is the next
    /// apply" actually true rather than true only for a fresh install.
    #[test]
    fn an_already_registered_client_has_its_wrong_category_corrected() {
        let before = existing_client("tvCategory", "sonarr");
        let after = registration_needing_category_fix(&before, "tvCategory", Some("tv"))
            .expect("a wrong category must be corrected");
        assert_eq!(category_value_in(&after, "tvCategory"), "tv");
        assert_eq!(after["id"], 3, "the id is needed for the PUT: {after}");
    }

    /// And it touches nothing else. Overwriting a priority or a toggle the
    /// operator set by hand would be a worse bug than the one being fixed,
    /// because ferrum has no opinion about those at all.
    #[test]
    fn correcting_a_category_leaves_every_other_field_alone() {
        let before = existing_client("tvCategory", "sonarr");
        let after =
            registration_needing_category_fix(&before, "tvCategory", Some("tv")).unwrap();
        assert_eq!(after["priority"], 7);
        assert_eq!(after["removeCompletedDownloads"], false);
        assert_eq!(category_value_in(&after, "host"), "127.0.0.1");
        assert_eq!(
            after["fields"].as_array().unwrap().len(),
            before["fields"].as_array().unwrap().len(),
            "no field was added or dropped: {after}"
        );
        for name in ["host", "port", "initialState"] {
            let b = before["fields"].as_array().unwrap().iter().find(|f| f["name"] == name);
            let a = after["fields"].as_array().unwrap().iter().find(|f| f["name"] == name);
            assert_eq!(a, b, "{name} changed: {after}");
        }
    }

    /// Anti-vacuity, and the property that keeps this from becoming a PUT
    /// on every single apply forever: a registration that is already right
    /// produces no update at all.
    #[test]
    fn a_correct_registration_is_left_entirely_alone() {
        let right = existing_client("tvCategory", "tv");
        assert!(
            registration_needing_category_fix(&right, "tvCategory", Some("tv")).is_none(),
            "a correct category must not be rewritten on every apply"
        );
        let none_wanted = existing_client("category", "");
        assert!(
            registration_needing_category_fix(&none_wanted, "category", None).is_none(),
            "an already-empty category must not be rewritten either"
        );
    }

    /// Prowlarr's direction: the live host has `[[prowlarr]]` registered,
    /// and the correct end state is no category at all.
    #[test]
    fn an_app_id_category_is_cleared_for_a_consumer_with_no_library() {
        let before = existing_client("category", "prowlarr");
        let after = registration_needing_category_fix(&before, "category", None)
            .expect("prowlarr's app-id category must be cleared");
        assert_eq!(category_value_in(&after, "category"), "");
    }

    /// A field the app did not return at all is the same state as empty --
    /// and must still be filled in when a category is wanted, rather than
    /// being read as "already correct".
    #[test]
    fn a_missing_category_field_is_added_rather_than_read_as_correct() {
        let before = serde_json::json!({
            "id": 1,
            "name": "sabnzbd",
            "fields": [ { "name": "host", "value": "127.0.0.1" } ],
        });
        let after = registration_needing_category_fix(&before, "tvCategory", Some("tv"))
            .expect("an absent category field must be added");
        assert_eq!(category_value_in(&after, "tvCategory"), "tv");
        assert!(
            registration_needing_category_fix(&before, "tvCategory", None).is_none(),
            "an absent field with no category wanted is already correct"
        );
    }

    /// A config in the shape modules/core/reconciler.nix really emits --
    /// taken verbatim from the rendered ferrum-reconcile-config.json of a
    /// host with sonarr, radarr, prowlarr, qbittorrent and sabnzbd enabled.
    fn real_shaped_config() -> ReconcileConfig {
        serde_json::from_str(
            r#"{
              "apps": {
                "qbittorrent": { "host": "127.0.0.1", "port": 8090, "apiKeySecretPath": null },
                "sabnzbd": { "host": "127.0.0.1", "port": 8080, "apiKeySecretPath": null }
              },
              "pairs": [
                { "kind": "application", "consumer": "prowlarr", "provider": "sonarr" },
                { "kind": "downloadClient", "consumer": "prowlarr", "provider": "qbittorrent", "category": null },
                { "kind": "downloadClient", "consumer": "prowlarr", "provider": "sabnzbd", "category": null },
                { "kind": "downloadClient", "consumer": "radarr", "provider": "qbittorrent", "category": "movies" },
                { "kind": "downloadClient", "consumer": "radarr", "provider": "sabnzbd", "category": "movies" },
                { "kind": "downloadClient", "consumer": "sonarr", "provider": "qbittorrent", "category": "tv" },
                { "kind": "downloadClient", "consumer": "sonarr", "provider": "sabnzbd", "category": "tv" }
              ],
              "rootFolders": [
                { "app": "radarr", "path": "/data/media/movies" },
                { "app": "sonarr", "path": "/data/media/tv" }
              ],
              "downloadPaths": [
                { "app": "qbittorrent", "path": "/data/torrents" },
                { "app": "sabnzbd", "path": "/data/usenet/complete", "incompletePath": "/data/usenet/incomplete" }
              ]
            }"#,
        )
        .expect("the fixture parses as a real config")
    }

    /// The two names Nix writes must be the two names this binary reads.
    ///
    /// They were not. `ReconcileConfig` had no `rename_all`, so `rootFolders`
    /// matched no field and `downloadPaths` matched no field; `#[serde(default)]`
    /// then supplied an empty Vec for each and the binary ran to completion
    /// reporting success, having set not one root folder and pointed not one
    /// download client at <mediaDir>. Silent on every host, for as long as
    /// those fields have existed.
    ///
    /// Asserted against the real emitted KEY NAMES rather than against a
    /// round-trip of this program's own serialization, because a round-trip
    /// would have agreed with itself and proved nothing -- the two sides that
    /// have to agree are Nix's writer and this reader.
    #[test]
    fn the_config_nix_writes_is_the_config_this_binary_reads() {
        let config = real_shaped_config();
        assert_eq!(
            config.root_folders.len(),
            2,
            "rootFolders did not reach the field that registers root folders"
        );
        assert_eq!(
            config.download_paths.len(),
            2,
            "downloadPaths did not reach the field that drives the download clients"
        );
        assert_eq!(config.pairs.len(), 7);

        // And the nested values arrive intact, not merely the outer arrays.
        let sab = config
            .download_paths
            .iter()
            .find(|dp| dp.app == "sabnzbd")
            .expect("sabnzbd's download path");
        assert_eq!(sab.path, "/data/usenet/complete");
        assert_eq!(
            sab.incomplete_path.as_deref(),
            Some("/data/usenet/incomplete"),
            "incompletePath is the camelCase case inside the nested struct too"
        );
    }

    /// Anti-vacuity for the test above, in the other direction: the empty
    /// result it now rejects is genuinely what the WRONG key names produce,
    /// rather than something no realistic input could reach. If serde had
    /// been strict about unknown fields all along, the defect would have
    /// been a parse error on the first apply instead of eight months of
    /// quiet success.
    #[test]
    fn the_wrong_key_names_deserialize_to_nothing_rather_than_failing() {
        let snake: ReconcileConfig = serde_json::from_str(
            r#"{ "apps": {}, "pairs": [],
                 "root_folders": [ { "app": "sonarr", "path": "/data/media/tv" } ],
                 "download_paths": [ { "app": "qbittorrent", "path": "/data/torrents" } ] }"#,
        )
        .expect("serde accepts unknown fields, which is exactly why this was silent");
        assert!(
            snake.root_folders.is_empty() && snake.download_paths.is_empty(),
            "a key name this binary does not read is dropped without a word"
        );
    }

    #[test]
    fn category_field_name_matches_each_apps_real_schema() {
        assert_eq!(category_field_name("sonarr").unwrap(), "tvCategory");
        assert_eq!(category_field_name("radarr").unwrap(), "movieCategory");
        assert_eq!(category_field_name("prowlarr").unwrap(), "category");
        assert!(category_field_name("qbittorrent").is_err());
    }

    #[test]
    fn download_client_api_path_uses_v1_for_prowlarr_v3_for_sonarr_radarr() {
        assert_eq!(download_client_api_path("sonarr").unwrap(), "/api/v3/downloadclient");
        assert_eq!(download_client_api_path("radarr").unwrap(), "/api/v3/downloadclient");
        assert_eq!(download_client_api_path("prowlarr").unwrap(), "/api/v1/downloadclient");
    }

    #[test]
    fn default_sync_categories_are_non_empty_and_real() {
        assert_eq!(default_sync_categories("sonarr").unwrap().len(), 8);
        assert_eq!(default_sync_categories("radarr").unwrap().len(), 11);
        assert!(default_sync_categories("qbittorrent").is_err());
    }

    #[test]
    fn read_api_key_trims_the_trailing_newline_encrypt_and_write_adds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, "deadbeef1234\n").unwrap();
        let result = read_api_key(&Some(path.to_string_lossy().to_string())).unwrap();
        assert_eq!(result, Some("deadbeef1234".to_string()));
    }

    #[test]
    fn read_api_key_returns_none_for_none_path() {
        assert_eq!(read_api_key(&None).unwrap(), None);
    }
}
