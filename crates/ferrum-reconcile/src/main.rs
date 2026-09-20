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
}

#[derive(Deserialize)]
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

    if had_error {
        anyhow::bail!("one or more pairs failed to reconcile -- see errors above");
    }
    Ok(())
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
    let url = format!(
        "{}/api?mode=set_config&section=categories&name={category}&dir={category}&apikey={provider_key}&output=json",
        base_url(provider)
    );
    ureq::get(&url)
        .call()
        .map_err(|e| anyhow::anyhow!("failed to ensure SABnzbd category '{category}': {e}"))?;
    Ok(())
}

fn register_download_client(
    consumer_id: &str,
    consumer: &AppConnInfo,
    consumer_key: &str,
    provider_id: &str,
    provider: &AppConnInfo,
) -> anyhow::Result<()> {
    let base = base_url(consumer);
    let path = download_client_api_path(consumer_id)?;
    if find_existing_id(&base, path, consumer_key, provider_id)?.is_some() {
        return Ok(());
    }

    // Only Sabnzbd needs its own key read here (qBittorrent needs none) --
    // read_api_key handles both, called with the PROVIDER's own secret path.
    let provider_key = read_api_key(&provider.api_key_secret_path)?;

    if provider_id == "sabnzbd" {
        let key = provider_key.as_ref().ok_or_else(|| {
            anyhow::anyhow!("SABnzbd provider has no API key configured -- cannot ensure its category")
        })?;
        ensure_sabnzbd_category(provider, key, consumer_id)?;
    }

    let (implementation, config_contract, protocol, extra_fields) =
        provider_implementation(provider_id, &provider_key)?;
    let category_field = category_field_name(consumer_id)?;

    let mut fields = vec![
        serde_json::json!({ "name": "host", "value": provider.host }),
        serde_json::json!({ "name": "port", "value": provider.port }),
        serde_json::json!({ "name": "useSsl", "value": false }),
        serde_json::json!({ "name": category_field, "value": consumer_id }),
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
