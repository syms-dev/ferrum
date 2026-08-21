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

    for pair in &config.pairs {
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
            "downloadClient" => {
                register_download_client(&pair.consumer, consumer, &consumer_key, &pair.provider, provider)?
            }
            "application" => {
                register_application(consumer, &consumer_key, &pair.provider, provider)?
            }
            other => anyhow::bail!("unknown pair kind '{other}' for {}->{}", pair.consumer, pair.provider),
        }
        println!("ferrum-reconcile: {} <- {} ({}) OK", pair.consumer, pair.provider, pair.kind);
    }
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

    let body = serde_json::json!({
        "enable": true,
        "protocol": protocol,
        "priority": 1,
        "name": provider_id,
        "implementation": implementation,
        "configContract": config_contract,
        "fields": fields,
    });

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
