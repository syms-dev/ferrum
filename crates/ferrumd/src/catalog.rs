// GET /api/catalog -- the document the schema-driven UI renders itself from.
//
// nix/modules/flake/packages.nix has built a `ferrum-catalog` package since
// Phase 1.1, and its own header comment read "Nothing consumes this yet
// (ferrumd is Phase 1.5)". This is that consumer: the per-app metadata the
// UI lists, plus the settings JSON Schema it generates one form definition
// from. The original design doc's "How the UI discovers the catalog" is the
// reasoning behind serving both.
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::Value;

/// Reads one JSON document named by an environment variable, distinguishing
/// the three ways it can fail.
///
/// Each failure names the real variable and the real path, because the
/// alternative -- a generic error, or worse an empty catalog -- renders in
/// the UI as "this host has no apps" and invites an operator to conclude
/// something was uninstalled. `settings.rs::validate_against_schema`
/// established this error style for `$FERRUM_SETTINGS_SCHEMA`; this matches
/// it deliberately rather than inventing a second one.
fn read_json_from_env(var: &str) -> Result<Value, String> {
    let path = std::env::var(var).map_err(|_| format!("{var} not set"))?;
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {var} at {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("{var} at {path} is not valid JSON: {e}"))
}

/// Builds the catalog document: the built catalog with the settings schema
/// embedded under a `schema` key, so the UI fetches one document rather than
/// racing two requests whose answers must agree.
///
/// Both files are read PER REQUEST rather than cached in a OnceCell. That is
/// deliberate and matches the reasoning `settings.rs` already records for the
/// schema: a ferrumd left running across a generation switch must not serve a
/// catalog its own binary no longer matches. The cost is two file reads on an
/// endpoint a human drives, which is not worth optimising away.
pub fn build_catalog() -> Result<Value, String> {
    let mut catalog = read_json_from_env("FERRUM_CATALOG")?;
    let schema = read_json_from_env("FERRUM_SETTINGS_SCHEMA")?;

    let obj = catalog
        .as_object_mut()
        .ok_or_else(|| "FERRUM_CATALOG is valid JSON but not a JSON object".to_string())?;
    obj.insert("schema".to_string(), schema);
    Ok(catalog)
}

pub async fn get_catalog() -> impl IntoResponse {
    // Two file reads and two JSON parses per request, on the blocking pool
    // rather than on the executor thread -- see main.rs's run_blocking.
    match crate::run_blocking(build_catalog).await {
        Ok(Ok(doc)) => (StatusCode::OK, Json(doc)).into_response(),
        Ok(Err(msg)) => (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
        Err(status) => status.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests mutate process-wide environment, which the other tests in
    /// this binary also read, so they are serialized into one #[test] rather
    /// than racing each other across the harness's threads -- the same
    /// discipline crates/ferrum-apply/src/progress.rs already applies for the
    /// identical reason.
    #[test]
    fn catalog_endpoint_behavior() {
        let dir = tempfile::tempdir().unwrap();
        let catalog_path = dir.path().join("catalog.json");
        let schema_path = dir.path().join("settings-schema.json");

        std::fs::write(
            &catalog_path,
            serde_json::json!({
                "schemaVersion": 1,
                "ferrumVersion": "abc1234",
                "apps": { "sonarr": { "id": "sonarr", "displayName": "Sonarr" } }
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            &schema_path,
            serde_json::json!({ "type": "object", "properties": { "apps": { "type": "object" } } })
                .to_string(),
        )
        .unwrap();

        // A real catalog and a real schema merge into one document, with the
        // catalog's own keys preserved alongside the embedded schema.
        std::env::set_var("FERRUM_CATALOG", &catalog_path);
        std::env::set_var("FERRUM_SETTINGS_SCHEMA", &schema_path);
        let doc = build_catalog().expect("a real catalog and schema must merge");
        assert_eq!(doc["schemaVersion"], 1);
        assert_eq!(doc["ferrumVersion"], "abc1234");
        assert_eq!(doc["apps"]["sonarr"]["displayName"], "Sonarr");
        assert_eq!(
            doc["schema"]["properties"]["apps"]["type"], "object",
            "the settings schema must be embedded under `schema`"
        );

        // A missing variable names the variable -- never an empty catalog,
        // which would render as "this host has no apps".
        std::env::remove_var("FERRUM_CATALOG");
        let err = build_catalog().expect_err("a missing FERRUM_CATALOG must be an error");
        assert!(err.contains("FERRUM_CATALOG not set"), "got: {err}");

        // A variable pointing at nothing names the real path.
        let missing = dir.path().join("does-not-exist.json");
        std::env::set_var("FERRUM_CATALOG", &missing);
        let err = build_catalog().expect_err("an unreadable catalog must be an error");
        assert!(err.contains("failed to read FERRUM_CATALOG"), "got: {err}");
        assert!(err.contains(missing.to_str().unwrap()), "got: {err}");

        // Invalid JSON is an error, NOT a silently empty app list.
        let broken = dir.path().join("broken.json");
        std::fs::write(&broken, "{ this is not json").unwrap();
        std::env::set_var("FERRUM_CATALOG", &broken);
        let err = build_catalog().expect_err("unparseable JSON must be an error");
        assert!(err.contains("is not valid JSON"), "got: {err}");

        // A catalog that parses but is not an object cannot have a schema
        // embedded in it, and says so rather than panicking.
        let not_obj = dir.path().join("array.json");
        std::fs::write(&not_obj, "[1, 2, 3]").unwrap();
        std::env::set_var("FERRUM_CATALOG", &not_obj);
        let err = build_catalog().expect_err("a non-object catalog must be an error");
        assert!(err.contains("not a JSON object"), "got: {err}");

        // A broken SCHEMA is reported against its own variable, not the
        // catalog's -- so an operator is sent to the right file.
        std::env::set_var("FERRUM_CATALOG", &catalog_path);
        std::env::set_var("FERRUM_SETTINGS_SCHEMA", &broken);
        let err = build_catalog().expect_err("an unparseable schema must be an error");
        assert!(err.contains("FERRUM_SETTINGS_SCHEMA"), "got: {err}");

        std::env::set_var("FERRUM_SETTINGS_SCHEMA", &schema_path);
    }
}
