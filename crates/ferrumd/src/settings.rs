// Settings read/write. PUT never triggers an apply -- that's always a
// separate, explicit POST /api/jobs call (Task 6), so an operator reviews
// a change before it's ever built. Schema validation happens against
// $FERRUM_SETTINGS_SCHEMA (the ferrum-settings-schema package built in
// this task's own Step 1), which is necessarily a snapshot from the last
// rebuild: a brand-new option only validates once the box has already
// rebuilt with it, exactly the same rebuild that app's own service.nix
// needs to exist at all.
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::Value;
use std::sync::Arc;

use crate::AppState;

fn settings_path() -> std::path::PathBuf {
    std::env::var("FERRUM_SETTINGS_PATH")
        .unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string())
        .into()
}

pub async fn get_settings() -> impl IntoResponse {
    match std::fs::read_to_string(settings_path()) {
        Ok(raw) => match serde_json::from_str::<Value>(&raw) {
            Ok(parsed) => (StatusCode::OK, Json(parsed)).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("settings.json is corrupt: {e}")).into_response(),
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to read settings.json: {e}")).into_response(),
    }
}

/// Real, verified API (see this plan's Global Constraints for the exact
/// jsonschema 0.18.3 facts, confirmed via a real compiled spike --
/// including the version-pin gotcha that an unpinned "0.18" would silently
/// resolve fine but a NEWER jsonschema major uses a different top-level
/// function name entirely). Compiling the schema on every request is
/// deliberate, not an oversight: $FERRUM_SETTINGS_SCHEMA's own file can
/// change between requests only via a full host rebuild, which always
/// restarts ferrumd (systemd unit dependency, Task 6 Step 6) -- so
/// re-reading it fresh each call is simpler than cache invalidation and
/// costs one file read plus a schema compile per settings write, not per
/// read.
fn validate_against_schema(proposed: &Value) -> Result<(), String> {
    let schema_path = std::env::var("FERRUM_SETTINGS_SCHEMA")
        .map_err(|_| "FERRUM_SETTINGS_SCHEMA not set -- cannot validate settings".to_string())?;
    let schema_raw = std::fs::read_to_string(&schema_path)
        .map_err(|e| format!("failed to read settings schema at {schema_path}: {e}"))?;
    let schema: Value = serde_json::from_str(&schema_raw)
        .map_err(|e| format!("settings schema at {schema_path} is not valid JSON: {e}"))?;
    let compiled = jsonschema::JSONSchema::compile(&schema)
        .map_err(|e| format!("settings schema at {schema_path} does not compile as JSON Schema: {e}"))?;
    let result = match compiled.validate(proposed) {
        Ok(()) => Ok(()),
        Err(errors) => {
            let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
            Err(format!("settings failed schema validation: {}", messages.join("; ")))
        }
    };
    result
}

pub async fn put_settings(
    State(_state): State<Arc<AppState>>,
    Json(proposed): Json<Value>,
) -> impl IntoResponse {
    if let Err(msg) = validate_against_schema(&proposed) {
        return (StatusCode::BAD_REQUEST, msg).into_response();
    }
    let path = settings_path();
    let content = serde_json::to_string_pretty(&proposed).unwrap();
    match std::fs::write(&path, content) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write settings.json: {e}")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_against_schema_rejects_when_env_var_unset() {
        std::env::remove_var("FERRUM_SETTINGS_SCHEMA");
        let result = validate_against_schema(&serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("FERRUM_SETTINGS_SCHEMA not set"));
    }

    #[test]
    fn validate_against_schema_accepts_a_conforming_document() {
        let dir = tempfile::tempdir().unwrap();
        let schema_path = dir.path().join("settings-schema.json");
        std::fs::write(&schema_path, serde_json::json!({
            "type": "object",
            "properties": { "secrets": { "type": "object" } },
            "required": ["secrets"]
        }).to_string()).unwrap();
        std::env::set_var("FERRUM_SETTINGS_SCHEMA", &schema_path);
        let result = validate_against_schema(&serde_json::json!({"secrets": {}}));
        assert!(result.is_ok(), "expected a conforming document to pass: {result:?}");
    }

    #[test]
    fn validate_against_schema_rejects_a_nonconforming_document() {
        let dir = tempfile::tempdir().unwrap();
        let schema_path = dir.path().join("settings-schema.json");
        std::fs::write(&schema_path, serde_json::json!({
            "type": "object",
            "properties": { "secrets": { "type": "object" } },
            "required": ["secrets"]
        }).to_string()).unwrap();
        std::env::set_var("FERRUM_SETTINGS_SCHEMA", &schema_path);
        let result = validate_against_schema(&serde_json::json!({"secrets": "not-an-object"}));
        assert!(result.is_err(), "expected a type mismatch to fail validation");
    }
}
