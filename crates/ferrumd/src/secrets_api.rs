// Write-only, by construction: there is deliberately no GET handler
// anywhere in this file, and never will be -- that's what makes "ferrumd
// can write any secret but cannot read one back" a structural property,
// not a policy someone has to remember to uphold.
use axum::{
    body::Bytes,
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::Value;

fn secrets_dir() -> std::path::PathBuf {
    std::env::var("FERRUM_SECRETS_DIR").unwrap_or_else(|_| "/etc/ferrum/secrets".to_string()).into()
}

fn host_key_pub() -> std::path::PathBuf {
    std::env::var("FERRUM_HOST_KEY_PUB")
        .unwrap_or_else(|_| ferrum_secrets::DEFAULT_HOST_KEY_PUB.to_string())
        .into()
}

/// `name` is only accepted when the current settings.json's own
/// `ferrum.secrets` map declares it -- an arbitrary name is rejected,
/// keeping the write surface catalog/settings-driven rather than an
/// open-ended file-write primitive.
fn is_declared_secret(name: &str) -> anyhow::Result<bool> {
    let settings_path = std::env::var("FERRUM_SETTINGS_PATH").unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string());
    let raw = std::fs::read_to_string(&settings_path)?;
    let parsed: Value = serde_json::from_str(&raw)?;
    Ok(parsed
        .get("secrets")
        .and_then(|s| s.as_object())
        .map(|obj| obj.contains_key(name))
        .unwrap_or(false))
}

pub async fn write_secret(Path(name): Path<String>, body: Bytes) -> impl IntoResponse {
    match is_declared_secret(&name) {
        Ok(true) => {}
        Ok(false) => return (StatusCode::BAD_REQUEST, format!("'{name}' is not declared in ferrum.secrets")).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to check ferrum.secrets: {e}")).into_response(),
    }

    let plaintext = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "secret value must be valid UTF-8").into_response(),
    };

    let recipient = match ferrum_secrets::host_age_recipient(&host_key_pub()) {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to derive host age recipient: {e}")).into_response(),
    };

    let dest = secrets_dir().join(format!("{name}.sops"));
    match ferrum_secrets::encrypt_and_write(plaintext, &recipient, &dest) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write secret: {e}")).into_response(),
    }
}
