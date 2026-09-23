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

/// Every step of a secret write blocks: two file reads, an age recipient
/// derivation, and the encrypt-and-write itself. They are kept together in
/// one synchronous function so the handler hands the whole sequence to the
/// blocking pool in a single hop rather than bouncing between pools four
/// times.
fn write_secret_blocking(name: &str, plaintext: &str) -> (StatusCode, String) {
    match is_declared_secret(name) {
        Ok(true) => {}
        Ok(false) => {
            return (StatusCode::BAD_REQUEST, format!("'{name}' is not declared in ferrum.secrets"))
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to check ferrum.secrets: {e}"),
            )
        }
    }

    let recipient = match ferrum_secrets::host_age_recipient(&host_key_pub()) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to derive host age recipient: {e}"),
            )
        }
    };

    let dest = secrets_dir().join(format!("{name}.sops"));
    match ferrum_secrets::encrypt_and_write(plaintext, &recipient, &dest) {
        Ok(()) => (StatusCode::OK, String::new()),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write secret: {e}")),
    }
}

pub async fn write_secret(
    Path(name): Path<String>,
    axum::Extension(crate::SessionUsername(username)): axum::Extension<crate::SessionUsername>,
    axum::Extension(client): axum::Extension<crate::client_addr::ClientAddr>,
    body: Bytes,
) -> impl IntoResponse {
    let user = username.as_deref().unwrap_or(crate::UNKNOWN_USER).to_string();
    // The secret's NAME, never one byte of `body`. This file exists to write
    // secrets, so it is the single most dangerous place in the crate to be
    // careless with a log line -- and `name` is already constrained to a
    // value declared in ferrum.secrets, so it is not free-form either.
    let audit_write = |outcome: &str, detail: &str| {
        crate::audit::record("secret-write", outcome, &user, &client, detail);
    };
    let audited_name = name.clone();

    let plaintext = match std::str::from_utf8(&body) {
        Ok(s) => s.to_string(),
        Err(_) => {
            audit_write("failure", "value was not valid UTF-8");
            return (StatusCode::BAD_REQUEST, "secret value must be valid UTF-8").into_response();
        }
    };

    match crate::run_blocking(move || write_secret_blocking(&name, &plaintext)).await {
        Ok((StatusCode::OK, _)) => {
            audit_write("success", &format!("secret={audited_name}"));
            StatusCode::OK.into_response()
        }
        Ok((status, message)) => {
            audit_write("failure", &format!("secret={audited_name} status={status}"));
            (status, message).into_response()
        }
        Err(status) => {
            audit_write("error", "blocking task failed");
            status.into_response()
        }
    }
}
