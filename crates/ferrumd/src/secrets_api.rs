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
        Err(e) => return internal("failed to check ferrum.secrets", &e),
    }

    let recipient = match ferrum_secrets::host_age_recipient(&host_key_pub()) {
        Ok(r) => r,
        Err(e) => return internal("failed to derive the host age recipient", &e),
    };

    let dest = secrets_dir().join(format!("{name}.sops"));
    match ferrum_secrets::encrypt_and_write(plaintext, &recipient, &dest) {
        Ok(()) => (StatusCode::OK, String::new()),
        Err(e) => internal("failed to write the secret", &e),
    }
}

/// A 500 whose detail goes to the journal and not to the caller (SEC-09).
///
/// Every failure in this file carries a filesystem path -- the settings
/// file, the host key, the destination under `secrets_dir` -- because that
/// is what the operations are. Those paths were being returned in the
/// response body, which hands a caller a map of the one directory on this
/// host that exists to hold secrets. The operator still needs the detail to
/// fix it, so it goes where an operator can read it and a caller cannot:
/// `login_handler` already got exactly this treatment under L-03.
///
/// # Arguments
/// * `summary` - the fixed, caller-safe description of what failed.
/// * `error` - the real error, journalled with its full cause chain.
///
/// # Returns
/// The status and body for the handler to send back.
fn internal(summary: &str, error: &anyhow::Error) -> (StatusCode, String) {
    eprintln!("ferrumd: {summary}: {error:#}");
    (StatusCode::INTERNAL_SERVER_ERROR, summary.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// SEC-09. Both 500 paths in this file fail on a FILE, so their errors
    /// name one -- the settings document, the host key, the destination
    /// under the secrets directory. Returning that to the caller hands them
    /// a map of the one directory on this host that exists to hold secrets.
    ///
    /// Driven through `write_secret_blocking` rather than asserted against
    /// the helper, so it is the real wiring that is pinned: a future branch
    /// that formats its own error in would not be caught by a test of
    /// `internal` alone.
    ///
    /// One test covering both branches rather than two, because they set
    /// the same process-wide environment variable and would otherwise race
    /// each other under the test harness's parallelism.
    #[test]
    fn a_failing_secret_write_never_returns_a_filesystem_path_to_the_caller() {
        let dir = tempfile::tempdir().unwrap();

        // Branch 1: the settings document cannot be read at all.
        let absent_settings = dir.path().join("no-such-settings.json");
        std::env::set_var("FERRUM_SETTINGS_PATH", &absent_settings);
        let (status, body) = write_secret_blocking("cloudflare-token", "value");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_no_path_leaked(&body, &absent_settings.to_string_lossy());

        // Branch 2: settings are readable and declare the secret, but the
        // host key the recipient is derived from is missing.
        let settings = dir.path().join("settings.json");
        std::fs::write(
            &settings,
            serde_json::json!({ "secrets": { "cloudflare-token": {} } }).to_string(),
        )
        .unwrap();
        let absent_key = dir.path().join("no-such-host-key.pub");
        std::env::set_var("FERRUM_SETTINGS_PATH", &settings);
        std::env::set_var("FERRUM_HOST_KEY_PUB", &absent_key);
        let (status, body) = write_secret_blocking("cloudflare-token", "value");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_no_path_leaked(&body, &absent_key.to_string_lossy());
    }

    /// Asserts a response body says what failed without saying where.
    ///
    /// Checks the specific path AND the separator, because the tempdir
    /// prefix alone would not catch a body that leaked a different absolute
    /// path -- `secrets_dir()`'s default, say, which is exactly the one
    /// worth not disclosing.
    fn assert_no_path_leaked(body: &str, path: &str) {
        assert!(!body.is_empty(), "the caller still needs to be told something failed");
        assert!(!body.contains(path), "the failing path reached the caller: {body}");
        assert!(
            !body.contains('/'),
            "a 500 body from the secrets API must carry no filesystem path: {body}"
        );
    }
}
