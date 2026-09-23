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
    match tokio::fs::read_to_string(settings_path()).await {
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
///
/// Takes the schema's path rather than reading `$FERRUM_SETTINGS_SCHEMA`
/// itself, so the unit under test holds no process-global state. That is
/// not tidiness: the environment is shared by every test in the binary, and
/// the tests below and `catalog.rs`'s run in parallel against the same
/// variable. Passing the path made a real cross-module flake impossible
/// rather than unlikely -- it had already produced a failure that
/// reproduced only in the full suite and passed in isolation.
fn validate_against_schema_at(schema_path: &std::path::Path, proposed: &Value) -> Result<(), String> {
    let schema_path = schema_path.display();
    let schema_raw = std::fs::read_to_string(schema_path.to_string())
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

/// [`validate_against_schema_at`] against the schema this host was built
/// with.
///
/// The one place `$FERRUM_SETTINGS_SCHEMA` is read, so the variable is a
/// detail of how the daemon is wired rather than something every layer
/// below has to know about.
///
/// # Errors
/// As [`validate_against_schema_at`], plus the variable being unset.
fn validate_against_schema(proposed: &Value) -> Result<(), String> {
    let schema_path = std::env::var("FERRUM_SETTINGS_SCHEMA")
        .map_err(|_| "FERRUM_SETTINGS_SCHEMA not set -- cannot validate settings".to_string())?;
    validate_against_schema_at(std::path::Path::new(&schema_path), proposed)
}

pub async fn put_settings(
    State(_state): State<Arc<AppState>>,
    axum::Extension(crate::SessionUsername(username)): axum::Extension<crate::SessionUsername>,
    axum::Extension(client): axum::Extension<crate::client_addr::ClientAddr>,
    Json(proposed): Json<Value>,
) -> impl IntoResponse {
    let user = username.as_deref().unwrap_or(crate::UNKNOWN_USER).to_string();
    // The settings DOCUMENT is never logged. It is operator-authored and can
    // hold anything, and `ferrum.secrets` declares secret names next to
    // whatever else an operator has put in there -- so the audit line
    // records that a write happened, by whom, from where, not what was in
    // it. The file itself is the record of its own contents.
    let audit_write = |outcome: &str, detail: &str| {
        crate::audit::record("settings-write", outcome, &user, &client, detail);
    };
    // Reading the schema off disk and compiling it is both file I/O and real
    // CPU work, so it runs on the blocking pool rather than on the executor
    // thread serving this request. The document is handed to the closure and
    // handed back by it, so validation and the write that follows cannot
    // disagree about what was validated.
    let validated = crate::run_blocking(move || validate_against_schema(&proposed).map(|()| proposed)).await;
    let proposed = match validated {
        Ok(Ok(proposed)) => proposed,
        Ok(Err(msg)) => {
            audit_write("failure", "rejected by schema validation");
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
        Err(status) => {
            audit_write("error", "blocking task failed");
            return status.into_response();
        }
    };
    let path = settings_path();
    let content = serde_json::to_string_pretty(&proposed).unwrap();
    match tokio::fs::write(&path, content).await {
        Ok(()) => {
            audit_write("success", "");
            StatusCode::OK.into_response()
        }
        Err(e) => {
            audit_write("error", "write failed");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to write settings.json: {e}")).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a schema to its own directory and hands back both.
    ///
    /// The `TempDir` comes back so the caller keeps it alive; dropping it
    /// deletes the file out from under the validator.
    fn schema_file(schema: serde_json::Value) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings-schema.json");
        std::fs::write(&path, schema.to_string()).unwrap();
        (dir, path)
    }

    /// The small schema the shape tests use.
    fn secrets_only_schema() -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "secrets": { "type": "object" } },
            "required": ["secrets"]
        })
    }

    #[test]
    fn validate_against_schema_rejects_when_env_var_unset() {
        std::env::remove_var("FERRUM_SETTINGS_SCHEMA");
        let result = validate_against_schema(&serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("FERRUM_SETTINGS_SCHEMA not set"));
    }

    #[test]
    fn validate_against_schema_accepts_a_conforming_document() {
        let (_dir, schema) = schema_file(secrets_only_schema());
        let result = validate_against_schema_at(&schema, &serde_json::json!({"secrets": {}}));
        assert!(result.is_ok(), "expected a conforming document to pass: {result:?}");
    }

    #[test]
    fn validate_against_schema_rejects_a_nonconforming_document() {
        let (_dir, schema) = schema_file(secrets_only_schema());
        let result =
            validate_against_schema_at(&schema, &serde_json::json!({"secrets": "not-an-object"}));
        assert!(result.is_err(), "expected a type mismatch to fail validation");
    }

    // --- the `pattern` guards on the write path ------------------------
    //
    // H-01 put a JSON-Schema `pattern` on `daemon.listenAddress`,
    // `proxy.baseDomain` and `daemon.subdomain`, because those three are
    // interpolated into nginx directives and an unconstrained string there
    // was a real, served injection. Three layers now refuse a bad value --
    // this `pattern` at the WRITE, `addressLiteral`/`dnsLabel` at NixOS
    // evaluation, and `isOctet`'s parse -- and until now only the latter
    // two had any regression pin at all: `wronglyAcceptedInjection` is a
    // Nix eval fixture, and nothing exercised the schema itself.
    //
    // WHAT THESE TESTS DO AND DO NOT HOLD, stated because a pin that is
    // believed to cover more than it does is worse than none. They drive
    // the REAL validator, so they die if `pattern` support regresses (a
    // jsonschema major bump renames the top-level entry point and would
    // otherwise fail silently -- that gotcha is documented above) and they
    // die if any of these payloads stops being refused. They do NOT read
    // modules/lib/settings-schema.json, so they do not die if a `pattern`
    // is deleted from it: every Rust derivation in nix/ filters `src` to
    // crates/ + examples/ + flake.lock, so the real file is not reachable
    // from a test here at all. Closing that half needs those filters
    // widened, which is a change to nix/, and it has been raised rather
    // than guessed at.

    /// The three patterns as shipped in `modules/lib/settings-schema.json`.
    ///
    /// Copied, and that copy is the limitation above. Kept as one constant
    /// rather than inline per test so there is a single place to compare
    /// against the real file by eye, and one place to point at from the
    /// change that makes the comparison mechanical.
    const LISTEN_ADDRESS_PATTERN: &str = concat!(
        r"^(127\.(0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])",
        r"\.(0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])",
        r"\.(0|[1-9][0-9]?|1[0-9][0-9]|2[0-4][0-9]|25[0-5])|::1)$"
    );
    /// `daemon.subdomain`: a DNS label, and NOT optional -- an empty one
    /// would collapse the daemon's vhost name onto the base domain.
    const DNS_LABEL_PATTERN: &str =
        r"^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$";

    /// `proxy.baseDomain`: the same shape wrapped in `(...)?`, because
    /// EMPTY is the value that means "this host publishes nothing" -- the
    /// safest configuration ferrum offers, and one the UI has to be able to
    /// write. Transcribing `daemon.subdomain`'s label pattern here instead
    /// is not a theoretical mistake: this constant was written that way
    /// first, and `the_configurations_that_are_actually_safe_are_still_writable`
    /// is what caught it.
    const BASE_DOMAIN_PATTERN: &str =
        r"^([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*)?$";

    /// A schema carrying the real patterns, and its path.
    ///
    /// No environment variable: see `validate_against_schema_at`.
    fn schema_with_patterns() -> (tempfile::TempDir, std::path::PathBuf) {
        schema_file(serde_json::json!({
                "type": "object",
                "properties": {
                    "secrets": { "type": "object" },
                    "proxy": {
                        "type": "object",
                        "properties": {
                            "enable": { "type": "boolean" },
                            "baseDomain": { "type": "string", "pattern": BASE_DOMAIN_PATTERN },
                        },
                    },
                    "auth": {
                        "type": "object",
                        "properties": { "enable": { "type": "boolean" } },
                    },
                    "daemon": {
                        "type": "object",
                        "properties": {
                            "enable": { "type": "boolean" },
                            "listenAddress": {
                                "type": "string",
                                "pattern": LISTEN_ADDRESS_PATTERN,
                            },
                            "subdomain": { "type": "string", "pattern": DNS_LABEL_PATTERN },
                        },
                    },
                },
        }))
    }

    /// The write-path half of H-01's defence, on all three fields.
    ///
    /// The payloads are the real ones: `listenAddress` is interpolated into
    /// `proxy_pass`, and `baseDomain` into `server_name` and into
    /// `error_page 401 =302 https://auth.${baseDomain}/...`. A `;` or a
    /// newline in either closes the directive and opens another, which is
    /// how a real nginx came to serve a smuggled block.
    #[test]
    fn the_schema_refuses_every_injection_payload_on_the_nginx_interpolated_fields() {
        let (_dir, schema) = schema_with_patterns();
        let cases: &[(&str, serde_json::Value)] = &[
            (
                "a listenAddress closing the proxy_pass directive",
                serde_json::json!({"daemon": {"listenAddress": "127.0.0.1; } location / { proxy_pass http://evil;"}}),
            ),
            (
                "a listenAddress that is not loopback at all",
                serde_json::json!({"daemon": {"listenAddress": "0.0.0.0"}}),
            ),
            (
                "a listenAddress octet out of range",
                serde_json::json!({"daemon": {"listenAddress": "127.0.0.256"}}),
            ),
            (
                "a listenAddress with a trailing newline",
                serde_json::json!({"daemon": {"listenAddress": "127.0.0.1\n"}}),
            ),
            (
                "a hostname rather than a literal",
                serde_json::json!({"daemon": {"listenAddress": "localhost"}}),
            ),
            (
                "a baseDomain carrying a directive terminator",
                serde_json::json!({"proxy": {"baseDomain": "example.com; return 200 'pwned';"}}),
            ),
            (
                "a baseDomain with an embedded space",
                serde_json::json!({"proxy": {"baseDomain": "example.com evil.com"}}),
            ),
            (
                "an empty subdomain, which would collapse the vhost name",
                serde_json::json!({"daemon": {"subdomain": ""}}),
            ),
            (
                "a subdomain closing its own location block",
                serde_json::json!({"daemon": {"subdomain": "ferrum} location /x {"}}),
            ),
        ];
        for (what, document) in cases {
            assert!(
                validate_against_schema_at(&schema, document).is_err(),
                "the schema accepted {what}: {document}"
            );
        }
    }

    /// The other direction, and the reason the test above is not vacuous:
    /// a pattern that refused everything would pass it while breaking every
    /// real host.
    #[test]
    fn the_schema_still_accepts_the_values_a_real_host_uses() {
        let (_dir, schema) = schema_with_patterns();
        let cases: &[serde_json::Value] = &[
            serde_json::json!({"daemon": {"listenAddress": "127.0.0.1"}}),
            serde_json::json!({"daemon": {"listenAddress": "127.0.0.2"}}),
            serde_json::json!({"daemon": {"listenAddress": "::1"}}),
            serde_json::json!({"daemon": {"subdomain": "ferrum"}}),
            serde_json::json!({"proxy": {"baseDomain": "home.example.com"}}),
        ];
        for document in cases {
            let result = validate_against_schema_at(&schema, document);
            assert!(result.is_ok(), "the schema refused a legitimate value {document}: {result:?}");
        }
    }
}
