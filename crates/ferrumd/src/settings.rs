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

/// Everything a proposed settings document must satisfy before it is
/// written: the schema's shape rules, then the cross-field rules the schema
/// cannot express.
///
/// Ordered deliberately. Schema first, so a document that is the wrong
/// SHAPE is reported as that rather than as whatever the cross-check makes
/// of a field of the wrong type.
///
/// # Arguments
/// * `schema_path` - the settings schema to validate against.
/// * `proposed` - the document as it arrived on the wire.
///
/// # Errors
/// A caller-facing message naming what is wrong, for a `400`.
fn validate_proposed_at(schema_path: &std::path::Path, proposed: &Value) -> Result<(), String> {
    validate_against_schema_at(schema_path, proposed)?;
    publication_matches_auth(proposed)
}

/// [`validate_proposed_at`] against the schema this host was built with.
///
/// The one place `$FERRUM_SETTINGS_SCHEMA` is read, so the variable is a
/// detail of how the daemon is wired rather than something every layer
/// below has to know about.
///
/// # Errors
/// As [`validate_proposed_at`], plus the variable being unset.
fn validate_proposed(proposed: &Value) -> Result<(), String> {
    let schema_path = std::env::var("FERRUM_SETTINGS_SCHEMA")
        .map_err(|_| "FERRUM_SETTINGS_SCHEMA not set -- cannot validate settings".to_string())?;
    validate_proposed_at(std::path::Path::new(&schema_path), proposed)
}

/// Refuses a document that would publish the control plane with no login in
/// front of it (SEC-04).
///
/// `auth.enable` is a bare boolean in the schema with no relation to
/// `daemon.enable`, so this write SUCCEEDED and then every subsequent apply
/// failed at modules/proxy/nginx.nix's H-03 assertion. Fail-closed, so
/// never an exposure -- but it bricks applies from the UI, which is a bad
/// outcome on a product whose whole claim is that the UI works. The
/// operator's only route back was to edit the file by hand, which is the
/// thing ferrum exists to avoid.
///
/// The predicate mirrors `modules/proxy/lib.nix`'s `daemonPublished`
/// conjoined with the assertion at `modules/proxy/nginx.nix:447`. The
/// defaults below are the NixOS options' own (modules/core/options.nix): a
/// key absent from settings.json takes the option default, so reading a
/// missing `daemon.enable` or `daemon.publish` as `false` would let exactly
/// the failing document through.
///
/// This is the one predicate written twice in two languages, so the drift
/// it can suffer is silent in both: a term added to `daemonPublished` and
/// not here refuses documents the host would build, and a term added here
/// and not there accepts documents it would not. `daemon.publish` was the
/// most recent such term.
///
/// Refusing the WRITE rather than only the apply is the same choice
/// `daemon.listenAddress`'s schema `pattern` already makes, and for the
/// same reason: eval time is too late once the value is on disk.
///
/// # Arguments
/// * `proposed` - the document as it arrived on the wire.
///
/// # Errors
/// A message naming both lines that would fix it, for a `400`.
fn publication_matches_auth(proposed: &Value) -> Result<(), String> {
    let flag = |section: &str, key: &str, default: bool| -> bool {
        proposed
            .get(section)
            .and_then(|s| s.get(key))
            .and_then(Value::as_bool)
            .unwrap_or(default)
    };
    let base_domain = proposed
        .get("proxy")
        .and_then(|p| p.get("baseDomain"))
        .and_then(Value::as_str)
        .unwrap_or("");

    // ferrum.daemon.enable and ferrum.daemon.publish both default to TRUE
    // and ferrum.auth.enable is an mkEnableOption, so it defaults to FALSE
    // -- which is why a document that merely sets a domain lands here.
    //
    // `publish` is a term here for the same reason it is a term in
    // daemonPublished: it is the ONLY key that unpublishes the dashboard
    // without deleting it. Omitting it would refuse the exact document the
    // installer's stage 1 writes, and would tell an operator who wants a
    // tunnel-only dashboard that their only option is a host with no web UI
    // at all -- which is the state this option was added to end.
    let published = flag("daemon", "enable", true)
        && flag("daemon", "publish", true)
        && flag("proxy", "enable", false)
        && !base_domain.is_empty();
    if published && !flag("auth", "enable", false) {
        return Err(
            "this would publish ferrum's own dashboard at the configured domain with no \
             login in front of it, and every apply would then be refused. Either set \
             auth.enable to true, or set daemon.publish to false -- which keeps ferrumd \
             running on loopback, reachable over an SSH tunnel, and takes only its vhost, \
             certificate and DNS record away."
                .to_string(),
        );
    }
    Ok(())
}

/// Replaces `path`'s contents with `content` atomically: a temp file in the
/// same directory, then a rename over the destination.
///
/// M2. This used to be a bare `tokio::fs::write`, which opens the
/// destination with `O_TRUNC` -- so the real settings.json is length 0 on
/// disk before any of the new document is written, for every write,
/// regardless of how small the document is. Two things fall into that
/// window:
///
/// * An apply's `builtins.fromJSON` read of this same file
///   (`ferrum-install/src/render.rs:394`) gets an empty or partial
///   document and fails evaluation with a parse error -- against a file
///   that is complete and valid by the time an operator goes to look at it.
/// * A crash inside the window leaves the file **permanently** empty.
///   Startup's `check_settings_writable` only opens the file, so it still
///   passes and ferrumd starts; `GET /api/settings` then 500s on the
///   unparseable document, so the UI cannot repair what it cannot load,
///   and every apply fails at eval. The only way out is hand-editing over
///   SSH, which is the failure mode this project exists to remove.
///
/// `rename(2)` within one filesystem is atomic: a reader holds either the
/// old complete document or the new one, never a partial, and a crash
/// leaves whichever of the two was current. The temp file is a sibling
/// rather than in `/tmp` precisely so the rename stays within one
/// filesystem -- across a mount boundary it would fail with `EXDEV`.
///
/// Same shape as `ferrum-apply`'s own intent write
/// (`crates/ferrum-apply/src/rollback.rs:63-64`), deliberately: this
/// project already had one correct answer to this and did not need a
/// second.
///
/// # Arguments
/// * `path` - the destination file, replaced wholesale.
/// * `content` - the complete document to leave there.
///
/// # Errors
/// Any I/O failure writing the temp file or renaming it into place. On
/// either, the destination still holds its previous contents.
async fn write_settings(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    tokio::fs::write(&tmp, content).await?;
    tokio::fs::rename(&tmp, path).await
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
    let validated = crate::run_blocking(move || validate_proposed(&proposed).map(|()| proposed)).await;
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
    match write_settings(&path, &content).await {
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
    fn validate_proposed_rejects_when_env_var_unset() {
        std::env::remove_var("FERRUM_SETTINGS_SCHEMA");
        let result = validate_proposed(&serde_json::json!({}));
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
    // EIGHT settings-writable values reach a sink that parses them. H-01
    // constrained three (`daemon.listenAddress`, `proxy.baseDomain`,
    // `daemon.subdomain`); SEC-01 and SEC-02 found the same class still
    // open on `proxy.trustedNetworks[]` and `apps.*.auth.bypassPaths[]`,
    // and the sweep that followed added `proxy.acme.email`,
    // `auth.adminEmail` and `apps.*.subdomain`. Six of the eight land in an
    // nginx directive, one reaches a shell, and one reaches Authelia's
    // users_database.yml -- the file that decides who may log in.
    //
    // Several layers refuse a bad value now -- this `pattern` at the WRITE,
    // the NixOS option types at evaluation, `isOctet`'s parse, and (for the
    // Authelia document) the escaping in
    // crates/ferrum-apply/src/secrets.rs -- and until now the write-path
    // layer had no regression pin at all: `wronglyAcceptedInjection` and
    // the fixtures beside it are Nix EVAL checks, so nothing tested that
    // the schema itself refuses a bad write.
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

    /// The patterns as shipped in `modules/lib/settings-schema.json`: six
    /// constants covering all eight guarded sites, since `daemon.subdomain`
    /// shares one with `apps.*.subdomain` and `proxy.acme.email` with
    /// `auth.adminEmail`.
    ///
    /// Copied, and that copy is the limitation above. Grouped here rather
    /// than inlined per test so there is a single place to compare against
    /// the real file, and one place to point at from the change that makes
    /// the comparison mechanical. All eight sites were compared
    /// byte-for-byte when this was written.
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

    /// `proxy.acme.email` and `auth.adminEmail`, which share one pattern.
    ///
    /// Two different sinks, both outside nginx. The ACME address reaches a
    /// shell; `auth.adminEmail` reaches
    /// `crates/ferrum-apply/src/secrets.rs`'s Authelia `users_database.yml`
    /// -- the file that decides who may log in to every gated app and to
    /// the control plane. Optional for the same reason `baseDomain` is:
    /// empty means "not configured".
    const EMAIL_PATTERN: &str = r"^([A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*)?$";

    /// `proxy.trustedNetworks[]`, which is emitted as `allow ${net};`
    /// BEFORE the `deny all` and `auth_request` that follow it -- so an
    /// injected `}` closed `location /` before the gate was ever emitted,
    /// and a real nginx served the application with forward-auth absent.
    const TRUSTED_NETWORK_PATTERN: &str = r"^[0-9A-Fa-f.:]+(/[0-9]{1,3})?$";

    /// `apps.<name>.auth.bypassPaths[]`, which becomes a location NAME
    /// (`location ${path} {`) and an Authelia regex. This one deletes
    /// `auth_request` from catalog apps.
    const BYPASS_PATH_PATTERN: &str = r"^/[A-Za-z0-9._~%/-]*$";

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
                            "acme": {
                                "type": "object",
                                "properties": {
                                    "email": { "type": "string", "pattern": EMAIL_PATTERN },
                                },
                            },
                            "trustedNetworks": {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "pattern": TRUSTED_NETWORK_PATTERN,
                                },
                            },
                        },
                    },
                    "auth": {
                        "type": "object",
                        "properties": {
                            "enable": { "type": "boolean" },
                            "adminEmail": { "type": "string", "pattern": EMAIL_PATTERN },
                        },
                    },
                    "apps": {
                        "type": "object",
                        "additionalProperties": {
                            "type": "object",
                            "properties": {
                                "subdomain": {
                                    "type": "string",
                                    "pattern": DNS_LABEL_PATTERN,
                                },
                                "auth": {
                                    "type": "object",
                                    "properties": {
                                        "bypassPaths": {
                                            "type": "array",
                                            "items": {
                                                "type": "string",
                                                "pattern": BYPASS_PATH_PATTERN,
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                    "daemon": {
                        "type": "object",
                        "properties": {
                            "enable": { "type": "boolean" },
                            "publish": { "type": "boolean" },
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

    /// The write-path half of the defence, on every guarded field.
    ///
    /// The payloads are the real ones, several of them served against a
    /// real nginx by the security review rather than argued: `listenAddress`
    /// is interpolated into `proxy_pass`, `baseDomain` into `server_name`
    /// and into `error_page 401 =302 https://auth.${baseDomain}/...`,
    /// `trustedNetworks[]` into `allow ${net};` ahead of the gate it is
    /// supposed to sit behind, and `bypassPaths[]` into a location name. A
    /// `;` or a `}` in any of them closes the directive and opens another,
    /// which is how a real nginx came to serve an application with
    /// forward-auth absent entirely.
    #[test]
    fn the_schema_refuses_every_injection_payload_on_the_pattern_guarded_fields() {
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
            // SEC-01. The payload the security review SERVED against a real
            // nginx: because the allow-list is concatenated BEFORE the
            // `deny all` and `auth_request`, the injected `}` closes
            // `location /` and the gate is never emitted at all.
            (
                "a trusted network closing the location it is meant to guard",
                serde_json::json!({"proxy": {"trustedNetworks": [
                    "127.0.0.1; } location /anything { proxy_pass http://127.0.0.1:8989; #"
                ]}}),
            ),
            (
                "a trusted network that is not an address at all",
                serde_json::json!({"proxy": {"trustedNetworks": ["all; #"]}}),
            ),
            // SEC-02. Same class, and materially worse: this one deletes
            // auth_request from a catalog app rather than from the daemon.
            (
                "a bypass path closing its own location block",
                serde_json::json!({"apps": {"sonarr": {"auth": {"bypassPaths": [
                    "/api} location / { proxy_pass http://evil; #"
                ]}}}}),
            ),
            (
                "a bypass path that is not rooted, so it is not a path",
                serde_json::json!({"apps": {"sonarr": {"auth": {"bypassPaths": ["api"]}}}}),
            ),
            (
                "an app subdomain closing its own server block",
                serde_json::json!({"apps": {"sonarr": {"subdomain": "sonarr} server {"}}}),
            ),
            // The ACME contact address reaches a shell, not a directive.
            (
                "an acme email carrying a shell command",
                serde_json::json!({"proxy": {"acme": {"email": "a@b.co; rm -rf /"}}}),
            ),
            // auth.adminEmail reaches Authelia's users_database.yml, the
            // file that decides who may log in. crates/ferrum-apply/src/
            // secrets.rs now escapes it too -- this is the boundary half of
            // that pair, and neither half is the whole defence.
            (
                "an admin email that would add a second Authelia admin",
                serde_json::json!({"auth": {
                    "adminEmail": "a@example.test\"\n  attacker:\n    groups:\n      - admins"
                }}),
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
            serde_json::json!({"proxy": {"trustedNetworks": ["192.168.1.0/24", "10.0.0.0/8"]}}),
            serde_json::json!({"proxy": {"trustedNetworks": ["::1", "fd00::/8"]}}),
            serde_json::json!({"proxy": {"acme": {"email": "admin@example.test"}}}),
            // Empty is legal on both addresses: it is what "not configured"
            // looks like, and the UI has to be able to write it back.
            serde_json::json!({"proxy": {"acme": {"email": ""}}}),
            serde_json::json!({"auth": {"adminEmail": "first.last+tag@example.co.uk"}}),
            serde_json::json!({"auth": {"adminEmail": ""}}),
            serde_json::json!({"apps": {"sonarr": {"subdomain": "sonarr"}}}),
            serde_json::json!({"apps": {"plex": {"auth": {"bypassPaths": [
                "/api", "/api/v3/", "/web/index.html", "/identity"
            ]}}}}),
        ];
        for document in cases {
            let result = validate_against_schema_at(&schema, document);
            assert!(result.is_ok(), "the schema refused a legitimate value {document}: {result:?}");
        }
    }

    /// MEASURED, not reasoned about: does this validator's `$` match
    /// before a trailing newline?
    ///
    /// It matters because every pattern here is anchored with `^...$`. If
    /// `$` behaved the way it does in Perl and Python -- matching before a
    /// final `\n` -- then a payload ending in a newline would PASS the
    /// schema and be caught later at NixOS evaluation instead. That is not
    /// an injection, because the eval-time type still refuses it, but it
    /// converts a cleanly refused REQUEST into a broken APPLY: the operator
    /// gets a 200 from the settings write and a failure on the next
    /// rebuild, which is precisely the failure mode the write-path guard
    /// exists to prevent.
    ///
    /// The answer, measured against jsonschema 0.18.3: `$` does NOT
    /// tolerate a trailing newline. `"abc\n"` is refused against `^abc$`.
    /// So the anchored patterns mean what they look like they mean, and no
    /// `\A...\z` rewrite is needed.
    ///
    /// Deliberately asserted against a throwaway `^abc$` rather than one of
    /// ferrum's patterns: those have many other reasons to reject a value,
    /// so a test using one would keep passing if this behaviour changed.
    /// This isolates the regex engine's anchor semantics and nothing else.
    ///
    /// The same fact is what makes the `"127.0.0.1\n"` case in the payload
    /// table above a real assertion rather than an accidental pass.
    #[test]
    fn the_validators_end_anchor_does_not_tolerate_a_trailing_newline() {
        let (_dir, schema) = schema_file(serde_json::json!({
            "type": "object",
            "properties": { "probe": { "type": "string", "pattern": "^abc$" } },
        }));
        assert!(
            validate_against_schema_at(&schema, &serde_json::json!({"probe": "abc"})).is_ok(),
            "the control must pass, or this test proves nothing"
        );
        assert!(
            validate_against_schema_at(&schema, &serde_json::json!({"probe": "abc\n"})).is_err(),
            "a trailing newline slipped past `$`: every anchored pattern in the real schema \
             would then be bypassable by appending one, turning a refused write into a \
             broken apply"
        );
    }

    // --- SEC-04: auth.enable vs daemon.enable --------------------------

    /// The document a host reaches by doing nothing but setting a domain:
    /// `daemon.enable` defaults to true, `auth.enable` to false. It used to
    /// be written happily and then refuse every apply afterwards.
    #[test]
    fn a_published_dashboard_with_auth_off_is_refused_at_the_write() {
        let (_dir, schema) = schema_with_patterns();
        let result = validate_proposed_at(&schema, &serde_json::json!({
            "proxy": { "enable": true, "baseDomain": "home.example.com" },
        }));
        let message = result.expect_err("a write that bricks every later apply must be refused");
        assert!(
            message.contains("auth.enable"),
            "the refusal must name the line that fixes it: {message}"
        );
    }

    /// Both ways out of it, exactly as the H-03 assertion offers them, and
    /// the two configurations that were never the problem. This is what
    /// keeps the check from being "refuse anything with a domain".
    #[test]
    fn the_configurations_that_are_actually_safe_are_still_writable() {
        let (_dir, schema) = schema_with_patterns();
        let cases: &[(&str, serde_json::Value)] = &[
            (
                "auth turned on, which is the fix the assertion asks for",
                serde_json::json!({
                    "proxy": { "enable": true, "baseDomain": "home.example.com" },
                    "auth": { "enable": true },
                }),
            ),
            (
                "the daemon not published, but still RUNNING and reached over an SSH \
                 tunnel -- the configuration ferrum.daemon.publish exists for, and the \
                 one the installer's stage 1 writes",
                serde_json::json!({
                    "proxy": { "enable": true, "baseDomain": "home.example.com" },
                    "daemon": { "enable": true, "publish": false },
                }),
            ),
            (
                "the daemon not running at all, which also publishes nothing -- the \
                 older, blunter spelling, still legal and still safe",
                serde_json::json!({
                    "proxy": { "enable": true, "baseDomain": "home.example.com" },
                    "daemon": { "enable": false },
                }),
            ),
            (
                "no domain at all -- the safest configuration ferrum offers, \
                 and the one an assertion keyed on auth alone would wrongly refuse",
                serde_json::json!({ "proxy": { "enable": true, "baseDomain": "" } }),
            ),
            (
                "the proxy off entirely",
                serde_json::json!({ "proxy": { "enable": false, "baseDomain": "home.example.com" } }),
            ),
            ("an empty document", serde_json::json!({})),
        ];
        for (what, document) in cases {
            let result = validate_proposed_at(&schema, document);
            assert!(result.is_ok(), "a write was refused for {what}: {result:?}");
        }
    }

    /// The defaults are the load-bearing part, and the easiest thing to get
    /// wrong: reading an absent `daemon.enable` as `false` would let the
    /// exact failing document through, because settings.json omits every
    /// key the operator has not set.
    #[test]
    fn an_absent_key_takes_the_nixos_option_default_not_the_json_one() {
        let (_dir, schema) = schema_with_patterns();
        // daemon.enable and daemon.publish both absent -> both TRUE, so
        // this IS published.
        assert!(
            validate_proposed_at(&schema, &serde_json::json!({
                "proxy": { "enable": true, "baseDomain": "home.example.com" },
                "auth": {},
            }))
            .is_err(),
            "an absent daemon.enable defaults to TRUE, so this publishes the dashboard"
        );
        // ...and specifically publish, which is the term added last and so
        // the one most likely to be read with a `false` default lifted from
        // JSON's idea of a missing boolean. A `daemon` block that names
        // some other key is the shape that would expose it: the block
        // exists, so a careless reader might treat its absence of `publish`
        // as an answer.
        assert!(
            validate_proposed_at(&schema, &serde_json::json!({
                "proxy": { "enable": true, "baseDomain": "home.example.com" },
                "daemon": { "enable": true },
            }))
            .is_err(),
            "an absent daemon.publish defaults to TRUE, so this publishes the dashboard"
        );
        // proxy.enable absent -> false, so nothing is published and the
        // domain alone is harmless.
        assert!(
            validate_proposed_at(&schema, &serde_json::json!({ "proxy": { "baseDomain": "home.example.com" } }))
                .is_ok(),
            "an absent proxy.enable defaults to FALSE, so nothing is published"
        );
    }

    /// Order matters: a document of the wrong SHAPE must be reported as
    /// that, not as whatever the cross-field check makes of a field whose
    /// type it never checked.
    #[test]
    fn schema_validation_runs_before_the_cross_field_check() {
        let (_dir, schema) = schema_with_patterns();
        let message = validate_proposed_at(&schema, &serde_json::json!({
            "proxy": { "enable": true, "baseDomain": "not a domain; return 200;" },
        }))
        .expect_err("a malformed baseDomain must be refused");
        assert!(
            message.contains("schema validation"),
            "the shape error must be the one reported: {message}"
        );
    }

    /// M2. A reader of settings.json must never see a document that is not
    /// a whole document.
    ///
    /// This is not a hypothetical concurrency worry. `builtins.fromJSON`
    /// reads this exact file during an apply
    /// (`ferrum-install/src/render.rs:394`), and a read landing inside the
    /// window a truncating write opens gets an empty or half file and dies
    /// with a parse error against a file that looks perfectly fine by the
    /// time anyone goes to look at it.
    ///
    /// The window belongs to `O_TRUNC`, not to the size of the payload:
    /// `tokio::fs::write` opens the destination truncating, so the file is
    /// length 0 on disk before a single byte of the new document is
    /// written, however small that document is. A reader polling across a
    /// few hundred writes hits it comfortably. With a temp-file-and-rename
    /// the window does not exist at any size, because the destination inode
    /// is only ever swapped for one that is already complete -- so this
    /// test cannot fail on the fixed code rather than merely tending not to.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_concurrent_reader_never_sees_a_half_written_settings_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let document = serde_json::json!({
            "secrets": { "example": "value" },
            "proxy": { "enable": true, "baseDomain": "example.test" },
        });
        let content = serde_json::to_string_pretty(&document).unwrap();
        let expected_len = content.len();

        // Seed it, so "the file is absent" is never a legitimate reading and
        // every observation below is of a file that genuinely exists.
        write_settings(&path, &content).await.unwrap();

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let torn = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let reader = {
            let (path, stop, torn) = (path.clone(), stop.clone(), torn.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    match std::fs::read_to_string(&path) {
                        // A short read is the tear itself; a read that is
                        // full-length but unparseable would be one too.
                        Ok(raw) => {
                            if raw.len() != expected_len {
                                torn.lock().unwrap().push(format!("{} bytes", raw.len()));
                            } else if serde_json::from_str::<Value>(&raw).is_err() {
                                torn.lock().unwrap().push("full length but not valid JSON".to_string());
                            }
                        }
                        // The destination vanishing is a tear of its own: an
                        // apply reading it here fails outright.
                        Err(e) => torn.lock().unwrap().push(format!("unreadable: {e}")),
                    }
                }
            })
        };

        for _ in 0..500 {
            write_settings(&path, &content).await.unwrap();
            tokio::task::yield_now().await;
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        reader.join().unwrap();

        let torn = torn.lock().unwrap();
        assert!(
            torn.is_empty(),
            "settings.json was observed in {} non-whole state(s) -- first few: {:?}. \
             A reader that catches this window gets a parse error on a file that is \
             intact by the time it is inspected, and a crash inside it leaves the file \
             permanently empty with no way to repair it from the UI",
            torn.len(),
            &torn[..torn.len().min(5)]
        );
    }
}
