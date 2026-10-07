// GET /api/vpn -- what ferrum can actually establish about an app's VPN
// tunnel, and WHEN it established it.
//
// ============================================================================
// WHAT THIS CAN ESTABLISH, AND WHAT IT CANNOT
// ============================================================================
//
// This is the most important paragraph in the file, because ROAD-TO-PUBLIC
// item 23 is the standing rule it exists under: *a reading without an "as of
// when" is a gauge frozen at green*, and this project has already shipped the
// sibling defect more than once (an empty `systemctl list-dependencies`
// reading as health; a bare green dot standing in for a measurement).
//
// The measurement is the ActiveState of ONE systemd unit, named by the app's
// own catalog metadata (`meta.vpn.unit` -- today `qbt-vpn-netns-setup.service`,
// defined in modules/apps/qbittorrent/service.nix). That unit is a
// `Type=oneshot` with `RemainAfterExit=true`, so:
//
//   * `active` means its script ran ALL THE WAY THROUGH on this boot. The
//     network namespace was created, the WireGuard interface was configured
//     inside it from the operator's own config, addresses were added, and the
//     default route was installed. Nothing in that script tolerates a failure
//     -- it runs under `set -euo pipefail` -- so a partial run is `failed`,
//     not `active`.
//
//   * `failed`/`inactive` means the tunnel is NOT set up. That is reported as
//     `tunnel-down`, and it is also the moment the kill switch earns its name:
//     `qbittorrent.service` is `bindsTo` this unit, so qBittorrent is stopped
//     rather than left running outside the tunnel. Downloads are blocked on
//     purpose and there is no fallback to the host's own address.
//
// **`tunnel-configured` is NOT "the tunnel is carrying traffic", and this
// endpoint must never be rendered as if it were.** WireGuard is connectionless:
// an interface is "up" from the instant it is configured, whether or not the
// peer exists, answers, or has ever completed a handshake. Establishing that
// the tunnel really carries traffic would require reading `wg show`'s latest
// handshake from INSIDE the namespace, and ferrumd is deliberately unprivileged
// (`User=ferrum`, `CapabilityBoundingSet=""`, `NoNewPrivileges=true` -- see
// modules/core/daemon.nix), so it cannot enter a network namespace or run
// `wg(8)`. That is a real limit, not an oversight, and the UI states it in
// those words rather than implying a liveness this cannot prove.
//
// Everything else that could be inferred is reported as its own named state
// instead of being folded into "down": a tunnel that was never declared is
// `not-configured`, a declaration that has not been applied yet is
// `not-applied`, and a bus that did not answer is `unknown`. Collapsing any of
// those into `tunnel-down` would tell an operator to debug WireGuard when the
// actual next step is "press Apply".
//
// ## Freshness
//
// Every reading is taken live, per request -- nothing here is cached, exactly
// as `health.rs` does it -- and the response carries `checkedAt`, the unix
// second the reading was taken. The UI ages that on screen and says "checked N
// minutes ago" rather than painting a dot that cannot go stale. What ferrum
// does NOT know is when the tunnel came up: systemd's own
// `ActiveEnterTimestamp` would answer that and is deliberately not read here,
// so this endpoint promises only what it measures.
//
// ## Why this is session-gated, unlike /api/health
//
// `health.rs` is reachable without a session and pays for it with a closed
// vocabulary of fixed words. This body names a catalog app, a systemd unit and
// whether a VPN exists on this host at all, which is exactly the kind of
// host-shape disclosure that file refuses to make. So `/api/vpn` lives inside
// `protected` with every other control-plane route.
use crate::catalog;
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use serde_json::Value;
use std::time::Duration;

/// How long the systemd query waits before the answer becomes `unknown`.
///
/// The caller holds a session, so this is not the anonymous-load bound
/// `health.rs` reasons about -- it is an honesty bound. A bus that has not
/// answered in this long has not told us anything, and saying so beats holding
/// the request open until a browser gives up and shows nothing at all.
const SYSTEMD_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

/// What ferrum could establish about one app's tunnel.
///
/// Six values and nothing else is ever serialized into `state`. Each one has a
/// DIFFERENT next action for the operator, which is the test a state has to
/// pass to exist here rather than being folded into its neighbour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum VpnState {
    /// No VPN secret is declared for this app in settings.json, so there is no
    /// tunnel and no kill switch. The app, if enabled, reaches the network the
    /// way every other app does. Next action: paste a config.
    NotConfigured,
    /// The secret IS declared, and systemd has no such unit loaded. On a host
    /// that has applied this configuration the unit is always loaded -- it is
    /// pulled in by `qbittorrent.service`'s own `bindsTo` -- so this is the
    /// shape of "declared but never applied". Next action: apply.
    NotApplied,
    /// systemd is still bringing the unit up or taking it down. Next action:
    /// wait and re-check.
    Starting,
    /// The unit is `active`: its setup script ran to completion, so the
    /// namespace exists and the interface in it was configured from the
    /// operator's config. **Not a statement that traffic is flowing** -- see
    /// this module's header. Next action: none.
    TunnelConfigured,
    /// The unit is `failed` or `inactive`: the tunnel is not set up, and
    /// because the app is bound to this unit it is stopped rather than running
    /// outside the tunnel. Next action: read the unit's journal.
    TunnelDown,
    /// ferrumd could not ask. The system bus did not answer inside
    /// `SYSTEMD_QUERY_TIMEOUT`, or refused. Reported as its own state because
    /// "I could not find out" is not "it is down" -- rendering it as down
    /// would send an operator to debug a tunnel that may be perfectly fine.
    Unknown,
}

/// One app's VPN reading.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnReading {
    /// What ferrum established. See `VpnState`.
    pub state: VpnState,
    /// Whether the kill switch is on for this app -- the effective value of
    /// the catalog-named settings key, falling back to the catalog's own
    /// default when the document says nothing.
    ///
    /// Reported separately from `state` on purpose: with the kill switch OFF
    /// the namespace keeps a lower-priority fallback route through the host, so
    /// `tunnel-down` there means "downloads are leaving over your own address",
    /// which is the opposite operational conclusion from the same state word.
    pub kill_switch: bool,
    /// The systemd unit this reading was taken from, named so the operator can
    /// go read its journal, and `None` when no unit was consulted (there was
    /// nothing configured to consult one about).
    pub unit: Option<String>,
    /// systemd's own `ActiveState` word, verbatim, or `None` when systemd was
    /// not asked or did not answer.
    ///
    /// Published because every other field here is ferrum's interpretation and
    /// this is the raw observation behind it. An operator who disagrees with
    /// the interpretation can see what it was made from.
    pub active_state: Option<String>,
}

/// The whole document: one reading per app that declares a VPN, plus the one
/// timestamp they were all taken at.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnReport {
    /// Unix seconds, as a string -- the same wire convention `started_at` and
    /// the generation timestamps use, and for the same reason: the daemon
    /// cannot know the reader's timezone, so the UI renders it in the
    /// operator's own locale.
    pub checked_at: String,
    /// Keyed by catalog app id. An app that declares no `vpn` block is absent
    /// rather than present-and-empty.
    pub apps: std::collections::BTreeMap<String, VpnReading>,
}

/// One app's VPN declaration, as the catalog states it.
#[derive(Debug, Clone)]
struct VpnMeta {
    /// Catalog app id.
    id: String,
    /// The sops secret holding the config. Write-only; nothing reads it back.
    secret: String,
    /// The systemd unit whose state is the measurement.
    unit: String,
    /// The key under the app's `settings` that turns the kill switch on.
    setting: String,
    /// The catalog's own default for that key, used when the settings document
    /// is silent -- the same "show the effective value, not the document
    /// value" rule ui/forms.js already applies.
    setting_default: bool,
}

/// Reads every app's `vpn` block out of a catalog document.
///
/// Nothing in this file names an app id. The catalog is what decides which
/// apps have a tunnel, which is what keeps "adding an app is adding a
/// directory" true for this endpoint too.
///
/// # Arguments
/// * `catalog_doc` - a parsed catalog.json.
///
/// # Returns
/// One entry per app whose metadata declares a complete `vpn` block, sorted by
/// app id. An incomplete block is skipped rather than half-read: a missing
/// `unit` would otherwise produce a reading taken from no unit at all.
fn vpn_apps(catalog_doc: &Value) -> Vec<VpnMeta> {
    let Some(apps) = catalog_doc.get("apps").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut found: Vec<VpnMeta> = apps
        .iter()
        .filter_map(|(id, meta)| {
            let vpn = meta.get("vpn")?;
            let secret = vpn.get("secret")?.as_str()?.to_string();
            let unit = vpn.get("unit")?.as_str()?.to_string();
            let setting = vpn.get("setting")?.as_str()?.to_string();
            let setting_default = meta
                .pointer("/settingsSchema/properties")
                .and_then(|props| props.get(&setting))
                .and_then(|node| node.get("default"))
                .and_then(Value::as_bool)
                .unwrap_or(true);
            Some(VpnMeta { id: id.clone(), secret, unit, setting, setting_default })
        })
        .collect();
    found.sort_by(|a, b| a.id.cmp(&b.id));
    found
}

/// Whether a settings document declares this app's VPN secret.
///
/// `ferrum.secrets` is where a secret's EXISTENCE is declared, and it is the
/// same map `secrets_api::is_declared_secret` gates writes on -- so "the
/// operator has pasted a config" and "this name may be written" are the same
/// fact read from the same place rather than two that could disagree.
///
/// # Arguments
/// * `settings` - a parsed settings.json.
/// * `meta` - the app's catalog VPN declaration.
///
/// # Returns
/// True when `secrets` contains the declared name.
fn secret_is_declared(settings: &Value, meta: &VpnMeta) -> bool {
    settings
        .get("secrets")
        .and_then(Value::as_object)
        .is_some_and(|obj| obj.contains_key(&meta.secret))
}

/// The effective kill-switch value: what the document says, or the catalog's
/// default when it says nothing.
///
/// # Arguments
/// * `settings` - a parsed settings.json.
/// * `meta` - the app's catalog VPN declaration.
///
/// # Returns
/// The boolean the running host is actually configured with.
fn kill_switch_is_on(settings: &Value, meta: &VpnMeta) -> bool {
    settings
        .pointer(&format!("/apps/{}/settings/{}", meta.id, meta.setting))
        .and_then(Value::as_bool)
        .unwrap_or(meta.setting_default)
}

/// Turns one systemd unit observation into a state.
///
/// Split out from the D-Bus call so every branch is unit-testable without a
/// bus: the classification is the part that can be wrong in a way nobody
/// notices, because every wrong answer still renders as a plausible panel.
///
/// # Arguments
/// * `observation` - `None` when systemd reported no unit by that name;
///   otherwise the unit's `load_state` and `active_state`, verbatim.
///
/// # Returns
/// The state, and the raw `active_state` it was derived from.
fn classify(observation: Option<(&str, &str)>) -> (VpnState, Option<String>) {
    let Some((load_state, active_state)) = observation else {
        return (VpnState::NotApplied, None);
    };
    // `not-found` and `error` are systemd's own words for "this unit name
    // resolves to no unit file". A referenced-but-absent unit is listed with
    // that load state rather than omitted, so without this branch it would be
    // classified from its `active_state` (`inactive`) and reported as a tunnel
    // that is down -- sending an operator to read the journal of a unit that
    // does not exist, when the real answer is that the host has not been
    // rebuilt since the VPN was declared.
    if load_state != "loaded" {
        return (VpnState::NotApplied, Some(active_state.to_string()));
    }
    let state = match active_state {
        "active" => VpnState::TunnelConfigured,
        "activating" | "deactivating" | "reloading" => VpnState::Starting,
        // `inactive`, `failed`, `maintenance`, and anything systemd adds
        // later. Defaulting an unrecognised word to "down" is the safe
        // direction: it understates confidence rather than claiming a tunnel
        // that was never observed.
        _ => VpnState::TunnelDown,
    };
    (state, Some(active_state.to_string()))
}

/// Asks systemd for the state of every named unit, in one call.
///
/// # Arguments
/// * `units` - the unit names to ask about.
///
/// # Returns
/// `None` when the bus did not answer inside `SYSTEMD_QUERY_TIMEOUT` or
/// refused -- which is reported as `unknown`, never as down. Otherwise one
/// `(load_state, active_state)` pair per unit systemd knows about, keyed by
/// name; a unit systemd does not list is simply absent from the map.
async fn unit_states(
    units: &[String],
) -> Option<std::collections::HashMap<String, (String, String)>> {
    let patterns: Vec<&str> = units.iter().map(String::as_str).collect();
    let query = async {
        let connection = zbus::Connection::system().await.ok()?;
        let proxy = crate::dbus::SystemdManagerProxy::new(&connection).await.ok()?;
        // An empty `states` filter, for the same reason dbus.rs passes one:
        // the classification lives in `classify` above, where it is tested,
        // rather than depending on systemd's filter semantics matching what
        // this file means by each word.
        proxy.list_units_by_patterns(&[], &patterns).await.ok()
    };
    let listed = tokio::time::timeout(SYSTEMD_QUERY_TIMEOUT, query).await.ok()??;
    Some(
        listed
            .into_iter()
            .map(|u| (u.name, (u.load_state, u.active_state)))
            .collect(),
    )
}

/// Builds the whole report from a catalog, a settings document and whatever
/// systemd said.
///
/// Pure, and takes the systemd answer rather than fetching it, so the state
/// machine above is exercised against every combination in tests instead of
/// only against whatever a build sandbox's bus happens to do.
///
/// # Arguments
/// * `catalog_doc` - a parsed catalog.json.
/// * `settings` - a parsed settings.json.
/// * `observed` - `None` when systemd could not be asked; otherwise its reply.
/// * `checked_at` - the unix second this reading was taken.
///
/// # Returns
/// The report, with one entry per VPN-declaring app.
fn build_report(
    catalog_doc: &Value,
    settings: &Value,
    observed: Option<&std::collections::HashMap<String, (String, String)>>,
    checked_at: u64,
) -> VpnReport {
    let mut apps = std::collections::BTreeMap::new();
    for meta in vpn_apps(catalog_doc) {
        let kill_switch = kill_switch_is_on(settings, &meta);
        let reading = if !secret_is_declared(settings, &meta) {
            // No unit is named here, and that is deliberate: there is nothing
            // configured, so there is no journal to send anyone to.
            VpnReading { state: VpnState::NotConfigured, kill_switch, unit: None, active_state: None }
        } else {
            match observed {
                None => VpnReading {
                    state: VpnState::Unknown,
                    kill_switch,
                    unit: Some(meta.unit.clone()),
                    active_state: None,
                },
                Some(map) => {
                    let (state, active_state) = classify(
                        map.get(&meta.unit).map(|(l, a)| (l.as_str(), a.as_str())),
                    );
                    VpnReading { state, kill_switch, unit: Some(meta.unit.clone()), active_state }
                }
            }
        };
        apps.insert(meta.id, reading);
    }
    VpnReport { checked_at: checked_at.to_string(), apps }
}

/// The unix second, now.
///
/// Saturates at the epoch rather than panicking on a clock before 1970: a box
/// whose RTC has not been set yet is a real state during provisioning, and it
/// must not take the control plane down.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `GET /api/vpn` -- the live reading.
///
/// # Returns
/// 200 with a `VpnReport`, or 500 naming which document could not be read.
/// The caller holds a session, so the message names the real variable and the
/// real path exactly as `catalog::build_catalog` does for the same reason.
pub async fn get_vpn() -> impl IntoResponse {
    let documents = crate::run_blocking(|| {
        let catalog_doc = catalog::read_json_from_env("FERRUM_CATALOG").map_err(|e| e.message)?;
        let settings_path = std::env::var("FERRUM_SETTINGS_PATH")
            .unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string());
        let raw = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("failed to read settings at {settings_path}: {e}"))?;
        let settings: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("settings at {settings_path} is not valid JSON: {e}"))?;
        Ok::<(Value, Value), String>((catalog_doc, settings))
    })
    .await;

    let (catalog_doc, settings) = match documents {
        Ok(Ok(pair)) => pair,
        Ok(Err(message)) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        Err(status) => return status.into_response(),
    };

    let units: Vec<String> = vpn_apps(&catalog_doc).into_iter().map(|m| m.unit).collect();
    // The bus is asked ONLY when something declares a tunnel. A host with no
    // VPN at all should not open a system bus connection per dashboard paint.
    let observed = if units.is_empty() { None } else { unit_states(&units).await };

    // Taken AFTER the systemd query, not before: `checkedAt` must describe the
    // reading the body carries, and a timestamp stamped before a three-second
    // timeout would overstate its freshness by exactly the length of the
    // slowest case.
    let report = build_report(&catalog_doc, &settings, observed.as_ref(), now_unix());
    (StatusCode::OK, Json(report)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A catalog shaped like the real one: qBittorrent declaring a complete
    /// `vpn` block with its kill-switch default, and a second app declaring
    /// none.
    fn catalog_doc() -> Value {
        json!({
            "apps": {
                "qbittorrent": {
                    "id": "qbittorrent",
                    "displayName": "qBittorrent",
                    "vpn": {
                        "secret": "qbittorrent-vpn",
                        "unit": "qbt-vpn-netns-setup.service",
                        "setting": "vpnKillSwitch"
                    },
                    "settingsSchema": {
                        "properties": { "vpnKillSwitch": { "type": "boolean", "default": true } }
                    }
                },
                "sonarr": { "id": "sonarr", "displayName": "Sonarr" }
            }
        })
    }

    fn observed(load_state: &str, active_state: &str) -> std::collections::HashMap<String, (String, String)> {
        let mut map = std::collections::HashMap::new();
        map.insert(
            "qbt-vpn-netns-setup.service".to_string(),
            (load_state.to_string(), active_state.to_string()),
        );
        map
    }

    fn declared_settings() -> Value {
        json!({ "secrets": { "qbittorrent-vpn": {} }, "apps": { "qbittorrent": { "enable": true } } })
    }

    /// Only apps whose catalog metadata declares a VPN appear at all. An app
    /// with no tunnel is ABSENT, not present with a green-ish placeholder --
    /// which is the shape that invites a UI to render a panel for an app that
    /// has no tunnel to report on.
    #[test]
    fn only_vpn_declaring_apps_are_reported() {
        let report = build_report(&catalog_doc(), &declared_settings(), None, 1_760_000_000);
        assert_eq!(report.apps.keys().collect::<Vec<_>>(), vec!["qbittorrent"]);
        assert_eq!(report.checked_at, "1760000000");
    }

    /// An incomplete `vpn` block is skipped entirely rather than half-read.
    ///
    /// Without this, a block missing `unit` would produce a reading whose
    /// state was derived from no unit at all -- a measurement of nothing,
    /// rendered identically to a measurement of something.
    #[test]
    fn an_incomplete_vpn_block_is_not_a_measurement() {
        let partial = json!({
            "apps": { "qbittorrent": { "vpn": { "secret": "qbittorrent-vpn" } } }
        });
        assert!(vpn_apps(&partial).is_empty());
    }

    /// Every state, from the observation that produces it. This is the table
    /// the whole endpoint exists to get right.
    #[test]
    fn each_observation_produces_its_own_state() {
        let catalog_doc = catalog_doc();
        let settings = declared_settings();

        let state = |obs: Option<&std::collections::HashMap<String, (String, String)>>| {
            build_report(&catalog_doc, &settings, obs, 0).apps["qbittorrent"].state
        };

        // The bus did not answer: `unknown`, NEVER `tunnel-down`. Reporting a
        // tunnel as down because we could not ask would send an operator to
        // debug WireGuard over a daemon that simply could not reach systemd.
        assert_eq!(state(None), VpnState::Unknown);

        // systemd answered and knows no such unit: declared, not applied.
        assert_eq!(state(Some(&std::collections::HashMap::new())), VpnState::NotApplied);

        // A referenced-but-absent unit file: the same conclusion, reached from
        // a DIFFERENT observation. Classifying this from `active_state` alone
        // would call it `tunnel-down`.
        assert_eq!(state(Some(&observed("not-found", "inactive"))), VpnState::NotApplied);

        assert_eq!(state(Some(&observed("loaded", "active"))), VpnState::TunnelConfigured);
        assert_eq!(state(Some(&observed("loaded", "activating"))), VpnState::Starting);
        assert_eq!(state(Some(&observed("loaded", "deactivating"))), VpnState::Starting);
        assert_eq!(state(Some(&observed("loaded", "reloading"))), VpnState::Starting);
        assert_eq!(state(Some(&observed("loaded", "failed"))), VpnState::TunnelDown);
        assert_eq!(state(Some(&observed("loaded", "inactive"))), VpnState::TunnelDown);
        // A word systemd has not invented yet errs toward down rather than
        // toward a tunnel nobody observed.
        assert_eq!(state(Some(&observed("loaded", "something-new"))), VpnState::TunnelDown);
    }

    /// With no secret declared the state is `not-configured` and NO unit is
    /// named -- there is nothing configured, so there is no journal to send
    /// anyone to, and naming one would invite a wild goose chase.
    ///
    /// Driven with systemd reporting the unit as fully `active`, which is the
    /// sharp version: the secret declaration, not the unit, is what decides
    /// this, and a stale namespace left over from a removed declaration must
    /// not read as a configured tunnel.
    #[test]
    fn an_undeclared_secret_is_not_configured_whatever_systemd_says() {
        let settings = json!({ "secrets": {}, "apps": {} });
        let report = build_report(
            &catalog_doc(),
            &settings,
            Some(&observed("loaded", "active")),
            0,
        );
        let reading = &report.apps["qbittorrent"];
        assert_eq!(reading.state, VpnState::NotConfigured);
        assert_eq!(reading.unit, None);
        assert_eq!(reading.active_state, None);
    }

    /// The kill switch is the EFFECTIVE value: the catalog's default when the
    /// document is silent, the document's value when it is not.
    ///
    /// Silence meaning "off" is the bug this pins. qBittorrent's catalog
    /// default is `true`, and a panel that read the absent key as `false`
    /// would tell an operator their kill switch was off on a host where it is
    /// on -- the same class of lie ui/forms.js's "show the effective value"
    /// comment records having already shipped once for Plex's media access.
    #[test]
    fn the_kill_switch_reported_is_the_one_the_host_is_running() {
        let silent = json!({ "secrets": { "qbittorrent-vpn": {} }, "apps": { "qbittorrent": {} } });
        assert!(build_report(&catalog_doc(), &silent, None, 0).apps["qbittorrent"].kill_switch);

        let off = json!({
            "secrets": { "qbittorrent-vpn": {} },
            "apps": { "qbittorrent": { "settings": { "vpnKillSwitch": false } } }
        });
        assert!(!build_report(&catalog_doc(), &off, None, 0).apps["qbittorrent"].kill_switch);
    }

    /// The wire words, pinned. ui/app.js branches on every one of these and
    /// `app-detail-view-is-wired` compares the two lists, so a rename here is
    /// a rename the UI has to see.
    #[test]
    fn the_state_vocabulary_serializes_as_the_ui_expects() {
        let words: Vec<String> = [
            VpnState::NotConfigured,
            VpnState::NotApplied,
            VpnState::Starting,
            VpnState::TunnelConfigured,
            VpnState::TunnelDown,
            VpnState::Unknown,
        ]
        .iter()
        .map(|s| serde_json::to_value(s).unwrap().as_str().unwrap().to_string())
        .collect();
        assert_eq!(
            words,
            vec![
                "not-configured",
                "not-applied",
                "starting",
                "tunnel-configured",
                "tunnel-down",
                "unknown"
            ]
        );
    }

    /// The envelope's own key names, which the UI reads by name.
    #[test]
    fn the_envelope_carries_a_timestamp_with_every_reading() {
        let body = serde_json::to_value(build_report(
            &catalog_doc(),
            &declared_settings(),
            Some(&observed("loaded", "active")),
            1_760_000_123,
        ))
        .unwrap();
        assert_eq!(body["checkedAt"], "1760000123");
        assert_eq!(body["apps"]["qbittorrent"]["state"], "tunnel-configured");
        assert_eq!(body["apps"]["qbittorrent"]["killSwitch"], true);
        assert_eq!(body["apps"]["qbittorrent"]["unit"], "qbt-vpn-netns-setup.service");
        assert_eq!(body["apps"]["qbittorrent"]["activeState"], "active");
    }

    /// **The security claim the UI makes, asserted against this file.**
    ///
    /// The VPN panel tells the operator, in as many words, that the config
    /// they paste is encrypted on save and that ferrumd can write it but can
    /// never read it back. This endpoint is the ONE new place that both knows
    /// a secret's NAME and answers a browser, so it is the obvious place for a
    /// well-meaning "show the current config" field to be added later.
    ///
    /// The assertion is on the ENVIRONMENT this file reads, not on a denylist
    /// of scary words: a denylist spelled out in this file would match its own
    /// source and could never pass, and -- worse -- the first thing a future
    /// reader would do is delete it. Every path to a secret's value on this
    /// host starts at the secrets directory, which is named by exactly one
    /// environment variable, so pinning the variables this module reads is the
    /// same claim made in a form that cannot rot.
    ///
    /// Anti-vacuity first: the scan must find the two reads that ARE here
    /// before its silence about a third means anything.
    #[test]
    fn the_vpn_endpoint_reads_only_the_catalog_and_the_settings() {
        let source = include_str!("vpn.rs");
        assert!(source.contains("fn build_report("), "the scan must really be reading vpn.rs");

        let mut read: Vec<&str> = Vec::new();
        for (index, _) in source.match_indices("std::env::var(\"") {
            let rest = &source[index + "std::env::var(\"".len()..];
            read.push(rest.split('"').next().expect("an env var name is quoted"));
        }
        read.sort_unstable();
        read.dedup();
        assert_eq!(
            read,
            vec!["FERRUM_SETTINGS_PATH"],
            "vpn.rs now reads a different set of environment variables: {read:?}. It may read \
             the catalog (through catalog::read_json_from_env) and the settings document, and \
             nothing else -- the moment it learns where the secrets directory is, the sentence \
             the VPN panel prints to the operator stops being true"
        );
        assert!(
            source.contains("read_json_from_env(\"FERRUM_CATALOG\")"),
            "the catalog read must still go through catalog.rs, which is where the \
             environment-named-document error vocabulary lives"
        );
    }
}
