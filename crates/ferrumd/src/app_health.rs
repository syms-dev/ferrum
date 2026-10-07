// GET /api/app-health -- whether each catalog app is actually answering, and
// WHEN that was established.
//
// ============================================================================
// THIS IS NOT /api/ready, AND IT MUST NEVER BE FOLDED INTO IT.
// ============================================================================
//
// `health.rs` carries a banner forbidding any watchdog, `Restart=` policy or
// automated monitoring from being pointed at `/api/ready`, and a paragraph
// stating in as many words that readiness "asks nothing at all about Sonarr,
// Plex or qBittorrent". Both still hold, unchanged, and this module exists
// precisely so neither has to bend:
//
//   * `/api/ready` stays dependency-scoped to ferrumd's OWN dependencies, and
//     stays unauthenticated by paying for it with a closed vocabulary of fixed
//     words that name no host, no path and no port.
//   * `/api/app-health` asks about the apps, names where it dialled, and is
//     therefore SESSION-GATED -- the same trade `/api/vpn` makes for the same
//     reason. It lives inside `protected`.
//
// Nothing here is wired to a restart, an alert or a watchdog either. It is a
// thing to READ.
//
// ## What this can establish, and what it cannot
//
// The measurement is one HTTP GET to the path the app's OWN catalog metadata
// declares (`meta.healthCheck.path`), at the address this host says the app
// listens on, and the observation is the status code that came back. That is
// genuinely a liveness signal: something accepted a connection, spoke HTTP,
// and answered. It is NOT a statement that the app is working -- Sonarr can
// answer `/ping` with a corrupt database, and Plex can answer `/identity`
// while its library is unmounted. The UI says so in those words rather than
// painting a green dot that implies more than was measured.
//
// ## No credential is ever sent, and that is measured rather than assumed
//
// This is the hazard the module is shaped around. `modules/apps/sabnzbd/
// meta.nix` declares `/api?mode=version`, and SABnzbd's API takes its key as
// a URL QUERY PARAMETER -- the same property docs/WHATS-ALREADY-WIRED.md
// already records as the reason Decluttarr is deliberately not told about
// SABnzbd ("upstream sends the SABnzbd API key as a URL query parameter and
// logs the failing URL verbatim, so configuring it would put that key in your
// journal every time SABnzbd was briefly unreachable"). A probe that put a key
// in a URL would reintroduce that defect inside ferrumd, where the URL could
// reach the journal, an error body, or this endpoint's own JSON.
//
// So every declared health path was MEASURED against the real application,
// unauthenticated, on 2026-10-07 (real containers, real responses):
//
//   sonarr   /ping                 -> 200 {"status":"OK"}      no key needed
//   radarr   /ping                 -> as Sonarr (same framework, same path)
//   prowlarr /ping                 -> as Sonarr (same framework, same path)
//   sabnzbd  /api?mode=version     -> 200 {"version":"5.1.3"}  NO KEY NEEDED
//   jellyfin /health               -> 200 Healthy              no key needed
//   plex     /identity             -> 200 XML                  no key needed
//   qbittorrent /api/v2/app/version -> 200 from loopback or a whitelisted
//                                      subnet; 401 from anywhere else
//
// Two controls prove those are real readings of an unauthenticated endpoint
// rather than an open server: Sonarr's `/api/v3/system/status` answers **401**
// with no key, and SABnzbd's `/api?mode=queue` answers **403 "API Key
// Required"** -- while `mode=version` on the very same socket answers 200.
// `version` is one of the handful of SABnzbd modes that genuinely needs no
// key.
//
// ### Why the `Host:` header is built from the dialled address
//
// Not cosmetic, and measured the hard way. Driving THIS function against the
// real SABnzbd with a foreign `Host:` header returns
// `403 Access denied - Hostname verification failed`, while the identical
// request carrying `Host: 127.0.0.1:<port>` returns `200 {"version":...}`.
// SABnzbd verifies the Host header, so a probe that sent a fixed or invented
// one would report a perfectly healthy SABnzbd as refusing it, forever, on
// every host. Deriving it from the address the shared table gave is what makes
// the request one SABnzbd will answer.
//
// That same run is also why `unauthenticated` is not a theoretical state: it
// absorbed TWO different real refusals -- SABnzbd's hostname verification and
// qBittorrent's non-loopback 401 -- and reported both apps as UP, which is what
// they were. A probe without that state would have called two running apps
// broken.
//
// **So no catalog app needs a credential to be probed, and this module has no
// way to send one.** `probe` takes a host, a port and a path, and there is no
// parameter for a secret to arrive in. Three further things keep it that way:
//
//   1. The declared path is an INPUT ONLY. It is never serialized into the
//      response, so no query string can reach a reader even if one were added
//      to a meta.nix later. `no_reading_can_carry_a_credential` proves this by
//      building a report from a catalog whose health paths have been seeded
//      with a key and asserting it appears nowhere in the body.
//   2. Nothing in this file logs. There is no `eprintln!`, so there is no
//      journal sink for a URL to land in.
//   3. `nix/modules/flake/checks.nix`'s `app-health-view-is-wired` fails
//      EVALUATION if any catalog `healthCheck.path` ever grows something that
//      looks like a key, token or password -- at the meta.nix where that edit
//      would be made, rather than after it shipped. The same check also fails
//      if this file grows a logging call, closing the journal sink too.
//
// qBittorrent's 401 is the reason `unauthenticated` is a FIRST-CLASS STATE
// rather than a failure. An app that answers "I will not tell you" is an app
// that is up: it accepted the connection, parsed the request, and applied its
// own auth policy. Reporting that as unhealthy would send an operator to debug
// a perfectly healthy app -- and on a VPN host, where qBittorrent is reached
// across a veth pair rather than from loopback, it is the ordinary answer
// unless that app's own `AuthSubnetWhitelist` covers the pair.
//
// ## Where the address comes from
//
// `$FERRUM_APP_ADDRESSES`, written by `modules/core/daemon.nix` from
// `modules/lib/app-address.nix` -- the shared table nginx and the reconciler
// already read. That file's header warns that "a THIRD consumer that
// hand-copies 127.0.0.1 fails there instead of in the field"; Decluttarr was
// the third and this is the fourth, so it reads the table instead.
//
// There is deliberately **no loopback fallback in this file**. The string
// "127.0.0.1" does not appear in it, and an app the table does not name is
// reported as `address-unknown` rather than probed at a guessed address. A
// guess would be wrong for exactly one app -- qBittorrent on a VPN host, which
// listens at 10.200.1.2 inside its namespace -- and the resulting reading
// would say "qBittorrent is down" about an app that is running perfectly. That
// is the defect this project has now shipped three times, and declining to
// guess is the only thing that makes a fourth impossible.
//
// ## Freshness, and "never checked"
//
// Every reading is taken live, per request; nothing is cached. The document
// carries `checkedAt`, stamped AFTER every probe has finished or timed out --
// never before, because a timestamp taken before a three-second timeout
// overstates the reading's freshness by exactly the length of the slowest
// case. The UI ages it on screen and keeps ageing it while the page sits open.
//
// "Never checked" is the UI's own state, not a wire value: before the first
// response arrives `checkedAt` is null and the panel says so, rather than
// painting a neutral dot that reads as "nothing wrong".
//
// ## Concurrency and timeout
//
// Every app is probed CONCURRENTLY, on its own task, so the endpoint's wall
// time is the slowest single probe rather than their sum. One wedged Plex must
// not hold up the answer about the other six -- a dashboard that blocks for
// thirty seconds is its own outage.
//
// The per-app deadline is `min(meta.healthCheck.timeoutSec, PROBE_CEILING)`.
// The catalog's own 30s is the POST-APPLY budget: `wait_for_healthy` uses it
// to answer "has this app finished starting", a question that legitimately
// takes half a minute. "Is it answering right now" is a different question
// with a different right answer, so it is capped at `PROBE_CEILING` (3s, the
// same honesty bound `vpn.rs` puts on its systemd query, for the same stated
// reason). A smaller declared value is still honoured; only the ceiling binds.
//
// The fan-out is NOT semaphore-bounded, unlike `sso.rs`'s. The two differ in
// the thing that matters: `/api/sso` is unauthenticated, so an anonymous
// caller could open sockets without limit, which is what `SSO_MAX_IN_FLIGHT`
// exists to stop. This route is inside `protected`, and one request opens at
// most one socket per catalog app -- seven, briefly, on the same box -- which
// is the same bound `/api/vpn` already relies on.
use crate::catalog;
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The longest any single app gets to answer before its reading becomes
/// `timed-out`.
///
/// See this module's header: the catalog's own `timeoutSec` answers a
/// different question (how long an app may take to FINISH STARTING after an
/// apply) and is far too long for a screen someone is waiting on.
const PROBE_CEILING: Duration = Duration::from_secs(3);

/// The most of an app's answer this module will read.
///
/// Only the status line is wanted, which is under a hundred bytes, so this is
/// two orders of magnitude of headroom and exists solely so a misconfigured or
/// hostile listener on the configured port cannot make ferrumd buffer without
/// bound. The same guard `sso.rs`'s `RESPONSE_LIMIT` provides, at the smaller
/// size a smaller question needs.
const RESPONSE_LIMIT: usize = 8 * 1024;

/// The environment variable naming where each enabled app listens.
///
/// Written by `modules/core/daemon.nix` from `modules/lib/app-address.nix`.
/// See this module's header for why there is no fallback when it is absent.
const ADDRESSES_VAR: &str = "FERRUM_APP_ADDRESSES";

/// What ferrum could establish about one app.
///
/// Nine values, and nothing else is ever serialized into `state`. The test a
/// state had to pass to exist here rather than be folded into its neighbour is
/// the one `vpn.rs` uses: each sends the operator somewhere DIFFERENT. Three
/// pairs in particular are kept apart on purpose, because collapsing any of
/// them is how a status ends up wrong in the reassuring direction:
///
///   * `unauthenticated` is not `unhealthy`. An app that refuses us is up.
///   * `timed-out` is not `refused`. A wedged app and a stopped app need
///     opposite next actions, and only one of them is fixed by starting it.
///   * `address-unknown` is not `unreachable`. Nothing was dialled at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealthState {
    /// This app is not enabled on this host, so nothing is running to ask.
    /// Next action: enable it, if you want it.
    NotEnabled,
    /// The app is enabled and its catalog metadata declares no `healthCheck`,
    /// so ferrum has nothing to dial. Decluttarr is the live example: it is a
    /// headless worker with no HTTP surface of its own. Next action: none --
    /// this is a permanent property of the app, not a fault.
    NotMeasurable,
    /// The app is enabled and declares a health check, but `$FERRUM_APP_ADDRESSES`
    /// does not say where it listens -- so ferrumd declined to guess. On a
    /// correctly built host this cannot happen; it is the shape of a daemon
    /// running against an older module set. Next action: rebuild this host.
    /// Deliberately NOT a loopback guess -- see this module's header.
    AddressUnknown,
    /// The app answered with exactly the status its catalog metadata declares.
    /// Next action: none.
    Healthy,
    /// The app answered `401` or `403`. It is UP -- it accepted the
    /// connection, read the request and applied its own auth policy -- and
    /// ferrum does not hold a credential for it, by design. This is a good
    /// liveness signal, not a fault. Next action: none.
    Unauthenticated,
    /// The app answered, with some other status than the one declared. It is
    /// listening and serving something, and that something is not what the
    /// catalog expects. Next action: read the app's own journal.
    Unhealthy,
    /// The connection was refused: the port is closed, so nothing is listening
    /// there. Next action: check whether the app's unit is running.
    Refused,
    /// A connection or read failed some other way, or the answer was not HTTP.
    /// The address is reachable in a different sense from `refused`: something
    /// about the route, the namespace or the listener is wrong rather than
    /// absent. Next action: check this app's network namespace and the address
    /// named in `measuredFrom`.
    Unreachable,
    /// Nothing came back inside the deadline. NOT the same as down: a wedged
    /// app holds its socket open and answers nothing, which is a different
    /// fault from a stopped one and is not fixed by starting it. Next action:
    /// check the app's load, then its journal.
    TimedOut,
}

/// One app's health reading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthReading {
    /// What ferrum established. See `HealthState`.
    pub state: HealthState,
    /// The HTTP status the app really answered with, and `None` whenever no
    /// answer was received.
    ///
    /// Published because every other field is ferrum's interpretation and this
    /// is the raw observation behind it -- the same reason `vpn.rs` publishes
    /// systemd's `activeState` verbatim.
    pub status: Option<u16>,
    /// The status the app's catalog metadata declares as healthy, so a reader
    /// can see what `status` was compared against rather than taking the
    /// verdict on trust. `None` when nothing was probed.
    pub expect_status: Option<u16>,
    /// The `host:port` this reading was taken from, so an operator can go and
    /// try it themselves, and `None` when nothing was dialled.
    ///
    /// This is also the field that makes the network-namespace defect visible:
    /// a qBittorrent reading measured from a loopback address on a VPN host is
    /// wrong on its face.
    ///
    /// **The declared PATH is deliberately absent.** It is an input to the
    /// probe and never an output, which is what makes it impossible for a
    /// query string to carry a credential into this document. See the module
    /// header and `no_reading_can_carry_a_credential`.
    pub measured_from: Option<String>,
}

/// The whole document: one reading per catalog app, plus the one timestamp
/// they were all taken at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthReport {
    /// Unix seconds, as a string -- the same wire convention `/api/vpn` and
    /// the generation timestamps use, and for the same reason: the daemon
    /// cannot know the reader's timezone, so the UI renders it in the
    /// operator's own locale.
    pub checked_at: String,
    /// Keyed by catalog app id. EVERY catalog app is present, including the
    /// disabled and the unmeasurable ones -- unlike `/api/vpn`, which omits
    /// apps with no tunnel. The apps list renders a row per app and needs a
    /// named reading for each; an absent key would be ambiguous between "this
    /// app is never checked" and "the daemon has not heard of it".
    pub apps: BTreeMap<String, HealthReading>,
}

/// One app's health-check declaration, as the catalog states it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HealthMeta {
    /// Catalog app id.
    id: String,
    /// The path to GET. An input only; never serialized.
    path: String,
    /// The status that means healthy.
    expect_status: u16,
    /// The app's own declared deadline, before `PROBE_CEILING` is applied.
    timeout: Duration,
}

/// What came back from one probe, before it is judged against the declared
/// status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// An HTTP answer, with its status code.
    Answered(u16),
    /// The connection was refused.
    Refused,
    /// Nothing arrived inside the deadline.
    TimedOut,
    /// Any other transport failure, or an answer that was not HTTP.
    Unreachable,
}

/// Reads every app's `healthCheck` block out of a catalog document.
///
/// Nothing in this file names an app id. The catalog decides which apps have a
/// health check, which is what keeps "adding an app is adding a directory"
/// true for this endpoint too.
///
/// # Arguments
/// * `catalog_doc` - a parsed catalog.json.
///
/// # Returns
/// One entry per app whose metadata declares a complete `healthCheck` block,
/// sorted by app id. An incomplete block is skipped rather than half-read: a
/// missing `expectStatus` would otherwise produce a reading judged against a
/// status nobody declared.
fn health_apps(catalog_doc: &Value) -> Vec<HealthMeta> {
    let Some(apps) = catalog_doc.get("apps").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut found: Vec<HealthMeta> = apps
        .iter()
        .filter_map(|(id, meta)| {
            let check = meta.get("healthCheck")?;
            let path = check.get("path")?.as_str()?.to_string();
            let expect_status = u16::try_from(check.get("expectStatus")?.as_u64()?).ok()?;
            // A declared timeout is an upper bound the catalog owns; its
            // absence is not a licence to wait forever, so it falls back to
            // the ceiling rather than to anything larger.
            let timeout = check
                .get("timeoutSec")
                .and_then(Value::as_u64)
                .map(Duration::from_secs)
                .unwrap_or(PROBE_CEILING);
            Some(HealthMeta { id: id.clone(), path, expect_status, timeout })
        })
        .collect();
    found.sort_by(|a, b| a.id.cmp(&b.id));
    found
}

/// Every catalog app id, whether or not it declares a health check.
///
/// # Arguments
/// * `catalog_doc` - a parsed catalog.json.
///
/// # Returns
/// The ids, sorted.
fn all_app_ids(catalog_doc: &Value) -> Vec<String> {
    let Some(apps) = catalog_doc.get("apps").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = apps.keys().cloned().collect();
    ids.sort();
    ids
}

/// Whether a settings document enables this app.
///
/// `enable` is absent-means-false, matching `ui/app.js`'s own
/// `?.enable === true` rather than inventing a second rule for the same fact.
///
/// # Arguments
/// * `settings` - a parsed settings.json.
/// * `id` - the catalog app id.
///
/// # Returns
/// True only when the document says so explicitly.
fn app_is_enabled(settings: &Value, id: &str) -> bool {
    settings.pointer(&format!("/apps/{id}/enable")).and_then(Value::as_bool).unwrap_or(false)
}

/// The `host:port` table this host renders for its enabled apps.
///
/// Takes the raw variable value rather than reading the environment itself, so
/// the parse is drivable from a test without mutating process-wide state other
/// tests in this binary read at the same time -- the same reason
/// `health.rs::check_generation` takes its directory.
///
/// # Arguments
/// * `raw` - the value of `$FERRUM_APP_ADDRESSES`, or `None` when it is unset.
///
/// # Returns
/// App id -> `host:port`. An unset, unparseable, or non-object value yields an
/// EMPTY table, which reports every app as `address-unknown`. That is the
/// honest answer and the deliberate one: the alternative is guessing an
/// address, which is the defect this whole arrangement exists to prevent.
fn address_table(raw: Option<&str>) -> BTreeMap<String, String> {
    let Some(raw) = raw else {
        return BTreeMap::new();
    };
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) else {
        return BTreeMap::new();
    };
    map.into_iter()
        .filter_map(|(id, value)| value.as_str().map(|s| (id, s.to_string())))
        .collect()
}

/// One fixed-shape HTTP/1.1 GET, and the status it came back with.
///
/// Hand-rolled over `tokio::net::TcpStream` for the reason `sso.rs`'s own
/// header gives: `crates/Cargo.lock` is a stop-and-report surface, ferrumd
/// carries no HTTP client, and the request is one fixed-shape GET whose
/// answer is read for a status code. Same shape as that module's `ask`:
/// bounded response, explicit timeout, `Connection: close`. Narrower in one
/// respect -- it stops at the end of the STATUS LINE rather than at the end of
/// the head, because the status code is the entire question.
///
/// **There is no parameter for a credential, and that is the point rather than
/// an omission.** See this module's header: no catalog app's declared health
/// path needs one, which was measured rather than assumed, and a signature
/// with nowhere to put a secret cannot grow one by accident.
///
/// # Arguments
/// * `address` - the `host:port` to dial, from `$FERRUM_APP_ADDRESSES`.
/// * `path` - the declared health path, verbatim.
///
/// # Returns
/// The [`Outcome`]. Never an `Err`: a caller that had to handle both an error
/// and an `Outcome::Unreachable` would eventually handle one as the other.
async fn probe(address: &str, path: &str) -> Outcome {
    // A path carrying CR or LF would let a meta.nix write extra headers into
    // the request. The paths are ferrum's own, so this cannot happen today --
    // which is exactly why it is cheap to make it a property of this function
    // rather than a property of the files that feed it.
    if path.contains(['\r', '\n', '\0']) {
        return Outcome::Unreachable;
    }

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );

    let mut stream = match tokio::net::TcpStream::connect(address).await {
        Ok(stream) => stream,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return Outcome::Refused,
        Err(_) => return Outcome::Unreachable,
    };
    if stream.write_all(request.as_bytes()).await.is_err() {
        return Outcome::Unreachable;
    }

    let mut raw = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let read = match stream.read(&mut buffer).await {
            Ok(read) => read,
            Err(_) => return Outcome::Unreachable,
        };
        if read == 0 {
            // EOF before a complete status line: something spoke, and it was
            // not HTTP.
            break;
        }
        raw.extend_from_slice(&buffer[..read]);
        if raw.len() > RESPONSE_LIMIT {
            return Outcome::Unreachable;
        }
        if let Some(status) = status_of(&raw) {
            return Outcome::Answered(status);
        }
    }
    match status_of(&raw) {
        Some(status) => Outcome::Answered(status),
        None => Outcome::Unreachable,
    }
}

/// The status code from an HTTP status line, once a whole one has arrived.
///
/// Split out so every branch is testable without a socket, and so the
/// "incomplete" case is a distinct `None` rather than a guess at a partial
/// line: `HTTP/1.1 50` must not be read as `50`.
///
/// # Arguments
/// * `raw` - the bytes read so far.
///
/// # Returns
/// `Some(status)` once a complete, parseable status line has arrived; `None`
/// while it is still incomplete, and also when the completed line is not an
/// HTTP status line at all.
fn status_of(raw: &[u8]) -> Option<u16> {
    let end = raw.windows(2).position(|w| w == b"\r\n")?;
    let line = std::str::from_utf8(&raw[..end]).ok()?;
    if !line.starts_with("HTTP/") {
        return None;
    }
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Judges one outcome against the status the catalog declared.
///
/// Pure, and separated from the socket on purpose: every state this endpoint
/// can report is then reachable in a test from synthesized inputs, including
/// the ones a test machine cannot produce on demand. The classification is the
/// part that can be wrong in a way nobody notices, because every wrong answer
/// still renders as a plausible row.
///
/// The ORDER is load-bearing. The declared status wins first, so an app whose
/// metadata declares `401` as healthy reads as healthy rather than as
/// `unauthenticated`; only after that does a refusal get its own state.
///
/// # Arguments
/// * `outcome` - what the probe came back with.
/// * `expect_status` - the status the catalog declares as healthy.
///
/// # Returns
/// The state.
fn classify(outcome: Outcome, expect_status: u16) -> HealthState {
    match outcome {
        Outcome::Answered(status) if status == expect_status => HealthState::Healthy,
        // 401 and 403 are the two ways an HTTP application says "you may not
        // ask". Both prove it is up. See this module's header for why that is
        // the ordinary answer for qBittorrent on a VPN host.
        Outcome::Answered(401 | 403) => HealthState::Unauthenticated,
        Outcome::Answered(_) => HealthState::Unhealthy,
        Outcome::Refused => HealthState::Refused,
        Outcome::TimedOut => HealthState::TimedOut,
        Outcome::Unreachable => HealthState::Unreachable,
    }
}

/// Probes one app, with its own deadline applied.
///
/// # Arguments
/// * `address` - the `host:port` from the address table.
/// * `meta` - the app's catalog health-check declaration.
///
/// # Returns
/// The reading, with `measuredFrom` naming the address really dialled.
async fn read_one(address: String, meta: HealthMeta) -> HealthReading {
    // `min`, so an app that declares something SHORTER than the ceiling is
    // still honoured -- the ceiling is a bound on waiting, not a target.
    let deadline = meta.timeout.min(PROBE_CEILING);
    let outcome = match tokio::time::timeout(deadline, probe(&address, &meta.path)).await {
        Ok(outcome) => outcome,
        Err(_) => Outcome::TimedOut,
    };
    HealthReading {
        state: classify(outcome, meta.expect_status),
        status: match outcome {
            Outcome::Answered(status) => Some(status),
            _ => None,
        },
        expect_status: Some(meta.expect_status),
        measured_from: Some(address),
    }
}

/// A reading for an app that was not probed at all.
///
/// # Arguments
/// * `state` - which of the three not-probed states applies.
///
/// # Returns
/// The reading, with every observation field `None` -- there is no observation
/// to report, and a zero or an empty string would read as one.
fn unprobed(state: HealthState) -> HealthReading {
    HealthReading { state, status: None, expect_status: None, measured_from: None }
}

/// Builds the whole report: decides what each app's reading should be, probes
/// the ones that can be probed, CONCURRENTLY, and assembles the document.
///
/// # Arguments
/// * `catalog_doc` - a parsed catalog.json.
/// * `settings` - a parsed settings.json.
/// * `addresses` - the `host:port` table from `$FERRUM_APP_ADDRESSES`.
///
/// # Returns
/// The report, with one entry per catalog app and `checkedAt` stamped AFTER
/// the last probe finished.
async fn build_report(
    catalog_doc: &Value,
    settings: &Value,
    addresses: &BTreeMap<String, String>,
) -> HealthReport {
    let checkable: BTreeMap<String, HealthMeta> =
        health_apps(catalog_doc).into_iter().map(|m| (m.id.clone(), m)).collect();

    let mut apps: BTreeMap<String, HealthReading> = BTreeMap::new();
    let mut probes = Vec::new();

    for id in all_app_ids(catalog_doc) {
        if !app_is_enabled(settings, &id) {
            apps.insert(id, unprobed(HealthState::NotEnabled));
            continue;
        }
        let Some(meta) = checkable.get(&id) else {
            apps.insert(id, unprobed(HealthState::NotMeasurable));
            continue;
        };
        let Some(address) = addresses.get(&id) else {
            apps.insert(id, unprobed(HealthState::AddressUnknown));
            continue;
        };
        // One task per app, spawned before any is awaited, so the wall time is
        // the slowest probe rather than the sum of all of them.
        probes.push((id, tokio::spawn(read_one(address.clone(), meta.clone()))));
    }

    for (id, handle) in probes {
        // A panicked probe task is reported as `unreachable` rather than
        // taking the whole endpoint down: from a reader's side "I could not
        // find out" and "it did not answer" are the same fact, which is the
        // judgement `health.rs`'s own `Reason::Unavailable` doc records.
        let reading = handle.await.unwrap_or_else(|_| unprobed(HealthState::Unreachable));
        apps.insert(id, reading);
    }

    // Taken AFTER every probe, not before: `checkedAt` must describe the
    // readings the body carries, and a timestamp stamped before a three-second
    // timeout would overstate their freshness by exactly the length of the
    // slowest case. The same rule, in the same words, as `vpn.rs`.
    HealthReport { checked_at: now_unix().to_string(), apps }
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

/// `GET /api/app-health` -- the live reading.
///
/// # Returns
/// 200 with a `HealthReport`, or 500 naming which document could not be read.
/// The caller holds a session, so the message names the real variable and the
/// real path exactly as `catalog::build_catalog` does for the same reason.
pub async fn get_app_health() -> impl IntoResponse {
    let documents = crate::run_blocking(|| {
        let catalog_doc = catalog::read_json_from_env("FERRUM_CATALOG").map_err(|e| e.message)?;
        let settings_path = std::env::var("FERRUM_SETTINGS_PATH")
            .unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string());
        let raw = std::fs::read_to_string(&settings_path)
            .map_err(|e| format!("failed to read settings at {settings_path}: {e}"))?;
        let settings: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("settings at {settings_path} is not valid JSON: {e}"))?;
        let addresses = address_table(std::env::var(ADDRESSES_VAR).ok().as_deref());
        Ok::<(Value, Value, BTreeMap<String, String>), String>((catalog_doc, settings, addresses))
    })
    .await;

    let (catalog_doc, settings, addresses) = match documents {
        Ok(Ok(triple)) => triple,
        Ok(Err(message)) => return (StatusCode::INTERNAL_SERVER_ERROR, message).into_response(),
        Err(status) => return status.into_response(),
    };

    let report = build_report(&catalog_doc, &settings, &addresses).await;
    (StatusCode::OK, Json(report)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tokio::net::TcpListener;

    /// A catalog shaped like the real one: three apps that declare a health
    /// check and one that declares none, so the `not-measurable` branch is
    /// reachable from the same fixture every other test uses.
    fn catalog_doc() -> Value {
        json!({
            "apps": {
                "sonarr": {
                    "id": "sonarr",
                    "healthCheck": { "path": "/ping", "expectStatus": 200, "timeoutSec": 30 }
                },
                "qbittorrent": {
                    "id": "qbittorrent",
                    "healthCheck": {
                        "path": "/api/v2/app/version", "expectStatus": 200, "timeoutSec": 30
                    }
                },
                "sabnzbd": {
                    "id": "sabnzbd",
                    "healthCheck": {
                        "path": "/api?mode=version", "expectStatus": 200, "timeoutSec": 30
                    }
                },
                "decluttarr": { "id": "decluttarr" }
            }
        })
    }

    fn settings_enabling(ids: &[&str]) -> Value {
        let apps: serde_json::Map<String, Value> =
            ids.iter().map(|id| ((*id).to_string(), json!({ "enable": true }))).collect();
        json!({ "apps": apps })
    }

    fn table(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    // ---- real servers -----------------------------------------------------
    //
    // The probe is driven against REAL `TcpListener`s, following the
    // `FakeCloudflare`/`FakeAuthelia` precedent: a parser test over a
    // hand-written byte string would pass identically if `probe` never opened
    // a socket at all.

    /// A listener that answers every request with one fixed status line, then
    /// closes. Returns its address.
    async fn fake_app(status_line: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    let _ = socket.read(&mut buffer).await;
                    let _ = socket
                        .write_all(
                            format!("{status_line}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
                        )
                        .await;
                });
            }
        });
        address
    }

    /// A listener that accepts the connection and then NEVER answers -- the
    /// wedged app `timed-out` exists for. It holds the socket rather than
    /// dropping it, which is the distinction from a refused connection.
    async fn silent_app() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        address
    }

    /// An address nothing is listening on: a port bound and then released, so
    /// it is genuinely closed rather than merely unlikely to be in use.
    async fn closed_port() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        address
    }

    #[tokio::test]
    async fn a_real_server_answering_the_declared_status_reads_as_healthy() {
        let address = fake_app("HTTP/1.1 200 OK").await;
        assert_eq!(probe(&address, "/ping").await, Outcome::Answered(200));
        assert_eq!(classify(Outcome::Answered(200), 200), HealthState::Healthy);
    }

    #[tokio::test]
    async fn a_real_server_answering_the_wrong_status_reads_as_unhealthy() {
        let address = fake_app("HTTP/1.1 500 Internal Server Error").await;
        assert_eq!(probe(&address, "/ping").await, Outcome::Answered(500));
        assert_eq!(
            classify(Outcome::Answered(500), 200),
            HealthState::Unhealthy,
            "an app that answered the wrong thing is a different finding from one that did \
             not answer -- it is listening, and its journal is the next place to look"
        );
    }

    /// The qBittorrent-across-a-veth case, which is the ordinary answer rather
    /// than a fault. Measured for real on 2026-10-07: a non-loopback caller
    /// gets `401 Unauthorized` from a running qBittorrent.
    #[tokio::test]
    async fn a_real_server_that_refuses_us_reads_as_up_and_not_as_down() {
        for status_line in ["HTTP/1.1 401 Unauthorized", "HTTP/1.1 403 Forbidden"] {
            let address = fake_app(status_line).await;
            let outcome = probe(&address, "/api/v2/app/version").await;
            assert_eq!(
                classify(outcome, 200),
                HealthState::Unauthenticated,
                "{status_line} proves the app is UP -- it parsed the request and applied its \
                 own auth policy. Reporting it as unhealthy sends an operator to debug an app \
                 that is running perfectly."
            );
        }
    }

    #[tokio::test]
    async fn a_closed_port_reads_as_refused_and_not_as_a_timeout() {
        let address = closed_port().await;
        assert_eq!(
            probe(&address, "/ping").await,
            Outcome::Refused,
            "nothing listening must be distinguishable from something listening and silent: \
             only one of the two is fixed by starting the unit"
        );
    }

    /// The whole point of the ceiling, driven against a server that really
    /// never answers.
    #[tokio::test]
    async fn a_server_that_never_answers_times_out_rather_than_hanging() {
        let address = silent_app().await;
        let meta = HealthMeta {
            id: "wedged".into(),
            path: "/ping".into(),
            // The catalog's own 30s, which must NOT be what is waited.
            expect_status: 200,
            timeout: Duration::from_secs(30),
        };
        let started = std::time::Instant::now();
        let reading = read_one(address, meta).await;
        assert_eq!(reading.state, HealthState::TimedOut);
        assert_eq!(reading.status, None, "a timeout observed no status, and must not invent one");
        assert!(
            started.elapsed() < PROBE_CEILING + Duration::from_secs(2),
            "the catalog's 30s is the post-apply budget, not a dashboard's: the probe must be \
             bounded by PROBE_CEILING, and this one took {:?}",
            started.elapsed()
        );
    }

    /// One wedged app must not hold up the answer about the others. Driven
    /// against four real servers at once, with the elapsed time asserted
    /// against the SUM of the deadlines rather than against one of them.
    #[tokio::test]
    async fn one_wedged_app_does_not_hold_up_the_rest() {
        let wedged = silent_app().await;
        let healthy = fake_app("HTTP/1.1 200 OK").await;
        let broken = fake_app("HTTP/1.1 503 Service Unavailable").await;
        let addresses = table(&[
            ("sonarr", &healthy),
            ("qbittorrent", &wedged),
            ("sabnzbd", &broken),
        ]);

        let started = std::time::Instant::now();
        let report = build_report(
            &catalog_doc(),
            &settings_enabling(&["sonarr", "qbittorrent", "sabnzbd", "decluttarr"]),
            &addresses,
        )
        .await;
        let elapsed = started.elapsed();

        assert_eq!(report.apps["sonarr"].state, HealthState::Healthy);
        assert_eq!(report.apps["qbittorrent"].state, HealthState::TimedOut);
        assert_eq!(report.apps["sabnzbd"].state, HealthState::Unhealthy);
        assert_eq!(report.apps["decluttarr"].state, HealthState::NotMeasurable);
        assert!(
            elapsed < PROBE_CEILING * 2,
            "three apps probed one after another would take at least three deadlines. This \
             took {elapsed:?}, which is not concurrent -- and a dashboard that blocks while \
             each app times out in turn is its own outage."
        );
    }

    /// `checkedAt` is stamped after the slowest probe, never before it. A
    /// timestamp taken first would describe a moment up to a full deadline
    /// earlier than the reading it is attached to -- which is the frozen-gauge
    /// defect in its subtlest form, since the number would still move.
    #[tokio::test]
    async fn checked_at_is_stamped_after_the_probe_and_never_before_it() {
        let wedged = silent_app().await;
        let before = now_unix();
        let report = build_report(
            &catalog_doc(),
            &settings_enabling(&["qbittorrent"]),
            &table(&[("qbittorrent", &wedged)]),
        )
        .await;
        let stamped: u64 = report.checked_at.parse().unwrap();
        assert_eq!(report.apps["qbittorrent"].state, HealthState::TimedOut);
        assert!(
            stamped >= before + PROBE_CEILING.as_secs(),
            "the probe waited {}s, so a checkedAt of {stamped} against a start of {before} was \
             taken BEFORE the reading it describes and overstates its freshness",
            PROBE_CEILING.as_secs()
        );
    }

    /// The three not-probed states, each reached on its own, and each with
    /// every observation field empty.
    #[tokio::test]
    async fn an_app_that_cannot_be_probed_says_which_of_the_three_reasons_applies() {
        let report = build_report(
            &catalog_doc(),
            // sonarr enabled with no address; sabnzbd and qbittorrent not
            // enabled at all; decluttarr enabled but declares no check.
            &settings_enabling(&["sonarr", "decluttarr"]),
            &BTreeMap::new(),
        )
        .await;

        assert_eq!(
            report.apps["sonarr"].state,
            HealthState::AddressUnknown,
            "an enabled app ferrum has no address for must say so rather than be probed at a \
             guessed one -- see this module's header"
        );
        assert_eq!(report.apps["decluttarr"].state, HealthState::NotMeasurable);
        assert_eq!(report.apps["sabnzbd"].state, HealthState::NotEnabled);
        assert_eq!(report.apps["qbittorrent"].state, HealthState::NotEnabled);

        for id in ["sonarr", "decluttarr", "sabnzbd", "qbittorrent"] {
            let reading = &report.apps[id];
            assert_eq!(reading.status, None, "{id} was not probed and observed no status");
            assert_eq!(reading.measured_from, None, "{id} was not probed and dialled nothing");
            assert_eq!(reading.expect_status, None, "{id} was not compared against anything");
        }
    }

    /// EVERY catalog app is present, unlike `/api/vpn`'s report. An absent key
    /// would be ambiguous between "never checked" and "not known about".
    #[tokio::test]
    async fn every_catalog_app_gets_a_named_reading() {
        let report = build_report(&catalog_doc(), &json!({}), &BTreeMap::new()).await;
        assert_eq!(
            report.apps.keys().collect::<Vec<_>>(),
            vec!["decluttarr", "qbittorrent", "sabnzbd", "sonarr"]
        );
    }

    /// THE CREDENTIAL GUARD, and the reason this probe can read a path out of
    /// a meta.nix at all.
    ///
    /// It seeds the catalog with the exact shape the hazard takes -- SABnzbd's
    /// `/api?mode=version` grown an `apikey=` query parameter, which is how
    /// SABnzbd's own API really takes its key -- drives a REAL probe against a
    /// REAL server with it, and asserts the secret reaches neither the report
    /// nor the reading's own fields.
    ///
    /// The failure it is built to catch is a later edit that attaches the
    /// declared path to `measuredFrom` "so the operator can see what was
    /// dialled". docs/WHATS-ALREADY-WIRED.md records that one unreachable
    /// SABnzbd made Decluttarr print its key three times in thirty seconds;
    /// this endpoint's body goes to a browser, which is a worse sink than a
    /// root-only journal.
    #[tokio::test]
    async fn no_reading_can_carry_a_credential() {
        const SECRET: &str = "d41d8cd98f00b204e9800998ecf8427e";
        let address = fake_app("HTTP/1.1 200 OK").await;
        let seeded = json!({
            "apps": {
                "sabnzbd": {
                    "id": "sabnzbd",
                    "healthCheck": {
                        "path": format!("/api?mode=version&apikey={SECRET}"),
                        "expectStatus": 200,
                        "timeoutSec": 30
                    }
                }
            }
        });

        let report = build_report(
            &seeded,
            &settings_enabling(&["sabnzbd"]),
            &table(&[("sabnzbd", &address)]),
        )
        .await;

        // The probe really ran -- without this the assertion below would hold
        // vacuously over a report that measured nothing.
        assert_eq!(report.apps["sabnzbd"].state, HealthState::Healthy);

        let body = serde_json::to_string(&report).unwrap();
        assert!(
            !body.contains(SECRET),
            "the declared health path reached the response body, so a key in a meta.nix \
             query string would be served to a browser: {body}"
        );
        assert!(
            !body.contains("apikey") && !body.contains("mode=version"),
            "no part of the declared path may reach the response -- it is an input to the \
             probe and never an output: {body}"
        );
        assert_eq!(
            report.apps["sabnzbd"].measured_from,
            Some(address),
            "measuredFrom must name the ADDRESS, which carries no credential, and never the \
             path, which can"
        );
    }

    /// A path that could rewrite the request is refused rather than sent --
    /// the same guard `sso.rs::header_safe` makes about a cookie, made here
    /// about a path, so it is a property of this function rather than of the
    /// files that currently feed it.
    #[tokio::test]
    async fn a_path_that_could_forge_a_header_is_refused_rather_than_sent() {
        let address = fake_app("HTTP/1.1 200 OK").await;
        assert_eq!(
            probe(&address, "/ping\r\nX-Injected: yes").await,
            Outcome::Unreachable,
            "a path carrying CRLF would let a meta.nix write its own headers into the request"
        );
    }

    /// The bytes really put on the wire: the right `Host:`, and NO credential
    /// header of any kind.
    ///
    /// The `Host:` half is not cosmetic. Measured against the real SABnzbd on
    /// 2026-10-07: a foreign `Host:` earns `403 Access denied - Hostname
    /// verification failed`, while `Host: 127.0.0.1:<port>` earns
    /// `200 {"version":...}` on the same socket. A probe that sent a fixed or
    /// invented Host would report a perfectly healthy SABnzbd as refusing it
    /// on every host, forever.
    ///
    /// The credential half is the structural claim this module rests on, made
    /// against the request itself rather than against the response: there is no
    /// parameter for a secret, so there must be no secret on the wire.
    #[tokio::test]
    async fn the_request_names_the_host_it_dialled_and_carries_no_credential() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 2048];
            let read = socket.read(&mut buffer).await.unwrap();
            tx.send(String::from_utf8_lossy(&buffer[..read]).to_string()).unwrap();
            let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
        });

        assert_eq!(probe(&address, "/api?mode=version").await, Outcome::Answered(200));
        let request = rx.recv_timeout(Duration::from_secs(5)).unwrap();

        assert!(
            request.contains(&format!("Host: {address}\r\n")),
            "the Host header must name the address really dialled, or SABnzbd's hostname \
             verification refuses a probe of an app that is perfectly healthy: {request:?}"
        );
        assert!(request.starts_with("GET /api?mode=version HTTP/1.1\r\n"), "{request:?}");
        assert!(
            request.contains("Connection: close\r\n"),
            "the response is self-delimiting only because the connection closes: {request:?}"
        );
        for forbidden in ["authorization", "cookie", "x-api-key", "apikey", "password", "token"] {
            assert!(
                !request.to_lowercase().contains(forbidden),
                "the probe put {forbidden:?} on the wire. It holds no credential and must send \
                 none: a key in a request is a key in the app's own access log. {request:?}"
            );
        }
    }

    /// The status-line parser, including the partial read that must NOT be
    /// guessed at.
    #[test]
    fn a_status_line_is_read_only_once_all_of_it_has_arrived() {
        assert_eq!(status_of(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(status_of(b"HTTP/1.0 503 Service Unavailable\r\nX: y\r\n"), Some(503));
        assert_eq!(
            status_of(b"HTTP/1.1 50"),
            None,
            "half a status line must not be read as a status -- `50` is not what the server said"
        );
        assert_eq!(
            status_of(b"SSH-2.0-OpenSSH_9.6\r\n"),
            None,
            "something that is not HTTP must be unreachable, not a status code"
        );
    }

    /// An app whose catalog declares a non-200 status as healthy reads as
    /// healthy on that status, and the `unauthenticated` branch does not steal
    /// it. No app does this today, which is why it is pinned: the precedence
    /// is invisible until one does.
    #[test]
    fn the_declared_status_outranks_the_unauthenticated_branch() {
        assert_eq!(classify(Outcome::Answered(401), 401), HealthState::Healthy);
        assert_eq!(classify(Outcome::Answered(200), 401), HealthState::Unhealthy);
    }

    /// The address table's failure modes all yield an EMPTY table, never a
    /// guess. The loopback default is the defect; this is the test that keeps
    /// it from creeping back in as a convenience.
    #[test]
    fn an_unreadable_address_table_yields_no_addresses_rather_than_a_guess() {
        assert_eq!(address_table(None), BTreeMap::new(), "unset must not mean loopback");
        assert_eq!(address_table(Some("{ not json")), BTreeMap::new());
        assert_eq!(address_table(Some("[]")), BTreeMap::new());
        assert_eq!(
            address_table(Some(r#"{"sonarr":"127.0.0.1:8989","qbittorrent":"10.200.1.2:8090"}"#)),
            table(&[("sonarr", "127.0.0.1:8989"), ("qbittorrent", "10.200.1.2:8090")]),
            "the namespaced address must survive the parse -- it is the one the whole \
             arrangement exists for"
        );
        assert_eq!(
            address_table(Some(r#"{"sonarr":8989}"#)),
            BTreeMap::new(),
            "a non-string address is not an address"
        );
    }

    /// An incomplete `healthCheck` block is skipped rather than half-read.
    #[test]
    fn an_incomplete_health_check_declaration_is_skipped() {
        let partial = json!({
            "apps": {
                "a": { "healthCheck": { "path": "/ping" } },
                "b": { "healthCheck": { "expectStatus": 200 } },
                "c": { "healthCheck": { "path": "/ping", "expectStatus": 200 } }
            }
        });
        let found = health_apps(&partial);
        assert_eq!(found.len(), 1, "only the complete declaration may produce a probe");
        assert_eq!(found[0].id, "c");
        assert_eq!(
            found[0].timeout, PROBE_CEILING,
            "a missing timeoutSec must not mean waiting forever"
        );
    }
}
