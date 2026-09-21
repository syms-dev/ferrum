//! The seam: every Cloudflare HTTP call ferrum makes, and nothing else.
//!
//! **Three things this module does that the house `ureq` idiom does not,**
//! each of them a finding rather than a preference:
//!
//! 1. **It checks the body's `success` field independent of HTTP status
//!    (UF-15).** Cloudflare's v4 API answers several permission and
//!    validation failures with **HTTP 200** and `{"success": false,
//!    "errors": [...]}`. The idiom used elsewhere in this workspace --
//!    `ureq::get(..).call().map_err(..)` -- inspects only the status and
//!    reads that as a successful call, so a token with the wrong scope
//!    would produce an install that reported success and published nothing.
//!    Every response passes through [`decode`], and [`decode`] refuses a
//!    `success: false` body whatever the status said.
//! 2. **It follows pagination on every listing.** Cloudflare returns 100
//!    records a page by default. A dropped second page makes an existing
//!    record look absent, and the planner then creates a duplicate at a
//!    name that already had one -- two A records round-robin, so roughly
//!    half of all requests reach the wrong host. That failure is
//!    intermittent and therefore far harder to diagnose than an outright
//!    error.
//! 3. **It sets explicit timeouts.** `ureq`'s defaults are generous, and the
//!    house idiom sets none at all. `ferrum-apply apply` calls into this
//!    crate between the switch and the operator's prompt; a hung apply is
//!    worse than a failed one, because a failure at least says what to do
//!    next.
//!
//! **The token travels in the `Authorization` header and nowhere else.** Not
//! in a URL, not in a query string, not in a log line, not in an error
//! message, not in `Debug` output -- [`Secret`] redacts itself, no method
//! here formats it, and a test in this module asserts that no request the
//! client makes carries it outside that header.
//!
//! **Ownership is enforced by the type system, here as everywhere.**
//! [`Client::update_record`] and [`Client::delete_record`] accept a
//! [`ManagedRecordId`], never a bare `&str`. That value is proof the record
//! carries ferrum's marker, and the only public way to obtain one is
//! [`crate::record::plan`]. An id read out of [`Client::list_records`]
//! cannot be passed to either method -- not "should not", *cannot*: the
//! program does not compile. A3 and A4 therefore hold for callers that do
//! not exist yet, which is the situation this crate is actually in.
//!
//! ## `verify_authoritative` -- deliberately absent, owned by R1-S3
//!
//! The frozen seam also names
//! `verify_authoritative(&self, zone: &Zone, name: &str, expected:
//! &RecordTarget) -> Result<bool, std::io::Error>`. It is **not implemented
//! here**, and its absence is a decision rather than an omission: decision
//! D-10 makes it a DNS query issued with `dig` against
//! [`crate::Zone::nameservers`] -- the zone's own authoritative servers,
//! never the host's recursive resolver, which can hold a negative-cache
//! entry from an earlier lookup and report a freshly created record as
//! absent. It is not an HTTP call, shares none of this module's machinery,
//! and belongs to story R1-S3. [`Zone::nameservers`] is carried on the zone
//! by [`Client::resolve_zone`] precisely so that story has them without a
//! second lookup.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Deserialize;

use crate::ownership::ManagedRecordId;
use crate::record::{plan, DesiredRecord, RecordAction, RecordJson, RecordWrite};
use crate::zone::{delegation_away, Delegation, ZoneJson};
use crate::{CloudflareError, DnsRecord, RecordTarget, Secret, Zone};

/// Cloudflare's v4 API root.
const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// How long to wait for a TCP connection to Cloudflare.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for Cloudflare to answer once connected.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Items per listing page. Cloudflare's maximum for both zones and records;
/// asking for fewer only multiplies round trips.
const PER_PAGE: u32 = 100;

/// A ceiling on pages followed for one listing.
///
/// A server that keeps reporting another page would otherwise loop forever
/// inside an apply. At [`PER_PAGE`] this is 5,000 items, far beyond any
/// plausible ferrum zone, so reaching it means the response is not what
/// Cloudflare documents rather than that the zone is large.
const MAX_PAGES: u32 = 50;

/// Cloudflare's v4 response envelope.
///
/// The explicit `bound` replaces the one `derive(Deserialize)` would infer:
/// `#[serde(default)]` on a generic field otherwise demands `T: Default`,
/// which none of the payload types are and none should have to be.
#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<ApiErrorJson>,
    #[serde(default)]
    result: Option<T>,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}

/// One entry of Cloudflare's own `errors` array.
#[derive(Debug, Deserialize)]
struct ApiErrorJson {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

/// Cloudflare's pagination block.
#[derive(Debug, Deserialize)]
struct ResultInfo {
    #[serde(default)]
    total_pages: u32,
}

/// The one type in this workspace that talks to Cloudflare.
///
/// Holds the token, a `ureq` agent with explicit timeouts, and the API base
/// URL. The base URL is overridable only under test so that no production
/// call site can be pointed somewhere else by configuration.
pub struct Client {
    token: Secret,
    agent: ureq::Agent,
    base_url: String,
}

impl std::fmt::Debug for Client {
    /// Deliberately omits the token. [`Secret`] already redacts itself, but
    /// a client is the value most likely to end up in a `dbg!` while
    /// debugging an apply, so the guarantee is restated here rather than
    /// depended upon from a distance.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Client {
    /// A client pointed at the real Cloudflare API.
    ///
    /// # Arguments
    /// * `token` - the Cloudflare API token, scoped `Zone:Read` +
    ///   `DNS:Edit`. On-host it must already have had the
    ///   `CLOUDFLARE_DNS_API_TOKEN=` prefix stripped: the secret file is a
    ///   systemd `EnvironmentFile=` line, not a bare token.
    #[must_use]
    pub fn new(token: Secret) -> Self {
        Self::build(token, API_BASE.to_string(), CONNECT_TIMEOUT, READ_TIMEOUT)
    }

    /// A client pointed at a fake API, for tests.
    ///
    /// # Arguments
    /// * `token` - any token; [`crate::testing::TEST_TOKEN`] by convention.
    /// * `base_url` - [`crate::testing::FakeCloudflare::base_url`].
    ///
    /// Gated on `test` *or* the `testing` feature rather than `test` alone,
    /// because `ferrum-install`'s own tests drive A5 and A7 through this
    /// same seam and would otherwise need a second fake.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn with_base_url(token: Secret, base_url: String) -> Self {
        Self::build(token, base_url, CONNECT_TIMEOUT, READ_TIMEOUT)
    }

    /// A test client with short timeouts.
    ///
    /// # Arguments
    /// * `token` - any token.
    /// * `base_url` - the fake's base URL.
    /// * `connect` - connection timeout.
    /// * `read` - response timeout.
    ///
    /// Exists so the timeout behaviour itself is testable: asserting on the
    /// production 30-second read timeout would mean a 30-second test, and an
    /// untested timeout is indistinguishable from an absent one.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn with_base_url_and_timeouts(
        token: Secret,
        base_url: String,
        connect: Duration,
        read: Duration,
    ) -> Self {
        Self::build(token, base_url, connect, read)
    }

    fn build(token: Secret, base_url: String, connect: Duration, read: Duration) -> Self {
        Client {
            token,
            agent: ureq::AgentBuilder::new()
                .timeout_connect(connect)
                .timeout_read(read)
                .timeout_write(read)
                .build(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// Finds the zone that holds the base domain's records, and proves it is
    /// authoritative for them.
    ///
    /// Lists every zone the token can see and takes the longest
    /// label-aligned suffix of `base_domain` (decision D-06 -- a lookup by
    /// name would reject a correctly scoped token whenever `base_domain` is
    /// a subdomain, which is the form `options.nix` documents). It then
    /// reads the zone's own `NS` records and refuses if the base domain has
    /// been delegated away.
    ///
    /// # Arguments
    /// * `base_domain` - `ferrum.proxy.baseDomain`.
    ///
    /// # Returns
    /// The zone, with the authoritative nameservers R1-S3's post-apply
    /// verification will query.
    ///
    /// # Errors
    /// [`CloudflareError::ZoneNotFound`] when no visible zone covers the
    /// domain; [`CloudflareError::ZoneDelegated`] when the subtree is served
    /// by someone else's nameservers, so records written here would be
    /// accepted by the API and resolve nowhere; [`CloudflareError::Api`],
    /// [`CloudflareError::Transport`] or [`CloudflareError::Malformed`] when
    /// the listing itself fails.
    pub fn resolve_zone(&self, base_domain: &str) -> Result<Zone, CloudflareError> {
        let zones: Vec<Zone> = self
            .list_all::<ZoneJson>("/zones", &[])?
            .into_iter()
            .map(Zone::from)
            .collect();
        let zone = crate::zone::select(base_domain, &zones)?;

        if let Some((name, nameservers)) =
            delegation_away(base_domain, &zone, &self.list_delegations(&zone)?)
        {
            return Err(CloudflareError::ZoneDelegated {
                base_domain: base_domain.to_string(),
                delegated_name: name,
                nameservers,
            });
        }

        Ok(zone)
    }

    /// Proves, at token-collection time, that this credential can manage
    /// records for the base domain (A5).
    ///
    /// A distinct method from [`Client::resolve_zone`] because it runs at a
    /// different moment and answers a narrower question: the installer calls
    /// it from the prompt, before a target host exists, and an operator
    /// reading its failure needs to hear "this token cannot see your
    /// domain", not a message written for a caller that already holds a
    /// [`Zone`]. Failing here costs a re-prompt; failing later costs a
    /// finished install that publishes nothing.
    ///
    /// # Arguments
    /// * `base_domain` - the domain the operator just entered.
    ///
    /// # Errors
    /// The same set as [`Client::resolve_zone`].
    pub fn verify_zone_access(&self, base_domain: &str) -> Result<(), CloudflareError> {
        self.resolve_zone(base_domain).map(|_| ())
    }

    /// Every `A` and `CNAME` record in the zone.
    ///
    /// This is the only source of ownership truth: `owned_by_ferrum` is
    /// derived from each record's live `comment` field here, never
    /// remembered between runs, so a reinstalled host with an empty
    /// `/var/lib/ferrum/state` recognises its own records on the first
    /// apply.
    ///
    /// # Arguments
    /// * `zone` - from [`Client::resolve_zone`].
    ///
    /// # Returns
    /// Every page of the listing, in Cloudflare's order. Records of other
    /// types -- including the `_acme-challenge` `TXT` records lego creates
    /// and removes -- are not returned; they are not ferrum's to reconcile.
    ///
    /// # Errors
    /// [`CloudflareError::Api`], [`CloudflareError::Transport`] or
    /// [`CloudflareError::Malformed`].
    pub fn list_records(&self, zone: &Zone) -> Result<Vec<DnsRecord>, CloudflareError> {
        Ok(self
            .list_all::<RecordJson>(&format!("/zones/{}/dns_records", zone.id), &[])?
            .into_iter()
            .filter_map(RecordJson::into_model)
            .collect())
    }

    /// The zone's `NS` records: every subtree handed to other nameservers.
    ///
    /// # Arguments
    /// * `zone` - the zone to inspect.
    ///
    /// # Returns
    /// One [`Delegation`] per `NS` record, including the zone's own apex
    /// records -- [`delegation_away`] is what distinguishes them.
    ///
    /// # Errors
    /// [`CloudflareError::Api`], [`CloudflareError::Transport`] or
    /// [`CloudflareError::Malformed`].
    pub fn list_delegations(&self, zone: &Zone) -> Result<Vec<Delegation>, CloudflareError> {
        Ok(self
            .list_all::<RecordJson>(
                &format!("/zones/{}/dns_records", zone.id),
                &[("type", "NS")],
            )?
            .into_iter()
            .filter(|r| r.record_type == "NS")
            .map(|r| Delegation {
                name: r.name,
                nameserver: r.content,
            })
            .collect())
    }

    /// Creates a record ferrum owns.
    ///
    /// The body always carries `proxied: false` and the ownership marker
    /// ([`RecordWrite`]); a create that omitted the marker would produce a
    /// record ferrum could never recognise again and would thereafter treat
    /// as the operator's.
    ///
    /// # Arguments
    /// * `zone` - the zone to create in.
    /// * `name` - the fully qualified record name, e.g. `auth.example.com`.
    /// * `target` - where it points.
    ///
    /// # Returns
    /// The created record as Cloudflare stored it.
    ///
    /// # Errors
    /// [`CloudflareError::Api`] when Cloudflare refuses -- including the
    /// HTTP 200 refusals -- and [`CloudflareError::Transport`] or
    /// [`CloudflareError::Malformed`] otherwise.
    pub fn create_record(
        &self,
        zone: &Zone,
        name: &str,
        target: &RecordTarget,
    ) -> Result<DnsRecord, CloudflareError> {
        let body = RecordWrite::new(name, target);
        let url = format!("{}/zones/{}/dns_records", self.base_url, zone.id);
        let raw = self.execute(self.agent.post(&url), Some(&body))?;
        Self::one_record(&raw)
    }

    /// Replaces a record ferrum owns with the desired state.
    ///
    /// `PUT` rather than `PATCH` deliberately: reconciliation means the
    /// record ends up exactly as ferrum describes it, including fields an
    /// operator changed in the dashboard that a partial update would leave
    /// in place.
    ///
    /// A3 is enforced in the signature: `record_id` is a
    /// [`ManagedRecordId`], which only [`crate::record::plan`] can produce
    /// and only for a record carrying ferrum's marker. There is no way to
    /// reach this method with an operator's record.
    ///
    /// # Arguments
    /// * `zone` - the zone holding the record.
    /// * `record_id` - proof, from a [`RecordAction::Update`], that the
    ///   record is ferrum's.
    /// * `name` - the fully qualified record name. Present because `PUT`
    ///   replaces the whole record and must therefore restate its name; the
    ///   frozen seam omitted it on the assumption of a partial update.
    /// * `target` - where the record should point.
    ///
    /// # Returns
    /// The record as Cloudflare stored it.
    ///
    /// # Errors
    /// As [`Client::create_record`].
    pub fn update_record(
        &self,
        zone: &Zone,
        record_id: &ManagedRecordId,
        name: &str,
        target: &RecordTarget,
    ) -> Result<DnsRecord, CloudflareError> {
        let body = RecordWrite::new(name, target);
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.base_url,
            zone.id,
            record_id.as_str()
        );
        let raw = self.execute(self.agent.put(&url), Some(&body))?;
        Self::one_record(&raw)
    }

    /// Removes a record ferrum owns (A4).
    ///
    /// A4 is enforced in the signature: `record_id` is a
    /// [`ManagedRecordId`]. A wrongly sourced id would delete an operator's
    /// record irrecoverably -- ferrum holds no copy of it, and reinstalling
    /// the host does not bring it back -- so the wrong id is made
    /// unrepresentable rather than merely discouraged.
    ///
    /// ```compile_fail
    /// # use ferrum_dns::client::Client;
    /// # use ferrum_dns::{Secret, Zone};
    /// # let client = Client::new(Secret::new(String::new()));
    /// # let zone = Zone { id: String::new(), name: String::new(), nameservers: Vec::new() };
    /// // An id straight out of a listing is not proof of ownership.
    /// client.delete_record(&zone, "an-id-from-list_records");
    /// ```
    ///
    /// # Arguments
    /// * `zone` - the zone holding the record.
    /// * `record_id` - proof, from a [`RecordAction::Delete`], that the
    ///   record is ferrum's.
    ///
    /// # Errors
    /// As [`Client::create_record`].
    pub fn delete_record(
        &self,
        zone: &Zone,
        record_id: &ManagedRecordId,
    ) -> Result<(), CloudflareError> {
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.base_url,
            zone.id,
            record_id.as_str()
        );
        let raw = self.execute(self.agent.delete(&url), None::<&RecordWrite>)?;
        decode::<serde_json::Value>(&raw).map(|_| ())
    }

    /// Computes the reconcile plan for a zone without changing anything
    /// (A7).
    ///
    /// The dry run and the apply must never diverge, so both derive their
    /// actions from this one call rather than from two descriptions of the
    /// same intent.
    ///
    /// # Arguments
    /// * `zone` - from [`Client::resolve_zone`].
    /// * `desired` - every record ferrum wants.
    ///
    /// # Returns
    /// The plan, as [`crate::record::plan`] computed it against a live
    /// listing.
    ///
    /// # Errors
    /// Whatever [`Client::list_records`] returns.
    pub fn plan_records(
        &self,
        zone: &Zone,
        desired: &[DesiredRecord],
    ) -> Result<Vec<RecordAction>, CloudflareError> {
        Ok(plan(desired, &self.list_records(zone)?))
    }

    /// Parses a single-record response into the model.
    fn one_record(raw: &str) -> Result<DnsRecord, CloudflareError> {
        let envelope = decode::<RecordJson>(raw)?;
        envelope
            .result
            .and_then(RecordJson::into_model)
            .ok_or_else(|| {
                CloudflareError::Malformed(
                    "Cloudflare accepted the write but returned no usable record".to_string(),
                )
            })
    }

    /// Follows every page of a listing.
    ///
    /// # Arguments
    /// * `path` - the API path, e.g. `/zones`.
    /// * `extra` - additional query parameters, e.g. `[("type", "NS")]`.
    ///   Values are restricted to the literal, already-safe constants this
    ///   crate passes; nothing operator-supplied reaches a query string.
    ///
    /// # Errors
    /// [`CloudflareError::Malformed`] if the listing never terminates within
    /// [`MAX_PAGES`], plus whatever the individual requests return.
    fn list_all<T: DeserializeOwned>(
        &self,
        path: &str,
        extra: &[(&str, &str)],
    ) -> Result<Vec<T>, CloudflareError> {
        let mut items: Vec<T> = Vec::new();
        let mut page: u32 = 1;
        loop {
            let mut url = format!("{}{path}?page={page}&per_page={PER_PAGE}", self.base_url);
            for (key, value) in extra {
                url.push_str(&format!("&{key}={value}"));
            }
            let raw = self.execute(self.agent.get(&url), None::<&RecordWrite>)?;
            let envelope = decode::<Vec<T>>(&raw)?;
            let batch = envelope.result.unwrap_or_default();
            let batch_len = batch.len();
            items.extend(batch);

            // No pagination block means a single-page answer. An empty page
            // also ends the walk, so a server that reports more pages than
            // it has cannot spin here.
            let Some(info) = envelope.result_info else {
                return Ok(items);
            };
            if page >= info.total_pages.max(1) || batch_len == 0 {
                return Ok(items);
            }
            page += 1;
            if page > MAX_PAGES {
                return Err(CloudflareError::Malformed(format!(
                    "the listing for {path} still reported more pages after {MAX_PAGES}"
                )));
            }
        }
    }

    /// Performs one request and returns its body.
    ///
    /// The token is attached here and only here, as an `Authorization`
    /// header. No other method in this crate touches it.
    ///
    /// # Errors
    /// [`CloudflareError::Api`] when a failing HTTP status still carried a
    /// Cloudflare error body -- the caller wants Cloudflare's own reason,
    /// not the number -- and [`CloudflareError::Transport`] for a connection
    /// failure, a timeout, or a failing status with no usable body.
    fn execute<B: serde::Serialize>(
        &self,
        request: ureq::Request,
        body: Option<&B>,
    ) -> Result<String, CloudflareError> {
        let request = request.set("Authorization", &format!("Bearer {}", self.token.expose()));
        let outcome = match body {
            Some(payload) => request.send_json(payload),
            None => request.call(),
        };
        match outcome {
            Ok(response) => response.into_string().map_err(|e| {
                CloudflareError::Transport(format!("could not read Cloudflare's response: {e}"))
            }),
            Err(ureq::Error::Status(status, response)) => {
                let body = response.into_string().unwrap_or_default();
                Err(
                    api_error(&body).unwrap_or(CloudflareError::Transport(format!(
                        "Cloudflare answered HTTP {status}"
                    ))),
                )
            }
            // `ureq`'s transport error renders the URL, which never carries
            // the token -- it travels in the header above.
            Err(ureq::Error::Transport(transport)) => {
                Err(CloudflareError::Transport(transport.to_string()))
            }
        }
    }
}

/// Reads a Cloudflare envelope, refusing a `success: false` body whatever
/// the HTTP status was (UF-15).
///
/// # Arguments
/// * `raw` - the response body.
///
/// # Errors
/// [`CloudflareError::Api`] carrying Cloudflare's own first error code and
/// message; [`CloudflareError::Malformed`] when the body is not the shape
/// Cloudflare documents -- including a `success: false` with an empty
/// `errors` array, which carries no cause to report. The error text quotes
/// only the parser's own message, never the body, so nothing a response
/// happens to contain can be logged from here.
fn decode<T: DeserializeOwned>(raw: &str) -> Result<Envelope<T>, CloudflareError> {
    let envelope: Envelope<T> = serde_json::from_str(raw)
        .map_err(|e| CloudflareError::Malformed(format!("could not read the response: {e}")))?;
    if !envelope.success {
        return Err(first_error(&envelope.errors));
    }
    Ok(envelope)
}

/// Extracts a Cloudflare error from a body that may not be an envelope at
/// all, for the failing-HTTP-status path.
fn api_error(raw: &str) -> Option<CloudflareError> {
    let envelope: Envelope<serde_json::Value> = serde_json::from_str(raw).ok()?;
    if envelope.success {
        return None;
    }
    Some(first_error(&envelope.errors))
}

/// Turns Cloudflare's `errors` array into this crate's error.
fn first_error(errors: &[ApiErrorJson]) -> CloudflareError {
    match errors.first() {
        Some(error) => CloudflareError::Api {
            code: error.code,
            message: error.message.clone(),
        },
        None => CloudflareError::Malformed(
            "Cloudflare reported a failure but named no error".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ownership::may_overwrite;
    use crate::testing::{CannedResponse, FakeCloudflare, Route, TEST_TOKEN};
    use crate::OWNERSHIP_MARKER;
    use std::net::Ipv4Addr;

    const HOST: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

    fn client(fake: &FakeCloudflare) -> Client {
        Client::with_base_url_and_timeouts(
            Secret::new(TEST_TOKEN.to_string()),
            fake.base_url().to_string(),
            Duration::from_secs(2),
            Duration::from_millis(400),
        )
    }

    fn zone_json(id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "name_servers": ["amber.ns.cloudflare.com", "bob.ns.cloudflare.com"],
        })
    }

    fn record_json(
        id: &str,
        name: &str,
        content: &str,
        comment: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "type": "A",
            "content": content,
            "proxied": false,
            "comment": comment,
        })
    }

    /// No delegation in the zone: the shape every happy-path test needs.
    fn script_no_delegations(fake: &FakeCloudflare, zone_id: &str) {
        fake.script(
            Route::get(&format!("/zones/{zone_id}/dns_records")),
            CannedResponse::ok(serde_json::json!([])),
        );
    }

    fn test_zone() -> Zone {
        Zone {
            id: "z1".to_string(),
            name: "example.com".to_string(),
            nameservers: vec!["amber.ns.cloudflare.com".to_string()],
        }
    }

    #[test]
    fn resolve_zone_picks_the_longest_suffix_across_every_page_of_the_listing() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok_paginated(vec![zone_json("z1", "example.com")], 1, 1, 2),
        );
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok_paginated(vec![zone_json("z2", "home.example.com")], 2, 1, 2),
        );
        script_no_delegations(&fake, "z2");

        let zone = client(&fake)
            .resolve_zone("app.home.example.com")
            .expect("a zone is resolved");

        assert_eq!(
            zone.id, "z2",
            "the zone on the second page is the correct one -- dropping that \
             page would silently pick the parent zone"
        );
        assert_eq!(zone.nameservers.len(), 2);
        assert_eq!(fake.requests_for(&Route::get("/zones")).len(), 2);
    }

    #[test]
    fn resolve_zone_sends_the_token_as_a_bearer_header_and_never_in_the_url() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([zone_json("z1", "example.com")])),
        );
        script_no_delegations(&fake, "z1");

        client(&fake).resolve_zone("example.com").expect("resolves");

        for request in fake.requests() {
            assert_eq!(
                request.header("authorization"),
                Some(format!("Bearer {TEST_TOKEN}").as_str())
            );
            assert!(
                !request.path.contains(TEST_TOKEN) && !request.query.contains(TEST_TOKEN),
                "the token must never reach a URL: {} ?{}",
                request.path,
                request.query
            );
        }
    }

    /// UF-15, and the reason this crate does not use the house `ureq`
    /// idiom. Delete the `success` check in [`decode`] and this test passes
    /// a permission failure off as a resolved zone.
    #[test]
    fn a_success_false_body_with_http_200_is_an_error_not_a_zone() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );

        let error = client(&fake)
            .resolve_zone("example.com")
            .expect_err("HTTP 200 with success:false is a refusal");
        assert_eq!(
            error,
            CloudflareError::Api {
                code: 9109,
                message: "Invalid access token".to_string(),
            }
        );
    }

    #[test]
    fn a_failing_status_reports_cloudflares_own_error_rather_than_the_number() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::http_error(403, 10000, "Authentication error"),
        );

        let error = client(&fake)
            .resolve_zone("example.com")
            .expect_err("a 403");
        assert_eq!(
            error,
            CloudflareError::Api {
                code: 10000,
                message: "Authentication error".to_string(),
            }
        );
    }

    #[test]
    fn a_failing_status_with_no_usable_body_is_a_transport_error() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::raw(502, "<html>bad gateway</html>"),
        );

        let error = client(&fake)
            .resolve_zone("example.com")
            .expect_err("a 502");
        assert!(
            matches!(error, CloudflareError::Transport(ref d) if d.contains("502")),
            "{error:?}"
        );
    }

    #[test]
    fn a_dropped_connection_is_a_transport_error() {
        let fake = FakeCloudflare::start();
        fake.script(Route::get("/zones"), CannedResponse::transport_failure());

        let error = client(&fake)
            .resolve_zone("example.com")
            .expect_err("no answer");
        assert!(matches!(error, CloudflareError::Transport(_)), "{error:?}");
    }

    /// A hung apply is worse than a failed one: the operator is left at a
    /// prompt that never returns, with no message telling them what to do.
    #[test]
    fn a_response_slower_than_the_read_timeout_fails_rather_than_hanging() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([])).after(Duration::from_millis(900)),
        );

        let error = client(&fake)
            .resolve_zone("example.com")
            .expect_err("900ms cannot beat a 400ms read timeout");
        assert!(matches!(error, CloudflareError::Transport(_)), "{error:?}");
    }

    #[test]
    fn a_body_that_is_not_an_envelope_is_malformed_not_a_silent_empty_result() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::raw(200, "not json at all"),
        );

        let error = client(&fake)
            .resolve_zone("example.com")
            .expect_err("not JSON");
        assert!(matches!(error, CloudflareError::Malformed(_)), "{error:?}");
    }

    #[test]
    fn no_error_this_client_produces_carries_the_token() {
        let fake = FakeCloudflare::start();
        for response in [
            CannedResponse::api_error(9109, "Invalid access token"),
            CannedResponse::http_error(403, 10000, "Authentication error"),
            CannedResponse::raw(200, "not json"),
            CannedResponse::transport_failure(),
        ] {
            fake.script(Route::get("/zones"), response);
            let error = client(&fake)
                .resolve_zone("example.com")
                .expect_err("each of these fails");
            let rendered = format!("{error} {error:?}");
            assert!(
                !rendered.contains(TEST_TOKEN),
                "an error message leaked the credential: {rendered}"
            );
        }
    }

    #[test]
    fn a_client_does_not_print_its_token_when_debugged() {
        let fake = FakeCloudflare::start();
        let rendered = format!("{:?}", client(&fake));
        assert!(!rendered.contains(TEST_TOKEN), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn no_visible_zone_covering_the_domain_names_the_domain() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([zone_json("z1", "somewhere-else.net")])),
        );

        let error = client(&fake)
            .resolve_zone("home.example.com")
            .expect_err("no zone covers it");
        assert_eq!(
            error,
            CloudflareError::ZoneNotFound {
                base_domain: "home.example.com".to_string()
            }
        );
    }

    /// The exact failure R1 exists to prevent, one level deeper: Cloudflare
    /// would accept every write and the names would resolve nowhere.
    #[test]
    fn a_base_domain_delegated_away_from_the_zone_is_refused() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([zone_json("z1", "example.com")])),
        );
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([
                {
                    "id": "ns1", "name": "home.example.com", "type": "NS",
                    "content": "ns1.elsewhere.net",
                },
                {
                    "id": "ns2", "name": "example.com", "type": "NS",
                    "content": "amber.ns.cloudflare.com",
                },
            ])),
        );

        let error = client(&fake)
            .resolve_zone("home.example.com")
            .expect_err("the subtree is not ours to write into");
        let CloudflareError::ZoneDelegated {
            base_domain,
            delegated_name,
            nameservers,
        } = error
        else {
            panic!("expected a delegation refusal, got {error:?}");
        };
        assert_eq!(base_domain, "home.example.com");
        assert_eq!(delegated_name, "home.example.com");
        assert_eq!(nameservers, vec!["ns1.elsewhere.net"]);
    }

    #[test]
    fn the_delegation_listing_asks_cloudflare_only_for_ns_records() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([])),
        );

        client(&fake)
            .list_delegations(&test_zone())
            .expect("an empty delegation list");

        let requests = fake.requests_for(&Route::get("/zones/z1/dns_records"));
        assert!(
            requests[0].query.contains("type=NS"),
            "{}",
            requests[0].query
        );
    }

    #[test]
    fn verify_zone_access_accepts_a_token_that_can_see_a_covering_zone() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([zone_json("z1", "example.com")])),
        );
        script_no_delegations(&fake, "z1");

        assert_eq!(client(&fake).verify_zone_access("home.example.com"), Ok(()));
    }

    #[test]
    fn verify_zone_access_refuses_a_token_that_cannot() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );

        assert!(client(&fake).verify_zone_access("example.com").is_err());
    }

    /// A dropped page makes an existing record look absent, and the planner
    /// then creates a duplicate that round-robins half the traffic away.
    #[test]
    fn a_record_listing_follows_every_page() {
        let fake = FakeCloudflare::start();
        let route = Route::get("/zones/z1/dns_records");
        fake.script(
            route.clone(),
            CannedResponse::ok_paginated(
                vec![record_json(
                    "r1",
                    "auth.example.com",
                    "203.0.113.7",
                    Some(OWNERSHIP_MARKER),
                )],
                1,
                1,
                2,
            ),
        );
        fake.script(
            route.clone(),
            CannedResponse::ok_paginated(
                vec![record_json("r2", "plex.example.com", "198.51.100.9", None)],
                2,
                1,
                2,
            ),
        );

        let records = client(&fake).list_records(&test_zone()).expect("a listing");

        assert_eq!(records.len(), 2, "both pages must be read: {records:?}");
        assert!(records[0].owned_by_ferrum);
        assert!(
            !records[1].owned_by_ferrum,
            "no marker means the operator's"
        );
        assert_eq!(fake.requests_for(&route).len(), 2);
    }

    #[test]
    fn a_listing_that_never_stops_reporting_pages_is_abandoned_rather_than_looped() {
        let fake = FakeCloudflare::start();
        let route = Route::get("/zones/z1/dns_records");
        for _ in 0..=MAX_PAGES {
            fake.script(
                route.clone(),
                CannedResponse::ok_paginated(
                    vec![record_json("r", "a.example.com", "203.0.113.7", None)],
                    1,
                    1,
                    u32::MAX,
                ),
            );
        }

        let error = client(&fake)
            .list_records(&test_zone())
            .expect_err("the walk must stop");
        assert!(matches!(error, CloudflareError::Malformed(_)), "{error:?}");
    }

    #[test]
    fn a_created_record_always_carries_the_marker_and_the_grey_cloud() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::post("/zones/z1/dns_records"),
            CannedResponse::ok(record_json(
                "r1",
                "auth.example.com",
                "203.0.113.7",
                Some(OWNERSHIP_MARKER),
            )),
        );

        let created = client(&fake)
            .create_record(&test_zone(), "auth.example.com", &RecordTarget::A(HOST))
            .expect("the record is created");
        assert!(created.owned_by_ferrum);

        let sent = fake.requests_for(&Route::post("/zones/z1/dns_records"))[0]
            .json_body()
            .expect("a JSON body");
        assert_eq!(sent["type"], serde_json::json!("A"));
        assert_eq!(sent["name"], serde_json::json!("auth.example.com"));
        assert_eq!(sent["content"], serde_json::json!("203.0.113.7"));
        assert_eq!(sent["proxied"], serde_json::json!(false));
        assert_eq!(sent["comment"], serde_json::json!(OWNERSHIP_MARKER));
    }

    #[test]
    fn a_create_refused_with_http_200_is_not_reported_as_a_created_record() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::post("/zones/z1/dns_records"),
            CannedResponse::api_error(81057, "Record already exists"),
        );

        let error = client(&fake)
            .create_record(&test_zone(), "auth.example.com", &RecordTarget::A(HOST))
            .expect_err("a refusal is not a record");
        assert_eq!(
            error,
            CloudflareError::Api {
                code: 81057,
                message: "Record already exists".to_string(),
            }
        );
    }

    #[test]
    fn an_update_replaces_the_whole_record_at_its_own_url() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::put("/zones/z1/dns_records/r1"),
            CannedResponse::ok(record_json(
                "r1",
                "auth.example.com",
                "203.0.113.7",
                Some(OWNERSHIP_MARKER),
            )),
        );

        let updated = client(&fake)
            .update_record(
                &test_zone(),
                &ManagedRecordId::unchecked("r1"),
                "auth.example.com",
                &RecordTarget::A(HOST),
            )
            .expect("the record is updated");
        assert_eq!(updated.target, RecordTarget::A(HOST));

        let sent = fake.requests_for(&Route::put("/zones/z1/dns_records/r1"))[0]
            .json_body()
            .expect("a JSON body");
        assert_eq!(sent["comment"], serde_json::json!(OWNERSHIP_MARKER));
        assert_eq!(sent["proxied"], serde_json::json!(false));
    }

    #[test]
    fn a_delete_addresses_the_record_by_id() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::delete("/zones/z1/dns_records/r1"),
            CannedResponse::ok(serde_json::json!({ "id": "r1" })),
        );

        client(&fake)
            .delete_record(&test_zone(), &ManagedRecordId::unchecked("r1"))
            .expect("the record is deleted");
        assert_eq!(
            fake.requests_for(&Route::delete("/zones/z1/dns_records/r1"))
                .len(),
            1
        );
    }

    #[test]
    fn a_delete_refused_with_http_200_is_not_reported_as_deleted() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::delete("/zones/z1/dns_records/r1"),
            CannedResponse::api_error(81044, "Record does not exist"),
        );

        assert!(client(&fake)
            .delete_record(&test_zone(), &ManagedRecordId::unchecked("r1"))
            .is_err());
    }

    /// The end-to-end shape A7 shows the operator and A3 depends on: a
    /// listing in, a plan out, nothing written.
    #[test]
    fn a_dry_run_plans_against_the_live_zone_without_writing_anything() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([
                record_json("r1", "plex.example.com", "198.51.100.9", None),
                record_json(
                    "r2",
                    "sonarr.example.com",
                    "203.0.113.7",
                    Some(OWNERSHIP_MARKER)
                ),
            ])),
        );

        let desired = vec![
            DesiredRecord {
                name: "plex.example.com".to_string(),
                target: RecordTarget::A(HOST),
            },
            DesiredRecord {
                name: "auth.example.com".to_string(),
                target: RecordTarget::A(HOST),
            },
        ];
        let actions = client(&fake)
            .plan_records(&test_zone(), &desired)
            .expect("a plan");

        assert!(
            matches!(actions[0], RecordAction::SkipForeign { .. }),
            "{actions:?}"
        );
        assert!(
            matches!(actions[1], RecordAction::Create { .. }),
            "{actions:?}"
        );
        assert!(
            matches!(actions[2], RecordAction::Delete { .. }),
            "{actions:?}"
        );
        assert!(
            fake.requests().iter().all(|r| r.method == "GET"),
            "a dry run must not write: {:?}",
            fake.requests()
        );
    }

    /// `may_overwrite` is re-exported through this module's imports; this
    /// asserts the seam and the guard agree about what a listing means.
    #[test]
    fn a_listed_record_without_the_marker_is_not_writable_by_ferrum() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones/z1/dns_records"),
            CannedResponse::ok(serde_json::json!([record_json(
                "r1",
                "plex.example.com",
                "198.51.100.9",
                None
            )])),
        );

        let records = client(&fake).list_records(&test_zone()).expect("a listing");
        assert!(!may_overwrite(&records[0]));
    }
}
