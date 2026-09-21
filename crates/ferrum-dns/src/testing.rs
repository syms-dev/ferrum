//! Fake servers, so no test ever calls a real one: a Cloudflare API over
//! HTTP ([`FakeCloudflare`]) and an authoritative nameserver over UDP
//! ([`FakeNameserver`]).
//!
//! Two facts make this module a precondition rather than a convenience. The
//! Nix derivation that runs the workspace suite (`workspace-tests` in
//! `nix/modules/flake/checks.nix`) builds in a sandbox with **no network**,
//! so a real Cloudflare call does not fail flakily -- it cannot succeed at
//! all. And no HTTP-mocking pattern existed anywhere in this workspace, so
//! without this module the first story to write a Cloudflare call would
//! either invent one under time pressure or ship untested.
//!
//! It is hand-rolled on [`std::net::TcpListener`] rather than pulling a
//! mock-server crate because adding a package to `crates/Cargo.lock` is a
//! stop-and-report condition for R1, and because the surface needed is
//! small: one HTTP/1.1 request in, one scripted response out.
//!
//! What it gives a test:
//!
//! * **Scripted responses per route**, queued in order, so a test can drive
//!   a paginated listing or a retry-then-succeed sequence.
//! * **Recorded requests** -- method, path, query, headers, body -- so a
//!   test can prove exactly what was sent, not merely that something was.
//! * **Real Cloudflare v4 envelopes**, including the one that matters most:
//!   [`CannedResponse::api_error`] serves **HTTP 200** with
//!   `{"success": false, "errors": [...]}`, which is how Cloudflare reports
//!   several permission and validation failures. The house `ureq` idiom in
//!   this repository inspects only the HTTP status and would read that as
//!   success, so this fixture is first-class here.
//! * **Failure modes that are not responses at all** --
//!   [`CannedResponse::transport_failure`] drops the connection, and
//!   [`CannedResponse::after`] delays one long enough to trip a read
//!   timeout -- so retry and error paths are testable.
//!
//! **Tokens.** Every fixture here uses [`TEST_TOKEN`], which is visibly not
//! a credential. The harness records request headers so a test can assert
//! the token travelled in `Authorization`, but it never prints a header
//! value: its own diagnostics name only the method and path of an
//! unscripted request.
//!
//! The responder is single-threaded and serves one connection at a time, in
//! the order they arrive. A delayed response therefore also delays whatever
//! is queued behind it, which is the right behaviour for a sequential
//! client and the reason a test should keep delays short.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// The only token any fixture in this crate uses.
///
/// It is deliberately self-describing: if this string ever appears in test
/// output, a log, or a diff, it is obvious at a glance that nothing real
/// leaked.
pub const TEST_TOKEN: &str = "test-token-not-a-real-credential";

/// A method-and-path pair a response is scripted against.
///
/// The method is held as a string built through the constructors below
/// rather than an enum, so that a request arriving with a verb this crate
/// does not use is still recorded faithfully instead of being forced into a
/// variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Route {
    /// The uppercased HTTP method, e.g. `GET`.
    pub method: String,
    /// The request path, without any query string, e.g. `/zones`.
    pub path: String,
}

impl Route {
    /// A `GET` route for `path`.
    #[must_use]
    pub fn get(path: &str) -> Self {
        Self::new("GET", path)
    }

    /// A `POST` route for `path`.
    #[must_use]
    pub fn post(path: &str) -> Self {
        Self::new("POST", path)
    }

    /// A `PATCH` route for `path`.
    #[must_use]
    pub fn patch(path: &str) -> Self {
        Self::new("PATCH", path)
    }

    /// A `PUT` route for `path`.
    #[must_use]
    pub fn put(path: &str) -> Self {
        Self::new("PUT", path)
    }

    /// A `DELETE` route for `path`.
    #[must_use]
    pub fn delete(path: &str) -> Self {
        Self::new("DELETE", path)
    }

    /// A route for an arbitrary method.
    ///
    /// # Arguments
    /// * `method` - HTTP method; uppercased so scripting is case-insensitive.
    /// * `path` - request path without a query string.
    #[must_use]
    pub fn new(method: &str, path: &str) -> Self {
        Route {
            method: method.to_ascii_uppercase(),
            path: path.to_string(),
        }
    }
}

/// What the fake does when a scripted route is hit.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Behaviour {
    /// Write a status line, headers, and this body.
    Reply { status: u16, body: String },
    /// Accept the connection and close it without writing anything, which
    /// `ureq` surfaces as a transport error rather than a status.
    DropConnection,
}

/// One scripted answer: what to send, and how long to wait first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CannedResponse {
    behaviour: Behaviour,
    delay: Duration,
}

impl CannedResponse {
    /// A successful Cloudflare v4 envelope carrying `result`.
    ///
    /// # Arguments
    /// * `result` - the value Cloudflare would put in `result`; an object for
    ///   a single record, an array for an unpaginated listing.
    ///
    /// # Returns
    /// An HTTP 200 response whose body is
    /// `{"success": true, "errors": [], "messages": [], "result": <result>}`.
    #[must_use]
    pub fn ok(result: serde_json::Value) -> Self {
        Self::reply(200, envelope(true, result, serde_json::json!([]), None))
    }

    /// A successful listing with Cloudflare's `result_info` pagination block.
    ///
    /// Zone and record listings are paginated in reality, so a test for a
    /// multi-page zone list scripts one of these per page.
    ///
    /// # Arguments
    /// * `results` - the items on this page.
    /// * `page` - 1-based page number this response represents.
    /// * `per_page` - the page size Cloudflare is applying.
    /// * `total_count` - the total number of items across all pages.
    ///
    /// # Returns
    /// An HTTP 200 success envelope whose `result_info` carries `page`,
    /// `per_page`, `count`, `total_count`, and a `total_pages` derived from
    /// `total_count` and `per_page`.
    ///
    /// # Panics
    /// If `per_page` is zero, since that has no meaningful page count.
    #[must_use]
    pub fn ok_paginated(
        results: Vec<serde_json::Value>,
        page: u32,
        per_page: u32,
        total_count: u32,
    ) -> Self {
        assert!(per_page > 0, "per_page must be non-zero");
        let total_pages = total_count.div_ceil(per_page).max(1);
        let result_info = serde_json::json!({
            "page": page,
            "per_page": per_page,
            "count": results.len(),
            "total_count": total_count,
            "total_pages": total_pages,
        });
        Self::reply(
            200,
            envelope(
                true,
                serde_json::Value::Array(results),
                serde_json::json!([]),
                Some(result_info),
            ),
        )
    }

    /// Cloudflare's refusal-with-HTTP-200: the finding this harness exists
    /// for (UF-15).
    ///
    /// Several permission and validation failures come back as a `200 OK`
    /// whose body says `{"success": false, "errors": [...]}`. Code that
    /// checks only the HTTP status reads that as a successful call, so this
    /// is the fixture every error path in this crate must be tested against.
    ///
    /// # Arguments
    /// * `code` - Cloudflare's own `errors[].code`, e.g. `9109`.
    /// * `message` - Cloudflare's own `errors[].message`.
    ///
    /// # Returns
    /// An **HTTP 200** response with a `success: false` envelope.
    #[must_use]
    pub fn api_error(code: i64, message: &str) -> Self {
        Self::reply(
            200,
            envelope(
                false,
                serde_json::Value::Null,
                serde_json::json!([{ "code": code, "message": message }]),
                None,
            ),
        )
    }

    /// A Cloudflare refusal that *does* carry a failing HTTP status, e.g. a
    /// `403` for a token with no access to the zone.
    ///
    /// # Arguments
    /// * `status` - the HTTP status to send.
    /// * `code` - Cloudflare's own `errors[].code`.
    /// * `message` - Cloudflare's own `errors[].message`.
    #[must_use]
    pub fn http_error(status: u16, code: i64, message: &str) -> Self {
        Self::reply(
            status,
            envelope(
                false,
                serde_json::Value::Null,
                serde_json::json!([{ "code": code, "message": message }]),
                None,
            ),
        )
    }

    /// A response with a verbatim body, for a malformed-payload test.
    ///
    /// # Arguments
    /// * `status` - the HTTP status to send.
    /// * `body` - the exact bytes of the response body.
    #[must_use]
    pub fn raw(status: u16, body: &str) -> Self {
        Self::reply(status, body.to_string())
    }

    /// Accept the connection, then close it without answering.
    ///
    /// `ureq` reports this as a transport error, which is the path a retry
    /// policy has to handle and which no status-code fixture can produce.
    #[must_use]
    pub fn transport_failure() -> Self {
        CannedResponse {
            behaviour: Behaviour::DropConnection,
            delay: Duration::ZERO,
        }
    }

    /// Delays this response by `delay` before it is written.
    ///
    /// Used to trip a client read timeout. Keep it short: the responder is
    /// single-threaded, so the delay also holds back anything queued behind
    /// it and the fake's shutdown waits for it.
    #[must_use]
    pub fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    fn reply(status: u16, body: String) -> Self {
        CannedResponse {
            behaviour: Behaviour::Reply { status, body },
            delay: Duration::ZERO,
        }
    }
}

/// Builds a Cloudflare v4 response envelope.
fn envelope(
    success: bool,
    result: serde_json::Value,
    errors: serde_json::Value,
    result_info: Option<serde_json::Value>,
) -> String {
    let mut body = serde_json::json!({
        "success": success,
        "errors": errors,
        "messages": [],
        "result": result,
    });
    if let Some(info) = result_info {
        body["result_info"] = info;
    }
    body.to_string()
}

/// One request the fake received, as it arrived on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    /// The HTTP method, uppercased.
    pub method: String,
    /// The path, with any query string stripped off.
    pub path: String,
    /// The raw query string without the leading `?`, empty when absent.
    pub query: String,
    /// Request headers, keyed by lowercased name.
    pub headers: BTreeMap<String, String>,
    /// The request body as received; empty when there was none.
    pub body: String,
}

impl RecordedRequest {
    /// The value of a header, looked up case-insensitively.
    ///
    /// # Arguments
    /// * `name` - header name in any case, e.g. `Authorization`.
    ///
    /// # Returns
    /// `Some(value)` when the header was present, `None` otherwise.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// The body parsed as JSON.
    ///
    /// # Returns
    /// `Some(value)` when the body is valid JSON, `None` when it is empty or
    /// not JSON -- so a test asserting on a payload fails on the assertion
    /// rather than on an unwrap.
    #[must_use]
    pub fn json_body(&self) -> Option<serde_json::Value> {
        serde_json::from_str(&self.body).ok()
    }
}

/// Shared state between the test thread and the responder thread.
struct Shared {
    scripted: Mutex<HashMap<Route, VecDeque<CannedResponse>>>,
    received: Mutex<Vec<RecordedRequest>>,
    shutdown: AtomicBool,
}

/// A fake Cloudflare API bound to an ephemeral port on loopback.
///
/// Bound to `127.0.0.1:0`, so concurrently running tests never collide on a
/// port. The server thread stops and is joined when the value is dropped.
pub struct FakeCloudflare {
    addr: SocketAddr,
    base_url: String,
    shared: Arc<Shared>,
    handle: Option<JoinHandle<()>>,
}

impl FakeCloudflare {
    /// Starts a fake with no scripted routes.
    ///
    /// # Returns
    /// A running fake; script it with [`FakeCloudflare::script`] and point a
    /// client at [`FakeCloudflare::base_url`].
    ///
    /// # Panics
    /// If loopback cannot be bound, which in a test environment means the
    /// test cannot run at all.
    #[must_use]
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback for the fake API");
        let addr = listener.local_addr().expect("read the fake API's own port");
        let shared = Arc::new(Shared {
            scripted: Mutex::new(HashMap::new()),
            received: Mutex::new(Vec::new()),
            shutdown: AtomicBool::new(false),
        });
        let thread_shared = Arc::clone(&shared);
        let handle = std::thread::spawn(move || serve(&listener, &thread_shared));
        FakeCloudflare {
            addr,
            base_url: format!("http://{addr}"),
            shared,
            handle: Some(handle),
        }
    }

    /// The base URL a client should be pointed at, e.g. `http://127.0.0.1:53124`.
    ///
    /// Plain HTTP on loopback: the fake is not a TLS endpoint, and the point
    /// of the seam's overridable base URL is that a test never needs one.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Queues one response for a route.
    ///
    /// Responses for the same route are served in the order they were
    /// scripted, so a paginated listing or a fail-then-succeed retry is
    /// expressed by scripting the same route twice.
    ///
    /// # Arguments
    /// * `route` - the method and path this response answers.
    /// * `response` - what to serve when that route is next hit.
    ///
    /// # Panics
    /// If the responder thread panicked while holding the script lock.
    pub fn script(&self, route: Route, response: CannedResponse) {
        self.shared
            .scripted
            .lock()
            .expect("the fake API's script lock")
            .entry(route)
            .or_default()
            .push_back(response);
    }

    /// Every request the fake has received so far, in arrival order.
    ///
    /// # Panics
    /// If the responder thread panicked while holding the request lock.
    #[must_use]
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.shared
            .received
            .lock()
            .expect("the fake API's request lock")
            .clone()
    }

    /// The requests that hit one route, in arrival order.
    ///
    /// # Arguments
    /// * `route` - the method and path to filter by; the query string is not
    ///   part of the match, so a test can collect every page of a listing.
    ///
    /// # Panics
    /// If the responder thread panicked while holding the request lock.
    #[must_use]
    pub fn requests_for(&self, route: &Route) -> Vec<RecordedRequest> {
        self.requests()
            .into_iter()
            .filter(|r| r.method == route.method && r.path == route.path)
            .collect()
    }
}

impl Drop for FakeCloudflare {
    /// Stops the responder and joins its thread, so no thread outlives the
    /// test that started it.
    ///
    /// The responder blocks in `accept`, so setting the flag is not enough
    /// on its own: one throwaway connection wakes it to observe the flag.
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The responder loop: one connection at a time until shutdown.
fn serve(listener: &TcpListener, shared: &Arc<Shared>) {
    for stream in listener.incoming() {
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        let Ok(mut stream) = stream else { continue };
        // A client that connects and then says nothing must not wedge the
        // responder for the rest of the test run.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let Some(request) = read_request(&mut stream) else {
            continue;
        };
        let route = Route::new(&request.method, &request.path);
        shared
            .received
            .lock()
            .expect("the fake API's request lock")
            .push(request);

        let scripted = shared
            .scripted
            .lock()
            .expect("the fake API's script lock")
            .get_mut(&route)
            .and_then(VecDeque::pop_front);

        match scripted {
            Some(response) => {
                if !response.delay.is_zero() {
                    std::thread::sleep(response.delay);
                }
                match response.behaviour {
                    Behaviour::Reply { status, body } => write_reply(&mut stream, status, &body),
                    Behaviour::DropConnection => {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                }
            }
            // Nothing was scripted for this route. Answering with a plausible
            // success would let a test pass against a request nobody meant to
            // make, so fail loudly instead -- naming only the method and path,
            // never a header value.
            None => write_reply(
                &mut stream,
                500,
                &envelope(
                    false,
                    serde_json::Value::Null,
                    serde_json::json!([{
                        "code": 0,
                        "message": format!(
                            "ferrum-dns fake API: no response scripted for {} {}",
                            route.method, route.path
                        ),
                    }]),
                    None,
                ),
            ),
        }
    }
}

/// Reads one HTTP/1.1 request, returning `None` on a malformed or empty one.
fn read_request(stream: &mut TcpStream) -> Option<RecordedRequest> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).ok()? == 0 {
        return None;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_ascii_uppercase();
    let target = parts.next()?.to_string();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };

    let mut headers = BTreeMap::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    if length > 0 {
        reader.read_exact(&mut body).ok()?;
    }

    Some(RecordedRequest {
        method,
        path,
        query,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// Writes one response and closes the connection.
fn write_reply(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Status",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
}

/// How the fake nameserver answers.
///
/// The three variants are exactly the three cases
/// [`crate::dns_query::verify`] has to tell apart, and nothing else: a
/// server that answers with a target, a server that answers with no record,
/// and a server that does not answer at all. The second and third look
/// identical to a caller that only reads `dig`'s output, and opposite to an
/// operator -- one means their DNS is wrong, the other means ferrum could
/// not tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsBehaviour {
    /// Answer every query with these targets, rendered as whatever record
    /// type was asked for.
    Answer(Vec<String>),
    /// Answer `NOERROR` with an empty answer section -- the name exists,
    /// the record does not.
    Empty,
    /// Receive the query and never reply, so `dig` times out.
    Silent,
}

impl NsBehaviour {
    /// An [`NsBehaviour::Answer`] from string targets.
    ///
    /// # Arguments
    /// * `targets` - IPv4 addresses for an `A` query, hostnames for a
    ///   `CNAME` query. Which one is used is decided by the query, not here.
    #[must_use]
    pub fn answer(targets: &[&str]) -> Self {
        NsBehaviour::Answer(targets.iter().map(ToString::to_string).collect())
    }
}

/// What the fake nameserver recorded about one query it received.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedQuery {
    /// The queried name, without its trailing root dot.
    name: String,
    /// The queried type as a string, e.g. `A` or `CNAME`.
    record_type: String,
}

/// State shared with the responder thread.
struct NsShared {
    behaviour: NsBehaviour,
    received: Mutex<Vec<RecordedQuery>>,
    shutdown: AtomicBool,
}

/// An authoritative nameserver bound to an ephemeral loopback UDP port.
///
/// **Why a real server rather than a mocked `dig`.** Decision D-10 makes
/// `dig` the mechanism, which means the things most likely to break are the
/// argv this crate builds and the round trip through `dig`'s own output --
/// neither of which a stubbed-out command would exercise at all. Pointing
/// the real `dig` at this fake tests both.
///
/// **Why this works with no network.** The Nix sandbox that runs
/// `workspace-tests` has no *external* network, but loopback works inside
/// it: [`FakeCloudflare`] already proves that today, in that same sandbox,
/// with a `TcpListener`. This is the same trick over UDP.
///
/// It speaks just enough DNS to answer `dig`: it echoes the transaction id
/// and question, sets `QR`/`AA`, and appends an answer record. The wire
/// handling it does is deliberately confined to this test-only module --
/// the production path in [`crate::dns_query`] parses no wire format at all,
/// which is the entire point of D-10's ruling.
pub struct FakeNameserver {
    port: u16,
    socket: UdpSocket,
    shared: Arc<NsShared>,
    handle: Option<JoinHandle<()>>,
}

impl FakeNameserver {
    /// Starts a nameserver on `127.0.0.1` with an ephemeral port.
    ///
    /// # Arguments
    /// * `behaviour` - how it answers every query it receives.
    ///
    /// # Returns
    /// A running server; point a query at `127.0.0.1` on
    /// [`FakeNameserver::port`].
    ///
    /// # Panics
    /// If loopback UDP cannot be bound, which in a test environment means
    /// the test cannot run at all.
    #[must_use]
    pub fn start(behaviour: NsBehaviour) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind loopback for the fake nameserver");
        let port = socket
            .local_addr()
            .expect("read the fake nameserver's own port")
            .port();
        // A read timeout rather than a blocking receive: the responder has
        // to wake up periodically to notice the shutdown flag, and a
        // `Silent` server never sends anything that could wake it otherwise.
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set the fake nameserver's read timeout");
        let shared = Arc::new(NsShared {
            behaviour,
            received: Mutex::new(Vec::new()),
            shutdown: AtomicBool::new(false),
        });
        let thread_socket = socket
            .try_clone()
            .expect("clone the fake nameserver socket");
        let thread_shared = Arc::clone(&shared);
        let handle = std::thread::spawn(move || serve_dns(&thread_socket, &thread_shared));
        FakeNameserver {
            port,
            socket,
            shared,
            handle: Some(handle),
        }
    }

    /// The loopback UDP port this server is listening on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// How many queries have reached it.
    ///
    /// # Panics
    /// If the responder thread panicked while holding the query lock.
    #[must_use]
    pub fn queries(&self) -> usize {
        self.shared
            .received
            .lock()
            .expect("the fake nameserver's query lock")
            .len()
    }

    /// The type of the most recent query, e.g. `A` or `CNAME`.
    ///
    /// # Returns
    /// `None` when nothing has been asked yet.
    ///
    /// # Panics
    /// If the responder thread panicked while holding the query lock.
    #[must_use]
    pub fn last_query_type(&self) -> Option<String> {
        self.shared
            .received
            .lock()
            .expect("the fake nameserver's query lock")
            .last()
            .map(|q| q.record_type.clone())
    }

    /// The name of the most recent query, without its trailing root dot.
    ///
    /// # Returns
    /// `None` when nothing has been asked yet.
    ///
    /// # Panics
    /// If the responder thread panicked while holding the query lock.
    #[must_use]
    pub fn last_query_name(&self) -> Option<String> {
        self.shared
            .received
            .lock()
            .expect("the fake nameserver's query lock")
            .last()
            .map(|q| q.name.clone())
    }
}

impl Drop for FakeNameserver {
    /// Stops the responder and joins its thread, so no thread outlives the
    /// test that started it.
    fn drop(&mut self) {
        self.shared.shutdown.store(true, Ordering::SeqCst);
        // The responder wakes on its own read timeout, so nothing needs to
        // be sent; this only shortens the wait.
        let _ = self.socket.send_to(&[0u8; 12], ("127.0.0.1", self.port));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// The responder loop: answer one datagram at a time until shutdown.
fn serve_dns(socket: &UdpSocket, shared: &Arc<NsShared>) {
    let mut buffer = [0u8; 1500];
    while !shared.shutdown.load(Ordering::SeqCst) {
        let Ok((len, from)) = socket.recv_from(&mut buffer) else {
            continue; // the read timeout firing, which is how shutdown is noticed
        };
        if shared.shutdown.load(Ordering::SeqCst) {
            return;
        }
        let Some(question) = read_question(&buffer[..len]) else {
            continue;
        };
        shared
            .received
            .lock()
            .expect("the fake nameserver's query lock")
            .push(RecordedQuery {
                name: question.name.clone(),
                record_type: type_name(question.qtype).to_string(),
            });

        if shared.behaviour == NsBehaviour::Silent {
            continue;
        }
        let answers = match &shared.behaviour {
            NsBehaviour::Answer(targets) => targets
                .iter()
                .filter_map(|t| answer_rdata(question.qtype, t))
                .collect(),
            _ => Vec::new(),
        };
        let _ = socket.send_to(&dns_response(&buffer[..len], &question, &answers), from);
    }
}

/// The question section of a query, as far as the fake needs to read it.
struct Question {
    /// The queried name in presentation form, without a trailing dot.
    name: String,
    /// The queried type code, e.g. 1 for `A`.
    qtype: u16,
    /// Where the question section ends in the datagram.
    end: usize,
}

/// Reads the question out of a query datagram.
///
/// Test-only, and deliberately minimal: no compression pointers are followed
/// (a query's question section never uses them), and every read is bounds
/// checked so a malformed datagram ends the parse rather than the process.
fn read_question(datagram: &[u8]) -> Option<Question> {
    if datagram.len() < 12 {
        return None;
    }
    let mut labels: Vec<String> = Vec::new();
    let mut cursor = 12;
    loop {
        let length = *datagram.get(cursor)? as usize;
        cursor += 1;
        if length == 0 {
            break;
        }
        // A pointer (top two bits set) is not something a question section
        // contains, so treat it as a datagram this fake does not serve.
        if length >= 0xC0 {
            return None;
        }
        let label = datagram.get(cursor..cursor + length)?;
        labels.push(String::from_utf8_lossy(label).to_string());
        cursor += length;
    }
    let qtype = u16::from_be_bytes([*datagram.get(cursor)?, *datagram.get(cursor + 1)?]);
    Some(Question {
        name: labels.join("."),
        qtype,
        end: cursor + 4,
    })
}

/// The presentation name for a query type code.
fn type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        5 => "CNAME",
        _ => "OTHER",
    }
}

/// Encodes one answer's rdata for the queried type.
///
/// # Returns
/// `None` when the target cannot be rendered as that type -- an unparseable
/// address for an `A` query -- which makes the fake answer emptily rather
/// than send something `dig` would reject.
fn answer_rdata(qtype: u16, target: &str) -> Option<Vec<u8>> {
    match qtype {
        1 => Some(target.parse::<Ipv4Addr>().ok()?.octets().to_vec()),
        5 => Some(encode_name(target)),
        _ => None,
    }
}

/// Encodes a presentation name as DNS labels.
fn encode_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        encoded.push(u8::try_from(label.len()).unwrap_or(0));
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

/// Builds the response: the query's own id and question, `QR`/`AA` set, and
/// one answer per rdata.
fn dns_response(query: &[u8], question: &Question, answers: &[Vec<u8>]) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend_from_slice(&query[..2]); // the transaction id, echoed
    response.extend_from_slice(&0x8400u16.to_be_bytes()); // QR + AA, NOERROR
    response.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    response.extend_from_slice(&u16::try_from(answers.len()).unwrap_or(0).to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    response.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    response.extend_from_slice(&query[12..question.end]);
    for rdata in answers {
        response.extend_from_slice(&[0xC0, 0x0C]); // a pointer to the question's name
        response.extend_from_slice(&question.qtype.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes()); // class IN
        response.extend_from_slice(&60u32.to_be_bytes()); // TTL
        response.extend_from_slice(&u16::try_from(rdata.len()).unwrap_or(0).to_be_bytes());
        response.extend_from_slice(rdata);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `ureq` agent with short timeouts, so a hung expectation fails the
    /// test quickly instead of hanging the suite.
    fn agent() -> ureq::Agent {
        ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(2))
            .timeout_read(Duration::from_millis(200))
            .build()
    }

    #[test]
    fn serves_a_cloudflare_shaped_success_envelope() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([{ "id": "zone1", "name": "example.com" }])),
        );

        let response = agent()
            .get(&format!("{}/zones", fake.base_url()))
            .call()
            .expect("the fake answers");
        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.into_json().expect("a JSON body");

        assert_eq!(body["success"], serde_json::json!(true));
        assert_eq!(body["errors"], serde_json::json!([]));
        assert_eq!(body["messages"], serde_json::json!([]));
        assert_eq!(body["result"][0]["name"], serde_json::json!("example.com"));
    }

    #[test]
    fn records_the_method_path_query_headers_and_body_that_arrived() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::post("/zones/zone1/dns_records"),
            CannedResponse::ok(serde_json::json!({ "id": "rec1" })),
        );

        agent()
            .post(&format!(
                "{}/zones/zone1/dns_records?foo=bar",
                fake.base_url()
            ))
            .set("Authorization", &format!("Bearer {TEST_TOKEN}"))
            .send_json(serde_json::json!({ "type": "A", "content": "203.0.113.7" }))
            .expect("the fake answers");

        let requests = fake.requests();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/zones/zone1/dns_records");
        assert_eq!(request.query, "foo=bar");
        assert_eq!(
            request.header("authorization"),
            Some(format!("Bearer {TEST_TOKEN}").as_str())
        );
        assert_eq!(
            request.json_body().expect("a JSON body")["content"],
            serde_json::json!("203.0.113.7")
        );
    }

    #[test]
    fn a_header_lookup_is_case_insensitive() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([])),
        );

        agent()
            .get(&format!("{}/zones", fake.base_url()))
            .set("Authorization", &format!("Bearer {TEST_TOKEN}"))
            .call()
            .expect("the fake answers");

        let requests = fake.requests();
        assert_eq!(
            requests[0].header("AUTHORIZATION"),
            requests[0].header("authorization")
        );
    }

    /// UF-15, the finding this harness exists for: Cloudflare reports some
    /// permission failures as `200 OK` with `success: false`, and this
    /// fixture must really be served that way -- otherwise every error-path
    /// test written against it proves nothing.
    #[test]
    fn an_api_error_is_served_as_http_200_with_success_false() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::api_error(9109, "Invalid access token"),
        );

        let response = agent()
            .get(&format!("{}/zones", fake.base_url()))
            .call()
            .expect("ureq treats this as a successful call -- that is the trap");
        assert_eq!(
            response.status(),
            200,
            "the whole point is that the status says nothing is wrong"
        );

        let body: serde_json::Value = response.into_json().expect("a JSON body");
        assert_eq!(body["success"], serde_json::json!(false));
        assert_eq!(body["errors"][0]["code"], serde_json::json!(9109));
        assert_eq!(
            body["errors"][0]["message"],
            serde_json::json!("Invalid access token")
        );
    }

    #[test]
    fn an_http_error_carries_both_the_status_and_cloudflares_own_error() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::http_error(403, 10000, "Authentication error"),
        );

        let error = agent()
            .get(&format!("{}/zones", fake.base_url()))
            .call()
            .expect_err("a 403 is an error for ureq");
        match error {
            ureq::Error::Status(403, response) => {
                let body: serde_json::Value = response.into_json().expect("a JSON body");
                assert_eq!(body["success"], serde_json::json!(false));
                assert_eq!(body["errors"][0]["code"], serde_json::json!(10000));
            }
            other => panic!("expected a 403 status error, got {other:?}"),
        }
    }

    #[test]
    fn a_paginated_listing_carries_result_info() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones/zone1/dns_records"),
            CannedResponse::ok_paginated(vec![serde_json::json!({ "id": "rec1" })], 2, 1, 3),
        );

        let body: serde_json::Value = agent()
            .get(&format!("{}/zones/zone1/dns_records", fake.base_url()))
            .call()
            .expect("the fake answers")
            .into_json()
            .expect("a JSON body");

        assert_eq!(body["success"], serde_json::json!(true));
        assert_eq!(body["result_info"]["page"], serde_json::json!(2));
        assert_eq!(body["result_info"]["per_page"], serde_json::json!(1));
        assert_eq!(body["result_info"]["count"], serde_json::json!(1));
        assert_eq!(body["result_info"]["total_count"], serde_json::json!(3));
        assert_eq!(body["result_info"]["total_pages"], serde_json::json!(3));
    }

    #[test]
    fn responses_for_one_route_are_served_in_the_order_they_were_scripted() {
        let fake = FakeCloudflare::start();
        let route = Route::get("/zones");
        fake.script(
            route.clone(),
            CannedResponse::ok_paginated(vec![serde_json::json!({ "id": "a" })], 1, 1, 2),
        );
        fake.script(
            route.clone(),
            CannedResponse::ok_paginated(vec![serde_json::json!({ "id": "b" })], 2, 1, 2),
        );

        let mut seen = Vec::new();
        for page in 1..=2 {
            let body: serde_json::Value = agent()
                .get(&format!("{}/zones?page={page}", fake.base_url()))
                .call()
                .expect("the fake answers")
                .into_json()
                .expect("a JSON body");
            seen.push(
                body["result"][0]["id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            );
        }

        assert_eq!(seen, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(fake.requests_for(&route).len(), 2);
    }

    #[test]
    fn a_transport_failure_is_surfaced_as_a_transport_error_not_a_status() {
        let fake = FakeCloudflare::start();
        fake.script(Route::get("/zones"), CannedResponse::transport_failure());

        let error = agent()
            .get(&format!("{}/zones", fake.base_url()))
            .call()
            .expect_err("a dropped connection cannot succeed");
        assert!(
            matches!(error, ureq::Error::Transport(_)),
            "expected a transport error, got {error:?}"
        );
        // It still counts as a request the fake saw.
        assert_eq!(fake.requests().len(), 1);
    }

    #[test]
    fn a_delayed_response_trips_a_client_read_timeout() {
        let fake = FakeCloudflare::start();
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([])).after(Duration::from_millis(600)),
        );

        let error = agent()
            .get(&format!("{}/zones", fake.base_url()))
            .call()
            .expect_err("a 600ms response cannot beat a 200ms read timeout");
        assert!(
            matches!(error, ureq::Error::Transport(_)),
            "expected a transport error, got {error:?}"
        );
    }

    #[test]
    fn an_unscripted_request_fails_loudly_and_echoes_no_header_value() {
        let fake = FakeCloudflare::start();

        let error = agent()
            .get(&format!("{}/zones", fake.base_url()))
            .set("Authorization", &format!("Bearer {TEST_TOKEN}"))
            .call()
            .expect_err("nothing was scripted");
        let ureq::Error::Status(500, response) = error else {
            panic!("expected a 500 for an unscripted route");
        };
        let rendered = response.into_string().expect("a body");

        assert!(
            rendered.contains("no response scripted for GET /zones"),
            "{rendered}"
        );
        assert!(
            !rendered.contains(TEST_TOKEN),
            "the harness must never echo a credential, even a fake one"
        );
    }

    #[test]
    fn the_responder_thread_stops_when_the_fake_is_dropped() {
        let fake = FakeCloudflare::start();
        let addr = fake.addr;
        fake.script(
            Route::get("/zones"),
            CannedResponse::ok(serde_json::json!([])),
        );
        agent()
            .get(&format!("{}/zones", fake.base_url()))
            .call()
            .expect("the fake answers while it is alive");

        drop(fake);

        // Drop joins the responder thread, so by the time it returns the
        // listener is closed and nothing can connect to the port again.
        assert!(
            TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err(),
            "the listener should be closed once the fake is dropped"
        );
    }
}
