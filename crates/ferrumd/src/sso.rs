//! Turning an Authelia login into a ferrumd session -- R5, second half.
//!
//! # Why this is not a header
//!
//! The obvious shape for this is the conventional one: nginx runs its
//! `auth_request`, Authelia answers with `Remote-User`, nginx forwards that
//! header to the application, and the application believes it. ferrumd
//! deliberately does not do that, and `main.rs`'s
//! `forged_forward_auth_headers_authenticate_nobody` has enforced the refusal
//! since R13.
//!
//! The reason is in `client_addr.rs`'s header, and it has not changed: ferrumd
//! binds an AF_INET loopback port, and nothing in `modules/core/daemon.nix` or
//! `modules/apps/*` has network-namespace isolation, so ANY process on this
//! host -- a compromised or SSRF'd catalog app, which the spec's threat model
//! enumerates -- can open `127.0.0.1:7788` directly and send whatever headers
//! it likes. There is no distinguisher available inside this crate: nginx and
//! a local process present the identical socket peer, and every address in
//! `127.0.0.0/8` is bindable by an unprivileged local process.
//!
//! So this module does not read an identity off the request at all. It takes
//! the **cookie the caller presented** and asks Authelia, over loopback, who
//! that cookie belongs to. The thing a forger would have to produce is not a
//! header but a valid Authelia session cookie for the control plane's own
//! cookie scope -- which, after R5's first half, is a scope no catalog app can
//! obtain one for.
//!
//! That dependency is the whole reason R5 is a pair, and it was measured
//! against the authelia 4.39.19 this repository pins rather than assumed.
//! Driving a real Authelia with the real two-scope cookie configuration:
//!
//! | what was presented | at `X-Original-URL` | answer |
//! |---|---|---|
//! | `ferrum_control_session` (dashboard scope) | `https://ferrum.example.test/` | `200`, `Remote-User: admin` |
//! | `authelia_session` (apps scope) | `https://ferrum.example.test/` | **`401`** |
//! | nothing | `https://ferrum.example.test/` | `401` |
//! | `authelia_session` (apps scope) | `https://sonarr.example.test/` | `200` (the control: that cookie is real) |
//! | `ferrum_control_session`, after Authelia logout | `https://ferrum.example.test/` | `401` |
//!
//! Row 2 is what the first half bought. Row 4 is why row 2 is a finding about
//! scope rather than a broken fixture. Row 5 is revocation, at the source.
//! `nix/modules/flake/checks.nix`'s `authelia-asserts-only-its-own-scope`
//! re-measures all five on every build.
//!
//! # Why the HTTP client is hand-rolled
//!
//! `crates/Cargo.lock` is a stop-and-report surface for this work, and ferrumd
//! carries no HTTP client (axum is a server). The request this module makes is
//! one fixed-shape `GET` to a loopback address, and the response is read for a
//! status code and one header, so [`AutheliaVerifier::ask`] is about sixty
//! lines over `tokio::net::TcpStream` rather than a dependency. The same
//! reasoning, in the same words, produced `ferrum-dns`'s `testing` module.
//!
//! # Where the configuration comes from
//!
//! Two environment variables, both set by `modules/core/daemon.nix` and only
//! on a host where the dashboard is published AND `ferrum.auth.enable` is on.
//! When `FERRUMD_SSO_ORIGIN` is unset there is no verifier, `POST /api/sso`
//! answers `404`, and nothing in this module runs -- which is what keeps the
//! SSH-tunnel recovery route independent of Authelia. A tunnel-only host has
//! no SSO and has never needed one; it has ferrumd's own password login, and
//! that path does not touch this file.

use crate::audit;
use crate::auth;
use crate::client_addr::ClientAddr;
use crate::{run_blocking, AppState, SESSION_COOKIE};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Authelia's forward-auth verification endpoint.
const VERIFY_PATH: &str = "/api/verify";

/// Where Authelia listens when `FERRUMD_AUTHELIA_ADDRESS` names nowhere.
///
/// The same `127.0.0.1:9091` `modules/proxy/nginx.nix` writes into every
/// `/authelia` subrequest location. It is a default rather than a constant so
/// a test can point this module at a fake on an ephemeral port.
const DEFAULT_AUTHELIA_ADDRESS: &str = "127.0.0.1:9091";

/// How long Authelia gets to answer before the attempt is reported as a
/// failure to ask rather than as an answer.
///
/// The distinction is the point: an unreachable Authelia must never be
/// indistinguishable from an Authelia that said "nobody" -- see
/// [`Assertion::Unavailable`].
const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// The most of Authelia's answer this module will read.
///
/// Authelia's verify response is a status line and a handful of headers. The
/// cap is three orders of magnitude more than that and exists only so a
/// misconfigured or hostile listener on the configured port cannot make
/// ferrumd buffer without bound.
const RESPONSE_LIMIT: usize = 64 * 1024;

/// What Authelia said about the cookie it was shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assertion {
    /// Authelia recognised the cookie and named its owner.
    Identified {
        /// The value of Authelia's `Remote-User` **response** header, trimmed
        /// and proven non-empty. Never a request header: see this module's
        /// own documentation, and `main.rs`'s source scan, which permits this
        /// file to name that header and permits no other file to.
        username: String,
    },
    /// Authelia recognised nobody: no cookie, the wrong cookie scope, an
    /// expired session, or a session logged out at Authelia.
    Anonymous,
    /// Authelia could not be asked, or answered something this module does
    /// not understand.
    ///
    /// Deliberately NOT folded into [`Assertion::Anonymous`]. "Authelia is
    /// down" and "Authelia says you are nobody" are different facts and every
    /// caller here treats them differently: the first is a `503` that leaves
    /// the operator's session alone, the second is a `401`. Collapsing them
    /// would log every SSO operator out for the few seconds an apply takes to
    /// restart `authelia-main.service`.
    Unavailable(String),
}

/// Asks Authelia who a cookie belongs to.
///
/// Holds no credential of its own: the authority is entirely the cookie the
/// caller presents, and this type's job is to put the question to Authelia in
/// the one shape Authelia answers.
#[derive(Debug, Clone)]
pub struct AutheliaVerifier {
    /// `host:port` of Authelia's own listener, on loopback.
    address: String,
    /// The URL Authelia is asked to make its access-control decision about.
    ///
    /// **Never taken from the request.** It is the dashboard's own published
    /// origin, from `FERRUMD_SSO_ORIGIN`, which `modules/core/daemon.nix`
    /// derives from `ferrum.daemon.subdomain` and `ferrum.proxy.baseDomain`.
    /// Taking it from the caller's `Host` header would let a local process
    /// name an app's hostname instead and have Authelia answer about the
    /// apps' cookie scope -- which is precisely the isolation R5's first half
    /// established, handed back on the next line.
    original_url: String,
}

impl AutheliaVerifier {
    /// Builds a verifier, or explains why the configuration cannot be used.
    ///
    /// # Arguments
    /// * `address` - `host:port` of Authelia's loopback listener.
    /// * `origin` - the dashboard's own published origin, e.g.
    ///   `https://ferrum.example.com`.
    ///
    /// # Errors
    /// A string naming the problem when either value is empty or carries a
    /// character that cannot appear in an HTTP header. Both are host
    /// configuration rather than request data, so a bad one is an operator
    /// error reported at startup, not a runtime branch.
    pub fn new(address: String, origin: String) -> Result<Self, String> {
        if address.is_empty() || !header_safe(&address) {
            return Err(format!("FERRUMD_AUTHELIA_ADDRESS is not a usable address: {address:?}"));
        }
        if origin.is_empty() || !header_safe(&origin) {
            return Err(format!("FERRUMD_SSO_ORIGIN is not a usable origin: {origin:?}"));
        }
        // Authelia matches its access_control rules against a URL, so the
        // value has to be one. A bare hostname would match the `deny`
        // default policy and make every SSO attempt fail with no clue why.
        if !origin.starts_with("https://") && !origin.starts_with("http://") {
            return Err(format!("FERRUMD_SSO_ORIGIN must be an absolute URL: {origin:?}"));
        }
        let original_url = format!("{}/", origin.trim_end_matches('/'));
        Ok(Self { address, original_url })
    }

    /// Builds a verifier from the environment, or `None` when this host has no
    /// SSO.
    ///
    /// `FERRUMD_SSO_ORIGIN` is the switch: `modules/core/daemon.nix` sets it
    /// only where the dashboard is published and Authelia is on. Absent, the
    /// SSO route answers `404` and ferrumd behaves exactly as it did before
    /// R5 -- which is the state a tunnel-only recovery host is in.
    ///
    /// # Returns
    /// `Ok(None)` when SSO is off, `Ok(Some(_))` when it is on, and `Err` when
    /// it is on but misconfigured -- so a typo is a startup failure rather
    /// than a dashboard that silently never offers SSO.
    ///
    /// # Errors
    /// The message from [`AutheliaVerifier::new`].
    pub fn from_env() -> Result<Option<Self>, String> {
        let Ok(origin) = std::env::var("FERRUMD_SSO_ORIGIN") else {
            return Ok(None);
        };
        if origin.trim().is_empty() {
            return Ok(None);
        }
        let address = std::env::var("FERRUMD_AUTHELIA_ADDRESS")
            .unwrap_or_else(|_| DEFAULT_AUTHELIA_ADDRESS.to_string());
        Self::new(address, origin).map(Some)
    }

    /// Asks Authelia about one cookie header.
    ///
    /// # Arguments
    /// * `cookie` - the request's own `Cookie` header, verbatim, or `None`.
    ///
    /// # Returns
    /// The [`Assertion`]. Never panics and never propagates an error: every
    /// failure to ask is an [`Assertion::Unavailable`] carrying the reason,
    /// because a caller that had to handle both an `Err` and an `Unavailable`
    /// would eventually handle one of them as the other.
    pub async fn verify(&self, cookie: Option<&str>) -> Assertion {
        match tokio::time::timeout(VERIFY_TIMEOUT, self.ask(cookie)).await {
            Ok(Ok(assertion)) => assertion,
            Ok(Err(reason)) => Assertion::Unavailable(reason),
            Err(_) => Assertion::Unavailable(format!(
                "Authelia at {} did not answer within {}s",
                self.address,
                VERIFY_TIMEOUT.as_secs()
            )),
        }
    }

    /// One fixed-shape HTTP/1.1 request to Authelia, and its answer.
    ///
    /// # Arguments
    /// * `cookie` - the caller's `Cookie` header, or `None` to ask about an
    ///   anonymous request.
    ///
    /// # Errors
    /// A string naming the transport or protocol problem. A refused or
    /// unparseable answer is an error here and becomes
    /// [`Assertion::Unavailable`] in [`AutheliaVerifier::verify`]; it is never
    /// an identity and never an anonymous verdict.
    async fn ask(&self, cookie: Option<&str>) -> Result<Assertion, String> {
        // Belt to axum's braces. `HeaderValue` already refuses control
        // characters, so a cookie carrying CR or LF cannot reach here through
        // the router -- which is asserted in this module's own tests. This
        // guard is what makes that a property of THIS function rather than of
        // its only current caller, because a request smuggled past it would
        // let the caller write their own extra headers into the question
        // ferrum asks Authelia.
        if let Some(value) = cookie {
            if !header_safe(value) {
                return Err("the caller's Cookie header is not representable in a request".into());
            }
        }

        let mut request = String::new();
        request.push_str(&format!("GET {VERIFY_PATH} HTTP/1.1\r\n"));
        request.push_str(&format!("Host: {}\r\n", self.address));
        request.push_str(&format!("X-Original-URL: {}\r\n", self.original_url));
        if let Some(value) = cookie {
            request.push_str(&format!("Cookie: {value}\r\n"));
        }
        request.push_str("Accept: */*\r\n");
        // `Connection: close` makes the response self-delimiting: Authelia
        // closes the socket when it is done, so this reads to EOF and needs
        // no chunked-transfer or Content-Length handling at all.
        request.push_str("Connection: close\r\n\r\n");

        let mut stream = tokio::net::TcpStream::connect(&self.address)
            .await
            .map_err(|e| format!("could not reach Authelia at {}: {e}", self.address))?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("could not send to Authelia at {}: {e}", self.address))?;

        let mut raw = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream
                .read(&mut buffer)
                .await
                .map_err(|e| format!("could not read from Authelia at {}: {e}", self.address))?;
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..read]);
            if raw.len() > RESPONSE_LIMIT {
                return Err(format!(
                    "whatever is listening at {} sent more than {RESPONSE_LIMIT} bytes for a verify response",
                    self.address
                ));
            }
            // The status line and headers are all this needs, and Authelia's
            // body is an error page nobody reads. Stopping at the blank line
            // keeps a large body from being buffered for nothing.
            if find_header_end(&raw).is_some() {
                break;
            }
        }
        parse_response(&raw)
    }
}

/// Whether a string can be put in an HTTP header without changing the shape of
/// the request.
///
/// CR and LF are the whole of the concern -- they are what turns one header
/// into two -- and a NUL is rejected with them because it has no business in a
/// header either.
///
/// # Arguments
/// * `value` - the candidate header value.
///
/// # Returns
/// `true` when the value is safe to interpolate.
fn header_safe(value: &str) -> bool {
    !value.contains(['\r', '\n', '\0'])
}

/// The index just past the blank line that ends an HTTP head, if it has
/// arrived.
///
/// # Arguments
/// * `raw` - the bytes read so far.
///
/// # Returns
/// `Some(index)` of the first byte of the body, or `None` while the head is
/// still incomplete.
fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Reads Authelia's answer into an [`Assertion`].
///
/// # Arguments
/// * `raw` - the bytes of the response, head at minimum.
///
/// # Returns
/// [`Assertion::Identified`] only for a `200` that names a non-empty user;
/// [`Assertion::Anonymous`] for the refusals Authelia actually sends.
///
/// # Errors
/// A string naming the problem for an answer that is not an HTTP response, or
/// whose status this module has no rule for -- which becomes
/// [`Assertion::Unavailable`] rather than a verdict.
fn parse_response(raw: &[u8]) -> Result<Assertion, String> {
    let end = find_header_end(raw).ok_or("Authelia's answer ended before its headers did")?;
    let head = std::str::from_utf8(&raw[..end])
        .map_err(|_| "Authelia's answer is not valid UTF-8".to_string())?;
    let mut lines = head.lines();
    let status_line = lines.next().ok_or("Authelia's answer had no status line")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("Authelia's answer had no status code: {status_line:?}"))?;

    match status {
        200 => {
            // A `200` with no identity is Authelia answering for a `bypass`
            // policy: the request is allowed and belongs to nobody.
            // `modules/proxy/lib.nix` gives the daemon `one_factor` and no
            // bypassPaths precisely so this does not arise -- but reading an
            // absent header as an empty username would authenticate a caller
            // as the empty account, so it is a verdict rather than a gap.
            match identity_header_value(head) {
                Some(username) if !username.is_empty() => {
                    Ok(Assertion::Identified { username: username.to_string() })
                }
                _ => Ok(Assertion::Anonymous),
            }
        }
        // Authelia's refusals. `401` is what it answers an unauthenticated
        // verify (measured); `403` is an authenticated caller the policy
        // denies; a `3xx` is "go and log in", which is the same fact in
        // redirect form.
        401 | 403 | 300..=399 => Ok(Assertion::Anonymous),
        other => Err(format!("Authelia answered {other}, which is neither an identity nor a refusal")),
    }
}

/// The identity Authelia named in its response head, if it named one.
///
/// Split out so the lookup can be tested on its own: every assertion that
/// feeds it is about which branch was taken, and a matcher that found nothing
/// would make the anonymous branch look correct forever.
///
/// # Arguments
/// * `head` - the response status line and headers.
///
/// # Returns
/// The trimmed header value, or `None` when the response named no identity.
fn identity_header_value(head: &str) -> Option<&str> {
    // Case-insensitive, because HTTP header names are (RFC 9110 5.1) and
    // Authelia's own spelling is not this module's to depend on.
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case(IDENTITY_HEADER))
        .map(|(_, value)| value.trim())
}

/// The response header Authelia names its subject in.
///
/// This constant is the ONE place in this crate that spells a forward-auth
/// header, and `main.rs`'s source scan is what keeps it that way: every other
/// file is still forbidden from naming one, and this file is forbidden from
/// naming it anywhere but here. It is a header on Authelia's **answer to a
/// question ferrumd asked**, not a header on a request ferrumd received, and
/// that distinction is the entire security argument of this module.
const IDENTITY_HEADER: &str = "remote-user";

/// The body `POST /api/sso` answers with on success.
///
/// Deliberately the same shape as `POST /api/login`'s: the UI's two paths into
/// a session then differ only in which call it made, and a field added to one
/// and not the other would be a bug the UI finds at runtime.
#[derive(serde::Serialize)]
pub struct SsoResponse {
    /// The CSRF token this new session's mutating requests must carry.
    pub csrf_token: String,
}

/// `POST /api/sso` -- exchange an Authelia session for a ferrumd session.
///
/// Unauthenticated by ferrumd's own session on purpose, exactly as
/// `POST /api/login` is: it is the call you make when you do not have one.
/// What it is not is unauthenticated -- the caller must present a cookie
/// Authelia accepts for the control plane's own scope.
///
/// # Arguments
/// * `state` - the daemon's shared state; `state.sso` is `None` on a host with
///   no SSO.
/// * `peer` - the socket peer, for the audit line.
/// * `cookies` - the cookie jar, used only to set the new session cookie.
/// * `headers` - the request headers; the `Cookie` header is passed through to
///   Authelia and nothing else is read from them.
///
/// # Returns
/// * `200` with [`SsoResponse`] and a `Set-Cookie`, on success.
/// * `404` when this host has no SSO configured at all.
/// * `401` when Authelia recognises nobody.
/// * `403` when Authelia recognises somebody ferrumd has no account for.
/// * `503` when Authelia could not be asked.
pub async fn sso_handler(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    cookies: tower_cookies::Cookies,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    let client = ClientAddr::resolve(peer.map(|p| p.0), &headers);
    let Some(verifier) = state.sso.as_ref() else {
        // Not an error and not a refusal: this host does not publish the
        // dashboard, or runs no Authelia. The UI reads the 404 as "there is
        // no SSO here" and shows the password form, which is the only way in
        // on a tunnel-only recovery host and must stay that way.
        return (StatusCode::NOT_FOUND, "single sign-on is not configured on this host")
            .into_response();
    };

    let cookie = headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok());

    let username = match verifier.verify(cookie).await {
        Assertion::Identified { username } => username,
        Assertion::Anonymous => {
            audit::record("sso", "failure", "", &client, "Authelia recognised no session");
            return StatusCode::UNAUTHORIZED.into_response();
        }
        Assertion::Unavailable(reason) => {
            audit::record("sso", "error", "", &client, &reason);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "could not reach the single sign-on service -- log in with your ferrum password",
            )
                .into_response();
        }
    };

    let asserted = username.clone();
    let outcome = match run_blocking(move || auth::start_sso_session(&state.db, &asserted)).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(e)) => {
            audit::record("sso", "error", &username, &client, &format!("{e}"));
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(status) => {
            audit::record("sso", "error", &username, &client, "blocking task failed");
            return status.into_response();
        }
    };

    match outcome {
        auth::SsoSessionOutcome::Started(result) => {
            // Byte-for-byte the cookie `login_handler` sets, built the same
            // way. The `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`
            // and `Path=/` are all load-bearing and all explained on
            // `SESSION_COOKIE`; a second spelling here would be a second place
            // for one of them to go missing.
            let mut cookie = tower_cookies::Cookie::new(SESSION_COOKIE, result.session_token);
            cookie.set_http_only(true);
            cookie.set_secure(true);
            cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            cookie.set_path("/");
            cookies.add(cookie);
            audit::record("sso", "success", &username, &client, "");
            (StatusCode::OK, Json(SsoResponse { csrf_token: result.csrf_token })).into_response()
        }
        auth::SsoSessionOutcome::NoSuchUser => {
            // Refuse, every time, rather than provisioning. See
            // `auth::start_sso_session` for the reasoning; the one thing this
            // handler adds is that the message names the identity, because an
            // operator reading "403" with no subject cannot tell a
            // misconfiguration from a rejection.
            audit::record("sso", "failure", &username, &client, "no ferrumd account of that name");
            (
                StatusCode::FORBIDDEN,
                format!(
                    "signed in to single sign-on as {username}, and this ferrum has no account \
                     of that name. ferrum never creates one from an Authelia identity. Log in \
                     with your ferrum password, or rename the Authelia user to match."
                ),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
pub mod testing {
    //! A fake Authelia, so no test here depends on a real one.
    //!
    //! The same shape, and for the same reason, as `ferrum-dns`'s
    //! `FakeCloudflare`: the Nix derivation that runs this suite builds with
    //! no network, and the surface needed is one HTTP/1.1 request in and one
    //! scripted response out. It is a REAL `std::net::TcpListener` rather than
    //! a trait seam on purpose -- the thing most worth testing in this module
    //! is the hand-rolled client, and a seam would replace exactly the code
    //! that needs exercising.

    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// An Authelia `200` naming `user`.
    ///
    /// Built from [`super::IDENTITY_HEADER`] rather than spelled out, and that
    /// is not style: `main.rs`'s source scan permits this crate to name a
    /// forward-auth header on exactly ONE line, the constant's own
    /// declaration. A literal here would spend that allowance on a test
    /// fixture and blunt the scan for the code it exists to watch.
    ///
    /// # Arguments
    /// * `user` - the identity Authelia should claim.
    ///
    /// # Returns
    /// A complete HTTP/1.1 response head, CRLF-terminated.
    pub fn authenticated_as(user: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\n{}: {user}\r\nContent-Length: 0\r\n\r\n",
            super::IDENTITY_HEADER
        )
    }

    /// One scripted answer, and the request that provoked it.
    pub struct FakeAuthelia {
        /// `host:port` to point an [`super::AutheliaVerifier`] at.
        pub address: String,
        /// The request head the fake received, once it has served one.
        requests: mpsc::Receiver<String>,
    }

    impl FakeAuthelia {
        /// Starts a fake that answers every connection with `response`.
        ///
        /// # Arguments
        /// * `response` - the bytes to write back, status line included, with
        ///   CRLF line endings. An owned `String` rather than a `&'static str`
        ///   so a caller can build one from [`super::IDENTITY_HEADER`] instead
        ///   of spelling that header out -- which is what keeps `main.rs`'s
        ///   source scan able to insist the crate names it on exactly one line.
        ///
        /// # Returns
        /// The running fake. It serves connections until dropped.
        pub fn serving(response: String) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("fake Authelia must bind");
            let address = listener.local_addr().unwrap().to_string();
            let (tx, requests) = mpsc::channel();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    // Read exactly the head: the verifier sends no body, and
                    // reading past the blank line would block until it closed.
                    while stream.read(&mut byte).map(|n| n == 1).unwrap_or(false) {
                        head.push(byte[0]);
                        if head.ends_with(b"\r\n\r\n") {
                            break;
                        }
                    }
                    let _ = tx.send(String::from_utf8_lossy(&head).to_string());
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            });
            Self { address, requests }
        }

        /// Starts a listener that accepts a connection and closes it without
        /// answering, so the transport-failure path can be driven.
        pub fn refusing() -> Self {
            Self::serving(String::new())
        }

        /// The head of the request the fake received.
        ///
        /// # Panics
        /// If no request arrived, which means the assertion that follows would
        /// have been about nothing.
        pub fn received(&self) -> String {
            self.requests
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the verifier must actually have sent a request")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeAuthelia;
    use super::*;

    fn verifier(address: &str) -> AutheliaVerifier {
        AutheliaVerifier::new(address.to_string(), "https://ferrum.example.test".to_string())
            .expect("the fixture configuration must be valid")
    }

    const REFUSED: &str = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";

    #[tokio::test]
    async fn a_recognised_cookie_yields_the_identity_authelia_named() {
        let fake = FakeAuthelia::serving(super::testing::authenticated_as("admin"));
        let assertion = verifier(&fake.address).verify(Some("ferrum_control_session=x")).await;
        assert_eq!(assertion, Assertion::Identified { username: "admin".to_string() });
    }

    /// The question matters as much as the answer. Authelia decides which
    /// cookie scope applies from `X-Original-URL`, so if this module took that
    /// from the request instead of from the host's own configuration, a local
    /// process could name an app's hostname and have an apps-scoped cookie
    /// accepted -- handing back exactly what R5's first half established.
    #[tokio::test]
    async fn the_question_names_the_dashboard_and_forwards_the_callers_cookie() {
        let fake = FakeAuthelia::serving(super::testing::authenticated_as("admin"));
        let _ = verifier(&fake.address).verify(Some("ferrum_control_session=opaque")).await;
        let sent = fake.received();
        assert!(sent.starts_with("GET /api/verify HTTP/1.1\r\n"), "{sent}");
        assert!(
            sent.contains("X-Original-URL: https://ferrum.example.test/\r\n"),
            "the question must name the dashboard's own origin: {sent}"
        );
        assert!(sent.contains("Cookie: ferrum_control_session=opaque\r\n"), "{sent}");
    }

    #[tokio::test]
    async fn a_refusal_is_anonymous_rather_than_an_error() {
        let fake = FakeAuthelia::serving(REFUSED.to_string());
        assert_eq!(verifier(&fake.address).verify(Some("stale=1")).await, Assertion::Anonymous);
    }

    /// With no cookie there is nothing to ask about, and the request must
    /// carry no `Cookie` header at all rather than an empty one.
    #[tokio::test]
    async fn no_cookie_asks_an_anonymous_question() {
        let fake = FakeAuthelia::serving(REFUSED.to_string());
        assert_eq!(verifier(&fake.address).verify(None).await, Assertion::Anonymous);
        assert!(!fake.received().contains("Cookie:"));
    }

    /// The failure that must never look like a verdict. An Authelia that is
    /// not listening is not an Authelia saying "nobody": the first leaves an
    /// operator's session alone and answers 503, the second logs them out.
    #[tokio::test]
    async fn an_unreachable_authelia_is_unavailable_and_not_anonymous() {
        // Bind and immediately drop, so the port is one nothing is listening
        // on -- a closed port rather than a timeout, which is what a stopped
        // authelia-main.service actually presents.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        drop(listener);
        let assertion = verifier(&address).verify(Some("x=1")).await;
        assert!(
            matches!(assertion, Assertion::Unavailable(_)),
            "an unreachable Authelia must not authenticate or de-authenticate anyone: {assertion:?}"
        );
    }

    #[tokio::test]
    async fn a_connection_closed_without_an_answer_is_unavailable() {
        let fake = FakeAuthelia::refusing();
        let assertion = verifier(&fake.address).verify(Some("x=1")).await;
        assert!(matches!(assertion, Assertion::Unavailable(_)), "{assertion:?}");
    }

    /// A 200 with no identity is Authelia answering for a bypass policy. The
    /// daemon's own rule is one_factor so it should not arise -- and reading
    /// the absent header as an empty username would authenticate a caller as
    /// the empty account, which is why it is a tested verdict rather than an
    /// assumption.
    #[tokio::test]
    async fn an_allowed_but_unidentified_request_authenticates_nobody() {
        let fake = FakeAuthelia::serving("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string());
        assert_eq!(verifier(&fake.address).verify(Some("x=1")).await, Assertion::Anonymous);
    }

    #[tokio::test]
    async fn an_empty_identity_authenticates_nobody() {
        let fake = FakeAuthelia::serving(super::testing::authenticated_as("   "));
        assert_eq!(verifier(&fake.address).verify(Some("x=1")).await, Assertion::Anonymous);
    }

    #[tokio::test]
    async fn a_status_this_module_has_no_rule_for_is_unavailable() {
        let fake = FakeAuthelia::serving("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_string());
        let assertion = verifier(&fake.address).verify(Some("x=1")).await;
        assert!(matches!(assertion, Assertion::Unavailable(_)), "{assertion:?}");
    }

    /// Response heads that DO name an identity, each on its own line starting
    /// with a quote.
    ///
    /// A table rather than inline arguments, for the same reason `main.rs`'s
    /// `READS_A_HEADER` is one: the source scan reads this file, and a fixture
    /// written inline would be a line of sso.rs naming a forward-auth header
    /// somewhere other than its one permitted declaration -- the scan would
    /// dutifully report its own positive control as a violation. A line
    /// beginning with a quote is the exemption that table already relies on.
    const HEADS_NAMING_A_USER: &[&str] = &[
        "HTTP/1.1 200 OK\r\nremote-user: alice\r\n\r\n",
        "HTTP/1.1 200 OK\r\nREMOTE-USER: alice\r\n\r\n",
        "HTTP/1.1 200 OK\r\nRemote-User:alice\r\n\r\n",
    ];

    /// Response heads that name no identity, including the one that looks most
    /// like it does.
    const HEADS_NAMING_NOBODY: &[&str] = &[
        "HTTP/1.1 200 OK\r\nRemote-Email: a@b.c\r\n\r\n",
        "HTTP/1.1 200 remote-user: nobody\r\n\r\n",
    ];

    /// The positive control the anonymous assertions above have none of.
    ///
    /// Every one of them is "the matcher found nothing", so without this the
    /// matcher itself is untested: it could return `None` unconditionally and
    /// each of those tests would go on passing for entirely the wrong reason.
    #[test]
    fn the_identity_matcher_reads_the_header_however_it_is_spelled() {
        for head in HEADS_NAMING_A_USER {
            assert_eq!(identity_header_value(head), Some("alice"), "missed a real identity: {head:?}");
        }
        for head in HEADS_NAMING_NOBODY {
            assert_eq!(identity_header_value(head), None, "found an identity that is not one: {head:?}");
        }
    }

    #[test]
    fn a_header_value_cannot_carry_a_newline_at_all() {
        // The http layer's own defence, pinned here because `ask`'s
        // `header_safe` guard is otherwise unreachable through the router and
        // would read as dead code to the next person.
        assert!(
            "x=1\r\nX-Original-URL: https://sonarr.example.test/"
                .parse::<axum::http::HeaderValue>()
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_cookie_that_could_forge_a_header_is_refused_rather_than_sent() {
        let fake = FakeAuthelia::serving(super::testing::authenticated_as("admin"));
        let assertion = verifier(&fake.address)
            .verify(Some("x=1\r\nX-Original-URL: https://sonarr.example.test/"))
            .await;
        assert!(
            matches!(assertion, Assertion::Unavailable(_)),
            "a cookie that would rewrite the question must not be asked: {assertion:?}"
        );
    }

    #[test]
    fn a_configuration_that_cannot_work_is_refused_at_construction() {
        assert!(AutheliaVerifier::new(String::new(), "https://a.test".into()).is_err());
        assert!(AutheliaVerifier::new("127.0.0.1:1".into(), String::new()).is_err());
        // Not a URL: Authelia matches access_control rules against one, so a
        // bare hostname would silently meet the deny default policy.
        assert!(AutheliaVerifier::new("127.0.0.1:1".into(), "ferrum.example.test".into()).is_err());
        assert!(AutheliaVerifier::new("127.0.0.1:1".into(), "https://a.test\r\nX: y".into()).is_err());
    }

    #[test]
    fn the_original_url_always_ends_in_exactly_one_slash() {
        let with = AutheliaVerifier::new("127.0.0.1:1".into(), "https://a.test/".into()).unwrap();
        let without = AutheliaVerifier::new("127.0.0.1:1".into(), "https://a.test".into()).unwrap();
        assert_eq!(with.original_url, "https://a.test/");
        assert_eq!(without.original_url, "https://a.test/");
    }
}
