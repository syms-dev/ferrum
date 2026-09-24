mod audit;
mod auth;
mod catalog;
mod client_addr;
mod db;
mod dbus;
mod generations;
mod jobs;
mod secrets_api;
mod settings;
mod static_files;
mod updates;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};

pub struct AppState {
    pub db: db::Db,
    /// ferrumd's own single-job interlock -- see jobs::create_job.
    /// Reconciled against systemd's real view of whether a
    /// `ferrum-apply@*.service` is running (see `reconcile_interlock` and
    /// dbus::ferrum_apply_job_is_running) from inside the JobRemoved
    /// subscription, so a ferrumd restarted mid-apply by its own generation
    /// switch does not admit a second job -- and so a completion missed
    /// while the listener was detached does not leave it held forever.
    /// Cleared both by ferrum-apply finishing (via systemd's JobRemoved
    /// signal, below) and, on the failure paths, by create_job itself.
    pub job_running: Mutex<bool>,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    csrf_token: String,
}

/// The session cookie's name.
///
/// The `__Host-` prefix is a security control, not a naming convention
/// (A4/D3). A browser refuses any `__Host-` cookie that carries a `Domain`
/// attribute, or that is not `Secure` with `Path=/`. That refusal is what
/// defends the control plane once it is published at
/// `ferrum.<baseDomain>`: a compromised sibling such as
/// `sonarr.<baseDomain>` is same-site, and can answer one of its own
/// requests with `Set-Cookie: <name>=...; Domain=<baseDomain>; Path=/`.
/// `HttpOnly` does not stop that -- it blocks JavaScript reads, not an
/// inbound `Set-Cookie` -- and RFC 6265 leaves it unspecified which of two
/// same-named cookies the browser then sends, while `require_session` does
/// a single lookup by name. Under the prefix the planted cookie is never
/// stored at all.
const SESSION_COOKIE: &str = "__Host-ferrumd_session";

/// Moves blocking work off the async executor and onto tokio's blocking pool.
///
/// Almost everything ferrumd does behind a request is synchronous: rusqlite
/// blocks the calling thread for the whole query, argon2id verification is
/// deliberately expensive CPU work, and `std::fs` blocks on the disk. Called
/// directly from an `async fn` each of those occupies one of tokio's worker
/// threads for its entire duration, and that pool is sized to the core count
/// -- so a handful of concurrent logins can starve every other request on the
/// daemon, including the SSE stream an operator is watching an apply through.
/// On a small box "a handful" is two or three.
///
/// What this does NOT do is change how the database mutex is held. The guard
/// discipline in this crate is already correct -- no `MutexGuard` crosses an
/// `.await` anywhere, which is why the usual deadlock shape is absent here --
/// and moving the same synchronous calls to a different thread preserves that
/// property rather than reopening it.
///
/// A panic inside `f` (a poisoned database mutex, most plausibly) arrives as
/// a `JoinError` instead of unwinding the caller, so it becomes a 500 rather
/// than taking the daemon down with it.
async fn run_blocking<F, T>(f: F) -> Result<T, StatusCode>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let client = client_addr::ClientAddr::resolve(peer.map(|p| p.0), &headers);
    // The submitted username is audited, so a failed attempt records WHICH
    // account was tried. `audit::record` escapes it -- it is caller-supplied
    // and could otherwise forge a log line.
    let username = req.username.clone();
    // The whole `ClientAddr`, not a pre-derived key string: the throttle
    // needs both of its axes (client_addr.rs, SEC-03), and handing it the
    // one value the audit line also uses keeps the two from disagreeing
    // about who this was.
    let throttled_as = client.clone();
    let outcome = run_blocking(move || {
        auth::login(&state.db, &req.username, &req.password, &throttled_as)
    })
    .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(status) => {
            audit::record("login", "error", &username, &client, "blocking task failed");
            return status.into_response();
        }
    };
    match outcome {
        Ok(auth::LoginOutcome::Success(result)) => {
            let mut cookie = Cookie::new(SESSION_COOKIE, result.session_token);
            cookie.set_http_only(true);
            cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            cookie.set_path("/");
            cookie.set_secure(true);
            cookies.add(cookie);
            audit::record("login", "success", &username, &client, "");
            (StatusCode::OK, Json(LoginResponse { csrf_token: result.csrf_token })).into_response()
        }
        Ok(auth::LoginOutcome::BadCredentials) => {
            audit::record("login", "failure", &username, &client, "bad credentials");
            StatusCode::UNAUTHORIZED.into_response()
        }
        Ok(auth::LoginOutcome::Throttled) => {
            audit::record("login", "denied", &username, &client, "source throttled");
            (
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed login attempts -- try again shortly",
            )
                .into_response()
        }
        // L-03. This arm used to be 429 carrying `e.to_string()`, so a
        // database fault answered with the wrong status AND spilled its
        // internal detail -- on the one unauthenticated endpoint the
        // internet can reach. The detail goes to the journal, where an
        // operator can read it and a caller cannot.
        Err(e) => {
            eprintln!("ferrumd: login failed: {e:#}");
            audit::record("login", "error", &username, &client, "daemon fault");
            (StatusCode::INTERNAL_SERVER_ERROR, "login failed").into_response()
        }
    }
}

/// The cookie `logout_handler` hands to `tower_cookies::Cookies::remove`.
///
/// `remove` expires whatever it is given rather than synthesising its own
/// attributes, so the removal `Set-Cookie` has to satisfy the `__Host-`
/// rules exactly as the login one does. Built here instead of inline so
/// the two cannot drift: a removal cookie the browser refuses revokes
/// nothing client-side, and nothing about the 200 it returns would say so.
fn removal_cookie() -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE, "");
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie
}

/// Resolves its own client address and account name rather than reading the
/// extensions `require_session` publishes, because this route is NOT behind
/// that middleware -- see the L-01 note in `build_router`. Taking them from
/// extensions here would compile and then fail at runtime with "Missing
/// request extension" on every logout.
async fn logout_handler(
    State(state): State<Arc<AppState>>,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    cookies: Cookies,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let client = client_addr::ClientAddr::resolve(peer.map(|p| p.0), &headers);
    let mut user = UNKNOWN_USER.to_string();
    if let Some(cookie) = cookies.get(SESSION_COOKIE) {
        let token = cookie.value().to_string();
        // One hop to the blocking pool for both: read who this session
        // belongs to (so the audit line names an account rather than a
        // token), then delete it.
        if let Ok(resolved) = run_blocking(move || {
            let name = auth::validate_session(&state.db, &token)
                .ok()
                .flatten()
                .and_then(|session| session.username);
            let _ = auth::logout(&state.db, &token);
            name
        })
        .await
        {
            user = resolved.unwrap_or_else(|| UNKNOWN_USER.to_string());
        }
    }
    cookies.remove(removal_cookie());
    audit::record("logout", "success", &user, &client, "");
    StatusCode::OK
}

/// The authenticated caller's own user id, put into the request's
/// extensions by `require_session` from the SAME session row it validated
/// the CSRF header against.
///
/// A newtype rather than a bare `i64` on purpose: axum resolves
/// `Extension<T>` by type, so a bare integer would collide with any other
/// integer a future layer inserts, and the collision would be silent.
#[derive(Clone, Copy, Debug)]
struct SessionUserId(i64);

/// The CSRF token of the session `require_session` just authenticated.
///
/// A second extension rather than a widened `SessionUserId`, so that type
/// keeps meaning exactly one thing and `POST /api/password`'s extractor is
/// untouched. `GET /api/session` reads the token from HERE, never from
/// anything on the wire -- the same rule require_session states for the
/// user id, and for the same reason.
#[derive(Clone)]
struct SessionCsrfToken(String);

/// The session cookie value `require_session` just authenticated.
///
/// `POST /api/password` needs it to know which session is its OWN, so that
/// invalidating every other session for the account does not log the caller
/// out of the tab they are standing in. A third newtype rather than widening
/// either of the two above, for the reason the second one already gives:
/// axum resolves `Extension<T>` by type, so each value keeps meaning exactly
/// one thing.
///
/// This is the session token, so it never goes anywhere near a log line.
#[derive(Clone)]
struct SessionToken(String);

/// The authenticated account's name, from the same row `require_session`
/// read everything else out of.
///
/// `None` means the session referenced a user row that no longer exists --
/// see `auth::SessionInfo::username` for why that is kept distinguishable
/// rather than flattened.
///
/// This is what every audit line's `user=` field comes from, so it is read
/// from the authenticated session and never from anything on the wire. The
/// one place a caller-supplied username is logged is a LOGIN attempt, where
/// by definition there is no session yet -- and `audit::record` escapes it.
#[derive(Clone)]
struct SessionUsername(Option<String>);

/// The name used in an audit line when the session's user row has vanished.
const UNKNOWN_USER: &str = "<unknown>";

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

/// Rotates the CALLER'S OWN password. There is no user-id parameter on the
/// wire on purpose: the account to change is taken from the session, so
/// this endpoint cannot be pointed at somebody else's account even by an
/// authenticated caller who is willing to forge a body.
///
/// Three distinct outcomes, deliberately not collapsed:
///   * `400` -- the request is malformed (an empty new password).
///   * `401` -- the current password is wrong. Nothing changed.
///   * `500` -- the daemon genuinely failed (database, hashing).
///
/// Every OTHER session for this account is invalidated; this one survives.
///
/// This used to invalidate nothing at all, and the reasoning recorded here
/// was that the cookie is an independent credential and logging the operator
/// out of their own tab would be a worse experience for no gain. The first
/// half is still true and is why the caller's own session is kept. The
/// second half was wrong about the threat (M-03): changing the password is
/// precisely what an operator does when they think their credential has been
/// taken, and leaving every other session valid meant a stolen one survived
/// the single remedy they would reach for -- for the remainder of its week.
/// Now that the control plane is published, that is not hypothetical.
async fn change_password_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(SessionUserId(user_id)): axum::Extension<SessionUserId>,
    axum::Extension(SessionToken(token)): axum::Extension<SessionToken>,
    axum::Extension(SessionUsername(username)): axum::Extension<SessionUsername>,
    axum::Extension(client): axum::Extension<client_addr::ClientAddr>,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let user = username.as_deref().unwrap_or(UNKNOWN_USER).to_string();
    if req.new_password.is_empty() {
        audit::record("password-change", "failure", &user, &client, "empty new password");
        return (StatusCode::BAD_REQUEST, "the new password must not be empty").into_response();
    }
    let throttled_as = client.clone();
    let outcome = run_blocking(move || {
        auth::change_password(
            &state.db,
            user_id,
            &req.current_password,
            &req.new_password,
            &token,
            &throttled_as,
        )
    })
    .await;
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(status) => return status.into_response(),
    };
    match outcome {
        Ok(auth::PasswordChangeOutcome::Changed) => {
            audit::record(
                "password-change",
                "success",
                &user,
                &client,
                "other sessions for this account were invalidated",
            );
            StatusCode::OK.into_response()
        }
        Ok(auth::PasswordChangeOutcome::WrongPassword) => {
            audit::record(
                "password-change",
                "failure",
                &user,
                &client,
                "current password incorrect",
            );
            (StatusCode::UNAUTHORIZED, "the current password is incorrect").into_response()
        }
        // SEC-06. Same status and same shape as the login throttle's 429,
        // carrying no internal detail: this endpoint is an oracle on
        // `current_password` and an unbounded argon2 handle, and neither
        // nginx's `limit_req` nor anything else covered it.
        Ok(auth::PasswordChangeOutcome::Throttled) => {
            audit::record("password-change", "denied", &user, &client, "source throttled");
            (
                StatusCode::TOO_MANY_REQUESTS,
                "too many failed attempts -- try again shortly",
            )
                .into_response()
        }
        // SEC-09, and the same treatment L-03 gave `login_handler`: the
        // error text can name a filesystem path or a database internal, so
        // it goes to the journal where an operator can read it, and the
        // caller gets a fixed string.
        Err(e) => {
            eprintln!("ferrumd: password change failed: {e:#}");
            audit::record("password-change", "error", &user, &client, "daemon fault");
            (StatusCode::INTERNAL_SERVER_ERROR, "failed to change the password").into_response()
        }
    }
}

/// The header a mutating request must carry, echoing back the CSRF token
/// `POST /api/login` handed out.
const CSRF_HEADER: &str = "X-CSRF-Token";

/// True for the methods that can actually change server state, and so must
/// prove the caller can READ the login response -- which a cross-origin
/// attacker forging a request from the operator's browser cannot do, even
/// though the browser would happily attach the session cookie for them.
///
/// `GET`/`HEAD` are excluded because they change nothing; `OPTIONS`/`TRACE`
/// likewise. Anything else is treated as mutating, so a method added to a
/// route later is protected by default rather than by remembering to come
/// back here.
fn method_is_mutating(method: &axum::http::Method) -> bool {
    !matches!(
        *method,
        axum::http::Method::GET
            | axum::http::Method::HEAD
            | axum::http::Method::OPTIONS
            | axum::http::Method::TRACE
    )
}

/// Whole-value equality against the session's own stored token, with a
/// missing header failing closed.
///
/// Spelled out as its own function mostly so the tests can pin the shapes
/// that a sloppier check would wave through: a prefix, a suffix, an empty
/// header, and the empty string as a wildcard. Not constant-time on
/// purpose -- reaching this code already requires a valid session cookie,
/// so there is no unauthenticated oracle to time, and the value being
/// compared is a per-session anti-forgery nonce rather than a long-lived
/// authentication secret.
fn csrf_header_is_valid(header: Option<&str>, session_csrf: &str) -> bool {
    match header {
        // A session whose stored token is somehow empty must not become a
        // session where any request passes.
        _ if session_csrf.is_empty() => false,
        Some(provided) => provided == session_csrf,
        None => false,
    }
}

/// Authenticates the session cookie AND, for mutating methods, validates
/// the CSRF header against the SAME session lookup.
///
/// Until the branch-wide final review of Phase 1.5a this discarded the
/// token `validate_session` returns (`Ok(Some(_csrf))`), so the CSRF
/// protection the spec describes did not exist at all: every mutating
/// endpoint was defended only by the session cookie's `SameSite=Strict`
/// attribute. That is a real defence, but it is one control in one place,
/// enforced by the browser rather than by the server.
///
/// The two failure modes are deliberately different status codes:
/// `401 Unauthorized` means "you have not proven who you are" (no cookie,
/// expired or unknown session), while `403 Forbidden` means "you are
/// authenticated, and this particular request is refused" -- which is
/// exactly what a missing or wrong CSRF header is. Collapsing both into 401
/// would tell a legitimate client to re-authenticate when re-authenticating
/// is not the fix.
async fn require_session(
    State(state): State<Arc<AppState>>,
    cookies: tower_cookies::Cookies,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let headers = request.headers().clone();
    let token = cookies
        .get(SESSION_COOKIE)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .value()
        .to_string();
    let db_state = state.clone();
    let lookup_token = token.clone();
    let session =
        match run_blocking(move || auth::validate_session(&db_state.db, &lookup_token)).await? {
            Ok(Some(session)) => session,
            _ => return Err(StatusCode::UNAUTHORIZED),
        };

    if method_is_mutating(request.method()) {
        let provided = request
            .headers()
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok());
        if !csrf_header_is_valid(provided, &session.csrf_token) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Handlers that act on "the caller's own account" (POST /api/password)
    // read the id from here rather than from anything on the wire, so the
    // account being acted on is always the one this middleware just
    // authenticated.
    request.extensions_mut().insert(SessionUserId(session.user_id));
    request
        .extensions_mut()
        .insert(SessionCsrfToken(session.csrf_token.clone()));
    request.extensions_mut().insert(SessionToken(token));
    request
        .extensions_mut()
        .insert(SessionUsername(session.username.clone()));
    // Resolved here, once, from the request's own ConnectInfo rather than
    // re-extracted in each handler -- so every audited route behind this
    // middleware agrees about where the caller is, and there is one place
    // that decides what may be trusted.
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|info| info.0);
    request
        .extensions_mut()
        .insert(client_addr::ClientAddr::resolve(peer, &headers));

    Ok(next.run(request).await)
}

/// The real application router, built separately from `main` so the tests
/// at the bottom of this file exercise the REAL middleware stack (cookie
/// layer, `require_session`, the actual routes) rather than a re-declared
/// approximation of it.
/// `GET /api/session` -- who am I, and what CSRF token do my mutating
/// requests need?
///
/// The UI gets both at login, but a page reload loses them while the session
/// cookie survives (it is HttpOnly, so JavaScript can never read it back).
/// Without this endpoint a refreshed tab is authenticated yet unable to make
/// a single mutating request, and would have to force a pointless re-login.
///
/// Handing out the CSRF token is safe here because two independent things
/// stop another origin from reading it, and this endpoint depends on BOTH:
///   1. the session cookie is `SameSite=Strict` (see `login_handler`), so a
///      cross-site request never carries it and gets a 401; and
///   2. ferrumd installs no CORS layer at all, so the browser's same-origin
///      policy stops a cross-origin page reading the response body.
///
/// Control 2 is the load-bearing one, and it is worth being precise about
/// why. `SameSite` is scoped to the registrable SITE, not the origin -- and
/// the dashboard now has a site to share. `modules/proxy/nginx.nix` serves
/// it at `<ferrum.daemon.subdomain>.<ferrum.proxy.baseDomain>` on every host
/// where `modules/proxy/lib.nix`'s `daemonPublished` holds, which is the
/// ordinary host. So a compromised catalog app on a sibling subdomain IS
/// same-site with this endpoint, and the browser WILL attach
/// `__Host-ferrumd_session` to a request it makes here. What stops it
/// reading the answer is purely the absence of CORS.
///
/// This was written as a future risk, on the premise that the daemon had no
/// vhost and its subdomain option went unread. Phase 1.7c R13 shipped the
/// vhost, so the paragraph stands because the risk arrived -- not because it
/// might.
///
/// Where ferrumd LISTENS is a different claim, and still loopback (see
/// `default_listen_address`): publishing the dashboard means nginx reaches
/// it there, not that the daemon binds a public interface. Both are true at
/// once, and reading the second as the first is what left this paragraph
/// arguing from a premise the host no longer had.
///
/// So the invariant to protect is specific: never serve this route with
/// `Access-Control-Allow-Credentials: true` alongside a reflected or wildcard
/// origin. That combination, and only that, turns this endpoint into a CSRF
/// bypass for every app hosted under the same base domain.
async fn session_handler(
    axum::Extension(SessionUsername(username)): axum::Extension<SessionUsername>,
    axum::Extension(SessionCsrfToken(csrf_token)): axum::Extension<SessionCsrfToken>,
) -> impl IntoResponse {
    match username {
        Some(username) => {
            Json(serde_json::json!({ "username": username, "csrf_token": csrf_token }))
                .into_response()
        }
        // The session authenticated against a user row that is gone. That is
        // a database inconsistency, not a failed login, so it is a 500 rather
        // than a 401: telling the operator to log in again would not fix it,
        // and a blank username in the UI would hide it entirely.
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "session references a user that no longer exists",
        )
            .into_response(),
    }
}

fn build_router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/catalog", axum::routing::get(catalog::get_catalog))
        .route("/api/generations", axum::routing::get(generations::get_generations))
        .route("/api/updates", axum::routing::get(updates::get_updates))
        .route("/api/settings", axum::routing::get(settings::get_settings).put(settings::put_settings))
        .route("/api/secrets/:name", axum::routing::post(secrets_api::write_secret))
        .route("/api/session", axum::routing::get(session_handler))
        .route("/api/jobs", axum::routing::post(jobs::create_job))
        .route("/api/jobs", axum::routing::get(jobs::list_jobs))
        .route("/api/jobs/:id", axum::routing::get(jobs::get_job))
        .route("/api/jobs/:id/stream", axum::routing::get(jobs::stream_job))
        .route("/api/password", post(change_password_handler))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_session));

    Router::new()
        // Unauthenticated ON PURPOSE, and attached as the FALLBACK rather
        // than a route so it can never shadow an API path: this serves the
        // login page and its assets, and requiring a session to fetch the
        // page you log in on would be circular. See static_files.rs's header.
        .fallback(static_files::serve)
        .route("/api/login", post(login_handler))
        // L-01 is knowingly still open here: this is the one mutating route
        // with no CSRF check. Moving it into `protected` is a one-line fix
        // that breaks the real UI, which sends no token on logout and then
        // swallows the 403 -- so the session would silently survive. Both
        // halves must land together. The whole argument, and the tripwire
        // that fails if somebody moves this alone, live in
        // `logout_is_still_unguarded_and_the_ui_still_depends_on_that`.
        .route("/api/logout", post(logout_handler))
        .merge(protected)
        .layer(CookieManagerLayer::new())
        .with_state(state)
}

/// Describes a real path's real current ownership and mode, for the error
/// message below -- so an operator reading `journalctl -u ferrumd` sees
/// what is actually on their disk, not just that something is wrong.
///
/// Returns an empty string when the metadata itself cannot be read: that is
/// already covered by the underlying error being reported, and a failure to
/// decorate a message must never itself become a failure.
fn ownership_summary(path: &std::path::Path) -> String {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;
    match std::fs::metadata(path) {
        Ok(meta) => format!(
            "    it is currently uid={} gid={} mode={:04o}\n",
            meta.uid(),
            meta.gid(),
            meta.permissions().mode() & 0o7777
        ),
        Err(_) => String::new(),
    }
}

/// Really opens `settings.json` for read+write, rather than inferring
/// writability from its mode bits.
///
/// The open is the honest check: mode bits alone can disagree with reality
/// (a read-only mount, a POSIX ACL, a MAC policy, a supplementary group the
/// process does not actually hold), and every one of those produces a host
/// where the bits look right and the first real `PUT /api/settings` still
/// fails. `.write(true).read(true)` with no `create` and no `truncate`
/// deliberately never modifies the file: it either succeeds and is dropped,
/// or it tells us why not.
fn check_settings_writable(path: &std::path::Path) -> Result<(), String> {
    match std::fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "ferrumd: refusing to start -- {} is not writable by this process.\n\
             \x20   cause: {e}\n\
             {}\
             \x20   ferrumd rewrites this file on every `PUT /api/settings`. A host provisioned\n\
             \x20   before this check existed typically has it as root:root 0644, which lets\n\
             \x20   ferrumd start and read settings, then fails the first real write with a bare\n\
             \x20   \"Permission denied\" long after the cause.\n\
             \x20   Fix it, as root on this host:\n\
             \x20       chown root:ferrum {} && chmod 0664 {}",
            path.display(),
            ownership_summary(path),
            path.display(),
            path.display()
        )),
    }
}

/// Really creates, writes, and removes a probe file inside the secrets
/// directory.
///
/// A directory's own mode bits are especially misleading here: what
/// `POST /api/secrets/<name>` needs is the ability to CREATE a new file in
/// this directory, which depends on the directory's write AND execute bits
/// together, on the process's real group membership, and on nothing else on
/// the box (an ACL, an immutable flag) forbidding it. Doing the real thing
/// the API will later do is the only check that cannot be wrong about that.
/// The probe name is process-scoped so two ferrumd instances starting at
/// once cannot delete each other's probe, and it is removed again
/// immediately -- a leftover probe file would look like a stray secret.
fn check_secrets_dir_writable(dir: &std::path::Path) -> Result<(), String> {
    let describe = |what: &str, e: std::io::Error| {
        format!(
            "ferrumd: refusing to start -- the secrets directory {} is not writable by this process.\n\
             \x20   cause: {what}: {e}\n\
             {}\
             \x20   ferrumd creates <name>.sops files here on every `POST /api/secrets/<name>`.\n\
             \x20   Fix it, as root on this host:\n\
             \x20       chown ferrum:ferrum {} && chmod 0750 {}",
            dir.display(),
            ownership_summary(dir),
            dir.display(),
            dir.display()
        )
    };

    if !dir.is_dir() {
        return Err(format!(
            "ferrumd: refusing to start -- the secrets directory {} does not exist, or is not a directory.\n\
             \x20   ferrumd creates <name>.sops files here on every `POST /api/secrets/<name>`.\n\
             \x20   Fix it, as root on this host:\n\
             \x20       mkdir -p {} && chown ferrum:ferrum {} && chmod 0750 {}",
            dir.display(),
            dir.display(),
            dir.display(),
            dir.display()
        ));
    }

    let probe = dir.join(format!(".ferrumd-write-probe-{}", std::process::id()));
    match std::fs::write(&probe, b"ferrumd startup writability probe\n") {
        Ok(()) => {}
        Err(e) => return Err(describe("could not create a probe file", e)),
    }
    if let Err(e) = std::fs::remove_file(&probe) {
        return Err(describe("could not remove the probe file it just created", e));
    }
    Ok(())
}

/// Both real checks, run BEFORE the listener binds.
///
/// This exists because the unit's own `AssertPathExists=` (see
/// modules/core/daemon.nix) answers a strictly weaker question -- the paths
/// EXIST -- and there is no systemd directive that asks the one that
/// matters ("can THIS user write THIS file"): `AssertPathIsReadWrite=` only
/// checks the underlying mount is not read-only, not per-file ownership or
/// mode. Failing here, with `Restart=on-failure` already on the unit, turns
/// a silently half-broken daemon into a crash loop whose every attempt
/// prints exactly what is wrong and exactly how to fix it.
fn check_writable_paths(settings_path: &std::path::Path, secrets_dir: &std::path::Path) -> Result<(), String> {
    check_settings_writable(settings_path)?;
    check_secrets_dir_writable(secrets_dir)?;
    Ok(())
}

/// Fires exactly once, however many times it is told to.
///
/// `main` waits on this before it binds the listener, so the interlock has
/// been reconciled against systemd's real view before the first request can
/// ask for a job. It has to fire on a FAILED first attempt too -- a box
/// whose system bus is unreachable must still serve the dashboard, which is
/// the only surface an operator has to diagnose it from.
struct ReadySignal(Mutex<Option<tokio::sync::oneshot::Sender<()>>>);

impl ReadySignal {
    fn new(tx: tokio::sync::oneshot::Sender<()>) -> Self {
        Self(Mutex::new(Some(tx)))
    }

    /// Releases `main`'s wait. Later calls do nothing.
    fn fire(&self) {
        if let Some(tx) = self.0.lock().unwrap().take() {
            // The receiver being gone means main stopped waiting (its own
            // timeout elapsed); the watcher carries on regardless.
            let _ = tx.send(());
        }
    }
}

/// How long to wait before re-attaching, after `consecutive_failures`
/// attempts in a row have failed or ended.
///
/// Doubling from one second to a thirty-second ceiling. The ceiling matters
/// more than the curve: a bus that is down stays down for a while, and a
/// listener retrying in a tight loop would spend the daemon's whole runtime
/// failing to connect. It must never return zero -- that IS the tight loop.
fn reconnect_delay(consecutive_failures: u32) -> Duration {
    const CEILING_SECS: u64 = 30;
    let secs = 1u64 << consecutive_failures.min(5);
    Duration::from_secs(secs.min(CEILING_SECS))
}

/// Sets the interlock from systemd's own answer about what is running.
///
/// The in-process flag is authoritative for admission but systemd is
/// authoritative for reality, and they can disagree in both directions: an
/// apply that switched to a generation carrying a new ferrumd restarts this
/// process mid-run (flag says no, systemd says yes), and a `JobRemoved`
/// that arrived while the listener was detached is gone forever (flag says
/// yes, systemd says no). Both are corrected here.
///
/// The correction is only sound because the caller is already subscribed
/// when it asks -- see `attach_and_watch`.
///
/// There is one narrow window this can get wrong: a re-attach whose query
/// lands in the few milliseconds between `create_job` claiming the flag and
/// systemd having a unit to report would clear a flag that is legitimately
/// held, admitting a second job. That is a rare race with a bounded,
/// self-correcting cost, and it replaces a wedge that was permanent.
///
/// # Arguments
/// * `state` - the daemon state holding the interlock.
/// * `systemd_says_running` - whether systemd currently reports a running
///   `ferrum-apply@*.service`.
fn reconcile_interlock(state: &AppState, systemd_says_running: bool) {
    let mut running = state.job_running.lock().unwrap();
    if *running == systemd_says_running {
        return;
    }
    if systemd_says_running {
        eprintln!(
            "ferrumd: a ferrum-apply job is still running -- holding the single-job \
             interlock; new jobs will be refused until it finishes"
        );
    } else {
        eprintln!(
            "ferrumd: systemd reports no ferrum-apply job running -- releasing the \
             single-job interlock"
        );
    }
    *running = systemd_says_running;
}

/// One attachment to systemd's `JobRemoved` signal, held until it breaks.
///
/// Only ever returns an error: either the attachment could not be made, or
/// the signal stream ended. `supervise_job_watch` is what makes that
/// survivable.
///
/// **The order of the first four statements is the fix for M3 and is not
/// interchangeable.** Subscribing and opening the stream come first, and
/// only then is systemd asked what is running. The other order -- which is
/// what `main` used to do, querying before this task had even been spawned
/// -- loses any completion that lands in between: `JobRemoved` fires while
/// nothing is listening, the query has already returned "running", and the
/// interlock stays closed for the rest of the process lifetime, answering
/// every `POST /api/jobs` with 409. The one situation this whole path
/// exists for is an apply that restarts ferrumd mid-run, which is exactly
/// the situation that finishes inside that window. Nothing in the UI could
/// clear it either, because clearing it would need a job.
///
/// Clearing twice is harmless, so the safe order costs nothing.
///
/// # Arguments
/// * `state` - the daemon state holding the interlock.
/// * `ready` - released once the interlock has been reconciled.
///
/// # Errors
/// Any D-Bus failure connecting, subscribing, or querying; and the normal
/// end of the signal stream, which is a fault here rather than an ending.
async fn attach_and_watch(
    state: &AppState,
    ready: &ReadySignal,
) -> anyhow::Result<std::convert::Infallible> {
    let connection = zbus::Connection::system().await?;
    let proxy = dbus::SystemdManagerProxy::new(&connection).await?;
    proxy.subscribe().await?;
    let mut stream = proxy.receive_job_removed().await?;

    // Safe to ask only now: any completion from here on has a listener.
    reconcile_interlock(state, dbus::ferrum_apply_job_is_running(&proxy).await?);
    ready.fire();

    use futures::StreamExt;
    while let Some(signal) = stream.next().await {
        let Ok(args) = signal.args() else { continue };
        if args.unit().starts_with("ferrum-apply@") {
            *state.job_running.lock().unwrap() = false;
            // The request file is spent the moment the unit's job is gone:
            // `ferrum-apply run-request` has already read it (JobRemoved for
            // a Type=oneshot start job fires after ExecStart returns), so
            // nothing legitimate still needs it, while leaving it in place
            // keeps a replayable privileged trigger sitting in
            // /run/ferrum/requests. Deliberately gated on the UUID parsing
            // cleanly -- the interlock above clears for ANY ferrum-apply@
            // unit, but only a real UUID may name a file to delete.
            if let Some(uuid) = jobs::job_uuid_from_unit(args.unit()) {
                jobs::remove_request_file(&uuid);
            }
        }
    }
    anyhow::bail!("the systemd JobRemoved signal stream ended unexpectedly")
}

/// Keeps `attach` attached, forever, however often it fails.
///
/// M3. This used to be `if let Err(e) = watch_job_completions(state).await`
/// in `main` -- log once, exit, never try again. The comment on it was
/// right about the consequence and wrong that logging was an answer to it:
/// with no listener, the interlock can only ever be cleared by
/// `create_job`'s own failure paths, so the first job that actually STARTS
/// holds it for the rest of the process lifetime and every later job is
/// refused with 409. The daemon is then unrecoverable from its own UI,
/// because the recovery is a restart and a restart is a job.
///
/// Failing to attach is an ordinary startup outcome, not an exotic one:
/// `modules/core/daemon.nix` orders ferrumd `after = network.target` only,
/// not after the system bus.
///
/// `attach` is a parameter rather than a direct call so that this
/// supervision -- the part that has to survive -- is testable without a
/// system bus. It only ever yields an error: an attachment that is working
/// has not returned yet.
///
/// # Arguments
/// * `attach` - makes one attachment attempt and holds it until it breaks.
async fn supervise_job_watch<A, Fut>(mut attach: A) -> std::convert::Infallible
where
    A: FnMut() -> Fut,
    Fut: std::future::Future<Output = anyhow::Error>,
{
    let mut consecutive_failures: u32 = 0;
    loop {
        let e = attach().await;
        let delay = reconnect_delay(consecutive_failures);
        eprintln!(
            "ferrumd: job-completion listener detached: {e} -- re-attaching in {}s",
            delay.as_secs()
        );
        tokio::time::sleep(delay).await;
        consecutive_failures = consecutive_failures.saturating_add(1);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Before anything else, and specifically before the listener binds:
    // a ferrumd that starts, serves a login, serves GET /api/settings, and
    // only then fails the operator's first real write with "Permission
    // denied" is worse than one that refuses to start at all. See
    // check_writable_paths.
    let settings_path = std::env::var("FERRUM_SETTINGS_PATH")
        .unwrap_or_else(|_| "/etc/ferrum/settings.json".to_string());
    let secrets_dir = std::env::var("FERRUM_SECRETS_DIR")
        .unwrap_or_else(|_| "/etc/ferrum/secrets".to_string());
    if let Err(message) = check_writable_paths(
        std::path::Path::new(&settings_path),
        std::path::Path::new(&secrets_dir),
    ) {
        eprintln!("{message}");
        std::process::exit(1);
    }

    let state_dir = std::env::var("FERRUMD_STATE_DIR").unwrap_or_else(|_| "/var/lib/ferrum".to_string());
    let state_dir = std::path::Path::new(&state_dir);
    let db = db::Db::open(&state_dir.join("ferrumd.db"))?;
    auth::ensure_first_user(&db, state_dir)?;

    // The interlock is in-process state, so it starts every process
    // lifetime believing nothing is running. That is wrong in one real,
    // reachable case: an `apply` job can switch to a generation carrying a
    // new ferrumd, which restarts ferrumd WHILE that same apply is still
    // executing -- and the restarted daemon would then happily admit a
    // second, concurrent job. Systemd is the only durable source of truth
    // about what is actually running, so it is asked before anything is
    // served.
    //
    // M3: that question is no longer asked here. It belongs inside
    // `attach_and_watch`, after the JobRemoved subscription exists, because
    // asking it first loses any completion that lands before the listener
    // is up and wedges the interlock closed for good. `false` is the
    // starting value; `reconcile_interlock` corrects it, in both
    // directions, from within the subscription.
    let state = Arc::new(AppState { db, job_running: Mutex::new(false) });

    // Independently confirms job completion via systemd's own JobRemoved
    // D-Bus signal, so `job_running` is cleared even if ferrum-apply
    // crashed before ever writing a "complete" line to its own progress
    // file -- see this plan's spec Known Risk #2 for why a job can
    // otherwise be left "running" forever.
    //
    // Filtered on the unit name, unlike the plan's original sketch:
    // JobRemoved fires for EVERY systemd job on the box (a timer firing, a
    // logrotate run, an operator restarting sshd), so an unfiltered
    // listener would clear the interlock the moment any unrelated unit
    // finished -- defeating the serialization jobs::create_job exists to
    // provide.
    //
    // M3: the listener no longer gives up. It used to log once and exit on
    // any error, which wedged the interlock exactly as badly as the race
    // did -- the very first job would be refused forever, and every one
    // after it. `modules/core/daemon.nix` orders ferrumd only `after =
    // network.target`, so "the system bus was not ready yet" is an ordinary
    // startup outcome, not an exotic one. It now re-attaches, and each
    // fresh attachment re-reconciles the flag against systemd, because
    // signals that arrived while it was detached are gone.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    {
        let state = state.clone();
        tokio::spawn(async move {
            let ready = ReadySignal::new(ready_tx);
            let (state, ready) = (&state, &ready);
            supervise_job_watch(move || async move {
                attach_and_watch(state, ready).await.unwrap_err()
            })
            .await;
        });
    }
    // The listener reconciles the interlock before this fires, so the first
    // request cannot be answered from an unreconciled flag. Bounded,
    // because a bus that never answers must delay the dashboard, not
    // withhold it: this is the surface an operator diagnoses a broken bus
    // from.
    match tokio::time::timeout(Duration::from_secs(5), ready_rx).await {
        Ok(_) => {}
        Err(_) => eprintln!(
            "ferrumd: systemd did not answer within 5s -- serving anyway with the \
             single-job interlock unreconciled. If ferrumd was just restarted by an \
             in-flight apply, a second concurrent job could be admitted until the \
             listener attaches."
        ),
    }

    let app = build_router(state);

    let listen_address =
        std::env::var("FERRUMD_LISTEN_ADDRESS").unwrap_or_else(|_| default_listen_address().into());
    let port: u16 = std::env::var("FERRUMD_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(7788);
    let listener = tokio::net::TcpListener::bind(format!("{listen_address}:{port}")).await?;
    // `into_make_service_with_connect_info` is what makes the real socket
    // peer available to handlers. Without it `ConnectInfo` never resolves,
    // every request looks like it came from nowhere, and both the login
    // throttle and the audit log lose the only address they can trust.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// The address ferrumd binds when `FERRUMD_LISTEN_ADDRESS` names none.
///
/// A named function rather than a literal inside `main`'s
/// `unwrap_or_else`, and the reason is the whole of its value: in there it
/// was unreachable from a test, so A5's headline guarantee -- ferrumd
/// keeps listening on loopback, and *publishing* the dashboard means
/// nginx reaches it there rather than the daemon binding a public
/// interface -- was asserted by nothing at all. Changing the literal to
/// `0.0.0.0` left all 103 tests in this crate green.
///
/// This owns only the default. The value an operator sets reaches this
/// process as `FERRUMD_LISTEN_ADDRESS` (`modules/core/daemon.nix`) and
/// replaces it outright, so the other half of A5 is a NixOS assertion in
/// that file -- there is no point re-checking here a value this process
/// has no power to refuse: it would fail at `bind` with the host already
/// built and the UI already gone.
///
/// # Returns
/// The default bind address, as a string `TcpListener::bind` accepts.
fn default_listen_address() -> &'static str {
    "127.0.0.1"
}

/// Real request-level tests for the CSRF gate, driven through the real
/// axum middleware stack (`tower::ServiceExt::oneshot` against the real
/// `require_session` layer) rather than by calling helper predicates in
/// isolation. Both halves are covered on purpose: a check that only ever
/// proves the REJECT case would also pass if the middleware rejected
/// everything, which would be a broken daemon rather than a secure one.
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt as _;

    /// One source, for tests that drive `auth::login` directly and are not
    /// about the throttle. A real `ClientAddr`, because that is what the
    /// throttle derives both of its axes from.
    fn test_client() -> client_addr::ClientAddr {
        client_addr::ClientAddr::Direct("127.0.0.1".parse().unwrap())
    }

    /// A real database with a real user, plus a real login producing a real
    /// session cookie and its real paired CSRF token.
    fn logged_in() -> (tempfile::TempDir, Arc<AppState>, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = db::Db::open(&dir.path().join("test.db")).unwrap();
        auth::ensure_first_user(&db, dir.path()).unwrap();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let result = auth::login(&db, "admin", password.trim(), &test_client()).unwrap().session().unwrap();
        let state = Arc::new(AppState { db, job_running: Mutex::new(false) });
        (dir, state, result.session_token, result.csrf_token)
    }

    /// The real `require_session` middleware in front of a handler that
    /// returns a sentinel, so "the request was allowed through" is observed
    /// directly instead of inferred from the absence of a rejection.
    fn sentinel_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route(
                "/guarded",
                axum::routing::get(|| async { "reached" }).put(|| async { "reached" }),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_session,
            ))
            .layer(CookieManagerLayer::new())
            .with_state(state)
    }

    fn guarded_request(method: Method, session: &str, csrf: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri("/guarded")
            .header("Cookie", format!("{SESSION_COOKIE}={session}"));
        if let Some(csrf) = csrf {
            builder = builder.header(CSRF_HEADER, csrf);
        }
        builder.body(Body::empty()).unwrap()
    }

    /// L-03. A throttled login is the ONLY thing that may answer 429, and it
    /// must answer with a fixed string.
    ///
    /// The old arm returned 429 with `e.to_string()` for every `Err` from
    /// `auth::login`, so a database fault -- a corrupt hash, an unreadable
    /// file, a disk full -- came back as "too many requests" carrying its own
    /// internal detail, on the one unauthenticated endpoint the internet can
    /// reach. The enum is what makes the arms separable; this pins that the
    /// handler really uses it.
    #[tokio::test]
    async fn a_throttled_login_is_429_with_no_internal_detail() {
        let (dir, state, _session, _csrf) = logged_in();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();

        let attempt = |body: String| {
            let router = build_router(state.clone());
            async move {
                router
                    .oneshot(
                        Request::builder()
                            .method(Method::POST)
                            .uri("/api/login")
                            .header("Content-Type", "application/json")
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
            }
        };
        let wrong =
            serde_json::json!({ "username": "admin", "password": "wrong" }).to_string();

        // Five real failures put this source over the limit. They are 401 --
        // "wrong password" is not "too many requests".
        for _ in 0..5 {
            assert_eq!(attempt(wrong.clone()).await.status(), StatusCode::UNAUTHORIZED);
        }

        let throttled = attempt(wrong).await;
        assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = axum::body::to_bytes(throttled.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body, "too many failed login attempts -- try again shortly");

        // And the throttle really is per-source rather than per-account: the
        // correct password from this same source is still refused (that is
        // the cooldown), but nothing here is a 500 or leaks a path.
        assert!(
            !body.contains('/'),
            "the 429 body must not carry a filesystem path: {body}"
        );
        let correct = serde_json::json!({ "username": "admin", "password": password.trim() })
            .to_string();
        assert_eq!(attempt(correct).await.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    /// Every audited handler now extracts `SessionUsername` and `ClientAddr`
    /// from request extensions, and a missing extension is a RUNTIME failure,
    /// not a compile error: axum answers 500 with "Missing request
    /// extension". So adding an audited route, or an audit field, to a
    /// handler that `require_session` does not feed would compile perfectly
    /// and fail only when someone actually used it.
    ///
    /// This drives every protected route with a real session and pins that
    /// none of them fails that way. It deliberately does not care what the
    /// status IS -- these requests carry empty bodies and most are rejected
    /// on their merits -- only that the reason is never a missing extension.
    #[tokio::test]
    async fn no_protected_route_is_missing_an_extension_the_audit_log_needs() {
        let (dir, state, session, csrf) = logged_in();
        // secrets/settings handlers read these; without them the routes fail
        // for an unrelated reason and this test would prove less than it says.
        std::env::set_var("FERRUM_SETTINGS_PATH", dir.path().join("settings.json"));
        std::env::set_var("FERRUM_SECRETS_DIR", dir.path());

        for (method, _pattern, uri) in cors_is_absent::API_ROUTES {
            let (session, csrf) = (session.clone(), csrf.clone());
            let request = Request::builder()
                .method(Method::from_bytes(method.as_bytes()).unwrap())
                .uri(*uri)
                .header("Cookie", format!("{SESSION_COOKIE}={session}"))
                .header(CSRF_HEADER, csrf)
                .header("Content-Type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let response = build_router(state.clone()).oneshot(request).await.unwrap();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body = String::from_utf8_lossy(&body).to_string();
            assert!(
                !body.contains("Missing request extension"),
                "{method} {uri} could not resolve an extension it declares: {body}"
            );
        }
    }

    /// L-01 is knowingly OPEN, and this test is the tripwire for closing it.
    ///
    /// `POST /api/logout` still takes no CSRF token, so a same-site sibling
    /// under `<baseDomain>` can force the operator's browser to POST it. The
    /// one-line fix -- move the route inside `protected` -- was made and then
    /// REVERTED, because ferrumd is only half of it: the real UI calls this
    /// endpoint with `csrf: false` (`ui/api.js:118`) and then SWALLOWS the
    /// resulting 403 (`ui/api.js:119-123`). Behind the guard the operator
    /// would appear to log out while the session stayed valid server-side for
    /// the rest of its idle window -- a worse failure than the forced logout
    /// being fixed, and a silent one.
    ///
    /// So this asserts the CURRENT contract deliberately. It is not approval
    /// of it: whoever moves the route sees this fail, and the message names
    /// the other half of the change. A comment in `build_router` would not
    /// have stopped them.
    #[tokio::test]
    async fn logout_is_still_unguarded_and_the_ui_still_depends_on_that() {
        let (_dir, state, session, _csrf) = logged_in();

        // No CSRF header, exactly as ui/api.js sends it today.
        let as_the_ui_sends_it = Request::builder()
            .method(Method::POST)
            .uri("/api/logout")
            .header("Cookie", format!("{SESSION_COOKIE}={session}"))
            .body(Body::empty())
            .unwrap();
        let response =
            build_router(state.clone()).oneshot(as_the_ui_sends_it).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "the UI sends no CSRF token on logout (ui/api.js:118). If you are moving this \
             route inside `protected` to close L-01, drop `csrf: false` from logout() in \
             ui/api.js in the SAME change -- otherwise the UI catches the 403 and the \
             session silently survives the logout."
        );
        assert!(
            auth::validate_session(&state.db, &session).unwrap().is_none(),
            "and the logout must really have revoked the session server-side"
        );
    }

    /// L-03's real defect, driven by a real fault rather than described.
    ///
    /// A corrupt stored hash makes `auth::login` return `Err`. That arm used
    /// to answer **429 carrying `e.to_string()`**, so this exact fault told
    /// an unauthenticated caller "too many requests" -- the wrong status
    /// entirely -- and handed them the daemon's own internal error text.
    /// It must be a 500 with a fixed body.
    #[tokio::test]
    async fn a_daemon_fault_during_login_is_500_and_leaks_no_detail() {
        let (_dir, state, _session, _csrf) = logged_in();
        state
            .db
            .conn()
            .execute(
                "UPDATE users SET password_hash = 'not-a-valid-argon2-hash' WHERE username = 'admin'",
                [],
            )
            .unwrap();

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        serde_json::json!({ "username": "admin", "password": "anything" })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a corrupt stored hash is a daemon fault, not a rate limit"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body, "login failed");
        assert!(
            !body.contains("corrupt") && !body.contains("argon2"),
            "the internal detail must go to the journal, not to the caller: {body}"
        );
    }

    /// C-01's actual property: expensive blocking work inside a handler must
    /// not stop the executor from running everything else.
    ///
    /// Deliberately on a SINGLE worker thread. `auth::login` runs argon2id
    /// verification, which is expensive on purpose -- `Argon2::default()` is
    /// 19MiB and two passes, tens of milliseconds per call. Called straight
    /// from the `async fn`, several concurrent logins own that one worker for
    /// the whole of their combined runtime, and nothing else on the runtime
    /// is polled until the last finishes: no timer, no second request, no SSE
    /// keep-alive on the apply an operator is watching. Handed to the
    /// blocking pool, the worker stays free.
    ///
    /// The probe is a bare 1ms timer loop, because a timer needs nothing from
    /// the process except to be polled -- so the longest gap between two of
    /// its ticks IS the longest time the executor was unavailable. Measuring
    /// the worst gap rather than a tick count is what makes this robust: the
    /// gap is ~1-3ms when the work is off the executor and the full length of
    /// the blocking run when it is not, and that separation does not depend
    /// on how long the test happens to take overall.
    ///
    /// PROVED TO FAIL, with real numbers rather than an assurance: reverting
    /// `login_handler` to call `auth::login` directly takes the observed
    /// worst stall from **3ms to 1948ms**. The 150ms threshold sits three
    /// orders of magnitude clear of one arm and an order clear of the other,
    /// so this is a real discriminator and not a timing race.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn blocking_work_in_a_handler_does_not_stall_the_executor() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        use std::time::{Duration, Instant};

        let (dir, state, _session, _csrf) = logged_in();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let password = password.trim().to_string();

        let worst_stall_ms = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let ticker = {
            let worst = worst_stall_ms.clone();
            let stop = stop.clone();
            tokio::spawn(async move {
                let mut last = Instant::now();
                while !stop.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    worst.fetch_max(last.elapsed().as_millis() as u64, Ordering::Relaxed);
                    last = Instant::now();
                }
            })
        };

        // Let the ticker reach steady state, then discard the startup gap so
        // only the window that overlaps the logins is measured.
        tokio::time::sleep(Duration::from_millis(50)).await;
        worst_stall_ms.store(0, Ordering::Relaxed);

        let logins: Vec<_> = (0..8)
            .map(|_| {
                let router = build_router(state.clone());
                let body =
                    serde_json::json!({ "username": "admin", "password": password }).to_string();
                tokio::spawn(async move {
                    router
                        .oneshot(
                            Request::builder()
                                .method(Method::POST)
                                .uri("/api/login")
                                .header("Content-Type", "application/json")
                                .body(Body::from(body))
                                .unwrap(),
                        )
                        .await
                        .unwrap()
                })
            })
            .collect();

        for login in logins {
            assert_eq!(
                login.await.unwrap().status(),
                StatusCode::OK,
                "each probe must be a REAL login -- a rejected one would not have run argon2 \
                 at all, and the test would be measuring nothing"
            );
        }

        // The ticker only records a gap when it is next POLLED, and while the
        // executor is blocked it is not polled at all -- so reading the value
        // the instant the logins finish races the scheduler and reads a stall
        // of zero no matter how long the executor was actually unavailable.
        // This measurement was wrong in exactly that way once: the reverted
        // build reported 0ms and the test passed. Let the ticker run once
        // more so the gap it has been sitting on is actually written down.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let observed = worst_stall_ms.load(Ordering::Relaxed);
        stop.store(true, Ordering::Relaxed);
        ticker.await.unwrap();

        assert!(
            observed < 150,
            "the executor stalled for {observed}ms while eight logins were in flight, which \
             means argon2id ran on the executor thread rather than the blocking pool"
        );
    }

    /// `GET /api/session` with no cookie at all must be a 401 -- it is
    /// inside the protected router, so `require_session` rejects it before
    /// the handler is reached.
    #[tokio::test]
    async fn the_session_endpoint_refuses_an_unauthenticated_caller() {
        let (_dir, state, _session, _csrf) = logged_in();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/session")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The real username, and a CSRF token that a real mutating request
    /// through the REAL router actually accepts.
    ///
    /// That second half is the whole point of the endpoint and is asserted
    /// by using the token, not by checking it is a non-empty string: a
    /// handler that returned any plausible-looking value would pass the
    /// weaker check and leave a refreshed UI unable to make a single
    /// mutating request.
    #[tokio::test]
    async fn the_session_endpoint_returns_a_csrf_token_that_really_works() {
        let (_dir, state, session, csrf) = logged_in();

        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/session")
            .header("Cookie", format!("{SESSION_COOKIE}={session}"))
            .body(Body::empty())
            .unwrap();
        let response = build_router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["username"], "admin", "the real username from the real database");

        let returned = body["csrf_token"].as_str().unwrap().to_string();
        assert_eq!(returned, csrf, "it must be THIS session's own token");

        // Now actually spend it on a real mutating request through the real
        // router. A wrong-but-plausible token would be a 403 here.
        let mutating = Request::builder()
            .method(Method::POST)
            .uri("/api/password")
            .header("Cookie", format!("{SESSION_COOKIE}={session}"))
            .header(CSRF_HEADER, &returned)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"current_password":"wrong","new_password":"x"}"#))
            .unwrap();
        let response = build_router(state).oneshot(mutating).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "401 means the CSRF gate PASSED and the handler ran (and rejected the \
             deliberately wrong current password); a 403 would mean the token was refused"
        );
    }

    /// One session must never be handed another session's CSRF token.
    #[tokio::test]
    async fn the_session_endpoint_returns_this_sessions_token_not_another() {
        let (_dir, state, _session, csrf) = logged_in();
        let password = std::fs::read_to_string(_dir.path().join("ferrumd-setup-password")).unwrap();
        let other = auth::login(&state.db, "admin", password.trim(), &test_client()).unwrap().session().unwrap();
        assert_ne!(other.csrf_token, csrf, "two real logins, two real tokens");

        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/session")
            .header("Cookie", format!("{SESSION_COOKIE}={}", other.session_token))
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["csrf_token"], other.csrf_token);
        assert_ne!(body["csrf_token"], csrf);
    }

    #[tokio::test]
    async fn a_mutating_request_with_the_real_csrf_token_is_allowed_through() {
        let (_dir, state, session, csrf) = logged_in();
        let response = sentinel_router(state)
            .oneshot(guarded_request(Method::PUT, &session, Some(&csrf)))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "a real session plus its own real CSRF token must reach the handler"
        );
    }

    #[tokio::test]
    async fn a_mutating_request_with_no_csrf_header_is_forbidden() {
        let (_dir, state, session, _csrf) = logged_in();
        let response = sentinel_router(state)
            .oneshot(guarded_request(Method::PUT, &session, None))
            .await
            .unwrap();
        // 403, not 401: the caller IS authenticated. See require_session.
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_mutating_request_with_the_wrong_csrf_token_is_forbidden() {
        let (_dir, state, session, csrf) = logged_in();
        for wrong in [
            "not-the-token".to_string(),
            String::new(),
            // The shapes a substring/prefix/suffix comparison would wave
            // through, which is precisely the bug this test exists to stop
            // anyone reintroducing.
            csrf[..csrf.len() - 1].to_string(),
            format!("{csrf}x"),
            format!("x{csrf}"),
        ] {
            let response = sentinel_router(state.clone())
                .oneshot(guarded_request(Method::PUT, &session, Some(&wrong)))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "a CSRF header of {wrong:?} must not be accepted"
            );
        }
    }

    #[tokio::test]
    async fn another_sessions_csrf_token_does_not_work() {
        let (_dir, state, session, _csrf) = logged_in();
        // A second real login against the same real database: a genuine,
        // currently-valid CSRF token that simply belongs to a different
        // session.
        let password =
            std::fs::read_to_string(_dir.path().join("ferrumd-setup-password")).unwrap();
        let other = auth::login(&state.db, "admin", password.trim(), &test_client()).unwrap().session().unwrap();
        assert_ne!(other.csrf_token, _csrf);
        let response = sentinel_router(state)
            .oneshot(guarded_request(Method::PUT, &session, Some(&other.csrf_token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_get_request_needs_no_csrf_header() {
        let (_dir, state, session, _csrf) = logged_in();
        let response = sentinel_router(state)
            .oneshot(guarded_request(Method::GET, &session, None))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "reads change nothing and must not be broken by the CSRF gate"
        );
    }

    #[tokio::test]
    async fn a_valid_csrf_header_without_a_session_is_still_unauthenticated() {
        let (_dir, state, _session, csrf) = logged_in();
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/guarded")
            .header(CSRF_HEADER, &csrf)
            .body(Body::empty())
            .unwrap();
        let response = sentinel_router(state).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "CSRF is not a substitute for authentication"
        );
    }

    /// The same gate, on the REAL routes rather than a sentinel one -- so a
    /// future refactor that drops `require_session` from the real router,
    /// or adds a mutating route outside it, fails here.
    #[tokio::test]
    async fn the_real_mutating_routes_are_really_behind_the_csrf_gate() {
        let (_dir, state, session, _csrf) = logged_in();
        for (method, uri) in [
            (Method::PUT, "/api/settings"),
            (Method::POST, "/api/secrets/test-secret"),
            (Method::POST, "/api/jobs"),
            // A password rotation is exactly the kind of mutating request a
            // cross-origin forgery would love to reach.
            (Method::POST, "/api/password"),
        ] {
            let request = Request::builder()
                .method(method.clone())
                .uri(uri)
                .header("Cookie", format!("{SESSION_COOKIE}={session}"))
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"kind":"preflight"}"#))
                .unwrap();
            let response = build_router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{method} {uri} must refuse a session-authenticated request carrying no CSRF header"
            );
        }
    }

    #[tokio::test]
    async fn the_real_read_route_still_works_without_a_csrf_header() {
        let (_dir, state, session, _csrf) = logged_in();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/settings")
            .header("Cookie", format!("{SESSION_COOKIE}={session}"))
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_ne!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a GET must never be turned away by the CSRF gate"
        );
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn only_state_changing_methods_are_gated() {
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            assert!(method_is_mutating(&method), "{method} must be gated");
        }
        for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
            assert!(!method_is_mutating(&method), "{method} must not be gated");
        }
    }

    /// A real `POST /api/password` through the REAL router: real session
    /// cookie, real CSRF header, real JSON body.
    async fn post_password(
        state: Arc<AppState>,
        session: &str,
        csrf: Option<&str>,
        body: &str,
    ) -> StatusCode {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/api/password")
            .header("Cookie", format!("{SESSION_COOKIE}={session}"))
            .header("Content-Type", "application/json");
        if let Some(csrf) = csrf {
            builder = builder.header(CSRF_HEADER, csrf);
        }
        build_router(state)
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap()
            .status()
    }

    /// The whole point of the endpoint, end to end through the real stack:
    /// after a real 200, the real `login` path accepts the new password and
    /// refuses the old one.
    #[tokio::test]
    async fn a_real_password_rotation_through_the_real_route_really_rotates_it() {
        let (dir, state, session, csrf) = logged_in();
        let old = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let old = old.trim().to_string();

        let status = post_password(
            state.clone(),
            &session,
            Some(&csrf),
            &serde_json::json!({"current_password": old, "new_password": "the-new-one"}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "a correct current password must be accepted");

        assert!(auth::login(&state.db, "admin", "the-new-one", &test_client()).unwrap().session().is_some());
        assert!(
            auth::login(&state.db, "admin", &old, &test_client()).unwrap().session().is_none(),
            "the old password must really stop working"
        );
    }

    /// 401, not 500 and not 403: the caller is authenticated and the
    /// request is well-formed -- the credential they offered is simply
    /// wrong. And nothing changed.
    #[tokio::test]
    async fn a_wrong_current_password_is_a_401_and_changes_nothing() {
        let (dir, state, session, csrf) = logged_in();
        let old = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let old = old.trim().to_string();

        let status = post_password(
            state.clone(),
            &session,
            Some(&csrf),
            r#"{"current_password":"not-it","new_password":"attempted"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            auth::login(&state.db, "admin", &old, &test_client()).unwrap().session().is_some(),
            "the real password must still work after a refused rotation"
        );
        assert!(auth::login(&state.db, "admin", "attempted", &test_client()).unwrap().session().is_none());
    }

    #[tokio::test]
    async fn an_empty_new_password_is_a_400() {
        let (dir, state, session, csrf) = logged_in();
        let old = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let status = post_password(
            state.clone(),
            &session,
            Some(&csrf),
            &serde_json::json!({"current_password": old.trim(), "new_password": ""}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(auth::login(&state.db, "admin", old.trim(), &test_client()).unwrap().session().is_some());
    }

    /// SEC-06, through the real route.
    ///
    /// `/api/password` had no rate limit at either layer: nginx's
    /// `limit_req` covers the login path only, and ferrumd's own throttle
    /// did not reach here. So an authenticated caller held an unbounded
    /// argon2 handle and an unthrottled oracle on `current_password`.
    #[tokio::test]
    async fn the_password_route_starts_refusing_a_caller_that_keeps_guessing() {
        let (_dir, state, session, csrf) = logged_in();
        let guess = r#"{"current_password":"not-it","new_password":"attempted"}"#;

        for attempt in 1..=5 {
            let status = post_password(state.clone(), &session, Some(&csrf), guess).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "guess {attempt} should still be a plain refusal"
            );
        }
        assert_eq!(
            post_password(state.clone(), &session, Some(&csrf), guess).await,
            StatusCode::TOO_MANY_REQUESTS,
            "an authenticated caller must not get unlimited guesses at the current password"
        );
    }

    /// SEC-09. The 500 on this route used to carry `e.to_string()`, which
    /// on the reachable failure below names the stored hash's own contents.
    ///
    /// Reached for real rather than mocked: a corrupt `password_hash`
    /// column is exactly what `change_password` turns into an `Err`, and it
    /// is the one 500 on this route a test can actually provoke.
    #[tokio::test]
    async fn a_daemon_fault_on_the_password_route_returns_no_internal_detail() {
        let (_dir, state, session, csrf) = logged_in();
        // After the login above, so the login itself still had a real hash.
        state
            .db
            .conn()
            .execute(
                "UPDATE users SET password_hash = 'not-a-phc-string' WHERE username = 'admin'",
                [],
            )
            .unwrap();

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/password")
            .header("Cookie", format!("{SESSION_COOKIE}={session}"))
            .header(CSRF_HEADER, &csrf)
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"current_password":"anything","new_password":"new"}"#.to_string(),
            ))
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8_lossy(&bytes).to_string();
        assert!(!body.is_empty(), "the caller still needs to be told something failed");
        assert!(
            !body.contains("not-a-phc-string") && !body.contains("corrupt"),
            "a 500 must not describe the daemon's internal state: {body}"
        );
    }

    /// AC25 -- the READ route is behind the session gate too.
    ///
    /// `the_real_mutating_routes_are_really_behind_the_csrf_gate` above
    /// enumerates mutating routes only, so a read route declared outside the
    /// `protected` group -- beside `/api/login` rather than behind
    /// `require_session` -- would be invisible to it and to every other test
    /// here. This drives the REAL router with no session cookie at all, so
    /// moving `/api/generations` out of `protected` fails here.
    #[tokio::test]
    async fn an_unauthenticated_generations_read_is_refused() {
        let (_dir, state, _session, _csrf) = logged_in();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/generations")
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "GET /api/generations must not be reachable without a session"
        );
    }

    #[tokio::test]
    async fn an_unauthenticated_password_change_is_refused() {
        let (_dir, state, _session, _csrf) = logged_in();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/password")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"current_password":"x","new_password":"y"}"#))
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Real tests for the startup self-check (`check_writable_paths`).
    ///
    /// Every case here is driven by a REAL filesystem state rather than a
    /// mocked one, and the permission-denied case is skipped when the test
    /// runs with the power to ignore permission bits -- `cargo test` is run
    /// as root on this project's own dev VM, where a 0000 file is still
    /// writable and asserting otherwise would be asserting something false.
    /// The unconditional cases below (a directory where a file belongs, a
    /// missing path) fail for everyone, root included, so the check is
    /// never left untested.
    mod startup_checks {
        use super::*;

        fn writable_fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let settings = dir.path().join("settings.json");
            std::fs::write(&settings, "{}").unwrap();
            let secrets = dir.path().join("secrets");
            std::fs::create_dir(&secrets).unwrap();
            (dir, settings, secrets)
        }

        /// True when this process can write a file whose mode says it
        /// cannot -- i.e. it is root, or holds CAP_DAC_OVERRIDE.
        fn permission_bits_are_ignored_here(dir: &std::path::Path) -> bool {
            use std::os::unix::fs::PermissionsExt as _;
            let probe = dir.join("root-detection-probe");
            std::fs::write(&probe, "x").unwrap();
            std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o000)).unwrap();
            let ignored = std::fs::OpenOptions::new().write(true).open(&probe).is_ok();
            std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::remove_file(&probe).unwrap();
            ignored
        }

        #[test]
        fn a_correctly_provisioned_pair_passes_and_leaves_no_probe_behind() {
            let (_dir, settings, secrets) = writable_fixture();
            assert_eq!(check_writable_paths(&settings, &secrets), Ok(()));
            // The probe must really have been cleaned up: a leftover file in
            // the secrets directory would look like a stray secret.
            let leftovers: Vec<_> = std::fs::read_dir(&secrets)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert!(leftovers.is_empty(), "the probe file must be removed: {leftovers:?}");
            // And the check must not have modified settings.json.
            assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{}");
        }

        #[test]
        fn a_settings_file_that_is_not_writable_is_refused_with_an_actionable_message() {
            use std::os::unix::fs::PermissionsExt as _;
            let (dir, settings, secrets) = writable_fixture();
            if permission_bits_are_ignored_here(dir.path()) {
                eprintln!(
                    "skipping: this process ignores permission bits (root/CAP_DAC_OVERRIDE); \
                     the real permission case is covered for real by tests/daemon-end-to-end.nix, \
                     where ferrumd runs as the unprivileged ferrum user"
                );
                return;
            }
            // Exactly the shape a host deployed before this check existed
            // has: readable by everyone, writable only by root.
            std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o444)).unwrap();
            let err = check_writable_paths(&settings, &secrets).unwrap_err();
            assert!(err.contains(&settings.display().to_string()), "{err}");
            assert!(err.contains("chown root:ferrum"), "{err}");
            assert!(err.contains("chmod 0664"), "{err}");
            assert!(err.contains("Permission denied"), "{err}");
        }

        #[test]
        fn a_secrets_directory_that_cannot_be_written_is_refused() {
            use std::os::unix::fs::PermissionsExt as _;
            let (dir, settings, secrets) = writable_fixture();
            if permission_bits_are_ignored_here(dir.path()) {
                eprintln!("skipping: this process ignores permission bits (root/CAP_DAC_OVERRIDE)");
                return;
            }
            // r-x: listable, but nothing can be created in it -- which is
            // precisely what POST /api/secrets/<name> needs and what a
            // mode-bit glance at "0555, looks fine" would miss.
            std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o555)).unwrap();
            let err = check_writable_paths(&settings, &secrets).unwrap_err();
            std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(err.contains(&secrets.display().to_string()), "{err}");
            assert!(err.contains("chown ferrum:ferrum"), "{err}");
            assert!(err.contains("chmod 0750"), "{err}");
        }

        /// Fails for root too, so this case really is exercised everywhere.
        #[test]
        fn a_settings_path_that_is_a_directory_is_refused() {
            let (dir, _settings, secrets) = writable_fixture();
            let not_a_file = dir.path().join("settings-as-a-directory");
            std::fs::create_dir(&not_a_file).unwrap();
            let err = check_writable_paths(&not_a_file, &secrets).unwrap_err();
            assert!(err.contains("refusing to start"), "{err}");
            assert!(err.contains(&not_a_file.display().to_string()), "{err}");
        }

        #[test]
        fn a_missing_settings_file_is_refused_with_the_real_reason() {
            let (dir, _settings, secrets) = writable_fixture();
            let missing = dir.path().join("nope.json");
            let err = check_writable_paths(&missing, &secrets).unwrap_err();
            assert!(err.contains(&missing.display().to_string()), "{err}");
            assert!(err.contains("chown root:ferrum"), "{err}");
        }

        #[test]
        fn a_missing_secrets_directory_is_refused_with_a_mkdir_in_the_fix() {
            let (dir, settings, _secrets) = writable_fixture();
            let missing = dir.path().join("no-secrets-here");
            let err = check_writable_paths(&settings, &missing).unwrap_err();
            assert!(err.contains("does not exist"), "{err}");
            assert!(err.contains("mkdir -p"), "{err}");
            assert!(err.contains(&missing.display().to_string()), "{err}");
        }

        /// A regular file where the secrets DIRECTORY belongs -- the check
        /// must say so rather than trying to write a probe into it.
        #[test]
        fn a_secrets_path_that_is_a_file_is_refused() {
            let (dir, settings, _secrets) = writable_fixture();
            let file = dir.path().join("secrets-as-a-file");
            std::fs::write(&file, "").unwrap();
            let err = check_writable_paths(&settings, &file).unwrap_err();
            assert!(err.contains("not a directory"), "{err}");
        }
    }

    /// A4/D3/D13 -- the real `Set-Cookie` the real login route really emits.
    ///
    /// Asserted on the wire rather than on the `Cookie` value built in
    /// `login_handler`, because the attribute that matters here is one the
    /// BROWSER enforces: a cookie named with the `__Host-` prefix is
    /// rejected outright unless it carries `Secure` and `Path=/` and
    /// carries NO `Domain`. That rejection is the whole mitigation -- it is
    /// what stops a compromised `sonarr.<baseDomain>` answering with
    /// `Set-Cookie: <session>=...; Domain=<baseDomain>` and planting a
    /// second same-named cookie that RFC 6265 lets the browser choose
    /// between arbitrarily. Checking the name alone would pass while the
    /// prefix was inert.
    #[tokio::test]
    async fn the_session_cookie_is_host_prefixed_secure_and_carries_no_domain() {
        let (dir, state, _session, _csrf) = logged_in();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/login")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"username": "admin", "password": password.trim()}).to_string(),
            ))
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("a successful login must set the session cookie")
            .to_str()
            .unwrap()
            .to_string();

        assert!(
            set_cookie.starts_with(&format!("{SESSION_COOKIE}=")),
            "the session cookie must be the __Host- prefixed name: {set_cookie}"
        );
        assert!(
            SESSION_COOKIE.starts_with("__Host-"),
            "the prefix IS the mitigation, not a naming preference"
        );
        assert!(set_cookie.contains("Secure"), "__Host- requires Secure: {set_cookie}");
        assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
        assert!(set_cookie.contains("SameSite=Strict"), "{set_cookie}");
        assert!(set_cookie.contains("Path=/"), "__Host- requires Path=/: {set_cookie}");
        assert!(
            !set_cookie.to_ascii_lowercase().contains("domain="),
            "a __Host- cookie carrying Domain is refused by every browser, which \
             would silently log every operator out: {set_cookie}"
        );
    }

    /// The rename must be real on the READ side too. A session token that
    /// is genuinely valid, presented under the pre-R13 name, must not
    /// authenticate -- otherwise `require_session` would still accept the
    /// unprefixed cookie a compromised sibling subdomain can plant, and the
    /// rename would be cosmetic.
    #[tokio::test]
    async fn a_valid_token_under_the_old_cookie_name_does_not_authenticate() {
        let (_dir, state, session, _csrf) = logged_in();
        let request = Request::builder()
            .method(Method::GET)
            .uri("/api/session")
            .header("Cookie", format!("ferrumd_session={session}"))
            .body(Body::empty())
            .unwrap();
        let response = build_router(state).oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "the unprefixed cookie name must carry no authority at all"
        );
    }

    /// Logout's removal cookie has to satisfy `__Host-`'s rules as well, or
    /// the browser discards the `Set-Cookie` that was supposed to clear the
    /// session and the operator stays logged in in their own tab. The
    /// server-side session really is revoked either way, so this failure
    /// mode is invisible to every test that only checks the status code.
    #[tokio::test]
    async fn logout_emits_a_removal_cookie_a_browser_will_actually_accept() {
        let (_dir, state, session, csrf) = logged_in();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/logout")
            .header("Cookie", format!("{SESSION_COOKIE}={session}"))
            .header(CSRF_HEADER, &csrf)
            .body(Body::empty())
            .unwrap();
        let response = build_router(state.clone()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .expect("logout must emit a removal cookie")
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.starts_with(&format!("{SESSION_COOKIE}=")), "{set_cookie}");
        assert!(set_cookie.contains("Path=/"), "{set_cookie}");
        assert!(set_cookie.contains("Secure"), "{set_cookie}");
        assert!(
            !set_cookie.to_ascii_lowercase().contains("domain="),
            "{set_cookie}"
        );

        // And the session really is gone server-side, so the removal cookie
        // is belt to a real braces rather than the only thing revoking it.
        assert!(auth::validate_session(&state.db, &session).unwrap().is_none());
    }

    /// D4 -- ferrumd's own session is the sole authoritative gate.
    ///
    /// Authelia sits in front of the daemon vhost after R13 and, when a
    /// deployment trusts it, hands downstream apps `Remote-User` &co. The
    /// daemon deliberately does NOT join that scheme: neither
    /// `modules/core/daemon.nix` nor any unit under `modules/apps/*` has
    /// network-namespace isolation, so any local process -- a compromised or
    /// SSRF'd catalog app -- can open `127.0.0.1:7788` directly and set
    /// whatever headers it likes, going around the browser and every
    /// same-site mitigation with it.
    #[tokio::test]
    async fn forged_forward_auth_headers_authenticate_nobody() {
        let (_dir, state, _session, _csrf) = logged_in();
        for header in FORWARD_AUTH_HEADERS {
            let request = Request::builder()
                .method(Method::GET)
                .uri("/api/session")
                .header(*header, "admin")
                .body(Body::empty())
                .unwrap();
            let response = build_router(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{header} must not authenticate a caller with no session cookie"
            );
        }
    }

    /// The other half: with a real session, a forged identity header must
    /// not REPLACE the identity the session proves either. A daemon that
    /// preferred the header would let a local process act as any user it
    /// named while still presenting its own valid session.
    #[tokio::test]
    async fn forged_forward_auth_headers_do_not_change_who_the_caller_is() {
        let (_dir, state, session, _csrf) = logged_in();
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri("/api/session")
            .header("Cookie", format!("{SESSION_COOKIE}={session}"));
        for header in FORWARD_AUTH_HEADERS {
            builder = builder.header(*header, "somebody-else");
        }
        let response = build_router(state)
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body["username"], "admin",
            "the identity must come from the session row, never from a header"
        );
    }

    /// The headers a forward-auth proxy conventionally injects. Named once
    /// so the behavioural tests above and the source scan below cannot
    /// drift apart into testing different sets.
    const FORWARD_AUTH_HEADERS: &[&str] = &[
        "Remote-User",
        "Remote-Groups",
        "Remote-Name",
        "Remote-Email",
        "X-Remote-User",
        "X-Remote-Groups",
        "X-Remote-Name",
        "X-Remote-Email",
    ];

    /// Every source file this crate actually compiles.
    ///
    /// Spelled out rather than walked on disk so the scan below needs no
    /// filesystem at test time, and kept honest by
    /// `the_source_scan_covers_every_module`: a module that exists but is
    /// missing here would make the scan quietly partial, which is the one
    /// way an absence proof fails without failing.
    const CRATE_SOURCES: &[(&str, &str)] = &[
        ("main.rs", include_str!("main.rs")),
        ("audit.rs", include_str!("audit.rs")),
        ("auth.rs", include_str!("auth.rs")),
        ("catalog.rs", include_str!("catalog.rs")),
        ("client_addr.rs", include_str!("client_addr.rs")),
        ("db.rs", include_str!("db.rs")),
        ("dbus.rs", include_str!("dbus.rs")),
        ("generations.rs", include_str!("generations.rs")),
        ("jobs.rs", include_str!("jobs.rs")),
        ("secrets_api.rs", include_str!("secrets_api.rs")),
        ("settings.rs", include_str!("settings.rs")),
        ("static_files.rs", include_str!("static_files.rs")),
        ("updates.rs", include_str!("updates.rs")),
    ];

    /// The behavioural tests above prove the routes they drive ignore a
    /// forged header. This proves the stronger thing they cannot: no code
    /// path anywhere in the crate so much as NAMES one, including paths no
    /// test reaches. D4's promise is an absence, and an absence is only
    /// really held by a check that reads everything.
    #[test]
    fn no_source_file_reads_a_forward_auth_header() {
        let mut found = Vec::new();
        for (name, source) in CRATE_SOURCES {
            for (number, line) in source.lines().enumerate() {
                if let Some(header) = forward_auth_header_named_on(line) {
                    found.push(format!("{name}:{}: {header}: {}", number + 1, line.trim()));
                }
            }
        }
        assert!(
            found.is_empty(),
            "ferrumd must never trust a forward-auth identity header (D4); found:\n{}",
            found.join("\n")
        );
    }

    /// The forward-auth header a line names, if it names one.
    ///
    /// Split out of the scan above so the recogniser can be exercised
    /// directly, for the same reason `module_declared_on` was: the scan it
    /// feeds asserts an ABSENCE, and an absence-finder with a broken
    /// matcher reports the same clean result as a codebase that really is
    /// clean. The matcher could have been replaced wholesale -- or by
    /// something that matches nothing at all -- and the only signal would
    /// have been a green test.
    ///
    /// # Arguments
    /// * `line` - one source line, exactly as written.
    ///
    /// # Returns
    /// The matched entry of `FORWARD_AUTH_HEADERS`, or `None` for a line
    /// that names none -- including this crate's own documentation of the
    /// rule, which names them all on purpose.
    fn forward_auth_header_named_on(line: &str) -> Option<&'static str> {
        // The test module names these headers deliberately, in the
        // FORWARD_AUTH_HEADERS table and in the prose explaining why they
        // are not trusted. Skipping the crate's own documentation of the
        // rule is not a loophole in it: a real read is
        // `headers().get(...)`, not a string in a comment.
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('"') {
            return None;
        }
        // Case-INSENSITIVE, because HTTP header names are (RFC 9110 5.1)
        // and Rust spells them lowercase by convention --
        // `headers().get("remote-user")` reads the same header the table
        // names in Title-Case, and a scan that only matched the table's own
        // spelling would miss the way the code would most likely be
        // written.
        let haystack = line.to_ascii_lowercase();
        FORWARD_AUTH_HEADERS
            .iter()
            .copied()
            .find(|header| haystack.contains(&header.to_ascii_lowercase()))
    }

    /// Lines the recogniser must match, and lines it must not.
    ///
    /// A table rather than inline arguments, for a reason peculiar to this
    /// guard: the scan reads main.rs too, so a fixture written inline
    /// would be a line of THIS file naming a forward-auth header outside a
    /// comment -- and the scan would dutifully report its own positive
    /// control as a violation. It did, on the first run. Each entry here
    /// sits on its own line beginning with a quote, which is the same
    /// exemption the FORWARD_AUTH_HEADERS table above already relies on.
    const READS_A_HEADER: &[&str] = &[
        "let who = headers.get(\"remote-user\");",
        "headers.get(\"Remote-Email\")",
        "headers.get(\"X-Remote-Groups\")",
        "HeaderName::from_static(\"REMOTE-NAME\")",
    ];

    /// The crate's own documentation of the rule, and ordinary code.
    const NAMES_NO_HEADER: &[&str] = &[
        "// Remote-User is never trusted here",
        "    \"Remote-User\",",
        "let session = require_session(&req)?;",
    ];

    /// The positive control the scan above had none of.
    ///
    /// Every assertion that recogniser feeds is "nothing matched", so
    /// without this the matcher itself is untested: it could return `None`
    /// unconditionally and the guard would go on reporting a clean crate
    /// forever. Modelled on
    /// `a_module_declaration_is_recognised_whatever_its_visibility` below,
    /// which exists for exactly the same reason.
    ///
    /// `is_some`, not the matched entry: the table's own entries overlap
    /// ("Remote-Groups" is a substring of "X-Remote-Groups"), so which one
    /// is reported first is an ordering detail, while whether anything is
    /// reported at all is the contract.
    #[test]
    fn a_forward_auth_header_read_is_recognised_however_it_is_spelled() {
        for line in READS_A_HEADER {
            assert!(
                forward_auth_header_named_on(line).is_some(),
                "the scan's matcher misses a real read: {line}"
            );
        }
        for line in NAMES_NO_HEADER {
            assert_eq!(
                forward_auth_header_named_on(line),
                None,
                "the scan's matcher reports a violation that is not one: {line}"
            );
        }
    }

    /// The module a `mod`/`pub mod`/`pub(crate) mod` line declares, if it
    /// declares one.
    ///
    /// Visibility is not part of what makes a line a module declaration,
    /// but the first version of this matched `mod ` alone -- so the day
    /// somebody wrote `pub mod`, the new module would have vanished from
    /// `declared` and the guard below would have gone on passing while
    /// the file escaped the forward-auth scan entirely. A completeness
    /// check with a blind spot is worse than none, because it is believed.
    ///
    /// Only column-zero lines count, which is what keeps a `mod ` inside a
    /// comment or a string from being read as a declaration, and an inline
    /// `mod tests {` out (it has no trailing semicolon and no file).
    fn module_declared_on(line: &str) -> Option<&str> {
        if line.starts_with(char::is_whitespace) {
            return None;
        }
        let mut tokens = line.split_whitespace();
        let name = match tokens.next()? {
            "mod" => tokens.next()?,
            // `pub`, `pub(crate)`, `pub(super)`, `pub(in path)` -- all of
            // them declare a module just as loudly.
            visibility if visibility.starts_with("pub") => {
                if tokens.next()? != "mod" {
                    return None;
                }
                tokens.next()?
            }
            _ => return None,
        };
        name.strip_suffix(';')
    }

    /// Keeps `CRATE_SOURCES` complete: it must list exactly the modules
    /// `main.rs` declares, so a new module cannot be added to the crate and
    /// silently escape the scan above.
    #[test]
    fn the_source_scan_covers_every_module() {
        let declared: Vec<String> = include_str!("main.rs")
            .lines()
            .filter_map(module_declared_on)
            .map(|name| format!("{name}.rs"))
            .collect();
        assert!(!declared.is_empty(), "the mod declarations must really have been found");
        let scanned: Vec<String> = CRATE_SOURCES
            .iter()
            .filter(|(name, _)| *name != "main.rs")
            .map(|(name, _)| (*name).to_string())
            .collect();
        assert_eq!(
            declared, scanned,
            "CRATE_SOURCES must list every module main.rs declares, in order"
        );
    }

    /// R3's second criterion, held as data rather than as a promise:
    /// ferrumd never shells out to `nix` and never opens the flake.
    ///
    /// The update check is dispatched to privileged `ferrum-apply` as an
    /// ordinary job precisely so the daemon needs neither -- a subprocess
    /// would put the whole Nix closure on the unprivileged daemon's PATH
    /// (modules/core/daemon.nix gives ferrumd exactly `pkgs.sops` and
    /// `pkgs.ssh-to-age`), and reading `/etc/ferrum/flake.nix` or
    /// `flake.lock` would make ferrumd a second reader of the privileged
    /// side's inputs. `updates.rs` serves a document somebody else
    /// produced, and this is what keeps it that way after the next edit.
    #[test]
    fn no_source_file_invokes_nix_or_opens_the_flake() {
        let mut found = Vec::new();
        for (name, source) in CRATE_SOURCES {
            for (number, line) in source.lines().enumerate() {
                if let Some(needle) = nix_reach_named_on(line) {
                    found.push(format!("{name}:{}: {needle}: {}", number + 1, line.trim()));
                }
            }
        }
        assert!(
            found.is_empty(),
            "ferrumd must never run a subprocess or read the flake (R3); found:\n{}",
            found.join("\n")
        );
    }

    /// The spellings a careless addition would use to reach the privileged
    /// side's tooling.
    ///
    /// Four literal substrings, and deliberately described as what they are:
    /// this is a TRIPWIRE, not a proof of absence. An aliased import
    /// (`use std::process::Command as Cmd;` then `Cmd::new(...)`), a direct
    /// `libc::execve`, or a flake path assembled at runtime rather than
    /// written as a literal all walk past it clean. It catches the way the
    /// code would most plausibly be written on a hurried afternoon, which is
    /// worth having; it does not catch an author who is working around it.
    /// The real guarantee is structural -- ferrumd is given exactly
    /// `pkgs.sops` and `pkgs.ssh-to-age` on its PATH by
    /// modules/core/daemon.nix -- and this only makes a regression noisy.
    ///
    /// `Command::new(` rather than the word "nix": the daemon runs NO
    /// subprocess at all today, which is both the stronger claim and the
    /// one with no false positives -- `/nix/var/nix/profiles` is a path
    /// generations.rs reads on purpose, and a scan keyed on the word would
    /// have to exempt it, then be one careless exemption away from missing
    /// the real thing.
    const NIX_REACH: &[&str] = &[
        "Command::new(",
        "process::Command",
        "flake.nix",
        "flake.lock",
    ];

    /// The reach a line makes, if it makes one.
    ///
    /// Split out so the recogniser can be exercised directly, for the same
    /// reason `forward_auth_header_named_on` was: the scan it feeds asserts
    /// an ABSENCE, and a broken matcher reports exactly what a clean crate
    /// reports.
    ///
    /// # Arguments
    /// * `line` - one source line, exactly as written.
    ///
    /// # Returns
    /// The matched entry of `NIX_REACH`, or `None` -- including for this
    /// crate's own prose about why it does none of these things, and for
    /// the fixture tables below, which are exempted by their leading quote
    /// exactly as the forward-auth scan's are.
    fn nix_reach_named_on(line: &str) -> Option<&'static str> {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('"') {
            return None;
        }
        NIX_REACH.iter().copied().find(|needle| line.contains(needle))
    }

    /// Lines the recogniser must match. Each begins with a quote so the
    /// scan above skips this table while reading main.rs -- the same
    /// exemption `READS_A_HEADER` relies on, and for the same reason: a
    /// positive control must not be reported as a violation.
    const REACHES_FOR_NIX: &[&str] = &[
        "    let out = std::process::Command::new(\"nix\").arg(\"eval\").output();",
        "        Command::new(\"nix-env\").arg(\"--set\").status()",
        "    let raw = std::fs::read_to_string(\"/etc/ferrum/flake.nix\")?;",
        "    let pins = std::fs::read(dir.join(\"flake.lock\"))?;",
    ];

    /// The crate's own prose about the rule, and ordinary code.
    const REACHES_FOR_NOTHING: &[&str] = &[
        "// ferrumd must never shell out to nix; see updates.rs",
        "    let dir = std::path::PathBuf::from(\"/nix/var/nix/profiles\");",
        "    let doc = crate::updates::get_updates(query).await;",
    ];

    /// `GET /api/updates` really is inside the session-gated router, and
    /// really serves the report that is on disk.
    ///
    /// The module's own tests drive `updates_response_in` directly, which
    /// says nothing about whether the handler was ever wired up or whether
    /// an anonymous caller can reach it. This drives the REAL router, so
    /// both are observed rather than assumed.
    #[tokio::test]
    async fn updates_is_session_gated_and_serves_the_report_on_disk() {
        let (dir, state, session, _csrf) = logged_in();
        let reports = dir.path().join("reports");
        std::fs::create_dir(&reports).unwrap();
        let job = "11111111-2222-3333-4444-555555555555";
        std::fs::write(
            reports.join(format!("{job}.update-check.json")),
            serde_json::json!({
                "schemaVersion": 1,
                "checkedAt": 1758700000u64,
                "candidate": { "state": "update-available" }
            })
            .to_string(),
        )
        .unwrap();
        // This is the only test that asserts anything about this
        // variable, but it is NOT the only code that reads it: the
        // API_ROUTES matrix drives `GET /api/updates` through the real
        // router, so `report_dir()` reads it on other threads of this same
        // binary while this line runs. That is safe for the specific reason
        // that those probes assert on CORS headers and on not-404, neither
        // of which depends on which directory the handler reads -- not
        // because nothing else looks. The distinction matters: a `set_var`
        // defended by "nobody else reads it" invites the next person to add
        // a test that does. (`FERRUM_JOBS_DIR` is the cautionary case, in
        // jobs.rs's
        // `handlers_skip_non_uuid_files_clamp_limit_and_reject_traversal_ids`.)
        std::env::set_var("FERRUM_UPDATE_REPORT_DIR", &reports);

        let anonymous = build_router(state.clone())
            .oneshot(Request::builder().uri("/api/updates").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            anonymous.status(),
            StatusCode::UNAUTHORIZED,
            "an unauthenticated read of the update report must be refused"
        );

        // No CSRF header, on purpose: require_session checks the token on
        // mutating methods only, and this read must not need one.
        let response = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/updates")
                    .header("Cookie", format!("{SESSION_COOKIE}={session}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["status"], "report");
        assert_eq!(body["jobId"], job);
        assert_eq!(body["report"]["candidate"]["state"], "update-available");

        std::env::remove_var("FERRUM_UPDATE_REPORT_DIR");
    }

    /// The positive control the scan above has none of on its own.
    #[test]
    fn a_reach_for_nix_is_recognised_however_it_is_spelled() {
        for line in REACHES_FOR_NIX {
            assert!(nix_reach_named_on(line).is_some(), "the scan's matcher misses: {line}");
        }
        for line in REACHES_FOR_NOTHING {
            assert_eq!(
                nix_reach_named_on(line),
                None,
                "the scan's matcher over-matches: {line}"
            );
        }
    }

    /// The shapes `module_declared_on` has to recognise, and the ones it
    /// must not. This is here because the recogniser is the whole of the
    /// guard above: the assertion it feeds cannot tell a module that does
    /// not exist from one it failed to read.
    #[test]
    fn a_module_declaration_is_recognised_whatever_its_visibility() {
        assert_eq!(module_declared_on("mod auth;"), Some("auth"));
        assert_eq!(module_declared_on("pub mod auth;"), Some("auth"));
        assert_eq!(module_declared_on("pub(crate) mod auth;"), Some("auth"));
        // Not declarations: an inline module, an indented line (which in
        // this crate means it is inside something else), a use, and prose.
        assert_eq!(module_declared_on("mod tests {"), None);
        assert_eq!(module_declared_on("    mod nested;"), None);
        assert_eq!(module_declared_on("use auth::mod;"), None);
        assert_eq!(module_declared_on("// mod auth;"), None);
    }

    /// Comment prose only, with the markers stripped and the wrapping
    /// undone.
    ///
    /// Doc comments in this crate wrap in the middle of a sentence, so a
    /// claim worth pinning is nearly always split across two lines and
    /// cannot be matched against the source as written. Collapsing to one
    /// whitespace-normalised string is what makes a phrase searchable;
    /// keeping only comment lines is what stops the scan reading code.
    ///
    /// # Arguments
    /// * `source` - Rust source, exactly as written.
    ///
    /// # Returns
    /// Every `//`, `///` and `//!` line's text, joined by single spaces.
    fn comment_prose(source: &str) -> String {
        let mut words: Vec<&str> = Vec::new();
        for line in source.lines() {
            let trimmed = line.trim_start();
            let text = trimmed
                .strip_prefix("//!")
                .or_else(|| trimmed.strip_prefix("///"))
                .or_else(|| trimmed.strip_prefix("//"));
            if let Some(text) = text {
                words.extend(text.split_whitespace());
            }
        }
        words.join(" ")
    }

    /// Sentences Phase 1.7c R13 turned false, kept here so a comment
    /// cannot quietly go back to making them.
    ///
    /// All four come from one paragraph above `session_handler`, which
    /// argued that no sibling could be same-site with this daemon yet
    /// because nginx built vhosts from `exposedApps` alone and
    /// `ferrum.daemon.subdomain` went unread. R13 built the vhost, so each
    /// of these now states the opposite of what an ordinary host does.
    const FALSIFIED_BY_R13: &[&str] = &[
        "ferrumd is loopback-only today",
        "`ferrum.daemon.subdomain` is declared but unused",
        "once a daemon vhost exists",
        "nginx builds vhosts solely from",
    ];

    /// The first sentence in `FALSIFIED_BY_R13` this source still makes.
    ///
    /// # Arguments
    /// * `source` - Rust source to read the comments of.
    ///
    /// # Returns
    /// The matched entry, or `None` for prose that makes none of them.
    fn stale_claim_in(source: &str) -> Option<&'static str> {
        let prose = comment_prose(source);
        FALSIFIED_BY_R13
            .iter()
            .copied()
            .find(|claim| prose.contains(claim))
    }

    /// A comment that has gone false is worse than no comment, because it
    /// is read as current and argues for a decision on grounds that have
    /// evaporated. This one is load-bearing in the strongest sense: the
    /// paragraph above `session_handler` is the crate's own statement of
    /// WHY the absence of CORS is the control that matters, and it reached
    /// that conclusion through a premise -- no sibling can be same-site
    /// with us yet -- that R13 removed. `ferrum-install`'s
    /// `no_state_still_claims_the_dashboard_has_not_shipped` pins the same
    /// class of sentence on the installer side, for the same reason.
    ///
    /// Scoped to the source ABOVE `mod tests`: that is where the crate's
    /// prose lives, and it is what keeps the table above from matching
    /// itself.
    #[test]
    fn no_comment_still_claims_the_daemon_has_no_vhost() {
        let (prose, _) = include_str!("main.rs")
            .split_once("\nmod tests {")
            .expect("main.rs must declare its test module at column zero");
        assert_eq!(
            stale_claim_in(prose),
            None,
            "a comment in this crate still makes a claim R13 falsified; the \
             daemon is published on <ferrum.daemon.subdomain>.<baseDomain> \
             whenever modules/proxy/lib.nix's daemonPublished holds"
        );
    }

    /// The positive control, without which the guard above is an assertion
    /// that `None == None`: a recogniser that matched nothing would leave
    /// it green forever while pinning no sentence at all.
    #[test]
    fn the_stale_claim_scan_really_reads_comments_and_only_comments() {
        for claim in FALSIFIED_BY_R13 {
            assert_eq!(
                stale_claim_in(&format!("/// {claim}")),
                Some(*claim),
                "the scan misses a claim it lists: {claim}"
            );
        }
        // Wrapped mid-sentence, which is how each of them was actually
        // written.
        assert_eq!(
            stale_claim_in("/// ferrumd is\n/// loopback-only today"),
            Some("ferrumd is loopback-only today")
        );
        // Code is not prose. A constant or a fixture naming the sentence
        // is not the crate asserting it.
        assert_eq!(stale_claim_in("let s = \"once a daemon vhost exists\";"), None);
        assert_eq!(stale_claim_in("// an ordinary comment"), None);
    }

    /// A5, on the half this crate owns.
    ///
    /// Asserted as a PROPERTY, not as the literal string: a test that only
    /// restates the constant passes on any edit that changes both, which
    /// is the shape of nearly every guard this phase has had to replace.
    /// What A5 requires is not this particular address but that ferrumd
    /// never *defaults* to an interface the world can reach -- so the
    /// assertion is `is_loopback`, and the parse is load-bearing too: the
    /// value goes straight to `TcpListener::bind`, so a hostname here
    /// would be a runtime failure on a host that has already been built.
    #[test]
    fn the_default_bind_address_is_loopback() {
        let address: std::net::IpAddr = default_listen_address().parse().expect(
            "the default must be a literal address: it is fed straight to TcpListener::bind",
        );
        assert!(
            address.is_loopback(),
            "ferrumd must not default to binding a public interface (A5); got {address}"
        );
    }

    /// A3/D5 -- the absence of CORS, enforced.
    ///
    /// The naive version of this test is worse than no test. A conforming
    /// CORS layer ECHOES the request's `Origin`, so it emits no
    /// `Access-Control-Allow-Origin` at all when the request carries none
    /// -- and every other test in this file builds Origin-less requests. An
    /// assertion over those would sit green against exactly the
    /// reflected-origin configuration `session_handler`'s own comment names
    /// as fatal. So every request below carries a real sibling `Origin`,
    /// the one a compromised `sonarr.<baseDomain>` would send.
    mod cors_is_absent {
        use super::*;

        /// A same-site sibling. After R13 the dashboard and every catalog
        /// app share a registrable domain, so this is not a hypothetical
        /// attacker-controlled origin -- it is the shape of the one the
        /// spec's own threat model names.
        const SIBLING_ORIGIN: &str = "https://sonarr.example.test";

        /// Every `/api` route the real router declares: the pattern as
        /// written in `build_router`, the method that really reaches it,
        /// and a concrete URI that matches the pattern.
        ///
        /// Kept honest by `the_matrix_covers_every_api_route` below, which
        /// re-derives the method/pattern pairs from `build_router`'s own
        /// source. Without that, a route added later would simply not be
        /// tested, and nothing would say so.
        /// `pub(super)` so the extension guard in the parent test module can
        /// reuse it: that check has the same requirement this table already
        /// carries its own guard for -- it must cover EVERY route, or the
        /// absence it proves is quietly partial.
        pub(super) const API_ROUTES: &[(&str, &str, &str)] = &[
            ("POST", "/api/login", "/api/login"),
            ("POST", "/api/logout", "/api/logout"),
            ("GET", "/api/catalog", "/api/catalog"),
            ("GET", "/api/generations", "/api/generations"),
            // No `?job=`: the probe asks for the most recent report, the
            // shape the Updates view uses on first paint, and the one that
            // answers 200 on a host that has never been checked rather
            // than the 400 a non-UUID `job` would earn.
            ("GET", "/api/updates", "/api/updates"),
            ("GET", "/api/settings", "/api/settings"),
            ("PUT", "/api/settings", "/api/settings"),
            ("POST", "/api/secrets/:name", "/api/secrets/cors-probe"),
            ("GET", "/api/session", "/api/session"),
            ("POST", "/api/jobs", "/api/jobs"),
            ("GET", "/api/jobs", "/api/jobs"),
            // Deliberately not a UUID: `get_job` and `stream_job` both
            // reject it immediately, so the SSE route answers instead of
            // holding the connection open for the length of the test run.
            ("GET", "/api/jobs/:id", "/api/jobs/not-a-uuid"),
            ("GET", "/api/jobs/:id/stream", "/api/jobs/not-a-uuid/stream"),
            ("POST", "/api/password", "/api/password"),
        ];

        /// Fails on ANY `access-control-*` response header, not only
        /// `Access-Control-Allow-Origin`. A3 names that one header because
        /// it is the one that does the damage, but a response carrying
        /// `Access-Control-Allow-Credentials` or an exposed-headers list is
        /// already a CORS layer somebody is part-way through wiring up.
        fn assert_no_cors_headers(context: &str, response: &axum::response::Response) {
            let offending: Vec<String> = response
                .headers()
                .iter()
                .filter(|(name, _)| name.as_str().starts_with("access-control-"))
                .map(|(name, value)| format!("{name}: {value:?}"))
                .collect();
            assert!(
                offending.is_empty(),
                "{context} was served with CORS headers, which is what would let a \
                 same-site sibling read the control plane's responses: {offending:?}"
            );
        }

        /// A real, currently-valid session on the real database.
        ///
        /// Taken fresh for each authenticated probe rather than reused,
        /// because the matrix drives `POST /api/logout` like every other
        /// route -- with one shared session every request after that one
        /// would quietly become a 401, and the matrix would stop testing
        /// what it says it tests.
        fn fresh_credentials(state: &Arc<AppState>, password: &str) -> (String, String) {
            let result = auth::login(&state.db, "admin", password, &test_client()).unwrap().session().unwrap();
            (result.session_token, result.csrf_token)
        }

        /// A real session paired with a CSRF token that is not the one the
        /// session row holds.
        ///
        /// This is the only way to reach `require_session`'s FORBIDDEN
        /// branch, which D5 leg 1 names alongside 401 and 500. Without it
        /// the matrix drives every authenticated request with a VALID
        /// token, so the 403 return is never on any response the CORS
        /// assertion sees -- and 403 is the refusal a browser's
        /// cross-origin attempt actually earns, since the attacker can
        /// send the cookie but cannot read the token.
        fn forged_csrf(state: &Arc<AppState>, password: &str) -> (String, String) {
            let (session, csrf) = fresh_credentials(state, password);
            assert_ne!(csrf, FORGED_CSRF_TOKEN, "the forged token must differ");
            (session, FORGED_CSRF_TOKEN.to_string())
        }

        /// Not a real token, and deliberately not empty: an empty header
        /// is already covered by `an_empty_stored_token_is_never_a_wildcard`.
        const FORGED_CSRF_TOKEN: &str = "not-the-session-csrf-token";

        fn request(method: &str, uri: &str, cookie: Option<&(String, String)>) -> Request<Body> {
            let mut builder = Request::builder()
                .method(Method::from_bytes(method.as_bytes()).unwrap())
                .uri(uri)
                .header("Origin", SIBLING_ORIGIN)
                .header("Content-Type", "application/json");
            if let Some((session, csrf)) = cookie {
                builder = builder
                    .header("Cookie", format!("{SESSION_COOKIE}={session}"))
                    .header(CSRF_HEADER, csrf);
            }
            builder.body(Body::from("{}")).unwrap()
        }

        /// The CORS preflight a browser sends before a cross-origin
        /// mutating request. It arrives as a bare `OPTIONS`, which is
        /// precisely where a CORS layer answers on the handler's behalf --
        /// so it is crossed with every route rather than checked once.
        fn preflight(method: &str, uri: &str) -> Request<Body> {
            Request::builder()
                .method(Method::OPTIONS)
                .uri(uri)
                .header("Origin", SIBLING_ORIGIN)
                .header("Access-Control-Request-Method", method)
                .header("Access-Control-Request-Headers", CSRF_HEADER)
                .body(Body::empty())
                .unwrap()
        }

        /// Every route, unauthenticated, authenticated, and authenticated
        /// with a forged CSRF token, on both the real method and its
        /// preflight.
        ///
        /// The three passes are not redundant, because each one is refused
        /// at a different point in the stack, and a CORS layer applied
        /// unconditionally shows up on whichever of them the handler never
        /// reaches. The unauthenticated pass is where the 401s live; the
        /// forged-CSRF pass is where the 403s live (D5 leg 1 names both,
        /// and the 500 has its own test below); the authenticated pass is
        /// the one where the handler really runs.
        #[tokio::test]
        async fn no_api_route_is_ever_served_with_a_cors_header() {
            let (dir, state, _session, _csrf) = logged_in();
            let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password"))
                .unwrap()
                .trim()
                .to_string();
            let mut unauthenticated_statuses = Vec::new();
            let mut authenticated_statuses = Vec::new();
            let mut forged_csrf_statuses = Vec::new();

            for (method, pattern, uri) in API_ROUTES {
                let response = build_router(state.clone())
                    .oneshot(request(method, uri, None))
                    .await
                    .unwrap();
                assert_no_cors_headers(&format!("unauthenticated {method} {pattern}"), &response);
                unauthenticated_statuses.push(response.status());

                let credentials = fresh_credentials(&state, &password);
                let response = build_router(state.clone())
                    .oneshot(request(method, uri, Some(&credentials)))
                    .await
                    .unwrap();
                assert_no_cors_headers(&format!("authenticated {method} {pattern}"), &response);
                authenticated_statuses.push(response.status());

                let forged = forged_csrf(&state, &password);
                let response = build_router(state.clone())
                    .oneshot(request(method, uri, Some(&forged)))
                    .await
                    .unwrap();
                assert_no_cors_headers(
                    &format!("session-with-forged-CSRF {method} {pattern}"),
                    &response,
                );
                forged_csrf_statuses.push(response.status());

                let response = build_router(state.clone())
                    .oneshot(preflight(method, uri))
                    .await
                    .unwrap();
                assert_no_cors_headers(
                    &format!("OPTIONS preflight for {method} {pattern}"),
                    &response,
                );
            }

            // The matrix has to have really produced both a refusal and a
            // success, or it proves only that a router answering nothing
            // answers nothing with CORS headers.
            assert!(
                unauthenticated_statuses.contains(&StatusCode::UNAUTHORIZED),
                "no 401 was produced, so the error path was never exercised: \
                 {unauthenticated_statuses:?}"
            );
            // And the same for the 403. `require_session` only reaches
            // FORBIDDEN on a mutating method, so this passing depends on
            // API_ROUTES still containing one -- which is exactly what the
            // assertion says when it fails.
            assert!(
                forged_csrf_statuses.contains(&StatusCode::FORBIDDEN),
                "no 403 was produced, so the CSRF-refusal path D5 names was \
                 never exercised: {forged_csrf_statuses:?}"
            );
            assert!(
                authenticated_statuses.iter().any(StatusCode::is_success),
                "no route succeeded, so the happy path was never exercised: \
                 {authenticated_statuses:?}"
            );
        }

        /// The 500 path, separately, because it is the hardest to reach and
        /// the easiest to leave uncovered. A session whose user row is gone
        /// makes `session_handler` return 500 from inside the handler --
        /// past routing, past `require_session` -- which is a different
        /// point in the stack from every 401 above.
        #[tokio::test]
        async fn an_internal_error_response_carries_no_cors_header_either() {
            let (_dir, state, session, csrf) = logged_in();
            // rusqlite's bundled SQLite enforces foreign keys by default
            // -- confirmed the hard way, the first version of this fixture
            // got a real FOREIGN KEY constraint failure -- so the pragma
            // has to come off to construct the inconsistency deliberately.
            // The inconsistency itself is real, and is exactly the one
            // `session_handler` documents: a live session row pointing at a
            // user that is gone.
            state
                .db
                .conn()
                .execute_batch("PRAGMA foreign_keys = OFF; DELETE FROM users;")
                .unwrap();

            let response = build_router(state)
                .oneshot(request("GET", "/api/session", Some(&(session, csrf))))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "the fixture must really produce a 500, or this test proves nothing"
            );
            assert_no_cors_headers("the 500 from GET /api/session", &response);
        }

        /// `API_ROUTES` must list exactly what `build_router` registers.
        ///
        /// This is the anti-vacuity guard. An absence proof is only as wide
        /// as the set it walks, and a hand-maintained table stops being
        /// that set the first time somebody adds a route -- silently, and
        /// in the direction of passing. So the pairs are re-derived from
        /// the real source of the real function and compared.
        #[test]
        fn the_matrix_covers_every_api_route() {
            let source = include_str!("main.rs");
            let body = source
                .split_once("fn build_router(")
                .expect("build_router must exist")
                .1
                .split_once("\n}\n")
                .expect("build_router must end")
                .0;

            // The derivation below reads exactly one shape: a literal
            // `.route("<path>", <method>(...))`. Every other way of
            // registering a route -- a path constant, a loop over a table,
            // a helper that returns a Router, a nested or merged router
            // built somewhere this scan cannot see -- would shrink
            // `declared` and `covered` TOGETHER and keep passing, which is
            // the one failure this guard exists to make impossible. So the
            // shapes it cannot read are refused outright: a refactor into
            // one of them fails here, loudly, and teaching the scan the new
            // shape is the price of making it.
            assert_eq!(
                body.matches(".route(").count(),
                body.matches(".route(\"").count(),
                "build_router registers a route whose path is not a string \
                 literal, so the scan below cannot see it"
            );
            for unreadable in [".nest(", ".route_service(", "for ", "while "] {
                assert!(
                    !body.contains(unreadable),
                    "build_router now contains {unreadable:?}, which can \
                     register routes this scan cannot derive; teach the \
                     scan that shape before using it"
                );
            }
            // `.merge(x)` is fine only when x is built inside this function,
            // where its own `.route(` lines are part of what gets scanned.
            for merged in body.split(".merge(").skip(1) {
                let name = merged.split(')').next().expect("a merge has an argument");
                assert!(
                    body.contains(&format!("let {name} =")),
                    "build_router merges {name:?}, which is built outside the \
                     scanned body, so its routes are invisible here"
                );
            }

            let mut declared: Vec<(String, String)> = Vec::new();
            for line in body.lines() {
                let Some((_, rest)) = line.split_once(".route(\"") else {
                    continue;
                };
                let path = rest.split_once('"').expect("a route path is quoted").0;
                for (needle, method) in [
                    ("get(", "GET"),
                    ("post(", "POST"),
                    ("put(", "PUT"),
                    ("patch(", "PATCH"),
                    ("delete(", "DELETE"),
                ] {
                    if line.contains(needle) {
                        declared.push((method.to_string(), path.to_string()));
                    }
                }
            }
            declared.sort();
            assert!(
                !declared.is_empty(),
                "the source scan found no routes at all, so the scan itself is broken"
            );

            let mut covered: Vec<(String, String)> = API_ROUTES
                .iter()
                .map(|(method, pattern, _)| ((*method).to_string(), (*pattern).to_string()))
                .collect();
            covered.sort();
            assert_eq!(
                declared, covered,
                "every route build_router registers must appear in API_ROUTES"
            );
        }

        /// And each concrete URI really does match its pattern. A typo
        /// would send the probe to the static-file fallback instead of the
        /// API -- and the fallback carries no CORS headers either, so
        /// nothing above would fail.
        #[tokio::test]
        async fn every_probe_uri_really_reaches_its_route() {
            let (dir, state, _session, _csrf) = logged_in();
            let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password"))
                .unwrap()
                .trim()
                .to_string();
            for (method, pattern, uri) in API_ROUTES {
                let credentials = fresh_credentials(&state, &password);
                let response = build_router(state.clone())
                    .oneshot(request(method, uri, Some(&credentials)))
                    .await
                    .unwrap();
                assert_ne!(
                    response.status(),
                    StatusCode::NOT_FOUND,
                    "{method} {uri} did not match {pattern}; it fell through to the \
                     static-file fallback, so the CORS matrix never tested this route"
                );
            }
        }
    }

    #[test]
    fn an_empty_stored_token_is_never_a_wildcard() {
        // Defensive: a session row with an empty csrf_token must fail every
        // request rather than accept an empty header.
        assert!(!csrf_header_is_valid(Some(""), ""));
        assert!(!csrf_header_is_valid(None, ""));
        assert!(!csrf_header_is_valid(Some("anything"), ""));
        assert!(csrf_header_is_valid(Some("real"), "real"));
    }

    /// M3, the interlock watcher. See `attach_and_watch`.
    mod job_watch {
        use super::*;
        use std::sync::atomic::{AtomicUsize, Ordering};

        fn state() -> AppState {
            let dir = tempfile::tempdir().unwrap();
            let db = db::Db::open(&dir.path().join("test.db")).unwrap();
            // The TempDir is dropped here on purpose: SQLite keeps the open
            // handle, and nothing in these tests touches the file again.
            AppState { db, job_running: Mutex::new(false) }
        }

        /// The half of M3 that needs no race at all.
        ///
        /// The listener used to log its error once and return. Anything
        /// that made the first attachment fail -- and ferrumd is ordered
        /// only `after = network.target`, so "the system bus is not up
        /// yet" is an ordinary startup, not an exotic one -- left the
        /// daemon with no listener for the rest of its lifetime. The first
        /// job then set the interlock, nothing ever cleared it, and every
        /// subsequent `POST /api/jobs` answered 409 forever. Nothing in
        /// the UI could recover it, because recovering it meant restarting
        /// ferrumd, and restarting ferrumd meant running a job.
        ///
        /// The fake attachment always fails, which is what a real one does
        /// against a bus that is not there. The assertion is simply that
        /// the supervisor tried again: one attempt is the defect, two is
        /// the fix.
        ///
        /// Real time rather than a paused clock, deliberately -- pausing
        /// would need tokio's `test-util` feature, and this is not worth a
        /// change to the crate's dependencies. The first retry is due one
        /// second in (`reconnect_delay(0)`), so the wait below settles in
        /// about that long when the supervisor is correct, and burns its
        /// whole deadline only when it has already given up.
        #[tokio::test]
        async fn the_listener_re_attaches_after_a_failed_attempt() {
            let attempts = Arc::new(AtomicUsize::new(0));
            let counter = attempts.clone();
            let watcher = tokio::spawn(async move {
                supervise_job_watch(move || {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        anyhow::anyhow!("the system bus is not up yet")
                    }
                })
                .await;
            });

            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while attempts.load(Ordering::SeqCst) < 2 && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            watcher.abort();

            assert!(
                attempts.load(Ordering::SeqCst) >= 2,
                "a failed attachment must be retried, not surrendered to: a listener that \
                 exits leaves the single-job interlock with nothing to clear it, and the \
                 first job then wedges the daemon permanently. Attempts observed: {}",
                attempts.load(Ordering::SeqCst)
            );
        }

        /// The retry must not become a busy loop against a bus that is
        /// down -- and must not stall forever either.
        #[test]
        fn the_reconnect_delay_is_never_zero_and_never_unbounded() {
            assert_eq!(reconnect_delay(0), Duration::from_secs(1));
            assert_eq!(reconnect_delay(1), Duration::from_secs(2));
            for attempt in 0..64 {
                let delay = reconnect_delay(attempt);
                assert!(delay >= Duration::from_secs(1), "attempt {attempt} would spin");
                assert!(delay <= Duration::from_secs(30), "attempt {attempt} would stall");
            }
        }

        /// Reconciliation corrects the flag in both directions. The
        /// "systemd says nothing is running" direction is the one that
        /// undoes a missed `JobRemoved`; without it a re-attachment would
        /// restore the listener but not the state it was supposed to be
        /// keeping.
        #[test]
        fn reconciling_sets_the_interlock_from_systemds_answer_in_both_directions() {
            let state = state();

            reconcile_interlock(&state, true);
            assert!(*state.job_running.lock().unwrap(), "a running apply must hold the interlock");

            reconcile_interlock(&state, true);
            assert!(*state.job_running.lock().unwrap(), "reconciling twice must not flip it");

            reconcile_interlock(&state, false);
            assert!(
                !*state.job_running.lock().unwrap(),
                "a completion missed while detached is gone forever, so systemd's own answer \
                 has to be able to release the interlock"
            );
        }

        /// The ordering half of M3, pinned against the source itself.
        ///
        /// The defect is a sequence of awaits inside one function, and the
        /// failure it produces needs a real system bus and a completion
        /// landing in a window of microseconds -- there is no honest
        /// timing test for it. What there IS is the thing that makes it
        /// safe: `attach_and_watch` subscribes and opens the signal stream
        /// BEFORE it asks systemd what is running, so no completion can
        /// fall between the question and the listener. That is a property
        /// of the source, and this reads the source.
        ///
        /// Same technique, and the same reason, as
        /// `no_source_file_reads_a_forward_auth_header` above: the
        /// property is about what the code does and does not do, not about
        /// what a call returns.
        #[test]
        fn the_watcher_subscribes_before_it_asks_systemd_what_is_running() {
            let body = include_str!("main.rs")
                .split_once("async fn attach_and_watch(")
                .expect("attach_and_watch must still exist")
                .1
                .split_once("\nasync fn ")
                .map(|(body, _)| body)
                .expect("attach_and_watch must be followed by another async fn");

            let subscribe = body.find("proxy.subscribe()").expect("it must still subscribe");
            let stream = body
                .find("proxy.receive_job_removed()")
                .expect("it must still open the signal stream");
            let query = body
                .find("ferrum_apply_job_is_running(")
                .expect("it must still ask systemd what is running");

            assert!(
                subscribe < query && stream < query,
                "the JobRemoved subscription and its stream must be established BEFORE \
                 systemd is asked what is running (subscribe at {subscribe}, stream at \
                 {stream}, query at {query}). Asking first loses any completion that lands \
                 in between -- the signal goes to nobody, the query has already said \
                 'running', and the interlock stays closed for the process lifetime, \
                 answering every POST /api/jobs with 409"
            );
        }
    }
}
