mod auth;
mod db;
mod dbus;
mod jobs;
mod secrets_api;
mod settings;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};

pub struct AppState {
    pub db: db::Db,
    /// ferrumd's own single-job interlock -- see jobs::create_job. Seeded
    /// at startup from systemd's real view of whether a
    /// `ferrum-apply@*.service` is currently running (see
    /// dbus::ferrum_apply_job_is_running), so a ferrumd restarted mid-apply
    /// by its own generation switch does not admit a second job. Cleared
    /// both by ferrum-apply finishing (via systemd's JobRemoved signal,
    /// below) and, on the failure paths, by create_job itself.
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

async fn login_handler(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    match auth::login(&state.db, &req.username, &req.password) {
        Ok(Some(result)) => {
            let mut cookie = Cookie::new("ferrumd_session", result.session_token);
            cookie.set_http_only(true);
            cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            cookie.set_path("/");
            cookies.add(cookie);
            (StatusCode::OK, Json(LoginResponse { csrf_token: result.csrf_token })).into_response()
        }
        Ok(None) => StatusCode::UNAUTHORIZED.into_response(),
        Err(e) => (StatusCode::TOO_MANY_REQUESTS, e.to_string()).into_response(),
    }
}

async fn logout_handler(State(state): State<Arc<AppState>>, cookies: Cookies) -> impl IntoResponse {
    if let Some(cookie) = cookies.get("ferrumd_session") {
        let _ = auth::logout(&state.db, cookie.value());
    }
    cookies.remove(Cookie::new("ferrumd_session", ""));
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
/// Existing sessions are deliberately NOT invalidated, including this one:
/// the session cookie is an independent credential that this call never
/// touches, and logging an operator out of the tab they just used to change
/// their password would be a worse experience with no security gain against
/// the threat this endpoint exists for (an operator rotating the generated
/// bootstrap password into one of their own).
async fn change_password_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(SessionUserId(user_id)): axum::Extension<SessionUserId>,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    if req.new_password.is_empty() {
        return (StatusCode::BAD_REQUEST, "the new password must not be empty").into_response();
    }
    match auth::change_password(&state.db, user_id, &req.current_password, &req.new_password) {
        Ok(true) => StatusCode::OK.into_response(),
        Ok(false) => (StatusCode::UNAUTHORIZED, "the current password is incorrect").into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to change the password: {e}"),
        )
            .into_response(),
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
    let token = cookies.get("ferrumd_session").ok_or(StatusCode::UNAUTHORIZED)?;
    let session = match auth::validate_session(&state.db, token.value()) {
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

    Ok(next.run(request).await)
}

/// The real application router, built separately from `main` so the tests
/// at the bottom of this file exercise the REAL middleware stack (cookie
/// layer, `require_session`, the actual routes) rather than a re-declared
/// approximation of it.
fn build_router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/api/settings", axum::routing::get(settings::get_settings).put(settings::put_settings))
        .route("/api/secrets/:name", axum::routing::post(secrets_api::write_secret))
        .route("/api/jobs", axum::routing::post(jobs::create_job))
        .route("/api/jobs/:id/stream", axum::routing::get(jobs::stream_job))
        .route("/api/password", post(change_password_handler))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_session));

    Router::new()
        .route("/api/login", post(login_handler))
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

/// Clears `job_running` when the real ferrum-apply unit's systemd job
/// finishes, whatever its result -- including the case ferrum-apply
/// crashed before writing a "complete" line to its own progress file.
async fn watch_job_completions(state: Arc<AppState>) -> anyhow::Result<()> {
    let connection = zbus::Connection::system().await?;
    let proxy = dbus::SystemdManagerProxy::new(&connection).await?;
    proxy.subscribe().await?;
    let mut stream = proxy.receive_job_removed().await?;
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

    // The interlock is in-process state, so it would otherwise start every
    // process lifetime believing nothing is running. That is wrong in one
    // real, reachable case: an `apply` job can switch to a generation
    // carrying a new ferrumd, which restarts ferrumd WHILE that same apply
    // is still executing -- and the restarted daemon would then happily
    // admit a second, concurrent job. Ask systemd (the only durable source
    // of truth about what is actually running) before serving anything.
    //
    // On a query failure this seeds `false` rather than `true`: a failed
    // query is not evidence that a job is running, and seeding `true` would
    // leave the daemon refusing every job forever with no way to clear the
    // flag (nothing would ever start, so no JobRemoved would ever arrive).
    // The failure is logged loudly instead.
    let job_running = match dbus::ferrum_apply_job_is_running().await {
        Ok(running) => {
            if running {
                eprintln!(
                    "ferrumd: a ferrum-apply job is still running -- starting with the \
                     single-job interlock already held; new jobs will be refused until it \
                     finishes"
                );
            }
            running
        }
        Err(e) => {
            eprintln!(
                "ferrumd: could not ask systemd whether a ferrum-apply job is running: {e} -- \
                 assuming none is. If ferrumd was just restarted by an in-flight apply, a \
                 second concurrent job could be admitted."
            );
            false
        }
    };

    let state = Arc::new(AppState { db, job_running: Mutex::new(job_running) });

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
    {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = watch_job_completions(state).await {
                // Deliberately loud rather than silent: if this listener
                // never comes up, the single-job interlock can only ever
                // be cleared on create_job's own failure paths, so the
                // daemon would refuse every job after the first. That is a
                // real, operator-visible degradation and belongs in the
                // journal, not swallowed by an `if let Ok` chain.
                eprintln!("ferrumd: job-completion listener stopped: {e}");
            }
        });
    }

    let app = build_router(state);

    let listen_address = std::env::var("FERRUMD_LISTEN_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("FERRUMD_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(7788);
    let listener = tokio::net::TcpListener::bind(format!("{listen_address}:{port}")).await?;
    axum::serve(listener, app).await?;
    Ok(())
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

    /// A real database with a real user, plus a real login producing a real
    /// session cookie and its real paired CSRF token.
    fn logged_in() -> (tempfile::TempDir, Arc<AppState>, String, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = db::Db::open(&dir.path().join("test.db")).unwrap();
        auth::ensure_first_user(&db, dir.path()).unwrap();
        let password = std::fs::read_to_string(dir.path().join("ferrumd-setup-password")).unwrap();
        let result = auth::login(&db, "admin", password.trim()).unwrap().unwrap();
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
            .header("Cookie", format!("ferrumd_session={session}"));
        if let Some(csrf) = csrf {
            builder = builder.header(CSRF_HEADER, csrf);
        }
        builder.body(Body::empty()).unwrap()
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
        let other = auth::login(&state.db, "admin", password.trim())
            .unwrap()
            .unwrap();
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
                .header("Cookie", format!("ferrumd_session={session}"))
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
            .header("Cookie", format!("ferrumd_session={session}"))
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
            .header("Cookie", format!("ferrumd_session={session}"))
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

        assert!(auth::login(&state.db, "admin", "the-new-one").unwrap().is_some());
        assert!(
            auth::login(&state.db, "admin", &old).unwrap().is_none(),
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
            auth::login(&state.db, "admin", &old).unwrap().is_some(),
            "the real password must still work after a refused rotation"
        );
        assert!(auth::login(&state.db, "admin", "attempted").unwrap().is_none());
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
        assert!(auth::login(&state.db, "admin", old.trim()).unwrap().is_some());
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

    #[test]
    fn an_empty_stored_token_is_never_a_wildcard() {
        // Defensive: a session row with an empty csrf_token must fail every
        // request rather than accept an empty header.
        assert!(!csrf_header_is_valid(Some(""), ""));
        assert!(!csrf_header_is_valid(None, ""));
        assert!(!csrf_header_is_valid(Some("anything"), ""));
        assert!(csrf_header_is_valid(Some("real"), "real"));
    }
}
