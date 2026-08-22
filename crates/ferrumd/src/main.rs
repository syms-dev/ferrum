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

async fn require_session(
    State(state): State<Arc<AppState>>,
    cookies: tower_cookies::Cookies,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let token = cookies.get("ferrumd_session").ok_or(StatusCode::UNAUTHORIZED)?;
    match auth::validate_session(&state.db, token.value()) {
        Ok(Some(_csrf)) => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
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
        }
    }
    anyhow::bail!("the systemd JobRemoved signal stream ended unexpectedly")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    let protected = Router::new()
        .route("/api/settings", axum::routing::get(settings::get_settings).put(settings::put_settings))
        .route("/api/secrets/:name", axum::routing::post(secrets_api::write_secret))
        .route("/api/jobs", axum::routing::post(jobs::create_job))
        .route("/api/jobs/:id/stream", axum::routing::get(jobs::stream_job))
        .route_layer(axum::middleware::from_fn_with_state(state.clone(), require_session));

    let app = Router::new()
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .merge(protected)
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listen_address = std::env::var("FERRUMD_LISTEN_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("FERRUMD_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(7788);
    let listener = tokio::net::TcpListener::bind(format!("{listen_address}:{port}")).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
