mod auth;
mod db;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};

pub struct AppState {
    pub db: db::Db,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let state_dir = std::env::var("FERRUMD_STATE_DIR").unwrap_or_else(|_| "/var/lib/ferrum".to_string());
    let state_dir = std::path::Path::new(&state_dir);
    let db = db::Db::open(&state_dir.join("ferrumd.db"))?;
    auth::ensure_first_user(&db, state_dir)?;

    let state = Arc::new(AppState { db });
    let app = Router::new()
        .route("/api/login", post(login_handler))
        .route("/api/logout", post(logout_handler))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let listen_address = std::env::var("FERRUMD_LISTEN_ADDRESS").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("FERRUMD_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(7788);
    let listener = tokio::net::TcpListener::bind(format!("{listen_address}:{port}")).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
