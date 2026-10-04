//! Helpers shared by the route, auth and server tests.
//!
//! Everything here runs against a fresh in-memory database, so tests never see
//! each other's users, sessions or items.

#![cfg(test)]

use std::time::Duration;

use axum::{
    Router,
    body::Body,
    http::{Request, header},
    response::Response,
};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

use crate::{AppState, auth::AuthConfig, db, routes};

/// A migrated in-memory database. Tests that need to look behind the API — to
/// read a stored password hash, say — hang on to this.
pub fn state() -> AppState {
    let conn = db::open_in_memory().expect("in-memory database");
    db::migrate(&conn).expect("migrate");
    AppState::new(
        conn,
        AuthConfig {
            cookie_secure: false,
            ttl: Duration::from_secs(3600),
        },
    )
}

pub fn app() -> Router {
    app_with(state())
}

pub fn app_with(state: AppState) -> Router {
    app_with_timeout(state, crate::REQUEST_TIMEOUT)
}

pub fn app_with_timeout(state: AppState, timeout: Duration) -> Router {
    routes::build_router(timeout).with_state(state)
}

pub async fn json_of(response: Response) -> Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("body should be JSON ({err}): {bytes:?}"))
}

/// The `name=value` pair from a `Set-Cookie` header, or `None` when the
/// response did not set the session cookie. Enough to hand back to the next
/// request as a `Cookie` header.
pub fn session_cookie(response: &Response) -> Option<String> {
    let raw = response.headers().get(header::SET_COOKIE)?.to_str().ok()?;
    let pair = raw.split(';').next()?.trim();
    let (name, value) = pair.split_once('=')?;
    (name == crate::auth::SESSION_COOKIE && !value.is_empty()).then(|| pair.to_string())
}

/// Sends one request through the router. `body` is sent as JSON when present;
/// `cookie` is sent verbatim as a `Cookie` header.
pub async fn send(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> Response {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    let request = match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    app.clone().oneshot(request).await.unwrap()
}
