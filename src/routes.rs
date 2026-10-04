//! HTTP surface: the demo routes plus the four auth endpoints, and the layers
//! every route shares.

use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    middleware::map_response,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::json;
use tower_http::{cors::CorsLayer, timeout::TimeoutLayer, trace::TraceLayer};

use crate::{
    AppState, REQUEST_TIMEOUT,
    api::ApiError,
    auth::{self, CurrentUser},
    db::{self, Item},
};

/// Biggest request body any route accepts. The auth endpoints only need a
/// username and a password; this also bounds what an unauthenticated caller can
/// make the server buffer.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Embedded at compile time so the image stays self-contained — no volume
/// mount needed to serve the test console.
const TEST_PAGE: &str = include_str!("../static/index.html");

pub fn build_router(timeout: Duration) -> Router<AppState> {
    Router::new()
        .route("/", get(index_page))
        .route("/api/routes", get(index))
        .route("/health", get(health))
        .route("/api/hello/{name}", get(hello))
        .route("/api/echo", axum::routing::post(echo))
        .route("/api/slow", get(slow))
        .route("/api/auth/register", axum::routing::post(auth::register))
        .route("/api/auth/login", axum::routing::post(auth::login))
        .route("/api/auth/logout", axum::routing::post(auth::logout))
        .route("/api/auth/me", get(auth::me))
        // The demo collection is what auth guards: it is the one place where
        // "logged in" has a visible effect.
        .route("/api/items", get(list_items).post(create_item))
        .route("/api/items/{id}", get(get_item).delete(delete_item))
        // Login and /api/auth/me answer with credentials; a shared cache must
        // not keep either of them after the response.
        .layer(map_response(no_store))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(TraceLayer::new_for_http())
        // Wide-open CORS suits local development; pin `allow_origin` before
        // production use.
        //
        // Note this one cannot carry credentials: the CORS spec forbids
        // `Access-Control-Allow-Credentials: true` alongside a wildcard origin,
        // so a cross-origin client will not get the session cookie sent. The
        // test console is same-origin, so it does not need it; serving a
        // separate front end means listing that origin here and turning
        // `allow_credentials(true)` on.
        .layer(CorsLayer::permissive())
}

async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn index_page() -> Html<&'static str> {
    Html(TEST_PAGE)
}

async fn index() -> Json<serde_json::Value> {
    Json(json!({
        "service": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "routes": [
            "POST   /api/auth/register        注册（无需登录）",
            "POST   /api/auth/login           登录，返回 session Cookie",
            "POST   /api/auth/logout          注销，仅当前令牌失效",
            "GET    /api/auth/me              当前用户（需登录）",
            "GET    /                         测试台页面",
            "GET    /api/routes               接口清单（JSON）",
            "GET    /health                   健康检查，被 Docker HEALTHCHECK 使用",
            "GET    /api/hello/{name}?loud=true",
            "POST   /api/echo",
            "GET    /api/items                列出全部条目（需登录）",
            "POST   /api/items                新建条目（需登录）",
            "GET    /api/items/{id}           按 id 查询（需登录）",
            "DELETE /api/items/{id}           删除条目（需登录）",
            "GET    /api/slow?ms=2000",
        ],
    }))
}

/// Liveness probe target. It does read the database, because a server whose
/// database has gone away is not serving anything useful — a probe that
/// ignored SQLite would stay green through exactly that failure.
async fn health(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let (users, items) = state
        .db(|conn| Ok((db::count_users(conn)?, db::count_items(conn)?)))
        .await?;
    Ok(Json(json!({
        "status": "ok",
        "uptime_secs": uptime().as_secs(),
        "users": users,
        "items": items,
    })))
}

fn uptime() -> Duration {
    use std::sync::OnceLock;
    static BOOT: OnceLock<Instant> = OnceLock::new();
    BOOT.get_or_init(Instant::now).elapsed()
}

async fn hello(
    Query(params): Query<HelloParams>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    let message = format!("Hello, {name}!");
    Json(json!({
        "message": if params.loud.unwrap_or(false) { message.to_uppercase() } else { message },
    }))
}

#[derive(Debug, Deserialize)]
struct HelloParams {
    loud: Option<bool>,
}

async fn echo(Json(body): Json<serde_json::Value>) -> Json<serde_json::Value> {
    Json(json!({ "echoed": body }))
}

async fn slow(Query(params): Query<SlowParams>) -> Json<serde_json::Value> {
    let ms = params
        .ms
        .unwrap_or(1000)
        .min(REQUEST_TIMEOUT.as_millis() as u64 + 1);
    tokio::time::sleep(Duration::from_millis(ms)).await;
    Json(json!({ "slept_ms": ms }))
}

#[derive(Debug, Deserialize)]
struct SlowParams {
    ms: Option<u64>,
}

// ---------- the protected demo collection ----------

async fn list_items(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Json<Vec<Item>>, ApiError> {
    Ok(Json(state.db(|conn| Ok(db::list_items(conn)?)).await?))
}

async fn create_item(
    State(state): State<AppState>,
    _user: CurrentUser,
    Json(new): Json<NewItem>,
) -> Result<Response, ApiError> {
    let item = state
        .db(move |conn| Ok(db::create_item(conn, new.name.trim())?))
        .await?;
    Ok((StatusCode::CREATED, Json(item)).into_response())
}

async fn get_item(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(id): Path<i64>,
) -> Result<Json<Item>, ApiError> {
    state
        .db(move |conn| Ok(db::item(conn, id)?))
        .await?
        .map(Json)
        .ok_or_else(|| item_not_found(id))
}

async fn delete_item(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let deleted = state.db(move |conn| Ok(db::delete_item(conn, id)?)).await?;
    if deleted == 0 {
        return Err(item_not_found(id));
    }
    Ok(StatusCode::NO_CONTENT)
}

fn item_not_found(id: i64) -> ApiError {
    ApiError::NotFound(format!("item {id} not found"))
}

#[derive(Debug, Deserialize)]
struct NewItem {
    name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{self, app, app_with, send, state};
    use http_body_util::BodyExt as _;

    /// Registers `alice` and returns the app plus her session cookie.
    async fn signed_in() -> (axum::Router, String) {
        let app = app();
        sign_in(&app, "alice").await
    }

    async fn sign_in(app: &axum::Router, username: &str) -> (axum::Router, String) {
        send(
            app,
            "POST",
            "/api/auth/register",
            Some(json!({ "username": username, "password": "correct horse" })),
            None,
        )
        .await;
        let response = send(
            app,
            "POST",
            "/api/auth/login",
            Some(json!({ "username": username, "password": "correct horse" })),
            None,
        )
        .await;
        let cookie = testutil::session_cookie(&response).expect("session cookie");
        (app.clone(), cookie)
    }

    #[tokio::test]
    async fn health_reports_ok() {
        let response = send(&app(), "GET", "/health", None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = testutil::json_of(response).await;
        assert_eq!(body["status"], "ok");
        assert_eq!(body["users"], 0);
        assert_eq!(body["items"], 3);
    }

    #[tokio::test]
    async fn hello_defaults_to_lowercase() {
        let response = send(&app(), "GET", "/api/hello/world", None, None).await;
        assert_eq!(
            testutil::json_of(response).await["message"],
            "Hello, world!"
        );
    }

    #[tokio::test]
    async fn hello_uppercases_when_asked() {
        let response = send(&app(), "GET", "/api/hello/world?loud=true", None, None).await;
        assert_eq!(
            testutil::json_of(response).await["message"],
            "HELLO, WORLD!"
        );
    }

    #[tokio::test]
    async fn echo_returns_the_request_body() {
        let response = send(&app(), "POST", "/api/echo", Some(json!({ "a": 1 })), None).await;
        assert_eq!(testutil::json_of(response).await["echoed"]["a"], 1);
    }

    #[tokio::test]
    async fn the_demo_routes_stay_open_to_anonymous_callers() {
        let app = app();
        for path in ["/", "/api/routes", "/api/hello/world", "/api/slow?ms=1"] {
            let response = send(&app, "GET", path, None, None).await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{path} should not require login"
            );
        }
    }

    #[tokio::test]
    async fn the_item_collection_requires_a_session() {
        let app = app();
        for (method, path) in [
            ("GET", "/api/items"),
            ("GET", "/api/items/1"),
            ("DELETE", "/api/items/1"),
        ] {
            let response = send(&app, method, path, None, None).await;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
        }
        let response = send(
            &app,
            "POST",
            "/api/items",
            Some(json!({ "name": "date" })),
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_then_get_then_delete_round_trips() {
        let (app, cookie) = signed_in().await;

        let created = send(
            &app,
            "POST",
            "/api/items",
            Some(json!({ "name": "date" })),
            None,
        )
        .await;
        assert_eq!(
            created.status(),
            StatusCode::UNAUTHORIZED,
            "anonymous write is still refused"
        );

        let created = send(
            &app,
            "POST",
            "/api/items",
            Some(json!({ "name": "date" })),
            Some(&cookie),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);
        let new_id = testutil::json_of(created).await["id"].as_i64().unwrap();

        let fetched = send(
            &app,
            "GET",
            &format!("/api/items/{new_id}"),
            None,
            Some(&cookie),
        )
        .await;
        assert_eq!(fetched.status(), StatusCode::OK);
        assert_eq!(testutil::json_of(fetched).await["name"], "date");

        let deleted = send(
            &app,
            "DELETE",
            &format!("/api/items/{new_id}"),
            None,
            Some(&cookie),
        )
        .await;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

        let gone = send(
            &app,
            "GET",
            &format!("/api/items/{new_id}"),
            None,
            Some(&cookie),
        )
        .await;
        assert_eq!(gone.status(), StatusCode::NOT_FOUND);
    }

    /// What a restart, or a second worker, looks like from the database's point
    /// of view: a second router over the same connection sees the first one's
    /// writes, and its session token still works.
    #[tokio::test]
    async fn state_is_shared_through_the_database_not_the_process() {
        let state = state();
        let (app, cookie) = sign_in(&app_with(state.clone()), "alice").await;
        let created = send(
            &app,
            "POST",
            "/api/items",
            Some(json!({ "name": "persisted" })),
            Some(&cookie),
        )
        .await;
        assert_eq!(created.status(), StatusCode::CREATED);

        let other = app_with(state);
        let listed = send(&other, "GET", "/api/items", None, Some(&cookie)).await;
        let items = testutil::json_of(listed).await;
        assert!(
            items
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["name"] == "persisted")
        );
    }

    #[tokio::test]
    async fn unknown_item_is_404() {
        let (app, cookie) = signed_in().await;
        let response = send(&app, "GET", "/api/items/999", None, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            testutil::json_of(response).await["error"],
            "item 999 not found"
        );
    }

    #[tokio::test]
    async fn deleting_a_missing_item_is_404() {
        let (app, cookie) = signed_in().await;
        let response = send(&app, "DELETE", "/api/items/999", None, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_non_numeric_id_is_rejected_before_it_reaches_sqlite() {
        let (app, cookie) = signed_in().await;
        let response = send(&app, "GET", "/api/items/not-a-number", None, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn slow_request_is_capped_by_timeout_layer() {
        let app = testutil::app_with_timeout(state(), Duration::from_millis(100));
        let response = send(&app, "GET", "/api/slow?ms=5000", None, None).await;
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn test_page_is_served_as_html_at_root() {
        let response = send(&app(), "GET", "/", None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(content_type.starts_with("text/html"), "got: {content_type}");

        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(
            body.contains("<title>http-server 测试台</title>"),
            "page looks wrong"
        );
        // The console drives these routes, so they must all exist.
        for path in [
            "/health",
            "/api/hello/",
            "/api/echo",
            "/api/items",
            "/api/slow",
            "/api/auth/register",
            "/api/auth/login",
            "/api/auth/logout",
            "/api/auth/me",
        ] {
            assert!(
                body.contains(path),
                "test page is missing a case for {path}"
            );
        }
    }

    #[tokio::test]
    async fn route_index_is_still_available_as_json() {
        let response = send(&app(), "GET", "/api/routes", None, None).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(testutil::json_of(response).await["service"], "http-server");
    }

    #[tokio::test]
    async fn a_login_response_is_never_cached() {
        let (app, _) = sign_in(&app(), "alice").await;
        let response = send(
            &app,
            "POST",
            "/api/auth/login",
            Some(json!({ "username": "alice", "password": "correct horse" })),
            None,
        )
        .await;

        let cache_control = response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(cache_control, "no-store");
    }
}
