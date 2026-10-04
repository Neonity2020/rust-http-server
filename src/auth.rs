//! Password login built on server-side sessions.
//!
//! A session is a 256-bit random token in an `HttpOnly` cookie. The database
//! stores only its SHA-256, so a copy of the database file is not a set of valid
//! cookies, and logging out is a `DELETE` rather than a client-side expiry the
//! server cannot vouch for.

use std::{
    collections::HashMap,
    future::Future,
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::{
    Json,
    extract::{FromRef, FromRequestParts, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::{
    AppState,
    api::ApiError,
    db::{self, User},
};

/// Name of the cookie carrying the session token.
pub const SESSION_COOKIE: &str = "session";

/// 32 bytes = 256 bits, the size RFC 6265bis asks bearer tokens to have.
const TOKEN_BYTES: usize = 32;

/// Same answer for "no such user" and "wrong password", so the response cannot
/// be used to enumerate accounts.
const INVALID_CREDENTIALS: &str = "用户名或密码不正确";
const NEED_LOGIN: &str = "请先登录";

/// Hashing a password that belongs to nobody, so the unknown-user path costs
/// the same wall-clock time as the known-user path.
const DECOY_PASSWORD: &str = "\u{0}no-such-account";

const MIN_USERNAME_LEN: usize = 3;
const MAX_USERNAME_LEN: usize = 32;
const MIN_PASSWORD_LEN: usize = 8;
/// Argon2 hashes the whole input, so an unbounded password would let one
/// request pin a blocking-pool thread. Bounded well above any real passphrase.
const MAX_PASSWORD_LEN: usize = 1024;

/// How long a login stays locked out after this many failures.
const MAX_FAILURES: usize = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
/// Ceiling on the throttle map, so a flood of distinct usernames cannot grow it
/// without bound.
const MAX_TRACKED_USERNAMES: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct AuthConfig {
    /// Set `Secure` on the session cookie. Defaults to false only because the
    /// demo runs on plain HTTP; anything behind TLS must turn it on, or a
    /// cookie sent over http will happily be replayed over https.
    pub cookie_secure: bool,
    pub ttl: Duration,
}

#[derive(Debug, Deserialize)]
pub struct Credentials {
    username: String,
    password: String,
}

fn hash_password(password: &str) -> Result<String, ApiError> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(ApiError::internal)
}

fn verify_password(password: &str, hash: &str) -> bool {
    Argon2::default()
        .verify_password(password.as_bytes(), hash)
        .is_ok()
}

fn new_token() -> Result<String, ApiError> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(ApiError::internal)?;
    Ok(hex::encode(bytes))
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn validate(username: &str, password: &str) -> Result<(), ApiError> {
    let username_len = username.chars().count();
    if !(MIN_USERNAME_LEN..=MAX_USERNAME_LEN).contains(&username_len) {
        return Err(ApiError::BadRequest(format!(
            "用户名长度需在 {MIN_USERNAME_LEN}–{MAX_USERNAME_LEN} 个字符之间"
        )));
    }
    if username
        .chars()
        .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(ApiError::BadRequest("用户名不能包含空白或控制字符".into()));
    }
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::BadRequest(format!(
            "密码至少 {MIN_PASSWORD_LEN} 个字符"
        )));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(ApiError::BadRequest(format!(
            "密码最长 {MAX_PASSWORD_LEN} 字节"
        )));
    }
    Ok(())
}

/// Failed-login counters, keyed by username.
///
/// Deliberately per-account and in memory. The server does not enable
/// `ConnectInfo` and does not trust `X-Forwarded-For`, so it has no client IP
/// it can rely on; and losing the counters to a restart costs an attacker
/// nothing but a restart. What this does stop is hammering one account from a
/// script — which is the point of a login throttle.
#[derive(Debug, Default)]
pub struct LoginThrottle {
    failures: Mutex<HashMap<String, Vec<Instant>>>,
}

impl LoginThrottle {
    /// How much longer this username must wait, or `None` if it may try now.
    pub fn lockout(&self, username: &str) -> Option<Duration> {
        let key = normalize(username);
        let mut map = self.lock();
        let attempts = map.get_mut(&key)?;
        retain_recent(attempts);
        if attempts.len() < MAX_FAILURES {
            return None;
        }
        // Measured from the oldest failure still in the window: that is the
        // moment the count drops back under the limit.
        let oldest = attempts.first()?;
        Some(FAILURE_WINDOW.saturating_sub(oldest.elapsed()))
    }

    pub fn record_failure(&self, username: &str) {
        let key = normalize(username);
        let mut map = self.lock();
        map.entry(key).or_default().push(Instant::now());
        if map.len() > MAX_TRACKED_USERNAMES {
            map.retain(|_, attempts| {
                retain_recent(attempts);
                !attempts.is_empty()
            });
        }
    }

    /// A successful login clears the history, so five typos and then a correct
    /// password does not lock the user out.
    pub fn clear(&self, username: &str) {
        self.lock().remove(&normalize(username));
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Vec<Instant>>> {
        self.failures.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn normalize(username: &str) -> String {
    username.trim().to_lowercase()
}

fn retain_recent(attempts: &mut Vec<Instant>) {
    attempts.retain(|at| at.elapsed() < FAILURE_WINDOW);
}

/// The account behind a valid session cookie. Handlers take it by value, so a
/// missing or expired cookie is a 401 at the extractor rather than a `None`
/// check each handler has to remember.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub user: User,
    pub expires_at: i64,
}

impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = ApiError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        // Taken out of `parts` before the future exists, so the future borrows
        // nothing from the request.
        let state = AppState::from_ref(state);
        let token = CookieJar::from_headers(&parts.headers)
            .get(SESSION_COOKIE)
            .map(|cookie| cookie.value().to_owned());

        Box::pin(async move {
            let Some(token) = token else {
                return Err(ApiError::Unauthorized(NEED_LOGIN.into()));
            };
            let hash = token_hash(&token);
            match state
                .db(move |conn| Ok(db::user_for_session(conn, &hash, db::now())?))
                .await?
            {
                Some((user, expires_at)) => Ok(Self { user, expires_at }),
                None => Err(ApiError::Unauthorized(NEED_LOGIN.into())),
            }
        })
    }
}

pub async fn register(
    State(state): State<AppState>,
    Json(body): Json<Credentials>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let username = body.username.trim().to_string();
    validate(&username, &body.password)?;

    // Argon2 costs tens of milliseconds, so check for a name clash before
    // spending it. The UNIQUE index is still what decides — a concurrent
    // registration can slip past this read and still ends in 409.
    let probe = username.clone();
    let taken = state
        .db(move |conn| Ok(db::user_with_hash(conn, &probe)?.is_some()))
        .await?;
    if taken {
        return Err(ApiError::Conflict("用户名已被占用".into()));
    }

    let password = body.password;
    let user = state
        .db(move |conn| {
            let hash = hash_password(&password)?;
            db::create_user(conn, &username, &hash).map_err(|err| {
                if db::is_username_taken_error(&err) {
                    ApiError::Conflict("用户名已被占用".into())
                } else {
                    ApiError::from(err)
                }
            })
        })
        .await?;

    info!(username = %user.username, id = user.id, "registered");
    Ok((StatusCode::CREATED, Json(json!({ "user": user }))))
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<Credentials>,
) -> Result<Response, ApiError> {
    let username = body.username.trim().to_string();

    if let Some(wait) = state.throttle.lockout(&username) {
        return Err(ApiError::TooManyRequests(format!(
            "失败次数过多，请在 {} 秒后重试",
            wait.as_secs().max(1)
        )));
    }

    let password = body.password;
    let expires_at = db::now() + state.auth.ttl.as_secs() as i64;

    // Look up, verify and open the session in one blocking hop: the hash
    // comparison is the expensive part and it cannot leave the closure. The
    // username is cloned in so the throttle below still has it.
    let lookup = username.clone();
    let opened = state
        .db(move |conn| {
            let Some((user, hash)) = db::user_with_hash(conn, &lookup)? else {
                let _ = hash_password(DECOY_PASSWORD);
                return Err(ApiError::Unauthorized(INVALID_CREDENTIALS.into()));
            };
            if !verify_password(&password, &hash) {
                return Err(ApiError::Unauthorized(INVALID_CREDENTIALS.into()));
            }
            let token = new_token()?;
            db::create_session(conn, &token_hash(&token), user.id, expires_at)?;
            Ok((token, user))
        })
        .await;

    let (token, user) = match opened {
        Ok(opened) => opened,
        Err(err) => {
            state.throttle.record_failure(&username);
            if matches!(&err, ApiError::Unauthorized(_)) {
                warn!(%username, "rejected login");
            }
            return Err(err);
        }
    };

    state.throttle.clear(&username);
    info!(username = %user.username, id = user.id, "login accepted");

    let jar = jar.add(session_cookie(token, state.auth));
    Ok((
        StatusCode::OK,
        jar,
        Json(json!({ "user": user, "expires_at": expires_at })),
    )
        .into_response())
}

/// Idempotent by design: logging out without a valid session is still a success,
/// so a client that lost its cookie can still clean up.
pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    if let Some(token) = jar
        .get(SESSION_COOKIE)
        .map(|cookie| cookie.value().to_owned())
    {
        let hash = token_hash(&token);
        state
            .db(move |conn| Ok(db::delete_session(conn, &hash)?))
            .await?;
    }

    // `CookieJar::remove` rewrites this into a removal cookie: empty value,
    // `Max-Age=0`, and an expiry in the past.
    let cleared = session_cookie(String::new(), state.auth);
    Ok((jar.remove(cleared), StatusCode::NO_CONTENT).into_response())
}

pub async fn me(current: CurrentUser) -> Json<serde_json::Value> {
    Json(json!({ "user": current.user, "expires_at": current.expires_at }))
}

/// `SameSite=Lax` because the API is cookie-authenticated: Lax withholds the
/// cookie from cross-site subrequests, which is what stops another origin from
/// driving these endpoints on the user's behalf.
fn session_cookie(token: String, config: AuthConfig) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(config.cookie_secure)
        .same_site(SameSite::Lax)
        // The `cookie` crate speaks `time::Duration`, not `std::time::Duration`.
        .max_age(time::Duration::seconds(config.ttl.as_secs() as i64))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{testutil, testutil::app};

    async fn register(
        app: &axum::Router,
        username: &str,
        password: &str,
    ) -> axum::response::Response {
        testutil::send(
            app,
            "POST",
            "/api/auth/register",
            Some(json!({ "username": username, "password": password })),
            None,
        )
        .await
    }

    async fn login(app: &axum::Router, username: &str, password: &str) -> axum::response::Response {
        testutil::send(
            app,
            "POST",
            "/api/auth/login",
            Some(json!({ "username": username, "password": password })),
            None,
        )
        .await
    }

    #[tokio::test]
    async fn register_then_login_returns_a_locked_down_cookie() {
        let app = app();
        assert_eq!(
            register(&app, "alice", "correct horse").await.status(),
            StatusCode::CREATED
        );

        let response = login(&app, "alice", "correct horse").await;
        assert_eq!(response.status(), StatusCode::OK);

        let set_cookie = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(set_cookie.starts_with("session="), "got: {set_cookie}");
        assert!(set_cookie.contains("HttpOnly"), "got: {set_cookie}");
        assert!(set_cookie.contains("SameSite=Lax"), "got: {set_cookie}");
        assert!(set_cookie.contains("Path=/"), "got: {set_cookie}");
        assert!(
            !set_cookie.contains("Secure"),
            "plain-HTTP demo, got: {set_cookie}"
        );

        let body = testutil::json_of(response).await;
        assert_eq!(body["user"]["username"], "alice");
        assert!(body["expires_at"].as_i64().unwrap() > db::now());
    }

    #[tokio::test]
    async fn the_token_is_32_random_bytes() {
        let app = app();
        register(&app, "bob", "correct horse").await;
        let response = login(&app, "bob", "correct horse").await;
        let token = testutil::session_cookie(&response).expect("session cookie");
        assert_eq!(
            token.trim_start_matches("session=").len(),
            64,
            "32 bytes as hex"
        );

        let again = login(&app, "bob", "correct horse").await;
        assert_ne!(
            testutil::session_cookie(&again),
            Some(token),
            "token must not repeat"
        );
    }

    #[tokio::test]
    async fn passwords_are_stored_as_argon2id_and_never_as_plaintext() {
        let state = testutil::state();
        let app = testutil::app_with(state.clone());
        register(&app, "carol", "correct horse").await;

        let stored: String = state
            .db(|conn| {
                Ok(conn.query_row(
                    "SELECT password_hash FROM users WHERE username = ?1",
                    rusqlite::params!["carol"],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();

        assert!(stored.starts_with("$argon2id$"), "got: {stored}");
        assert!(
            !stored.contains("correct horse"),
            "password leaked into the database"
        );
    }

    #[tokio::test]
    async fn the_wrong_password_and_an_unknown_user_are_indistinguishable() {
        let app = app();
        register(&app, "dave", "correct horse").await;

        let wrong = login(&app, "dave", "wrong horse").await;
        let unknown = login(&app, "nobody", "correct horse").await;

        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(testutil::json_of(wrong).await["error"], INVALID_CREDENTIALS);
        assert_eq!(
            testutil::json_of(unknown).await["error"],
            INVALID_CREDENTIALS
        );
    }

    #[tokio::test]
    async fn usernames_are_case_insensitive() {
        let app = app();
        register(&app, "Erin", "correct horse").await;

        assert_eq!(
            login(&app, "erin", "correct horse").await.status(),
            StatusCode::OK
        );
        assert_eq!(
            register(&app, "ERIN", "another one").await.status(),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn registering_a_taken_name_is_409_and_weak_input_is_400() {
        let app = app();
        assert_eq!(
            register(&app, "frank", "correct horse").await.status(),
            StatusCode::CREATED
        );
        assert_eq!(
            register(&app, "frank", "correct horse").await.status(),
            StatusCode::CONFLICT
        );

        assert_eq!(
            register(&app, "ab", "correct horse").await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            register(&app, "has space", "correct horse").await.status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            register(&app, "shorty", "1234567").await.status(),
            StatusCode::BAD_REQUEST
        );

        let too_long = "x".repeat(MAX_PASSWORD_LEN + 1);
        assert_eq!(
            register(&app, "verbose", &too_long).await.status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn a_registration_over_the_length_limit_is_400() {
        let app = app();
        let long = "n".repeat(MAX_USERNAME_LEN + 1);
        let response = register(&app, &long, "correct horse").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            testutil::json_of(response).await["error"]
                .as_str()
                .unwrap()
                .contains("用户名")
        );
    }

    #[tokio::test]
    async fn me_needs_a_cookie_and_accepts_a_valid_one() {
        let app = app();
        register(&app, "grace", "correct horse").await;

        let anonymous = testutil::send(&app, "GET", "/api/auth/me", None, None).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(testutil::json_of(anonymous).await["error"], NEED_LOGIN);

        let cookie =
            testutil::session_cookie(&login(&app, "grace", "correct horse").await).unwrap();
        let body = testutil::json_of(
            testutil::send(&app, "GET", "/api/auth/me", None, Some(&cookie)).await,
        )
        .await;
        assert_eq!(body["user"]["username"], "grace");
    }

    #[tokio::test]
    async fn a_forged_cookie_is_rejected() {
        let app = app();
        register(&app, "heidi", "correct horse").await;

        // Well-formed but not a token this server ever issued, including one
        // that hashes to nothing in the sessions table.
        let forged = format!("session={}", hex::encode([0xabu8; 32]));
        let response = testutil::send(&app, "GET", "/api/auth/me", None, Some(&forged)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_kills_the_session_on_the_server() {
        let app = app();
        register(&app, "ivan", "correct horse").await;
        let cookie = testutil::session_cookie(&login(&app, "ivan", "correct horse").await).unwrap();

        let response = testutil::send(&app, "POST", "/api/auth/logout", None, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cleared = response
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            cleared.contains("Max-Age=0"),
            "cookie should be expired, got: {cleared}"
        );

        // The stolen copy of the token is worth nothing now.
        let replayed = testutil::send(&app, "GET", "/api/auth/me", None, Some(&cookie)).await;
        assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_without_a_session_still_succeeds() {
        let app = app();
        assert_eq!(
            testutil::send(&app, "POST", "/api/auth/logout", None, None)
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn an_expired_session_is_refused() {
        let state = testutil::state();
        let app = testutil::app_with(state.clone());
        register(&app, "judy", "correct horse").await;

        // A session minted with a deadline that has already passed.
        let token = new_token().unwrap();
        let hash = token_hash(&token);
        state
            .db(move |conn| {
                let (user, _) = db::user_with_hash(conn, "judy")?
                    .ok_or_else(|| ApiError::NotFound("no user".into()))?;
                db::create_session(conn, &hash, user.id, db::now() - 1)?;
                Ok(())
            })
            .await
            .unwrap();

        let cookie = format!("{SESSION_COOKIE}={token}");
        let response = testutil::send(&app, "GET", "/api/auth/me", None, Some(&cookie)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn repeated_failures_lock_the_account_out() {
        let app = app();
        register(&app, "karl", "correct horse").await;

        for _ in 0..MAX_FAILURES {
            assert_eq!(
                login(&app, "karl", "wrong horse").await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
        // Even the right password is refused now.
        let locked = login(&app, "karl", "correct horse").await;
        assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            testutil::json_of(locked).await["error"]
                .as_str()
                .unwrap()
                .contains("秒后重试")
        );

        // A different account is unaffected.
        register(&app, "other", "correct horse").await;
        assert_eq!(
            login(&app, "other", "correct horse").await.status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn a_success_clears_the_failure_history() {
        let app = app();
        register(&app, "liam", "correct horse").await;

        for _ in 0..MAX_FAILURES - 1 {
            login(&app, "liam", "wrong horse").await;
        }
        assert_eq!(
            login(&app, "liam", "correct horse").await.status(),
            StatusCode::OK
        );
        // The counter is back to zero, so four more typos still do not lock out.
        for _ in 0..MAX_FAILURES - 1 {
            assert_eq!(
                login(&app, "liam", "wrong horse").await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }

    #[tokio::test]
    async fn throttling_is_case_insensitive_too() {
        let throttle = LoginThrottle::default();
        for _ in 0..MAX_FAILURES {
            throttle.record_failure("Karl");
        }
        assert!(throttle.lockout("karl").is_some());
        assert!(throttle.lockout("  KARL ").is_some());
        assert!(throttle.lockout("someone-else").is_none());

        throttle.clear("KARL");
        assert!(throttle.lockout("karl").is_none());
    }

    #[tokio::test]
    async fn the_throttle_forgets_stale_usernames_instead_of_growing() {
        let throttle = LoginThrottle::default();
        for _ in 0..MAX_FAILURES {
            throttle.record_failure("user0");
        }
        for i in 0..MAX_TRACKED_USERNAMES + 10 {
            throttle.record_failure(&format!("user{i}"));
        }

        // Pruning drops only the entries that are no longer locked; a locked
        // account survives the sweep.
        assert!(throttle.lockout("user0").is_some());
        assert!(throttle.lockout("nobody").is_none());
    }

    #[tokio::test]
    async fn a_single_failure_does_not_lock_anyone_out() {
        let throttle = LoginThrottle::default();
        throttle.record_failure("mallory");
        assert_eq!(throttle.lockout("mallory"), None);
        assert_eq!(throttle.lockout("mallory"), None);

        for _ in 1..MAX_FAILURES {
            throttle.record_failure("mallory");
        }
        assert!(throttle.lockout("mallory").is_some());
    }
}
