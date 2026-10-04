//! One error type for the whole API, so every handler turns a failure into the
//! same JSON body: `{"error": "..."}`.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    TooManyRequests(String),
    /// The cause is logged, never returned: a SQLite message can name tables,
    /// columns and file paths, which is not the caller's business.
    Internal(String),
}

impl ApiError {
    pub fn internal(cause: impl std::fmt::Display) -> Self {
        tracing::error!(%cause, "request failed with an internal error");
        Self::Internal("服务器内部错误".into())
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(err: rusqlite::Error) -> Self {
        Self::internal(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Unauthorized(message) => (StatusCode::UNAUTHORIZED, message),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message),
            Self::Conflict(message) => (StatusCode::CONFLICT, message),
            Self::TooManyRequests(message) => (StatusCode::TOO_MANY_REQUESTS, message),
            Self::Internal(message) => (StatusCode::INTERNAL_SERVER_ERROR, message),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::Response;
    use http_body_util::BodyExt as _;

    async fn rendered(err: ApiError) -> Response {
        err.into_response()
    }

    async fn body_of(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).expect("body should be JSON")
    }

    #[tokio::test]
    async fn each_variant_maps_to_its_status_and_message() {
        let cases = [
            (ApiError::BadRequest("坏".into()), StatusCode::BAD_REQUEST),
            (
                ApiError::Unauthorized("没登录".into()),
                StatusCode::UNAUTHORIZED,
            ),
            (ApiError::NotFound("没有".into()), StatusCode::NOT_FOUND),
            (ApiError::Conflict("重复".into()), StatusCode::CONFLICT),
            (
                ApiError::TooManyRequests("太频繁".into()),
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                ApiError::Internal("炸了".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];

        for (err, expected) in cases {
            let response = rendered(err).await;
            assert_eq!(response.status(), expected);
            assert!(body_of(response).await["error"].is_string());
        }
    }

    #[tokio::test]
    async fn the_content_type_stays_json() {
        let response = rendered(ApiError::Unauthorized("没登录".into())).await;
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            content_type.starts_with("application/json"),
            "got: {content_type}"
        );
    }

    /// The body must never carry the underlying cause — a SQLite error names
    /// tables and file paths.
    #[tokio::test]
    async fn database_errors_do_not_leak_their_cause() {
        let err: ApiError = rusqlite::Error::InvalidQuery.into();
        let response = rendered(err).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body_of(response).await["error"], "服务器内部错误");
    }

    #[tokio::test]
    async fn unauthenticated_is_401_not_403() {
        let response = rendered(ApiError::Unauthorized("请先登录".into())).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
