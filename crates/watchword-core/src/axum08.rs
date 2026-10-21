use axum08::Json;
use axum08::http::StatusCode;
use axum08::response::{IntoResponse, Response};

use crate::{AuthError, AuthResponse};

/// Answers with the error as its JSON body, such as
/// `{"error":"conflict","detail":"email"}`, and its
/// [status](AuthError::status).
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "axum08")))]
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

/// Answers with the value the response carries as its JSON body, and
/// [`Done`](AuthResponse::Done) with 204 No Content, as watchword's routes
/// do.
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "axum08")))]
impl IntoResponse for AuthResponse {
    fn into_response(self) -> Response {
        match self {
            AuthResponse::Config(value) => Json(value).into_response(),
            AuthResponse::User(value) => Json(value).into_response(),
            AuthResponse::Users(value) => Json(value).into_response(),
            AuthResponse::CreatedUser(value) => Json(value).into_response(),
            AuthResponse::Link(value) => Json(value).into_response(),
            AuthResponse::RegisterInfo(value) => Json(value).into_response(),
            AuthResponse::Cloudflare(value) => Json(value).into_response(),
            AuthResponse::Done => StatusCode::NO_CONTENT.into_response(),
        }
    }
}
