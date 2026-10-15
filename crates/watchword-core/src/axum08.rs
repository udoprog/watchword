use axum08::Json;
use axum08::http::StatusCode;
use axum08::response::{IntoResponse, Response};

use crate::AuthError;

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
