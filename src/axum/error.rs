use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::core::Error;
use crate::types::AuthError;

/// Answers with the error as its JSON body, such as
/// `{"error":"conflict","detail":"email"}`, and its
/// [status](AuthError::status).
impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}

/// Answers an [`AuthError`] as that error does. Any other failure is logged
/// and answered with a bare 500, so internals never reach the client.
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::Auth(error) => error.into_response(),
            error => {
                tracing::error!(error = ?error, "auth: request failed: {error}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}
