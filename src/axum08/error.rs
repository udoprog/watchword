use axum08::http::StatusCode;
use axum08::response::{IntoResponse, Response};

use crate::core::Error;

/// Answers an [`AuthError`](crate::AuthError) as that error does
/// (watchword-core implements `IntoResponse` for it). Any other failure is
/// logged and answered with a bare 500, so internals never reach the client.
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
