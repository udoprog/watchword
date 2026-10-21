use core::fmt;

use musli_web05::ws::{self, ErrorPayload, ResponseError};

use crate::core::Error;
use crate::store::StoreError;
use crate::types::AuthError;

/// The error a socket request fails with, which musli-web sends the client
/// as the request's error. A refusal is sent as its [`AuthError`], typed, so
/// the client decodes it with `web::Error::server_error::<AuthError>()`, with
/// the [`AuthError`]'s text as the message. An internal failure is sent as
/// just the message `internal error`, as the HTTP routes answer a 500. The
/// [`Error`] it holds, with its cause, is for the server's logs.
///
/// Use it as the error of the app's `ws::Handler::Response`, which is what
/// [`Connection`](super::Connection)'s handler returns. The app's own
/// requests convert into it with `?` from an [`Error`], an [`AuthError`] or a
/// [`StoreError`], so their refusals reach the client typed as well.
///
/// It is not [`Display`](fmt::Display): musli-web sends any error that is as
/// text, and this one decides per error what the client sees. Log
/// [`error`](RequestError::error) instead.
///
/// [`Connection`](super::Connection) has already logged its internal
/// failures, so an app does not log those again; it logs the internal
/// failures of its own requests, which only it sees.
#[derive(Debug)]
pub struct RequestError(Error);

impl RequestError {
    /// The error the request failed with.
    pub fn error(&self) -> &Error {
        &self.0
    }

    /// The error the request failed with.
    pub fn into_error(self) -> Error {
        self.0
    }

    /// The [`AuthError`] the request was refused with, or `None` for an
    /// internal failure.
    pub fn auth_error(&self) -> Option<&AuthError> {
        self.0.auth_error()
    }
}

impl ResponseError for RequestError {
    fn fmt_message(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Error::Auth(error) => fmt::Display::fmt(error, f),
            _ => f.write_str("internal error"),
        }
    }

    fn encode_payload(&self, payload: ErrorPayload<'_>) -> Result<(), ws::Error> {
        match &self.0 {
            Error::Auth(error) => payload.encode(error),
            // The cause stays on the server.
            _ => Ok(()),
        }
    }
}

impl From<Error> for RequestError {
    fn from(error: Error) -> Self {
        Self(error)
    }
}

impl From<AuthError> for RequestError {
    fn from(error: AuthError) -> Self {
        Self(Error::Auth(error))
    }
}

impl From<StoreError> for RequestError {
    fn from(error: StoreError) -> Self {
        Self(Error::Store(error))
    }
}
