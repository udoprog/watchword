use core::fmt;
use std::error::Error as StdError;

use crate::core::Error;
use crate::store::StoreError;
use crate::types::AuthError;

/// The error a socket request fails with, which musli-web sends the client
/// as the request's error: a refusal as its [`AuthError`]'s message, and any
/// internal failure as just `internal error`, as the HTTP routes answer a
/// 500. The [`Error`] it holds, with its cause, is for the server's logs.
///
/// Use it as the error of the app's `ws::Handler::Response`, which is what
/// [`Connection::handle`](super::Connection::handle) returns. The app's own
/// requests convert into it with `?` from an [`Error`], an [`AuthError`] or a
/// [`StoreError`].
///
/// `Connection::handle` has already logged its internal failures, so an app
/// does not log those again; it logs the internal failures of its own
/// requests, which only it sees.
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

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Error::Auth(error) => error.fmt(f),
            _ => f.write_str("internal error"),
        }
    }
}

impl StdError for RequestError {
    /// Always the [`Error`], so [`Error::find_auth_error`] finds a refusal
    /// through it.
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.0)
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
