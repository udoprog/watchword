use std::fmt;
use std::string::String;
use std::string::ToString;

use watchword_core::AuthError;

/// Why a request made with the [`AuthService`](super::AuthService), or one
/// of the [`http`](super::http) functions, failed.
///
/// A [`Transport`](super::Transport) of the app's own answers with these
/// too: [`Error::Auth`] for the server's refusal, which the components act
/// on (a 401 checks the session), and the others for the transport failing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The server refused the request with an [`AuthError`].
    Auth(AuthError),
    /// The server answered with an unexpected status, such as a 500 or a 502
    /// from a proxy, without an [`AuthError`] body.
    Status(u16),
    /// The server could not be reached, or its answer could not be read.
    Network(String),
    /// A request over the app's musli-web socket failed without an
    /// [`AuthError`]: the server answered with a request error, such as an
    /// internal failure, or the socket closed before the answer. Only with
    /// the `musliweb05` feature and a socket handed to
    /// [`AuthContext::set_socket`](super::AuthContext).
    Socket(String),
    /// The transport answered a request with the
    /// [`AuthResponse`](watchword_core::AuthResponse) of another, such as a
    /// [`Transport`](super::Transport) of the app's that mixed them up.
    UnexpectedResponse,
}

impl Error {
    /// Whether the server says there is no session, or that the credentials
    /// are wrong.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Error::Auth(AuthError::Unauthorized))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Auth(error) => error.fmt(f),
            Error::Status(status) => write!(f, "the server answered with HTTP {status}"),
            Error::Network(error) => write!(f, "could not reach the server: {error}"),
            Error::Socket(error) => write!(f, "the request over the socket failed: {error}"),
            Error::UnexpectedResponse => write!(f, "the answer was not for the request made"),
        }
    }
}

impl std::error::Error for Error {}

impl From<AuthError> for Error {
    fn from(error: AuthError) -> Self {
        Error::Auth(error)
    }
}

impl From<gloo_net::Error> for Error {
    fn from(error: gloo_net::Error) -> Self {
        Error::Network(error.to_string())
    }
}
