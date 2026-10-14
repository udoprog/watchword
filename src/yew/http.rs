//! A client for the library's `/api/auth` JSON routes.
//!
//! Requests go to the page's own origin with same-origin cookies, so the
//! session cookie set by the server is sent along. The client uses this
//! crate's own gloo-net, so an app does not need to match its gloo version.
//!
//! Each function maps an error status to [`Error::Auth`] when the body is an
//! [`AuthError`], as every route of the `axum` feature answers.

use std::fmt;

use gloo_net::http::{Request, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use web_sys::RequestCredentials;

use crate::types::{AuthConfig, AuthError, LoginRequest, RegisterInfo, RegisterRequest, UserInfo};

/// Why a request to an `/api/auth` route failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The server refused the request with an [`AuthError`].
    Auth(AuthError),
    /// The server answered with an unexpected status, such as a 500 or a 502
    /// from a proxy, without an [`AuthError`] body.
    Status(u16),
    /// The server could not be reached, or its answer could not be read.
    Network(String),
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

/// What the sign-in page offers: `GET /api/auth/config`.
pub async fn config() -> Result<AuthConfig, Error> {
    read(get("/api/auth/config").send().await?).await
}

/// The signed-in user: `GET /api/auth/me`. Fails with
/// [`AuthError::Unauthorized`] without a live session.
pub async fn me() -> Result<UserInfo, Error> {
    read(get("/api/auth/me").send().await?).await
}

/// Signs in with a login name or email and a password:
/// `POST /api/auth/login`.
pub async fn login(request: &LoginRequest) -> Result<UserInfo, Error> {
    read(post("/api/auth/login").json(request)?.send().await?).await
}

/// Signs in with the Cloudflare Access credentials the request carries:
/// `POST /api/auth/cloudflare`.
pub async fn cloudflare() -> Result<UserInfo, Error> {
    read(post("/api/auth/cloudflare").send().await?).await
}

/// Signs out, deleting the session and clearing its cookie:
/// `POST /api/auth/logout`.
pub async fn logout() -> Result<(), Error> {
    check(post("/api/auth/logout").send().await?).await?;
    Ok(())
}

/// What a registration or reset link is for:
/// `GET /api/auth/register/{token}`. Fails with [`AuthError::NotFound`] for an
/// unknown link and [`AuthError::Gone`] for a used or expired one.
pub async fn register_info(token: &str) -> Result<RegisterInfo, Error> {
    read(get(&register_path(token)).send().await?).await
}

/// Sets the password of a link's user and signs them in:
/// `POST /api/auth/register/{token}`.
pub async fn register(token: &str, request: &RegisterRequest) -> Result<UserInfo, Error> {
    read(post(&register_path(token)).json(request)?.send().await?).await
}

/// Where the browser goes to sign in with Google: `GET /api/auth/google`.
pub const GOOGLE_SIGN_IN: &str = "/api/auth/google";

/// Where the browser goes to register a link's user with Google:
/// `GET /api/auth/google/register/{token}`.
pub fn google_register_url(token: &str) -> String {
    format!("/api/auth/google/register/{}", encode(token))
}

fn register_path(token: &str) -> String {
    format!("/api/auth/register/{}", encode(token))
}

/// Percent-encodes a path segment. Tokens are base64url and pass through
/// unchanged; anything else (from a hand-edited URL) cannot escape the
/// segment.
fn encode(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());

    for b in segment.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }

    out
}

fn get(url: &str) -> RequestBuilder {
    Request::get(url).credentials(RequestCredentials::SameOrigin)
}

fn post(url: &str) -> RequestBuilder {
    Request::post(url).credentials(RequestCredentials::SameOrigin)
}

async fn read<T>(response: Response) -> Result<T, Error>
where
    T: DeserializeOwned,
{
    Ok(check(response).await?.json().await?)
}

async fn check(response: Response) -> Result<Response, Error> {
    if response.ok() {
        return Ok(response);
    }

    let status = response.status();

    match response.json::<AuthError>().await {
        Ok(error) => Err(Error::Auth(error)),
        Err(_) => Err(Error::Status(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::encode;

    #[test]
    fn encode_keeps_base64url() {
        assert_eq!(encode("aZ09-_"), "aZ09-_");
    }

    #[test]
    fn encode_escapes_separators() {
        assert_eq!(encode("a/b?c#d"), "a%2Fb%3Fc%23d");
        assert_eq!(encode("é"), "%C3%A9");
    }
}
