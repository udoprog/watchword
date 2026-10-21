//! The low-level HTTP layer: one function per `/api/auth` JSON route.
//!
//! Apps make their requests with the [`AuthService`](super::AuthService)
//! from [`use_auth_service`](super::use_auth_service), as watchword's own
//! components do, so they go over the same transport: the app's socket when
//! one is handed over, or a [`Transport`](super::Transport) the app injects.
//! These functions always use HTTP; [`HttpTransport`](super::HttpTransport)
//! sends every request with them, through [`send`].
//!
//! Requests go to the page's own origin with same-origin cookies, so the
//! session cookie set by the server is sent along. The client uses this
//! crate's own gloo-net, so an app does not need to match its gloo version.
//!
//! Each function maps an error status to [`Error::Auth`] when the body is an
//! [`AuthError`], as every route of watchword's `axum08` feature answers.

use std::string::String;
use std::vec::Vec;

use gloo_net::http::{Request, RequestBuilder, Response};
use serde::de::DeserializeOwned;
use web_sys::RequestCredentials;

use watchword_core::{
    AuthConfig, AuthError, AuthRequest, AuthResponse, CloudflareConfig, Link, LoginRequest,
    NewUser, PasswordChange, RegisterInfo, RegisterRequest, UserChange, UserEntry, UserId,
    UserInfo,
};

#[doc(no_inline)]
pub use super::Error;

/// Sends `request` to its route and answers as the route does, the way
/// [`HttpTransport`](super::HttpTransport) sends every request. An operation
/// this version does not know, from a newer watchword-core, fails with
/// [`AuthError::NotFound`].
pub async fn send(request: AuthRequest) -> Result<AuthResponse, Error> {
    Ok(match request {
        AuthRequest::Config => AuthResponse::Config(config().await?),
        AuthRequest::Me => AuthResponse::User(me().await?),
        AuthRequest::Login(request) => AuthResponse::User(login(&request).await?),
        AuthRequest::CloudflareSignIn => AuthResponse::User(cloudflare().await?),
        AuthRequest::Logout => {
            logout().await?;
            AuthResponse::Done
        }
        AuthRequest::RegisterInfo { token } => {
            AuthResponse::RegisterInfo(register_info(&token).await?)
        }
        AuthRequest::Register { token, request } => {
            AuthResponse::User(register(&token, &request).await?)
        }
        AuthRequest::ChangePassword(request) => {
            AuthResponse::User(change_password(&request).await?)
        }
        AuthRequest::UpdateAccount(change) => AuthResponse::User(update_account(&change).await?),
        AuthRequest::Users => AuthResponse::Users(users().await?),
        AuthRequest::CreateUser(new) => AuthResponse::CreatedUser(create_user(&new).await?),
        AuthRequest::UpdateUser { id, change } => {
            AuthResponse::User(update_user(id, &change).await?)
        }
        AuthRequest::DeleteUser { id } => {
            delete_user(id).await?;
            AuthResponse::Done
        }
        AuthRequest::IssueLink { id } => AuthResponse::Link(issue_link(id).await?),
        AuthRequest::RevokeLink { id } => {
            revoke_link(id).await?;
            AuthResponse::Done
        }
        AuthRequest::SignOutUser { id } => {
            sign_out_user(id).await?;
            AuthResponse::Done
        }
        AuthRequest::RevokeAccess { id } => AuthResponse::User(revoke_access(id).await?),
        AuthRequest::Impersonate { id } => AuthResponse::User(impersonate(id).await?),
        AuthRequest::StopImpersonating => AuthResponse::User(stop_impersonating().await?),
        AuthRequest::Cloudflare => AuthResponse::Cloudflare(cloudflare_settings().await?),
        AuthRequest::SetCloudflare(config) => {
            AuthResponse::Cloudflare(set_cloudflare_settings(&config).await?)
        }
        _ => return Err(Error::Auth(AuthError::NotFound)),
    })
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

/// Where the browser goes to switch the signed-in user to Google:
/// `GET /api/auth/google/link`.
pub const GOOGLE_LINK: &str = "/api/auth/google/link";

/// Changes or sets the signed-in user's password:
/// `POST /api/auth/account/password`. This session stays signed in and the
/// user's other sessions end; a Google user switches to the password.
pub async fn change_password(request: &PasswordChange) -> Result<UserInfo, Error> {
    read(
        post("/api/auth/account/password")
            .json(request)?
            .send()
            .await?,
    )
    .await
}

/// Changes the signed-in user's own login or email: `PATCH /api/auth/account`.
/// The role cannot be changed this way, nor the email of a Google user.
pub async fn update_account(change: &UserChange) -> Result<UserInfo, Error> {
    read(patch("/api/auth/account").json(change)?.send().await?).await
}

/// Every user, for admins: `GET /api/auth/users`.
pub async fn users() -> Result<Vec<UserEntry>, Error> {
    read(get("/api/auth/users").send().await?).await
}

pub use watchword_core::CreatedUser;

/// Creates a user, for admins: `POST /api/auth/users`. Fails with
/// [`AuthError::Conflict`] when the login or email is taken.
pub async fn create_user(new: &NewUser) -> Result<CreatedUser, Error> {
    read(post("/api/auth/users").json(new)?.send().await?).await
}

/// Changes a user's login, email or role, for admins:
/// `PATCH /api/auth/users/{id}`. An admin cannot change their own role.
pub async fn update_user(id: UserId, change: &UserChange) -> Result<UserInfo, Error> {
    read(patch(&user_path(id, "")).json(change)?.send().await?).await
}

/// Deletes a user, for admins: `DELETE /api/auth/users/{id}`. An admin cannot
/// delete themselves.
pub async fn delete_user(id: UserId) -> Result<(), Error> {
    check(delete(&user_path(id, "")).send().await?).await?;
    Ok(())
}

/// Issues a new registration or reset link for a user, using up their
/// earlier ones, for admins: `POST /api/auth/users/{id}/link`. The token is
/// shown only this once.
pub async fn issue_link(id: UserId) -> Result<Link, Error> {
    read(post(&user_path(id, "/link")).send().await?).await
}

/// Uses up a user's live link, for admins: `DELETE /api/auth/users/{id}/link`.
pub async fn revoke_link(id: UserId) -> Result<(), Error> {
    check(delete(&user_path(id, "/link")).send().await?).await?;
    Ok(())
}

/// Ends every session of a user, for admins:
/// `POST /api/auth/users/{id}/sign-out`.
pub async fn sign_out_user(id: UserId) -> Result<(), Error> {
    check(post(&user_path(id, "/sign-out")).send().await?).await?;
    Ok(())
}

/// Revokes a user's access: their password is cleared, their links are used
/// up and their sessions end, until they are issued a new link. For admins,
/// and not on themselves: `POST /api/auth/users/{id}/revoke`. The answer is
/// the user as revoked.
pub async fn revoke_access(id: UserId) -> Result<UserInfo, Error> {
    read(post(&user_path(id, "/revoke")).send().await?).await
}

/// Signs this browser in as another user, for admins when the server enables
/// impersonation: `POST /api/auth/users/{id}/impersonate`. The session
/// cookie is replaced, and the answer is the user, with
/// [`impersonated_by`](UserInfo::impersonated_by) set; reload the user
/// afterwards, such as with
/// [`AuthContext::refresh`](super::AuthContext::refresh).
/// [`stop_impersonating`] returns to the admin.
pub async fn impersonate(id: UserId) -> Result<UserInfo, Error> {
    read(post(&user_path(id, "/impersonate")).send().await?).await
}

/// Ends the impersonated session this browser holds and signs the admin who
/// started it back in: `POST /api/auth/impersonate/stop`. The session cookie
/// is replaced, and the answer is the admin. Refused with
/// [`AuthError::Forbidden`] when the session is not impersonated, or the
/// admin is no longer an active admin.
pub async fn stop_impersonating() -> Result<UserInfo, Error> {
    read(post("/api/auth/impersonate/stop").send().await?).await
}

/// The Cloudflare Access settings, or their default when the server has
/// none, for admins: `GET /api/auth/cloudflare`. Fails with
/// [`AuthError::NotFound`] when the server is built without Cloudflare
/// Access.
pub async fn cloudflare_settings() -> Result<CloudflareConfig, Error> {
    read(get("/api/auth/cloudflare").send().await?).await
}

/// Stores and applies the Cloudflare Access settings, for admins:
/// `PUT /api/auth/cloudflare`. The answer is the settings as stored, with
/// the team domain and audience trimmed.
pub async fn set_cloudflare_settings(config: &CloudflareConfig) -> Result<CloudflareConfig, Error> {
    read(put("/api/auth/cloudflare").json(config)?.send().await?).await
}

fn user_path(id: UserId, rest: &str) -> String {
    format!("/api/auth/users/{id}{rest}")
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

fn put(url: &str) -> RequestBuilder {
    Request::put(url).credentials(RequestCredentials::SameOrigin)
}

fn patch(url: &str) -> RequestBuilder {
    Request::patch(url).credentials(RequestCredentials::SameOrigin)
}

fn delete(url: &str) -> RequestBuilder {
    Request::delete(url).credentials(RequestCredentials::SameOrigin)
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
