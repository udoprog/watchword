//! [`Auth::dispatch`]: every operation of [`AuthRequest`], run once for
//! every transport.

use std::net::IpAddr;

use http::HeaderMap;

use super::{Auth, Result, require_admin};
use crate::store::{Session, User};
use crate::types::{AuthError, AuthRequest, AuthResponse, CookieChange, CreatedUser, Invalid};

/// Who an [`AuthRequest`] comes from, as its transport knows them, for
/// [`Auth::dispatch`].
///
/// An empty caller is signed out. The HTTP routes give the request's
/// headers, and for a route behind [`SignedIn`](crate::axum08::SignedIn)
/// the user it already loaded; a socket gives the session its upgrade
/// carried, which `dispatch` reads again for each request.
///
/// ```
/// # async fn run(auth: watchword::Auth, session_id: &str) -> watchword::core::Result<()> {
/// use watchword::core::Caller;
/// use watchword::types::{AuthRequest, AuthResponse};
///
/// let caller = Caller::new().session(session_id);
/// let dispatched = auth.dispatch(&caller, AuthRequest::Me).await?;
///
/// if let AuthResponse::User(me) = dispatched.response {
///     println!("signed in as {}", me.id);
/// }
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Caller<'a> {
    signed_in: Option<(&'a User, &'a Session)>,
    session_id: Option<&'a str>,
    headers: Option<&'a HeaderMap>,
    address: Option<IpAddr>,
}

impl<'a> Caller<'a> {
    /// A caller with no session, no headers and no address.
    pub fn new() -> Self {
        Self::default()
    }

    /// Signed in with the session `session_id`, which
    /// [`dispatch`](Auth::dispatch) reads through [`Auth::session`] when the
    /// request needs a signed-in user, as the HTTP extractors do. An ended
    /// session is refused with [`AuthError::Unauthorized`].
    pub fn session(mut self, session_id: &'a str) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Signed in as `user` with `session`, already read through
    /// [`Auth::session`] for this request, such as by the
    /// [`SignedIn`](crate::axum08::SignedIn) extractor. Takes precedence over
    /// [`session`](Caller::session) and the headers' cookie.
    pub fn signed_in(mut self, user: &'a User, session: &'a Session) -> Self {
        self.signed_in = Some((user, session));
        self
    }

    /// The request's HTTP headers: its session cookie, when neither
    /// [`signed_in`](Caller::signed_in) nor [`session`](Caller::session) is
    /// given, and its Cloudflare Access credentials.
    pub fn headers(mut self, headers: &'a HeaderMap) -> Self {
        self.headers = Some(headers);
        self
    }

    /// The headers given with [`headers`](Caller::headers), for the
    /// response's `Set-Cookie`.
    #[cfg(feature = "axum08")]
    pub(crate) fn http_headers(&self) -> Option<&'a HeaderMap> {
        self.headers
    }

    /// The client's address, as [`Auth::client_address`] gives it, which
    /// [`AuthRequest::Login`] is throttled by and needs.
    pub fn address(mut self, address: IpAddr) -> Self {
        self.address = Some(address);
        self
    }
}

/// What [`Auth::dispatch`] answered: the response, and what to do with the
/// session cookie.
#[derive(Debug)]
#[non_exhaustive]
pub struct Dispatched {
    /// The answer to the request.
    pub response: AuthResponse,
    /// The change to the session cookie, for the requests whose
    /// [`AuthRequest::cookie`] says they make one, and `None` for the rest.
    pub cookie: Option<SessionCookie>,
}

impl Dispatched {
    fn new(response: AuthResponse) -> Self {
        Self {
            response,
            cookie: None,
        }
    }

    fn set(response: AuthResponse, session: Session) -> Self {
        Self {
            response,
            cookie: Some(SessionCookie::Set(session)),
        }
    }
}

/// A change to the session cookie, which only an HTTP response can make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionCookie {
    /// Sign in with this new session: [`Auth::set_cookie`] with its id. For
    /// both [`CookieChange::Set`](crate::types::CookieChange::Set) and
    /// [`Replace`](crate::types::CookieChange::Replace).
    Set(Session),
    /// Clear the cookie: [`Auth::clear_cookie`].
    Clear,
}

impl Auth {
    /// Runs one [`AuthRequest`] for `caller`.
    ///
    /// Every transport's requests come through here: the `axum08` routes and
    /// the musli-web `Connection` decode their own request into an
    /// `AuthRequest` and answer with the [`Dispatched`] response, so an
    /// operation behaves the same over each. The checks happen here: a
    /// request that needs a signed-in user is refused with
    /// [`AuthError::Unauthorized`] without a live session, an admin request
    /// with [`AuthError::Forbidden`] unless the user is an active admin now,
    /// and the operations enforce the rest of their rules themselves.
    ///
    /// The requests whose [`cookie`](AuthRequest::cookie) is set answer with
    /// a [`SessionCookie`] in [`Dispatched::cookie`], which the caller must
    /// apply for the user to be signed in (or out) as answered.
    ///
    /// Without the `cloudflare` feature, the Cloudflare requests are refused
    /// with [`AuthError::NotFound`], after the same checks as with it.
    /// [`AuthRequest::Login`] needs the caller's
    /// [`address`](Caller::address) and is refused with
    /// [`AuthError::Forbidden`], logged as an error, without one.
    ///
    /// Errors with [`Error::Auth`](super::Error::Auth) for a refusal, and
    /// otherwise when the store fails or hashing a password does.
    pub async fn dispatch(&self, caller: &Caller<'_>, request: AuthRequest) -> Result<Dispatched> {
        let change = request.cookie();

        let dispatched = match request {
            AuthRequest::Config => Dispatched::new(AuthResponse::Config(crate::AuthConfig {
                password: true,
                google: self.offers_google(),
                cloudflare: self.cloudflare_available_for(caller).await?,
                logins: self.uses_logins(),
            })),
            AuthRequest::Me => {
                let (user, session) = self.caller_session(caller).await?;
                let info = self.session_info(&user, &session).await?;
                Dispatched::new(AuthResponse::User(info))
            }
            AuthRequest::Login(request) => {
                let Some(address) = caller.address else {
                    tracing::error!(
                        "auth: sign-in needs the client's address, which the caller lacks"
                    );
                    return Err(AuthError::Forbidden.into());
                };

                let (user, session) = self.sign_in_password(address, &request).await?;
                Dispatched::set(AuthResponse::User(user.info()), session)
            }
            AuthRequest::CloudflareSignIn => {
                let (user, session) = self.sign_in_cloudflare_for(caller).await?;
                Dispatched::set(AuthResponse::User(user.info()), session)
            }
            AuthRequest::Logout => {
                if let Some(id) = self.caller_session_id(caller) {
                    self.sign_out(&id).await?;
                }

                Dispatched {
                    response: AuthResponse::Done,
                    cookie: Some(SessionCookie::Clear),
                }
            }
            AuthRequest::RegisterInfo { token } => Dispatched::new(AuthResponse::RegisterInfo(
                self.register_info(&token).await?,
            )),
            AuthRequest::Register { token, request } => {
                let (user, session) = self.register(&token, &request).await?;
                Dispatched::set(AuthResponse::User(user.info()), session)
            }
            AuthRequest::ChangePassword(change) => {
                let (user, session) = self.caller_session(caller).await?;
                let user = self.change_password(&user, &session, &change).await?;
                let info = self.session_info(&user, &session).await?;
                Dispatched::new(AuthResponse::User(info))
            }
            AuthRequest::UpdateAccount(change) => {
                let (user, session) = self.caller_session(caller).await?;

                if change.role.is_some() {
                    return Err(AuthError::Invalid(Invalid::RoleNotChangeable).into());
                }

                let user = self.update_user(&user, &session, user.id, &change).await?;
                let info = self.session_info(&user, &session).await?;
                Dispatched::new(AuthResponse::User(info))
            }
            AuthRequest::Users => {
                let (admin, _) = self.caller_admin(caller).await?;
                Dispatched::new(AuthResponse::Users(self.users(&admin).await?))
            }
            AuthRequest::CreateUser(new) => {
                let (admin, session) = self.caller_admin(caller).await?;
                let (entry, link) = self.create_user(&admin, &session, &new).await?;
                Dispatched::new(AuthResponse::CreatedUser(CreatedUser { entry, link }))
            }
            AuthRequest::UpdateUser { id, change } => {
                let (admin, session) = self.caller_admin(caller).await?;
                let user = self.update_user(&admin, &session, id, &change).await?;
                Dispatched::new(AuthResponse::User(user.info()))
            }
            AuthRequest::DeleteUser { id } => {
                let (admin, session) = self.caller_admin(caller).await?;
                self.delete_user(&admin, &session, id).await?;
                Dispatched::new(AuthResponse::Done)
            }
            AuthRequest::IssueLink { id } => {
                let (admin, session) = self.caller_admin(caller).await?;
                Dispatched::new(AuthResponse::Link(
                    self.issue_link(&admin, &session, id).await?,
                ))
            }
            AuthRequest::RevokeLink { id } => {
                let (admin, session) = self.caller_admin(caller).await?;
                self.revoke_link(&admin, &session, id).await?;
                Dispatched::new(AuthResponse::Done)
            }
            AuthRequest::SignOutUser { id } => {
                let (admin, session) = self.caller_admin(caller).await?;
                self.sign_out_everywhere(&admin, &session, id).await?;
                Dispatched::new(AuthResponse::Done)
            }
            AuthRequest::RevokeAccess { id } => {
                let (admin, session) = self.caller_admin(caller).await?;
                let user = self.revoke_access(&admin, &session, id).await?;
                Dispatched::new(AuthResponse::User(user.info()))
            }
            AuthRequest::Impersonate { id } => {
                let (admin, session) = self.caller_admin(caller).await?;
                let (user, session) = self.impersonate(&admin, &session, id).await?;
                let info = self.session_info(&user, &session).await?;
                Dispatched::set(AuthResponse::User(info), session)
            }
            AuthRequest::StopImpersonating => {
                let (_, session) = self.caller_session(caller).await?;
                let (admin, session) = self.stop_impersonating(&session).await?;
                Dispatched::set(AuthResponse::User(admin.info()), session)
            }
            AuthRequest::Cloudflare => {
                self.caller_admin(caller).await?;
                Dispatched::new(AuthResponse::Cloudflare(self.cloudflare_settings().await?))
            }
            AuthRequest::SetCloudflare(config) => {
                let (admin, session) = self.caller_admin(caller).await?;
                Dispatched::new(AuthResponse::Cloudflare(
                    self.set_cloudflare_settings(&admin, &session, config)
                        .await?,
                ))
            }
            // Unreachable while watchword-core is pinned to this version: an
            // operation is added to both at once.
            _ => return Err(AuthError::NotFound.into()),
        };

        // What the request says it does to the cookie is what it did.
        debug_assert_eq!(
            change.map(|change| change == CookieChange::Clear),
            dispatched
                .cookie
                .as_ref()
                .map(|cookie| *cookie == SessionCookie::Clear),
        );

        Ok(dispatched)
    }

    /// The caller's live session and its user, or
    /// [`AuthError::Unauthorized`].
    async fn caller_session(&self, caller: &Caller<'_>) -> Result<(User, Session)> {
        if let Some((user, session)) = caller.signed_in {
            return Ok((user.clone(), session.clone()));
        }

        let Some(id) = self.caller_session_id(caller) else {
            return Err(AuthError::Unauthorized.into());
        };

        match self.session(&id).await? {
            Some(signed_in) => Ok(signed_in),
            None => Err(AuthError::Unauthorized.into()),
        }
    }

    /// As [`caller_session`](Auth::caller_session), refused with
    /// [`AuthError::Forbidden`] unless the user is an active admin.
    async fn caller_admin(&self, caller: &Caller<'_>) -> Result<(User, Session)> {
        let (user, session) = self.caller_session(caller).await?;
        require_admin(&user)?;
        Ok((user, session))
    }

    /// The id of the session the caller presents, live or not.
    fn caller_session_id(&self, caller: &Caller<'_>) -> Option<std::string::String> {
        if let Some((_, session)) = caller.signed_in {
            return Some(session.id.clone());
        }

        if let Some(id) = caller.session_id {
            return Some(id.into());
        }

        self.session_id(caller.headers?)
    }

    #[cfg(feature = "cloudflare")]
    async fn cloudflare_available_for(&self, caller: &Caller<'_>) -> Result<bool> {
        match caller.headers {
            Some(headers) => self.cloudflare_available(headers).await,
            None => Ok(false),
        }
    }

    #[cfg(not(feature = "cloudflare"))]
    async fn cloudflare_available_for(&self, _: &Caller<'_>) -> Result<bool> {
        Ok(false)
    }

    #[cfg(feature = "cloudflare")]
    async fn sign_in_cloudflare_for(&self, caller: &Caller<'_>) -> Result<(User, Session)> {
        match caller.headers {
            Some(headers) => self.sign_in_cloudflare(headers).await,
            None => self.sign_in_cloudflare(&HeaderMap::new()).await,
        }
    }

    #[cfg(not(feature = "cloudflare"))]
    async fn sign_in_cloudflare_for(&self, _: &Caller<'_>) -> Result<(User, Session)> {
        Err(AuthError::NotFound.into())
    }

    /// The settings, or their default when there are none.
    #[cfg(feature = "cloudflare")]
    async fn cloudflare_settings(&self) -> Result<crate::types::CloudflareConfig> {
        Ok(self.cloudflare().await?.unwrap_or_default())
    }

    #[cfg(not(feature = "cloudflare"))]
    async fn cloudflare_settings(&self) -> Result<crate::types::CloudflareConfig> {
        Err(AuthError::NotFound.into())
    }

    #[cfg(feature = "cloudflare")]
    async fn set_cloudflare_settings(
        &self,
        admin: &User,
        session: &Session,
        config: crate::types::CloudflareConfig,
    ) -> Result<crate::types::CloudflareConfig> {
        self.set_cloudflare(admin, session, config).await
    }

    #[cfg(not(feature = "cloudflare"))]
    async fn set_cloudflare_settings(
        &self,
        _: &User,
        _: &Session,
        _: crate::types::CloudflareConfig,
    ) -> Result<crate::types::CloudflareConfig> {
        Err(AuthError::NotFound.into())
    }
}

#[cfg(test)]
mod tests;
