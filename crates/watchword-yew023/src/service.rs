//! [`AuthService`]: watchword's operations, for its components and the app's.

use core::fmt;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

use yew::prelude::*;

use watchword_core::{
    AuthConfig, AuthRequest, AuthResponse, CloudflareConfig, CreatedUser, Link, LoginRequest,
    NewUser, PasswordChange, RegisterInfo, RegisterRequest, UserChange, UserEntry, UserId,
    UserInfo,
};

use super::Error;
use super::transport::{HttpTransport, Transport};

/// Sends `$request` and answers with what `$pattern` binds, or
/// [`Error::UnexpectedResponse`] for any other answer.
macro_rules! call {
    ($service:expr, $request:expr, $pattern:pat => $value:expr) => {
        match $service.transport.send($request).await? {
            $pattern => Ok($value),
            _ => Err(Error::UnexpectedResponse),
        }
    };
}

/// watchword's operations, each an `async` method, sent over a
/// [`Transport`]. Get it with [`use_auth_service`].
///
/// [`AuthProvider`](super::AuthProvider) provides it to everything it
/// renders, the sign-in and registration pages included, and watchword's
/// own components make every request with it, so an app's components that
/// use it behave the same as watchword's: by default the requests go over
/// the app's socket once it is handed over with
/// [`AuthContext::set_socket`](super::AuthContext::set_socket) (feature
/// `musliweb05`), and over HTTP otherwise, while a transport given with the
/// provider's [`service`](super::AuthProviderProps::service) prop carries
/// them all, such as a test's.
///
/// The service only sends requests: the provider's state follows what
/// watchword's components do, but an app's own request does not reach it by
/// itself. After an app changes the signed-in user, it passes the answer to
/// [`AuthContext::set_user`](super::AuthContext::set_user), and after a 401
/// it calls [`AuthContext::check_session`](super::AuthContext::check_session).
///
/// Clones share the transport and are equal.
///
/// ```ignore
/// use watchword::yew023::{use_auth, use_auth_service};
/// use watchword::types::UserChange;
///
/// #[function_component]
/// fn Nickname() -> Html {
///     let auth = use_auth();
///     let service = use_auth_service();
///
///     let onclick = Callback::from(move |_| {
///         let auth = auth.clone();
///         let service = service.clone();
///
///         yew::platform::spawn_local(async move {
///             let change = UserChange {
///                 login: Some(Some("nick".into())),
///                 ..UserChange::default()
///             };
///
///             match service.update_account(change).await {
///                 Ok(user) => auth.set_user(user),
///                 Err(error) if error.is_unauthorized() => auth.check_session(),
///                 Err(..) => {}
///             }
///         });
///     });
///
///     html! { <button {onclick}>{"Call me nick"}</button> }
/// }
/// ```
#[derive(Clone)]
pub struct AuthService {
    transport: Rc<dyn Transport>,
}

impl AuthService {
    /// A service that sends its requests over `transport`.
    pub fn new<T>(transport: T) -> Self
    where
        T: Transport + 'static,
    {
        Self::from_rc(Rc::new(transport))
    }

    /// A service over a transport the caller keeps a handle to.
    pub(super) fn from_rc(transport: Rc<dyn Transport>) -> Self {
        Self { transport }
    }

    /// What the sign-in page offers. Anyone. `GET /api/auth/config`.
    pub async fn config(&self) -> Result<AuthConfig, Error> {
        call!(self, AuthRequest::Config, AuthResponse::Config(config) => config)
    }

    /// The signed-in user. Fails with
    /// [`AuthError::Unauthorized`](watchword_core::AuthError::Unauthorized)
    /// without a live session. `GET /api/auth/me`.
    pub async fn me(&self) -> Result<UserInfo, Error> {
        call!(self, AuthRequest::Me, AuthResponse::User(user) => user)
    }

    /// Signs in with a login name or email and a password, setting the
    /// session cookie. `POST /api/auth/login`.
    pub async fn login(&self, request: LoginRequest) -> Result<UserInfo, Error> {
        call!(self, AuthRequest::Login(request), AuthResponse::User(user) => user)
    }

    /// Signs in with the Cloudflare Access credentials the browser's
    /// requests carry, setting the session cookie. `POST
    /// /api/auth/cloudflare`.
    pub async fn cloudflare_sign_in(&self) -> Result<UserInfo, Error> {
        call!(self, AuthRequest::CloudflareSignIn, AuthResponse::User(user) => user)
    }

    /// Signs out, ending the session and clearing its cookie. `POST
    /// /api/auth/logout`. Most apps call
    /// [`AuthContext::sign_out`](super::AuthContext::sign_out) instead,
    /// which also shows the sign-in page.
    pub async fn logout(&self) -> Result<(), Error> {
        call!(self, AuthRequest::Logout, AuthResponse::Done => ())
    }

    /// What a registration or reset link is for. Fails with
    /// [`AuthError::NotFound`](watchword_core::AuthError::NotFound) for an
    /// unknown link and [`AuthError::Gone`](watchword_core::AuthError::Gone)
    /// for a used or expired one. `GET /api/auth/register/{token}`.
    pub async fn register_info(&self, token: String) -> Result<RegisterInfo, Error> {
        call!(
            self,
            AuthRequest::RegisterInfo { token },
            AuthResponse::RegisterInfo(info) => info
        )
    }

    /// Sets the password of a link's user and signs them in, setting the
    /// session cookie. `POST /api/auth/register/{token}`.
    pub async fn register(
        &self,
        token: String,
        request: RegisterRequest,
    ) -> Result<UserInfo, Error> {
        call!(
            self,
            AuthRequest::Register { token, request },
            AuthResponse::User(user) => user
        )
    }

    /// Changes or sets the signed-in user's password. This session stays
    /// signed in and the user's other sessions end; a Google user switches to
    /// the password. `POST /api/auth/account/password`.
    pub async fn change_password(&self, change: PasswordChange) -> Result<UserInfo, Error> {
        call!(self, AuthRequest::ChangePassword(change), AuthResponse::User(user) => user)
    }

    /// Changes the signed-in user's own login or email; not the role, nor the
    /// email of a Google user. `PATCH /api/auth/account`.
    pub async fn update_account(&self, change: UserChange) -> Result<UserInfo, Error> {
        call!(self, AuthRequest::UpdateAccount(change), AuthResponse::User(user) => user)
    }

    /// Every user, for admins. `GET /api/auth/users`. Components showing the
    /// list share it through [`use_users`](super::use_users) instead.
    pub async fn users(&self) -> Result<Vec<UserEntry>, Error> {
        call!(self, AuthRequest::Users, AuthResponse::Users(users) => users)
    }

    /// Creates a user and their registration link, for admins. Fails with
    /// [`AuthError::Conflict`](watchword_core::AuthError::Conflict) when the
    /// login or email is taken. `POST /api/auth/users`.
    pub async fn create_user(&self, new: NewUser) -> Result<CreatedUser, Error> {
        call!(self, AuthRequest::CreateUser(new), AuthResponse::CreatedUser(created) => created)
    }

    /// Changes a user's login, email or role, for admins; not their own
    /// role. `PATCH /api/auth/users/{id}`.
    pub async fn update_user(&self, id: UserId, change: UserChange) -> Result<UserInfo, Error> {
        call!(
            self,
            AuthRequest::UpdateUser { id, change },
            AuthResponse::User(user) => user
        )
    }

    /// Deletes a user, for admins; not themselves. `DELETE
    /// /api/auth/users/{id}`.
    pub async fn delete_user(&self, id: UserId) -> Result<(), Error> {
        call!(self, AuthRequest::DeleteUser { id }, AuthResponse::Done => ())
    }

    /// Issues a new registration or reset link for a user, using up their
    /// earlier ones, for admins. The token is shown only this once. `POST
    /// /api/auth/users/{id}/link`.
    pub async fn issue_link(&self, id: UserId) -> Result<Link, Error> {
        call!(self, AuthRequest::IssueLink { id }, AuthResponse::Link(link) => link)
    }

    /// Uses up a user's live link, for admins. `DELETE
    /// /api/auth/users/{id}/link`.
    pub async fn revoke_link(&self, id: UserId) -> Result<(), Error> {
        call!(self, AuthRequest::RevokeLink { id }, AuthResponse::Done => ())
    }

    /// Ends every session of a user, for admins. `POST
    /// /api/auth/users/{id}/sign-out`.
    pub async fn sign_out_user(&self, id: UserId) -> Result<(), Error> {
        call!(self, AuthRequest::SignOutUser { id }, AuthResponse::Done => ())
    }

    /// Revokes a user's access: their password is cleared, their links are
    /// used up and their sessions end, until they are issued a new link. For
    /// admins, not on themselves. The answer is the user as revoked. `POST
    /// /api/auth/users/{id}/revoke`.
    pub async fn revoke_access(&self, id: UserId) -> Result<UserInfo, Error> {
        call!(self, AuthRequest::RevokeAccess { id }, AuthResponse::User(user) => user)
    }

    /// Signs this browser in as another user, for admins when the server
    /// enables impersonation, replacing the session cookie. The answer is the
    /// user, with [`impersonated_by`](UserInfo::impersonated_by) set; reload
    /// the user afterwards with
    /// [`AuthContext::refresh`](super::AuthContext::refresh). `POST
    /// /api/auth/users/{id}/impersonate`.
    pub async fn impersonate(&self, id: UserId) -> Result<UserInfo, Error> {
        call!(self, AuthRequest::Impersonate { id }, AuthResponse::User(user) => user)
    }

    /// Ends the impersonated session this browser holds and signs the admin
    /// who started it back in, replacing the session cookie; the answer is
    /// the admin. Refused with
    /// [`AuthError::Forbidden`](watchword_core::AuthError::Forbidden) when the
    /// session is not impersonated. `POST /api/auth/impersonate/stop`.
    pub async fn stop_impersonating(&self) -> Result<UserInfo, Error> {
        call!(self, AuthRequest::StopImpersonating, AuthResponse::User(user) => user)
    }

    /// The Cloudflare Access settings, or their default when the server has
    /// none, for admins. Fails with
    /// [`AuthError::NotFound`](watchword_core::AuthError::NotFound) when the
    /// server is built without Cloudflare Access. `GET /api/auth/cloudflare`.
    pub async fn cloudflare_settings(&self) -> Result<CloudflareConfig, Error> {
        call!(self, AuthRequest::Cloudflare, AuthResponse::Cloudflare(config) => config)
    }

    /// Stores and applies the Cloudflare Access settings, for admins. The
    /// answer is the settings as stored, with the team domain and audience
    /// trimmed. `PUT /api/auth/cloudflare`.
    pub async fn set_cloudflare_settings(
        &self,
        config: CloudflareConfig,
    ) -> Result<CloudflareConfig, Error> {
        call!(
            self,
            AuthRequest::SetCloudflare(config),
            AuthResponse::Cloudflare(config) => config
        )
    }
}

/// Over [`HttpTransport`].
impl Default for AuthService {
    fn default() -> Self {
        Self::new(HttpTransport)
    }
}

impl PartialEq for AuthService {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.transport, &other.transport)
    }
}

impl fmt::Debug for AuthService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthService").finish_non_exhaustive()
    }
}

/// The [`AuthService`] of the enclosing [`AuthProvider`](super::AuthProvider),
/// which is there for the sign-in and registration pages too. Outside a
/// provider, a service over [`HttpTransport`].
///
/// The service is its own context, apart from the
/// [`AuthContext`](super::AuthContext), so a component that only shows the
/// user does not render again when the service changes, nor one that only
/// makes requests when the user does.
///
/// A struct component reads it with `ctx.link().context::<AuthService>(..)`.
#[hook]
pub fn use_auth_service() -> AuthService {
    use_context::<AuthService>().unwrap_or_default()
}
