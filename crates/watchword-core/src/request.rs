//! [`AuthRequest`] and [`AuthResponse`]: every operation of watchword's
//! service as one value, whichever transport carried it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::{
    AuthConfig, CloudflareConfig, CreatedUser, Link, LoginRequest, NewUser, PasswordChange,
    RegisterInfo, RegisterRequest, UserChange, UserEntry, UserId, UserInfo,
};

/// One operation of watchword's service, as the server's `Auth::dispatch`
/// runs it and a frontend's transport carries it.
///
/// This is plumbing, not a wire format: it has no serde or musli
/// derives. The HTTP routes keep their paths and JSON bodies, and the
/// musli-web endpoints their own request types; each transport decodes its
/// request into an `AuthRequest`, has it dispatched, and encodes the
/// [`AuthResponse`] as that route or endpoint answers. Since every
/// transport runs the same dispatch, an operation behaves the same over each.
///
/// The operations that set, replace or clear the session cookie say so
/// with [`cookie`](AuthRequest::cookie). Only an HTTP response can carry the
/// cookie, so those go over HTTP.
///
/// New operations are added as new variants, so a `match` on it needs a
/// wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthRequest {
    /// The sign-in methods on offer, [`AuthConfig`]. Anyone. `GET
    /// /api/auth/config`.
    Config,
    /// The signed-in user, with [`UserInfo::impersonated_by`] when an admin
    /// is acting as them. Signed in. `GET /api/auth/me`, the musli-web
    /// endpoint `Me`.
    Me,
    /// Signs in with a password. Anyone; throttled by the client's address.
    /// Sets the cookie. `POST /api/auth/login`.
    Login(LoginRequest),
    /// Signs in the user the request's Cloudflare Access credentials vouch
    /// for. Anyone. Sets the cookie. `POST /api/auth/cloudflare`.
    CloudflareSignIn,
    /// Ends the session. Anyone. Clears the cookie. `POST /api/auth/logout`.
    Logout,
    /// What a registration or reset link is for. Anyone. `GET
    /// /api/auth/register/{token}`.
    RegisterInfo {
        /// The link's token.
        token: String,
    },
    /// Registers, or resets the password, with a link. Anyone. Sets the
    /// cookie. `POST /api/auth/register/{token}`.
    Register {
        /// The link's token.
        token: String,
        /// The credentials to register with.
        request: RegisterRequest,
    },
    /// Sets or changes the signed-in user's password. Signed in. `POST
    /// /api/auth/account/password`, the musli-web endpoint `ChangePassword`.
    ChangePassword(PasswordChange),
    /// Changes the signed-in user's own login or email, not their role.
    /// Signed in. `PATCH /api/auth/account`, the musli-web endpoint
    /// `UpdateAccount`.
    UpdateAccount(UserChange),
    /// Every user. Admins. `GET /api/auth/users`, the musli-web endpoint
    /// `Users`.
    Users,
    /// Creates a user and their registration link. Admins. `POST
    /// /api/auth/users`, the musli-web endpoint `CreateUser`.
    CreateUser(NewUser),
    /// Changes another user. Admins. `PATCH /api/auth/users/{id}`, the
    /// musli-web endpoint `UpdateUser`.
    UpdateUser {
        /// The user to change.
        id: UserId,
        /// The change.
        change: UserChange,
    },
    /// Deletes another user. Admins. `DELETE /api/auth/users/{id}`, the
    /// musli-web endpoint `DeleteUser`.
    DeleteUser {
        /// The user.
        id: UserId,
    },
    /// Issues a registration or reset link for a user. Admins. `POST
    /// /api/auth/users/{id}/link`, the musli-web endpoint `IssueLink`.
    IssueLink {
        /// The user.
        id: UserId,
    },
    /// Uses up a user's links. Admins. `DELETE /api/auth/users/{id}/link`,
    /// the musli-web endpoint `RevokeLink`.
    RevokeLink {
        /// The user.
        id: UserId,
    },
    /// Ends every session of a user. Admins. `POST
    /// /api/auth/users/{id}/sign-out`, the musli-web endpoint `SignOutUser`.
    SignOutUser {
        /// The user.
        id: UserId,
    },
    /// Revokes another user's access. Admins. `POST
    /// /api/auth/users/{id}/revoke`, the musli-web endpoint `RevokeAccess`.
    RevokeAccess {
        /// The user.
        id: UserId,
    },
    /// Signs in as another user, in a session marked with the admin. Admins,
    /// if impersonation is enabled. Replaces the cookie. `POST
    /// /api/auth/users/{id}/impersonate`.
    Impersonate {
        /// The user to act as.
        id: UserId,
    },
    /// Ends an impersonated session, signing the admin back in. Signed in,
    /// impersonated. Replaces the cookie. `POST /api/auth/impersonate/stop`.
    StopImpersonating,
    /// The Cloudflare Access settings. Admins. `GET /api/auth/cloudflare`,
    /// the musli-web endpoint `Cloudflare`.
    Cloudflare,
    /// Stores and applies the Cloudflare Access settings. Admins. `PUT
    /// /api/auth/cloudflare`, the musli-web endpoint `SetCloudflare`.
    SetCloudflare(CloudflareConfig),
}

impl AuthRequest {
    /// What the operation does to the session cookie, or `None` when it
    /// leaves it alone.
    ///
    /// Only an HTTP response can set or clear the `HttpOnly` cookie, so an
    /// operation with a [`CookieChange`] must go over HTTP; the server's
    /// socket adapter has no endpoint for one. One that
    /// [replaces](CookieChange::Replace) the cookie also leaves a socket
    /// opened with the earlier session speaking for that session.
    pub fn cookie(&self) -> Option<CookieChange> {
        match self {
            AuthRequest::Login(..)
            | AuthRequest::CloudflareSignIn
            | AuthRequest::Register { .. } => Some(CookieChange::Set),
            AuthRequest::Impersonate { .. } | AuthRequest::StopImpersonating => {
                Some(CookieChange::Replace)
            }
            AuthRequest::Logout => Some(CookieChange::Clear),
            AuthRequest::Config
            | AuthRequest::Me
            | AuthRequest::RegisterInfo { .. }
            | AuthRequest::ChangePassword(..)
            | AuthRequest::UpdateAccount(..)
            | AuthRequest::Users
            | AuthRequest::CreateUser(..)
            | AuthRequest::UpdateUser { .. }
            | AuthRequest::DeleteUser { .. }
            | AuthRequest::IssueLink { .. }
            | AuthRequest::RevokeLink { .. }
            | AuthRequest::SignOutUser { .. }
            | AuthRequest::RevokeAccess { .. }
            | AuthRequest::Cloudflare
            | AuthRequest::SetCloudflare(..) => None,
        }
    }
}

/// What an [`AuthRequest`] does to the session cookie; see
/// [`AuthRequest::cookie`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CookieChange {
    /// Signs in, setting the cookie to a new session.
    Set,
    /// Replaces the signed-in session with a new one, as impersonating and
    /// stopping do.
    Replace,
    /// Ends the session and clears the cookie.
    Clear,
}

/// The answer to an [`AuthRequest`], one variant per type of answer.
///
/// Like the request, this is plumbing: each transport answers with the
/// value a variant carries, as that route or endpoint has always answered.
/// With the `axum08` feature it is an `IntoResponse`, and with `musliweb05`
/// it encodes as the value it carries, the response of the musli-web
/// endpoint for its request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthResponse {
    /// The answer to [`AuthRequest::Config`].
    Config(AuthConfig),
    /// A user: the signed-in one for [`Me`](AuthRequest::Me), the account
    /// operations and the sign-ins, or the one an admin operation changed.
    User(UserInfo),
    /// The answer to [`AuthRequest::Users`].
    Users(Vec<UserEntry>),
    /// The answer to [`AuthRequest::CreateUser`].
    CreatedUser(CreatedUser),
    /// The answer to [`AuthRequest::IssueLink`].
    Link(Link),
    /// The answer to [`AuthRequest::RegisterInfo`].
    RegisterInfo(RegisterInfo),
    /// The Cloudflare Access settings, the answer to
    /// [`Cloudflare`](AuthRequest::Cloudflare) and
    /// [`SetCloudflare`](AuthRequest::SetCloudflare).
    Cloudflare(CloudflareConfig),
    /// Done, with nothing to answer: HTTP's 204, musli-web's `()`.
    Done,
}

#[cfg(feature = "musliweb05")]
mod musli {
    use alloc::vec::Vec;

    use musli_core02::en::{Encode, Encoder};

    use super::AuthResponse;
    use crate::{
        AuthConfig, CloudflareConfig, CreatedUser, Link, RegisterInfo, UserEntry, UserInfo,
    };

    /// Encodes as the value the variant carries, `()` for
    /// [`Done`](AuthResponse::Done): the response of the musli-web endpoint
    /// that answers the request. There is no `Decode`; a client decodes the
    /// endpoint's own response type.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "musliweb05")))]
    impl<M> Encode<M> for AuthResponse
    where
        M: 'static,
        AuthConfig: Encode<M>,
        UserInfo: Encode<M>,
        Vec<UserEntry>: Encode<M>,
        CreatedUser: Encode<M>,
        Link: Encode<M>,
        RegisterInfo: Encode<M>,
        CloudflareConfig: Encode<M>,
        (): Encode<M>,
    {
        type Encode = Self;

        fn encode<E>(&self, encoder: E) -> Result<(), E::Error>
        where
            E: Encoder<Mode = M>,
        {
            match self {
                AuthResponse::Config(value) => value.encode(encoder),
                AuthResponse::User(value) => value.encode(encoder),
                AuthResponse::Users(value) => value.encode(encoder),
                AuthResponse::CreatedUser(value) => value.encode(encoder),
                AuthResponse::Link(value) => value.encode(encoder),
                AuthResponse::RegisterInfo(value) => value.encode(encoder),
                AuthResponse::Cloudflare(value) => value.encode(encoder),
                AuthResponse::Done => ().encode(encoder),
            }
        }

        fn as_encode(&self) -> &Self::Encode {
            self
        }
    }
}
