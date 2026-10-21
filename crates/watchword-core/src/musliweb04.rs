//! watchword's account and user-management operations, and its live updates,
//! as [musli-web] 0.4 API types, so an app can carry them on the musli-web
//! WebSocket it already has.
//!
//! The endpoints and [`AuthBroadcast`] form their own `define!` list beside
//! the app's: one connection carries both, as long as their ids differ.
//! watchword owns the ids 32000–32255 and pins each of its types to one of
//! them, so an app's own implicit ids, which count up from 1, never clash with
//! them. A released id never changes meaning.
//!
//! Every response is `Result<T, AuthError>`, so a frontend gets the same
//! structured [`AuthError`] over the socket as over HTTP. Each request body is
//! its own type here, since musli-web ties a request type to one endpoint.
//!
//! | Endpoint | Id | Request | Response's `Ok` |
//! |---|---|---|---|
//! | [`Me`] | 32000 | [`MeRequest`] | [`UserInfo`] |
//! | [`UpdateAccount`] | 32001 | [`UserChange`] | [`UserInfo`] |
//! | [`ChangePassword`] | 32002 | [`PasswordChange`] | [`UserInfo`] |
//! | [`Users`] | 32003 | [`UsersRequest`] | `Vec<`[`UserEntry`]`>` |
//! | [`CreateUser`] | 32004 | [`NewUser`] | [`CreatedUser`] |
//! | [`UpdateUser`] | 32005 | [`UserUpdate`] | [`UserInfo`] |
//! | [`DeleteUser`] | 32006 | [`DeleteUserRequest`] | `()` |
//! | [`IssueLink`] | 32007 | [`IssueLinkRequest`] | [`Link`] |
//! | [`RevokeLink`] | 32008 | [`RevokeLinkRequest`] | `()` |
//! | [`SignOutUser`] | 32009 | [`SignOutUserRequest`] | `()` |
//! | [`RevokeAccess`] | 32010 | [`RevokeAccessRequest`] | [`UserInfo`] |
//! | [`Cloudflare`] | 32011 | [`CloudflareRequest`] | [`CloudflareConfig`] |
//! | [`SetCloudflare`] | 32012 | [`CloudflareConfig`] | [`CloudflareConfig`] |
//!
//! [`AuthBroadcast`] (32100) carries [`AuthUpdate`]s.
//!
//! [musli-web]: https://docs.rs/musli-web

use alloc::vec::Vec;

use musli_core01::{Decode, Encode};

use crate::{
    AuthError, CloudflareConfig, CreatedUser, Link, NewUser, PasswordChange, UserChange, UserEntry,
    UserId, UserInfo,
};

/// The first id of the band watchword owns.
pub const FIRST_ID: u16 = 32000;

/// The last id of the band watchword owns.
pub const LAST_ID: u16 = 32255;

/// Whether `id` is in the band of ids watchword owns, [`FIRST_ID`] to
/// [`LAST_ID`].
pub fn is_watchword_id(id: musli_web::api::MessageId) -> bool {
    (FIRST_ID..=LAST_ID).contains(&id.get())
}

musli_web::api::define! {
    /// The signed-in user, with [`UserInfo::impersonated_by`] set when an
    /// admin is acting as them. Like `GET /api/auth/me`.
    #[musli(id = 32000)]
    pub type Me;

    impl Endpoint for Me {
        impl Request for MeRequest;
        type Response<'de> = Result<UserInfo, AuthError>;
    }

    /// Changes the signed-in user's own login or email. Like
    /// `PATCH /api/auth/account`.
    #[musli(id = 32001)]
    pub type UpdateAccount;

    impl Endpoint for UpdateAccount {
        impl Request for UserChange;
        type Response<'de> = Result<UserInfo, AuthError>;
    }

    /// Sets or changes the signed-in user's password. Like
    /// `POST /api/auth/account/password`.
    #[musli(id = 32002)]
    pub type ChangePassword;

    impl Endpoint for ChangePassword {
        impl Request for PasswordChange;
        type Response<'de> = Result<UserInfo, AuthError>;
    }

    /// Every user, for the admin list. Admins only. Like
    /// `GET /api/auth/users`.
    #[musli(id = 32003)]
    pub type Users;

    impl Endpoint for Users {
        impl Request for UsersRequest;
        type Response<'de> = Result<Vec<UserEntry>, AuthError>;
    }

    /// Creates a user and their registration link. Admins only. Like
    /// `POST /api/auth/users`.
    #[musli(id = 32004)]
    pub type CreateUser;

    impl Endpoint for CreateUser {
        impl Request for NewUser;
        type Response<'de> = Result<CreatedUser, AuthError>;
    }

    /// Changes another user. Admins only. Like
    /// `PATCH /api/auth/users/{id}`.
    #[musli(id = 32005)]
    pub type UpdateUser;

    impl Endpoint for UpdateUser {
        impl Request for UserUpdate;
        type Response<'de> = Result<UserInfo, AuthError>;
    }

    /// Deletes another user. Admins only. Like
    /// `DELETE /api/auth/users/{id}`.
    #[musli(id = 32006)]
    pub type DeleteUser;

    impl Endpoint for DeleteUser {
        impl Request for DeleteUserRequest;
        type Response<'de> = Result<(), AuthError>;
    }

    /// Issues a new registration or reset link for a user, replacing any
    /// live one. Admins only. Like `POST /api/auth/users/{id}/link`.
    #[musli(id = 32007)]
    pub type IssueLink;

    impl Endpoint for IssueLink {
        impl Request for IssueLinkRequest;
        type Response<'de> = Result<Link, AuthError>;
    }

    /// Revokes a user's live link. Admins only. Like
    /// `DELETE /api/auth/users/{id}/link`.
    #[musli(id = 32008)]
    pub type RevokeLink;

    impl Endpoint for RevokeLink {
        impl Request for RevokeLinkRequest;
        type Response<'de> = Result<(), AuthError>;
    }

    /// Ends every session of another user. Admins only. Like
    /// `POST /api/auth/users/{id}/sign-out`.
    #[musli(id = 32009)]
    pub type SignOutUser;

    impl Endpoint for SignOutUser {
        impl Request for SignOutUserRequest;
        type Response<'de> = Result<(), AuthError>;
    }

    /// Revokes another user's access, so they cannot sign in until issued a
    /// new link. Admins only. Like `POST /api/auth/users/{id}/revoke`.
    #[musli(id = 32010)]
    pub type RevokeAccess;

    impl Endpoint for RevokeAccess {
        impl Request for RevokeAccessRequest;
        type Response<'de> = Result<UserInfo, AuthError>;
    }

    /// The Cloudflare Access settings, as stored, or the [`Default`] when
    /// none are. Admins only. Like `GET /api/auth/cloudflare`.
    #[musli(id = 32011)]
    pub type Cloudflare;

    impl Endpoint for Cloudflare {
        impl Request for CloudflareRequest;
        type Response<'de> = Result<CloudflareConfig, AuthError>;
    }

    /// Stores and applies the Cloudflare Access settings, answering with
    /// them as stored. Admins only. Like `PUT /api/auth/cloudflare`.
    #[musli(id = 32012)]
    pub type SetCloudflare;

    impl Endpoint for SetCloudflare {
        impl Request for CloudflareConfig;
        type Response<'de> = Result<CloudflareConfig, AuthError>;
    }

    /// The live auth changes a connection may see, as [`AuthUpdate`]s.
    #[musli(id = 32100)]
    pub type AuthBroadcast;

    impl Broadcast for AuthBroadcast {
        impl Event for AuthUpdate;
    }
}

/// A live auth change, the event of [`AuthBroadcast`].
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[musli(crate = musli_core01)]
pub enum AuthUpdate {
    /// The connection's own user changed: role, login, email or credential.
    /// Set as [`Me`] answers, so an impersonated session keeps its marker.
    Me(UserInfo),
    /// A user was created. Sent to admins only.
    UserCreated(UserInfo),
    /// A user changed. Sent to admins only.
    UserChanged(UserInfo),
    /// A user was deleted. Sent to admins only.
    UserDeleted(UserId),
    /// Updates were missed, so what the page shows of the user list may be
    /// stale and should be fetched again. Carries the connection's own user
    /// as [`Me`](AuthUpdate::Me) does. Sent to admins only; a regular user's
    /// connection gets a `Me` instead.
    Resync(UserInfo),
}

/// The request of [`Me`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Encode, Decode)]
#[musli(crate = musli_core01)]
pub struct MeRequest;

/// The request of [`Users`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Encode, Decode)]
#[musli(crate = musli_core01)]
pub struct UsersRequest;

/// The request of [`Cloudflare`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Encode, Decode)]
#[musli(crate = musli_core01)]
pub struct CloudflareRequest;

/// The request of [`UpdateUser`]: the change to make to the user `id`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[musli(crate = musli_core01)]
pub struct UserUpdate {
    /// The user to change.
    pub id: UserId,
    /// The change.
    pub change: UserChange,
}

/// Declares the requests that only name their target user.
macro_rules! user_requests {
    ($($name:ident => $endpoint:ident),* $(,)?) => {
        $(
            #[doc = concat!("The request of [`", stringify!($endpoint), "`]: the user it acts on.")]
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
            #[musli(crate = musli_core01)]
            pub struct $name {
                /// The user.
                pub id: UserId,
            }
        )*
    };
}

user_requests! {
    DeleteUserRequest => DeleteUser,
    IssueLinkRequest => IssueLink,
    RevokeLinkRequest => RevokeLink,
    SignOutUserRequest => SignOutUser,
    RevokeAccessRequest => RevokeAccess,
}
