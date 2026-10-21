//! watchword's account and user-management operations, and its live updates,
//! as [musli-web] 0.5 API types, so an app can carry them on the musli-web
//! WebSocket it already has.
//!
//! The endpoints and [`AuthBroadcast`] form a `define!` list of their own,
//! which an app includes in its list (`include watchword_core::musliweb05 as
//! Auth;`), so one connection carries both and musli-web checks at compile
//! time that no id is used twice. watchword pins each of its types to an id in
//! 32000–32255, a band an app's own implicit ids, which count up from 1, never
//! reach. A released id never changes meaning.
//!
//! A response is the operation's value. A refused request fails with the same
//! structured [`AuthError`] as over HTTP, sent as musli-web's typed request
//! error, which the client decodes with `web::Error::server_error`; an
//! internal failure fails with just the message `internal error`. Each request
//! body is its own type here, since musli-web ties a request type to one
//! endpoint.
//!
//! ```
//! use musli_core02::{Decode, Encode};
//! use musli_web05::api::Id;
//! use watchword_core::musliweb05::{self as auth, Me};
//!
//! #[derive(Encode, Decode)]
//! #[musli(crate = musli_core02)]
//! pub struct StatusRequest;
//!
//! musli_web05::api::define! {
//!     // Only needed since the dependency is renamed, as it is here.
//!     #![musli(crate = musli_web05)]
//!
//!     pub type Status;
//!
//!     impl Endpoint for Status {
//!         impl Request for StatusRequest;
//!         type Response<'de> = u32;
//!     }
//!
//!     /// watchword's endpoints and broadcast.
//!     include watchword_core::musliweb05 as Auth;
//! }
//!
//! assert_eq!(Request::from_id(Me::ID), Request::Auth(auth::Request::Me));
//! assert_eq!(Request::from_id(Status::ID), Request::Status);
//! ```
//!
//! | Endpoint | Id | Request | Response |
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

use musli_core02::{Decode, Encode};

#[cfg(doc)]
use crate::AuthError;
use crate::{
    CloudflareConfig, CreatedUser, Link, NewUser, PasswordChange, UserChange, UserEntry, UserId,
    UserInfo,
};

/// The first id of the band watchword owns.
pub const FIRST_ID: u16 = 32000;

/// The last id of the band watchword owns.
pub const LAST_ID: u16 = 32255;

/// Whether `id` is in the band of ids watchword owns, [`FIRST_ID`] to
/// [`LAST_ID`].
pub fn is_watchword_id(id: musli_web05::api::MessageId) -> bool {
    (FIRST_ID..=LAST_ID).contains(&id.get())
}

musli_web05::api::define! {
    #![musli(crate = musli_web05)]

    /// The signed-in user, with [`UserInfo::impersonated_by`] set when an
    /// admin is acting as them. Like `GET /api/auth/me`.
    #[musli(id = 32000)]
    pub type Me;

    impl Endpoint for Me {
        impl Request for MeRequest;
        type Response<'de> = UserInfo;
    }

    /// Changes the signed-in user's own login or email. Like
    /// `PATCH /api/auth/account`.
    #[musli(id = 32001)]
    pub type UpdateAccount;

    impl Endpoint for UpdateAccount {
        impl Request for UserChange;
        type Response<'de> = UserInfo;
    }

    /// Sets or changes the signed-in user's password. Like
    /// `POST /api/auth/account/password`.
    #[musli(id = 32002)]
    pub type ChangePassword;

    impl Endpoint for ChangePassword {
        impl Request for PasswordChange;
        type Response<'de> = UserInfo;
    }

    /// Every user, for the admin list. Admins only. Like
    /// `GET /api/auth/users`.
    #[musli(id = 32003)]
    pub type Users;

    impl Endpoint for Users {
        impl Request for UsersRequest;
        type Response<'de> = Vec<UserEntry>;
    }

    /// Creates a user and their registration link. Admins only. Like
    /// `POST /api/auth/users`.
    #[musli(id = 32004)]
    pub type CreateUser;

    impl Endpoint for CreateUser {
        impl Request for NewUser;
        type Response<'de> = CreatedUser;
    }

    /// Changes another user. Admins only. Like
    /// `PATCH /api/auth/users/{id}`.
    #[musli(id = 32005)]
    pub type UpdateUser;

    impl Endpoint for UpdateUser {
        impl Request for UserUpdate;
        type Response<'de> = UserInfo;
    }

    /// Deletes another user. Admins only. Like
    /// `DELETE /api/auth/users/{id}`.
    #[musli(id = 32006)]
    pub type DeleteUser;

    impl Endpoint for DeleteUser {
        impl Request for DeleteUserRequest;
        type Response<'de> = ();
    }

    /// Issues a new registration or reset link for a user, replacing any
    /// live one. Admins only. Like `POST /api/auth/users/{id}/link`.
    #[musli(id = 32007)]
    pub type IssueLink;

    impl Endpoint for IssueLink {
        impl Request for IssueLinkRequest;
        type Response<'de> = Link;
    }

    /// Revokes a user's live link. Admins only. Like
    /// `DELETE /api/auth/users/{id}/link`.
    #[musli(id = 32008)]
    pub type RevokeLink;

    impl Endpoint for RevokeLink {
        impl Request for RevokeLinkRequest;
        type Response<'de> = ();
    }

    /// Ends every session of another user. Admins only. Like
    /// `POST /api/auth/users/{id}/sign-out`.
    #[musli(id = 32009)]
    pub type SignOutUser;

    impl Endpoint for SignOutUser {
        impl Request for SignOutUserRequest;
        type Response<'de> = ();
    }

    /// Revokes another user's access, so they cannot sign in until issued a
    /// new link. Admins only. Like `POST /api/auth/users/{id}/revoke`.
    #[musli(id = 32010)]
    pub type RevokeAccess;

    impl Endpoint for RevokeAccess {
        impl Request for RevokeAccessRequest;
        type Response<'de> = UserInfo;
    }

    /// The Cloudflare Access settings, as stored, or the [`Default`] when
    /// none are. Admins only. Like `GET /api/auth/cloudflare`.
    #[musli(id = 32011)]
    pub type Cloudflare;

    impl Endpoint for Cloudflare {
        impl Request for CloudflareRequest;
        type Response<'de> = CloudflareConfig;
    }

    /// Stores and applies the Cloudflare Access settings, answering with
    /// them as stored. Admins only. Like `PUT /api/auth/cloudflare`.
    #[musli(id = 32012)]
    pub type SetCloudflare;

    impl Endpoint for SetCloudflare {
        impl Request for CloudflareConfig;
        type Response<'de> = CloudflareConfig;
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
#[musli(crate = musli_core02)]
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
#[musli(crate = musli_core02)]
pub struct MeRequest;

/// The request of [`Users`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Encode, Decode)]
#[musli(crate = musli_core02)]
pub struct UsersRequest;

/// The request of [`Cloudflare`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Encode, Decode)]
#[musli(crate = musli_core02)]
pub struct CloudflareRequest;

/// The request of [`UpdateUser`]: the change to make to the user `id`.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
#[musli(crate = musli_core02)]
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
            #[musli(crate = musli_core02)]
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
