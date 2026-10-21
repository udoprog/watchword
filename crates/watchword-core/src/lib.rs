//! [<img alt="github" src="https://img.shields.io/badge/github-udoprog/watchword-8da0cb?style=for-the-badge&logo=github" height="20">](https://github.com/udoprog/watchword)
//! [<img alt="crates.io" src="https://img.shields.io/crates/v/watchword-core.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/watchword-core)
//! [<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-watchword--core-66c2a5?style=for-the-badge&logoColor=white&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">](https://docs.rs/watchword-core)
//!
//! The types [watchword]'s server and frontends share: identities, roles,
//! account state, the JSON wire types of the `/api/auth` routes,
//! [`AuthError`], and input validation.
//!
//! Apps normally use these through watchword, which re-exports them as
//! `watchword::types` and at its crate root, or through a frontend crate such
//! as `watchword-yew023`. Released in lockstep with watchword.
//!
//! <br>
//!
//! ## Features
//!
//! The crate is `no_std`, and safe to build for `wasm32-unknown-unknown` with
//! any feature but `axum08` and `sqll014`. Only `std` is on by default.
//!
//! | Feature | What it provides |
//! |---|---|
//! | *(none)* | `UserId`, `Role`, `Access`, `Method`, `Conflict`, `AuthConfig` and `MIN_PASSWORD_LEN` |
//! | `alloc` | the wire types that hold strings (`UserInfo`, `LoginRequest`, `CreatedUser`, ...), [`AuthError`] and its `Invalid` reasons, `validate_password` and `normalize_email` |
//! | `std` *(default)* | `alloc`, and the standard library for the dependencies that have it |
//! | `musli01` | musli 0.1 `Encode`/`Decode` on the types, so an app can embed them in its own WebSocket messages |
//! | `musliweb04` | `alloc` + `musli01` + [`musliweb04`]: the account, user-management and Cloudflare Access settings endpoints and `AuthBroadcast` as musli-web 0.4 API types, with their ids pinned in 32000–32255 |
//! | `axum08` | `std` + axum 0.8 `IntoResponse` for [`AuthError`], answering with its JSON body and status; watchword's `axum08` feature turns it on (not for wasm) |
//! | `sqll014` | `std` + sqll 0.14 `BindValue`, `Bind` and `FromColumn` for `UserId` (an integer with the same bits, as watchword's `SqllStore` stores it) and for `Role`, `Access` and `Method` (their names as text), so an app's own statements bind and read them directly; watchword's `sqll014` feature turns it on. It takes sqll with `threadsafe` only; the app names `bundled` or links its own SQLite (not for wasm) |
//! | `phrasebook01` | `std` + [`phrasebook01`]: `L10N`, watchword's messages (the text of its Yew components) as a [phrasebook] 0.1 catalog, for a tool such as an app's localization checker that needs them without building a frontend; watchword-yew023 re-exports it, and watchword's `phrasebook01` and `yew023` features turn it on |
//!
//! [`AuthError`]: https://docs.rs/watchword-core/latest/watchword_core/enum.AuthError.html
//! [`musliweb04`]: https://docs.rs/watchword-core/latest/watchword_core/musliweb04/index.html
//! [`phrasebook01`]: https://docs.rs/watchword-core/latest/watchword_core/phrasebook01/index.html
//! [phrasebook]: https://docs.rs/phrasebook
//! [watchword]: https://docs.rs/watchword

#![no_std]
#![cfg_attr(watchword_docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use core::fmt;
use core::num::TryFromIntError;
use core::str::FromStr;

#[cfg(feature = "alloc")]
use alloc::format;
#[cfg(feature = "alloc")]
use alloc::string::String;

#[cfg(feature = "alloc")]
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[cfg(feature = "musli01")]
use musli_core01::{Decode, Encode};

// `define!` expands to `::musli_web::` paths.
#[cfg(feature = "musliweb04")]
extern crate musli_web04 as musli_web;

#[cfg(feature = "axum08")]
mod axum08;

#[cfg(feature = "sqll014")]
mod sqll014;

#[cfg(feature = "musliweb04")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "musliweb04")))]
pub mod musliweb04;

#[cfg(feature = "phrasebook01")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "phrasebook01")))]
pub mod phrasebook01;

#[cfg(all(test, feature = "alloc"))]
mod tests;

/// The shortest password [`validate_password`] accepts, in bytes.
pub const MIN_PASSWORD_LEN: usize = 8;

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// Returns why the password is not acceptable, if it is not.
pub fn validate_password(password: &str) -> Option<Invalid> {
    if password.len() < MIN_PASSWORD_LEN {
        return Some(Invalid::PasswordTooShort {
            min: MIN_PASSWORD_LEN,
        });
    }

    None
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// Trims and lowercases an email so lookups and comparisons are
/// case-insensitive.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// A user's id. Apps convert to and from their own `u64` ids with [`new`]
/// and [`get`] or `From`, and to and from signed integers with `TryFrom`,
/// which fails on a value out of the other's range. With the `sqll014`
/// feature it binds and reads as a sqll column directly.
///
/// [`new`]: UserId::new
/// [`get`]: UserId::get
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01, transparent))]
#[serde(transparent)]
pub struct UserId(pub u64);

impl UserId {
    /// The id with the given value.
    #[inline]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The id's value.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl From<u64> for UserId {
    #[inline]
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<UserId> for u64 {
    #[inline]
    fn from(id: UserId) -> Self {
        id.0
    }
}

/// Fails on a negative value.
impl TryFrom<i64> for UserId {
    type Error = TryFromIntError;

    #[inline]
    fn try_from(id: i64) -> Result<Self, Self::Error> {
        Ok(Self(u64::try_from(id)?))
    }
}

/// Fails on an id beyond `i64::MAX`.
impl TryFrom<UserId> for i64 {
    type Error = TryFromIntError;

    #[inline]
    fn try_from(id: UserId) -> Result<Self, Self::Error> {
        i64::try_from(id.0)
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Implements `as_str`, `Display` and `FromStr` for a fieldless enum, using
/// the same lowercase names as its serde form.
macro_rules! names {
    ($ty:ident, $error:ident, $what:literal, $($variant:ident => $name:literal),* $(,)?) => {
        impl $ty {
            #[doc = concat!("The ", $what, "'s name, as stored and as serialized.")]
            pub fn as_str(self) -> &'static str {
                match self {
                    $($ty::$variant => $name,)*
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        #[doc = concat!("The error parsing an unknown ", $what, " name.")]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $error;

        impl fmt::Display for $error {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!("unknown ", $what))
            }
        }

        impl core::error::Error for $error {}

        impl FromStr for $ty {
            type Err = $error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($name => Ok($ty::$variant),)*
                    _ => Err($error),
                }
            }
        }
    };
}

/// A user's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Manages users, and whatever else the app reserves for admins.
    Admin,
    /// An ordinary user.
    Regular,
}

names!(Role, UnknownRole, "role", Admin => "admin", Regular => "regular");

/// A user's account state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// Created but not yet registered. Signs in only through Cloudflare
    /// Access, which activates the user.
    Pending,
    /// May sign in.
    Active,
    /// May not sign in by any path until issued a new link.
    Revoked,
}

names!(Access, UnknownAccess, "access state", Pending => "pending", Active => "active", Revoked => "revoked");

/// The credential a user has stored. A user has exactly one, and can switch
/// between them. Cloudflare Access is not a stored credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
#[serde(rename_all = "lowercase")]
pub enum Method {
    /// A password (which a pending user may not have set yet).
    Password,
    /// A bound Google account.
    Google,
}

names!(Method, UnknownMethod, "sign-in method", Password => "password", Google => "google");

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// What the frontend and the admin pages see of a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct UserInfo {
    /// The user's id.
    pub id: UserId,
    /// The unique login name, if the user has one.
    pub login: Option<String>,
    /// The unique, normalized email, if the user has one.
    pub email: Option<String>,
    /// The user's role.
    pub role: Role,
    /// The user's account state.
    pub access: Access,
    /// The user's stored credential.
    pub method: Method,
    /// Whether a password is set.
    pub has_password: bool,
    /// When the user was created.
    #[cfg_attr(feature = "musli01", musli(with = self::musli_timestamp))]
    pub created_at: Timestamp,
    /// The admin acting as this user, when this is the signed-in user of a
    /// session an admin created by impersonating them. Only the answers about
    /// the request's own user (`GET /api/auth/me`, sign-in, impersonation and
    /// the account routes) set it; it is absent from JSON when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonated_by: Option<Impersonator>,
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// The admin behind an impersonated session; see
/// [`UserInfo::impersonated_by`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct Impersonator {
    /// The admin's id.
    pub id: UserId,
    /// The admin's name to show, as [`UserInfo::name`] gives it.
    pub name: String,
}

#[cfg(feature = "alloc")]
impl UserInfo {
    /// The name to show: the login if there is one, otherwise the email.
    pub fn name(&self) -> &str {
        self.login
            .as_deref()
            .or(self.email.as_deref())
            .unwrap_or_default()
    }

    /// Whether the user is an admin.
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// A user in the admin list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct UserEntry {
    /// The user.
    pub user: UserInfo,
    /// When the user's live registration or reset link expires, if there is
    /// one.
    #[cfg_attr(feature = "musli01", musli(with = self::musli_timestamp::option))]
    pub link_expires_at: Option<Timestamp>,
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// The answer to `POST /api/auth/users`: the new user and their
/// registration link, whose token is shown only this once.
///
/// Its JSON form is `{"entry": UserEntry, "link": Link}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct CreatedUser {
    /// The new user.
    pub entry: UserEntry,
    /// The new user's registration link.
    pub link: Link,
}

/// What the sign-in page offers, from `GET /api/auth/config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct AuthConfig {
    /// Password sign-in is offered.
    pub password: bool,
    /// Google sign-in is offered.
    pub google: bool,
    /// This request carries Cloudflare Access credentials that map to a user.
    pub cloudflare: bool,
    /// The app uses login names, not only emails.
    pub logins: bool,
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// The body of `POST /api/auth/login`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct LoginRequest {
    /// A login name or an email.
    pub login: String,
    /// The password.
    pub password: String,
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// What a registration or reset link is for, from
/// `GET /api/auth/register/{token}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct RegisterInfo {
    /// The user's login name, if any.
    pub login: Option<String>,
    /// The user's email, if any.
    pub email: Option<String>,
    /// Registering with Google is offered.
    pub google: bool,
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// The body of `POST /api/auth/register/{token}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct RegisterRequest {
    /// The new password.
    pub password: String,
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// A registration or reset link's token, shown once when issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct Link {
    /// The token, for the frontend route `/register/{token}`.
    pub token: String,
    /// When the link stops working.
    #[cfg_attr(feature = "musli01", musli(with = self::musli_timestamp))]
    pub expires_at: Timestamp,
}

#[cfg(feature = "alloc")]
impl Link {
    /// The link's path on the app, `/register/{token}`, the route the
    /// frontend registers or resets from.
    pub fn path(&self) -> String {
        format!("/register/{}", self.token)
    }

    /// The link as a full URL under `public_url`, the URL the app is reached
    /// at (with or without a trailing slash), or as [`path`](Link::path)
    /// without one.
    pub fn url(&self, public_url: Option<&str>) -> String {
        match public_url {
            Some(base) => format!("{}{}", base.trim_end_matches('/'), self.path()),
            None => self.path(),
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// A user to create. At least one of `login` and `email` is required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct NewUser {
    /// The login name.
    pub login: Option<String>,
    /// The email.
    pub email: Option<String>,
    /// The role.
    pub role: Role,
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// A change to a user. `None` leaves a field as it is; `Some(None)` clears an
/// optional one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct UserChange {
    /// The new login name.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "double_option"
    )]
    pub login: Option<Option<String>>,
    /// The new email.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "double_option"
    )]
    pub email: Option<Option<String>>,
    /// The new role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// The body of `POST /api/auth/account/password`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct PasswordChange {
    /// The current password, required when one is set.
    pub old_password: Option<String>,
    /// The new password.
    pub new_password: String,
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// The Cloudflare Access settings an app stores and edits.
///
/// The [`Default`] is the safe starting point for a settings form: sign-in
/// through Access is disabled, the email header is not trusted, and the
/// Access JWT is verified once it is enabled, so an app that fills in
/// [`enabled`], [`team_domain`] and [`audience`] on top of it checks every
/// request's token.
///
/// A field missing from its JSON takes its value from the [`Default`], so
/// settings stored or sent without [`verify_jwt`] still verify the token.
///
/// [`enabled`]: Self::enabled
/// [`verify_jwt`]: Self::verify_jwt
/// [`team_domain`]: Self::team_domain
/// [`audience`]: Self::audience
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
pub struct CloudflareConfig {
    /// Signing in through Cloudflare Access is enabled. Off by default.
    pub enabled: bool,
    /// The team's host, such as `example.cloudflareaccess.com`.
    pub team_domain: String,
    /// The Access application's audience (AUD) tag.
    pub audience: String,
    /// Accept the email header that Access sets. Off by default.
    ///
    /// Without [`verify_jwt`](Self::verify_jwt), anyone who can reach the
    /// server without going through Cloudflare can sign in as any user by
    /// sending the header, so turn this on alone only when the server is
    /// reachable through Cloudflare and nothing else.
    pub trust_email_header: bool,
    /// Require and verify the Access JWT against the team's signing keys
    /// and the audience. On by default.
    ///
    /// Turning it off leaves [`trust_email_header`](Self::trust_email_header)
    /// as the only way to sign in, with the email header taken on trust.
    pub verify_jwt: bool,
}

#[cfg(feature = "alloc")]
impl Default for CloudflareConfig {
    /// Disabled, with the email header untrusted and JWT verification on.
    fn default() -> Self {
        Self {
            enabled: false,
            team_domain: String::new(),
            audience: String::new(),
            trust_email_header: false,
            verify_jwt: true,
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// The error of an `/api/auth` route, sent as the JSON body of its 4xx
/// response, such as `{"error":"conflict","detail":"email"}` or
/// `{"error":"invalid","detail":{"reason":"password_too_short","min":8}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
#[serde(tag = "error", content = "detail", rename_all = "snake_case")]
pub enum AuthError {
    /// Not signed in, or the credentials are wrong (401).
    #[error("not signed in")]
    Unauthorized,
    /// Signed in, but not allowed (403).
    #[error("not allowed")]
    Forbidden,
    /// No such user or link (404).
    #[error("not found")]
    NotFound,
    /// The link was used or has expired (410).
    #[error("the link was used or has expired")]
    Gone,
    /// Too many sign-in attempts (429).
    #[error("too many attempts, try again later")]
    TooManyRequests,
    /// The login or email is taken (409).
    #[error("{0} is already taken")]
    Conflict(Conflict),
    /// The request is invalid, and why (400).
    #[error("{0}")]
    Invalid(Invalid),
}

#[cfg(feature = "alloc")]
impl AuthError {
    /// The HTTP status code the error is sent with.
    pub fn status(&self) -> u16 {
        match self {
            AuthError::Unauthorized => 401,
            AuthError::Forbidden => 403,
            AuthError::NotFound => 404,
            AuthError::Gone => 410,
            AuthError::TooManyRequests => 429,
            AuthError::Conflict(_) => 409,
            AuthError::Invalid(_) => 400,
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "alloc")))]
/// Why a request is invalid, the detail of [`AuthError::Invalid`].
///
/// On the wire a reason is a stable code with its parameters, such as
/// `{"reason":"password_too_short","min":8}`, so a frontend can phrase it in
/// its own language. [`Display`](fmt::Display) gives an English message for
/// the user.
///
/// New reasons may be added without a breaking release. One this version
/// does not know, sent by a newer server, decodes as [`Invalid::Unknown`],
/// so an older frontend still shows that the request was refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
#[serde(tag = "reason", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Invalid {
    /// The password is shorter than `min` bytes; see [`validate_password`].
    #[error("Must be at least {min} characters.")]
    PasswordTooShort {
        /// The shortest password accepted, [`MIN_PASSWORD_LEN`].
        min: usize,
    },
    /// The current password, given to change it, is wrong.
    #[error("The current password is incorrect.")]
    PasswordIncorrect,
    /// The app uses only emails, and the user would have none.
    #[error("An email is required.")]
    EmailRequired,
    /// The user would have neither a login nor an email.
    #[error("A login or an email is required.")]
    LoginOrEmailRequired,
    /// The login name is blank.
    #[error("The login cannot be empty.")]
    LoginEmpty,
    /// A login name was given, but the app uses only emails.
    #[error("Login names are not used.")]
    LoginsDisabled,
    /// A Google user tried to change their own email, which their Google
    /// account manages.
    #[error("Your email is managed by your Google account.")]
    EmailManagedByGoogle,
    /// The Google account is already linked to another user.
    #[error("This Google account is already linked to another user.")]
    GoogleAccountTaken,
    /// The role cannot be changed through this route, such as on the user's
    /// own account.
    #[error("The role cannot be changed here.")]
    RoleNotChangeable,
    /// The request body could not be read, such as malformed JSON or a
    /// missing field.
    #[error("The request is malformed.")]
    MalformedRequest,
    /// A reason this version does not know, from a newer server; its
    /// parameters are dropped. A server never sends it.
    ///
    /// New reasons go after it, at the end, since musli numbers variants by
    /// position.
    #[error("The request is invalid.")]
    #[serde(other)]
    #[cfg_attr(feature = "musli01", musli(default))]
    Unknown,
}

/// Which unique field a change conflicts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "musli01", derive(Encode, Decode))]
#[cfg_attr(feature = "musli01", musli(crate = musli_core01))]
#[serde(rename_all = "lowercase")]
pub enum Conflict {
    /// The login name is taken.
    Login,
    /// The email is taken.
    Email,
}

impl fmt::Display for Conflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Conflict::Login => f.write_str("login"),
            Conflict::Email => f.write_str("email"),
        }
    }
}

#[cfg(feature = "alloc")]
/// Serde for `Option<Option<T>>`, so that an absent field is `None` and an
/// explicit `null` is `Some(None)`.
mod double_option {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T, S>(value: &Option<Option<T>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize,
        S: Serializer,
    {
        match value {
            Some(inner) => inner.serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        T: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Some)
    }
}

/// musli for [`Timestamp`], as its RFC 3339 string, the same form as its serde
/// encoding.
#[cfg(all(feature = "musli01", feature = "alloc"))]
mod musli_timestamp {
    use jiff::Timestamp;
    use musli_core01::{Context, Decoder, Encoder};

    pub fn encode<E>(value: &Timestamp, encoder: E) -> Result<(), E::Error>
    where
        E: Encoder,
    {
        encoder.collect_string(value)
    }

    pub fn decode<'de, D>(decoder: D) -> Result<Timestamp, D::Error>
    where
        D: Decoder<'de>,
    {
        let cx = decoder.cx();
        decoder.decode_unsized(|s: &str| s.parse::<Timestamp>().map_err(|error| cx.message(error)))
    }

    pub mod option {
        use jiff::Timestamp;
        use musli_core01::{Decoder, Encoder};

        pub fn encode<E>(value: &Option<Timestamp>, encoder: E) -> Result<(), E::Error>
        where
            E: Encoder,
        {
            match value {
                Some(value) => super::encode(value, encoder.encode_some()?),
                None => encoder.encode_none(),
            }
        }

        pub fn decode<'de, D>(decoder: D) -> Result<Option<Timestamp>, D::Error>
        where
            D: Decoder<'de>,
        {
            match decoder.decode_option()? {
                Some(decoder) => super::decode(decoder).map(Some),
                None => Ok(None),
            }
        }
    }
}
