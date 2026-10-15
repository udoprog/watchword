//! Types shared by the server and the frontend: identities, roles, account
//! state, the JSON wire types of the `/api/auth` routes, [`AuthError`], and
//! input validation.
//!
//! This module is always available and is safe to build for
//! `wasm32-unknown-unknown`. With the `musli` feature, the wire types also
//! implement musli's `Encode` and `Decode`, so an app can embed them in its own
//! WebSocket messages.

use std::fmt;
use std::str::FromStr;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[cfg(feature = "musli")]
use musli_core::{Decode, Encode};

#[cfg(test)]
mod tests;

/// The shortest password [`validate_password`] accepts, in bytes.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Returns a message for the user when the password is not acceptable.
pub fn validate_password(password: &str) -> Option<&'static str> {
    if password.len() < MIN_PASSWORD_LEN {
        return Some("Must be at least 8 characters.");
    }

    None
}

/// Trims and lowercases an email so lookups and comparisons are
/// case-insensitive.
pub fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// A user's id. Apps convert to and from their own `u64` ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core, transparent))]
#[serde(transparent)]
pub struct UserId(pub u64);

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

        impl std::error::Error for $error {}

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
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
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
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
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
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
#[serde(rename_all = "lowercase")]
pub enum Method {
    /// A password (which a pending user may not have set yet).
    Password,
    /// A bound Google account.
    Google,
}

names!(Method, UnknownMethod, "sign-in method", Password => "password", Google => "google");

/// What the frontend and the admin pages see of a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
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
    #[cfg_attr(feature = "musli", musli(with = self::musli_timestamp))]
    pub created_at: Timestamp,
    /// The admin acting as this user, when this is the signed-in user of a
    /// session an admin created by impersonating them. Only the answers about
    /// the request's own user (`GET /api/auth/me`, sign-in, impersonation and
    /// the account routes) set it; it is absent from JSON when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonated_by: Option<Impersonator>,
}

/// The admin behind an impersonated session; see
/// [`UserInfo::impersonated_by`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct Impersonator {
    /// The admin's id.
    pub id: UserId,
    /// The admin's name to show, as [`UserInfo::name`] gives it.
    pub name: String,
}

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

/// A user in the admin list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct UserEntry {
    /// The user.
    pub user: UserInfo,
    /// When the user's live registration or reset link expires, if there is
    /// one.
    #[cfg_attr(feature = "musli", musli(with = self::musli_timestamp::option))]
    pub link_expires_at: Option<Timestamp>,
}

/// The answer to `POST /api/auth/users`: the new user and their
/// registration link, whose token is shown only this once.
///
/// Its JSON form is `{"entry": UserEntry, "link": Link}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct CreatedUser {
    /// The new user.
    pub entry: UserEntry,
    /// The new user's registration link.
    pub link: Link,
}

/// What the sign-in page offers, from `GET /api/auth/config`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
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

/// The body of `POST /api/auth/login`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct LoginRequest {
    /// A login name or an email.
    pub login: String,
    /// The password.
    pub password: String,
}

/// What a registration or reset link is for, from
/// `GET /api/auth/register/{token}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct RegisterInfo {
    /// The user's login name, if any.
    pub login: Option<String>,
    /// The user's email, if any.
    pub email: Option<String>,
    /// Registering with Google is offered.
    pub google: bool,
}

/// The body of `POST /api/auth/register/{token}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct RegisterRequest {
    /// The new password.
    pub password: String,
}

/// A registration or reset link's token, shown once when issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct Link {
    /// The token, for the frontend route `/register/{token}`.
    pub token: String,
    /// When the link stops working.
    #[cfg_attr(feature = "musli", musli(with = self::musli_timestamp))]
    pub expires_at: Timestamp,
}

/// A user to create. At least one of `login` and `email` is required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct NewUser {
    /// The login name.
    pub login: Option<String>,
    /// The email.
    pub email: Option<String>,
    /// The role.
    pub role: Role,
}

/// A change to a user. `None` leaves a field as it is; `Some(None)` clears an
/// optional one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
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

/// The body of `POST /api/auth/account/password`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct PasswordChange {
    /// The current password, required when one is set.
    pub old_password: Option<String>,
    /// The new password.
    pub new_password: String,
}

/// The Cloudflare Access settings an app stores and edits.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
pub struct CloudflareConfig {
    /// Signing in through Cloudflare Access is enabled.
    pub enabled: bool,
    /// The team's host, such as `example.cloudflareaccess.com`.
    pub team_domain: String,
    /// The Access application's audience (AUD) tag.
    pub audience: String,
    /// Accept the email header that Access sets.
    pub trust_email_header: bool,
    /// Require and verify the Access JWT.
    pub verify_jwt: bool,
}

/// The error of an `/api/auth` route, sent as the JSON body of its 4xx
/// response, such as `{"error":"conflict","detail":"email"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
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
    /// The request is invalid, with a message for the user (400).
    #[error("{0}")]
    Invalid(String),
}

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

/// Which unique field a change conflicts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "musli", derive(Encode, Decode))]
#[cfg_attr(feature = "musli", musli(crate = musli_core))]
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
#[cfg(feature = "musli")]
mod musli_timestamp {
    use jiff::Timestamp;
    use musli_core::{Context, Decoder, Encoder};

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
        decoder.decode_unsized(|s: &str| s.parse::<Timestamp>().map_err(cx.map()))
    }

    pub mod option {
        use jiff::Timestamp;
        use musli_core::{Decoder, Encoder};

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
