//! Storage of users, sessions, link tokens and settings: the [`Store`] trait,
//! the records it stores, and [`MemoryStore`].
//!
//! Needs the `server` feature. watchword ships no database storage: each app
//! implements [`Store`] over its own database, with its own tables and
//! migrations, and maps its rows into the records here ([`User`],
//! [`Session`], [`Token`]). [`Auth`](crate::core::Auth) enforces every rule;
//! a store only keeps the records and makes the documented multi-record
//! changes atomic.
//!
//! # Writing a store
//!
//! Start from [`examples/sqll-store`], a complete store over SQLite with sqll
//! 0.15 (a pool, `sqll::Migrations` and the app's own tables), and change the
//! tables to the app's. [`MemoryStore`] is the reference for what each method
//! does. Then check the store with the conformance suite,
//! [`store_suite!`](crate::store_suite) (feature `test-util`), in the app's
//! tests: it defines one `#[test]` per rule of `Auth` that depends on what a
//! store keeps, each over a fresh store, so a store that passes it is one
//! `Auth` works with.
//!
//! ```ignore
//! #[cfg(test)]
//! mod store_tests {
//!     // A fresh, empty store per test, such as one over a new database in
//!     // a temporary directory.
//!     watchword::store_suite!(crate::AppStore::open_scratch().await?);
//! }
//! ```
//!
//! `Auth` calls a store from many tasks at once, and
//! [`prune_every`](crate::AuthBuilder::prune_every) writes while
//! requests read, so the suite does too: a store must let a write run beside
//! reads, waiting rather than failing on a lock. Over SQLite that is a
//! database file in WAL mode with a busy timeout, as in
//! [`examples/sqll-store`], and not a shared-cache in-memory database, where
//! a write beside a read fails with `SQLITE_LOCKED`.
//!
//! Every method takes the current time from the caller, which keeps tests
//! deterministic. Emails are passed in already normalized (see
//! [`normalize_email`](crate::normalize_email)) and compared exactly. A store
//! keeps times with at least millisecond precision.
//!
//! [`examples/sqll-store`]: https://github.com/udoprog/watchword/tree/main/examples/sqll-store

use std::boxed::Box;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::string::String;
use std::vec::Vec;

use jiff::Timestamp;

use crate::types::{Access, Conflict, Method, NewUser, Role, UserChange, UserId, UserInfo};

mod memory;

// The store conformance suite, run through `store_suite!`; its functions are
// public only for the macro.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod suite;

pub use self::memory::MemoryStore;

/// The result of a [`Store`] operation.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// A storage failure, such as a database error. [`Auth`](crate::core::Auth)
/// passes it on as an internal error rather than a response to the user.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct StoreError(Box<dyn StdError + Send + Sync>);

impl StoreError {
    /// Wraps any error, or a message.
    pub fn new(error: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        Self(error.into())
    }
}

/// A stored user, as the store maps it from its own record. A store may keep
/// more about a user (the app's own columns); `Auth` needs only these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// The user's id, assigned by the store.
    pub id: UserId,
    /// The unique login name, if any.
    pub login: Option<String>,
    /// The unique, normalized email, if any.
    pub email: Option<String>,
    /// The user's role.
    pub role: Role,
    /// The user's account state.
    pub access: Access,
    /// The user's stored credential: which of
    /// [`password_hash`](User::password_hash) and
    /// [`google_sub`](User::google_sub) signs them in.
    pub method: Method,
    /// The bcrypt hash of the password, when the method is
    /// [`Method::Password`] and one is set.
    pub password_hash: Option<String>,
    /// The bound Google account's subject, when the method is
    /// [`Method::Google`] and one is bound.
    pub google_sub: Option<String>,
    /// When the user was created, as the admin pages show it.
    pub created_at: Timestamp,
}

impl User {
    /// What the frontend sees of the user.
    pub fn info(&self) -> UserInfo {
        UserInfo {
            id: self.id,
            login: self.login.clone(),
            email: self.email.clone(),
            role: self.role,
            access: self.access,
            method: self.method,
            has_password: self.password_hash.is_some(),
            created_at: self.created_at,
            impersonated_by: None,
        }
    }

    /// Whether the user is an admin.
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

impl From<&User> for UserInfo {
    #[inline]
    fn from(user: &User) -> Self {
        user.info()
    }
}

/// A signed-in session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The session id, as carried in the signed cookie.
    pub id: String,
    /// The signed-in user.
    pub user: UserId,
    /// The admin acting as [`user`](Session::user), when the session was
    /// created by impersonation.
    pub impersonator: Option<UserId>,
    /// When the session was created. [`Store::create_session`] may prune
    /// the sessions that expired by then.
    pub created_at: Timestamp,
    /// When the session expires. `Auth` refuses an expired session itself, so
    /// a store need not filter them out.
    pub expires_at: Timestamp,
}

#[cfg(any(test, feature = "test-util"))]
impl Session {
    /// A session for `user` that is not stored, for operations that take
    /// the actor's session only to attribute their audit events.
    pub(crate) fn unstored(user: &User) -> Self {
        let now = Timestamp::now();

        Self {
            id: "unstored".into(),
            user: user.id,
            impersonator: None,
            created_at: now,
            expires_at: now,
        }
    }
}

/// A registration or reset link's token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The token, as carried in the link.
    pub id: String,
    /// The user the link was issued to.
    pub user: UserId,
    /// What the link was issued for.
    pub kind: TokenKind,
    /// When the link stops working.
    pub expires_at: Timestamp,
    /// When the link was used, or used up by a newer link or a revocation.
    pub used_at: Option<Timestamp>,
}

/// What a link was issued for, decided by the user's access when issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// Issued to a pending or revoked user. It stops working once the user is
    /// active, so a leftover link cannot take over a registered account.
    Registration,
    /// Issued to an active user, to reset their credential.
    Reset,
}

impl TokenKind {
    /// The kind's name, `registration` or `reset`, to store it as. It parses
    /// back with [`str::parse`].
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Registration => "registration",
            TokenKind::Reset => "reset",
        }
    }
}

impl fmt::Display for TokenKind {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error parsing an unknown [`TokenKind`] name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown link kind")]
pub struct UnknownTokenKind;

impl FromStr for TokenKind {
    type Err = UnknownTokenKind;

    /// Parses a name from [`TokenKind::as_str`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "registration" => Ok(TokenKind::Registration),
            "reset" => Ok(TokenKind::Reset),
            _ => Err(UnknownTokenKind),
        }
    }
}

/// A credential to store for a user. Storing one replaces the other kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// A bcrypt password hash. Clears any bound Google account.
    Password(String),
    /// A verified Google account: its subject, bound to the user, and its
    /// normalized email, which becomes the user's. Clears the password.
    Google {
        /// The Google account's stable subject.
        sub: String,
        /// The account's verified, normalized email.
        email: String,
    },
}

/// Storage for users, sessions, link tokens and settings, implemented by each
/// app over its own database. See [writing a store](self#writing-a-store).
///
/// The methods are `async fn`s whose futures are `Send`; implement them with
/// `async fn`. Every method that writes must be atomic: its reads and writes
/// happen in one transaction (or under one lock), so another call cannot land
/// in between and none of its changes are seen without the others. Each
/// method's documentation says which checks must happen inside it; a store
/// that checks first and writes in a separate step lets a concurrent
/// revocation, or a second use of a link, slip through.
///
/// Uniqueness of logins, emails and Google subjects is the store's to keep:
/// [`create_user`](Store::create_user) and
/// [`update_user`](Store::update_user) report a taken login or email as a
/// [`Conflict`], and any other violation is an error.
///
/// Deleting a user deletes everything that refers to them, as
/// [`delete_user`](Store::delete_user) says; the store does that itself or
/// through its database's cascades.
pub trait Store: Send + Sync + 'static {
    /// The user with `id`.
    fn user(&self, id: UserId) -> impl Future<Output = Result<Option<User>>> + Send;

    /// The user with the normalized `email`.
    fn user_by_email(&self, email: &str) -> impl Future<Output = Result<Option<User>>> + Send;

    /// The user with the login name `login`.
    fn user_by_login(&self, login: &str) -> impl Future<Output = Result<Option<User>>> + Send;

    /// The user bound to the Google account with the subject `sub`.
    fn user_by_google_sub(&self, sub: &str) -> impl Future<Output = Result<Option<User>>> + Send;

    /// Every user, ordered by id, each with the expiry of their live link: an
    /// unused token that has not expired at `now`.
    fn users(
        &self,
        now: Timestamp,
    ) -> impl Future<Output = Result<Vec<(User, Option<Timestamp>)>>> + Send;

    /// How many users there are.
    fn user_count(&self) -> impl Future<Output = Result<u64>> + Send;

    /// Creates a pending user with no credential and [`Method::Password`],
    /// assigning a new id. The login and email are already validated and
    /// normalized.
    ///
    /// Atomically: returns the [`Conflict`], and creates nothing, when another
    /// user has the login or the email.
    fn create_user(
        &self,
        new: &NewUser,
        now: Timestamp,
    ) -> impl Future<Output = Result<Result<User, Conflict>>> + Send;

    /// Applies `change` to the user, returning `None` if there is no such
    /// user. The change is already validated and normalized.
    ///
    /// Atomically: returns the [`Conflict`], and changes nothing, when
    /// another user has the new login or email.
    fn update_user(
        &self,
        id: UserId,
        change: &UserChange,
    ) -> impl Future<Output = Result<Result<Option<User>, Conflict>>> + Send;

    /// In one transaction: deletes the user with their sessions and tokens,
    /// and the sessions in which they impersonate someone
    /// ([`Session::impersonator`]). Returns whether the user existed.
    fn delete_user(&self, id: UserId) -> impl Future<Output = Result<bool>> + Send;

    /// In one transaction: sets the credential (setting
    /// [`User::method`] to match), marks the user active, and deletes the
    /// user's sessions except `keep`. Returns whether it did: `false`, with
    /// nothing changed, when there is no such user or the user is revoked,
    /// so that a revocation that lands after the caller read the user is
    /// not undone.
    fn set_credential(
        &self,
        id: UserId,
        cred: &Credential,
        keep: Option<&str>,
    ) -> impl Future<Output = Result<bool>> + Send;

    /// Binds the Google subject `sub` to the user only if the user has none
    /// or the same one, and no other user has `sub`, as one atomic check and
    /// change. Returns whether `sub` is bound to the user afterwards: `false`
    /// when there is no such user, or either is bound elsewhere.
    fn bind_google_sub(&self, id: UserId, sub: &str) -> impl Future<Output = Result<bool>> + Send;

    /// Sets the user's access. Returns whether the user existed.
    fn set_access(&self, id: UserId, access: Access) -> impl Future<Output = Result<bool>> + Send;

    /// Sets the user's access to active only if it is pending, as one atomic
    /// change. Returns whether it changed: `false`, with nothing changed,
    /// when there is no such user or the user is not pending, such as one
    /// revoked after the caller read them.
    fn activate(&self, id: UserId) -> impl Future<Output = Result<bool>> + Send;

    /// In one transaction: sets access to revoked, clears the password, uses
    /// up the user's unused tokens at `now` and deletes their sessions.
    /// Returns whether the user existed.
    fn revoke(&self, id: UserId, now: Timestamp) -> impl Future<Output = Result<bool>> + Send;

    /// Inserts a session, whose id is new. May also delete sessions that
    /// expired by `session.created_at`.
    fn create_session(&self, session: &Session) -> impl Future<Output = Result<()>> + Send;

    /// The session with `id`, expired or not.
    fn session(&self, id: &str) -> impl Future<Output = Result<Option<Session>>> + Send;

    /// Deletes the session with `id`, if there is one.
    fn delete_session(&self, id: &str) -> impl Future<Output = Result<()>> + Send;

    /// Deletes the user's sessions except `keep`.
    fn delete_sessions(
        &self,
        user: UserId,
        keep: Option<&str>,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Deletes every session that expired by `now`.
    fn delete_expired_sessions(&self, now: Timestamp) -> impl Future<Output = Result<()>> + Send;

    /// In one transaction: uses up the user's other unused tokens at `now`
    /// and inserts the token, whose id is new, so a user has at most one live
    /// link.
    fn create_token(
        &self,
        token: &Token,
        now: Timestamp,
    ) -> impl Future<Output = Result<()>> + Send;

    /// The token with `id`, used or not.
    fn token(&self, id: &str) -> impl Future<Output = Result<Option<Token>>> + Send;

    /// Deletes every token, used or not, that expired by `before`.
    fn delete_expired_tokens(&self, before: Timestamp) -> impl Future<Output = Result<()>> + Send;

    /// Marks the user's unused tokens used at `now`.
    fn use_up_tokens(
        &self,
        user: UserId,
        now: Timestamp,
    ) -> impl Future<Output = Result<()>> + Send;

    /// In one transaction: marks the token used at `now` if it is still
    /// unused (otherwise returns `false` and changes nothing), sets the
    /// token's user's credential and marks them active as
    /// [`set_credential`](Store::set_credential) does, whatever their access
    /// (a registration link re-registers a revoked user), deletes all of the
    /// user's sessions and creates `session`. Returns `false`, changing
    /// nothing, when there is no such token or user.
    fn redeem_token(
        &self,
        token: &str,
        cred: &Credential,
        session: &Session,
        now: Timestamp,
    ) -> impl Future<Output = Result<bool>> + Send;

    /// The setting `key`, such as `session_key`, or `cloudflare`, the Cloudflare
    /// Access settings as JSON (feature `cloudflare`).
    fn config_get(&self, key: &str) -> impl Future<Output = Result<Option<String>>> + Send;

    /// Stores the setting `key`.
    fn config_set(&self, key: &str, value: &str) -> impl Future<Output = Result<()>> + Send;
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// The part of [`Store`] that [`Auth`](crate::core::Auth) uses, with boxed
/// futures, so that `Auth` can hold any store behind one pointer without a type parameter.
pub(crate) trait DynStore: Send + Sync + 'static {
    fn user(&self, id: UserId) -> BoxFuture<'_, Option<User>>;
    fn user_by_email<'a>(&'a self, email: &'a str) -> BoxFuture<'a, Option<User>>;
    fn user_by_login<'a>(&'a self, login: &'a str) -> BoxFuture<'a, Option<User>>;
    // Used by the Google sign-in paths.
    #[cfg_attr(not(test), allow(dead_code))]
    fn user_by_google_sub<'a>(&'a self, sub: &'a str) -> BoxFuture<'a, Option<User>>;
    fn users(&self, now: Timestamp) -> BoxFuture<'_, Vec<(User, Option<Timestamp>)>>;
    fn user_count(&self) -> BoxFuture<'_, u64>;
    fn create_user<'a>(
        &'a self,
        new: &'a NewUser,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<User, Conflict>>;
    fn update_user<'a>(
        &'a self,
        id: UserId,
        change: &'a UserChange,
    ) -> BoxFuture<'a, Result<Option<User>, Conflict>>;
    fn delete_user(&self, id: UserId) -> BoxFuture<'_, bool>;
    fn set_credential<'a>(
        &'a self,
        id: UserId,
        cred: &'a Credential,
        keep: Option<&'a str>,
    ) -> BoxFuture<'a, bool>;
    // Used by the Google sign-in paths.
    #[cfg_attr(not(test), allow(dead_code))]
    fn bind_google_sub<'a>(&'a self, id: UserId, sub: &'a str) -> BoxFuture<'a, bool>;
    // Used by Cloudflare Access sign-in, which activates pending users.
    #[cfg_attr(not(feature = "cloudflare"), allow(dead_code))]
    fn activate(&self, id: UserId) -> BoxFuture<'_, bool>;
    fn revoke(&self, id: UserId, now: Timestamp) -> BoxFuture<'_, bool>;
    fn create_session<'a>(&'a self, session: &'a Session) -> BoxFuture<'a, ()>;
    fn session<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Option<Session>>;
    fn delete_session<'a>(&'a self, id: &'a str) -> BoxFuture<'a, ()>;
    fn delete_sessions<'a>(&'a self, user: UserId, keep: Option<&'a str>) -> BoxFuture<'a, ()>;
    fn delete_expired_sessions(&self, now: Timestamp) -> BoxFuture<'_, ()>;
    fn create_token<'a>(&'a self, token: &'a Token, now: Timestamp) -> BoxFuture<'a, ()>;
    fn token<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Option<Token>>;
    fn delete_expired_tokens(&self, before: Timestamp) -> BoxFuture<'_, ()>;
    fn use_up_tokens(&self, user: UserId, now: Timestamp) -> BoxFuture<'_, ()>;
    fn redeem_token<'a>(
        &'a self,
        token: &'a str,
        cred: &'a Credential,
        session: &'a Session,
        now: Timestamp,
    ) -> BoxFuture<'a, bool>;
    // Used by the Cloudflare Access settings, which `Auth` stores. Named
    // apart from `Store::config_get` and `config_set`, which a test with
    // both traits in scope would otherwise find twice.
    #[cfg_attr(not(feature = "cloudflare"), allow(dead_code))]
    fn setting<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Option<String>>;
    #[cfg_attr(not(feature = "cloudflare"), allow(dead_code))]
    fn set_setting<'a>(&'a self, key: &'a str, value: &'a str) -> BoxFuture<'a, ()>;
}

impl<S> DynStore for S
where
    S: Store,
{
    fn user(&self, id: UserId) -> BoxFuture<'_, Option<User>> {
        Box::pin(Store::user(self, id))
    }

    fn user_by_email<'a>(&'a self, email: &'a str) -> BoxFuture<'a, Option<User>> {
        Box::pin(Store::user_by_email(self, email))
    }

    fn user_by_login<'a>(&'a self, login: &'a str) -> BoxFuture<'a, Option<User>> {
        Box::pin(Store::user_by_login(self, login))
    }

    fn user_by_google_sub<'a>(&'a self, sub: &'a str) -> BoxFuture<'a, Option<User>> {
        Box::pin(Store::user_by_google_sub(self, sub))
    }

    fn users(&self, now: Timestamp) -> BoxFuture<'_, Vec<(User, Option<Timestamp>)>> {
        Box::pin(Store::users(self, now))
    }

    fn user_count(&self) -> BoxFuture<'_, u64> {
        Box::pin(Store::user_count(self))
    }

    fn create_user<'a>(
        &'a self,
        new: &'a NewUser,
        now: Timestamp,
    ) -> BoxFuture<'a, Result<User, Conflict>> {
        Box::pin(Store::create_user(self, new, now))
    }

    fn update_user<'a>(
        &'a self,
        id: UserId,
        change: &'a UserChange,
    ) -> BoxFuture<'a, Result<Option<User>, Conflict>> {
        Box::pin(Store::update_user(self, id, change))
    }

    fn delete_user(&self, id: UserId) -> BoxFuture<'_, bool> {
        Box::pin(Store::delete_user(self, id))
    }

    fn set_credential<'a>(
        &'a self,
        id: UserId,
        cred: &'a Credential,
        keep: Option<&'a str>,
    ) -> BoxFuture<'a, bool> {
        Box::pin(Store::set_credential(self, id, cred, keep))
    }

    fn bind_google_sub<'a>(&'a self, id: UserId, sub: &'a str) -> BoxFuture<'a, bool> {
        Box::pin(Store::bind_google_sub(self, id, sub))
    }

    fn activate(&self, id: UserId) -> BoxFuture<'_, bool> {
        Box::pin(Store::activate(self, id))
    }

    fn revoke(&self, id: UserId, now: Timestamp) -> BoxFuture<'_, bool> {
        Box::pin(Store::revoke(self, id, now))
    }

    fn create_session<'a>(&'a self, session: &'a Session) -> BoxFuture<'a, ()> {
        Box::pin(Store::create_session(self, session))
    }

    fn session<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Option<Session>> {
        Box::pin(Store::session(self, id))
    }

    fn delete_session<'a>(&'a self, id: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(Store::delete_session(self, id))
    }

    fn delete_sessions<'a>(&'a self, user: UserId, keep: Option<&'a str>) -> BoxFuture<'a, ()> {
        Box::pin(Store::delete_sessions(self, user, keep))
    }

    fn delete_expired_sessions(&self, now: Timestamp) -> BoxFuture<'_, ()> {
        Box::pin(Store::delete_expired_sessions(self, now))
    }

    fn create_token<'a>(&'a self, token: &'a Token, now: Timestamp) -> BoxFuture<'a, ()> {
        Box::pin(Store::create_token(self, token, now))
    }

    fn token<'a>(&'a self, id: &'a str) -> BoxFuture<'a, Option<Token>> {
        Box::pin(Store::token(self, id))
    }

    fn delete_expired_tokens(&self, before: Timestamp) -> BoxFuture<'_, ()> {
        Box::pin(Store::delete_expired_tokens(self, before))
    }

    fn use_up_tokens(&self, user: UserId, now: Timestamp) -> BoxFuture<'_, ()> {
        Box::pin(Store::use_up_tokens(self, user, now))
    }

    fn redeem_token<'a>(
        &'a self,
        token: &'a str,
        cred: &'a Credential,
        session: &'a Session,
        now: Timestamp,
    ) -> BoxFuture<'a, bool> {
        Box::pin(Store::redeem_token(self, token, cred, session, now))
    }

    fn setting<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Option<String>> {
        Box::pin(Store::config_get(self, key))
    }

    fn set_setting<'a>(&'a self, key: &'a str, value: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(Store::config_set(self, key, value))
    }
}
