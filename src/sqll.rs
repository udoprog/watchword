//! [`SqllStore`], a [`Store`] over SQLite through [sqll] 0.14 (the `sqll`
//! feature).
//!
//! The store works over four tables with a fixed set of columns, created by
//! [`SCHEMA`] in a new database:
//!
//! ```sql
#![doc = include_str!("sqll/schema.sql")]
//! ```
//!
//! An app keeps its own columns on `users` (with defaults, since the store
//! inserts only its own) and its own tables referencing `users (id)`. The
//! store reads and writes only the columns above, and deletes a user's
//! sessions and links itself, so it does not rely on `ON DELETE CASCADE`;
//! the app's own tables cascade only if its connections enable foreign keys.
//!
//! # Sharing the app's pool
//!
//! The store runs its statements on a [`sqll::Pool`]. An app with its own
//! pool nests [`Read`] and [`Write`] in its statement collections and gives
//! the store access to them through [`AsMut`], so that auth and the app share
//! one write connection:
//!
//! ```ignore
//! #[derive(Statements)]
//! #[sql(read_only)]
//! struct AppRead {
//!     #[sql(statements)]
//!     auth: auth::sqll::Read,
//!     // the app's own statements
//! }
//!
//! impl AsMut<auth::sqll::Read> for AppRead {
//!     fn as_mut(&mut self) -> &mut auth::sqll::Read {
//!         &mut self.auth
//!     }
//! }
//!
//! // ...and the same for `AppWrite` with `auth::sqll::Write`.
//!
//! let pool: Arc<Pool<AppRead, AppWrite>> = /* the app's pool */;
//! let store = SqllStore::new(pool.clone());
//! ```
//!
//! A store over its own pool is a `SqllStore` (that is,
//! `SqllStore<Read, Write>`) over a `Pool<Read, Write>`.
//!
//! The pool's statements are prepared when it opens, so the schema must be in
//! place by then: run [`SCHEMA`] (or an app's migration) first.
//!
//! # Migrating track and territory
//!
//! Each app moves its existing auth tables onto this schema once, with the
//! migration in `docs/sqll/track.sql` or `docs/sqll/territory.sql` of this
//! repository, added to the app's own migrations:
//!
//! - track: `users.login` becomes optional (a table rebuild, which needs
//!   foreign keys off, as track's migration connection has them), every user
//!   becomes `active` with the `password` method, and `login_tokens` becomes
//!   `auth_tokens`, its links becoming `reset` links.
//! - territory: `users` gains an optional unique `login`, `auth_method`
//!   becomes `method` (`plain` becomes `password`), `registration_tokens`
//!   becomes `auth_tokens`, and every auth timestamp goes from RFC 3339 TEXT
//!   to INTEGER milliseconds.
//!
//! Both also give `sessions` the `impersonator_id` column.
//!
//! # Upgrading a database made with an earlier schema
//!
//! A database created with [`SCHEMA`] before sessions recorded the admin
//! behind an impersonation lacks `sessions.impersonator_id`, and the store's
//! statements fail to prepare on it. Add the column once with
//! `docs/sqll/impersonator.sql` (a single `ALTER TABLE`) in the app's
//! migrations. Running [`SCHEMA`] again does not add it.

use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;

use jiff::Timestamp;
use sqll::{IsReadOnly, Pool, Row, Statements};
use tokio::task::spawn_blocking;

use crate::store::{Credential, Result, Session, Store, StoreError, Token, TokenKind, User};
use crate::types::{Access, Conflict, Method, NewUser, Role, UserChange, UserId};

#[cfg(test)]
mod tests;

/// The SQL that creates the store's tables in a new database. Every statement
/// is `IF NOT EXISTS`, so running it again changes nothing.
pub const SCHEMA: &str = include_str!("sqll/schema.sql");

/// A [`Store`] over SQLite, on a [`sqll::Pool`] whose read and write
/// statement collections contain [`Read`] and [`Write`]. See the [module
/// documentation](self) for the schema and for sharing an app's pool.
///
/// Clones share the same pool.
pub struct SqllStore<R = Read, W = Write> {
    pool: Arc<Pool<R, W>>,
}

impl<R, W> Clone for SqllStore<R, W> {
    #[inline]
    fn clone(&self) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
        }
    }
}

impl<R, W> SqllStore<R, W>
where
    R: IsReadOnly + AsMut<Read> + Send + 'static,
    W: Statements + AsMut<Write> + Send + 'static,
{
    /// A store over `pool`, whose database already has the store's tables.
    pub fn new(pool: Arc<Pool<R, W>>) -> Self {
        Self { pool }
    }

    /// Runs `f` on a read connection.
    async fn read<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Read) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let mut guard = self.pool.clone().shared().await.map_err(StoreError::new)?;
        spawn_blocking(move || f(guard.as_mut()))
            .await
            .map_err(StoreError::new)?
    }

    /// Runs `f` on the write connection in one transaction, which commits
    /// when `f` returns `Ok` and rolls back otherwise.
    async fn write<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Write) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let mut guard = self
            .pool
            .clone()
            .exclusive()
            .await
            .map_err(StoreError::new)?;
        spawn_blocking(move || guard.as_mut().transaction(f))
            .await
            .map_err(StoreError::new)?
    }
}

/// The statement collections, apart because the code `Statements` derives
/// trips `clippy::redundant_field_names`.
mod statements {
    #![allow(clippy::redundant_field_names)]

    use sqll::{Statements, TypedStatement};

    use super::{SessionRow, TokenRow, UserLinkRow, UserRow};

    /// The store's read statements, to nest in an app's read-only statement
    /// collection with `#[sql(statements)]`.
    #[derive(Statements)]
    #[sql(read_only)]
    pub struct Read {
        #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
        #[sql = "FROM users WHERE id = ?"]
        pub(super) user: TypedStatement<(i64,), UserRow>,
        #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
        #[sql = "FROM users WHERE email = ?"]
        pub(super) user_by_email: TypedStatement<(String,), UserRow>,
        #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
        #[sql = "FROM users WHERE login = ?"]
        pub(super) user_by_login: TypedStatement<(String,), UserRow>,
        #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
        #[sql = "FROM users WHERE google_sub = ?"]
        pub(super) user_by_google_sub: TypedStatement<(String,), UserRow>,
        #[sql = "SELECT u.id, u.login, u.email, u.role, u.access, u.method, u.password_hash,"]
        #[sql = "u.google_sub, u.created_at,"]
        #[sql = "(SELECT MAX(t.expires_at) FROM auth_tokens t"]
        #[sql = " WHERE t.user_id = u.id AND t.used_at IS NULL AND t.expires_at > ?) AS link"]
        #[sql = "FROM users u ORDER BY u.id"]
        pub(super) users: TypedStatement<(i64,), UserLinkRow>,
        #[sql = "SELECT COUNT(*) FROM users"]
        pub(super) user_count: TypedStatement<(), i64>,
        #[sql = "SELECT id, user_id, impersonator_id, created_at, expires_at FROM sessions WHERE id = ?"]
        pub(super) session: TypedStatement<(String,), SessionRow>,
        #[sql = "SELECT id, user_id, kind, expires_at, used_at FROM auth_tokens WHERE id = ?"]
        pub(super) token: TypedStatement<(String,), TokenRow>,
        #[sql = "SELECT value FROM config WHERE key = ?"]
        pub(super) config: TypedStatement<(String,), String>,
    }

    /// The store's write statements, to nest in an app's write statement
    /// collection with `#[sql(statements)]`. They include [`Read`].
    #[derive(Statements)]
    pub struct Write {
        #[sql(statements)]
        pub(super) read: Read,

        #[sql = "BEGIN IMMEDIATE"]
        pub(super) begin: TypedStatement<(), ()>,
        #[sql = "COMMIT"]
        pub(super) commit: TypedStatement<(), ()>,
        #[sql = "ROLLBACK"]
        pub(super) rollback: TypedStatement<(), ()>,

        #[sql = "INSERT INTO users (login, email, role, access, method, created_at)"]
        #[sql = "VALUES (?, ?, ?, 'pending', 'password', ?) RETURNING id"]
        pub(super) insert_user: TypedStatement<(Option<String>, Option<String>, String, i64), i64>,
        #[sql = "UPDATE users SET login = ? WHERE id = ?"]
        pub(super) set_login: TypedStatement<(Option<String>, i64), ()>,
        #[sql = "UPDATE users SET email = ? WHERE id = ?"]
        pub(super) set_email: TypedStatement<(Option<String>, i64), ()>,
        #[sql = "UPDATE users SET role = ? WHERE id = ?"]
        pub(super) set_role: TypedStatement<(String, i64), ()>,
        #[sql = "DELETE FROM users WHERE id = ? RETURNING id"]
        pub(super) delete_user: TypedStatement<(i64,), i64>,
        #[sql = "UPDATE users SET method = 'password', password_hash = ?, google_sub = NULL,"]
        #[sql = "access = 'active' WHERE id = ? RETURNING id"]
        pub(super) set_password: TypedStatement<(String, i64), i64>,
        #[sql = "UPDATE users SET method = 'google', password_hash = NULL, google_sub = ?,"]
        #[sql = "email = ?, access = 'active' WHERE id = ? RETURNING id"]
        pub(super) set_google: TypedStatement<(String, String, i64), i64>,
        #[sql = "UPDATE users SET google_sub = ? WHERE id = ?"]
        pub(super) set_google_sub: TypedStatement<(String, i64), ()>,
        #[sql = "UPDATE users SET access = ? WHERE id = ? RETURNING id"]
        pub(super) set_access: TypedStatement<(String, i64), i64>,
        #[sql = "UPDATE users SET access = 'active' WHERE id = ? AND access = 'pending' RETURNING id"]
        pub(super) activate: TypedStatement<(i64,), i64>,
        #[sql = "UPDATE users SET access = 'revoked', password_hash = NULL WHERE id = ? RETURNING id"]
        pub(super) revoke: TypedStatement<(i64,), i64>,

        #[sql = "INSERT INTO sessions (id, user_id, impersonator_id, created_at, expires_at)"]
        #[sql = "VALUES (?, ?, ?, ?, ?)"]
        pub(super) insert_session: TypedStatement<(String, i64, Option<i64>, i64, i64), ()>,
        #[sql = "DELETE FROM sessions WHERE id = ?"]
        pub(super) delete_session: TypedStatement<(String,), ()>,
        #[sql = "DELETE FROM sessions WHERE user_id = ? AND id IS NOT ?"]
        pub(super) delete_sessions: TypedStatement<(i64, Option<String>), ()>,
        #[sql = "DELETE FROM sessions WHERE impersonator_id = ?"]
        pub(super) delete_impersonations: TypedStatement<(i64,), ()>,
        #[sql = "DELETE FROM sessions WHERE expires_at <= ?"]
        pub(super) delete_expired_sessions: TypedStatement<(i64,), ()>,

        #[sql = "INSERT INTO auth_tokens (id, user_id, kind, expires_at, used_at) VALUES (?, ?, ?, ?, ?)"]
        pub(super) insert_token: TypedStatement<(String, i64, String, i64, Option<i64>), ()>,
        #[sql = "UPDATE auth_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL"]
        pub(super) use_up_tokens: TypedStatement<(i64, i64), ()>,
        #[sql = "UPDATE auth_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL"]
        pub(super) use_token: TypedStatement<(i64, String), ()>,
        #[sql = "DELETE FROM auth_tokens WHERE user_id = ?"]
        pub(super) delete_tokens: TypedStatement<(i64,), ()>,

        #[sql = "INSERT INTO config (key, value) VALUES (?, ?)"]
        #[sql = "ON CONFLICT (key) DO UPDATE SET value = excluded.value"]
        pub(super) set_config: TypedStatement<(String, String), ()>,
    }
}

pub use self::statements::{Read, Write};

impl AsMut<Read> for Read {
    #[inline]
    fn as_mut(&mut self) -> &mut Read {
        self
    }
}

impl Read {
    fn user(&mut self, id: UserId) -> Result<Option<User>> {
        self.user
            .bind((sql_id(id),))?
            .first()?
            .map(User::try_from)
            .transpose()
    }

    fn user_by_email(&mut self, email: &str) -> Result<Option<User>> {
        let row = self.user_by_email.bind((email,))?.first()?;
        row.map(User::try_from).transpose()
    }

    fn user_by_login(&mut self, login: &str) -> Result<Option<User>> {
        let row = self.user_by_login.bind((login,))?.first()?;
        row.map(User::try_from).transpose()
    }

    fn user_by_google_sub(&mut self, sub: &str) -> Result<Option<User>> {
        let row = self.user_by_google_sub.bind((sub,))?.first()?;
        row.map(User::try_from).transpose()
    }

    /// Whether `login` or `email` belong to a user other than `id`.
    fn conflict(
        &mut self,
        id: Option<UserId>,
        login: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<Conflict>> {
        if let Some(login) = login
            && let Some(user) = self.user_by_login(login)?
            && Some(user.id) != id
        {
            return Ok(Some(Conflict::Login));
        }

        if let Some(email) = email
            && let Some(user) = self.user_by_email(email)?
            && Some(user.id) != id
        {
            return Ok(Some(Conflict::Email));
        }

        Ok(None)
    }

    fn token(&mut self, id: &str) -> Result<Option<Token>> {
        let row = self.token.bind((id,))?.first()?;
        row.map(Token::try_from).transpose()
    }
}

impl AsMut<Write> for Write {
    #[inline]
    fn as_mut(&mut self) -> &mut Write {
        self
    }
}

impl Write {
    /// Runs `f` inside `BEGIN IMMEDIATE` / `COMMIT`, rolling back when it
    /// fails or panics, so the connection is never left in a transaction.
    fn transaction<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.begin.execute(())?;

        let result = match panic::catch_unwind(AssertUnwindSafe(|| f(self))) {
            Ok(Ok(value)) => match self.commit.execute(()) {
                Ok(()) => return Ok(value),
                Err(e) => Err(e.into()),
            },
            Ok(Err(e)) => Err(e),
            Err(payload) => {
                _ = self.rollback.execute(());
                panic::resume_unwind(payload);
            }
        };

        // Fails only when SQLite already rolled the transaction back itself.
        _ = self.rollback.execute(());
        result
    }

    /// Sets the credential and activates the user, as
    /// [`Store::set_credential`] does, without touching sessions. Returns
    /// whether the user exists. A Google subject or email that belongs to
    /// another user fails on the unique constraints.
    fn set_credential(&mut self, id: i64, cred: &Credential) -> Result<bool> {
        let found = match cred {
            Credential::Password(hash) => self.set_password.bind((hash.as_str(), id))?.first()?,
            Credential::Google { sub, email } => {
                let row = self.set_google.bind((sub.as_str(), email.as_str(), id));
                row?.first()?
            }
        };

        Ok(found.is_some())
    }

    fn delete_sessions(&mut self, user: i64, keep: Option<&str>) -> Result<()> {
        self.delete_sessions.execute((user, keep))?;
        Ok(())
    }

    fn insert_session(&mut self, session: &Session) -> Result<()> {
        self.insert_session.execute((
            session.id.as_str(),
            sql_id(session.user),
            session.impersonator.map(sql_id),
            millis(session.created_at),
            millis(session.expires_at),
        ))?;
        Ok(())
    }
}

impl<R, W> Store for SqllStore<R, W>
where
    R: IsReadOnly + AsMut<Read> + Send + 'static,
    W: Statements + AsMut<Write> + Send + 'static,
{
    async fn user(&self, id: UserId) -> Result<Option<User>> {
        self.read(move |r| r.user(id)).await
    }

    async fn user_by_email(&self, email: &str) -> Result<Option<User>> {
        let email = email.to_owned();
        self.read(move |r| r.user_by_email(&email)).await
    }

    async fn user_by_login(&self, login: &str) -> Result<Option<User>> {
        let login = login.to_owned();
        self.read(move |r| r.user_by_login(&login)).await
    }

    async fn user_by_google_sub(&self, sub: &str) -> Result<Option<User>> {
        let sub = sub.to_owned();
        self.read(move |r| r.user_by_google_sub(&sub)).await
    }

    async fn users(&self, now: Timestamp) -> Result<Vec<(User, Option<Timestamp>)>> {
        self.read(move |r| {
            let mut users = Vec::new();
            let mut stmt = r.users.bind((millis(now),))?;

            while let Some(row) = stmt.next()? {
                let (user, link) = row.split();
                users.push((User::try_from(user)?, link.map(timestamp).transpose()?));
            }

            Ok(users)
        })
        .await
    }

    async fn user_count(&self) -> Result<u64> {
        self.read(|r| {
            let count = r.user_count.query()?.first()?.unwrap_or_default();
            u64::try_from(count).map_err(StoreError::new)
        })
        .await
    }

    async fn create_user(&self, new: &NewUser, now: Timestamp) -> Result<Result<User, Conflict>> {
        let new = new.clone();

        self.write(move |w| {
            let (login, email) = (new.login.as_deref(), new.email.as_deref());

            if let Some(conflict) = w.read.conflict(None, login, email)? {
                return Ok(Err(conflict));
            }

            let id = w
                .insert_user
                .bind((login, email, new.role.as_str(), millis(now)))?
                .first()?
                .ok_or_else(|| StoreError::new("insert returned no id"))?;

            let user = w.read.user(user_id(id))?;
            Ok(Ok(user.ok_or_else(|| {
                StoreError::new("inserted user is missing")
            })?))
        })
        .await
    }

    async fn update_user(
        &self,
        id: UserId,
        change: &UserChange,
    ) -> Result<Result<Option<User>, Conflict>> {
        let change = change.clone();

        self.write(move |w| {
            let login = change.login.as_ref().and_then(Option::as_deref);
            let email = change.email.as_ref().and_then(Option::as_deref);

            if let Some(conflict) = w.read.conflict(Some(id), login, email)? {
                return Ok(Err(conflict));
            }

            if w.read.user(id)?.is_none() {
                return Ok(Ok(None));
            }

            let sql = sql_id(id);

            if let Some(login) = &change.login {
                w.set_login.execute((login.as_deref(), sql))?;
            }

            if let Some(email) = &change.email {
                w.set_email.execute((email.as_deref(), sql))?;
            }

            if let Some(role) = change.role {
                w.set_role.execute((role.as_str(), sql))?;
            }

            Ok(Ok(w.read.user(id)?))
        })
        .await
    }

    async fn delete_user(&self, id: UserId) -> Result<bool> {
        self.write(move |w| {
            let sql = sql_id(id);
            w.delete_sessions(sql, None)?;
            w.delete_impersonations.execute((sql,))?;
            w.delete_tokens.execute((sql,))?;
            Ok(w.delete_user.bind((sql,))?.first()?.is_some())
        })
        .await
    }

    async fn set_credential(
        &self,
        id: UserId,
        cred: &Credential,
        keep: Option<&str>,
    ) -> Result<bool> {
        let cred = cred.clone();
        let keep = keep.map(str::to_owned);

        self.write(move |w| {
            let sql = sql_id(id);

            // Read inside the transaction, so a revocation cannot land in
            // between.
            if w.read.user(id)?.is_none_or(|u| u.access == Access::Revoked) {
                return Ok(false);
            }

            if !w.set_credential(sql, &cred)? {
                return Ok(false);
            }

            w.delete_sessions(sql, keep.as_deref())?;
            Ok(true)
        })
        .await
    }

    async fn bind_google_sub(&self, id: UserId, sub: &str) -> Result<bool> {
        let sub = sub.to_owned();

        self.write(move |w| {
            if let Some(bound) = w.read.user_by_google_sub(&sub)? {
                return Ok(bound.id == id);
            }

            let Some(user) = w.read.user(id)? else {
                return Ok(false);
            };

            if user.google_sub.is_some() {
                // Bound to another subject, since `sub` is bound to no one.
                return Ok(false);
            }

            w.set_google_sub.execute((sub.as_str(), sql_id(id)))?;
            Ok(true)
        })
        .await
    }

    async fn set_access(&self, id: UserId, access: Access) -> Result<bool> {
        self.write(move |w| {
            let row = w.set_access.bind((access.as_str(), sql_id(id)))?;
            Ok(row.first()?.is_some())
        })
        .await
    }

    async fn activate(&self, id: UserId) -> Result<bool> {
        self.write(move |w| Ok(w.activate.bind((sql_id(id),))?.first()?.is_some()))
            .await
    }

    async fn revoke(&self, id: UserId, now: Timestamp) -> Result<bool> {
        self.write(move |w| {
            let sql = sql_id(id);

            if w.revoke.bind((sql,))?.first()?.is_none() {
                return Ok(false);
            }

            w.use_up_tokens.execute((millis(now), sql))?;
            w.delete_sessions(sql, None)?;
            Ok(true)
        })
        .await
    }

    async fn create_session(&self, session: &Session) -> Result<()> {
        let session = session.clone();

        self.write(move |w| {
            w.delete_expired_sessions
                .execute((millis(session.created_at),))?;
            w.insert_session(&session)
        })
        .await
    }

    async fn session(&self, id: &str) -> Result<Option<Session>> {
        let id = id.to_owned();

        self.read(move |r| {
            let row = r.session.bind((id.as_str(),))?.first()?;
            row.map(Session::try_from).transpose()
        })
        .await
    }

    async fn delete_session(&self, id: &str) -> Result<()> {
        let id = id.to_owned();

        self.write(move |w| {
            w.delete_session.execute((id.as_str(),))?;
            Ok(())
        })
        .await
    }

    async fn delete_sessions(&self, user: UserId, keep: Option<&str>) -> Result<()> {
        let keep = keep.map(str::to_owned);
        self.write(move |w| w.delete_sessions(sql_id(user), keep.as_deref()))
            .await
    }

    async fn delete_expired_sessions(&self, now: Timestamp) -> Result<()> {
        self.write(move |w| {
            w.delete_expired_sessions.execute((millis(now),))?;
            Ok(())
        })
        .await
    }

    async fn create_token(&self, token: &Token, now: Timestamp) -> Result<()> {
        let token = token.clone();

        self.write(move |w| {
            let user = sql_id(token.user);
            w.use_up_tokens.execute((millis(now), user))?;
            w.insert_token.execute((
                token.id.as_str(),
                user,
                token.kind.as_str(),
                millis(token.expires_at),
                token.used_at.map(millis),
            ))?;
            Ok(())
        })
        .await
    }

    async fn token(&self, id: &str) -> Result<Option<Token>> {
        let id = id.to_owned();
        self.read(move |r| r.token(&id)).await
    }

    async fn use_up_tokens(&self, user: UserId, now: Timestamp) -> Result<()> {
        self.write(move |w| {
            w.use_up_tokens.execute((millis(now), sql_id(user)))?;
            Ok(())
        })
        .await
    }

    async fn redeem_token(
        &self,
        token: &str,
        cred: &Credential,
        session: &Session,
        now: Timestamp,
    ) -> Result<bool> {
        let token = token.to_owned();
        let cred = cred.clone();
        let session = session.clone();

        self.write(move |w| {
            // Read inside the transaction, so nothing changes in between.
            let Some(row) = w.read.token(&token)? else {
                return Ok(false);
            };

            if row.used_at.is_some() {
                return Ok(false);
            }

            let user = sql_id(row.user);

            if !w.set_credential(user, &cred)? {
                return Ok(false);
            }

            w.use_token.execute((millis(now), token.as_str()))?;
            w.delete_sessions(user, None)?;
            w.insert_session(&session)?;
            Ok(true)
        })
        .await
    }

    async fn config_get(&self, key: &str) -> Result<Option<String>> {
        let key = key.to_owned();
        self.read(move |r| Ok(r.config.bind((key.as_str(),))?.first()?))
            .await
    }

    async fn config_set(&self, key: &str, value: &str) -> Result<()> {
        let (key, value) = (key.to_owned(), value.to_owned());

        self.write(move |w| {
            w.set_config.execute((key.as_str(), value.as_str()))?;
            Ok(())
        })
        .await
    }
}

impl From<sqll::Error> for StoreError {
    #[inline]
    fn from(error: sqll::Error) -> Self {
        StoreError::new(error)
    }
}

#[derive(Row)]
struct UserRow {
    id: i64,
    login: Option<String>,
    email: Option<String>,
    role: String,
    access: String,
    method: String,
    password_hash: Option<String>,
    google_sub: Option<String>,
    created_at: i64,
}

impl TryFrom<UserRow> for User {
    type Error = StoreError;

    fn try_from(row: UserRow) -> Result<Self> {
        Ok(User {
            id: user_id(row.id),
            login: row.login,
            email: row.email,
            role: row.role.parse::<Role>().map_err(StoreError::new)?,
            access: row.access.parse::<Access>().map_err(StoreError::new)?,
            method: row.method.parse::<Method>().map_err(StoreError::new)?,
            password_hash: row.password_hash,
            google_sub: row.google_sub,
            created_at: timestamp(row.created_at)?,
        })
    }
}

/// A [`UserRow`] with the expiry of the user's live link.
#[derive(Row)]
struct UserLinkRow {
    id: i64,
    login: Option<String>,
    email: Option<String>,
    role: String,
    access: String,
    method: String,
    password_hash: Option<String>,
    google_sub: Option<String>,
    created_at: i64,
    link: Option<i64>,
}

impl UserLinkRow {
    fn split(self) -> (UserRow, Option<i64>) {
        let user = UserRow {
            id: self.id,
            login: self.login,
            email: self.email,
            role: self.role,
            access: self.access,
            method: self.method,
            password_hash: self.password_hash,
            google_sub: self.google_sub,
            created_at: self.created_at,
        };

        (user, self.link)
    }
}

#[derive(Row)]
struct SessionRow {
    id: String,
    user_id: i64,
    impersonator_id: Option<i64>,
    created_at: i64,
    expires_at: i64,
}

impl TryFrom<SessionRow> for Session {
    type Error = StoreError;

    fn try_from(row: SessionRow) -> Result<Self> {
        Ok(Session {
            id: row.id,
            user: user_id(row.user_id),
            impersonator: row.impersonator_id.map(user_id),
            created_at: timestamp(row.created_at)?,
            expires_at: timestamp(row.expires_at)?,
        })
    }
}

#[derive(Row)]
struct TokenRow {
    id: String,
    user_id: i64,
    kind: String,
    expires_at: i64,
    used_at: Option<i64>,
}

impl TryFrom<TokenRow> for Token {
    type Error = StoreError;

    fn try_from(row: TokenRow) -> Result<Self> {
        let kind = match row.kind.as_str() {
            "registration" => TokenKind::Registration,
            "reset" => TokenKind::Reset,
            other => return Err(StoreError::new(format!("unknown token kind {other:?}"))),
        };

        Ok(Token {
            id: row.id,
            user: user_id(row.user_id),
            kind,
            expires_at: timestamp(row.expires_at)?,
            used_at: row.used_at.map(timestamp).transpose()?,
        })
    }
}

/// A stored timestamp, in milliseconds since the Unix epoch. Stored times
/// keep millisecond precision.
fn millis(timestamp: Timestamp) -> i64 {
    timestamp.as_millisecond()
}

fn timestamp(millis: i64) -> Result<Timestamp> {
    Timestamp::from_millisecond(millis).map_err(StoreError::new)
}

/// A user id as stored: bit-reinterpreted as SQLite's signed integer, so
/// every [`UserId`] has a column value, and one beyond `i64::MAX` is simply
/// not found.
fn sql_id(id: UserId) -> i64 {
    id.0 as i64
}

fn user_id(id: i64) -> UserId {
    UserId(id as u64)
}
