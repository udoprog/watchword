//! [`SqllStore`], a [`Store`] over SQLite through
//! [sqll](https://docs.rs/sqll/0.14) 0.14 (the `sqll014` feature).
//!
//! The store works over four tables with a fixed set of columns, created by
//! [`SCHEMA`] in a new database:
//!
//! ```sql
#![doc = include_str!("sqll014/schema.sql")]
//! ```
//!
//! An app keeps its own columns on `users` (with defaults, since the store
//! inserts only its own) and its own tables referencing `users (id)`. The
//! store reads and writes only the columns above, and deletes a user's
//! sessions and links itself, so it does not rely on `ON DELETE CASCADE`;
//! the app's own tables cascade only if its connections enable foreign keys.
//!
//! An app's own SQL may read the store's columns, such as joining its tables
//! on `users`: they change only through a new entry in [`MIGRATIONS`]. It
//! changes them only through the [`Store`], which keeps a user's sessions and
//! links consistent with them. [`UserId`], [`Role`], [`Access`] and [`Method`]
//! bind and read as these columns hold them, so app statements take and
//! return them directly: an id as an integer with the same bits, the enums as
//! their names.
//!
//! # Sharing the app's pool
//!
//! The store runs its statements on a [`sqll014::Pool`]. An app with its own
//! pool nests [`Read`] and [`Write`] in its statement collections and gives
//! the store access to them through [`AsMut`], so that auth and the app share
//! one write connection:
//!
//! ```ignore
//! #[derive(Statements)]
//! #[sql(read_only)]
//! struct AppRead {
//!     #[sql(statements)]
//!     auth: watchword::sqll014::Read,
//!     // the app's own statements
//! }
//!
//! impl AsMut<watchword::sqll014::Read> for AppRead {
//!     fn as_mut(&mut self) -> &mut watchword::sqll014::Read {
//!         &mut self.auth
//!     }
//! }
//!
//! // ...and the same for `AppWrite` with `watchword::sqll014::Write`.
//!
//! let pool: Arc<Pool<AppRead, AppWrite>> = /* the app's pool */;
//! let store = SqllStore::new(pool.clone());
//! ```
//!
//! A store over its own pool is a `SqllStore` (that is,
//! `SqllStore<Read, Write>`) over a `Pool<Read, Write>`.
//!
//! The pool's statements are prepared when it opens, so the schema must be in
//! place by then: migrate the database first, from the pool's write setup.
//!
//! # Creating and upgrading the tables
//!
//! The store's tables come in two forms that end up the same:
//!
//! * [`MIGRATIONS`], ordered `(id, sql)` pairs: the tables as first released,
//!   then every change to them since, each under a stable id starting with
//!   `watchword-`. A new release only appends to it.
//! * [`SCHEMA`], what all of [`MIGRATIONS`] add up to, for creating the tables
//!   in a new database in one step. Running it again changes nothing, but it
//!   does not upgrade older tables either: it adds no columns.
//!
//! Use [`MIGRATIONS`] for any database that outlives a watchword upgrade, and
//! [`SCHEMA`] alone only for one that never does, such as a test's.
//!
//! An app applies each migration whose id it has not recorded yet, in order,
//! and records the id in the same transaction. It either hands the pairs to a
//! migration runner that takes ordered `(id, sql)` pairs (such as sqll's
//! `Migrations`, in releases after 0.14.7, which also takes [`SCHEMA`] as its
//! fresh schema), or splices them into its own list of migrations, before any
//! migration of its own that refers to `users`. Then [`check_schema`] fails at
//! startup with an error naming every missing table and column, rather than
//! letting a statement fail to prepare:
//!
//! ```
//! use sqll014::{Connection, OpenOptions, PoolBuilder};
//! use watchword::sqll014::{MIGRATIONS, Read, SqllStore, Write, check_schema};
//!
//! /// Applies the migrations `c` has not recorded, each in one transaction.
//! fn migrate(c: &Connection, migrations: &[(&str, &str)]) -> sqll014::Result<()> {
//!     c.execute(
//!         "CREATE TABLE IF NOT EXISTS migrations \
//!          (id TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)",
//!     )?;
//!
//!     for &(id, sql) in migrations {
//!         c.execute("BEGIN IMMEDIATE")?;
//!
//!         let result = (|| {
//!             let seen = {
//!                 let mut stmt = c.prepare("SELECT COUNT(*) FROM migrations WHERE id = ?")?;
//!                 stmt.bind((id,))?;
//!                 stmt.next::<i64>()?
//!             };
//!
//!             if seen == Some(0) {
//!                 c.execute(sql)?;
//!                 let mut record = c.prepare(
//!                     "INSERT INTO migrations (id, applied_at) VALUES (?, strftime('%s', 'now'))",
//!                 )?;
//!                 record.execute((id,))?;
//!             }
//!
//!             c.execute("COMMIT")
//!         })();
//!
//!         if result.is_err() {
//!             _ = c.execute("ROLLBACK");
//!         }
//!
//!         result?;
//!     }
//!
//!     Ok(())
//! }
//!
//! let mut options = OpenOptions::new();
//! options.uri().create();
//!
//! let pool = PoolBuilder::new(options, 4)
//!     .with_write_setup(|c| {
//!         // The app's own migrations go before or after these, by what they need.
//!         migrate(c, MIGRATIONS)?;
//!         check_schema(c)
//!     })
//!     .open::<Read, Write>("file:watchword-doc?mode=memory&cache=shared")?;
//!
//! let store = SqllStore::new(std::sync::Arc::new(pool));
//! # Ok::<_, Box<dyn std::error::Error>>(())
//! ```
//!
//! ## An app whose own migrations already made the tables
//!
//! An app that created the store's tables with a copy of an earlier schema in
//! a migration of its own (a frozen base schema, say) keeps that migration as
//! it is, and from then on takes watchword's changes from [`MIGRATIONS`]
//! instead of copying them: it splices in every pair after it, leaving out the
//! ids its own migrations already did. Its copy of the first schema did
//! `watchword-0001-tables`; a copy of the `impersonator_id` column, as
//! `ALTER TABLE` or in the copied schema, did
//! `watchword-0002-sessions-impersonator`.
//!
//! ```
//! use watchword::sqll014::MIGRATIONS;
//!
//! /// Ids of watchword's migrations this app's own migrations already did.
//! const DONE: &[&str] = &["watchword-0001-tables", "watchword-0002-sessions-impersonator"];
//!
//! let watchword = MIGRATIONS.iter().filter(|(id, _)| !DONE.contains(id));
//! // ...appended to the app's own migrations, in this order.
//! # assert_eq!(watchword.count(), MIGRATIONS.len() - 2);
//! ```
//!
//! [`check_schema`] then catches an upgrade that was left out.
//!
//! # Moving existing tables onto the store
//!
//! An app that already keeps users, sessions or tokens in tables of its own
//! moves them onto the store's tables once, with a migration of its own among
//! its migrations, before it first opens the store. Afterwards the store's
//! tables must have every column [`SCHEMA`] gives them, with timestamps as
//! INTEGER milliseconds since the Unix epoch; the app's own columns on `users`
//! need defaults. It then takes the ids of [`MIGRATIONS`] its move covers as
//! done, as above.

use std::borrow::ToOwned;
use std::panic::{self, AssertUnwindSafe};
use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use jiff::Timestamp;
use sqll014::{IsReadOnly, Pool, Row, Statements, TypedStatement};
use tokio::task::spawn_blocking;

use crate::store::{Credential, Result, Session, Store, StoreError, Token, TokenKind, User};
use crate::types::{Access, Conflict, Method, NewUser, Role, UserChange, UserId};

#[cfg(test)]
mod tests;

/// The SQL that creates the store's tables in a new database, as all of
/// [`MIGRATIONS`] together would. Every statement is `IF NOT EXISTS`, so
/// running it again changes nothing, and it does not upgrade tables made by an
/// earlier release. See [creating and upgrading the
/// tables](self#creating-and-upgrading-the-tables).
pub const SCHEMA: &str = include_str!("sqll014/schema.sql");

/// The store's migrations, in the order to apply them, as `(id, sql)` pairs:
/// the tables as first released, then each change to them since. Ids are
/// stable and start with `watchword-`; a new release only appends.
///
/// Apply each one whose id the database has not recorded, and record it in
/// the same transaction. See [creating and upgrading the
/// tables](self#creating-and-upgrading-the-tables).
///
/// | Id | Change |
/// |----|--------|
/// | `watchword-0001-tables` | The `users`, `sessions`, `auth_tokens` and `config` tables |
/// | `watchword-0002-sessions-impersonator` | `sessions.impersonator_id`, the admin behind an impersonated session |
pub const MIGRATIONS: &[(&str, &str)] = &[
    (
        "watchword-0001-tables",
        include_str!("sqll014/migrations/0001-tables.sql"),
    ),
    (
        "watchword-0002-sessions-impersonator",
        include_str!("sqll014/migrations/0002-sessions-impersonator.sql"),
    ),
];

/// A table's columns, each with the id of the migration that added it after
/// the table, if one did.
type Columns = &'static [(&'static str, Option<&'static str>)];

/// The tables and columns the store reads and writes.
const COLUMNS: &[(&str, Columns)] = &[
    (
        "users",
        &[
            ("id", None),
            ("login", None),
            ("email", None),
            ("role", None),
            ("access", None),
            ("method", None),
            ("password_hash", None),
            ("google_sub", None),
            ("created_at", None),
        ],
    ),
    (
        "sessions",
        &[
            ("id", None),
            ("user_id", None),
            (
                "impersonator_id",
                Some("watchword-0002-sessions-impersonator"),
            ),
            ("created_at", None),
            ("expires_at", None),
        ],
    ),
    (
        "auth_tokens",
        &[
            ("id", None),
            ("user_id", None),
            ("kind", None),
            ("expires_at", None),
            ("used_at", None),
        ],
    ),
    ("config", &[("key", None), ("value", None)]),
];

/// Checks that the database on `c` has every table and column the store
/// uses, so that an app fails at startup, before its pool prepares the
/// store's statements, with an error naming each one missing and the
/// migration that adds it.
///
/// Run it after migrating, such as at the end of the pool's write setup. It
/// checks names only, not types or constraints, and ignores the app's own
/// columns and tables.
///
/// # Errors
///
/// Fails with a [`sqll014::Error`] whose message lists what is missing, or
/// with the error of reading the database's schema.
pub fn check_schema(c: &sqll014::Connection) -> sqll014::Result<()> {
    let mut stmt = c.prepare("SELECT name FROM pragma_table_info(?)")?;
    let mut missing = Vec::new();

    for &(table, columns) in COLUMNS {
        stmt.reset()?;
        stmt.bind((table,))?;
        let mut found = Vec::new();

        while let Some(name) = stmt.next::<String>()? {
            found.push(name);
        }

        if found.is_empty() {
            missing.push(format!("table `{table}`"));
            continue;
        }

        for &(column, added_by) in columns {
            if found.iter().any(|f| f.eq_ignore_ascii_case(column)) {
                continue;
            }

            missing.push(match added_by {
                Some(id) => format!("column `{table}.{column}` (added by `{id}`)"),
                None => format!("column `{table}.{column}`"),
            });
        }
    }

    if missing.is_empty() {
        return Ok(());
    }

    Err(sqll014::Error::custom(format_args!(
        "watchword's tables lack {}; apply sqll014::MIGRATIONS",
        missing.join(", ")
    )))
}

/// A [`Store`] over SQLite, on a [`sqll014::Pool`] whose read and write
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

/// The store's read statements, to nest in an app's read-only statement
/// collection with `#[sql(statements)]`.
#[derive(Statements)]
#[sql(crate = sqll014)]
#[sql(read_only)]
pub struct Read {
    #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
    #[sql = "FROM users WHERE id = ?"]
    user: TypedStatement<(UserId,), UserRow>,
    #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
    #[sql = "FROM users WHERE email = ?"]
    user_by_email: TypedStatement<(String,), UserRow>,
    #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
    #[sql = "FROM users WHERE login = ?"]
    user_by_login: TypedStatement<(String,), UserRow>,
    #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
    #[sql = "FROM users WHERE google_sub = ?"]
    user_by_google_sub: TypedStatement<(String,), UserRow>,
    #[sql = "SELECT u.id, u.login, u.email, u.role, u.access, u.method, u.password_hash,"]
    #[sql = "u.google_sub, u.created_at,"]
    #[sql = "(SELECT MAX(t.expires_at) FROM auth_tokens t"]
    #[sql = " WHERE t.user_id = u.id AND t.used_at IS NULL AND t.expires_at > ?) AS link"]
    #[sql = "FROM users u ORDER BY u.id"]
    users: TypedStatement<(i64,), UserLinkRow>,
    #[sql = "SELECT COUNT(*) FROM users"]
    user_count: TypedStatement<(), i64>,
    #[sql = "SELECT id, user_id, impersonator_id, created_at, expires_at FROM sessions WHERE id = ?"]
    session: TypedStatement<(String,), SessionRow>,
    #[sql = "SELECT id, user_id, kind, expires_at, used_at FROM auth_tokens WHERE id = ?"]
    token: TypedStatement<(String,), TokenRow>,
    #[sql = "SELECT value FROM config WHERE key = ?"]
    config: TypedStatement<(String,), String>,
}

/// The store's write statements, to nest in an app's write statement
/// collection with `#[sql(statements)]`. They include [`Read`].
#[derive(Statements)]
#[sql(crate = sqll014)]
pub struct Write {
    #[sql(statements)]
    read: Read,

    #[sql = "BEGIN IMMEDIATE"]
    begin: TypedStatement<(), ()>,
    #[sql = "COMMIT"]
    commit: TypedStatement<(), ()>,
    #[sql = "ROLLBACK"]
    rollback: TypedStatement<(), ()>,

    #[sql = "INSERT INTO users (login, email, role, access, method, created_at)"]
    #[sql = "VALUES (?, ?, ?, 'pending', 'password', ?) RETURNING id"]
    insert_user: TypedStatement<(Option<String>, Option<String>, Role, i64), UserId>,
    #[sql = "UPDATE users SET login = ? WHERE id = ?"]
    set_login: TypedStatement<(Option<String>, UserId), ()>,
    #[sql = "UPDATE users SET email = ? WHERE id = ?"]
    set_email: TypedStatement<(Option<String>, UserId), ()>,
    #[sql = "UPDATE users SET role = ? WHERE id = ?"]
    set_role: TypedStatement<(Role, UserId), ()>,
    #[sql = "DELETE FROM users WHERE id = ? RETURNING id"]
    delete_user: TypedStatement<(UserId,), UserId>,
    #[sql = "UPDATE users SET method = 'password', password_hash = ?, google_sub = NULL,"]
    #[sql = "access = 'active' WHERE id = ? RETURNING id"]
    set_password: TypedStatement<(String, UserId), UserId>,
    #[sql = "UPDATE users SET method = 'google', password_hash = NULL, google_sub = ?,"]
    #[sql = "email = ?, access = 'active' WHERE id = ? RETURNING id"]
    set_google: TypedStatement<(String, String, UserId), UserId>,
    #[sql = "UPDATE users SET google_sub = ? WHERE id = ?"]
    set_google_sub: TypedStatement<(String, UserId), ()>,
    #[sql = "UPDATE users SET access = ? WHERE id = ? RETURNING id"]
    set_access: TypedStatement<(Access, UserId), UserId>,
    #[sql = "UPDATE users SET access = 'active' WHERE id = ? AND access = 'pending' RETURNING id"]
    activate: TypedStatement<(UserId,), UserId>,
    #[sql = "UPDATE users SET access = 'revoked', password_hash = NULL WHERE id = ? RETURNING id"]
    revoke: TypedStatement<(UserId,), UserId>,

    #[sql = "INSERT INTO sessions (id, user_id, impersonator_id, created_at, expires_at)"]
    #[sql = "VALUES (?, ?, ?, ?, ?)"]
    insert_session: TypedStatement<(String, UserId, Option<UserId>, i64, i64), ()>,
    #[sql = "DELETE FROM sessions WHERE id = ?"]
    delete_session: TypedStatement<(String,), ()>,
    #[sql = "DELETE FROM sessions WHERE user_id = ? AND id IS NOT ?"]
    delete_sessions: TypedStatement<(UserId, Option<String>), ()>,
    #[sql = "DELETE FROM sessions WHERE impersonator_id = ?"]
    delete_impersonations: TypedStatement<(UserId,), ()>,
    #[sql = "DELETE FROM sessions WHERE expires_at <= ?"]
    delete_expired_sessions: TypedStatement<(i64,), ()>,

    #[sql = "INSERT INTO auth_tokens (id, user_id, kind, expires_at, used_at) VALUES (?, ?, ?, ?, ?)"]
    insert_token: TypedStatement<(String, UserId, String, i64, Option<i64>), ()>,
    #[sql = "UPDATE auth_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL"]
    use_up_tokens: TypedStatement<(i64, UserId), ()>,
    #[sql = "UPDATE auth_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL"]
    use_token: TypedStatement<(i64, String), ()>,
    #[sql = "DELETE FROM auth_tokens WHERE user_id = ?"]
    delete_tokens: TypedStatement<(UserId,), ()>,
    #[sql = "DELETE FROM auth_tokens WHERE expires_at <= ?"]
    delete_expired_tokens: TypedStatement<(i64,), ()>,

    #[sql = "INSERT INTO config (key, value) VALUES (?, ?)"]
    #[sql = "ON CONFLICT (key) DO UPDATE SET value = excluded.value"]
    set_config: TypedStatement<(String, String), ()>,
}

impl AsMut<Read> for Read {
    #[inline]
    fn as_mut(&mut self) -> &mut Read {
        self
    }
}

impl Read {
    fn user(&mut self, id: UserId) -> Result<Option<User>> {
        self.user
            .bind((id,))?
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
    fn set_credential(&mut self, id: UserId, cred: &Credential) -> Result<bool> {
        let found = match cred {
            Credential::Password(hash) => self.set_password.bind((hash.as_str(), id))?.first()?,
            Credential::Google { sub, email } => {
                let row = self.set_google.bind((sub.as_str(), email.as_str(), id));
                row?.first()?
            }
        };

        Ok(found.is_some())
    }

    fn delete_sessions(&mut self, user: UserId, keep: Option<&str>) -> Result<()> {
        self.delete_sessions.execute((user, keep))?;
        Ok(())
    }

    fn insert_session(&mut self, session: &Session) -> Result<()> {
        self.insert_session.execute((
            session.id.as_str(),
            session.user,
            session.impersonator,
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
                .bind((login, email, new.role, millis(now)))?
                .first()?
                .ok_or_else(|| StoreError::new("insert returned no id"))?;

            let user = w.read.user(id)?;
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

            if let Some(login) = &change.login {
                w.set_login.execute((login.as_deref(), id))?;
            }

            if let Some(email) = &change.email {
                w.set_email.execute((email.as_deref(), id))?;
            }

            if let Some(role) = change.role {
                w.set_role.execute((role, id))?;
            }

            Ok(Ok(w.read.user(id)?))
        })
        .await
    }

    async fn delete_user(&self, id: UserId) -> Result<bool> {
        self.write(move |w| {
            w.delete_sessions(id, None)?;
            w.delete_impersonations.execute((id,))?;
            w.delete_tokens.execute((id,))?;
            Ok(w.delete_user.bind((id,))?.first()?.is_some())
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
            // Read inside the transaction, so a revocation cannot land in
            // between.
            if w.read.user(id)?.is_none_or(|u| u.access == Access::Revoked) {
                return Ok(false);
            }

            if !w.set_credential(id, &cred)? {
                return Ok(false);
            }

            w.delete_sessions(id, keep.as_deref())?;
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

            w.set_google_sub.execute((sub.as_str(), id))?;
            Ok(true)
        })
        .await
    }

    async fn set_access(&self, id: UserId, access: Access) -> Result<bool> {
        self.write(move |w| {
            let row = w.set_access.bind((access, id))?;
            Ok(row.first()?.is_some())
        })
        .await
    }

    async fn activate(&self, id: UserId) -> Result<bool> {
        self.write(move |w| Ok(w.activate.bind((id,))?.first()?.is_some()))
            .await
    }

    async fn revoke(&self, id: UserId, now: Timestamp) -> Result<bool> {
        self.write(move |w| {
            if w.revoke.bind((id,))?.first()?.is_none() {
                return Ok(false);
            }

            w.use_up_tokens.execute((millis(now), id))?;
            w.delete_sessions(id, None)?;
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
        self.write(move |w| w.delete_sessions(user, keep.as_deref()))
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
            let user = token.user;
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

    async fn delete_expired_tokens(&self, before: Timestamp) -> Result<()> {
        self.write(move |w| {
            w.delete_expired_tokens.execute((millis(before),))?;
            Ok(())
        })
        .await
    }

    async fn use_up_tokens(&self, user: UserId, now: Timestamp) -> Result<()> {
        self.write(move |w| {
            w.use_up_tokens.execute((millis(now), user))?;
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

            let user = row.user;

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

impl From<sqll014::Error> for StoreError {
    #[inline]
    fn from(error: sqll014::Error) -> Self {
        StoreError::new(error)
    }
}

#[derive(Row)]
#[sql(crate = sqll014)]
struct UserRow {
    id: UserId,
    login: Option<String>,
    email: Option<String>,
    role: Role,
    access: Access,
    method: Method,
    password_hash: Option<String>,
    google_sub: Option<String>,
    created_at: i64,
}

impl TryFrom<UserRow> for User {
    type Error = StoreError;

    fn try_from(row: UserRow) -> Result<Self> {
        Ok(User {
            id: row.id,
            login: row.login,
            email: row.email,
            role: row.role,
            access: row.access,
            method: row.method,
            password_hash: row.password_hash,
            google_sub: row.google_sub,
            created_at: timestamp(row.created_at)?,
        })
    }
}

/// A [`UserRow`] with the expiry of the user's live link.
#[derive(Row)]
#[sql(crate = sqll014)]
struct UserLinkRow {
    id: UserId,
    login: Option<String>,
    email: Option<String>,
    role: Role,
    access: Access,
    method: Method,
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
#[sql(crate = sqll014)]
struct SessionRow {
    id: String,
    user_id: UserId,
    impersonator_id: Option<UserId>,
    created_at: i64,
    expires_at: i64,
}

impl TryFrom<SessionRow> for Session {
    type Error = StoreError;

    fn try_from(row: SessionRow) -> Result<Self> {
        Ok(Session {
            id: row.id,
            user: row.user_id,
            impersonator: row.impersonator_id,
            created_at: timestamp(row.created_at)?,
            expires_at: timestamp(row.expires_at)?,
        })
    }
}

#[derive(Row)]
#[sql(crate = sqll014)]
struct TokenRow {
    id: String,
    user_id: UserId,
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
            user: row.user_id,
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
