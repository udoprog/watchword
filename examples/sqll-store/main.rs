//! An app's own [`Store`] over SQLite with [sqll] 0.15: the starting point for
//! writing one.
//!
//! watchword ships no storage of its own besides `MemoryStore`, because the
//! shape of user data differs from app to app. Each app keeps users,
//! sessions, links and settings in tables of its own, with its own migrations,
//! and implements [`Store`] over them, mapping its rows into watchword's
//! records ([`User`], [`Session`], [`Token`]). Copy this file and change the
//! tables to the app's.
//!
//! Here the tables are `accounts`, `sessions`, `links` and `settings` (see
//! `migrations/`), and `accounts` has a column watchword knows nothing about,
//! `display_name`, which has no default: the store fills it when it creates
//! an account. The store runs on a sqll [`Pool`] whose statement collections
//! are the app's own, so the app's other statements sit beside the store's in
//! [`Read`] and [`Write`] and share the one write connection.
//!
//! The tests at the end run watchword's store conformance suite,
//! `watchword::store_suite!`, over the store: one `#[test]` per rule of
//! `Auth` that depends on what a store keeps.
//!
//! ```sh
//! cargo run --example sqll-store --features test-util,sqll015 -- [database]
//! cargo test --example sqll-store --features test-util,sqll015
//! ```
//!
//! An app takes `watchword` with the `sqll015` feature, which makes
//! [`UserId`], [`Role`], [`Access`] and [`Method`] bind and read as sqll
//! columns (an id as an integer with the same bits, the enums as their names),
//! and `sqll` with `derive`, `pool`, `typed` and `threadsafe` (its defaults)
//! plus `bundled` or its own SQLite. Its tests take `watchword` with
//! `test-util` for the suite.
//!
//! [sqll]: https://docs.rs/sqll/0.15

use std::error::Error as StdError;
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use sqll::{
    JournalMode, Migrations, OpenOptions, Pool, PoolBuilder, Row, Statements, TypedStatement,
};
use watchword::store::{self, Credential, Session, Store, StoreError, Token, TokenKind, User};
use watchword::{
    Access, Auth, BootstrapAdmin, Conflict, Method, NewUser, Role, UserChange, UserId,
};

/// The app's migrations, in order, as sqll's [`Migrations`] runs them. A new
/// release of the app only appends to them.
const MIGRATIONS: &[(&str, &str)] = &[("0001-tables", include_str!("migrations/0001-tables.sql"))];

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn StdError>> {
    // A database file, or by default one in memory, which will do for this
    // run since it never writes beside a read (see `AppStore::open`).
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| String::from("file:sqll-store?mode=memory&cache=shared"));

    let store = AppStore::open(&path)?;

    // The session key is kept in the store, so sessions outlive a restart.
    let auth = Auth::builder_from_store(store.clone()).await?.build();

    let bootstrap = auth.bootstrap_admin(&BootstrapAdmin::new("admin")).await?;

    if let Some(link) = bootstrap.link() {
        let admin = store.user_by_login("admin").await?.ok_or("no admin")?;
        let name = store.display_name(admin.id).await?.unwrap_or_default();
        println!("Sign up as {name}: {}", link.url(None));
    }

    println!("{} account(s) in {path}", store.user_count().await?);
    Ok(())
}

/// The app's store. Clones share the pool.
#[derive(Clone)]
pub struct AppStore {
    pool: Arc<Pool<Read, Write>>,
    /// The directory of a scratch database, removed with the last clone.
    #[cfg(test)]
    _scratch: Option<Arc<tempfile::TempDir>>,
}

impl AppStore {
    /// Opens the database at `path` (a file name or an SQLite URI), creating
    /// and migrating it as needed.
    pub fn open(path: &str) -> Result<Self, Error> {
        // A pool runs a write beside its reads, as `Auth` does when it prunes
        // on a timer while requests read. In WAL mode the readers keep
        // reading while the writer writes, and the busy timeout makes a
        // connection wait out the moments SQLite still locks the file rather
        // than fail. An in-memory database has no WAL: with a shared cache a
        // write beside a read fails at once with `SQLITE_LOCKED`, which no
        // busy timeout waits out, so the pool needs a file.
        let mut options = OpenOptions::new();
        options
            .uri()
            .create()
            .busy_timeout(Duration::from_secs(5))
            .journal_mode(JournalMode::Wal);

        // The pool prepares its statements when it opens, so the write
        // setup migrates the database first. Foreign keys are on, so deleting
        // an account deletes its sessions and links.
        let pool = PoolBuilder::new(options, 4)
            .with_write_setup(|c| {
                c.execute("PRAGMA foreign_keys = ON")?;
                Migrations::new().run(c, MIGRATIONS.iter().copied())?;
                Ok::<_, sqll::Error>(())
            })
            .with_read_setup(|c| c.execute("PRAGMA foreign_keys = ON"))
            .open(path)?;

        Ok(Self {
            pool: Arc::new(pool),
            #[cfg(test)]
            _scratch: None,
        })
    }

    /// A store over a new database in a temporary directory, removed when
    /// the last clone of the store is dropped.
    #[cfg(test)]
    fn open_scratch() -> Result<Self, Box<dyn StdError>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("store.db");
        let path = path.to_str().ok_or("temporary path is not UTF-8")?;

        Ok(Self {
            _scratch: Some(Arc::new(dir)),
            ..Self::open(path)?
        })
    }

    /// The account's display name: one of the app's own columns, read
    /// through the same pool.
    pub async fn display_name(&self, id: UserId) -> store::Result<Option<String>> {
        self.read(move |r| Ok(r.display_name.bind((id,))?.first()?))
            .await
    }

    /// Runs `f` on a read connection, on a blocking thread.
    async fn read<T>(
        &self,
        f: impl FnOnce(&mut Read) -> Result<T, Error> + Send + 'static,
    ) -> store::Result<T>
    where
        T: Send + 'static,
    {
        let result = self.pool.read(move |r| f(r)).await.map_err(Error::from)?;
        Ok(result?)
    }

    /// Runs `f` on the write connection, on a blocking thread, in one
    /// transaction: it commits when `f` returns `Ok`, and rolls back when `f`
    /// fails or panics. Every write goes through here, so each `Store` method
    /// is atomic.
    async fn write<T>(
        &self,
        f: impl FnOnce(&mut Write) -> Result<T, Error> + Send + 'static,
    ) -> store::Result<T>
    where
        T: Send + 'static,
    {
        let result = self
            .pool
            .write(move |w| w.transaction(|w, _| f(w)))
            .await
            .map_err(Error::from)?;

        Ok(result?)
    }
}

/// The app's read statements. The app's own reads go here too.
#[derive(Statements)]
#[sql(read_only)]
pub struct Read {
    #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
    #[sql = "FROM accounts WHERE id = ?"]
    user: TypedStatement<(UserId,), AccountRow>,
    #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
    #[sql = "FROM accounts WHERE email = ?"]
    user_by_email: TypedStatement<(String,), AccountRow>,
    #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
    #[sql = "FROM accounts WHERE login = ?"]
    user_by_login: TypedStatement<(String,), AccountRow>,
    #[sql = "SELECT id, login, email, role, access, method, password_hash, google_sub, created_at"]
    #[sql = "FROM accounts WHERE google_sub = ?"]
    user_by_google_sub: TypedStatement<(String,), AccountRow>,
    #[sql = "SELECT a.id, a.login, a.email, a.role, a.access, a.method, a.password_hash,"]
    #[sql = "a.google_sub, a.created_at,"]
    #[sql = "(SELECT MAX(l.expires_at) FROM links l"]
    #[sql = " WHERE l.account_id = a.id AND l.used_at IS NULL AND l.expires_at > ?) AS link"]
    #[sql = "FROM accounts a ORDER BY a.id"]
    users: TypedStatement<(i64,), ListedRow>,
    #[sql = "SELECT COUNT(*) FROM accounts"]
    user_count: TypedStatement<(), i64>,
    #[sql = "SELECT access FROM accounts WHERE id = ?"]
    access: TypedStatement<(UserId,), Access>,
    #[sql = "SELECT id, account_id, impersonator_id, created_at, expires_at"]
    #[sql = "FROM sessions WHERE id = ?"]
    session: TypedStatement<(String,), SessionRow>,
    #[sql = "SELECT id, account_id, kind, expires_at, used_at FROM links WHERE id = ?"]
    link: TypedStatement<(String,), LinkRow>,
    #[sql = "SELECT value FROM settings WHERE key = ?"]
    setting: TypedStatement<(String,), String>,

    // The app's own.
    #[sql = "SELECT display_name FROM accounts WHERE id = ?"]
    display_name: TypedStatement<(UserId,), String>,
}

/// An account's login, email, display name, role and creation time.
type NewAccount = (Option<String>, Option<String>, String, Role, i64);

/// The app's write statements, with its reads for use inside a transaction.
/// The app's own writes go here too.
#[derive(Statements)]
pub struct Write {
    #[sql(statements)]
    read: Read,

    #[sql = "INSERT INTO accounts (login, email, display_name, role, access, method, created_at)"]
    #[sql = "VALUES (?, ?, ?, ?, 'pending', 'password', ?) RETURNING id"]
    insert_account: TypedStatement<NewAccount, UserId>,
    #[sql = "UPDATE accounts SET login = ? WHERE id = ?"]
    set_login: TypedStatement<(Option<String>, UserId), ()>,
    #[sql = "UPDATE accounts SET email = ? WHERE id = ?"]
    set_email: TypedStatement<(Option<String>, UserId), ()>,
    #[sql = "UPDATE accounts SET role = ? WHERE id = ?"]
    set_role: TypedStatement<(Role, UserId), ()>,
    #[sql = "DELETE FROM accounts WHERE id = ?"]
    delete_account: TypedStatement<(UserId,), ()>,
    #[sql = "UPDATE accounts SET method = 'password', password_hash = ?, google_sub = NULL,"]
    #[sql = "access = 'active' WHERE id = ?"]
    set_password: TypedStatement<(String, UserId), ()>,
    #[sql = "UPDATE accounts SET method = 'google', password_hash = NULL, google_sub = ?,"]
    #[sql = "email = ?, access = 'active' WHERE id = ?"]
    set_google: TypedStatement<(String, String, UserId), ()>,
    #[sql = "UPDATE accounts SET google_sub = ? WHERE id = ?"]
    set_google_sub: TypedStatement<(String, UserId), ()>,
    #[sql = "UPDATE accounts SET access = ? WHERE id = ?"]
    set_access: TypedStatement<(Access, UserId), ()>,
    #[sql = "UPDATE accounts SET access = 'active' WHERE id = ? AND access = 'pending'"]
    activate: TypedStatement<(UserId,), ()>,
    #[sql = "UPDATE accounts SET access = 'revoked', password_hash = NULL WHERE id = ?"]
    revoke: TypedStatement<(UserId,), ()>,

    #[sql = "INSERT INTO sessions (id, account_id, impersonator_id, created_at, expires_at)"]
    #[sql = "VALUES (?, ?, ?, ?, ?)"]
    insert_session: TypedStatement<(String, UserId, Option<UserId>, i64, i64), ()>,
    #[sql = "DELETE FROM sessions WHERE id = ?"]
    delete_session: TypedStatement<(String,), ()>,
    #[sql = "DELETE FROM sessions WHERE account_id = ? AND id IS NOT ?"]
    delete_sessions: TypedStatement<(UserId, Option<String>), ()>,
    #[sql = "DELETE FROM sessions WHERE expires_at <= ?"]
    delete_expired_sessions: TypedStatement<(i64,), ()>,

    #[sql = "INSERT INTO links (id, account_id, kind, expires_at, used_at) VALUES (?, ?, ?, ?, ?)"]
    insert_link: TypedStatement<(String, UserId, String, i64, Option<i64>), ()>,
    #[sql = "UPDATE links SET used_at = ? WHERE account_id = ? AND used_at IS NULL"]
    use_up_links: TypedStatement<(i64, UserId), ()>,
    #[sql = "UPDATE links SET used_at = ? WHERE id = ? AND used_at IS NULL"]
    use_link: TypedStatement<(i64, String), ()>,
    #[sql = "DELETE FROM links WHERE expires_at <= ?"]
    delete_expired_links: TypedStatement<(i64,), ()>,

    #[sql = "INSERT INTO settings (key, value) VALUES (?, ?)"]
    #[sql = "ON CONFLICT (key) DO UPDATE SET value = excluded.value"]
    set_setting: TypedStatement<(String, String), ()>,
}

impl Read {
    fn user(&mut self, id: UserId) -> Result<Option<User>, Error> {
        let row = self.user.bind((id,))?.first()?;
        row.map(User::try_from).transpose()
    }

    fn user_by_email(&mut self, email: &str) -> Result<Option<User>, Error> {
        let row = self.user_by_email.bind((email,))?.first()?;
        row.map(User::try_from).transpose()
    }

    fn user_by_login(&mut self, login: &str) -> Result<Option<User>, Error> {
        let row = self.user_by_login.bind((login,))?.first()?;
        row.map(User::try_from).transpose()
    }

    fn user_by_google_sub(&mut self, sub: &str) -> Result<Option<User>, Error> {
        let row = self.user_by_google_sub.bind((sub,))?.first()?;
        row.map(User::try_from).transpose()
    }

    /// The conflict, if `login` or `email` belongs to an account other than
    /// `id`. Run inside the write transaction, so nothing changes between
    /// this check and the write it guards.
    fn conflict(
        &mut self,
        id: Option<UserId>,
        login: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<Conflict>, Error> {
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

    fn link(&mut self, id: &str) -> Result<Option<Token>, Error> {
        let row = self.link.bind((id,))?.first()?;
        row.map(Token::try_from).transpose()
    }
}

impl Write {
    /// Sets the credential and activates the account. Returns whether the
    /// account exists. A Google subject or email that belongs to another
    /// account fails on the unique constraints.
    fn set_credential(&mut self, id: UserId, cred: &Credential) -> Result<bool, Error> {
        let changed = match cred {
            Credential::Password(hash) => self.set_password.execute((hash.as_str(), id))?,
            Credential::Google { sub, email } => {
                self.set_google
                    .execute((sub.as_str(), email.as_str(), id))?
            }
        };

        Ok(changed > 0)
    }

    fn delete_sessions(&mut self, user: UserId, keep: Option<&str>) -> Result<(), Error> {
        self.delete_sessions.execute((user, keep))?;
        Ok(())
    }

    fn insert_session(&mut self, session: &Session) -> Result<(), Error> {
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

impl Store for AppStore {
    async fn user(&self, id: UserId) -> store::Result<Option<User>> {
        self.read(move |r| r.user(id)).await
    }

    async fn user_by_email(&self, email: &str) -> store::Result<Option<User>> {
        let email = email.to_owned();
        self.read(move |r| r.user_by_email(&email)).await
    }

    async fn user_by_login(&self, login: &str) -> store::Result<Option<User>> {
        let login = login.to_owned();
        self.read(move |r| r.user_by_login(&login)).await
    }

    async fn user_by_google_sub(&self, sub: &str) -> store::Result<Option<User>> {
        let sub = sub.to_owned();
        self.read(move |r| r.user_by_google_sub(&sub)).await
    }

    async fn users(&self, now: Timestamp) -> store::Result<Vec<(User, Option<Timestamp>)>> {
        self.read(move |r| {
            let mut users = Vec::new();
            let mut rows = r.users.bind((millis(now),))?;

            while let Some(row) = rows.next().transpose()? {
                let (account, link) = row.split();
                users.push((User::try_from(account)?, link.map(timestamp).transpose()?));
            }

            Ok(users)
        })
        .await
    }

    async fn user_count(&self) -> store::Result<u64> {
        self.read(|r| {
            let count = r.user_count.query()?.first()?.unwrap_or_default();
            Ok(u64::try_from(count).unwrap_or_default())
        })
        .await
    }

    async fn create_user(
        &self,
        new: &NewUser,
        now: Timestamp,
    ) -> store::Result<Result<User, Conflict>> {
        let new = new.clone();

        self.write(move |w| {
            let (login, email) = (new.login.as_deref(), new.email.as_deref());

            if let Some(conflict) = w.read.conflict(None, login, email)? {
                return Ok(Err(conflict));
            }

            // The app's own column, filled from what the store is given.
            let display_name = login.or(email).unwrap_or("user");

            let id = w
                .insert_account
                .bind((login, email, display_name, new.role, millis(now)))?
                .first()?
                .ok_or(Error::Missing("inserted account id"))?;

            let user = w.read.user(id)?.ok_or(Error::Missing("inserted account"))?;
            Ok(Ok(user))
        })
        .await
    }

    async fn update_user(
        &self,
        id: UserId,
        change: &UserChange,
    ) -> store::Result<Result<Option<User>, Conflict>> {
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

    async fn delete_user(&self, id: UserId) -> store::Result<bool> {
        // The foreign keys delete the account's sessions and links, and the
        // sessions in which it impersonates someone.
        self.write(move |w| Ok(w.delete_account.execute((id,))? > 0))
            .await
    }

    async fn set_credential(
        &self,
        id: UserId,
        cred: &Credential,
        keep: Option<&str>,
    ) -> store::Result<bool> {
        let cred = cred.clone();
        let keep = keep.map(str::to_owned);

        self.write(move |w| {
            // Read inside the transaction, so a revocation cannot land in
            // between.
            if w.read
                .access
                .bind((id,))?
                .first()?
                .is_none_or(|a| a == Access::Revoked)
            {
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

    async fn bind_google_sub(&self, id: UserId, sub: &str) -> store::Result<bool> {
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

    async fn set_access(&self, id: UserId, access: Access) -> store::Result<bool> {
        self.write(move |w| Ok(w.set_access.execute((access, id))? > 0))
            .await
    }

    async fn activate(&self, id: UserId) -> store::Result<bool> {
        // One conditional UPDATE, so a revocation in between is not undone.
        self.write(move |w| Ok(w.activate.execute((id,))? > 0))
            .await
    }

    async fn revoke(&self, id: UserId, now: Timestamp) -> store::Result<bool> {
        self.write(move |w| {
            if w.revoke.execute((id,))? == 0 {
                return Ok(false);
            }

            w.use_up_links.execute((millis(now), id))?;
            w.delete_sessions(id, None)?;
            Ok(true)
        })
        .await
    }

    async fn create_session(&self, session: &Session) -> store::Result<()> {
        let session = session.clone();

        self.write(move |w| {
            w.delete_expired_sessions
                .execute((millis(session.created_at),))?;
            w.insert_session(&session)
        })
        .await
    }

    async fn session(&self, id: &str) -> store::Result<Option<Session>> {
        let id = id.to_owned();

        self.read(move |r| {
            let row = r.session.bind((id.as_str(),))?.first()?;
            row.map(Session::try_from).transpose()
        })
        .await
    }

    async fn delete_session(&self, id: &str) -> store::Result<()> {
        let id = id.to_owned();

        self.write(move |w| {
            w.delete_session.execute((id.as_str(),))?;
            Ok(())
        })
        .await
    }

    async fn delete_sessions(&self, user: UserId, keep: Option<&str>) -> store::Result<()> {
        let keep = keep.map(str::to_owned);
        self.write(move |w| w.delete_sessions(user, keep.as_deref()))
            .await
    }

    async fn delete_expired_sessions(&self, now: Timestamp) -> store::Result<()> {
        self.write(move |w| {
            w.delete_expired_sessions.execute((millis(now),))?;
            Ok(())
        })
        .await
    }

    async fn create_token(&self, token: &Token, now: Timestamp) -> store::Result<()> {
        let token = token.clone();

        self.write(move |w| {
            w.use_up_links.execute((millis(now), token.user))?;
            w.insert_link.execute((
                token.id.as_str(),
                token.user,
                token.kind.as_str(),
                millis(token.expires_at),
                token.used_at.map(millis),
            ))?;
            Ok(())
        })
        .await
    }

    async fn token(&self, id: &str) -> store::Result<Option<Token>> {
        let id = id.to_owned();
        self.read(move |r| r.link(&id)).await
    }

    async fn delete_expired_tokens(&self, before: Timestamp) -> store::Result<()> {
        self.write(move |w| {
            w.delete_expired_links.execute((millis(before),))?;
            Ok(())
        })
        .await
    }

    async fn use_up_tokens(&self, user: UserId, now: Timestamp) -> store::Result<()> {
        self.write(move |w| {
            w.use_up_links.execute((millis(now), user))?;
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
    ) -> store::Result<bool> {
        let token = token.to_owned();
        let cred = cred.clone();
        let session = session.clone();

        self.write(move |w| {
            // Read inside the transaction, so nothing changes in between.
            let Some(link) = w.read.link(&token)? else {
                return Ok(false);
            };

            if link.used_at.is_some() {
                return Ok(false);
            }

            // Any access: a registration link re-registers a revoked user.
            if !w.set_credential(link.user, &cred)? {
                return Ok(false);
            }

            w.use_link.execute((millis(now), token.as_str()))?;
            w.delete_sessions(link.user, None)?;
            w.insert_session(&session)?;
            Ok(true)
        })
        .await
    }

    async fn config_get(&self, key: &str) -> store::Result<Option<String>> {
        let key = key.to_owned();
        self.read(move |r| Ok(r.setting.bind((key.as_str(),))?.first()?))
            .await
    }

    async fn config_set(&self, key: &str, value: &str) -> store::Result<()> {
        let (key, value) = (key.to_owned(), value.to_owned());

        self.write(move |w| {
            w.set_setting.execute((key.as_str(), value.as_str()))?;
            Ok(())
        })
        .await
    }
}

/// The store's errors, which reach watchword as a [`StoreError`].
#[derive(Debug)]
pub enum Error {
    Sql(sqll::Error),
    Pool(sqll::PoolError),
    Time(jiff::Error),
    Value(Box<dyn StdError + Send + Sync>),
    Missing(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Sql(e) => e.fmt(f),
            Error::Pool(e) => e.fmt(f),
            Error::Time(e) => e.fmt(f),
            Error::Value(e) => e.fmt(f),
            Error::Missing(what) => write!(f, "{what} is missing"),
        }
    }
}

impl StdError for Error {}

impl From<sqll::Error> for Error {
    fn from(e: sqll::Error) -> Self {
        Error::Sql(e)
    }
}

impl From<sqll::PoolError> for Error {
    fn from(e: sqll::PoolError) -> Self {
        Error::Pool(e)
    }
}

impl From<jiff::Error> for Error {
    fn from(e: jiff::Error) -> Self {
        Error::Time(e)
    }
}

impl From<Error> for StoreError {
    fn from(e: Error) -> Self {
        StoreError::new(e)
    }
}

/// An `accounts` row, as the store maps it into a [`User`].
#[derive(Row)]
struct AccountRow {
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

impl TryFrom<AccountRow> for User {
    type Error = Error;

    fn try_from(row: AccountRow) -> Result<Self, Error> {
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

/// An [`AccountRow`] with the expiry of the account's live link.
#[derive(Row)]
struct ListedRow {
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

impl ListedRow {
    fn split(self) -> (AccountRow, Option<i64>) {
        let account = AccountRow {
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

        (account, self.link)
    }
}

#[derive(Row)]
struct SessionRow {
    id: String,
    account_id: UserId,
    impersonator_id: Option<UserId>,
    created_at: i64,
    expires_at: i64,
}

impl TryFrom<SessionRow> for Session {
    type Error = Error;

    fn try_from(row: SessionRow) -> Result<Self, Error> {
        Ok(Session {
            id: row.id,
            user: row.account_id,
            impersonator: row.impersonator_id,
            created_at: timestamp(row.created_at)?,
            expires_at: timestamp(row.expires_at)?,
        })
    }
}

#[derive(Row)]
struct LinkRow {
    id: String,
    account_id: UserId,
    kind: String,
    expires_at: i64,
    used_at: Option<i64>,
}

impl TryFrom<LinkRow> for Token {
    type Error = Error;

    fn try_from(row: LinkRow) -> Result<Self, Error> {
        Ok(Token {
            id: row.id,
            user: row.account_id,
            kind: row
                .kind
                .parse::<TokenKind>()
                .map_err(|e| Error::Value(e.into()))?,
            expires_at: timestamp(row.expires_at)?,
            used_at: row.used_at.map(timestamp).transpose()?,
        })
    }
}

/// A stored time, in milliseconds since the Unix epoch.
fn millis(timestamp: Timestamp) -> i64 {
    timestamp.as_millisecond()
}

fn timestamp(millis: i64) -> Result<Timestamp, Error> {
    Ok(Timestamp::from_millisecond(millis)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // watchword's store conformance suite: one test per rule, each over a
    // new database.
    watchword::store_suite!(AppStore::open_scratch()?);

    #[tokio::test]
    async fn fills_the_display_name() -> Result<(), Box<dyn StdError>> {
        let store = AppStore::open_scratch()?;
        let new = NewUser {
            login: None,
            email: Some("ada@example.com".into()),
            role: Role::Regular,
        };

        let user = store.create_user(&new, Timestamp::now()).await?;
        let user = user.expect("no conflict");
        let name = store.display_name(user.id).await?;
        assert_eq!(name.as_deref(), Some("ada@example.com"));
        Ok(())
    }
}
