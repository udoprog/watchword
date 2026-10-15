use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use sqll014::{Connection, OpenOptions, PoolBuilder};

use super::*;
use crate::core::{Auth, generate_session_key, hash_password, new_session_id};
use crate::store::suite::{TestResult, store_suite};
use crate::types::LoginRequest;

store_suite!(store(&scratch_uri(), true));

const TRACK_MIGRATION: &str = include_str!("../../docs/sqll/track.sql");
const TERRITORY_MIGRATION: &str = include_str!("../../docs/sqll/territory.sql");
const IMPERSONATOR_MIGRATION: &str = include_str!("../../docs/sqll/impersonator.sql");

/// A new in-memory database's URI, shared by every connection that opens it
/// while one is open.
fn scratch_uri() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!(
        "file:watchword-sqll-{}-{n}?mode=memory&cache=shared",
        std::process::id()
    )
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.uri().no_mutex().create();
    options
}

/// A connection to the database at `uri`, without foreign keys, like the
/// migration connections of track and territory.
fn connect(uri: &str) -> Connection {
    options().read_write().open(uri).expect("open")
}

/// A store over a pool on `uri`, which creates the schema first when
/// `create` is set. Its connections enforce foreign keys.
fn store(uri: &str, create: bool) -> SqllStore {
    let pool = PoolBuilder::new(options(), 2)
        .with_write_setup(move |c| {
            c.execute("PRAGMA foreign_keys = ON")?;

            if create {
                c.execute(SCHEMA)?;
            }

            Ok(())
        })
        .with_read_setup(|c| c.execute("PRAGMA foreign_keys = ON"))
        .open(uri)
        .expect("open pool");

    SqllStore::new(Arc::new(pool))
}

/// Runs `sql` as a migration: in one transaction, which a failure rolls
/// back, as both apps' migration runners do.
fn migrate(c: &Connection, sql: &str) -> sqll014::Result<()> {
    c.execute("BEGIN IMMEDIATE")?;

    let result = c.execute(sql).and_then(|()| c.execute("COMMIT"));

    if result.is_err() {
        _ = c.execute("ROLLBACK");
    }

    result
}

/// Executes a prepared statement again.
fn run(stmt: &mut sqll014::Statement, bind: impl sqll014::Bind) -> sqll014::Result<()> {
    stmt.reset()?;
    stmt.execute(bind)
}

fn count(c: &Connection, sql: &str) -> i64 {
    let mut stmt = c.prepare(sql).expect("prepare");
    stmt.next::<i64>().expect("step").expect("row")
}

fn ip() -> IpAddr {
    IpAddr::from([192, 0, 2, 1])
}

fn login(name: &str, password: &str) -> LoginRequest {
    LoginRequest {
        login: name.to_owned(),
        password: password.to_owned(),
    }
}

/// Times as the store keeps them, with millisecond precision.
fn ms(t: Timestamp) -> Timestamp {
    Timestamp::from_millisecond(t.as_millisecond()).unwrap()
}

#[tokio::test]
async fn schema_can_be_run_again() -> TestResult {
    let uri = scratch_uri();
    let store = store(&uri, true);
    store.config_set("session_key", "a").await?;

    let c = connect(&uri);
    c.execute(SCHEMA)?;

    assert_eq!(store.config_get("session_key").await?.as_deref(), Some("a"));
    store.config_set("session_key", "b").await?;
    assert_eq!(store.config_get("session_key").await?.as_deref(), Some("b"));
    Ok(())
}

/// A database made with the schema from before sessions recorded their
/// impersonator takes the column from `docs/sqll/impersonator.sql`.
#[tokio::test]
async fn adds_the_impersonator_column() -> TestResult {
    let column = "        impersonator_id INTEGER REFERENCES users (id) ON DELETE CASCADE,\n";
    assert!(SCHEMA.contains(column));
    let before = SCHEMA.replace(column, "");

    let uri = scratch_uri();
    let c = connect(&uri);
    c.execute(&before)?;
    c.execute(
        "INSERT INTO users (id, login, role, access, created_at) VALUES \
         (1, 'root', 'admin', 'active', 0), (2, 'bob', 'regular', 'active', 0);
         INSERT INTO sessions (id, user_id, created_at, expires_at) \
         VALUES ('old', 2, 0, 9999999999999);",
    )?;
    migrate(&c, IMPERSONATOR_MIGRATION)?;

    let store = store(&uri, false);
    let old = store.session("old").await?.unwrap();
    assert_eq!((old.user, old.impersonator), (UserId(2), None));

    let auth = Auth::builder(store.clone(), generate_session_key())
        .impersonation(true)
        .build();
    let root = store.user(UserId(1)).await?.unwrap();
    let (_, session) = auth
        .impersonate(&root, &root_session(&old), UserId(2))
        .await?;
    let stored = store.session(&session.id).await?.unwrap();
    assert_eq!(stored.impersonator, Some(UserId(1)));

    // The column references users: deleting the admin removes the session.
    assert!(store.delete_user(UserId(1)).await?);
    assert!(store.session(&session.id).await?.is_none());
    assert!(store.session("old").await?.is_some());
    assert_eq!(
        count(&c, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
    Ok(())
}

/// A session of the admin's own that is not impersonated, standing in for
/// the one an admin acts from.
fn root_session(other: &Session) -> Session {
    Session {
        id: new_session_id(),
        user: UserId(1),
        impersonator: None,
        ..other.clone()
    }
}

#[tokio::test]
async fn timestamps_are_stored_as_integer_milliseconds() -> TestResult {
    let uri = scratch_uri();
    let store = store(&uri, true);

    let now = Timestamp::now();
    let new = NewUser {
        login: Some("a".to_owned()),
        email: None,
        role: Role::Regular,
    };
    let user = store.create_user(&new, now).await?.unwrap();
    assert_eq!(user.created_at, ms(now));

    let c = connect(&uri);
    let mut stmt = c.prepare("SELECT typeof(created_at), created_at FROM users")?;
    let row = stmt.next::<(String, i64)>()?.unwrap();
    assert_eq!(row, ("integer".to_owned(), now.as_millisecond()));
    Ok(())
}

/// track's auth tables as of track 49dcf8c, with a table of its own that
/// references users.
const TRACK_BEFORE: &str = r#"
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    login TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    role TEXT NOT NULL,
    password_hash TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX idx_sessions_user ON sessions (user_id);

CREATE TABLE login_tokens (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

CREATE INDEX idx_login_tokens_user ON login_tokens (user_id);

CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE user_config (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (user_id, key)
);

-- The administrator "root" with the password "root".
INSERT INTO users (login, role, password_hash, created_at)
VALUES ('root', 'admin', '$2y$12$jxThPHsK8E/RT.IrJcuNfO6Deoc5a7DkfUZ0cLhM2TZsbPT0MvIwO', 1700000000123);

INSERT INTO users (login, email, role, created_at)
VALUES ('bob', 'bob@example.com', 'regular', 1700000000456);

INSERT INTO login_tokens (id, user_id, expires_at, used_at) VALUES ('bob-link', 2, 32503680000000, NULL);
INSERT INTO login_tokens (id, user_id, expires_at, used_at) VALUES ('old-link', 2, 32503680000000, 1700000001000);
INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES ('root-session', 1, 1700000000000, 32503680000000);
INSERT INTO config (key, value) VALUES ('session_key', 'key');
INSERT INTO user_config (user_id, key, value) VALUES (2, 'theme', '"dark"');
"#;

#[tokio::test]
async fn migrates_track() -> TestResult {
    let uri = scratch_uri();
    let c = connect(&uri);
    c.execute(TRACK_BEFORE)?;
    migrate(&c, TRACK_MIGRATION)?;

    let store = store(&uri, false);
    let auth = Auth::builder(store.clone(), generate_session_key())
        .logins(true)
        .build();

    // Users keep their ids, logins, emails, roles and hashes, and are active.
    let root = store.user_by_login("root").await?.unwrap();
    assert_eq!(root.id, UserId(1));
    assert_eq!((root.role, root.access), (Role::Admin, Access::Active));
    assert_eq!(root.method, Method::Password);
    assert_eq!(root.created_at, Timestamp::from_millisecond(1700000000123)?);

    let (user, _) = auth.sign_in_password(ip(), &login("root", "root")).await?;
    assert_eq!(user.id, root.id);

    let bob = store.user_by_email("bob@example.com").await?.unwrap();
    assert_eq!((bob.id, bob.access), (UserId(2), Access::Active));
    assert_eq!(bob.password_hash, None);

    // Sessions survive; the outstanding link is a usable reset link.
    assert!(auth.session("root-session").await?.is_some());
    let link = store.token("bob-link").await?.unwrap();
    assert_eq!((link.kind, link.used_at), (TokenKind::Reset, None));
    assert!(auth.register_info("bob-link").await.is_ok());
    let old = store.token("old-link").await?.unwrap();
    assert_eq!(
        old.used_at,
        Some(Timestamp::from_millisecond(1700000001000)?)
    );
    assert_eq!(
        store.config_get("session_key").await?.as_deref(),
        Some("key")
    );

    // Logins are optional now.
    let new = NewUser {
        login: None,
        email: Some("carol@example.com".to_owned()),
        role: Role::Regular,
    };
    assert!(store.create_user(&new, Timestamp::now()).await?.is_ok());

    // The app's own table still references users and cascades.
    assert_eq!(count(&c, "SELECT COUNT(*) FROM user_config"), 1);
    assert!(store.delete_user(bob.id).await?);
    assert_eq!(count(&c, "SELECT COUNT(*) FROM user_config"), 0);
    assert_eq!(
        count(&c, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
    Ok(())
}

#[tokio::test]
async fn track_migration_refuses_to_run_with_foreign_keys_on() -> TestResult {
    let uri = scratch_uri();
    let c = connect(&uri);
    c.execute(TRACK_BEFORE)?;
    c.execute("PRAGMA foreign_keys = ON")?;

    assert!(migrate(&c, TRACK_MIGRATION).is_err());

    // Nothing changed, and nothing cascaded.
    assert_eq!(count(&c, "SELECT COUNT(*) FROM users"), 2);
    assert_eq!(count(&c, "SELECT COUNT(*) FROM user_config"), 1);
    assert_eq!(count(&c, "SELECT COUNT(*) FROM login_tokens"), 2);
    Ok(())
}

/// territory's auth tables as of territory 154ff85 (its migrations up to
/// 2026-10-05c), with its groups.
const TERRITORY_BEFORE: &str = r#"
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('admin', 'regular')),
    password_hash TEXT,
    created_at TEXT NOT NULL,
    auth_method TEXT NOT NULL DEFAULT 'plain',
    access TEXT NOT NULL DEFAULT 'pending',
    google_sub TEXT
);

CREATE UNIQUE INDEX users_google_sub ON users (google_sub);

CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);

CREATE TABLE group_users (
    group_id INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE registration_tokens (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    kind TEXT NOT NULL DEFAULT 'registration'
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"#;

#[tokio::test]
async fn migrates_territory() -> TestResult {
    let uri = scratch_uri();
    let c = connect(&uri);
    c.execute(TERRITORY_BEFORE)?;

    // Times as jiff writes them, with sub-millisecond digits, which the
    // migration rounds to the nearest millisecond.
    let created: Timestamp = "2026-10-14T12:34:56.123456789Z".parse()?;
    let expires: Timestamp = "2999-11-13T12:34:56.5Z".parse()?;
    let used: Timestamp = "2026-10-14T11:34:56.9996Z".parse()?;
    let hash = hash_password("correct horse battery staple")?;

    let mut insert = c.prepare(
        "INSERT INTO users (email, role, password_hash, created_at, auth_method, access, google_sub) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )?;
    let at = created.to_string();
    run(
        &mut insert,
        (
            "a@example.com",
            "admin",
            Some(hash.as_str()),
            at.as_str(),
            "plain",
            "active",
            None::<&str>,
        ),
    )?;
    run(
        &mut insert,
        (
            "g@example.com",
            "regular",
            None::<&str>,
            at.as_str(),
            "google",
            "active",
            Some("sub:g"),
        ),
    )?;
    run(
        &mut insert,
        (
            "legacy@example.com",
            "regular",
            None::<&str>,
            at.as_str(),
            "google",
            "active",
            None::<&str>,
        ),
    )?;
    run(
        &mut insert,
        (
            "p@example.com",
            "regular",
            None::<&str>,
            at.as_str(),
            "plain",
            "pending",
            None::<&str>,
        ),
    )?;

    let session = new_session_id();
    let mut insert = c.prepare("INSERT INTO sessions VALUES (?, 1, ?, ?)")?;
    run(
        &mut insert,
        (session.as_str(), at.as_str(), expires.to_string().as_str()),
    )?;

    let mut insert = c.prepare(
        "INSERT INTO registration_tokens (id, user_id, expires_at, used_at, kind) VALUES (?, 4, ?, ?, ?)",
    )?;
    let exp = expires.to_string();
    run(
        &mut insert,
        ("live", exp.as_str(), None::<&str>, "registration"),
    )?;
    run(
        &mut insert,
        (
            "used",
            exp.as_str(),
            Some(used.to_string().as_str()),
            "registration",
        ),
    )?;

    c.execute("INSERT INTO groups (name) VALUES ('g'); INSERT INTO group_users VALUES (1, 2);")?;

    // Territory's connections may enforce foreign keys; the migration is
    // safe either way.
    c.execute("PRAGMA foreign_keys = ON")?;
    migrate(&c, TERRITORY_MIGRATION)?;

    let store = store(&uri, false);
    let auth = Auth::builder(store.clone(), generate_session_key())
        .logins(false)
        .build();

    let admin = store.user(UserId(1)).await?.unwrap();
    assert_eq!(admin.email.as_deref(), Some("a@example.com"));
    assert_eq!(admin.login, None);
    assert_eq!(
        (admin.method, admin.access),
        (Method::Password, Access::Active)
    );
    assert_eq!(admin.created_at, ms(created));

    let (user, _) = auth
        .sign_in_password(
            ip(),
            &login("a@example.com", "correct horse battery staple"),
        )
        .await?;
    assert_eq!(user.id, admin.id);

    // Sessions keep their times, to the millisecond.
    let stored = store.session(&session).await?.unwrap();
    assert_eq!((stored.user, stored.created_at), (admin.id, ms(created)));
    assert_eq!(stored.expires_at, expires);
    assert!(auth.session(&session).await?.is_some());

    // Google users sign in by subject, and legacy ones are bound by email.
    let (user, _) = auth.sign_in_google("sub:g", "g@example.com").await?;
    assert_eq!((user.id, user.method), (UserId(2), Method::Google));
    let (user, _) = auth
        .sign_in_google("sub:legacy", "legacy@example.com")
        .await?;
    assert_eq!(user.google_sub.as_deref(), Some("sub:legacy"));

    // Links keep their kind and times, and the pending user can register.
    let live = store.token("live").await?.unwrap();
    assert_eq!(
        (live.kind, live.expires_at),
        (TokenKind::Registration, expires)
    );
    let old = store.token("used").await?.unwrap();
    assert_eq!(old.used_at, Some(ms(used)));
    let info = auth.register_info("live").await?;
    assert_eq!(info.email.as_deref(), Some("p@example.com"));

    // The app's groups still reference users.
    assert_eq!(count(&c, "SELECT COUNT(*) FROM group_users"), 1);
    assert!(store.delete_user(UserId(2)).await?);
    assert_eq!(count(&c, "SELECT COUNT(*) FROM group_users"), 0);
    assert_eq!(
        count(&c, "SELECT COUNT(*) FROM pragma_foreign_key_check"),
        0
    );
    Ok(())
}

/// An app's read statements with the store's nested, as the module
/// documentation shows.
#[derive(sqll014::Statements)]
#[sql(crate = sqll014)]
#[sql(read_only)]
struct AppRead {
    #[sql(statements)]
    auth: Read,
    #[sql = "SELECT login FROM users WHERE login LIKE ? ORDER BY login"]
    logins_like: sqll014::TypedStatement<(String,), String>,
    #[sql = "SELECT login FROM users ORDER BY login LIMIT ?"]
    first_logins: sqll014::TypedStatement<(i64,), String>,
}

impl AsMut<Read> for AppRead {
    fn as_mut(&mut self) -> &mut Read {
        &mut self.auth
    }
}

/// The write side of [`AppRead`].
#[derive(sqll014::Statements)]
#[sql(crate = sqll014)]
struct AppWrite {
    #[sql(statements)]
    auth: Write,
    #[sql = "SELECT login FROM users WHERE login LIKE ? ORDER BY login"]
    logins_like: sqll014::TypedStatement<(String,), String>,
    #[sql = "SELECT login FROM users ORDER BY login LIMIT ?"]
    first_logins: sqll014::TypedStatement<(i64,), String>,
}

impl AsMut<Write> for AppWrite {
    fn as_mut(&mut self) -> &mut Write {
        &mut self.auth
    }
}

fn logins<I: sqll014::Bind>(
    stmt: &mut sqll014::TypedStatement<I, String>,
    bind: impl sqll014::Bind,
) -> sqll014::Result<Vec<String>> {
    let mut stmt = stmt.bind(bind)?;
    let mut out = Vec::new();

    while let Some(login) = stmt.next()? {
        out.push(login);
    }

    Ok(out)
}

/// The store shares an app's pool, whose own statements include ones SQLite
/// re-prepares on every bind (a bare `LIKE ?` or `LIMIT ?`). Those fail with
/// "bad parameter or other API misuse" on sqll before 0.14.6, whose pool
/// closed the connections its statements were prepared on.
#[tokio::test]
async fn shares_an_app_pool() -> TestResult {
    let pool = PoolBuilder::new(options(), 2)
        .with_write_setup(|c| c.execute(SCHEMA))
        .open::<AppRead, AppWrite>(scratch_uri())?;
    let pool = Arc::new(pool);
    let store = SqllStore::new(pool.clone());

    for name in ["alice", "alex", "bob"] {
        let new = NewUser {
            login: Some(name.to_owned()),
            email: None,
            role: Role::Regular,
        };
        store.create_user(&new, Timestamp::now()).await?.unwrap();
    }

    assert!(store.user_by_login("alex").await?.is_some());

    for _ in 0..2 {
        let mut read = pool.clone().shared().await?;
        assert_eq!(logins(&mut read.logins_like, ("al%",))?, ["alex", "alice"]);
        assert_eq!(logins(&mut read.logins_like, ("b%",))?, ["bob"]);
        assert_eq!(logins(&mut read.first_logins, (1,))?, ["alex"]);
        assert_eq!(logins(&mut read.first_logins, (2,))?, ["alex", "alice"]);
    }

    let mut write = pool.clone().exclusive().await?;
    assert_eq!(logins(&mut write.logins_like, ("al%",))?, ["alex", "alice"]);
    assert_eq!(
        logins(&mut write.first_logins, (3,))?,
        ["alex", "alice", "bob"]
    );
    Ok(())
}
