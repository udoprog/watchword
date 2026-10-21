use std::string::String;
use std::sync::atomic::{AtomicU64, Ordering};
use std::vec::Vec;

use sqll014::{Connection, OpenOptions, PoolBuilder};

use super::*;
use crate::core::{Auth, generate_session_key, new_session_id};
use crate::store::suite::{TestResult, store_suite};

store_suite!(store(&scratch_uri(), true));

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

/// A connection to the database at `uri`, without foreign keys, as an app's
/// migration connection may be.
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
/// back, as a migration runner would.
fn migrate(c: &Connection, sql: &str) -> sqll014::Result<()> {
    c.execute("BEGIN IMMEDIATE")?;

    let result = c.execute(sql).and_then(|()| c.execute("COMMIT"));

    if result.is_err() {
        _ = c.execute("ROLLBACK");
    }

    result
}

fn count(c: &Connection, sql: &str) -> i64 {
    let mut stmt = c.prepare(sql).expect("prepare");
    stmt.next::<i64>().expect("step").expect("row")
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
