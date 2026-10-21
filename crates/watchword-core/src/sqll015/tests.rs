use sqll015::{Code, Connection, Result};

use crate::{Access, Method, Role, UserId};

fn connection() -> Result<Connection> {
    let c = Connection::open_in_memory()?;

    c.execute(
        "CREATE TABLE users (id INTEGER, role TEXT, access TEXT, method TEXT, parent INTEGER);",
    )?;

    Ok(c)
}

#[test]
fn round_trip() -> Result<()> {
    let c = connection()?;

    let rows = [
        (
            UserId(1),
            Role::Admin,
            Access::Pending,
            Method::Password,
            None,
        ),
        (
            UserId(i64::MAX as u64),
            Role::Regular,
            Access::Active,
            Method::Google,
            Some(UserId(1)),
        ),
        (
            UserId(u64::MAX),
            Role::Regular,
            Access::Revoked,
            Method::Password,
            Some(UserId(u64::MAX)),
        ),
    ];

    let mut insert = c.prepare("INSERT INTO users VALUES (?, ?, ?, ?, ?)")?;

    for row in rows {
        insert.execute(row)?;
        insert.reset()?;
    }

    let mut select =
        c.prepare("SELECT id, role, access, method, parent FROM users ORDER BY rowid")?;

    for row in rows {
        assert_eq!(
            select.next::<(UserId, Role, Access, Method, Option<UserId>)>()?,
            Some(row)
        );
    }

    assert_eq!(
        select.next::<(UserId, Role, Access, Method, Option<UserId>)>()?,
        None
    );
    Ok(())
}

#[test]
fn stored_form() -> Result<()> {
    let c = connection()?;

    let mut insert = c.prepare("INSERT INTO users VALUES (?, ?, ?, ?, NULL)")?;
    insert.execute((
        UserId(u64::MAX),
        Role::Admin,
        Access::Active,
        Method::Google,
    ))?;

    let mut select = c.prepare("SELECT id, role, access, method FROM users")?;

    assert_eq!(
        select.next::<(i64, &str, &str, &str)>()?,
        Some((-1, "admin", "active", "google"))
    );

    Ok(())
}

#[test]
fn single_parameter() -> Result<()> {
    let c = connection()?;
    c.execute("INSERT INTO users VALUES (7, 'admin', 'active', 'password', NULL)")?;

    let mut select = c.prepare("SELECT id FROM users WHERE id = ?")?;
    select.bind(UserId(7))?;
    assert_eq!(select.next::<UserId>()?, Some(UserId(7)));

    let mut select = c.prepare("SELECT id FROM users WHERE role = ?")?;
    select.bind(Role::Admin)?;
    assert_eq!(select.next::<UserId>()?, Some(UserId(7)));
    Ok(())
}

#[test]
fn unknown_name() -> Result<()> {
    let c = connection()?;
    c.execute("INSERT INTO users VALUES (1, 'owner', 'gone', 'magic', NULL)")?;

    let mut select = c.prepare("SELECT role FROM users")?;
    assert_eq!(select.next::<Role>().unwrap_err().code(), Code::MISMATCH);

    let mut select = c.prepare("SELECT access FROM users")?;
    assert_eq!(select.next::<Access>().unwrap_err().code(), Code::MISMATCH);

    let mut select = c.prepare("SELECT method FROM users")?;
    assert_eq!(select.next::<Method>().unwrap_err().code(), Code::MISMATCH);
    Ok(())
}
