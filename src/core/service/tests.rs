use std::boxed::Box;

use http::{HeaderMap, HeaderValue, header};

use super::*;
use crate::store::MemoryStore;
use crate::types::{NewUser, PasswordChange};

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();

    for (name, value) in pairs {
        headers.append(*name, HeaderValue::from_str(value).unwrap());
    }

    headers
}

fn auth(cookie: CookieConfig) -> Auth {
    Auth::builder(MemoryStore::new(), generate_session_key())
        .cookie(cookie)
        .build()
}

#[test]
fn cookies_round_trip() {
    let auth = auth(CookieConfig::new("track_session"));

    let set = auth.set_cookie(&HeaderMap::new(), "abc_-123");
    let set = set.to_str().unwrap();
    assert!(set.starts_with("track_session=abc_-123."), "{set}");
    assert!(set.contains("HttpOnly"), "{set}");
    assert!(set.contains("SameSite=Strict"), "{set}");
    assert!(set.contains("Max-Age=2592000"), "{set}");
    assert!(!set.contains("Secure"), "{set}");
    assert!(!set.contains("Expires"), "{set}");

    let value = auth.cookie_header("abc_-123");
    let value = value.to_str().unwrap();
    assert!(set.starts_with(&format!("{value};")), "{set}");
    assert!(!value.contains(';'), "{value}");
    let request = headers(&[(header::COOKIE.as_str(), &format!("other=1; {value}"))]);
    assert_eq!(auth.session_id(&request).as_deref(), Some("abc_-123"));

    // Another name, a bad signature or another key are ignored.
    let other = auth_with_name("territory_session");
    assert_eq!(other.session_id(&request), None);
    let tampered = headers(&[(header::COOKIE.as_str(), "track_session=abd.AAAA")]);
    assert_eq!(auth.session_id(&tampered), None);
    let foreign = Auth::builder(MemoryStore::new(), generate_session_key())
        .cookie(CookieConfig::new("track_session"))
        .build();
    assert_eq!(foreign.session_id(&request), None);

    let clear = auth.clear_cookie(&HeaderMap::new());
    let clear = clear.to_str().unwrap();
    assert!(clear.starts_with("track_session=;"), "{clear}");
    assert!(clear.contains("Max-Age=0"), "{clear}");
}

fn auth_with_name(name: &'static str) -> Auth {
    auth(CookieConfig::new(name))
}

#[test]
fn secure_follows_the_config() {
    let https = headers(&[("x-forwarded-proto", "HTTPS, http")]);
    let http = headers(&[("x-forwarded-proto", "http")]);

    let is_secure = |secure, headers: &HeaderMap| {
        let auth = auth(CookieConfig {
            name: "s".into(),
            secure,
        });
        let set = auth.set_cookie(headers, "abc");
        let clear = auth.clear_cookie(headers);
        let set = set.to_str().unwrap().contains("Secure");
        assert_eq!(set, clear.to_str().unwrap().contains("Secure"));
        set
    };

    assert!(is_secure(Secure::Auto, &https));
    assert!(!is_secure(Secure::Auto, &http));
    assert!(!is_secure(Secure::Auto, &HeaderMap::new()));
    assert!(is_secure(Secure::Always, &http));
    assert!(!is_secure(Secure::Never, &https));
}

#[tokio::test]
async fn key_is_created_once_and_read_in_either_encoding() {
    let store = MemoryStore::new();
    let key = load_or_create_key(&store).await.unwrap();
    assert_eq!(load_or_create_key(&store).await.unwrap(), key);
    assert_eq!(
        store.config_get(SESSION_KEY).await.unwrap(),
        Some(STANDARD.encode(key))
    );

    // Standard padded base64, with whitespace.
    let padded = [7u8; 32];
    store
        .config_set(SESSION_KEY, &format!(" {}\n", STANDARD.encode(padded)))
        .await
        .unwrap();
    assert_eq!(load_or_create_key(&store).await.unwrap(), padded);

    // Unpadded base64url.
    let url_safe = [0xfbu8; 32];
    store
        .config_set(SESSION_KEY, &URL_SAFE_NO_PAD.encode(url_safe))
        .await
        .unwrap();
    assert_eq!(load_or_create_key(&store).await.unwrap(), url_safe);

    store.config_set(SESSION_KEY, "c2hvcnQ=").await.unwrap();
    assert!(load_or_create_key(&store).await.is_err());
    store.config_set(SESSION_KEY, "!!!").await.unwrap();
    assert!(load_or_create_key(&store).await.is_err());
}

#[test]
fn bootstrap_admin_names() {
    assert_eq!(BootstrapAdmin::new("a@b.c"), BootstrapAdmin::email("a@b.c"));
    assert_eq!(BootstrapAdmin::new("root"), BootstrapAdmin::login("root"));
    assert_eq!(
        BootstrapAdmin::new("root")
            .public_url(Some("https://x"))
            .public_url,
        Some("https://x".to_owned())
    );
}

/// A user revoked after a password change read them is refused, and keeps
/// no password.
#[tokio::test]
async fn a_concurrent_revocation_refuses_a_password_change()
-> Result<(), Box<dyn std::error::Error>> {
    let store = MemoryStore::new();
    let auth = Auth::builder(store.clone(), generate_session_key()).build();

    let new = NewUser {
        login: None,
        email: Some("erin@example.com".to_owned()),
        role: Role::Regular,
    };
    let user = Store::create_user(&store, &new, Timestamp::now())
        .await?
        .unwrap();
    let cred = Credential::Password(hash_blocking("first password here").await?);
    assert!(Store::set_credential(&store, user.id, &cred, None).await?);
    let user = Store::user(&store, user.id).await?.unwrap();
    let session = auth.create_session(user.id).await?;

    let change = PasswordChange {
        old_password: Some("first password here".to_owned()),
        new_password: "second password here".to_owned(),
    };

    store.revoke_before_next_write(user.id);
    let error = auth.change_password(&user, &session, &change).await;
    assert_eq!(
        error.err().and_then(|e| e.auth_error().cloned()),
        Some(AuthError::Unauthorized)
    );

    let user = Store::user(&store, user.id).await?.unwrap();
    assert_eq!(user.access, Access::Revoked);
    assert_eq!(user.password_hash, None);
    Ok(())
}

/// An internal failure's message carries its cause once: in the message,
/// not again in its source.
#[test]
fn internal_errors_show_their_cause() {
    let error = Error::from(StoreError::new("the disk is full"));
    assert_eq!(error.to_string(), "storage failed: the disk is full");
    assert!(StdError::source(&error).is_none());
    assert_eq!(error.auth_error(), None);
    assert_eq!(Error::find_auth_error(&error), None);

    let error = Error::from(AuthError::Forbidden);
    assert_eq!(error.to_string(), AuthError::Forbidden.to_string());
    assert_eq!(Error::find_auth_error(&error), Some(&AuthError::Forbidden));
    assert_eq!(
        Error::find_auth_error(&AuthError::Gone),
        Some(&AuthError::Gone)
    );
}

/// Each operation sends one audit event naming who acted, an admin acting
/// through an impersonated session included, and read-only operations,
/// sign-ins, sign-outs and changes that change nothing send none.
#[tokio::test]
async fn operations_send_actor_attributed_audit_events() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Mutex;

    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();

    let auth = Auth::builder(MemoryStore::new(), generate_session_key())
        .impersonation(true)
        .audit(move |event| sink.lock().unwrap().push(event.clone()))
        .build();

    let take = || std::mem::take(&mut *log.lock().unwrap());
    let password = |p: &str| RegisterRequest {
        password: p.to_owned(),
    };

    // The system bootstraps the first admin, who registers.
    let link = auth
        .bootstrap_admin(&BootstrapAdmin::login("root"))
        .await?
        .link()
        .cloned()
        .ok_or("no link")?;
    let (root, root_session) = auth
        .register(&link.token, &password("root password 1"))
        .await?;

    let events = take();
    assert_eq!(events.len(), 3, "{events:?}");
    assert!(matches!(
        &events[0],
        AuditEvent::UserCreated { actor: Actor::System, user } if user.id == root.id
    ));
    assert!(matches!(
        &events[1],
        AuditEvent::LinkIssued { actor: Actor::System, user, expires_at }
            if *user == root.id && *expires_at == link.expires_at
    ));
    assert_eq!(
        events[2],
        AuditEvent::LinkRedeemed {
            actor: Actor::user(root.id),
            user: root.info(),
        }
    );
    let by_root = Actor::of(&root, &root_session);
    assert_eq!(by_root, Actor::user(root.id));

    // Root creates pat, who registers, and promotes them.
    let new = NewUser {
        login: Some("pat".to_owned()),
        email: None,
        role: Role::Regular,
    };
    let (entry, link) = auth.create_user(&root, &root_session, &new).await?;
    let (pat, _) = auth
        .register(&link.token, &password("pat password 12"))
        .await?;
    let events = take();
    assert_eq!(events.len(), 3, "{events:?}");
    assert_eq!(
        events[0],
        AuditEvent::UserCreated {
            actor: by_root,
            user: entry.user.clone(),
        }
    );
    assert_eq!(events[1].actor(), by_root);
    assert_eq!(events[1].user(), Some(pat.id));

    let promoted = auth
        .set_role(&root, &root_session, pat.id, Role::Admin)
        .await?;
    assert_eq!(
        take(),
        [AuditEvent::UserUpdated {
            actor: by_root,
            before: pat.info(),
            after: promoted.info(),
        }]
    );

    // Setting the same role again changes nothing, and reading and signing
    // in send nothing.
    auth.set_role(&root, &root_session, pat.id, Role::Admin)
        .await?;
    auth.users(&root).await?;
    let login = LoginRequest {
        login: "pat".to_owned(),
        password: "pat password 12".to_owned(),
    };
    let (_, pat_session) = auth
        .sign_in_password(IpAddr::from([127, 0, 0, 1]), &login)
        .await?;
    auth.sign_out(&pat_session.id).await?;
    assert_eq!(take(), []);

    // Root impersonates pat, now an admin, and acts as them: the events
    // name root as the impersonator, and as the one responsible.
    let (as_pat, as_pat_session) = auth.impersonate(&root, &root_session, pat.id).await?;
    let by_root_as_pat = Actor::of(&as_pat, &as_pat_session);
    assert_eq!(
        by_root_as_pat,
        Actor::User {
            user: pat.id,
            impersonator: Some(root.id),
        }
    );
    assert_eq!(by_root_as_pat.responsible(), Some(root.id));

    let new = NewUser {
        login: Some("eve".to_owned()),
        email: None,
        role: Role::Regular,
    };
    let (eve, _) = auth.create_user(&as_pat, &as_pat_session, &new).await?;
    let eve = eve.user;
    let change = PasswordChange {
        old_password: Some("pat password 12".to_owned()),
        new_password: "pat password 13".to_owned(),
    };
    let as_pat = auth
        .change_password(&as_pat, &as_pat_session, &change)
        .await?;
    auth.stop_impersonating(&as_pat_session).await?;

    let events = take();
    assert_eq!(events.len(), 5, "{events:?}");
    assert_eq!(
        events[0],
        AuditEvent::ImpersonationStarted {
            admin: root.id,
            user: pat.id,
        }
    );
    assert_eq!(events[0].actor(), by_root);
    assert_eq!(
        events[1],
        AuditEvent::UserCreated {
            actor: by_root_as_pat,
            user: eve.clone(),
        }
    );
    assert_eq!(events[2].actor(), by_root_as_pat);
    assert_eq!(
        events[3],
        AuditEvent::CredentialChanged {
            actor: by_root_as_pat,
            user: as_pat.info(),
        }
    );
    assert_eq!(
        events[4],
        AuditEvent::ImpersonationStopped {
            admin: root.id,
            user: pat.id,
        }
    );

    // Root's other admin operations on eve.
    let link = auth.issue_link(&root, &root_session, eve.id).await?;
    auth.revoke_link(&root, &root_session, eve.id).await?;
    auth.sign_out_everywhere(&root, &root_session, eve.id)
        .await?;
    let revoked = auth.revoke_access(&root, &root_session, eve.id).await?;
    let before_delete = auth.store().user(eve.id).await?.ok_or("eve")?;
    auth.delete_user(&root, &root_session, eve.id).await?;

    assert_eq!(
        take(),
        [
            AuditEvent::LinkIssued {
                actor: by_root,
                user: eve.id,
                expires_at: link.expires_at,
            },
            AuditEvent::LinkRevoked {
                actor: by_root,
                user: eve.id,
            },
            AuditEvent::SignedOutEverywhere {
                actor: by_root,
                user: eve.id,
            },
            AuditEvent::AccessRevoked {
                actor: by_root,
                before: eve.clone(),
                after: revoked.info(),
            },
            AuditEvent::UserDeleted {
                actor: by_root,
                user: before_delete.info(),
            },
        ]
    );

    // A refused operation sends nothing.
    assert!(
        auth.delete_user(&root, &root_session, eve.id)
            .await
            .is_err()
    );
    assert_eq!(take(), []);

    // The system's recovery link and import.
    auth.recovery_link("pat").await?;
    let imported = auth
        .import_user(&NewUser {
            login: Some("zed".to_owned()),
            email: None,
            role: Role::Regular,
        })
        .await?;
    let events = take();
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].actor(), Actor::System);
    assert_eq!(events[0].user(), Some(pat.id));
    assert!(matches!(events[0], AuditEvent::LinkIssued { .. }));
    assert_eq!(
        events[1],
        AuditEvent::UserCreated {
            actor: Actor::System,
            user: imported.info(),
        }
    );
    assert_eq!(Actor::System.responsible(), None);
    Ok(())
}

/// A test user signs in with their password and a test session acts for
/// them, in the service and through the `Cookie` header.
#[tokio::test]
async fn test_users_and_sessions() -> Result<(), Box<dyn std::error::Error>> {
    let auth = auth(CookieConfig::default());

    let new = NewUser {
        login: Some(" alice ".into()),
        email: Some("Alice@Example.com".into()),
        role: Role::Admin,
    };

    let alice = auth.test_user(&new, "pw").await?;
    assert_eq!(alice.login.as_deref(), Some("alice"));
    assert_eq!(alice.email.as_deref(), Some("alice@example.com"));
    assert_eq!(alice.role, Role::Admin);
    assert_eq!(alice.access, Access::Active);
    assert_eq!(alice.method, Method::Password);

    let login = LoginRequest {
        login: "alice@example.com".into(),
        password: "pw".into(),
    };
    let (signed_in, _) = auth
        .sign_in_password(IpAddr::from([127, 0, 0, 1]), &login)
        .await?;
    assert_eq!(signed_in, alice);

    let taken = auth.test_user(&new, "pw").await.unwrap_err();
    assert!(
        matches!(taken.auth_error(), Some(AuthError::Conflict(_))),
        "{taken}"
    );

    let session = auth.test_session(&alice).await?;
    let request = headers(&[(
        header::COOKIE.as_str(),
        auth.cookie_header(&session.id).to_str()?,
    )]);
    let id = auth.session_id(&request).ok_or("no session cookie")?;
    assert_eq!(
        auth.session(&id).await?,
        Some((alice.clone(), session.clone()))
    );

    // The session acts as the admin.
    let bob = NewUser {
        login: Some("bob".into()),
        email: None,
        role: Role::Regular,
    };
    auth.create_user(&alice, &session, &bob).await?;
    Ok(())
}
