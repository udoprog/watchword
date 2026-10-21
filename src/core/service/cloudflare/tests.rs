use std::borrow::ToOwned;
use std::boxed::Box;
use std::error::Error as StdError;

use http::header::COOKIE;
use http::{HeaderMap, HeaderValue};
use jiff::{SignedDuration, Timestamp};

use super::*;
use crate::cloudflare::{EMAIL_HEADER, JWT_COOKIE, JWT_HEADER, presents_access};
use crate::core::{Error, generate_session_key, new_token};
use crate::store::{Credential, MemoryStore, Store, Token, TokenKind};
use crate::types::{Method, NewUser, Role};

type TestResult = Result<(), Box<dyn StdError>>;

fn config(trust_email_header: bool, verify_jwt: bool) -> CloudflareConfig {
    CloudflareConfig {
        enabled: true,
        team_domain: "example.cloudflareaccess.com".to_owned(),
        audience: "aud".to_owned(),
        trust_email_header,
        verify_jwt,
    }
}

/// Access that believes the email header, so a test can name any user.
fn header_only() -> CloudflareConfig {
    config(true, false)
}

fn auth(store: &MemoryStore, config: Option<CloudflareConfig>) -> Auth {
    Auth::builder(store.clone(), generate_session_key())
        .cloudflare(config)
        .build()
}

fn email(email: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(EMAIL_HEADER, HeaderValue::from_str(email).unwrap());
    headers
}

fn cookie(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(COOKIE, HeaderValue::from_static(value));
    headers
}

fn refused<T>(result: Result<T, Error>) -> AuthError {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => error.auth_error().cloned().expect("an AuthError"),
    }
}

/// An active admin, to save settings as.
async fn admin(store: &MemoryStore) -> Result<User, Box<dyn StdError>> {
    let new = NewUser {
        login: Some("root".to_owned()),
        email: None,
        role: Role::Admin,
    };
    let user = store.create_user(&new, Timestamp::now()).await?.unwrap();
    let cred = Credential::Password(crate::core::dummy_hash().to_owned());
    assert!(store.set_credential(user.id, &cred, None).await?);
    Ok(store.user(user.id).await?.unwrap())
}

/// A session for `user`, to act with.
async fn session(auth: &Auth, user: &User) -> Result<Session, Box<dyn StdError>> {
    Ok(auth.create_session(user.id).await?)
}

/// A pending user with `email`.
async fn pending(store: &MemoryStore, email: &str) -> Result<User, Box<dyn StdError>> {
    let new = NewUser {
        login: None,
        email: Some(email.to_owned()),
        role: Role::Regular,
    };

    Ok(store.create_user(&new, Timestamp::now()).await?.unwrap())
}

/// An active password user with `email`.
async fn active(store: &MemoryStore, email: &str) -> Result<User, Box<dyn StdError>> {
    let user = pending(store, email).await?;
    let cred = Credential::Password(crate::core::dummy_hash().to_owned());
    assert!(store.set_credential(user.id, &cred, None).await?);
    Ok(store.user(user.id).await?.unwrap())
}

fn has_warning(auth: &Auth, needle: &str) -> bool {
    auth.cloudflare_warnings()
        .iter()
        .any(|w| w.contains(needle))
}

#[test]
fn presents_access_sees_any_access_credential() {
    assert!(!presents_access(&HeaderMap::new()));
    assert!(!presents_access(&cookie("session=abc; other=1")));
    assert!(presents_access(&email("a@example.com")));
    assert!(presents_access(&cookie("other=1; CF_Authorization=a.b.c")));

    let mut headers = HeaderMap::new();
    headers.insert(JWT_HEADER, HeaderValue::from_static("a.b.c"));
    assert!(presents_access(&headers));
    assert_eq!(JWT_COOKIE, "CF_Authorization");
}

/// Disabled Access signs no one in, and says why only when the request
/// carried Access credentials, once a minute.
#[tokio::test]
async fn disabled_access_is_logged_once() -> TestResult {
    let store = MemoryStore::new();
    active(&store, "alice@example.com").await?;

    for config in [None, Some(CloudflareConfig::default())] {
        let auth = auth(&store, config);

        assert!(!auth.cloudflare_available(&HeaderMap::new()).await?);
        assert!(auth.cloudflare_warnings().is_empty());

        for _ in 0..2 {
            assert!(
                !auth
                    .cloudflare_available(&cookie("CF_Authorization=a.b.c"))
                    .await?
            );
        }

        assert!(
            !auth
                .cloudflare_available(&email("alice@example.com"))
                .await?
        );
        let error = refused(auth.sign_in_cloudflare(&email("alice@example.com")).await);
        assert_eq!(error, AuthError::Unauthorized);

        let warnings = auth.cloudflare_warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("sign-in is disabled"), "{warnings:?}");
    }

    Ok(())
}

/// Access matches any user by normalized email, whatever their method, and
/// signs them in with an ordinary session.
#[tokio::test]
async fn signs_in_existing_users_by_email() -> TestResult {
    let store = MemoryStore::new();
    let alice = active(&store, "alice@example.com").await?;
    let google = pending(&store, "google@example.com").await?;
    let cred = Credential::Google {
        sub: "sub:google".to_owned(),
        email: "google@example.com".to_owned(),
    };
    assert!(store.set_credential(google.id, &cred, None).await?);

    let auth = auth(&store, Some(header_only()));
    let headers = email("  Alice@Example.COM ");

    assert!(auth.cloudflare_available(&headers).await?);
    let (user, session) = auth.sign_in_cloudflare(&headers).await?;
    assert_eq!(user, alice);
    let (live, _) = auth.session(&session.id).await?.expect("a live session");
    assert_eq!(live.id, alice.id);

    let (user, _) = auth
        .sign_in_cloudflare(&email("google@example.com"))
        .await?;
    assert_eq!(user.id, google.id);
    assert_eq!(user.method, Method::Google);

    assert!(auth.cloudflare_warnings().is_empty());
    Ok(())
}

/// Unknown emails are refused and never create a user.
#[tokio::test]
async fn unknown_emails_are_refused() -> TestResult {
    let store = MemoryStore::new();
    let auth = auth(&store, Some(header_only()));
    let headers = email("carol@example.com");

    assert!(!auth.cloudflare_available(&headers).await?);
    let error = refused(auth.sign_in_cloudflare(&headers).await);
    assert_eq!(error, AuthError::Unauthorized);
    assert_eq!(store.user_count().await?, 0);
    assert!(has_warning(
        &auth,
        "no user has the email carol@example.com"
    ));
    Ok(())
}

/// A pending user who signs in through Access becomes active, which ends
/// their registration link.
#[tokio::test]
async fn pending_users_become_active() -> TestResult {
    let store = MemoryStore::new();
    let bob = pending(&store, "bob@example.com").await?;
    let now = Timestamp::now();

    let token = Token {
        id: new_token(),
        user: bob.id,
        kind: TokenKind::Registration,
        expires_at: now + SignedDuration::from_hours(1),
        used_at: None,
    };
    store.create_token(&token, now).await?;

    let auth = auth(&store, Some(header_only()));
    let mut events = auth.events();
    let headers = email("bob@example.com");

    assert!(auth.cloudflare_available(&headers).await?);
    assert_eq!(store.user(bob.id).await?.unwrap().access, Access::Pending);

    let (user, session) = auth.sign_in_cloudflare(&headers).await?;
    assert_eq!(user.access, Access::Active);
    assert_eq!(store.user(bob.id).await?.unwrap().access, Access::Active);
    assert!(auth.session(&session.id).await?.is_some());
    assert_eq!(events.try_recv()?, AuthEvent::UserChanged(user.info()));
    assert!(events.try_recv().is_err());

    let error = refused(auth.register_info(&token.id).await);
    assert_eq!(error, AuthError::Gone);

    // Signing in again changes nothing more.
    auth.sign_in_cloudflare(&headers).await?;
    assert!(events.try_recv().is_err());
    Ok(())
}

/// A revoked user is refused, and stays revoked.
#[tokio::test]
async fn revoked_users_are_refused() -> TestResult {
    let store = MemoryStore::new();
    let dave = active(&store, "dave@example.com").await?;
    assert!(store.revoke(dave.id, Timestamp::now()).await?);

    let auth = auth(&store, Some(header_only()));
    let headers = email("dave@example.com");

    assert!(!auth.cloudflare_available(&headers).await?);
    let error = refused(auth.sign_in_cloudflare(&headers).await);
    assert_eq!(error, AuthError::Unauthorized);
    assert_eq!(store.user(dave.id).await?.unwrap().access, Access::Revoked);
    assert!(has_warning(
        &auth,
        "dave@example.com has had their access revoked"
    ));
    Ok(())
}

/// A token that does not verify is refused, with the reason logged.
#[tokio::test]
async fn bad_tokens_are_logged() -> TestResult {
    let store = MemoryStore::new();
    active(&store, "alice@example.com").await?;
    let auth = auth(&store, Some(config(false, true)));

    // Without anything from Access, the request is simply signed out.
    assert!(!auth.cloudflare_available(&HeaderMap::new()).await?);
    assert!(auth.cloudflare_warnings().is_empty());

    // The email header alone is not enough when the token is required.
    assert!(
        !auth
            .cloudflare_available(&email("alice@example.com"))
            .await?
    );
    assert!(has_warning(&auth, "missing Access JWT"));

    assert!(
        !auth
            .cloudflare_available(&cookie("CF_Authorization=a.b.c"))
            .await?
    );
    assert!(has_warning(
        &auth,
        "Cloudflare Access sign-in failed: malformed Access JWT"
    ));
    Ok(())
}

/// Settings apply at runtime: enabling, changing and disabling.
#[tokio::test]
async fn settings_change_at_runtime() -> TestResult {
    let store = MemoryStore::new();
    active(&store, "alice@example.com").await?;
    let root = admin(&store).await?;
    let auth = auth(&store, None);
    let root_session = session(&auth, &root).await?;
    let headers = email("alice@example.com");

    assert!(!auth.cloudflare_available(&headers).await?);

    auth.set_cloudflare(&root, &root_session, header_only())
        .await?;
    assert!(auth.cloudflare_available(&headers).await?);
    auth.sign_in_cloudflare(&headers).await?;

    // Applying the same settings again is harmless.
    auth.set_cloudflare(&root, &root_session, header_only())
        .await?;
    assert!(auth.cloudflare_available(&headers).await?);

    // Requiring the token, which this request lacks.
    auth.set_cloudflare(&root, &root_session, config(true, true))
        .await?;
    assert!(!auth.cloudflare_available(&headers).await?);

    auth.set_cloudflare(
        &root,
        &root_session,
        CloudflareConfig {
            enabled: false,
            ..header_only()
        },
    )
    .await?;
    assert!(!auth.cloudflare_available(&headers).await?);
    let error = refused(auth.sign_in_cloudflare(&headers).await);
    assert_eq!(error, AuthError::Unauthorized);

    auth.set_cloudflare(&root, &root_session, header_only())
        .await?;
    assert!(auth.cloudflare_available(&headers).await?);
    Ok(())
}

/// Without stored settings, the builder's are used; once saved, the stored
/// ones are, by every service over the store, and the builder's no longer
/// matter.
#[tokio::test]
async fn settings_are_stored() -> TestResult {
    let store = MemoryStore::new();
    active(&store, "alice@example.com").await?;
    let headers = email("alice@example.com");

    let none = auth(&store, None);
    assert_eq!(none.cloudflare().await?, None);
    assert_eq!(store.config_get("cloudflare").await?, None);

    let initial = auth(&store, Some(header_only()));
    assert_eq!(initial.cloudflare().await?, Some(header_only()));
    assert!(initial.cloudflare_available(&headers).await?);
    // Using the builder's settings does not store them.
    assert_eq!(store.config_get("cloudflare").await?, None);

    let disabled = CloudflareConfig {
        enabled: false,
        team_domain: " example.cloudflareaccess.com\n".to_owned(),
        audience: " aud ".to_owned(),
        ..header_only()
    };
    let root = admin(&store).await?;
    let alice = store.user_by_email("alice@example.com").await?.unwrap();
    let alice_session = session(&initial, &alice).await?;
    let root_session = session(&initial, &root).await?;
    let error = refused(
        initial
            .set_cloudflare(&alice, &alice_session, disabled.clone())
            .await,
    );
    assert_eq!(error, AuthError::Forbidden);
    assert_eq!(store.config_get("cloudflare").await?, None);

    let saved = initial
        .set_cloudflare(&root, &root_session, disabled)
        .await?;
    assert_eq!(
        saved,
        CloudflareConfig {
            enabled: false,
            ..header_only()
        }
    );
    // Disabled settings are still the settings, for the admin page.
    assert_eq!(initial.cloudflare().await?, Some(saved.clone()));
    assert!(!initial.cloudflare_available(&headers).await?);

    // A restart with other builder settings keeps what was saved.
    let restarted = auth(&store, Some(header_only()));
    assert_eq!(restarted.cloudflare().await?, Some(saved.clone()));
    assert!(!restarted.cloudflare_available(&headers).await?);

    let stored: CloudflareConfig =
        serde_json::from_str(&store.config_get("cloudflare").await?.unwrap())?;
    assert_eq!(stored, saved);
    Ok(())
}

/// Stored settings without a field take its default, so they verify the
/// token, and settings that do not parse fall back to the builder's rather
/// than breaking sign-in.
#[tokio::test]
async fn stored_settings_are_read_safely() -> TestResult {
    let store = MemoryStore::new();
    store
        .config_set(
            "cloudflare",
            r#"{"enabled":true,"team_domain":"example.cloudflareaccess.com","audience":"aud","trust_email_header":true}"#,
        )
        .await?;

    let lenient = auth(&store, None);
    let stored = lenient.cloudflare().await?.unwrap();
    assert!(stored.verify_jwt);
    assert!(stored.trust_email_header);

    store.config_set("cloudflare", "not json").await?;
    let fallback = auth(&store, Some(header_only()));
    assert_eq!(fallback.cloudflare().await?, Some(header_only()));

    let nothing = auth(&store, None);
    assert_eq!(nothing.cloudflare().await?, None);
    Ok(())
}

/// A pending user revoked after sign-in read them, but before it activated
/// them, is refused and stays revoked.
#[tokio::test]
async fn a_concurrent_revocation_is_not_undone() -> TestResult {
    let store = MemoryStore::new();
    let erin = pending(&store, "erin@example.com").await?;
    let auth = auth(&store, Some(header_only()));
    let mut events = auth.events();

    store.revoke_before_next_write(erin.id);
    let error = refused(auth.sign_in_cloudflare(&email("erin@example.com")).await);
    assert_eq!(error, AuthError::Unauthorized);
    assert_eq!(store.user(erin.id).await?.unwrap().access, Access::Revoked);
    assert!(events.try_recv().is_err());
    Ok(())
}

/// Changing the settings sends an audit event with them before and after,
/// naming an impersonating admin; saving them unchanged sends none.
#[tokio::test]
async fn changing_settings_is_audited() -> TestResult {
    use std::sync::{Arc, Mutex};

    let store = MemoryStore::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();

    let auth = Auth::builder(store.clone(), generate_session_key())
        .cloudflare(Some(header_only()))
        .impersonation(true)
        .audit(move |event| sink.lock().unwrap().push(event.clone()))
        .build();

    let take = || std::mem::take(&mut *log.lock().unwrap());

    let root = admin(&store).await?;
    let root_session = session(&auth, &root).await?;
    let by_root = Actor::of(&root, &root_session);

    // The builder's settings are the ones replaced, and saving them as they
    // are changes nothing.
    auth.set_cloudflare(&root, &root_session, header_only())
        .await?;
    assert_eq!(take(), []);

    let required = config(true, true);
    auth.set_cloudflare(&root, &root_session, required.clone())
        .await?;
    let events = take();
    assert_eq!(
        events,
        [AuditEvent::CloudflareChanged {
            actor: by_root,
            before: Some(header_only()),
            after: required.clone(),
        }]
    );
    assert_eq!(events[0].actor(), by_root);
    assert_eq!(events[0].user(), None);

    // An admin impersonating another admin is named as responsible.
    let new = NewUser {
        login: Some("other".to_owned()),
        email: None,
        role: Role::Admin,
    };
    let other = store.create_user(&new, Timestamp::now()).await?.unwrap();
    let cred = Credential::Password(crate::core::dummy_hash().to_owned());
    assert!(store.set_credential(other.id, &cred, None).await?);
    let (as_other, as_other_session) = auth.impersonate(&root, &root_session, other.id).await?;
    take();

    let disabled = CloudflareConfig {
        enabled: false,
        ..required.clone()
    };
    auth.set_cloudflare(&as_other, &as_other_session, disabled.clone())
        .await?;
    let events = take();
    assert_eq!(
        events,
        [AuditEvent::CloudflareChanged {
            actor: Actor::User {
                user: other.id,
                impersonator: Some(root.id),
            },
            before: Some(required),
            after: disabled,
        }]
    );
    assert_eq!(events[0].actor().responsible(), Some(root.id));
    Ok(())
}

/// With no settings before, the event says so.
#[tokio::test]
async fn first_settings_are_audited_from_none() -> TestResult {
    use std::sync::{Arc, Mutex};

    let store = MemoryStore::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();

    let auth = Auth::builder(store.clone(), generate_session_key())
        .audit(move |event| sink.lock().unwrap().push(event.clone()))
        .build();

    let root = admin(&store).await?;
    let root_session = session(&auth, &root).await?;

    auth.set_cloudflare(&root, &root_session, header_only())
        .await?;

    assert_eq!(
        *log.lock().unwrap(),
        [AuditEvent::CloudflareChanged {
            actor: Actor::of(&root, &root_session),
            before: None,
            after: header_only(),
        }]
    );
    Ok(())
}
