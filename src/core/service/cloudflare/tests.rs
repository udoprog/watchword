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
    let auth = auth(&store, None);
    let headers = email("alice@example.com");

    assert!(!auth.cloudflare_available(&headers).await?);

    auth.set_cloudflare(Some(header_only()));
    assert!(auth.cloudflare_available(&headers).await?);
    auth.sign_in_cloudflare(&headers).await?;

    // Applying the same settings again is harmless.
    auth.set_cloudflare(Some(header_only()));
    assert!(auth.cloudflare_available(&headers).await?);

    // Requiring the token, which this request lacks.
    auth.set_cloudflare(Some(config(true, true)));
    assert!(!auth.cloudflare_available(&headers).await?);

    auth.set_cloudflare(Some(CloudflareConfig {
        enabled: false,
        ..header_only()
    }));
    assert!(!auth.cloudflare_available(&headers).await?);

    auth.set_cloudflare(Some(header_only()));
    assert!(auth.cloudflare_available(&headers).await?);

    auth.set_cloudflare(None);
    let error = refused(auth.sign_in_cloudflare(&headers).await);
    assert_eq!(error, AuthError::Unauthorized);
    Ok(())
}
