use std::borrow::ToOwned;
use std::boxed::Box;
use std::error::Error as StdError;
use std::format;
use std::string::String;
use std::sync::Mutex;
use std::vec::Vec;

use super::*;
use crate::core::{Error, generate_session_key};
use crate::google::runtime::SETTINGS_KEY;
use crate::store::{Credential, MemoryStore, Store};
use crate::types::{NewUser, Role};

type TestResult = Result<(), Box<dyn StdError>>;

fn public_url() -> Url {
    Url::parse("https://example.com").unwrap()
}

fn update(client_id: &str, client_secret: Option<&str>) -> GoogleSettingsUpdate {
    GoogleSettingsUpdate {
        enabled: true,
        client_id: client_id.to_owned(),
        client_secret: client_secret.map(ToOwned::to_owned),
        public_url: None,
    }
}

/// What a runtime client with the public URL fixed reports before a
/// client is saved.
fn unset() -> GoogleSettings {
    GoogleSettings {
        public_url: Some(public_url().as_str().to_owned()),
        public_url_fixed: true,
        ..GoogleSettings::default()
    }
}

fn runtime(store: &MemoryStore) -> Auth {
    Auth::builder(store.clone(), generate_session_key())
        .google_public_url(public_url())
        .build()
}

fn refused<T>(result: Result<T, Error>) -> AuthError {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => error.auth_error().cloned().expect("an AuthError"),
    }
}

async fn user(store: &MemoryStore, login: &str, role: Role) -> Result<User, Box<dyn StdError>> {
    let new = NewUser {
        login: Some(login.to_owned()),
        email: None,
        role,
    };
    let user = store.create_user(&new, Timestamp::now()).await?.unwrap();
    let cred = Credential::Password(crate::core::dummy_hash().to_owned());
    assert!(store.set_credential(user.id, &cred, None).await?);
    Ok(store.user(user.id).await?.unwrap())
}

/// The client id and state a sign-in sends the browser to Google with.
async fn sign_in(auth: &Auth) -> Result<(String, String), Box<dyn StdError>> {
    let url = auth.google_sign_in(None).await?;
    let param = |name: &str| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .unwrap()
    };
    Ok((param("client_id"), param("state")))
}

/// Without a client or a public URL, Google is neither offered nor settable.
#[tokio::test]
async fn not_offered_without_a_client_or_public_url() -> TestResult {
    let store = MemoryStore::new();
    let auth = Auth::builder(store.clone(), generate_session_key()).build();
    let root = user(&store, "root", Role::Admin).await?;
    let session = auth.create_session(root.id).await?;

    assert_eq!(auth.google().await?, None);
    assert!(!auth.offers_google().await?);
    let error = refused(
        auth.set_google(&root, &session, update("id", Some("secret")))
            .await,
    );
    assert_eq!(error, AuthError::NotFound);
    Ok(())
}

/// A client given to the builder wins over a stored one and cannot be
/// changed.
#[tokio::test]
async fn a_fixed_client_wins() -> TestResult {
    let store = MemoryStore::new();
    let root = user(&store, "root", Role::Admin).await?;
    store
        .config_set(
            SETTINGS_KEY,
            r#"{"enabled":true,"client_id":"stored","client_secret":"s"}"#,
        )
        .await?;

    let config = GoogleConfig::new("fixed", "secret", &public_url())?;
    let auth = Auth::builder(store.clone(), generate_session_key())
        .google(Some(config))
        .google_public_url(public_url())
        .build();
    let session = auth.create_session(root.id).await?;

    assert_eq!(
        auth.google().await?,
        Some(GoogleSettings {
            enabled: true,
            client_id: "fixed".to_owned(),
            has_secret: true,
            fixed: true,
            public_url: Some(public_url().as_str().to_owned()),
            public_url_fixed: true,
        })
    );
    assert!(auth.offers_google().await?);
    assert_eq!(sign_in(&auth).await?.0, "fixed");

    let error = refused(
        auth.set_google(&root, &session, update("other", Some("s")))
            .await,
    );
    assert_eq!(error, AuthError::Forbidden);
    Ok(())
}

/// Runtime settings apply at once: enabling, changing and disabling.
#[tokio::test]
async fn settings_change_at_runtime() -> TestResult {
    let store = MemoryStore::new();
    let auth = runtime(&store);
    let root = user(&store, "root", Role::Admin).await?;
    let session = auth.create_session(root.id).await?;

    assert_eq!(auth.google().await?, Some(unset()));
    assert!(!auth.offers_google().await?);
    assert_eq!(
        refused(auth.google_sign_in(None).await),
        AuthError::NotFound
    );

    let saved = auth
        .set_google(&root, &session, update(" first ", Some("secret")))
        .await?;
    assert_eq!(
        saved,
        GoogleSettings {
            enabled: true,
            client_id: "first".to_owned(),
            has_secret: true,
            fixed: false,
            ..unset()
        }
    );
    assert_eq!(auth.google().await?, Some(saved));
    assert!(auth.offers_google().await?);
    assert_eq!(sign_in(&auth).await?.0, "first");

    auth.set_google(&root, &session, update("second", None))
        .await?;
    assert_eq!(sign_in(&auth).await?.0, "second");

    let disabled = GoogleSettingsUpdate {
        enabled: false,
        ..update("second", None)
    };
    let saved = auth.set_google(&root, &session, disabled).await?;
    assert!(!saved.enabled);
    assert!(saved.has_secret);
    assert!(!auth.offers_google().await?);
    assert_eq!(
        refused(auth.google_sign_in(None).await),
        AuthError::NotFound
    );
    Ok(())
}

/// Enabled settings without a client id or secret leave Google off.
#[tokio::test]
async fn incomplete_settings_offer_nothing() -> TestResult {
    let store = MemoryStore::new();
    let auth = runtime(&store);
    let root = user(&store, "root", Role::Admin).await?;
    let session = auth.create_session(root.id).await?;

    let saved = auth.set_google(&root, &session, update("id", None)).await?;
    assert!(saved.enabled && !saved.has_secret);
    assert!(!auth.offers_google().await?);

    auth.set_google(&root, &session, update("  ", Some("secret")))
        .await?;
    assert!(!auth.offers_google().await?);

    auth.set_google(&root, &session, update("id", None)).await?;
    assert!(auth.offers_google().await?);
    Ok(())
}

/// The secret is kept in the store and survives a restart, but is never
/// returned; an empty one keeps it.
#[tokio::test]
async fn settings_are_stored_without_returning_the_secret() -> TestResult {
    let store = MemoryStore::new();
    let auth = runtime(&store);
    let root = user(&store, "root", Role::Admin).await?;
    let session = auth.create_session(root.id).await?;

    let saved = auth
        .set_google(&root, &session, update("id", Some("hunter2")))
        .await?;
    assert!(!format!("{saved:?}").contains("hunter2"));
    assert!(!serde_json::to_string(&saved)?.contains("hunter2"));
    assert!(!format!("{:?}", update("id", Some("hunter2"))).contains("hunter2"));

    auth.set_google(&root, &session, update("id", Some("")))
        .await?;
    let stored = store.config_get(SETTINGS_KEY).await?.unwrap();
    assert!(stored.contains("hunter2"));

    let restarted = runtime(&store);
    assert_eq!(restarted.google().await?, Some(saved));
    assert!(restarted.offers_google().await?);
    Ok(())
}

/// Stored settings that do not parse leave Google off until saved again.
#[tokio::test]
async fn malformed_settings_are_read_safely() -> TestResult {
    let store = MemoryStore::new();
    store.config_set(SETTINGS_KEY, "not json").await?;
    let auth = runtime(&store);
    let root = user(&store, "root", Role::Admin).await?;
    let session = auth.create_session(root.id).await?;

    assert_eq!(auth.google().await?, Some(unset()));
    assert!(!auth.offers_google().await?);

    auth.set_google(&root, &session, update("id", Some("secret")))
        .await?;
    assert!(runtime(&store).offers_google().await?);
    Ok(())
}

/// Only active admins may change the settings.
#[tokio::test]
async fn only_admins_change_settings() -> TestResult {
    let store = MemoryStore::new();
    let auth = runtime(&store);
    let alice = user(&store, "alice", Role::Regular).await?;
    let session = auth.create_session(alice.id).await?;

    let error = refused(
        auth.set_google(&alice, &session, update("id", Some("secret")))
            .await,
    );
    assert_eq!(error, AuthError::Forbidden);
    assert!(!auth.offers_google().await?);
    Ok(())
}

/// Changing the client ends the flows pending on the old one; saving the
/// same settings again keeps them.
#[tokio::test]
async fn changing_the_client_ends_pending_flows() -> TestResult {
    let store = MemoryStore::new();
    let auth = runtime(&store);
    let root = user(&store, "root", Role::Admin).await?;
    let session = auth.create_session(root.id).await?;

    auth.set_google(&root, &session, update("id", Some("secret")))
        .await?;
    let (_, kept) = sign_in(&auth).await?;
    let (_, ended) = sign_in(&auth).await?;

    auth.set_google(&root, &session, update("id", None)).await?;
    let provider = auth.google_provider().await?.unwrap();
    assert!(provider.take(&kept).is_some());

    auth.set_google(&root, &session, update("id", Some("rotated")))
        .await?;
    let provider = auth.google_provider().await?.unwrap();
    assert!(provider.take(&ended).is_none());
    Ok(())
}

/// Changing the settings or only the secret is audited without the secret;
/// saving them unchanged sends nothing.
#[tokio::test]
async fn changing_settings_is_audited() -> TestResult {
    use std::sync::Arc;

    let store = MemoryStore::new();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();

    let auth = Auth::builder(store.clone(), generate_session_key())
        .google_public_url(public_url())
        .audit(move |event| sink.lock().unwrap().push(event.clone()))
        .build();

    let take = || std::mem::take(&mut *log.lock().unwrap());

    let root = user(&store, "root", Role::Admin).await?;
    let session = auth.create_session(root.id).await?;
    let by_root = Actor::of(&root, &session);
    take();

    let first = auth
        .set_google(&root, &session, update("id", Some("hunter2")))
        .await?;
    let events = take();
    assert_eq!(
        events,
        [AuditEvent::GoogleChanged {
            actor: by_root,
            before: unset(),
            after: first.clone(),
            secret_changed: true,
        }]
    );
    assert_eq!(events[0].user(), None);
    assert!(!format!("{events:?}").contains("hunter2"));

    auth.set_google(&root, &session, update("id", None)).await?;
    auth.set_google(&root, &session, update("id", Some("hunter2")))
        .await?;
    assert_eq!(take(), []);

    auth.set_google(&root, &session, update("id", Some("rotated")))
        .await?;
    assert_eq!(
        take(),
        [AuditEvent::GoogleChanged {
            actor: by_root,
            before: first.clone(),
            after: first,
            secret_changed: true,
        }]
    );
    Ok(())
}

/// With neither a client nor a public URL from the app, an admin sets both,
/// and Google sign-in is off until the public URL is there.
#[tokio::test]
async fn public_url_is_set_at_runtime() -> TestResult {
    let store = MemoryStore::new();
    let auth = Auth::builder(store.clone(), generate_session_key())
        .google_at_runtime()
        .build();
    let root = user(&store, "root", Role::Admin).await?;
    let session = auth.create_session(root.id).await?;

    assert_eq!(auth.google().await?, Some(GoogleSettings::default()));

    let saved = auth
        .set_google(&root, &session, update("id", Some("secret")))
        .await?;
    assert_eq!(saved.public_url, None);
    assert!(!auth.offers_google().await?);

    let with_url = GoogleSettingsUpdate {
        public_url: Some(" https://example.com ".to_owned()),
        ..update("id", None)
    };
    let saved = auth.set_google(&root, &session, with_url).await?;
    assert_eq!(saved.public_url.as_deref(), Some("https://example.com"));
    assert!(!saved.public_url_fixed);
    assert!(auth.offers_google().await?);
    assert_eq!(sign_in(&auth).await?.0, "id");

    // An update without one keeps it; an empty one clears it.
    let saved = auth.set_google(&root, &session, update("id", None)).await?;
    assert_eq!(saved.public_url.as_deref(), Some("https://example.com"));

    let cleared = GoogleSettingsUpdate {
        public_url: Some(String::new()),
        ..update("id", None)
    };
    let saved = auth.set_google(&root, &session, cleared).await?;
    assert_eq!(saved.public_url, None);
    assert!(!auth.offers_google().await?);

    // A fixed one is not changed by an update.
    let fixed = runtime(&store);
    let other = GoogleSettingsUpdate {
        public_url: Some("https://other.example".to_owned()),
        ..update("id", None)
    };
    let saved = fixed.set_google(&root, &session, other).await?;
    assert_eq!(saved.public_url, Some(public_url().as_str().to_owned()));
    assert!(saved.public_url_fixed);
    Ok(())
}
