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

    let value = set.split(';').next().unwrap();
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
