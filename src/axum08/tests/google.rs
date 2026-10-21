//! Route-level tests of the Google OAuth flow, against the fake Google of
//! [`crate::google::fake`].

use std::borrow::ToOwned;
use std::collections::HashMap;
use std::string::String;

use super::*;
use crate::google::fake::{FakeAccount, FakeGoogle};
use crate::google::{GoogleConfig, REDIRECT_PATH, Url};

fn redirect_url() -> Url {
    Url::parse(&format!("https://app.example{REDIRECT_PATH}")).unwrap()
}

async fn google_auth() -> (Auth, FakeGoogle) {
    let public_url = Url::parse("https://app.example").unwrap();
    let config = GoogleConfig::new("client", "secret", &public_url).unwrap();
    assert_eq!(config.redirect_url, redirect_url());

    let google = FakeGoogle::start(&config).await.unwrap();

    let auth = Auth::builder(MemoryStore::new(), generate_session_key())
        .google(Some(config))
        .google_endpoints(google.endpoints())
        .build();

    (auth, google)
}

/// A verified Google account.
fn account(sub: &str, email: &str) -> FakeAccount {
    FakeAccount::new(sub, email)
}

fn location(answer: &Answer) -> &str {
    answer.headers[header::LOCATION].to_str().unwrap()
}

/// Starts a flow at `uri`, returning the URL the browser is sent to.
async fn start(app: &Router, uri: &str, cookie: Option<&str>) -> Url {
    let answer = call(app, Method::GET, uri, cookie, None).await;
    assert_eq!(answer.status, StatusCode::SEE_OTHER, "{}", answer.body);
    Url::parse(location(&answer)).unwrap()
}

/// The state of the flow started at `auth_url`.
fn state_of(auth_url: &Url) -> String {
    let query: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
    query["state"].clone()
}

/// Returns from Google with `query`.
async fn callback(app: &Router, query: &[(&str, &str)]) -> Answer {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query)
        .finish();
    call(
        app,
        Method::GET,
        &format!("{REDIRECT_PATH}?{query}"),
        None,
        None,
    )
    .await
}

/// Follows the callback URL the fake Google returned.
async fn follow(app: &Router, url: &Url) -> Answer {
    assert!(url.as_str().starts_with(redirect_url().as_str()));
    let uri = format!("{}?{}", url.path(), url.query().unwrap_or_default());
    call(app, Method::GET, &uri, None, None).await
}

/// Approves the flow at `auth_url` as `account`, expecting to be signed in;
/// returns the new cookie.
async fn signed_in_as(
    app: &Router,
    google: &FakeGoogle,
    auth_url: &Url,
    account: FakeAccount,
) -> String {
    let answer = follow(app, &google.approve(auth_url, account)).await;
    assert_eq!(answer.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&answer), "/");
    answer.cookie()
}

/// Expects `answer` to redirect with `error` and no cookie.
fn failed_with(answer: Answer, error: &str) {
    assert_eq!(answer.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&answer), format!("/?error={error}"));
    assert!(!answer.headers.contains_key(header::SET_COOKIE));
}

/// Returns from Google with `query`, expecting the redirect to carry `error`
/// and no cookie.
async fn fails_with(app: &Router, query: &[(&str, &str)], error: &str) {
    failed_with(callback(app, query).await, error);
}

/// Approves the flow at `auth_url` as `account`, expecting the redirect to
/// carry `error` and no cookie.
async fn approved_fails_with(
    app: &Router,
    google: &FakeGoogle,
    auth_url: &Url,
    account: FakeAccount,
    error: &str,
) {
    failed_with(follow(app, &google.approve(auth_url, account)).await, error);
}

async fn me(app: &Router, cookie: &str) -> Answer {
    call(app, Method::GET, "/api/auth/me", Some(cookie), None).await
}

/// Creates a user with `email` as `admin`, returning their link's token.
async fn invite(app: &Router, admin: &str, email: &str) -> String {
    let created = call(
        app,
        Method::POST,
        "/api/auth/users",
        Some(admin),
        Some(json!({ "login": null, "email": email, "role": "regular" })),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.body);
    let created: CreatedUser = serde_json::from_value(created.body).unwrap();
    created.link.token.rsplit('/').next().unwrap().to_owned()
}

#[tokio::test]
async fn google_is_offered_only_when_configured() {
    let plain = auth();
    let app = router(&plain);

    for uri in ["/api/auth/google", "/api/auth/google/register/nope"] {
        let answer = call(&app, Method::GET, uri, None, None).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{uri}");
    }

    let (auth, _google) = google_auth().await;
    let app = router(&auth);

    let config = call(&app, Method::GET, "/api/auth/config", None, None).await;
    assert_eq!(config.body["google"], json!(true));

    let admin = admin(&auth, &app).await;
    let token = invite(&app, &admin, "new@example.com").await;
    let info = call(
        &app,
        Method::GET,
        &format!("/api/auth/register/{token}"),
        None,
        None,
    )
    .await;
    assert_eq!(
        info.body,
        json!({ "login": null, "email": "new@example.com", "google": true })
    );

    // Starting needs a usable link, or a signed-in user.
    let unknown = call(
        &app,
        Method::GET,
        "/api/auth/google/register/nope",
        None,
        None,
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    let link = call(&app, Method::GET, "/api/auth/google/link", None, None).await;
    assert_eq!(link.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn registering_and_signing_in_with_google() {
    let (auth, google) = google_auth().await;
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let token = invite(&app, &admin, "new@example.com").await;

    let url = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    let cookie = signed_in_as(&app, &google, &url, account("sub:new", "New@example.com")).await;

    let info = me(&app, &cookie).await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(info.body["method"], json!("google"));
    assert_eq!(info.body["email"], json!("new@example.com"));
    assert_eq!(info.body["access"], json!("active"));

    // The link is used up.
    let used = call(
        &app,
        Method::GET,
        &format!("/api/auth/google/register/{token}"),
        None,
        None,
    )
    .await;
    assert_eq!(used.status, StatusCode::GONE);

    // The account signs in by its subject.
    let url = start(&app, "/api/auth/google", None).await;
    let again = signed_in_as(&app, &google, &url, account("sub:new", "new@example.com")).await;
    assert_eq!(me(&app, &again).await.status, StatusCode::OK);

    // An account no user has is not found, even with a user's email.
    let url = start(&app, "/api/auth/google", None).await;
    let other = account("sub:other", "new@example.com");
    approved_fails_with(&app, &google, &url, other, "user-not-found").await;
}

#[tokio::test]
async fn failed_callbacks_redirect_with_auth_failed() {
    let (auth, google) = google_auth().await;
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let token = invite(&app, &admin, "new@example.com").await;
    let good = || account("sub:new", "new@example.com");

    // Google refused, or returned without a code.
    let url = start(&app, "/api/auth/google", None).await;
    failed_with(follow(&app, &google.deny(&url)).await, "auth-failed");
    let url = start(&app, "/api/auth/google", None).await;
    fails_with(&app, &[("state", &state_of(&url))], "auth-failed").await;
    fails_with(&app, &[], "auth-failed").await;

    // A state that was never handed out.
    let code = google.code(good());
    fails_with(&app, &[("code", &code), ("state", "forged")], "auth-failed").await;

    // The token exchange fails: Google does not know the code.
    let url = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    let state = state_of(&url);
    fails_with(&app, &[("code", "bad"), ("state", &state)], "auth-failed").await;

    // The state was used up by the failed attempt.
    let code = google.code(good());
    fails_with(&app, &[("code", &code), ("state", &state)], "auth-failed").await;

    // An unverified email.
    let url = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    approved_fails_with(&app, &google, &url, good().unverified(), "auth-failed").await;

    // A state is good once.
    let url = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    signed_in_as(&app, &google, &url, good()).await;
    let code = google.code(good());
    fails_with(
        &app,
        &[("code", &code), ("state", &state_of(&url))],
        "auth-failed",
    )
    .await;

    // A code is good for one exchange.
    let url = start(&app, "/api/auth/google", None).await;
    let answer = callback(&app, &[("code", &code), ("state", &state_of(&url))]).await;
    assert_eq!(location(&answer), "/");
    let url = start(&app, "/api/auth/google", None).await;
    fails_with(
        &app,
        &[("code", &code), ("state", &state_of(&url))],
        "auth-failed",
    )
    .await;
}

#[tokio::test]
async fn a_misconfigured_client_fails_the_token_exchange() {
    let (_, google) = google_auth().await;

    let wrong = GoogleConfig {
        client_id: "client".to_owned(),
        client_secret: "wrong".to_owned(),
        redirect_url: redirect_url(),
    };

    let auth = Auth::builder(MemoryStore::new(), generate_session_key())
        .google(Some(wrong))
        .google_endpoints(google.endpoints())
        .build();
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let token = invite(&app, &admin, "new@example.com").await;

    let url = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    let new = account("sub:new", "new@example.com");
    approved_fails_with(&app, &google, &url, new, "auth-failed").await;
}

#[tokio::test]
async fn switching_to_google_ends_the_other_sessions() {
    let (auth, google) = google_auth().await;
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let (_, alice) = regular(&app, &admin, "alice").await;

    let url = start(&app, "/api/auth/google/link", Some(&alice)).await;
    let cookie = signed_in_as(
        &app,
        &google,
        &url,
        account("sub:alice", "alice@example.com"),
    )
    .await;

    // The session that started switching ended with the password.
    assert_eq!(me(&app, &alice).await.status, StatusCode::UNAUTHORIZED);

    let me = me(&app, &cookie).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["login"], json!("alice"));
    assert_eq!(me.body["method"], json!("google"));
    assert_eq!(me.body["email"], json!("alice@example.com"));

    let login = call(
        &app,
        Method::POST,
        "/api/auth/login",
        None,
        Some(json!({ "login": "alice", "password": PASSWORD })),
    )
    .await;
    assert_eq!(login.status, StatusCode::UNAUTHORIZED);

    let url = start(&app, "/api/auth/google", None).await;
    signed_in_as(
        &app,
        &google,
        &url,
        account("sub:alice", "alice@example.com"),
    )
    .await;
}

#[tokio::test]
async fn a_bound_google_account_cannot_be_linked_again() {
    let (auth, google) = google_auth().await;
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let token = invite(&app, &admin, "taken@example.com").await;

    let url = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    signed_in_as(
        &app,
        &google,
        &url,
        account("sub:taken", "taken@example.com"),
    )
    .await;

    let (_, bob) = regular(&app, &admin, "bob").await;
    let url = start(&app, "/api/auth/google/link", Some(&bob)).await;
    let taken = account("sub:taken", "bob@example.com");
    approved_fails_with(&app, &google, &url, taken, "auth-failed").await;

    // Nothing changed for bob.
    let me = me(&app, &bob).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["method"], json!("password"));
}

/// Signing in with Google comes back to a same-origin `next`, kept through
/// the round trip, and never to anywhere else.
#[tokio::test]
async fn signing_in_with_google_returns_to_next() {
    let (auth, google) = google_auth().await;
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let token = invite(&app, &admin, "new@example.com").await;
    let url = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    signed_in_as(&app, &google, &url, account("sub:new", "new@example.com")).await;

    // Where signing in from `/api/auth/google{query}` returns to.
    let returns_to = async |query: &str| {
        let url = start(&app, &format!("/api/auth/google{query}"), None).await;
        let answer = follow(
            &app,
            &google.approve(&url, account("sub:new", "new@example.com")),
        )
        .await;
        assert_eq!(answer.status, StatusCode::SEE_OTHER, "{query}");
        assert!(answer.headers.contains_key(header::SET_COOKIE), "{query}");
        location(&answer).to_owned()
    };

    assert_eq!(
        returns_to("?next=/notes%3Fq%3D1%23top").await,
        "/notes?q=1#top"
    );
    assert_eq!(returns_to("?next=/notes").await, "/notes");
    // Only what cannot be sent as it is gets encoded.
    assert_eq!(returns_to("?next=/a%20b/%C3%A5").await, "/a%20b/%C3%A5");
    assert_eq!(returns_to("?next=/%252F%252Fhost").await, "/%2F%2Fhost");
    // Never normalized into `//evil.example`, which would leave the origin.
    assert_eq!(
        returns_to("?next=/.//evil.example").await,
        "/.//evil.example"
    );
    assert_eq!(returns_to("").await, "/");
    assert_eq!(returns_to("?other=1").await, "/");

    // Another host, a scheme, or not a path: ignored.
    for bad in [
        "",
        "notes",
        "//evil.example",
        "%2F%2Fevil.example",
        "///evil.example",
        "/%5Cevil.example",
        "%5C%5Cevil.example",
        "https://evil.example",
        "https%3A%2F%2Fevil.example",
        "javascript:alert(1)",
        "/%09/evil.example",
        "/%0A/evil.example",
        "%20//evil.example",
    ] {
        assert_eq!(returns_to(&format!("?next={bad}")).await, "/", "{bad:?}");
    }

    // A byte that is not UTF-8 decodes as U+FFFD, which stays on the origin.
    assert_eq!(returns_to("?next=/%FF").await, "/%EF%BF%BD");

    // A failed sign-in keeps it on the error redirect, for trying again.
    let url = start(&app, "/api/auth/google?next=/notes%3Fq%3D1", None).await;
    let other = account("sub:other", "other@example.com");
    let answer = follow(&app, &google.approve(&url, other)).await;
    assert_eq!(
        location(&answer),
        "/?error=user-not-found&next=/notes%3Fq%3D1"
    );
    assert!(!answer.headers.contains_key(header::SET_COOKIE));

    let url = start(&app, "/api/auth/google?next=/a%20b", None).await;
    let answer = follow(&app, &google.deny(&url)).await;
    assert_eq!(location(&answer), "/?error=auth-failed&next=/a%2520b");

    // The state is used up by the denial, `next` and all.
    let code = google.code(account("sub:new", "new@example.com"));
    fails_with(
        &app,
        &[("code", &code), ("state", &state_of(&url))],
        "auth-failed",
    )
    .await;

    // A state that was never handed out has no `next`.
    fails_with(&app, &[("code", &code), ("state", "forged")], "auth-failed").await;
}
