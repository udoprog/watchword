//! Route-level tests of the Google OAuth flow, against a local server
//! standing in for Google's token and tokeninfo endpoints.
//!
//! The fake hands out the authorization code as the access token, and
//! tokeninfo reads the account from it: a code is `sub|email|verified`.

use std::collections::HashMap;

use axum::extract::Query;
use axum::response::IntoResponse;
use axum::routing::post;

use super::*;
use crate::google::{Endpoints, GoogleConfig, REDIRECT_PATH, Url};

/// Serves a fake Google, returning its endpoints.
async fn fake_google() -> Endpoints {
    let app = Router::new()
        .route(
            "/token",
            post(|body: String| async move {
                let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
                    .into_owned()
                    .collect();

                assert_eq!(form["client_id"], "client");
                assert_eq!(form["client_secret"], "secret");
                assert_eq!(form["grant_type"], "authorization_code");
                assert_eq!(form["redirect_uri"], redirect_url().as_str());

                if form["code"] == "bad" {
                    return StatusCode::BAD_REQUEST.into_response();
                }

                axum::Json(json!({ "access_token": form["code"] })).into_response()
            }),
        )
        .route(
            "/tokeninfo",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                let mut parts = query["access_token"].splitn(3, '|');
                let (sub, email, verified) = (
                    parts.next().unwrap().to_owned(),
                    parts.next().unwrap().to_owned(),
                    parts.next().unwrap().to_owned(),
                );
                axum::Json(json!({ "sub": sub, "email": email, "email_verified": verified }))
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    Endpoints {
        auth: Url::parse("https://accounts.example/auth").unwrap(),
        token: Url::parse(&format!("http://{address}/token")).unwrap(),
        tokeninfo: Url::parse(&format!("http://{address}/tokeninfo")).unwrap(),
    }
}

fn redirect_url() -> Url {
    Url::parse(&format!("https://app.example{REDIRECT_PATH}")).unwrap()
}

async fn google_auth() -> Auth {
    let config = GoogleConfig {
        client_id: "client".to_owned(),
        client_secret: "secret".to_owned(),
        redirect_url: redirect_url(),
    };

    Auth::builder(MemoryStore::new(), generate_session_key())
        .google(Some(config))
        .google_endpoints(fake_google().await)
        .build()
}

/// A verified account's authorization code.
fn code(sub: &str, email: &str) -> String {
    format!("{sub}|{email}|true")
}

fn location(answer: &Answer) -> &str {
    answer.headers[header::LOCATION].to_str().unwrap()
}

/// Starts a flow at `uri`, returning its state.
async fn start(app: &Router, uri: &str, cookie: Option<&str>) -> String {
    let answer = call(app, Method::GET, uri, cookie, None).await;
    assert_eq!(answer.status, StatusCode::SEE_OTHER, "{}", answer.body);

    let url = Url::parse(location(&answer)).unwrap();
    assert!(url.as_str().starts_with("https://accounts.example/auth?"));

    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["client_id"], "client");
    assert_eq!(query["redirect_uri"], redirect_url().as_str());
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

/// Returns from Google with `code` for `state`, expecting to be signed in;
/// returns the new cookie.
async fn signed_in_with(app: &Router, state: &str, code: &str) -> String {
    let answer = callback(app, &[("code", code), ("state", state)]).await;
    assert_eq!(answer.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&answer), "/");
    answer.cookie()
}

/// Returns from Google with `code` for `state`, expecting the redirect to
/// carry `error` and no cookie.
async fn fails_with(app: &Router, query: &[(&str, &str)], error: &str) {
    let answer = callback(app, query).await;
    assert_eq!(answer.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&answer), format!("/?error={error}"));
    assert!(!answer.headers.contains_key(header::SET_COOKIE));
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

    let auth = google_auth().await;
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
    let auth = google_auth().await;
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let token = invite(&app, &admin, "new@example.com").await;

    let state = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    let cookie = signed_in_with(&app, &state, &code("sub:new", "New@example.com")).await;

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
    let state = start(&app, "/api/auth/google", None).await;
    let again = signed_in_with(&app, &state, &code("sub:new", "new@example.com")).await;
    assert_eq!(me(&app, &again).await.status, StatusCode::OK);

    // An account no user has is not found, even with a user's email.
    let state = start(&app, "/api/auth/google", None).await;
    let query = code("sub:other", "new@example.com");
    fails_with(
        &app,
        &[("code", &query), ("state", &state)],
        "user-not-found",
    )
    .await;
}

#[tokio::test]
async fn failed_callbacks_redirect_with_auth_failed() {
    let auth = google_auth().await;
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let token = invite(&app, &admin, "new@example.com").await;
    let good = code("sub:new", "new@example.com");

    // Google refused, or returned without a code.
    let state = start(&app, "/api/auth/google", None).await;
    fails_with(
        &app,
        &[("error", "access_denied"), ("state", &state)],
        "auth-failed",
    )
    .await;
    fails_with(&app, &[("state", &state)], "auth-failed").await;
    fails_with(&app, &[], "auth-failed").await;

    // A state that was never handed out.
    fails_with(&app, &[("code", &good), ("state", "forged")], "auth-failed").await;

    // The token exchange fails.
    let state = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    fails_with(&app, &[("code", "bad"), ("state", &state)], "auth-failed").await;

    // The state was used up by the failed attempt.
    fails_with(&app, &[("code", &good), ("state", &state)], "auth-failed").await;

    // An unverified email.
    let state = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    fails_with(
        &app,
        &[("code", "sub:new|new@example.com|false"), ("state", &state)],
        "auth-failed",
    )
    .await;

    // A state is good once.
    let state = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    signed_in_with(&app, &state, &good).await;
    fails_with(&app, &[("code", &good), ("state", &state)], "auth-failed").await;
}

#[tokio::test]
async fn switching_to_google_ends_the_other_sessions() {
    let auth = google_auth().await;
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let (_, alice) = regular(&app, &admin, "alice").await;

    let state = start(&app, "/api/auth/google/link", Some(&alice)).await;
    let cookie = signed_in_with(&app, &state, &code("sub:alice", "alice@example.com")).await;

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

    let state = start(&app, "/api/auth/google", None).await;
    signed_in_with(&app, &state, &code("sub:alice", "alice@example.com")).await;
}

#[tokio::test]
async fn a_bound_google_account_cannot_be_linked_again() {
    let auth = google_auth().await;
    let app = router(&auth);
    let admin = admin(&auth, &app).await;
    let token = invite(&app, &admin, "taken@example.com").await;

    let state = start(&app, &format!("/api/auth/google/register/{token}"), None).await;
    signed_in_with(&app, &state, &code("sub:taken", "taken@example.com")).await;

    let (_, bob) = regular(&app, &admin, "bob").await;
    let state = start(&app, "/api/auth/google/link", Some(&bob)).await;
    let taken = code("sub:taken", "bob@example.com");
    fails_with(&app, &[("code", &taken), ("state", &state)], "auth-failed").await;

    // Nothing changed for bob.
    let me = me(&app, &bob).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["method"], json!("password"));
}
