//! Tests of [`require_session`](crate::axum08::require_session) and
//! [`is_public`](crate::axum08::is_public).

use axum08::Extension;
use axum08::middleware::from_fn_with_state;

use super::*;
use crate::axum08::gate::sign_in_url;
use crate::axum08::{RequireSession, is_public, require_session};

#[test]
fn public_paths() {
    assert!(is_public("/api/auth/config"));
    assert!(is_public("/api/auth/register/abc"));
    assert!(is_public("/register/abc"));
    assert!(!is_public("/"));
    assert!(!is_public("/api/auth"));
    assert!(!is_public("/api/notes"));
    assert!(!is_public("/register"));
    assert!(!is_public("/users/register/abc"));
}

#[test]
fn sign_in_urls() {
    assert_eq!(sign_in_url("/login", "/"), "/login");
    assert_eq!(sign_in_url("/login", "/notes"), "/login?next=/notes");
    assert_eq!(
        sign_in_url("/login", "/notes/a b?q=x&r=%2F#"),
        "/login?next=/notes/a%20b%3Fq%3Dx%26r%3D%252F%23"
    );
    assert_eq!(sign_in_url("/login", "/?q=1"), "/login?next=/%3Fq%3D1");
    // An `?error=` moves to the sign-in page's own query.
    assert_eq!(
        sign_in_url("/login", "/?error=auth-failed"),
        "/login?error=auth-failed"
    );
    assert_eq!(
        sign_in_url("/login", "/a?b=1&error=user-not-found&c=2"),
        "/login?error=user-not-found&next=/a%3Fb%3D1%26c%3D2"
    );
}

fn gated(auth: &Auth) -> Router {
    let gate =
        RequireSession::new(auth.clone(), "/login").public(|path| path.starts_with("/assets/"));

    routes()
        .route(
            "/api/notes",
            get(|Extension(signed_in): Extension<SignedIn>| async move {
                signed_in.user.id.0.to_string()
            }),
        )
        .route(
            "/admin",
            get(
                |super::super::Admin(admin): super::super::Admin| async move {
                    admin.user.id.0.to_string()
                },
            ),
        )
        .fallback(|| async { "app" })
        .layer(from_fn_with_state(gate, require_session))
        .with_state(auth.clone())
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))))
}

/// Requests `uri` as a browser loading a page would.
async fn page(app: &Router, uri: &str, cookie: Option<&str>) -> Answer {
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(header::ACCEPT, "text/html,application/xhtml+xml,*/*;q=0.8");

    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }

    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();

    Answer {
        status: response.status(),
        headers: response.headers().clone(),
        body: Value::Null,
    }
}

fn location(answer: &Answer) -> &str {
    answer.headers[header::LOCATION].to_str().unwrap()
}

#[tokio::test]
async fn require_session_gates() {
    let auth = auth();
    let app = gated(&auth);

    // Public: watchword's routes, the sign-in page and the app's own.
    let config = call(&app, Method::GET, "/api/auth/config", None, None).await;
    assert_eq!(config.status, StatusCode::OK);
    assert_eq!(page(&app, "/login", None).await.status, StatusCode::OK);
    assert_eq!(
        page(&app, "/login?next=/notes", None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        page(&app, "/register/abc", None).await.status,
        StatusCode::OK
    );
    let asset = call(&app, Method::GET, "/assets/app.wasm", None, None).await;
    assert_eq!(asset.status, StatusCode::OK);
    assert_eq!(asset.body, json!("app"));

    // A page redirects to sign-in, coming back afterwards.
    let redirect = page(&app, "/notes?q=1", None).await;
    assert_eq!(redirect.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&redirect), "/login?next=/notes%3Fq%3D1");

    let redirect = page(&app, "/", None).await;
    assert_eq!(redirect.status, StatusCode::SEE_OTHER);
    assert_eq!(location(&redirect), "/login");

    // The API, and anything that does not accept HTML, is refused.
    let refused = call(&app, Method::GET, "/api/notes", None, None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.error(), "unauthorized");
    let refused = page(&app, "/api/notes", None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    let refused = call(&app, Method::GET, "/notes", None, None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    let refused = call(&app, Method::POST, "/notes", None, None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

    // An unknown cookie is no session.
    let refused = page(&app, "/notes", Some("session=nope")).await;
    assert_eq!(refused.status, StatusCode::SEE_OTHER);

    // Signed in, everything goes through, with the session in the
    // extensions.
    let admin = admin(&auth, &app).await;
    let (id, regular) = regular(&app, &admin, "alice").await;
    assert_eq!(
        page(&app, "/notes", Some(&regular)).await.status,
        StatusCode::OK
    );
    let notes = call(&app, Method::GET, "/api/notes", Some(&regular), None).await;
    assert_eq!(notes.status, StatusCode::OK);
    assert_eq!(notes.body, json!(id));
    let me = call(&app, Method::GET, "/api/auth/me", Some(&regular), None).await;
    assert_eq!(me.status, StatusCode::OK);

    // The extractors behind it still check the role.
    let forbidden = call(&app, Method::GET, "/admin", Some(&regular), None).await;
    assert_eq!(forbidden.status, StatusCode::FORBIDDEN);
    let allowed = call(&app, Method::GET, "/admin", Some(&admin), None).await;
    assert_eq!(allowed.status, StatusCode::OK);

    // Signing out ends it.
    let out = call(&app, Method::POST, "/api/auth/logout", Some(&regular), None).await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    let refused = call(&app, Method::GET, "/api/notes", Some(&regular), None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
}
