//! Route-level tests over `MemoryStore`, driving the router with
//! `tower::ServiceExt::oneshot`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::routing::get;
use jiff::{SignedDuration, Timestamp};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::{LiveSession, SignedIn, routes};
use crate::store::User;
use crate::types::{
    Access, CreatedUser, LoginRequest, Method as UserMethod, RegisterRequest, Role, UserChange,
    UserInfo,
};
use crate::{Auth, BootstrapAdmin, MemoryStore, generate_session_key};

const PASSWORD: &str = "password1";

fn auth() -> Auth {
    Auth::builder(MemoryStore::new(), generate_session_key()).build()
}

fn router(auth: &Auth) -> Router {
    routes()
        .route(
            "/tile",
            get(|LiveSession(id): LiveSession| async move { id }),
        )
        .with_state(auth.clone())
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))))
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

impl Answer {
    /// The `name=value` of the response's `Set-Cookie`.
    fn cookie(&self) -> String {
        let set = self.headers[header::SET_COOKIE].to_str().unwrap();
        set.split(';').next().unwrap().to_owned()
    }

    fn error(&self) -> &str {
        self.body["error"].as_str().unwrap_or_default()
    }
}

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> Answer {
    let mut request = Request::builder().method(method).uri(uri);

    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }

    let request = match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => request.body(Body::empty()),
    }
    .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();

    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };

    Answer {
        status,
        headers,
        body,
    }
}

/// Registers through a `/register/{token}` URL, returning the cookie.
async fn register(app: &Router, url: &str) -> String {
    let token = url.rsplit('/').next().unwrap();
    let path = format!("/api/auth/register/{token}");
    let answer = call(
        app,
        Method::POST,
        &path,
        None,
        Some(json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.body);
    answer.cookie()
}

/// Bootstraps and registers the admin `root`, returning their cookie.
async fn admin(auth: &Auth, app: &Router) -> String {
    let url = auth
        .bootstrap_admin(&BootstrapAdmin::login("root"))
        .await
        .unwrap()
        .unwrap();
    register(app, &url).await
}

/// Creates and registers the regular user `login`, returning their id and
/// cookie.
async fn regular(app: &Router, admin: &str, login: &str) -> (u64, String) {
    let created = call(
        app,
        Method::POST,
        "/api/auth/users",
        Some(admin),
        Some(json!({ "login": login, "email": null, "role": "regular" })),
    )
    .await;
    assert_eq!(created.status, StatusCode::OK, "{}", created.body);
    let created: CreatedUser = serde_json::from_value(created.body).unwrap();
    let cookie = register(app, &created.link.token).await;
    (created.entry.user.id.0, cookie)
}

#[tokio::test]
async fn config_me_and_registration() {
    let auth = auth();
    let app = router(&auth);

    let config = call(&app, Method::GET, "/api/auth/config", None, None).await;
    assert_eq!(config.status, StatusCode::OK);
    assert_eq!(
        config.body,
        json!({ "password": true, "google": false, "cloudflare": false, "logins": true })
    );

    let me = call(&app, Method::GET, "/api/auth/me", None, None).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    assert_eq!(me.body, json!({ "error": "unauthorized" }));

    let unknown = call(&app, Method::GET, "/api/auth/register/nope", None, None).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.error(), "not_found");

    let url = auth
        .bootstrap_admin(&BootstrapAdmin::login("root"))
        .await
        .unwrap()
        .unwrap();
    let token = url.rsplit('/').next().unwrap();
    let path = format!("/api/auth/register/{token}");

    let info = call(&app, Method::GET, &path, None, None).await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(
        info.body,
        json!({ "login": "root", "email": null, "google": false })
    );

    let short = call(
        &app,
        Method::POST,
        &path,
        None,
        Some(json!({ "password": "short" })),
    )
    .await;
    assert_eq!(short.status, StatusCode::BAD_REQUEST);
    assert_eq!(short.error(), "invalid");

    let registered = call(
        &app,
        Method::POST,
        &path,
        None,
        Some(json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(registered.status, StatusCode::OK);
    let cookie = registered.cookie();
    assert!(cookie.starts_with("session="), "{cookie}");
    let user: UserInfo = serde_json::from_value(registered.body).unwrap();
    assert_eq!(user.login.as_deref(), Some("root"));
    assert_eq!(user.role, Role::Admin);

    let me = call(&app, Method::GET, "/api/auth/me", Some(&cookie), None).await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(serde_json::from_value::<UserInfo>(me.body).unwrap(), user);

    let used = call(&app, Method::GET, &path, None, None).await;
    assert_eq!(used.status, StatusCode::GONE);
    let used = call(
        &app,
        Method::POST,
        &path,
        None,
        Some(json!({ "password": PASSWORD })),
    )
    .await;
    assert_eq!(used.status, StatusCode::GONE);
    assert_eq!(used.error(), "gone");
}

#[tokio::test]
async fn login_and_logout() {
    let auth = auth();
    let app = router(&auth);
    let first = admin(&auth, &app).await;

    let wrong = call(
        &app,
        Method::POST,
        "/api/auth/login",
        None,
        Some(json!({ "login": "root", "password": "wrong-password" })),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(!wrong.headers.contains_key(header::SET_COOKIE));

    let malformed = call(
        &app,
        Method::POST,
        "/api/auth/login",
        None,
        Some(json!({ "login": 1 })),
    )
    .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert_eq!(malformed.error(), "invalid");

    let login = json!({ "login": "root", "password": PASSWORD });
    let signed_in = call(
        &app,
        Method::POST,
        "/api/auth/login",
        None,
        Some(login.clone()),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::OK);
    assert_eq!(signed_in.body["login"], "root");
    let second = signed_in.cookie();
    assert_ne!(first, second);

    let logout = call(&app, Method::POST, "/api/auth/logout", Some(&second), None).await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);
    let clear = logout.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(
        clear.starts_with("session=;") && clear.contains("Max-Age=0"),
        "{clear}"
    );

    let me = call(&app, Method::GET, "/api/auth/me", Some(&second), None).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    let me = call(&app, Method::GET, "/api/auth/me", Some(&first), None).await;
    assert_eq!(me.status, StatusCode::OK);

    // Signing out without a session still clears the cookie.
    let logout = call(&app, Method::POST, "/api/auth/logout", None, None).await;
    assert_eq!(logout.status, StatusCode::NO_CONTENT);

    // Without connect info the client's address is unknown.
    let bare = routes().with_state(auth.clone());
    let refused = call(&bare, Method::POST, "/api/auth/login", None, Some(login)).await;
    assert_eq!(refused.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn admin_routes() {
    let auth = auth();
    let app = router(&auth);
    let root = admin(&auth, &app).await;
    let (bob, bob_cookie) = regular(&app, &root, "bob").await;
    let bob_path = format!("/api/auth/users/{bob}");

    // Not an admin.
    let refused = call(
        &app,
        Method::GET,
        "/api/auth/users",
        Some(&bob_cookie),
        None,
    )
    .await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.error(), "forbidden");
    let refused = call(&app, Method::GET, "/api/auth/users", None, None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

    let users = call(&app, Method::GET, "/api/auth/users", Some(&root), None).await;
    assert_eq!(users.status, StatusCode::OK);
    assert_eq!(users.body.as_array().unwrap().len(), 2);

    // A taken login.
    let taken = call(
        &app,
        Method::POST,
        "/api/auth/users",
        Some(&root),
        Some(json!({ "login": "bob", "email": null, "role": "regular" })),
    )
    .await;
    assert_eq!(taken.status, StatusCode::CONFLICT);
    assert_eq!(
        taken.body,
        json!({ "error": "conflict", "detail": "login" })
    );

    // Admin rights apply as soon as they are granted.
    let promote = call(
        &app,
        Method::PATCH,
        &bob_path,
        Some(&root),
        Some(json!({ "role": "admin" })),
    )
    .await;
    assert_eq!(promote.status, StatusCode::OK);
    assert_eq!(promote.body["role"], "admin");
    let users = call(
        &app,
        Method::GET,
        "/api/auth/users",
        Some(&bob_cookie),
        None,
    )
    .await;
    assert_eq!(users.status, StatusCode::OK);
    let demote = call(
        &app,
        Method::PATCH,
        &bob_path,
        Some(&root),
        Some(json!({ "role": "regular" })),
    )
    .await;
    assert_eq!(demote.status, StatusCode::OK);
    let users = call(
        &app,
        Method::GET,
        "/api/auth/users",
        Some(&bob_cookie),
        None,
    )
    .await;
    assert_eq!(users.status, StatusCode::FORBIDDEN);

    // Not on oneself.
    let me = call(&app, Method::GET, "/api/auth/me", Some(&root), None).await;
    let root_path = format!("/api/auth/users/{}", me.body["id"]);
    let own_role = call(
        &app,
        Method::PATCH,
        &root_path,
        Some(&root),
        Some(json!({ "role": "regular" })),
    )
    .await;
    assert_eq!(own_role.status, StatusCode::FORBIDDEN);
    let own_delete = call(&app, Method::DELETE, &root_path, Some(&root), None).await;
    assert_eq!(own_delete.status, StatusCode::FORBIDDEN);
    let own_revoke = call(
        &app,
        Method::POST,
        &format!("{root_path}/revoke"),
        Some(&root),
        None,
    )
    .await;
    assert_eq!(own_revoke.status, StatusCode::FORBIDDEN);

    // Ids that are not users.
    let bad = call(
        &app,
        Method::DELETE,
        "/api/auth/users/bob",
        Some(&root),
        None,
    )
    .await;
    assert_eq!(bad.status, StatusCode::NOT_FOUND);
    let missing = call(
        &app,
        Method::POST,
        "/api/auth/users/9999/link",
        Some(&root),
        None,
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);

    // Links.
    let link = call(
        &app,
        Method::POST,
        &format!("{bob_path}/link"),
        Some(&root),
        None,
    )
    .await;
    assert_eq!(link.status, StatusCode::OK);
    let token = link.body["token"].as_str().unwrap().to_owned();
    let info = call(
        &app,
        Method::GET,
        &format!("/api/auth/register/{token}"),
        None,
        None,
    )
    .await;
    assert_eq!(info.status, StatusCode::OK);
    let revoked = call(
        &app,
        Method::DELETE,
        &format!("{bob_path}/link"),
        Some(&root),
        None,
    )
    .await;
    assert_eq!(revoked.status, StatusCode::NO_CONTENT);
    let info = call(
        &app,
        Method::GET,
        &format!("/api/auth/register/{token}"),
        None,
        None,
    )
    .await;
    assert_eq!(info.status, StatusCode::GONE);

    // Sign out everywhere; bob can sign in again.
    let out = call(
        &app,
        Method::POST,
        &format!("{bob_path}/sign-out"),
        Some(&root),
        None,
    )
    .await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    let me = call(&app, Method::GET, "/api/auth/me", Some(&bob_cookie), None).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    let again = call(
        &app,
        Method::POST,
        "/api/auth/login",
        None,
        Some(json!({ "login": "bob", "password": PASSWORD })),
    )
    .await;
    assert_eq!(again.status, StatusCode::OK);
    let bob_cookie = again.cookie();

    // Revoke access; bob cannot.
    let revoke = call(
        &app,
        Method::POST,
        &format!("{bob_path}/revoke"),
        Some(&root),
        None,
    )
    .await;
    assert_eq!(revoke.status, StatusCode::OK);
    assert_eq!(revoke.body["access"], "revoked");
    let me = call(&app, Method::GET, "/api/auth/me", Some(&bob_cookie), None).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);

    let deleted = call(&app, Method::DELETE, &bob_path, Some(&root), None).await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let users = call(&app, Method::GET, "/api/auth/users", Some(&root), None).await;
    assert_eq!(users.body.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn account_routes() {
    let auth = auth();
    let app = router(&auth);
    let root = admin(&auth, &app).await;
    let login = json!({ "login": "root", "password": PASSWORD });
    let other = call(&app, Method::POST, "/api/auth/login", None, Some(login))
        .await
        .cookie();

    let renamed = call(
        &app,
        Method::PATCH,
        "/api/auth/account",
        Some(&root),
        Some(json!({ "login": "boss", "email": "Boss@Example.com" })),
    )
    .await;
    assert_eq!(renamed.status, StatusCode::OK, "{}", renamed.body);
    assert_eq!(renamed.body["login"], "boss");
    assert_eq!(renamed.body["email"], "boss@example.com");

    let role = call(
        &app,
        Method::PATCH,
        "/api/auth/account",
        Some(&root),
        Some(json!({ "role": "regular" })),
    )
    .await;
    assert_eq!(role.status, StatusCode::BAD_REQUEST);

    let wrong = call(
        &app,
        Method::POST,
        "/api/auth/account/password",
        Some(&root),
        Some(json!({ "old_password": "wrong-password", "new_password": "password2" })),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.error(), "invalid");

    let changed = call(
        &app,
        Method::POST,
        "/api/auth/account/password",
        Some(&root),
        Some(json!({ "old_password": PASSWORD, "new_password": "password2" })),
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK);
    assert_eq!(changed.body["login"], "boss");

    // This session stays, the other one ends.
    let me = call(&app, Method::GET, "/api/auth/me", Some(&root), None).await;
    assert_eq!(me.status, StatusCode::OK);
    let me = call(&app, Method::GET, "/api/auth/me", Some(&other), None).await;
    assert_eq!(me.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn impersonation() {
    let auth = auth();
    let app = router(&auth);
    let root = admin(&auth, &app).await;

    // A pending user may be impersonated.
    let created = call(
        &app,
        Method::POST,
        "/api/auth/users",
        Some(&root),
        Some(json!({ "login": "pat", "email": null, "role": "regular" })),
    )
    .await;
    let created: CreatedUser = serde_json::from_value(created.body).unwrap();
    let path = format!("/api/auth/users/{}/impersonate", created.entry.user.id);

    let refused = call(&app, Method::POST, &path, Some(&root), None).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);

    // With impersonation on.
    let auth = Auth::builder(MemoryStore::new(), generate_session_key())
        .impersonation(true)
        .build();
    let app = router(&auth);
    let root = admin(&auth, &app).await;
    let created = call(
        &app,
        Method::POST,
        "/api/auth/users",
        Some(&root),
        Some(json!({ "login": "pat", "email": null, "role": "regular" })),
    )
    .await;
    let created: CreatedUser = serde_json::from_value(created.body).unwrap();
    let path = format!("/api/auth/users/{}/impersonate", created.entry.user.id);

    let as_pat = call(&app, Method::POST, &path, Some(&root), None).await;
    assert_eq!(as_pat.status, StatusCode::OK);
    assert_eq!(as_pat.body["login"], "pat");
    let me = call(
        &app,
        Method::GET,
        "/api/auth/me",
        Some(&as_pat.cookie()),
        None,
    )
    .await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.body["access"], "pending");
}

#[tokio::test]
async fn live_session() {
    let auth = auth();
    let app = router(&auth);

    let refused = call(&app, Method::GET, "/tile", None, None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

    let root = admin(&auth, &app).await;
    let tile = call(&app, Method::GET, "/tile", Some(&root), None).await;
    assert_eq!(tile.status, StatusCode::OK);
    assert_eq!(auth.live_cache().len(), 1);
    let tile = call(&app, Method::GET, "/tile", Some(&root), None).await;
    assert_eq!(tile.status, StatusCode::OK);

    // Signing out ends the cached session at once.
    call(&app, Method::POST, "/api/auth/logout", Some(&root), None).await;
    assert_eq!(auth.live_cache().len(), 0);
    let tile = call(&app, Method::GET, "/tile", Some(&root), None).await;
    assert_eq!(tile.status, StatusCode::UNAUTHORIZED);
}

/// The admin `root`, registered through the service, as an extractor would
/// load them.
async fn signed_in(auth: &Auth) -> SignedIn {
    let url = auth
        .bootstrap_admin(&BootstrapAdmin::login("root"))
        .await
        .unwrap()
        .unwrap();
    let token = url.rsplit('/').next().unwrap();
    let request = RegisterRequest {
        password: PASSWORD.to_owned(),
    };
    let (user, session) = auth.register(token, &request).await.unwrap();
    SignedIn { user, session }
}

const WAIT: Duration = Duration::from_secs(5);
const BRIEFLY: Duration = Duration::from_millis(100);

#[tokio::test]
async fn guard_ends_on_sign_out() {
    let auth = auth();
    let root = signed_in(&auth).await;
    let guard = auth.guard(&root);

    // Ending another session of the user keeps this one.
    let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let login = LoginRequest {
        login: "root".to_owned(),
        password: PASSWORD.to_owned(),
    };
    let (_, other) = auth.sign_in_password(address, &login).await.unwrap();
    auth.sign_out(&other.id).await.unwrap();
    assert!(tokio::time::timeout(BRIEFLY, guard.ended()).await.is_err());

    auth.sign_out(&root.session.id).await.unwrap();
    tokio::time::timeout(WAIT, guard.ended()).await.unwrap();
    // And it stays ended.
    tokio::time::timeout(WAIT, guard.ended()).await.unwrap();
}

#[tokio::test]
async fn guard_follows_user_changes() {
    let auth = auth();
    let root = signed_in(&auth).await;
    let (pat, _) = auth
        .create_user(
            &root.user,
            &crate::NewUser {
                login: Some("pat".to_owned()),
                email: None,
                role: Role::Regular,
            },
        )
        .await
        .unwrap();

    let guard = auth.guard(&root);

    // Another user's change is not this socket's.
    let rename = UserChange {
        login: Some(Some("patty".to_owned())),
        ..UserChange::default()
    };
    auth.update_user(&root.user, pat.user.id, &rename)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(BRIEFLY, guard.changed())
            .await
            .is_err()
    );

    let rename = UserChange {
        login: Some(Some("boss".to_owned())),
        ..UserChange::default()
    };
    auth.update_user(&root.user, root.user.id, &rename)
        .await
        .unwrap();
    let info = tokio::time::timeout(WAIT, guard.changed()).await.unwrap();
    assert_eq!(info.login.as_deref(), Some("boss"));

    // A credential change elsewhere keeps the session it was made from:
    // here, another one.
    let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let login = LoginRequest {
        login: "boss".to_owned(),
        password: PASSWORD.to_owned(),
    };
    let (user, other) = auth.sign_in_password(address, &login).await.unwrap();
    let change = crate::PasswordChange {
        old_password: Some(PASSWORD.to_owned()),
        new_password: "password2".to_owned(),
    };
    auth.change_password(&user, &other, &change).await.unwrap();
    tokio::time::timeout(WAIT, guard.ended()).await.unwrap();
}

#[tokio::test]
async fn guard_ends_on_delete_and_expiry() {
    let auth = auth();
    let root = signed_in(&auth).await;

    // Expiry, from the session the request loaded.
    let mut soon = root.clone();
    soon.session.expires_at = Timestamp::now() + SignedDuration::from_millis(200);
    let guard = auth.guard(&soon);
    assert!(tokio::time::timeout(BRIEFLY, guard.ended()).await.is_err());
    tokio::time::timeout(WAIT, guard.ended()).await.unwrap();

    // A session that ended before the guard started.
    let (pat, _) = auth
        .create_user(
            &root.user,
            &crate::NewUser {
                login: Some("pat".to_owned()),
                email: None,
                role: Role::Admin,
            },
        )
        .await
        .unwrap();
    // The admin as a request would load them.
    let pat = User {
        id: pat.user.id,
        login: pat.user.login,
        email: None,
        role: Role::Admin,
        access: Access::Pending,
        method: UserMethod::Password,
        password_hash: None,
        google_sub: None,
        created_at: pat.user.created_at,
    };
    let guard = auth.guard(&root);
    assert!(tokio::time::timeout(BRIEFLY, guard.ended()).await.is_err());
    auth.delete_user(&pat, root.user.id).await.unwrap();
    tokio::time::timeout(WAIT, guard.ended()).await.unwrap();

    let gone = auth.guard(&root);
    tokio::time::timeout(WAIT, gone.ended()).await.unwrap();
}

/// `POST /api/auth/cloudflare` and the `cloudflare` flag of
/// `GET /api/auth/config`, with Access believing the email header.
#[cfg(feature = "cloudflare")]
mod cloudflare {
    use axum::http::HeaderValue;

    use super::*;
    use crate::cloudflare::EMAIL_HEADER;
    use crate::types::CloudflareConfig;

    fn header_only() -> CloudflareConfig {
        CloudflareConfig {
            enabled: true,
            team_domain: "example.cloudflareaccess.com".to_owned(),
            audience: "aud".to_owned(),
            trust_email_header: true,
            verify_jwt: false,
        }
    }

    /// Calls `uri` with Access vouching for `email`, if any.
    async fn access(app: &Router, method: Method, uri: &str, email: Option<&str>) -> Answer {
        let mut request = Request::builder().method(method).uri(uri);

        if let Some(email) = email {
            request = request.header(EMAIL_HEADER, HeaderValue::from_str(email).unwrap());
        }

        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };

        Answer {
            status,
            headers,
            body,
        }
    }

    async fn available(app: &Router, email: Option<&str>) -> bool {
        let config = access(app, Method::GET, "/api/auth/config", email).await;
        assert_eq!(config.status, StatusCode::OK, "{}", config.body);
        config.body["cloudflare"].as_bool().unwrap()
    }

    /// Creates the pending regular user with `email`, returning their id.
    async fn pending(app: &Router, admin: &str, email: &str) -> u64 {
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
        assert_eq!(created.entry.user.access, Access::Pending);
        created.entry.user.id.0
    }

    #[tokio::test]
    async fn sign_in_activates_pending_user() {
        let auth = Auth::builder(MemoryStore::new(), generate_session_key())
            .cloudflare(Some(header_only()))
            .build();
        let app = router(&auth);
        let admin = admin(&auth, &app).await;
        let id = pending(&app, &admin, "alice@example.com").await;

        assert!(!available(&app, None).await);
        assert!(!available(&app, Some("nobody@example.com")).await);
        assert!(available(&app, Some("alice@example.com")).await);

        for email in [None, Some("nobody@example.com")] {
            let refused = access(&app, Method::POST, "/api/auth/cloudflare", email).await;
            assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
            assert_eq!(refused.error(), "unauthorized");
            assert!(!refused.headers.contains_key(header::SET_COOKIE));
        }

        let signed_in = access(
            &app,
            Method::POST,
            "/api/auth/cloudflare",
            Some("alice@example.com"),
        )
        .await;
        assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.body);
        let cookie = signed_in.cookie();
        assert!(cookie.starts_with("session="), "{cookie}");
        let user: UserInfo = serde_json::from_value(signed_in.body).unwrap();
        assert_eq!(user.id.0, id);
        assert_eq!(user.access, Access::Active);
        assert_eq!(user.email.as_deref(), Some("alice@example.com"));

        let me = call(&app, Method::GET, "/api/auth/me", Some(&cookie), None).await;
        assert_eq!(me.status, StatusCode::OK);
        assert_eq!(serde_json::from_value::<UserInfo>(me.body).unwrap(), user);
    }

    #[tokio::test]
    async fn revoked_user_is_refused() {
        let auth = Auth::builder(MemoryStore::new(), generate_session_key())
            .cloudflare(Some(header_only()))
            .build();
        let app = router(&auth);
        let admin = admin(&auth, &app).await;
        let id = pending(&app, &admin, "bob@example.com").await;

        let signed_in = access(
            &app,
            Method::POST,
            "/api/auth/cloudflare",
            Some("bob@example.com"),
        )
        .await;
        assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.body);
        let cookie = signed_in.cookie();

        let revoked = call(
            &app,
            Method::POST,
            &format!("/api/auth/users/{id}/revoke"),
            Some(&admin),
            None,
        )
        .await;
        assert_eq!(revoked.status, StatusCode::OK, "{}", revoked.body);

        assert!(!available(&app, Some("bob@example.com")).await);
        let refused = access(
            &app,
            Method::POST,
            "/api/auth/cloudflare",
            Some("bob@example.com"),
        )
        .await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
        assert_eq!(refused.error(), "unauthorized");
        assert!(!refused.headers.contains_key(header::SET_COOKIE));

        let me = call(&app, Method::GET, "/api/auth/me", Some(&cookie), None).await;
        assert_eq!(me.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn follows_runtime_settings() {
        let auth = Auth::builder(MemoryStore::new(), generate_session_key()).build();
        let app = router(&auth);
        let admin = admin(&auth, &app).await;
        pending(&app, &admin, "carol@example.com").await;
        let carol = Some("carol@example.com");

        assert!(!available(&app, carol).await);
        let refused = access(&app, Method::POST, "/api/auth/cloudflare", carol).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);

        auth.set_cloudflare(Some(header_only()));
        assert!(available(&app, carol).await);
        let signed_in = access(&app, Method::POST, "/api/auth/cloudflare", carol).await;
        assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.body);

        auth.set_cloudflare(Some(CloudflareConfig {
            enabled: false,
            ..header_only()
        }));
        assert!(!available(&app, carol).await);
        let refused = access(&app, Method::POST, "/api/auth/cloudflare", carol).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    }
}
