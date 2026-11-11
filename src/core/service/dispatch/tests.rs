//! `Auth::dispatch` over `MemoryStore`: the checks it makes for every
//! transport, and the cookie change each request says it makes.

use std::borrow::ToOwned;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use http::{HeaderMap, HeaderValue, header};

use super::{Caller, Dispatched, SessionCookie};
use crate::core::AuditEvent;
use crate::store::{Session, User};
use crate::types::{
    AuthError, AuthRequest, AuthResponse, CookieChange, LoginRequest, NewUser, PAGE_SESSION_HEADER,
    PageSession, PasswordChange, RegisterRequest, Role, UserChange, UserId, UserInfo,
};
use crate::{Auth, MemoryStore, generate_session_key, verify_page_credential};

const PASSWORD: &str = "password1";

fn auth() -> Auth {
    Auth::builder(MemoryStore::new(), generate_session_key())
        .impersonation(true)
        .build()
}

async fn user(auth: &Auth, login: &str, role: Role) -> (User, Session) {
    let new = NewUser {
        login: Some(login.to_owned()),
        email: None,
        role,
    };

    let user = auth.test_user(&new, PASSWORD).await.unwrap();
    let session = auth.test_session(&user).await.unwrap();
    (user, session)
}

async fn dispatch(auth: &Auth, caller: Caller<'_>, request: AuthRequest) -> Dispatched {
    let page = caller
        .headers
        .is_some_and(|headers| headers.contains_key(PAGE_SESSION_HEADER));
    let change = request.cookie().filter(|_| !page);
    let dispatched = auth.dispatch(&caller, request).await.unwrap();

    match (change, &dispatched.cookie) {
        (None, None)
        | (Some(CookieChange::Set), Some(SessionCookie::Set(..)))
        | (Some(CookieChange::Clear), Some(SessionCookie::Clear)) => {}
        (change, cookie) => panic!("{change:?} answered with {cookie:?}"),
    }

    dispatched
}

async fn refusal(auth: &Auth, caller: Caller<'_>, request: AuthRequest) -> AuthError {
    match auth.dispatch(&caller, request).await {
        Ok(dispatched) => panic!("answered {dispatched:?}"),
        Err(error) => error.auth_error().cloned().expect("a refusal"),
    }
}

fn user_of(dispatched: Dispatched) -> UserInfo {
    match dispatched.response {
        AuthResponse::User(info) => info,
        response => panic!("not a user: {response:?}"),
    }
}

fn page_session(dispatched: Dispatched) -> PageSession {
    assert_eq!(dispatched.cookie, None);

    match dispatched.response {
        AuthResponse::PageSession(page) => page,
        response => panic!("not a page session: {response:?}"),
    }
}

/// The headers of a request from an impersonated page: the admin's cookie
/// and the page's credential.
fn page_headers(auth: &Auth, cookie: &str, credential: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::COOKIE, auth.cookie_header(cookie));
    headers.insert(
        PAGE_SESSION_HEADER,
        HeaderValue::from_str(credential).unwrap(),
    );
    headers
}

fn new_session(dispatched: &Dispatched) -> Session {
    match &dispatched.cookie {
        Some(SessionCookie::Set(session)) => session.clone(),
        cookie => panic!("no new session: {cookie:?}"),
    }
}

#[tokio::test]
async fn signed_in_requests_need_a_live_session() {
    let auth = auth();
    let (admin, session) = user(&auth, "root", Role::Admin).await;

    assert_eq!(
        refusal(&auth, Caller::new(), AuthRequest::Me).await,
        AuthError::Unauthorized
    );

    assert_eq!(
        refusal(&auth, Caller::new().session("nope"), AuthRequest::Me).await,
        AuthError::Unauthorized
    );

    let me = user_of(dispatch(&auth, Caller::new().session(&session.id), AuthRequest::Me).await);
    assert_eq!(me.id, admin.id);

    let me = user_of(
        dispatch(
            &auth,
            Caller::new().signed_in(&admin, &session),
            AuthRequest::Me,
        )
        .await,
    );
    assert_eq!(me.id, admin.id);
}

#[tokio::test]
async fn admin_requests_need_an_admin() {
    let auth = auth();
    let (_, root) = user(&auth, "root", Role::Admin).await;
    let (regular, session) = user(&auth, "regular", Role::Regular).await;

    let caller = Caller::new().session(&session.id);

    for request in [
        AuthRequest::Users,
        AuthRequest::DeleteUser { id: UserId(1) },
        AuthRequest::UpdateUser {
            id: regular.id,
            change: UserChange::default(),
        },
        AuthRequest::Cloudflare,
        AuthRequest::Google,
        AuthRequest::SetGoogle(Default::default()),
    ] {
        assert_eq!(refusal(&auth, caller, request).await, AuthError::Forbidden);
    }

    let caller = Caller::new().session(&root.id);

    match dispatch(&auth, caller, AuthRequest::Users).await.response {
        AuthResponse::Users(users) => assert_eq!(users.len(), 2),
        response => panic!("{response:?}"),
    }

    let dispatched = dispatch(&auth, caller, AuthRequest::SignOutUser { id: regular.id }).await;
    assert_eq!(dispatched.response, AuthResponse::Done);
    assert!(auth.session(&session.id).await.unwrap().is_none());
}

#[tokio::test]
async fn the_cookie_requests_say_what_to_do_with_it() {
    let auth = auth();
    let (admin, _) = user(&auth, "root", Role::Admin).await;
    let (regular, _) = user(&auth, "regular", Role::Regular).await;

    let login = AuthRequest::Login(LoginRequest {
        login: "root".to_owned(),
        password: PASSWORD.to_owned(),
    });

    // A sign-in needs the client's address, to throttle by.
    assert_eq!(
        refusal(&auth, Caller::new(), login.clone()).await,
        AuthError::Forbidden
    );

    let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let dispatched = dispatch(&auth, Caller::new().address(address), login).await;
    let signed_in = new_session(&dispatched);
    assert_eq!(user_of(dispatched).id, admin.id);

    // Impersonating answers a page session and leaves the cookie alone.
    let caller = Caller::new().session(&signed_in.id);
    let dispatched = dispatch(&auth, caller, AuthRequest::Impersonate { id: regular.id }).await;
    let page = page_session(dispatched);
    assert_eq!(page.user.id, regular.id);
    assert_eq!(
        page.user.impersonated_by.as_ref().map(|by| by.id),
        Some(admin.id)
    );

    // Stopping ends the page's session alone, and leaves the cookie alone.
    let headers = page_headers(&auth, &signed_in.id, &page.credential);
    let (_, impersonated) = auth.request_session(&headers).await.unwrap().unwrap();
    let caller = Caller::new().headers(&headers);
    let dispatched = dispatch(&auth, caller, AuthRequest::StopImpersonating).await;
    assert_eq!(dispatched.response, AuthResponse::Done);
    assert_eq!(dispatched.cookie, None);
    assert!(auth.session(&impersonated.id).await.unwrap().is_none());
    assert!(auth.session(&signed_in.id).await.unwrap().is_some());

    // Signing out ends the session and clears the cookie.
    let caller = Caller::new().session(&signed_in.id);
    let dispatched = dispatch(&auth, caller, AuthRequest::Logout).await;
    assert_eq!(dispatched.response, AuthResponse::Done);
    assert!(auth.session(&signed_in.id).await.unwrap().is_none());

    // Signed out, it still clears the cookie.
    let dispatched = dispatch(&auth, Caller::new(), AuthRequest::Logout).await;
    assert_eq!(dispatched.cookie, Some(SessionCookie::Clear));
}

#[tokio::test]
async fn registering_signs_in() {
    let auth = auth();
    let (admin, session) = user(&auth, "root", Role::Admin).await;

    let new = NewUser {
        login: Some("new".to_owned()),
        email: None,
        role: Role::Regular,
    };

    let caller = Caller::new().signed_in(&admin, &session);

    let link = match dispatch(&auth, caller, AuthRequest::CreateUser(new))
        .await
        .response
    {
        AuthResponse::CreatedUser(created) => created.link,
        response => panic!("{response:?}"),
    };

    let info = AuthRequest::RegisterInfo {
        token: link.token.clone(),
    };

    match dispatch(&auth, Caller::new(), info).await.response {
        AuthResponse::RegisterInfo(info) => assert_eq!(info.login.as_deref(), Some("new")),
        response => panic!("{response:?}"),
    }

    let register = AuthRequest::Register {
        token: link.token,
        request: RegisterRequest {
            password: PASSWORD.to_owned(),
        },
    };

    let dispatched = dispatch(&auth, Caller::new(), register).await;
    let session = new_session(&dispatched);
    let info = user_of(dispatched);
    assert_eq!(session.user, info.id);
}

#[tokio::test]
async fn a_page_credential_never_touches_the_cookie() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    let auth = Auth::builder(MemoryStore::new(), generate_session_key())
        .impersonation(true)
        .audit(move |event| sink.lock().unwrap().push(event.clone()))
        .build();
    let take = || std::mem::take(&mut *log.lock().unwrap());

    let (admin, cookie) = user(&auth, "root", Role::Admin).await;
    let (regular, theirs) = user(&auth, "regular", Role::Regular).await;

    let caller = Caller::new().signed_in(&admin, &cookie);
    let impersonate = AuthRequest::Impersonate { id: regular.id };
    let page = page_session(dispatch(&auth, caller, impersonate).await);
    let headers = page_headers(&auth, &cookie.id, &page.credential);
    let (_, session) = auth.request_session(&headers).await.unwrap().unwrap();
    assert_eq!(session.impersonator, Some(admin.id));

    // The sign-ins are refused with a page credential, valid or not.
    let bogus = page_headers(&auth, &cookie.id, "bogus");
    let address = IpAddr::V4(Ipv4Addr::LOCALHOST);

    for headers in [&headers, &bogus] {
        let login = AuthRequest::Login(LoginRequest {
            login: "regular".to_owned(),
            password: PASSWORD.to_owned(),
        });
        let register = AuthRequest::Register {
            token: "token".to_owned(),
            request: RegisterRequest {
                password: PASSWORD.to_owned(),
            },
        };

        for request in [login, AuthRequest::CloudflareSignIn, register] {
            let caller = Caller::new().headers(headers).address(address);
            assert_eq!(
                refusal(&auth, caller, request.clone()).await,
                AuthError::Forbidden,
                "{request:?}"
            );
        }
    }

    // A password change in the page keeps its session and ends the user's
    // others, never the admin's.
    let change = PasswordChange {
        old_password: Some(PASSWORD.to_owned()),
        new_password: "password2".to_owned(),
    };
    let (user, signed_in) = auth.request_session(&headers).await.unwrap().unwrap();
    let caller = Caller::new().signed_in(&user, &signed_in);
    dispatch(&auth, caller, AuthRequest::ChangePassword(change)).await;
    assert!(auth.request_session(&headers).await.unwrap().is_some());
    assert!(auth.session(&theirs.id).await.unwrap().is_none());
    assert!(auth.session(&cookie.id).await.unwrap().is_some());

    // Signing out with a bad credential does nothing.
    take();
    let dispatched = dispatch(&auth, Caller::new().headers(&bogus), AuthRequest::Logout).await;
    assert_eq!(dispatched.cookie, None);
    assert!(auth.request_session(&headers).await.unwrap().is_some());
    assert_eq!(take(), []);

    // Signing out ends the page's session alone, as stopping does.
    let dispatched = dispatch(&auth, Caller::new().headers(&headers), AuthRequest::Logout).await;
    assert_eq!(dispatched.response, AuthResponse::Done);
    assert_eq!(dispatched.cookie, None);
    assert!(auth.session(&session.id).await.unwrap().is_none());
    assert!(auth.session(&cookie.id).await.unwrap().is_some());
    assert_eq!(
        take(),
        [AuditEvent::ImpersonationStopped {
            admin: admin.id,
            user: regular.id,
        }]
    );

    // The credential names the session it was minted for.
    assert_eq!(
        verify_page_credential(&auth.inner.key, &page.credential),
        Some(session.id.as_str())
    );
}
