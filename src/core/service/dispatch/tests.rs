//! `Auth::dispatch` over `MemoryStore`: the checks it makes for every
//! transport, and the cookie change each request says it makes.

use std::borrow::ToOwned;
use std::net::{IpAddr, Ipv4Addr};

use super::{Caller, Dispatched, SessionCookie};
use crate::store::{Session, User};
use crate::types::{
    AuthError, AuthRequest, AuthResponse, CookieChange, LoginRequest, NewUser, RegisterRequest,
    Role, UserChange, UserId, UserInfo,
};
use crate::{Auth, MemoryStore, generate_session_key};

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
    let change = request.cookie();
    let dispatched = auth.dispatch(&caller, request).await.unwrap();

    match (change, &dispatched.cookie) {
        (None, None)
        | (Some(CookieChange::Set | CookieChange::Replace), Some(SessionCookie::Set(..)))
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

    // Impersonating replaces the session with one as the user.
    let caller = Caller::new().session(&signed_in.id);
    let dispatched = dispatch(&auth, caller, AuthRequest::Impersonate { id: regular.id }).await;
    let impersonated = new_session(&dispatched);
    let info = user_of(dispatched);
    assert_eq!(info.id, regular.id);
    assert!(info.impersonated_by.is_some());

    // Stopping replaces it with a new one as the admin.
    let caller = Caller::new().session(&impersonated.id);
    let dispatched = dispatch(&auth, caller, AuthRequest::StopImpersonating).await;
    let back = new_session(&dispatched);
    assert_eq!(user_of(dispatched).id, admin.id);
    assert_eq!(back.user, admin.id);

    // Signing out ends the session and clears the cookie.
    let caller = Caller::new().session(&back.id);
    let dispatched = dispatch(&auth, caller, AuthRequest::Logout).await;
    assert_eq!(dispatched.response, AuthResponse::Done);
    assert!(auth.session(&back.id).await.unwrap().is_none());

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
