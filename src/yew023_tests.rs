//! watchword-yew023's `AuthService` over a `Transport` wired straight to
//! `Auth::dispatch` on a `MemoryStore`: the service's operations end to end,
//! without HTTP or a socket, as an app's test of its own components would
//! wire it.

use std::borrow::ToOwned;
use std::boxed::Box;
use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr};
use std::string::{String, ToString};

use crate::core::{Caller, SessionCookie};
use crate::types::{
    AuthError, AuthRequest, AuthResponse, LoginRequest, NewUser, PasswordChange, Role, UserChange,
};
use crate::yew023::{AuthService, Error, Transport, TransportFuture};
use crate::{Auth, MemoryStore, generate_session_key};

const PASSWORD: &str = "password1";

/// Dispatches each request on the server as this browser, keeping the
/// session its cookie would hold.
struct Dispatch {
    auth: Auth,
    session: RefCell<Option<String>>,
}

impl Transport for Dispatch {
    fn send(&self, request: AuthRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            let session = self.session.borrow().clone();
            let mut caller = Caller::new().address(IpAddr::V4(Ipv4Addr::LOCALHOST));

            if let Some(session) = &session {
                caller = caller.session(session);
            }

            let dispatched = match self.auth.dispatch(&caller, request).await {
                Ok(dispatched) => dispatched,
                Err(error) => {
                    return Err(match error.auth_error() {
                        Some(error) => Error::Auth(error.clone()),
                        None => Error::Network(error.to_string()),
                    });
                }
            };

            match dispatched.cookie {
                Some(SessionCookie::Set(session)) => *self.session.borrow_mut() = Some(session.id),
                Some(SessionCookie::Clear) => *self.session.borrow_mut() = None,
                None => {}
            }

            Ok(dispatched.response)
        })
    }
}

async fn setup() -> AuthService {
    let auth = Auth::builder(MemoryStore::new(), generate_session_key())
        .impersonation(true)
        .build();

    for (login, role) in [("root", Role::Admin), ("bob", Role::Regular)] {
        let new = NewUser {
            login: Some(login.to_owned()),
            email: None,
            role,
        };

        auth.test_user(&new, PASSWORD).await.unwrap();
    }

    AuthService::new(Dispatch {
        auth,
        session: RefCell::new(None),
    })
}

fn login(login: &str) -> LoginRequest {
    LoginRequest {
        login: login.to_owned(),
        password: PASSWORD.to_owned(),
    }
}

#[tokio::test]
async fn signs_in_and_out() {
    let service = setup().await;

    assert!(service.me().await.unwrap_err().is_unauthorized());
    assert!(service.config().await.unwrap().password);

    let bob = service.login(login("bob")).await.unwrap();
    assert_eq!(bob.login.as_deref(), Some("bob"));
    assert_eq!(service.me().await.unwrap().id, bob.id);

    service.logout().await.unwrap();
    assert!(service.me().await.unwrap_err().is_unauthorized());
}

#[tokio::test]
async fn account_operations() {
    let service = setup().await;
    service.login(login("bob")).await.unwrap();

    let change = UserChange {
        login: Some(Some("robert".to_owned())),
        ..UserChange::default()
    };

    let user = service.update_account(change).await.unwrap();
    assert_eq!(user.login.as_deref(), Some("robert"));

    let change = PasswordChange {
        old_password: Some("wrong-password".to_owned()),
        new_password: "password2".to_owned(),
    };

    assert!(matches!(
        service.change_password(change).await,
        Err(Error::Auth(
            AuthError::Unauthorized | AuthError::Invalid(..)
        ))
    ));

    // Admin operations are refused.
    assert_eq!(
        service.users().await.unwrap_err(),
        Error::Auth(AuthError::Forbidden)
    );
}

#[tokio::test]
async fn admin_operations_and_impersonation() {
    let service = setup().await;
    let root = service.login(login("root")).await.unwrap();

    let new = NewUser {
        login: Some("carol".to_owned()),
        email: None,
        role: Role::Regular,
    };

    let created = service.create_user(new).await.unwrap();
    let carol = created.entry.user.id;
    assert_eq!(service.users().await.unwrap().len(), 3);

    let link = service.issue_link(carol).await.unwrap();
    assert_ne!(link.token, created.link.token);
    service.revoke_link(carol).await.unwrap();

    let bob = service
        .users()
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.user.login.as_deref() == Some("bob"))
        .unwrap()
        .user;

    let change = UserChange {
        role: Some(Role::Admin),
        ..UserChange::default()
    };

    assert_eq!(
        service.update_user(bob.id, change).await.unwrap().role,
        Role::Admin
    );

    service.sign_out_user(bob.id).await.unwrap();

    // Impersonating replaces the session, which the transport keeps.
    let acting = service.impersonate(bob.id).await.unwrap();
    assert_eq!(acting.id, bob.id);
    let me = service.me().await.unwrap();
    assert_eq!(me.id, bob.id);
    assert!(me.impersonated_by.is_some());

    assert_eq!(service.stop_impersonating().await.unwrap().id, root.id);
    assert_eq!(service.me().await.unwrap().id, root.id);

    service.delete_user(carol).await.unwrap();
    assert_eq!(service.users().await.unwrap().len(), 2);
}

/// A transport answering with the wrong response is caught by the service.
#[tokio::test]
async fn unexpected_response() {
    struct Wrong;

    impl Transport for Wrong {
        fn send(&self, _: AuthRequest) -> TransportFuture<'_> {
            Box::pin(async { Ok(AuthResponse::Done) })
        }
    }

    let service = AuthService::new(Wrong);
    assert_eq!(service.me().await.unwrap_err(), Error::UnexpectedResponse);
    service.logout().await.unwrap();
}
