//! HTTP/socket parity: every endpoint of watchword's musli-web list decodes
//! into an `AuthRequest` that leaves the session cookie alone, and an HTTP
//! route takes that same request. Both transports then run it through
//! `Auth::dispatch`, so they answer it alike.

use std::any::Any;
use std::borrow::ToOwned;
use std::boxed::Box;
use std::format;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use axum08::body::Body;
use axum08::http::{Method, Request as HttpRequest, StatusCode, header};
use musli_web05::api::{DecodeBody, Id as _, MessageId};
use serde_json::Value;
use tower::ServiceExt;

use super::super::connection::{ReadBody, decode};
use super::super::{
    CloudflareRequest, DeleteUserRequest, FIRST_ID, IssueLinkRequest, LAST_ID, MeRequest, Request,
    RevokeAccessRequest, RevokeLinkRequest, SignOutUserRequest, UserUpdate, UsersRequest,
};
use super::auth;
use crate::types::{
    AuthRequest, CloudflareConfig, NewUser, PasswordChange, Role, UserChange, UserId,
};

/// A body of every request type of watchword's list, each read at most once.
struct Bodies(Vec<Box<dyn Any>>);

impl Bodies {
    fn new() -> Self {
        let id = UserId(2);

        Self(vec![
            Box::new(MeRequest),
            Box::new(UsersRequest),
            Box::new(CloudflareRequest),
            Box::new(UserChange {
                login: Some(Some("new".to_owned())),
                ..UserChange::default()
            }),
            Box::new(PasswordChange {
                old_password: None,
                new_password: "password2".to_owned(),
            }),
            Box::new(NewUser {
                login: Some("someone".to_owned()),
                email: None,
                role: Role::Regular,
            }),
            Box::new(UserUpdate {
                id,
                change: UserChange::default(),
            }),
            Box::new(DeleteUserRequest { id }),
            Box::new(IssueLinkRequest { id }),
            Box::new(RevokeLinkRequest { id }),
            Box::new(SignOutUserRequest { id }),
            Box::new(RevokeAccessRequest { id }),
            Box::new(CloudflareConfig::default()),
        ])
    }
}

impl ReadBody for Bodies {
    fn read<T>(&mut self) -> Option<T>
    where
        T: for<'de> DecodeBody<'de> + 'static,
    {
        let index = self.0.iter().position(|body| body.is::<T>())?;
        self.0.swap_remove(index).downcast().ok().map(|body| *body)
    }
}

/// The HTTP route of `request`: its method, path and JSON body.
fn route(request: &AuthRequest) -> (Method, String, Option<Value>) {
    fn json<T: serde::Serialize>(value: &T) -> Option<Value> {
        Some(serde_json::to_value(value).unwrap())
    }

    match request {
        AuthRequest::Me => (Method::GET, "/api/auth/me".to_owned(), None),
        AuthRequest::UpdateAccount(change) => {
            (Method::PATCH, "/api/auth/account".to_owned(), json(change))
        }
        AuthRequest::ChangePassword(change) => (
            Method::POST,
            "/api/auth/account/password".to_owned(),
            json(change),
        ),
        AuthRequest::Users => (Method::GET, "/api/auth/users".to_owned(), None),
        AuthRequest::CreateUser(new) => (Method::POST, "/api/auth/users".to_owned(), json(new)),
        AuthRequest::UpdateUser { id, change } => {
            (Method::PATCH, format!("/api/auth/users/{id}"), json(change))
        }
        AuthRequest::DeleteUser { id } => (Method::DELETE, format!("/api/auth/users/{id}"), None),
        AuthRequest::IssueLink { id } => (Method::POST, format!("/api/auth/users/{id}/link"), None),
        AuthRequest::RevokeLink { id } => {
            (Method::DELETE, format!("/api/auth/users/{id}/link"), None)
        }
        AuthRequest::SignOutUser { id } => {
            (Method::POST, format!("/api/auth/users/{id}/sign-out"), None)
        }
        AuthRequest::RevokeAccess { id } => {
            (Method::POST, format!("/api/auth/users/{id}/revoke"), None)
        }
        AuthRequest::Cloudflare => (Method::GET, "/api/auth/cloudflare".to_owned(), None),
        AuthRequest::SetCloudflare(config) => {
            (Method::PUT, "/api/auth/cloudflare".to_owned(), json(config))
        }
        request => panic!("no HTTP route known here for {request:?}"),
    }
}

#[tokio::test]
async fn every_socket_endpoint_has_an_http_route() {
    let auth = auth();
    let app = crate::axum08::routes().with_state(auth);
    let mut endpoints = 0;

    for id in FIRST_ID..=LAST_ID {
        let id = Request::from_id(MessageId::new(id).unwrap());

        if matches!(id, Request::Unknown(..)) {
            continue;
        }

        endpoints += 1;

        let request = decode(id, &mut Bodies::new())
            .unwrap_or_else(|| panic!("{id:?} decodes into an AuthRequest"));

        assert_eq!(
            request.cookie(),
            None,
            "{id:?} changes the cookie, which a socket cannot"
        );

        let (method, uri, body) = route(&request);
        let http = HttpRequest::builder().method(method).uri(&uri);

        let http = match body {
            Some(body) => http
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string())),
            None => http.body(Body::empty()),
        }
        .unwrap();

        let response = app.clone().oneshot(http).await.unwrap();
        let status = response.status();
        let bytes = axum08::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();

        // Without the feature, neither transport has the Cloudflare settings.
        let cloudflare = matches!(
            request,
            AuthRequest::Cloudflare | AuthRequest::SetCloudflare(..)
        );

        if cloudflare && !cfg!(feature = "cloudflare") {
            assert_eq!(status, StatusCode::NOT_FOUND, "{id:?}: {uri}");
            continue;
        }

        // Signed out, the route refuses with the `AuthError` body, which
        // shows that it exists and is watchword's.
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{id:?}: {uri}");
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "unauthorized", "{id:?}: {uri}");
    }

    assert!(endpoints > 0);
}

#[test]
fn a_body_that_does_not_decode_is_no_request() {
    struct Nothing;

    impl ReadBody for Nothing {
        fn read<T>(&mut self) -> Option<T>
        where
            T: for<'de> DecodeBody<'de> + 'static,
        {
            None
        }
    }

    assert_eq!(decode(Request::Me, &mut Nothing), None);
    assert_eq!(decode(Request::UpdateUser, &mut Nothing), None);
}
