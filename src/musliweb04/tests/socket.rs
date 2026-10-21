//! `Connection::handle` over a real WebSocket: an axum server whose handler
//! delegates the ids its own API does not know, as an app's does, and a
//! tungstenite client.

use std::borrow::ToOwned;
use std::future::Future;
use std::net::SocketAddr;
use std::string::String;
use std::time::Duration;
use std::vec::Vec;

use axum08::Router;
use axum08::extract::ws::{WebSocket, WebSocketUpgrade};
use axum08::extract::{Path, State};
use axum08::response::Response;
use axum08::routing::any;
use musli_web::api::Endpoint;
use musli_web::client::{self, Handle};
use musli_web::{tungstenite030, ws};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::super::{
    DeleteUserRequest, IssueLinkRequest, MeRequest, RevokeAccessRequest, RevokeLinkRequest,
    SignOutUserRequest, UserUpdate, UsersRequest,
};
use super::{PASSWORD, auth, pending, root, user};
use crate::axum08::SignedIn;
use crate::musliweb04::Connection;
use crate::types::{
    AuthError, Conflict, Invalid, NewUser, PasswordChange, Role, UserChange, UserEntry, UserId,
    UserInfo,
};
use crate::{Auth, AuthEvent};

const TIMEOUT: Duration = Duration::from_secs(20);

async fn timeout<F>(future: F) -> F::Output
where
    F: Future,
{
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("timed out")
}

/// The app's own API, with implicit ids.
mod app {
    use musli::{Decode, Encode};

    #[derive(Debug, Encode, Decode)]
    pub struct PingRequest;

    musli_web::api::define! {
        pub type Ping;

        impl Endpoint for Ping {
            impl Request for PingRequest;
            type Response<'de> = u32;
        }
    }
}

/// Endpoints the server knows nothing of, to send ids it does not answer.
mod stray {
    use musli::{Decode, Encode};

    #[derive(Debug, Encode, Decode)]
    pub struct OutsideRequest;

    #[derive(Debug, Encode, Decode)]
    pub struct InBandRequest;

    #[derive(Debug, Encode, Decode)]
    pub struct MalformedRequest;

    musli_web::api::define! {
        /// Neither the app's nor watchword's.
        #[musli(id = 500)]
        pub type Outside;

        impl Endpoint for Outside {
            impl Request for OutsideRequest;
            type Response<'de> = u32;
        }

        /// In watchword's band, but no endpoint of it.
        #[musli(id = 32254)]
        pub type InBand;

        impl Endpoint for InBand {
            impl Request for InBandRequest;
            type Response<'de> = u32;
        }

        /// `UpdateUser`'s id, with a body that is not a `UserUpdate`.
        #[musli(id = 32005)]
        pub type Malformed;

        impl Endpoint for Malformed {
            impl Request for MalformedRequest;
            type Response<'de> = u32;
        }
    }
}

#[derive(Clone)]
struct Handler {
    conn: Connection,
}

impl ws::Handler for Handler {
    type Id = app::Request;
    type Response = crate::core::Result<bool>;

    async fn handle(
        &self,
        id: app::Request,
        incoming: &mut ws::Incoming<'_>,
        outgoing: &mut ws::Outgoing<'_>,
    ) -> Self::Response {
        match id {
            app::Request::Ping => {
                let Some(app::PingRequest) = incoming.read() else {
                    return Ok(false);
                };

                outgoing.write(7u32);
                Ok(true)
            }
            app::Request::Unknown(id) => self.conn.handle(id, incoming, outgoing).await,
        }
    }
}

/// `/ws/{session}` signs the socket in with the session named in the path,
/// standing in for the app's cookie. The socket stays open when the session
/// ends (no guard), so requests made after that reach the handler.
async fn upgrade(
    ws: WebSocketUpgrade,
    State(auth): State<Auth>,
    Path(session): Path<String>,
) -> Response {
    let (user, session) = auth.session(&session).await.unwrap().expect("signed in");
    let conn = Connection::new(auth, &SignedIn { user, session });
    ws.on_upgrade(move |socket| connection(socket, conn))
}

async fn connection(socket: WebSocket, conn: Connection) {
    let server = musli_web::axum08::server(socket, Handler { conn });

    let Ok(mut server) = server.connect().await else {
        return;
    };

    _ = server.run().await;
}

struct Server {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Server {
    async fn new(auth: &Auth) -> Self {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/ws/{session}", any(upgrade))
            .with_state(auth.clone());

        let task = tokio::spawn(async move {
            axum08::serve(listener, app).await.unwrap();
        });

        Self { addr, task }
    }

    /// A client signed in as `signed_in`, connected.
    async fn client(&self, signed_in: &SignedIn) -> Client {
        let url = format!("ws://{}/ws/{}", self.addr, signed_in.session.id);
        let mut service = tungstenite030::connect(url).reconnect(false).build();
        let handle = service.handle().clone();

        let task = tokio::spawn(async move {
            _ = service.run().await;
        });

        timeout(handle.wait_until_open()).await.unwrap();
        Client { handle, task }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Client {
    handle: Handle,
    task: JoinHandle<()>,
}

impl Client {
    /// Sends `body` and decodes the endpoint's `Result<T, AuthError>`.
    async fn send<B, T>(&self, body: B) -> Result<T, AuthError>
    where
        B: musli_web::api::Request,
        B::Endpoint: for<'de> Endpoint<Response<'de> = Result<T, AuthError>>,
        T: for<'de> musli_web::api::DecodeBody<'de>,
    {
        let packet = timeout(self.handle.request().body(body).send())
            .await
            .unwrap();
        packet.decode_any::<Result<T, AuthError>>().unwrap()
    }

    /// Sends `body` and returns the `AuthError` it was refused with, if any.
    async fn refused<B, T>(&self, body: B) -> Option<AuthError>
    where
        B: musli_web::api::Request,
        B::Endpoint: for<'de> Endpoint<Response<'de> = Result<T, AuthError>>,
        T: for<'de> musli_web::api::DecodeBody<'de>,
    {
        self.send(body).await.err()
    }

    /// Sends `body`, expecting a request error, and returns its message.
    async fn fail<B>(&self, body: B) -> String
    where
        B: musli_web::api::Request,
    {
        let error: client::Error = timeout(self.handle.request().body(body).send())
            .await
            .expect_err("a request error");
        error.as_server_error().expect("a server error").to_owned()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[test]
fn handles_watchwords_endpoints() {
    for id in 32000..=32010 {
        let id = musli_web::api::MessageId::new(id).unwrap();
        assert!(Connection::handles(id), "{id}");
    }

    for id in [1, 500, 31999, 32011, 32254, 32255, 32256] {
        let id = musli_web::api::MessageId::new(id).unwrap();
        assert!(!Connection::handles(id), "{id}");
    }

    assert!(!Connection::handles(
        <super::super::AuthBroadcast as musli_web::api::Broadcast>::ID
    ));
}

/// The app answers its own ids; watchword answers the band; any other id is
/// unknown to both.
#[tokio::test]
async fn delegates_by_id() {
    let auth = auth();
    let root = root(&auth).await;
    let server = Server::new(&auth).await;
    let client = server.client(&root).await;

    let packet = timeout(client.handle.request().body(app::PingRequest).send())
        .await
        .unwrap();
    assert_eq!(packet.decode().unwrap(), 7);

    let me: UserInfo = client.send(MeRequest).await.unwrap();
    assert_eq!(me, root.user.info());

    let error = client.fail(stray::OutsideRequest).await;
    assert!(error.contains("500"), "{error}");
    let error = client.fail(stray::InBandRequest).await;
    assert!(error.contains("32254"), "{error}");

    // A body that does not decode is musli-web's request error.
    let error = client.fail(stray::MalformedRequest).await;
    assert!(!error.is_empty());

    // The socket is still usable.
    let me: UserInfo = client.send(MeRequest).await.unwrap();
    assert_eq!(me, root.user.info());
}

/// Each endpoint runs its operation for the connection's user.
#[tokio::test]
async fn an_admin_runs_every_endpoint() {
    let auth = auth();
    let root = root(&auth).await;
    let server = Server::new(&auth).await;
    let client = server.client(&root).await;
    let mut events = auth.events();

    // Own account.
    let change = UserChange {
        login: Some(Some("boss".to_owned())),
        email: None,
        role: None,
    };
    let me: UserInfo = client.send(change).await.unwrap();
    assert_eq!(me.login.as_deref(), Some("boss"));
    assert!(matches!(events.try_recv(), Ok(AuthEvent::UserChanged(_))));

    let change = PasswordChange {
        old_password: Some(PASSWORD.to_owned()),
        new_password: "password2".to_owned(),
    };
    let me: UserInfo = client.send(change).await.unwrap();
    assert_eq!(me.login.as_deref(), Some("boss"));

    // User management.
    let new = NewUser {
        login: Some("erin".to_owned()),
        email: None,
        role: Role::Regular,
    };
    let created = client.send(new).await.unwrap();
    let erin = created.entry.user.id;

    let users: Vec<UserEntry> = client.send(UsersRequest).await.unwrap();
    assert_eq!(users.len(), 2);

    let update = UserUpdate {
        id: erin,
        change: UserChange {
            login: None,
            email: None,
            role: Some(Role::Admin),
        },
    };
    let info: UserInfo = client.send(update).await.unwrap();
    assert_eq!(info.role, Role::Admin);

    let link = client.send(IssueLinkRequest { id: erin }).await.unwrap();
    assert_ne!(link.token, created.link.token);
    let () = client.send(RevokeLinkRequest { id: erin }).await.unwrap();
    assert_eq!(
        auth.register_info(&link.token)
            .await
            .unwrap_err()
            .auth_error(),
        Some(&AuthError::Gone)
    );

    let () = client.send(SignOutUserRequest { id: erin }).await.unwrap();
    let info: UserInfo = client.send(RevokeAccessRequest { id: erin }).await.unwrap();
    assert_eq!(info.id, erin);

    let () = client.send(DeleteUserRequest { id: erin }).await.unwrap();
    let users: Vec<UserEntry> = client.send(UsersRequest).await.unwrap();
    assert_eq!(users.len(), 1);
}

/// A regular user may use their own account, not the admin endpoints, as
/// over HTTP; that includes changing themselves through `UpdateUser`.
#[tokio::test]
async fn a_regular_user_is_refused_the_admin_endpoints() {
    let auth = auth();
    let root = root(&auth).await;
    let erin = user(&auth, &root, "erin", Role::Regular).await;
    let server = Server::new(&auth).await;
    let client = server.client(&erin).await;

    let me: UserInfo = client.send(MeRequest).await.unwrap();
    assert_eq!(me, erin.user.info());

    let target = root.user.id;
    let forbidden = Some(AuthError::Forbidden);
    assert_eq!(client.refused(UsersRequest).await, forbidden);
    let new = NewUser {
        login: Some("finn".to_owned()),
        email: None,
        role: Role::Regular,
    };
    assert_eq!(client.refused(new).await, forbidden);
    let own = UserUpdate {
        id: erin.user.id,
        change: UserChange {
            login: Some(Some("erin2".to_owned())),
            email: None,
            role: None,
        },
    };
    assert_eq!(client.refused(own).await, forbidden);
    assert_eq!(
        client.refused(DeleteUserRequest { id: target }).await,
        forbidden
    );
    assert_eq!(
        client.refused(IssueLinkRequest { id: target }).await,
        forbidden
    );
    assert_eq!(
        client.refused(RevokeLinkRequest { id: target }).await,
        forbidden
    );
    assert_eq!(
        client.refused(SignOutUserRequest { id: target }).await,
        forbidden
    );
    assert_eq!(
        client.refused(RevokeAccessRequest { id: target }).await,
        forbidden
    );

    // Nothing changed.
    let users = auth.users(&root.user).await.unwrap();
    assert_eq!(users.len(), 2);
}

/// The session is read again for every request: an admin demoted on an open
/// socket is refused the next admin request, and promoted again, allowed.
#[tokio::test]
async fn a_demoted_admin_is_refused_on_an_open_socket() {
    let auth = auth();
    let root = root(&auth).await;
    let ada = user(&auth, &root, "ada", Role::Admin).await;
    let server = Server::new(&auth).await;
    let client = server.client(&ada).await;

    let users: Vec<UserEntry> = client.send(UsersRequest).await.unwrap();
    assert_eq!(users.len(), 2);

    auth.set_role(&root.user, ada.user.id, Role::Regular)
        .await
        .unwrap();
    assert_eq!(
        client.send::<_, Vec<UserEntry>>(UsersRequest).await,
        Err(AuthError::Forbidden)
    );
    let me: UserInfo = client.send(MeRequest).await.unwrap();
    assert_eq!(me.role, Role::Regular);

    auth.set_role(&root.user, ada.user.id, Role::Admin)
        .await
        .unwrap();
    let users: Vec<UserEntry> = client.send(UsersRequest).await.unwrap();
    assert_eq!(users.len(), 2);
}

/// Once the session has ended, every endpoint answers `Unauthorized`, even
/// before the app's guard closes the socket.
#[tokio::test]
async fn an_ended_session_is_unauthorized() {
    let auth = auth();
    let root = root(&auth).await;
    let ada = user(&auth, &root, "ada", Role::Admin).await;
    let erin = user(&auth, &root, "erin", Role::Regular).await;
    let server = Server::new(&auth).await;

    let ada_client = server.client(&ada).await;
    let erin_client = server.client(&erin).await;

    auth.revoke_access(&root.user, ada.user.id).await.unwrap();
    auth.sign_out(&erin.session.id).await.unwrap();

    for client in [&ada_client, &erin_client] {
        let unauthorized = Some(AuthError::Unauthorized);
        assert_eq!(client.refused(MeRequest).await, unauthorized);
        let change = UserChange {
            login: Some(Some("other".to_owned())),
            email: None,
            role: None,
        };
        assert_eq!(client.refused(change).await, unauthorized);
        assert_eq!(client.refused(UsersRequest).await, unauthorized);
        let id = root.user.id;
        assert_eq!(client.refused(DeleteUserRequest { id }).await, unauthorized);
    }

    let users = auth.users(&root.user).await.unwrap();
    assert_eq!(users.len(), 3);
}

/// Refusals arrive as the same `AuthError`s as over HTTP.
#[tokio::test]
async fn refusals_map_to_auth_errors() {
    let auth = auth();
    let root = root(&auth).await;
    let (erin, _) = pending(&auth, &root, "erin", Role::Regular).await;
    let server = Server::new(&auth).await;
    let client = server.client(&root).await;

    // Changing the own role through the account endpoint.
    let change = UserChange {
        login: None,
        email: None,
        role: Some(Role::Regular),
    };
    assert_eq!(
        client.send(change).await.map(|_| ()),
        Err(AuthError::Invalid(Invalid::RoleNotChangeable))
    );

    // Never on oneself.
    assert_eq!(
        client.send(DeleteUserRequest { id: root.user.id }).await,
        Err(AuthError::Forbidden)
    );

    // An unknown user.
    assert_eq!(
        client.send(DeleteUserRequest { id: UserId(9999) }).await,
        Err(AuthError::NotFound)
    );

    // A login that is taken.
    let new = NewUser {
        login: Some("erin".to_owned()),
        email: None,
        role: Role::Regular,
    };
    assert_eq!(
        client.send(new).await.map(|_| ()),
        Err(AuthError::Conflict(Conflict::Login))
    );

    // A wrong current password.
    let change = PasswordChange {
        old_password: Some("wrong".to_owned()),
        new_password: "password2".to_owned(),
    };
    assert_eq!(
        client.send::<_, UserInfo>(change).await,
        Err(AuthError::Invalid(Invalid::PasswordIncorrect))
    );

    let users = auth.users(&root.user).await.unwrap();
    assert!(users.iter().any(|entry| entry.user.id == erin.id));
}
