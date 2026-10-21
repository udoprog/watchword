//! `Connection::handle` over a real WebSocket: an axum server whose app
//! API includes watchword's list and whose handler passes that list's
//! requests on, as an app's does, and a tungstenite client that signs in with
//! the session cookie on the upgrade, as a browser does.

use std::borrow::ToOwned;
use std::future::Future;
use std::net::SocketAddr;
use std::string::ToString;
use std::time::Duration;
use std::vec::Vec;

use axum08::Router;
use axum08::extract::State;
use axum08::extract::ws::WebSocketUpgrade;
use axum08::response::Response;
use axum08::routing::any;
use musli_web05::api::{self, Endpoint, Id};
use musli_web05::client::{self, Handle};
use musli_web05::ws::Handler as _;
use musli_web05::{tungstenite030, ws};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::super::{
    CloudflareRequest, DeleteUserRequest, IssueLinkRequest, MeRequest, RevokeAccessRequest,
    RevokeLinkRequest, SignOutUserRequest, UserUpdate, UsersRequest,
};
use super::{PASSWORD, auth, pending, root, user};
use crate::axum08::SignedIn;
use crate::musliweb05::{Connection, RequestError};
use crate::store::StoreError;
use crate::types::{
    AuthError, CloudflareConfig, Conflict, Invalid, NewUser, PasswordChange, Role, UserChange,
    UserEntry, UserId, UserInfo,
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

/// The app's own API, with implicit ids, including watchword's.
mod app {
    use musli::{Decode, Encode};

    #[derive(Debug, Encode, Decode)]
    pub struct PingRequest;

    #[derive(Debug, Encode, Decode)]
    pub struct BrokenRequest;

    #[derive(Debug, Encode, Decode)]
    pub struct RefusedRequest;

    musli_web05::api::define! {
        #![musli(crate = musli_web05)]

        pub type Ping;

        impl Endpoint for Ping {
            impl Request for PingRequest;
            type Response<'de> = u32;
        }

        /// Fails as the store failing would.
        pub type Broken;

        impl Endpoint for Broken {
            impl Request for BrokenRequest;
            type Response<'de> = u32;
        }

        /// Refused as an admin-only request is for a regular user.
        pub type Refused;

        impl Endpoint for Refused {
            impl Request for RefusedRequest;
            type Response<'de> = u32;
        }

        /// watchword's endpoints and broadcast.
        include crate::musliweb05 as Auth;
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

    musli_web05::api::define! {
        #![musli(crate = musli_web05)]

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
    type Response = Result<bool, RequestError>;

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
            app::Request::Broken => {
                let Some(app::BrokenRequest) = incoming.read() else {
                    return Ok(false);
                };

                Err(StoreError::new("the disk is full").into())
            }
            app::Request::Refused => {
                let Some(app::RefusedRequest) = incoming.read() else {
                    return Ok(false);
                };

                Err(AuthError::Forbidden.into())
            }
            app::Request::Auth(request) => self.conn.handle(request, incoming, outgoing).await,
            app::Request::Unknown(..) => Ok(false),
        }
    }
}

/// The app's own API, without watchword's, for a handler combined with
/// [`Connection`] through `ws::Handler::or`.
mod alone {
    use musli::{Decode, Encode};

    #[derive(Debug, Encode, Decode)]
    pub struct PingRequest;

    musli_web05::api::define! {
        #![musli(crate = musli_web05)]

        pub type Ping;

        impl Endpoint for Ping {
            impl Request for PingRequest;
            type Response<'de> = u32;
        }
    }
}

#[derive(Clone)]
struct AloneHandler;

impl ws::Handler for AloneHandler {
    type Id = alone::Request;
    type Response = Result<bool, RequestError>;

    async fn handle(
        &self,
        id: alone::Request,
        incoming: &mut ws::Incoming<'_>,
        outgoing: &mut ws::Outgoing<'_>,
    ) -> Self::Response {
        match id {
            alone::Request::Ping => {
                let Some(alone::PingRequest) = incoming.read() else {
                    return Ok(false);
                };

                outgoing.write(9u32);
                Ok(true)
            }
            alone::Request::Unknown(..) => Ok(false),
        }
    }
}

/// `/ws` signs the socket in with the session cookie of the upgrade, as an
/// app's route does, and `/ws/or` serves `AloneHandler.or(conn)`. The socket
/// stays open when the session ends (no guard), so requests made after that
/// reach the handler.
async fn upgrade(ws: WebSocketUpgrade, State(auth): State<Auth>, signed_in: SignedIn) -> Response {
    let conn = Connection::new(auth, &signed_in);

    ws.on_upgrade(move |socket| async move {
        let server = musli_web05::axum08::server(socket, Handler { conn });

        if let Ok(mut server) = server.connect().await {
            _ = server.run().await;
        }
    })
}

async fn upgrade_or(
    ws: WebSocketUpgrade,
    State(auth): State<Auth>,
    signed_in: SignedIn,
) -> Response {
    let conn = Connection::new(auth, &signed_in);

    ws.on_upgrade(move |socket| async move {
        let server = musli_web05::axum08::server(socket, AloneHandler.or(conn));

        if let Ok(mut server) = server.connect().await {
            _ = server.run().await;
        }
    })
}

struct Server {
    addr: SocketAddr,
    auth: Auth,
    task: JoinHandle<()>,
}

impl Server {
    async fn new(auth: &Auth) -> Self {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/ws", any(upgrade))
            .route("/ws/or", any(upgrade_or))
            .with_state(auth.clone());

        let task = tokio::spawn(async move {
            axum08::serve(listener, app).await.unwrap();
        });

        Self {
            addr,
            auth: auth.clone(),
            task,
        }
    }

    /// A client signed in as `signed_in`, connected.
    async fn client(&self, signed_in: &SignedIn) -> Client {
        self.client_at("/ws", signed_in).await
    }

    /// A client of `path` signed in as `signed_in` with its session cookie
    /// on the upgrade, connected.
    async fn client_at(&self, path: &str, signed_in: &SignedIn) -> Client {
        let url = format!("ws://{}{path}", self.addr);
        let cookie = self.auth.cookie_header(&signed_in.session.id);
        let mut service = tungstenite030::connect(url)
            .header("Cookie", cookie.to_str().unwrap())
            .reconnect(false)
            .build();
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
    /// Sends `body` and returns the endpoint's response, or the `AuthError`
    /// it was refused with.
    async fn send<B, T>(&self, body: B) -> Result<T, AuthError>
    where
        B: api::Request,
        B::Endpoint: for<'de> Endpoint<Response<'de> = T>,
        T: for<'de> api::DecodeBody<'de>,
    {
        match timeout(self.handle.call(body)).await {
            Ok(value) => Ok(value),
            Err(error) => Err(error
                .server_error::<AuthError>()
                .unwrap()
                .unwrap_or_else(|| panic!("not a refusal: {error}"))),
        }
    }

    /// Sends `body` and returns the `AuthError` it was refused with, if any.
    async fn refused<B, T>(&self, body: B) -> Option<AuthError>
    where
        B: api::Request,
        B::Endpoint: for<'de> Endpoint<Response<'de> = T>,
        T: for<'de> api::DecodeBody<'de>,
    {
        self.send(body).await.err()
    }

    /// Sends `body`, expecting a request error, and returns it.
    async fn fail<B>(&self, body: B) -> client::Error
    where
        B: api::Request,
    {
        timeout(self.handle.request().body(body).send())
            .await
            .expect_err("a request error")
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The app's list routes watchword's ids to the variant it included them
/// as, and the combined handler routes them to `Connection`.
#[test]
fn routes_watchwords_endpoints() {
    type Or = ws::Or<AloneHandler, Connection>;

    for id in 32000..=32012 {
        let id = api::MessageId::new(id).unwrap();
        assert!(
            matches!(app::Request::from_id(id), app::Request::Auth(..)),
            "{id}"
        );
        assert!(
            matches!(<Or as ws::Handler>::Id::from_id(id), ws::Either::Second(..)),
            "{id}"
        );
    }

    for id in [1, 500, 31999, 32013, 32254, 32255, 32256] {
        let id = api::MessageId::new(id).unwrap();
        assert!(
            !matches!(app::Request::from_id(id), app::Request::Auth(..)),
            "{id}"
        );
        assert!(
            matches!(<Or as ws::Handler>::Id::from_id(id), ws::Either::First(..)),
            "{id}"
        );
    }

    let broadcast = <super::super::AuthBroadcast as api::Broadcast>::ID;
    assert!(matches!(
        app::Event::from_id(broadcast),
        app::Event::Auth(..)
    ));
}

/// The app answers its own ids and watchword its list; any other id is
/// unknown to both.
#[tokio::test]
async fn delegates_by_id() {
    let auth = auth();
    let root = root(&auth).await;
    let server = Server::new(&auth).await;
    let client = server.client(&root).await;

    let ping: u32 = timeout(client.handle.call(app::PingRequest)).await.unwrap();
    assert_eq!(ping, 7);

    let me: UserInfo = client.send(MeRequest).await.unwrap();
    assert_eq!(me, root.user.info());

    let error = client.fail(stray::OutsideRequest).await;
    let message = error.as_server_error().expect("a server error");
    assert!(message.contains("500"), "{message}");
    let error = client.fail(stray::InBandRequest).await;
    let message = error.as_server_error().expect("a server error");
    assert!(message.contains("32254"), "{message}");

    // A body that does not decode is musli-web's request error.
    let error = client.fail(stray::MalformedRequest).await;
    assert!(!error.as_server_error().expect("a server error").is_empty());
    assert_eq!(error.server_error::<AuthError>().unwrap(), None);

    // The socket is still usable.
    let me: UserInfo = client.send(MeRequest).await.unwrap();
    assert_eq!(me, root.user.info());
}

/// `AloneHandler.or(conn)` answers both lists on one socket.
#[tokio::test]
async fn combines_with_or() {
    let auth = auth();
    let root = root(&auth).await;
    let erin = user(&auth, &root, "erin", Role::Regular).await;
    let server = Server::new(&auth).await;
    let client = server.client_at("/ws/or", &erin).await;

    let ping: u32 = timeout(client.handle.call(alone::PingRequest))
        .await
        .unwrap();
    assert_eq!(ping, 9);

    let me: UserInfo = client.send(MeRequest).await.unwrap();
    assert_eq!(me, erin.user.info());
    assert_eq!(
        client.refused(UsersRequest).await,
        Some(AuthError::Forbidden)
    );

    let error = client.fail(stray::OutsideRequest).await;
    let message = error.as_server_error().expect("a server error");
    assert!(message.contains("500"), "{message}");
}

/// The upgrade is signed in by the session cookie, as any route is: without
/// one it is refused.
#[tokio::test]
async fn the_upgrade_needs_the_session_cookie() {
    let auth = auth();
    let server = Server::new(&auth).await;
    let url = format!("ws://{}/ws", server.addr);
    let mut service = tungstenite030::connect(url).reconnect(false).build();
    assert!(timeout(service.try_connect()).await.is_err());

    let root = root(&auth).await;
    let mut service = tungstenite030::connect(format!("ws://{}/ws", server.addr))
        .header(
            "Cookie",
            auth.cookie_header(&root.session.id).to_str().unwrap(),
        )
        .reconnect(false)
        .build();
    timeout(service.try_connect()).await.unwrap();
}

/// A `RequestError` keeps the error it holds, and knows a refusal.
#[test]
fn request_errors_keep_their_error() {
    let error = RequestError::from(StoreError::new("the disk is full"));
    assert_eq!(error.auth_error(), None);
    assert_eq!(
        error.error().to_string(),
        "storage failed: the disk is full"
    );

    let error = RequestError::from(AuthError::Forbidden);
    assert_eq!(error.auth_error(), Some(&AuthError::Forbidden));
}

/// A `RequestError` answers the client with a refusal as its typed
/// `AuthError` and its text, and with only `internal error` for an internal
/// failure, whose cause stays on the server.
#[tokio::test]
async fn request_errors_hide_internal_causes() {
    let auth = auth();
    let root = root(&auth).await;
    let server = Server::new(&auth).await;
    let client = server.client(&root).await;

    let error = client.fail(app::BrokenRequest).await;
    assert_eq!(error.as_server_error(), Some("internal error"));
    assert_eq!(error.server_error::<AuthError>().unwrap(), None);

    let error = client.fail(app::RefusedRequest).await;
    let message = AuthError::Forbidden.to_string();
    assert_eq!(error.as_server_error(), Some(message.as_str()));
    assert_eq!(
        error.server_error::<AuthError>().unwrap(),
        Some(AuthError::Forbidden)
    );
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

/// An admin reads and saves the Cloudflare Access settings over the socket,
/// as over HTTP; a regular user is refused both. Without the `cloudflare`
/// feature there are no settings, as there is no route.
#[tokio::test]
async fn cloudflare_settings_are_for_admins() {
    let auth = auth();
    let root = root(&auth).await;
    let erin = user(&auth, &root, "erin", Role::Regular).await;
    let server = Server::new(&auth).await;
    let admin = server.client(&root).await;
    let regular = server.client(&erin).await;

    let settings = CloudflareConfig {
        enabled: true,
        team_domain: " example.cloudflareaccess.com ".to_owned(),
        audience: "aud".to_owned(),
        trust_email_header: false,
        verify_jwt: true,
    };

    let forbidden = Some(AuthError::Forbidden);
    assert_eq!(regular.refused(CloudflareRequest).await, forbidden);
    assert_eq!(regular.refused(settings.clone()).await, forbidden);

    #[cfg(feature = "cloudflare")]
    {
        let stored: CloudflareConfig = admin.send(CloudflareRequest).await.unwrap();
        assert_eq!(stored, CloudflareConfig::default());

        let saved: CloudflareConfig = admin.send(settings.clone()).await.unwrap();
        assert_eq!(saved.team_domain, "example.cloudflareaccess.com");
        assert_eq!(auth.cloudflare().await.unwrap(), Some(saved.clone()));

        let stored: CloudflareConfig = admin.send(CloudflareRequest).await.unwrap();
        assert_eq!(stored, saved);
    }

    #[cfg(not(feature = "cloudflare"))]
    {
        let not_found = Some(AuthError::NotFound);
        assert_eq!(admin.refused(CloudflareRequest).await, not_found);
        assert_eq!(admin.refused(settings).await, not_found);
    }
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

    auth.set_role(&root.user, &root.session, ada.user.id, Role::Regular)
        .await
        .unwrap();
    assert_eq!(
        client.send::<_, Vec<UserEntry>>(UsersRequest).await,
        Err(AuthError::Forbidden)
    );
    let me: UserInfo = client.send(MeRequest).await.unwrap();
    assert_eq!(me.role, Role::Regular);

    auth.set_role(&root.user, &root.session, ada.user.id, Role::Admin)
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

    auth.revoke_access(&root.user, &root.session, ada.user.id)
        .await
        .unwrap();
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
