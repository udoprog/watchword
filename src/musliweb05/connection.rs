use std::sync::Arc;

use musli_web05::api::EncodeBody;
use musli_web05::ws::{self, Incoming, Outgoing};

use super::{
    AuthUpdate, CloudflareRequest, DeleteUserRequest, IssueLinkRequest, MeRequest, Request,
    RequestError, RevokeAccessRequest, RevokeLinkRequest, SignOutUserRequest, Updates, UserUpdate,
    UsersRequest,
};
use crate::Auth;
use crate::axum08::SignedIn;
#[cfg(doc)]
use crate::core::Error;
use crate::core::{AuthEvent, Result};
use crate::store::{Session, User};
use crate::types::{
    Access, AuthError, CloudflareConfig, CreatedUser, Invalid, NewUser, PasswordChange, UserChange,
    UserId,
};

/// watchword's side of one musli-web WebSocket, signed in with one session.
///
/// Create it at upgrade from the [`SignedIn`] the app's `/ws` route already
/// extracts, and take its [`updates`](Connection::updates) for the
/// connection's loop, broadcasting each until the session ends:
///
/// ```no_run
/// # async fn ws(auth: watchword::Auth, signed_in: watchword::axum08::SignedIn) {
/// use watchword::musliweb05::{AuthUpdate, Connection};
///
/// let conn = Connection::new(auth.clone(), &signed_in);
/// let mut updates = conn.updates();
///
/// loop {
///     tokio::select! {
///         update = updates.next() => {
///             // The session ended: close the socket.
///             let Some(update) = update else {
///                 break;
///             };
///
///             // server.broadcast(update)?;
///             # let _: AuthUpdate = update;
///         }
///         // ... the socket's own messages
///     }
/// }
/// # }
/// ```
///
/// An app with a loop of its own feeds [`update`](Connection::update) the
/// [`AuthEvent`]s of [`Auth::events`], and [`lagged`](Connection::lagged)
/// stands in for those it missed, which is what [`Updates`] does.
///
/// Ending the socket when its session ends stays the job of
/// [`Auth::guard`], which [`Updates`] holds: no update is sent for it.
///
/// Cloning a `Connection` is cheap, so it sits beside the app's own handler.
/// The main way to use it is from an app whose `define!` list includes
/// watchword's (`include watchword::musliweb05 as Auth;`), which passes that
/// variant's requests to [`handle`](Connection::handle). The client then gets
/// watchword's endpoints through the app's list type, so one socket handle
/// sends both, and the exhaustive `match` below does not compile until it
/// forwards `api::Request::Auth`:
///
/// ```no_run
/// # mod api {
/// #     #[derive(musli::Encode, musli::Decode)]
/// #     pub struct StatusRequest;
/// #     musli_web05::api::define! {
/// #         #![musli(crate = musli_web05)]
/// #         pub type Status;
/// #         impl Endpoint for Status {
/// #             impl Request for StatusRequest;
/// #             type Response<'de> = u32;
/// #         }
/// #         include watchword::musliweb05 as Auth;
/// #     }
/// # }
/// use musli_web05::ws;
/// use watchword::musliweb05::{Connection, RequestError};
///
/// #[derive(Clone)]
/// struct Handler {
///     conn: Connection,
/// }
///
/// impl ws::Handler for Handler {
///     type Id = api::Request;
///     type Response = Result<bool, RequestError>;
///
///     async fn handle(
///         &self,
///         id: api::Request,
///         incoming: &mut ws::Incoming<'_>,
///         outgoing: &mut ws::Outgoing<'_>,
///     ) -> Self::Response {
///         match id {
///             // ... the app's own requests
///             # api::Request::Status => Ok(false),
///             api::Request::Auth(request) => self.conn.handle(request, incoming, outgoing).await,
///             api::Request::Unknown(..) => Ok(false),
///         }
///     }
/// }
/// ```
///
/// The alternative, for an app whose API crate should not depend on
/// watchword's types, keeps the lists apart: `Connection` is also the
/// [`ws::Handler`] of watchword's list, which the app combines with its own
/// through [`ws::Handler::or`], routing each request by the list that knows
/// its id. `Or` refuses lists that share an id, but being generic that check
/// only runs once a binary is built, so `cargo check` misses it; a `const`
/// assertion on the lists' [`IdSet`](musli_web05::api::IdSet)s catches it
/// earlier. watchword's band, 32000–32255, is a convention, so this matters
/// for an app that pins ids of its own:
///
/// ```no_run
/// # mod api {
/// #     #[derive(musli::Encode, musli::Decode)]
/// #     pub struct StatusRequest;
/// #     musli_web05::api::define! {
/// #         #![musli(crate = musli_web05)]
/// #         pub type Status;
/// #         impl Endpoint for Status {
/// #             impl Request for StatusRequest;
/// #             type Response<'de> = u32;
/// #         }
/// #     }
/// # }
/// # #[derive(Clone)]
/// # struct AppHandler;
/// # impl musli_web05::ws::Handler for AppHandler {
/// #     type Id = api::Request;
/// #     type Response = bool;
/// #     async fn handle(&self, _: Self::Id, _: &mut musli_web05::ws::Incoming<'_>, _: &mut musli_web05::ws::Outgoing<'_>) -> bool { false }
/// # }
/// use musli_web05::api::Id;
/// use watchword::musliweb05 as auth;
///
/// const _: () = {
///     assert!(api::Request::IDS.is_disjoint(&auth::Request::IDS));
///     assert!(api::Event::IDS.is_disjoint(&auth::Event::IDS));
/// };
///
/// # async fn run(socket: axum08::extract::ws::WebSocket, conn: watchword::musliweb05::Connection) -> Result<(), musli_web05::ws::Error> {
/// use musli_web05::ws::Handler;
///
/// let mut server = musli_web05::axum08::server(socket, AppHandler.or(conn))
///     .connect()
///     .await?;
///
/// server.run().await
/// # }
/// ```
///
/// The app's own requests check their user the way watchword's do, with
/// [`signed_in`](Connection::signed_in) and
/// [`require_admin`](Connection::require_admin), which re-read the session
/// for each request and refuse with the same [`AuthError`] as the HTTP
/// extractors. A refusal is [`Error::Auth`]; any other error is the store
/// failing. The app's own requests fail with a [`RequestError`] as well,
/// converted with `?`, so a refusal reaches the client as the same typed
/// [`AuthError`]; the app logs their internal failures, which `handle` never
/// sees:
///
/// ```no_run
/// use musli_web05::ws;
/// use watchword::core::Error;
/// use watchword::musliweb05::{Connection, RequestError};
///
/// async fn stats(conn: &Connection, outgoing: &mut ws::Outgoing<'_>) -> Result<bool, RequestError> {
///     let admin = match conn.require_admin().await {
///         Ok(admin) => admin,
///         // A refusal, sent to the client as its typed `AuthError`.
///         Err(error @ Error::Auth(..)) => return Err(error.into()),
///         Err(error) => {
///             tracing::error!("stats failed: {error}");
///             return Err(error.into());
///         }
///     };
///
///     // ... answer with what only `admin` may see.
///     # let _ = (admin, outgoing);
///     Ok(true)
/// }
/// ```
///
/// A socket loop that only needs the role as last seen, without a store
/// read, has it from its [`SessionGuard`](crate::core::SessionGuard), which
/// follows the user's changes: [`user`](crate::core::SessionGuard::user) and
/// [`watch_user`](crate::core::SessionGuard::watch_user).
#[derive(Clone)]
pub struct Connection {
    auth: Auth,
    signed_in: Arc<SignedIn>,
}

impl Connection {
    /// The connection signed in as `signed_in`, as the app's `/ws` route
    /// extracted it at upgrade.
    pub fn new(auth: Auth, signed_in: &SignedIn) -> Self {
        Self {
            auth,
            signed_in: Arc::new(signed_in.clone()),
        }
    }

    /// The live [`AuthUpdate`]s for this connection, to broadcast on its
    /// socket until its session ends, which replace the app's own
    /// [`Auth::guard`] and [`Auth::events`] in the socket loop.
    ///
    /// The guard follows the session the upgrade signed in with, and the
    /// events are subscribed to now, so call it before negotiating the
    /// socket: nothing sent meanwhile is missed. See [`Updates`].
    pub fn updates(&self) -> Updates {
        Updates::new(self.clone())
    }

    /// The [`Auth`] this connection answers with.
    pub(super) fn auth(&self) -> &Auth {
        &self.auth
    }

    /// The session and user the upgrade signed in with.
    pub(super) fn upgrade(&self) -> &SignedIn {
        &self.signed_in
    }

    /// The [`AuthUpdate`] this connection may see of `event`, if any:
    ///
    /// - [`AuthUpdate::Me`] when the connection's own user changed, as
    ///   [`Auth::session_info`] gives it, so an impersonated session keeps
    ///   its [`impersonated_by`](crate::UserInfo::impersonated_by) marker.
    /// - [`AuthUpdate::UserCreated`], [`UserChanged`](AuthUpdate::UserChanged)
    ///   and [`UserDeleted`](AuthUpdate::UserDeleted) for other users, only
    ///   while the connection's user is an active admin. The session and its
    ///   user are re-read from the store for each such event, so an admin
    ///   demoted or revoked on an open socket stops receiving them at once.
    /// - Nothing for an event that ends sessions, or for any event once the
    ///   connection's session has ended: [`Auth::guard`] ends the socket.
    ///
    /// Errors only when the store fails.
    pub async fn update(&self, event: &AuthEvent) -> Result<Option<AuthUpdate>> {
        let update = match event {
            AuthEvent::SessionEnded(_) | AuthEvent::UserSessionsEnded { .. } => return Ok(None),
            AuthEvent::UserChanged(info) if info.id == self.user_id() => {
                let Some((user, session)) = self.auth.session(self.session_id()).await? else {
                    return Ok(None);
                };

                let info = self.auth.session_info(&user, &session).await?;
                return Ok(Some(AuthUpdate::Me(info)));
            }
            AuthEvent::UserChanged(info) => AuthUpdate::UserChanged(info.clone()),
            AuthEvent::UserCreated(info) => AuthUpdate::UserCreated(info.clone()),
            AuthEvent::UserDeleted(id) => AuthUpdate::UserDeleted(*id),
        };

        let Some((user, _)) = self.auth.session(self.session_id()).await? else {
            return Ok(None);
        };

        if user.access != Access::Active || !user.is_admin() {
            return Ok(None);
        }

        Ok(Some(update))
    }

    /// The [`AuthUpdate`] to send in place of the events this connection
    /// missed, when the app's receiver of [`Auth::events`] lagged:
    ///
    /// - [`AuthUpdate::Resync`] while the connection's user is an active
    ///   admin, which tells the page to fetch the user list again.
    /// - [`AuthUpdate::Me`] for any other user, who sees nothing else.
    /// - Nothing once the connection's session has ended: [`Auth::guard`]
    ///   ends the socket.
    ///
    /// Both carry the connection's own user as it is now, as
    /// [`Auth::session_info`] gives it, since a missed event may have
    /// changed it. Errors only when the store fails.
    pub async fn lagged(&self) -> Result<Option<AuthUpdate>> {
        let Some((user, session)) = self.auth.session(self.session_id()).await? else {
            return Ok(None);
        };

        let info = self.auth.session_info(&user, &session).await?;

        if user.access == Access::Active && user.is_admin() {
            Ok(Some(AuthUpdate::Resync(info)))
        } else {
            Ok(Some(AuthUpdate::Me(info)))
        }
    }

    /// Answers one of watchword's requests. Call it from the app's
    /// `ws::Handler::handle`, in the arm of the list it included watchword's
    /// as, or let [`ws::Handler::or`] call it.
    ///
    /// For each request the session and its user are read again through
    /// [`Auth::session`], as the HTTP routes' extractors do, so a session
    /// that has ended since the socket opened is refused with
    /// [`AuthError::Unauthorized`], and a role change or revocation applies
    /// to the next request. The request then runs the same [`Auth`]
    /// operation as its HTTP route, with that user as the actor: the admin
    /// endpoints refuse with [`AuthError::Forbidden`] unless the user is an
    /// admin now, and the operations enforce the rest of their rules
    /// themselves. Without the `cloudflare` feature, the Cloudflare settings
    /// endpoints refuse an admin with [`AuthError::NotFound`].
    ///
    /// The response is the endpoint's value. A refused request fails with a
    /// [`RequestError`] that musli-web sends as the typed [`AuthError`], the
    /// same as over HTTP. A body that does not decode answers `Ok(false)`,
    /// and musli-web reports the decode error to the client, as it does for
    /// an [`Unknown`](super::Request::Unknown) id.
    ///
    /// Errors when refused, and when the store fails or hashing a password
    /// does. An internal failure is logged here, at error level with its
    /// cause, so the app does not log it again; musli-web answers the request
    /// with the [`RequestError`]'s generic message, `internal error`, the
    /// analogue of an HTTP 500.
    pub async fn handle(
        &self,
        request: Request,
        incoming: &mut Incoming<'_>,
        outgoing: &mut Outgoing<'_>,
    ) -> Result<bool, RequestError> {
        let result = self.dispatch(request, incoming, outgoing).await;

        if let Err(error) = &result
            && error.auth_error().is_none()
        {
            tracing::error!(error = ?error, "auth: socket request {request:?} failed: {error}");
        }

        Ok(result?)
    }

    async fn dispatch(
        &self,
        request: Request,
        incoming: &mut Incoming<'_>,
        outgoing: &mut Outgoing<'_>,
    ) -> Result<bool> {
        match request {
            Request::Me => {
                let Some(MeRequest) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let (user, session) = self.signed_in().await?;
                    self.auth.session_info(&user, &session).await
                };

                respond(outgoing, response.await)
            }
            Request::UpdateAccount => {
                let Some(change) = incoming.read::<UserChange>() else {
                    return Ok(false);
                };

                let response = async {
                    let (user, session) = self.signed_in().await?;

                    if change.role.is_some() {
                        return Err(AuthError::Invalid(Invalid::RoleNotChangeable).into());
                    }

                    let user = self
                        .auth
                        .update_user(&user, &session, user.id, &change)
                        .await?;
                    self.auth.session_info(&user, &session).await
                };

                respond(outgoing, response.await)
            }
            Request::ChangePassword => {
                let Some(change) = incoming.read::<PasswordChange>() else {
                    return Ok(false);
                };

                let response = async {
                    let (user, session) = self.signed_in().await?;
                    let user = self.auth.change_password(&user, &session, &change).await?;
                    self.auth.session_info(&user, &session).await
                };

                respond(outgoing, response.await)
            }
            Request::Users => {
                let Some(UsersRequest) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let admin = self.require_admin().await?;
                    self.auth.users(&admin).await
                };

                respond(outgoing, response.await)
            }
            Request::CreateUser => {
                let Some(new) = incoming.read::<NewUser>() else {
                    return Ok(false);
                };

                let response = async {
                    let (admin, session) = self.admin_session().await?;
                    let (entry, link) = self.auth.create_user(&admin, &session, &new).await?;
                    Ok(CreatedUser { entry, link })
                };

                respond(outgoing, response.await)
            }
            Request::UpdateUser => {
                let Some(UserUpdate { id, change }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let (admin, session) = self.admin_session().await?;
                    let user = self.auth.update_user(&admin, &session, id, &change).await?;
                    Ok(user.info())
                };

                respond(outgoing, response.await)
            }
            Request::DeleteUser => {
                let Some(DeleteUserRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let (admin, session) = self.admin_session().await?;
                    self.auth.delete_user(&admin, &session, id).await
                };

                respond(outgoing, response.await)
            }
            Request::IssueLink => {
                let Some(IssueLinkRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let (admin, session) = self.admin_session().await?;
                    self.auth.issue_link(&admin, &session, id).await
                };

                respond(outgoing, response.await)
            }
            Request::RevokeLink => {
                let Some(RevokeLinkRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let (admin, session) = self.admin_session().await?;
                    self.auth.revoke_link(&admin, &session, id).await
                };

                respond(outgoing, response.await)
            }
            Request::SignOutUser => {
                let Some(SignOutUserRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let (admin, session) = self.admin_session().await?;
                    self.auth.sign_out_everywhere(&admin, &session, id).await
                };

                respond(outgoing, response.await)
            }
            Request::RevokeAccess => {
                let Some(RevokeAccessRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let (admin, session) = self.admin_session().await?;
                    let user = self.auth.revoke_access(&admin, &session, id).await?;
                    Ok(user.info())
                };

                respond(outgoing, response.await)
            }
            Request::Cloudflare => {
                let Some(CloudflareRequest) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    self.require_admin().await?;
                    self.cloudflare().await
                };

                respond(outgoing, response.await)
            }
            Request::SetCloudflare => {
                let Some(config) = incoming.read::<CloudflareConfig>() else {
                    return Ok(false);
                };

                let response = async {
                    let (admin, session) = self.admin_session().await?;
                    self.set_cloudflare(&admin, &session, config).await
                };

                respond(outgoing, response.await)
            }
            Request::Unknown(_) => Ok(false),
        }
    }

    /// The Cloudflare Access settings, or their default when there are
    /// none, as `GET /api/auth/cloudflare` answers.
    #[cfg(feature = "cloudflare")]
    async fn cloudflare(&self) -> Result<CloudflareConfig> {
        Ok(self.auth.cloudflare().await?.unwrap_or_default())
    }

    /// Without the `cloudflare` feature there are no settings, as there is
    /// no route for them.
    #[cfg(not(feature = "cloudflare"))]
    async fn cloudflare(&self) -> Result<CloudflareConfig> {
        Err(AuthError::NotFound.into())
    }

    /// Stores and applies the settings, as `PUT /api/auth/cloudflare` does.
    #[cfg(feature = "cloudflare")]
    async fn set_cloudflare(
        &self,
        admin: &User,
        session: &Session,
        config: CloudflareConfig,
    ) -> Result<CloudflareConfig> {
        self.auth.set_cloudflare(admin, session, config).await
    }

    #[cfg(not(feature = "cloudflare"))]
    async fn set_cloudflare(
        &self,
        _: &User,
        _: &Session,
        _: CloudflareConfig,
    ) -> Result<CloudflareConfig> {
        Err(AuthError::NotFound.into())
    }

    /// The id of the user this connection signed in as, as its upgrade
    /// carried it. For an impersonated session it is the impersonated user.
    pub fn user_id(&self) -> UserId {
        self.signed_in.user.id
    }

    /// The id of the session this connection signed in with.
    pub fn session_id(&self) -> &str {
        &self.signed_in.session.id
    }

    /// The connection's session and its user as stored now, or
    /// [`AuthError::Unauthorized`] once the session has ended, as the
    /// [`SignedIn`] extractor answers over HTTP.
    ///
    /// For an app's own socket requests that need a signed-in user: like
    /// [`handle`](Connection::handle), it reads the session through
    /// [`Auth::session`] each time, so a request on a socket whose session
    /// ended a moment ago is refused even before [`Auth::guard`] closes it.
    /// Errors with [`Error::Auth`] for the refusal and another [`Error`] when
    /// the store fails, which the app should not report as a refusal.
    pub async fn signed_in(&self) -> Result<(User, Session)> {
        match self.auth.session(self.session_id()).await? {
            Some(signed_in) => Ok(signed_in),
            None => Err(AuthError::Unauthorized.into()),
        }
    }

    /// The connection's user as stored now, refused with
    /// [`AuthError::Forbidden`] unless they are an active admin now, and with
    /// [`AuthError::Unauthorized`] once the session has ended, as the
    /// [`Admin`](crate::axum08::Admin) extractor answers over HTTP.
    ///
    /// For an app's own admin-only socket requests, so the check matches
    /// watchword's admin endpoints: a demoted or revoked admin is refused on
    /// the next request. Like [`signed_in`](Connection::signed_in), a store
    /// failure is an error of its own, not a refusal.
    pub async fn require_admin(&self) -> Result<User> {
        let (user, _) = self.admin_session().await?;
        Ok(user)
    }

    /// As [`require_admin`](Connection::require_admin), with the session.
    async fn admin_session(&self) -> Result<(User, Session)> {
        let (user, session) = self.signed_in().await?;

        if user.access != Access::Active || !user.is_admin() {
            return Err(AuthError::Forbidden.into());
        }

        Ok((user, session))
    }
}

/// Writes an operation's value as the endpoint's response, passing a
/// refusal or an internal failure on as the request's error.
fn respond<T>(outgoing: &mut Outgoing<'_>, result: Result<T>) -> Result<bool>
where
    T: EncodeBody,
{
    outgoing.write(result?);
    Ok(true)
}

/// watchword's endpoints, for an app that combines its own handler with this
/// one through [`ws::Handler::or`]. See [`Connection::handle`].
impl ws::Handler for Connection {
    type Id = Request;
    type Response = Result<bool, RequestError>;

    fn handle<'this>(
        &'this self,
        id: Request,
        incoming: &'this mut Incoming<'_>,
        outgoing: &'this mut Outgoing<'_>,
    ) -> impl Future<Output = Self::Response> + Send + 'this {
        Connection::handle(self, id, incoming, outgoing)
    }
}
