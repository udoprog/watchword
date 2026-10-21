use std::sync::Arc;

use musli_web04::api::{EncodeBody, Id, MessageId};
use musli_web04::ws::{Incoming, Outgoing};

use super::{
    AuthUpdate, DeleteUserRequest, IssueLinkRequest, MeRequest, Request, RequestError,
    RevokeAccessRequest, RevokeLinkRequest, SignOutUserRequest, Updates, UserUpdate, UsersRequest,
};
use crate::Auth;
use crate::axum08::SignedIn;
use crate::core::{AuthEvent, Error, Result};
use crate::store::{Session, User};
use crate::types::{
    Access, AuthError, CreatedUser, Invalid, NewUser, PasswordChange, UserChange, UserId,
};

/// watchword's side of one musli-web WebSocket, signed in with one session.
///
/// Create it at upgrade from the [`SignedIn`] the app's `/ws` route already
/// extracts, and take its [`updates`](Connection::updates) for the
/// connection's loop, broadcasting each until the session ends:
///
/// ```no_run
/// # async fn ws(auth: watchword::Auth, signed_in: watchword::axum08::SignedIn) {
/// use watchword::musliweb04::{AuthUpdate, Connection};
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
/// [`Auth::guard`], which [`Updates`] holds: no update is sent for it. Cloning a `Connection` is cheap,
/// so it can sit inside the app's own `ws::Handler`, which hands it the
/// requests its own API does not know with [`handle`](Connection::handle):
///
/// ```no_run
/// # mod api { pub enum Request { Unknown(musli_web::api::MessageId) } }
/// # extern crate musli_web04 as musli_web;
/// use musli_web::ws;
/// use watchword::musliweb04::{Connection, RequestError};
///
/// #[derive(Clone)]
/// struct Handler {
///     conn: Connection,
/// }
///
/// impl Handler {
///     async fn handle(
///         &self,
///         id: api::Request,
///         incoming: &mut ws::Incoming<'_>,
///         outgoing: &mut ws::Outgoing<'_>,
///     ) -> Result<bool, RequestError> {
///         match id {
///             // ... the app's own requests
///             api::Request::Unknown(id) => self.conn.handle(id, incoming, outgoing).await,
///         }
///     }
/// }
/// ```
///
/// The app's own requests check their user the way watchword's do, with
/// [`signed_in`](Connection::signed_in) and
/// [`require_admin`](Connection::require_admin), which re-read the session
/// for each request and refuse with the same [`AuthError`] as the HTTP
/// extractors. A refusal is [`Error::Auth`]; any other error is the store
/// failing. The app's own requests fail with a [`RequestError`] as well,
/// converted with `?`, and the app logs their internal failures, which
/// `handle` never sees:
///
/// ```no_run
/// # extern crate musli_web04 as musli_web;
/// use musli_web::ws;
/// use watchword::core::Error;
/// use watchword::musliweb04::{Connection, RequestError};
///
/// async fn stats(conn: &Connection, outgoing: &mut ws::Outgoing<'_>) -> Result<bool, RequestError> {
///     let admin = match conn.require_admin().await {
///         Ok(admin) => admin,
///         Err(Error::Auth(error)) => {
///             // Answer with the app's own response type, as a refusal.
///             # let _ = error;
///             return Ok(true);
///         }
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

    /// Whether `id` is one of watchword's endpoints, which
    /// [`handle`](Connection::handle) answers. For an app that writes its own
    /// combined `api::Id` rather than delegating its `Unknown` arm.
    pub fn handles(id: MessageId) -> bool {
        !matches!(Request::from_id(id), Request::Unknown(_))
    }

    /// Answers the request `id` if it is one of watchword's endpoints,
    /// returning `Ok(false)` otherwise, which the app treats as it treats its
    /// own unknown ids. Call it from the app's `ws::Handler::handle`, in the
    /// arm for the ids its own API does not know.
    ///
    /// For each request the session and its user are read again through
    /// [`Auth::session`], as the HTTP routes' extractors do, so a session
    /// that has ended since the socket opened is answered with
    /// [`AuthError::Unauthorized`], and a role change or revocation applies
    /// to the next request. The request then runs the same [`Auth`]
    /// operation as its HTTP route, with that user as the actor: the admin
    /// endpoints answer [`AuthError::Forbidden`] unless the user is an admin
    /// now, and the operations enforce the rest of their rules themselves.
    ///
    /// The response is the endpoint's `Result<T, AuthError>`, so a refused
    /// request gets the same [`AuthError`] as over HTTP. A body that does not
    /// decode is reported to the client by musli-web, as a request error.
    ///
    /// Errors when the store fails or hashing a password does. The error is
    /// logged here, at error level with its cause, so the app does not log
    /// it again; musli-web answers the request with the [`RequestError`]'s
    /// generic message, `internal error`, the analogue of an HTTP 500.
    pub async fn handle(
        &self,
        id: MessageId,
        incoming: &mut Incoming<'_>,
        outgoing: &mut Outgoing<'_>,
    ) -> Result<bool, RequestError> {
        let result = self
            .dispatch(Request::from_id(id), incoming, outgoing)
            .await;

        if let Err(error) = &result {
            tracing::error!(error = ?error, "auth: socket request {id} failed: {error}");
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
            Request::Unknown(_) => Ok(false),
        }
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

/// Writes an operation's result as the endpoint's `Result<T, AuthError>`,
/// passing an internal failure on as the request's error.
fn respond<T>(outgoing: &mut Outgoing<'_>, result: Result<T>) -> Result<bool>
where
    Result<T, AuthError>: EncodeBody,
{
    let response = match result {
        Ok(value) => Ok(value),
        Err(Error::Auth(error)) => Err(error),
        Err(error) => return Err(error),
    };

    outgoing.write(response);
    Ok(true)
}
