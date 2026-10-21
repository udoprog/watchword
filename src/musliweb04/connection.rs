use musli_web04::api::{EncodeBody, Id, MessageId};
use musli_web04::ws::{Incoming, Outgoing};

use super::{
    AuthUpdate, DeleteUserRequest, IssueLinkRequest, MeRequest, Request, RevokeAccessRequest,
    RevokeLinkRequest, SignOutUserRequest, UserUpdate, UsersRequest,
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
/// extracts, and feed it the [`AuthEvent`]s of [`Auth::events`] in the
/// connection's loop, broadcasting what [`update`](Connection::update)
/// returns:
///
/// ```no_run
/// # async fn ws(auth: watchword::Auth, signed_in: watchword::axum08::SignedIn) -> watchword::core::Result<()> {
/// use tokio::sync::broadcast::error::RecvError;
/// use watchword::musliweb04::{AuthUpdate, Connection};
///
/// let conn = Connection::new(auth.clone(), &signed_in);
/// let guard = auth.guard(&signed_in.user, &signed_in.session);
/// let mut events = auth.events();
///
/// loop {
///     tokio::select! {
///         _ = guard.ended() => break,
///         event = events.recv() => {
///             let update = match event {
///                 Ok(event) => conn.update(&event).await?,
///                 // Events were missed: the page fetches again what it
///                 // shows, and the guard re-checks the session itself.
///                 Err(RecvError::Lagged(..)) => conn.lagged().await?,
///                 Err(RecvError::Closed) => break,
///             };
///
///             if let Some(update) = update {
///                 // server.broadcast(update)?;
///                 # let _: AuthUpdate = update;
///             }
///         }
///         // ... the socket's own messages
///     }
/// }
/// # Ok(()) }
/// ```
///
/// Ending the socket when its session ends stays the job of
/// [`Auth::guard`]: no update is sent for it. Cloning a `Connection` is cheap,
/// so it can sit inside the app's own `ws::Handler`, which hands it the
/// requests its own API does not know with [`handle`](Connection::handle):
///
/// ```no_run
/// # mod api { pub enum Request { Unknown(musli_web::api::MessageId) } }
/// # extern crate musli_web04 as musli_web;
/// use musli_web::ws;
/// use watchword::musliweb04::Connection;
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
///     ) -> watchword::core::Result<bool> {
///         match id {
///             // ... the app's own requests
///             api::Request::Unknown(id) => self.conn.handle(id, incoming, outgoing).await,
///         }
///     }
/// }
/// ```
#[derive(Clone)]
pub struct Connection {
    auth: Auth,
    session: String,
    user: UserId,
}

impl Connection {
    /// The connection signed in as `signed_in`, as the app's `/ws` route
    /// extracted it at upgrade.
    pub fn new(auth: Auth, signed_in: &SignedIn) -> Self {
        Self {
            auth,
            session: signed_in.session.id.clone(),
            user: signed_in.user.id,
        }
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
            AuthEvent::UserChanged(info) if info.id == self.user => {
                let Some((user, session)) = self.auth.session(&self.session).await? else {
                    return Ok(None);
                };

                let info = self.auth.session_info(&user, &session).await?;
                return Ok(Some(AuthUpdate::Me(info)));
            }
            AuthEvent::UserChanged(info) => AuthUpdate::UserChanged(info.clone()),
            AuthEvent::UserCreated(info) => AuthUpdate::UserCreated(info.clone()),
            AuthEvent::UserDeleted(id) => AuthUpdate::UserDeleted(*id),
        };

        let Some((user, _)) = self.auth.session(&self.session).await? else {
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
        let Some((user, session)) = self.auth.session(&self.session).await? else {
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
    /// Errors when the store fails or hashing a password does: the error is
    /// logged, and musli-web answers the request with its message (such as
    /// `storage failed`), the analogue of an HTTP 500.
    pub async fn handle(
        &self,
        id: MessageId,
        incoming: &mut Incoming<'_>,
        outgoing: &mut Outgoing<'_>,
    ) -> Result<bool> {
        let result = self
            .dispatch(Request::from_id(id), incoming, outgoing)
            .await;

        if let Err(error) = &result {
            tracing::error!(error = ?error, "auth: socket request {id} failed: {error}");
        }

        result
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

                    let user = self.auth.update_user(&user, user.id, &change).await?;
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
                    let admin = self.admin().await?;
                    self.auth.users(&admin).await
                };

                respond(outgoing, response.await)
            }
            Request::CreateUser => {
                let Some(new) = incoming.read::<NewUser>() else {
                    return Ok(false);
                };

                let response = async {
                    let admin = self.admin().await?;
                    let (entry, link) = self.auth.create_user(&admin, &new).await?;
                    Ok(CreatedUser { entry, link })
                };

                respond(outgoing, response.await)
            }
            Request::UpdateUser => {
                let Some(UserUpdate { id, change }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let admin = self.admin().await?;
                    let user = self.auth.update_user(&admin, id, &change).await?;
                    Ok(user.info())
                };

                respond(outgoing, response.await)
            }
            Request::DeleteUser => {
                let Some(DeleteUserRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let admin = self.admin().await?;
                    self.auth.delete_user(&admin, id).await
                };

                respond(outgoing, response.await)
            }
            Request::IssueLink => {
                let Some(IssueLinkRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let admin = self.admin().await?;
                    self.auth.issue_link(&admin, id).await
                };

                respond(outgoing, response.await)
            }
            Request::RevokeLink => {
                let Some(RevokeLinkRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let admin = self.admin().await?;
                    self.auth.revoke_link(&admin, id).await
                };

                respond(outgoing, response.await)
            }
            Request::SignOutUser => {
                let Some(SignOutUserRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let admin = self.admin().await?;
                    self.auth.sign_out_everywhere(&admin, id).await
                };

                respond(outgoing, response.await)
            }
            Request::RevokeAccess => {
                let Some(RevokeAccessRequest { id }) = incoming.read() else {
                    return Ok(false);
                };

                let response = async {
                    let admin = self.admin().await?;
                    let user = self.auth.revoke_access(&admin, id).await?;
                    Ok(user.info())
                };

                respond(outgoing, response.await)
            }
            Request::Unknown(_) => Ok(false),
        }
    }

    /// The connection's session and its user as stored now, or
    /// [`AuthError::Unauthorized`] once the session has ended, as the
    /// `SignedIn` extractor answers over HTTP.
    async fn signed_in(&self) -> Result<(User, Session)> {
        match self.auth.session(&self.session).await? {
            Some(signed_in) => Ok(signed_in),
            None => Err(AuthError::Unauthorized.into()),
        }
    }

    /// The connection's user, refused with [`AuthError::Forbidden`] unless
    /// they are an active admin now, as the `Admin` extractor answers over
    /// HTTP.
    async fn admin(&self) -> Result<User> {
        let (user, _) = self.signed_in().await?;

        if user.access != Access::Active || !user.is_admin() {
            return Err(AuthError::Forbidden.into());
        }

        Ok(user)
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
