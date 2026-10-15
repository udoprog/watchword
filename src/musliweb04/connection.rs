use super::AuthUpdate;
use crate::Auth;
use crate::axum08::SignedIn;
use crate::core::{AuthEvent, Result};
use crate::types::{Access, UserId};

/// watchword's side of one musli-web WebSocket, signed in with one session.
///
/// Create it at upgrade from the [`SignedIn`] the app's `/ws` route already
/// extracts, and feed it the [`AuthEvent`]s of [`Auth::events`] in the
/// connection's loop, broadcasting what [`update`](Connection::update)
/// returns:
///
/// ```no_run
/// # async fn ws(auth: watchword::Auth, signed_in: watchword::axum08::SignedIn) -> watchword::core::Result<()> {
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
///             let Ok(event) = event else {
///                 // Lagged: the guard re-checks the session itself.
///                 continue;
///             };
///
///             if let Some(update) = conn.update(&event).await? {
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
/// so it can sit inside the app's own `ws::Handler`.
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
}
