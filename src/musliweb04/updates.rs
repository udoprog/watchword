use core::future::Future;

use tokio::sync::broadcast::{self, error::RecvError};

use super::{AuthUpdate, Connection};
use crate::core::{AuthEvent, SessionGuard};

/// The live [`AuthUpdate`]s of one socket, from
/// [`Connection::updates`]: the socket loop's whole auth arm.
///
/// It owns the connection's [`SessionGuard`] and its receiver of
/// [`Auth::events`](crate::Auth::events), and [`next`](Updates::next)
/// yields each update to broadcast, filtered by
/// [`Connection::update`], standing in for missed events with
/// [`Connection::lagged`], and returning `None` once the session has ended,
/// when the app closes the socket. [`unless_ended`](Updates::unless_ended)
/// runs any other step, such as negotiating the socket, only while the
/// session lasts:
///
/// ```no_run
/// # async fn session_socket(
/// #     conn: watchword::musliweb04::Connection,
/// #     connect: impl std::future::Future<Output = Result<(), std::io::Error>>,
/// # ) {
/// // Before negotiating, so nothing broadcast meanwhile is missed.
/// let mut updates = conn.updates();
///
/// // A client stalling the negotiation does not outlive its session.
/// // let server = match updates.unless_ended(server.connect()).await { ... };
/// let Some(Ok(server)) = updates.unless_ended(connect).await else {
///     return;
/// };
/// # let _ = server;
///
/// loop {
///     tokio::select! {
///         // The session ended: dropping the server closes the socket.
///         update = updates.next() => {
///             let Some(update) = update else {
///                 break;
///             };
///
///             // if server.broadcast(update).is_err() { break; }
///             # let _: watchword::musliweb04::AuthUpdate = update;
///         }
///         // ... result = server.run() => break,
///     }
/// }
/// # }
/// ```
///
/// A store failure while filtering an event is logged here, at error level
/// with its cause, and the event is skipped, as the socket can do nothing
/// else about it.
pub struct Updates {
    conn: Connection,
    guard: SessionGuard,
    events: broadcast::Receiver<AuthEvent>,
    /// What was received and not yet turned into an update, kept across a
    /// cancelled [`next`](Updates::next).
    pending: Option<Pending>,
    ended: bool,
}

enum Pending {
    Event(AuthEvent),
    Lagged,
}

impl Updates {
    pub(super) fn new(conn: Connection) -> Self {
        let upgrade = conn.upgrade();
        let guard = conn.auth().guard(&upgrade.user, &upgrade.session);
        let events = conn.auth().events();

        Self {
            conn,
            guard,
            events,
            pending: None,
            ended: false,
        }
    }

    /// The next [`AuthUpdate`] to broadcast on the socket, or `None` once
    /// its session has ended, and from then on.
    ///
    /// The session ends as [`SessionGuard::ended`] says. When events were
    /// missed, the update is what [`Connection::lagged`] gives in their
    /// place.
    ///
    /// Cancel safe, so it can be a branch of the socket loop's
    /// `tokio::select!`: an event received by a cancelled call is the next
    /// call's.
    pub async fn next(&mut self) -> Option<AuthUpdate> {
        loop {
            if self.ended {
                return None;
            }

            if self.pending.is_none() {
                tokio::select! {
                    biased;
                    _ = self.guard.ended() => {
                        self.ended = true;
                        return None;
                    }
                    event = self.events.recv() => {
                        self.pending = Some(match event {
                            Ok(event) => Pending::Event(event),
                            // The guard re-checks the session itself.
                            Err(RecvError::Lagged(..)) => Pending::Lagged,
                            // Only once `Auth` is gone, which this holds.
                            Err(RecvError::Closed) => {
                                self.ended = true;
                                return None;
                            }
                        });
                    }
                }
            }

            let result = match &self.pending {
                Some(Pending::Event(event)) => self.conn.update(event).await,
                Some(Pending::Lagged) => self.conn.lagged().await,
                None => continue,
            };

            let pending = self.pending.take();

            match result {
                Ok(Some(update)) => return Some(update),
                Ok(None) => {}
                Err(error) => {
                    let what = match pending {
                        Some(Pending::Lagged) => "a lag",
                        _ => "an event",
                    };

                    tracing::error!(error = ?error, "auth: filtering {what} for a socket failed: {error}");
                }
            }
        }
    }

    /// Runs `future` unless the session ends first, giving `None` if it does,
    /// such as when negotiating the socket, so a client stalling it does not
    /// outlive its session.
    pub async fn unless_ended<F>(&self, future: F) -> Option<F::Output>
    where
        F: Future,
    {
        if self.ended {
            return None;
        }

        tokio::select! {
            biased;
            _ = self.guard.ended() => None,
            output = future => Some(output),
        }
    }

    /// The connection these are the updates of.
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The guard of the connection's session, which also follows its user:
    /// [`SessionGuard::user`] and [`SessionGuard::watch_user`].
    pub fn guard(&self) -> &SessionGuard {
        &self.guard
    }
}
