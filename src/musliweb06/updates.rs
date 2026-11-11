use core::future::{Future, pending};
use std::sync::OnceLock;

use tokio::sync::broadcast::{self, error::RecvError};
use tokio::sync::watch;

use super::connection::Accepted;
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
/// #     conn: watchword::musliweb06::Connection,
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
///             # let _: watchword::musliweb06::AuthUpdate = update;
///         }
///         // ... result = server.run() => break,
///     }
/// }
/// # }
/// ```
///
/// [`next`](Updates::next) yields nothing until [`Connection::accept`] has
/// settled whose socket it is, since the updates are taken before
/// negotiating; the events sent meanwhile wait in the receiver and are
/// filtered for the settled session. They do not end merely because
/// `accept` has not run, only when the upgrade's session ends.
///
/// Once [`Connection::accept`] switched the connection to a page's session,
/// the updates follow both it and the upgrade's session, which vouched for
/// it, and end when either ends. A refused connection's updates end at once.
///
/// A store failure while filtering an event is logged here, at error level
/// with its cause, and the event is skipped, as the socket can do nothing
/// else about it.
pub struct Updates {
    sessions: Sessions,
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
        let settled = conn.settled();

        Self {
            sessions: Sessions {
                conn,
                upgrade: guard,
                page: OnceLock::new(),
                settled,
            },
            events,
            pending: None,
            ended: false,
        }
    }

    /// The next [`AuthUpdate`] to broadcast on the socket, or `None` once
    /// its session has ended, and from then on.
    ///
    /// The session ends as [`SessionGuard::ended`] says, of the upgrade's
    /// session and, once switched to it, of the page's. When events were
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

            // Until accept settled whose socket it is, nothing is received,
            // so what arrives meanwhile is filtered for that session.
            if self.sessions.conn.accepted().is_none() {
                tokio::select! {
                    biased;
                    _ = self.sessions.ended() => {
                        self.ended = true;
                        return None;
                    }
                    _ = self.sessions.settled() => continue,
                }
            }

            if self.pending.is_none() {
                tokio::select! {
                    biased;
                    _ = self.sessions.ended() => {
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
                Some(Pending::Event(event)) => self.sessions.conn.update(event).await,
                Some(Pending::Lagged) => self.sessions.conn.lagged().await,
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
            _ = self.sessions.ended() => None,
            output = future => Some(output),
        }
    }

    /// The connection these are the updates of.
    pub fn connection(&self) -> &Connection {
        &self.sessions.conn
    }

    /// The guard of the session the connection speaks for, which also
    /// follows its user: [`SessionGuard::user`] and
    /// [`SessionGuard::watch_user`]. Once [`Connection::accept`] switched to
    /// a page's session, it is that session's guard.
    pub fn guard(&self) -> &SessionGuard {
        self.sessions.page().unwrap_or(&self.sessions.upgrade)
    }
}

/// The guards of the sessions a connection depends on, apart from the event
/// receiver so both can be awaited at once.
struct Sessions {
    conn: Connection,
    /// The guard of the upgrade's session.
    upgrade: SessionGuard,
    /// The guard of the page's session, made once the connection switched
    /// to it.
    page: OnceLock<SessionGuard>,
    /// Turns `true` once [`Connection::accept`] settled.
    settled: watch::Receiver<bool>,
}

impl Sessions {
    /// Resolves once a session the connection depends on has ended, or the
    /// connection was refused. Cancel safe.
    async fn ended(&self) {
        tokio::select! {
            biased;
            _ = self.upgrade.ended() => {}
            _ = self.page_ended() => {}
        }
    }

    /// Resolves once the page's session ended or the connection was
    /// refused; never while it speaks for the upgrade's session.
    async fn page_ended(&self) {
        self.settled().await;

        match self.conn.accepted() {
            Some(Accepted::Refused) => {}
            Some(Accepted::Page(..)) => {
                if let Some(guard) = self.page() {
                    guard.ended().await;
                }
            }
            _ => pending().await,
        }
    }

    /// Resolves once [`Connection::accept`] settled.
    async fn settled(&self) {
        let mut settled = self.settled.clone();

        // The connection held here holds the sender.
        if settled.wait_for(|settled| *settled).await.is_err() {
            pending::<()>().await;
        }
    }

    /// The guard of the page's session, once the connection switched to it.
    fn page(&self) -> Option<&SessionGuard> {
        let Some(Accepted::Page(page)) = self.conn.accepted() else {
            return None;
        };

        Some(
            self.page
                .get_or_init(|| self.conn.auth().guard(&page.user, &page.session)),
        )
    }
}
