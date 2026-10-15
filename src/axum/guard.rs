use std::time::Duration;

use jiff::Timestamp;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use super::SignedIn;
use crate::Auth;
use crate::core::AuthEvent;
use crate::types::{Access, UserId, UserInfo};

/// How often a guard re-checks its session in the store, to notice a session
/// ended by another process.
const RECHECK: Duration = Duration::from_secs(5 * 60);

impl Auth {
    /// Watches the session of `signed_in`, for a WebSocket's `select!` loop:
    ///
    /// ```no_run
    /// # async fn ws(auth: auth::Auth, user: auth::axum::SignedIn) {
    /// let guard = auth.guard(&user);
    ///
    /// loop {
    ///     tokio::select! {
    ///         _ = guard.ended() => break,
    ///         info = guard.changed() => {
    ///             // The user's role, email, login or credential changed.
    ///         }
    ///         // ... the socket's own messages
    ///     }
    /// }
    /// # }
    /// ```
    ///
    /// The guard follows [`AuthEvent`]s, sleeps until the session expires,
    /// and re-checks the session in the store on broadcast lag and every 5
    /// minutes, so a session deleted by another process still ends the
    /// socket. It runs a task on the current Tokio runtime until it is
    /// dropped or the session ends.
    pub fn guard(&self, signed_in: &SignedIn) -> SessionGuard {
        let (ended_tx, ended) = watch::channel(false);
        let (changed_tx, changed) = watch::channel(signed_in.user.info());

        let watcher = Watcher {
            auth: self.clone(),
            // Subscribe now, so nothing sent after this call is missed.
            events: self.events(),
            session: signed_in.session.id.clone(),
            user: signed_in.user.id,
            impersonator: signed_in.session.impersonator,
            expires_at: signed_in.session.expires_at,
            ended: ended_tx,
            changed: changed_tx,
        };

        SessionGuard {
            ended: Mutex::new(ended),
            changed: Mutex::new(changed),
            task: tokio::spawn(watcher.run()),
        }
    }
}

/// Resolves when a WebSocket's session ends; see [`Auth::guard`].
///
/// Both methods take `&self` and are cancel-safe, so they can share one
/// `tokio::select!`.
pub struct SessionGuard {
    ended: Mutex<watch::Receiver<bool>>,
    changed: Mutex<watch::Receiver<UserInfo>>,
    task: JoinHandle<()>,
}

impl SessionGuard {
    /// Resolves once the session has ended: signed out, signed out
    /// everywhere, revoked, the credential changed elsewhere, the user
    /// deleted, or the session expired; for an impersonated session also
    /// when its admin is revoked, demoted or deleted. Once ended, it
    /// resolves at once.
    pub async fn ended(&self) {
        let mut ended = self.ended.lock().await;
        // An error means the watcher is gone, which it only is once ended.
        let _ = ended.wait_for(|ended| *ended).await;
    }

    /// Resolves with the user whenever their login, email, role, access or
    /// credential changes. Changes made while nobody waits are coalesced
    /// into the latest one. Never resolves once the session has ended.
    pub async fn changed(&self) -> UserInfo {
        let mut changed = self.changed.lock().await;

        if changed.changed().await.is_err() {
            return std::future::pending().await;
        }

        changed.borrow_and_update().clone()
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Watcher {
    auth: Auth,
    events: tokio::sync::broadcast::Receiver<AuthEvent>,
    session: String,
    user: UserId,
    impersonator: Option<UserId>,
    expires_at: Timestamp,
    ended: watch::Sender<bool>,
    changed: watch::Sender<UserInfo>,
}

impl Watcher {
    async fn run(mut self) {
        let expiry = tokio::time::sleep(until(self.expires_at));
        tokio::pin!(expiry);

        let mut recheck = tokio::time::interval_at(Instant::now() + RECHECK, RECHECK);
        recheck.set_missed_tick_behavior(MissedTickBehavior::Delay);

        // Catches anything that happened between the request loading the
        // session and the guard subscribing.
        let mut live = self.recheck().await;

        while live {
            live = tokio::select! {
                _ = &mut expiry => false,
                _ = recheck.tick() => self.recheck().await,
                event = self.events.recv() => match event {
                    Ok(event) => self.apply(event),
                    Err(RecvError::Lagged(_)) => self.recheck().await,
                    // The service holds the sender, and this task the service.
                    Err(RecvError::Closed) => false,
                },
            };
        }

        let _ = self.ended.send(true);
    }

    /// Whether the session is still live after `event`.
    fn apply(&self, event: AuthEvent) -> bool {
        match event {
            AuthEvent::SessionEnded(id) => id != self.session,
            AuthEvent::UserSessionsEnded { user, keep } => {
                user != self.user || keep.as_deref() == Some(self.session.as_str())
            }
            AuthEvent::UserDeleted(user) => user != self.user && Some(user) != self.impersonator,
            // An impersonated session ends with its admin's standing.
            AuthEvent::UserChanged(info) if Some(info.id) == self.impersonator => {
                info.access == Access::Active && info.is_admin()
            }
            AuthEvent::UserChanged(info) if info.id == self.user => {
                if info.access == Access::Revoked {
                    return false;
                }

                self.change(info);
                true
            }
            AuthEvent::UserChanged(_) | AuthEvent::UserCreated(_) => true,
        }
    }

    /// Asks the store whether the session is live, passing on a change to
    /// the user that an event may have been lost for.
    async fn recheck(&self) -> bool {
        match self.auth.session(&self.session).await {
            Ok(Some((user, _))) => {
                self.change(user.info());
                true
            }
            Ok(None) => false,
            Err(error) => {
                // Keep the socket; the next check may succeed.
                tracing::warn!(error = ?error, "auth: re-checking a socket's session failed");
                true
            }
        }
    }

    fn change(&self, info: UserInfo) {
        self.changed.send_if_modified(|current| {
            if *current == info {
                return false;
            }

            *current = info;
            true
        });
    }
}

/// How long until `at`, or zero if it has passed.
fn until(at: Timestamp) -> Duration {
    let left = at.duration_since(Timestamp::now());
    Duration::try_from(left).unwrap_or(Duration::ZERO)
}
