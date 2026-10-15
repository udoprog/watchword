use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::Auth;
use crate::core::{AuthEvent, Result};
use crate::types::{Access, UserId};

/// How long a confirmed session is believed live without asking the store.
pub(crate) const LIVE_TTL: Duration = Duration::from_secs(10);

/// How many sessions the cache remembers.
const LIVE_CAPACITY: usize = 1024;

/// Sessions recently confirmed live, for the `LiveSession` extractor on hot
/// asset routes (territory's tile cache). Only live sessions are cached, and
/// every [`AuthEvent`] that ends a session forgets it at once, so the TTL
/// only bounds how long a session ended by another process stays usable.
#[derive(Default)]
pub(crate) struct LiveCache {
    entries: Mutex<HashMap<String, Entry>>,
}

/// A session confirmed live: its user, its impersonator, and when.
struct Entry {
    user: UserId,
    impersonator: Option<UserId>,
    at: Instant,
}

impl LiveCache {
    fn get(&self, session: &str, now: Instant) -> bool {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        entries
            .get(session)
            .is_some_and(|entry| now.duration_since(entry.at) < LIVE_TTL)
    }

    fn insert(&self, session: &str, user: UserId, impersonator: Option<UserId>, now: Instant) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        if entries.len() >= LIVE_CAPACITY && !entries.contains_key(session) {
            entries.retain(|_, entry| now.duration_since(entry.at) < LIVE_TTL);

            if entries.len() >= LIVE_CAPACITY
                && let Some(oldest) = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.at)
                    .map(|(id, _)| id.clone())
            {
                entries.remove(&oldest);
            }
        }

        entries.insert(
            session.to_owned(),
            Entry {
                user,
                impersonator,
                at: now,
            },
        );
    }

    /// Forgets the sessions `event` ends.
    pub(crate) fn forget(&self, event: &AuthEvent) {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());

        match event {
            AuthEvent::SessionEnded(id) => {
                entries.remove(id);
            }
            AuthEvent::UserSessionsEnded { user, keep } => {
                entries.retain(|id, e| e.user != *user || keep.as_ref() == Some(id));
            }
            AuthEvent::UserDeleted(user) => {
                entries.retain(|_, e| e.user != *user && e.impersonator != Some(*user));
            }
            AuthEvent::UserChanged(info) => {
                let revoked = info.access == Access::Revoked;
                // Sessions they impersonate in end with their admin standing.
                let admin = info.access == Access::Active && info.is_admin();

                entries.retain(|_, e| {
                    !(revoked && e.user == info.id || !admin && e.impersonator == Some(info.id))
                });
            }
            AuthEvent::UserCreated(_) => {}
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl Auth {
    /// Whether the session `session_id` is live, as [`Auth::session`] says,
    /// answering from the cache for [`LIVE_TTL`] after a confirmation.
    pub(crate) async fn session_live(&self, session_id: &str) -> Result<bool> {
        let cache = self.live_cache();

        if cache.get(session_id, Instant::now()) {
            return Ok(true);
        }

        let Some((user, session)) = self.session(session_id).await? else {
            return Ok(false);
        };

        cache.insert(session_id, user.id, session.impersonator, Instant::now());
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Method, Role, UserInfo};

    #[test]
    fn expires_and_evicts() {
        let cache = LiveCache::default();
        let t0 = Instant::now();

        cache.insert("a", UserId(1), None, t0);
        assert!(cache.get("a", t0 + Duration::from_secs(9)));
        assert!(!cache.get("a", t0 + LIVE_TTL));
        assert!(!cache.get("b", t0));

        for n in 0..LIVE_CAPACITY + 10 {
            cache.insert(
                &n.to_string(),
                UserId(2),
                None,
                t0 + Duration::from_millis(n as u64),
            );
        }

        assert_eq!(cache.len(), LIVE_CAPACITY);
        // The oldest went first.
        assert!(!cache.get("a", t0));
        assert!(!cache.get("0", t0 + Duration::from_secs(1)));
        assert!(cache.get(
            &(LIVE_CAPACITY + 9).to_string(),
            t0 + Duration::from_secs(1)
        ));
    }

    #[test]
    fn events_forget_sessions() {
        let cache = LiveCache::default();
        let now = Instant::now();

        cache.insert("a1", UserId(1), None, now);
        cache.insert("a2", UserId(1), None, now);
        cache.insert("b1", UserId(2), None, now);
        cache.insert("c1", UserId(3), None, now);

        cache.forget(&AuthEvent::SessionEnded("c1".to_owned()));
        assert!(!cache.get("c1", now));

        cache.forget(&AuthEvent::UserSessionsEnded {
            user: UserId(1),
            keep: Some("a2".to_owned()),
        });
        assert!(!cache.get("a1", now));
        assert!(cache.get("a2", now));
        assert!(cache.get("b1", now));

        cache.forget(&AuthEvent::UserDeleted(UserId(2)));
        assert!(!cache.get("b1", now));
        assert!(cache.get("a2", now));
    }

    #[test]
    fn impersonations_end_with_their_admin() {
        let cache = LiveCache::default();
        let now = Instant::now();
        let info = |role, access| UserInfo {
            id: UserId(1),
            login: Some("boss".to_owned()),
            email: None,
            role,
            access,
            method: Method::Password,
            has_password: true,
            created_at: jiff::Timestamp::UNIX_EPOCH,
            impersonated_by: None,
        };

        cache.insert("own", UserId(1), None, now);
        cache.insert("as2", UserId(2), Some(UserId(1)), now);
        cache.insert("as3", UserId(3), Some(UserId(1)), now);
        cache.insert("as4", UserId(4), Some(UserId(5)), now);

        // Still an active admin: nothing ends.
        cache.forget(&AuthEvent::UserChanged(info(Role::Admin, Access::Active)));
        assert!(cache.get("own", now) && cache.get("as2", now) && cache.get("as3", now));

        // Demoted: their impersonations end, their own session does not.
        cache.forget(&AuthEvent::UserChanged(info(Role::Regular, Access::Active)));
        assert!(cache.get("own", now));
        assert!(!cache.get("as2", now) && !cache.get("as3", now));
        assert!(cache.get("as4", now));

        // Revoked: everything of theirs ends.
        cache.insert("as2", UserId(2), Some(UserId(1)), now);
        cache.forget(&AuthEvent::UserChanged(info(Role::Admin, Access::Revoked)));
        assert!(!cache.get("own", now) && !cache.get("as2", now));

        // Deleted: so do the impersonations of the deleted admin.
        cache.forget(&AuthEvent::UserDeleted(UserId(5)));
        assert!(!cache.get("as4", now));
    }
}
