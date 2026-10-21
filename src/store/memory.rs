use std::borrow::ToOwned;
use std::collections::{BTreeMap, HashMap};
use std::string::String;
use std::sync::{Arc, Mutex, MutexGuard};
use std::vec::Vec;

use jiff::Timestamp;

use super::{Credential, Result, Session, Store, StoreError, Token, User};
use crate::core::is_expired;
use crate::types::{Access, Conflict, Method, NewUser, UserChange, UserId};

/// A [`Store`] in memory, for tests and examples. Clones share the same data.
#[derive(Clone, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    users: BTreeMap<UserId, User>,
    sessions: HashMap<String, Session>,
    tokens: HashMap<String, Token>,
    config: HashMap<String, String>,
    /// A user to revoke at the start of the next conditional write, to stand
    /// in for a concurrent revocation in tests.
    #[cfg(test)]
    revoke_before_write: Option<UserId>,
}

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // Every change is applied whole before the lock is released, so the
        // data is consistent even if a panic poisoned it.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Revokes the user `id` at the start of the next
    /// [`activate`](Store::activate) or
    /// [`set_credential`](Store::set_credential), after the caller has read
    /// the user, as a concurrent revocation would.
    #[cfg(test)]
    pub(crate) fn revoke_before_next_write(&self, id: UserId) {
        self.lock().revoke_before_write = Some(id);
    }

    /// Locks the store for a conditional write, first applying the
    /// revocation set by
    /// [`revoke_before_next_write`](Self::revoke_before_next_write).
    fn lock_for_write(&self) -> MutexGuard<'_, Inner> {
        #[allow(unused_mut)]
        let mut inner = self.lock();

        #[cfg(test)]
        if let Some(id) = inner.revoke_before_write.take() {
            inner.revoke(id, Timestamp::now());
        }

        inner
    }
}

impl Inner {
    fn conflict(
        &self,
        id: Option<UserId>,
        login: Option<&str>,
        email: Option<&str>,
    ) -> Option<Conflict> {
        let others = || self.users.values().filter(move |u| Some(u.id) != id);

        if login.is_some() && others().any(|u| u.login.as_deref() == login) {
            return Some(Conflict::Login);
        }

        if email.is_some() && others().any(|u| u.email.as_deref() == email) {
            return Some(Conflict::Email);
        }

        None
    }

    fn set_credential(&mut self, id: UserId, cred: &Credential) -> Result<bool> {
        if let Credential::Google { sub, email } = cred {
            if self
                .users
                .values()
                .any(|u| u.id != id && u.google_sub.as_deref() == Some(sub))
            {
                return Err(StoreError::new("google account is bound to another user"));
            }

            if self.conflict(Some(id), None, Some(email)).is_some() {
                return Err(StoreError::new("email is taken by another user"));
            }
        }

        let Some(user) = self.users.get_mut(&id) else {
            return Ok(false);
        };

        match cred {
            Credential::Password(hash) => {
                user.method = Method::Password;
                user.password_hash = Some(hash.clone());
                user.google_sub = None;
            }
            Credential::Google { sub, email } => {
                user.method = Method::Google;
                user.password_hash = None;
                user.google_sub = Some(sub.clone());
                user.email = Some(email.clone());
            }
        }

        user.access = Access::Active;
        Ok(true)
    }

    fn revoke(&mut self, id: UserId, now: Timestamp) -> bool {
        let Some(user) = self.users.get_mut(&id) else {
            return false;
        };

        user.access = Access::Revoked;
        user.password_hash = None;
        self.use_up_tokens(id, now);
        self.delete_sessions(id, None);
        true
    }

    fn delete_sessions(&mut self, user: UserId, keep: Option<&str>) {
        self.sessions
            .retain(|id, s| s.user != user || Some(id.as_str()) == keep);
    }

    fn use_up_tokens(&mut self, user: UserId, now: Timestamp) {
        for token in self.tokens.values_mut() {
            if token.user == user && token.used_at.is_none() {
                token.used_at = Some(now);
            }
        }
    }
}

impl Store for MemoryStore {
    async fn user(&self, id: UserId) -> Result<Option<User>> {
        Ok(self.lock().users.get(&id).cloned())
    }

    async fn user_by_email(&self, email: &str) -> Result<Option<User>> {
        let inner = self.lock();
        let user = inner
            .users
            .values()
            .find(|u| u.email.as_deref() == Some(email));
        Ok(user.cloned())
    }

    async fn user_by_login(&self, login: &str) -> Result<Option<User>> {
        let inner = self.lock();
        let user = inner
            .users
            .values()
            .find(|u| u.login.as_deref() == Some(login));
        Ok(user.cloned())
    }

    async fn user_by_google_sub(&self, sub: &str) -> Result<Option<User>> {
        let inner = self.lock();
        let user = inner
            .users
            .values()
            .find(|u| u.google_sub.as_deref() == Some(sub));
        Ok(user.cloned())
    }

    async fn users(&self, now: Timestamp) -> Result<Vec<(User, Option<Timestamp>)>> {
        let inner = self.lock();

        let users = inner.users.values().map(|user| {
            let link = inner
                .tokens
                .values()
                .filter(|t| t.user == user.id && t.used_at.is_none())
                .filter(|t| !is_expired(t.expires_at, now))
                .map(|t| t.expires_at)
                .max();

            (user.clone(), link)
        });

        Ok(users.collect())
    }

    async fn user_count(&self) -> Result<u64> {
        Ok(self.lock().users.len() as u64)
    }

    async fn create_user(&self, new: &NewUser, now: Timestamp) -> Result<Result<User, Conflict>> {
        let mut inner = self.lock();

        if let Some(conflict) = inner.conflict(None, new.login.as_deref(), new.email.as_deref()) {
            return Ok(Err(conflict));
        }

        inner.next_id += 1;

        let user = User {
            id: UserId(inner.next_id),
            login: new.login.clone(),
            email: new.email.clone(),
            role: new.role,
            access: Access::Pending,
            method: Method::Password,
            password_hash: None,
            google_sub: None,
            created_at: now,
        };

        inner.users.insert(user.id, user.clone());
        Ok(Ok(user))
    }

    async fn update_user(
        &self,
        id: UserId,
        change: &UserChange,
    ) -> Result<Result<Option<User>, Conflict>> {
        let mut inner = self.lock();

        let login = change.login.as_ref().and_then(Option::as_deref);
        let email = change.email.as_ref().and_then(Option::as_deref);

        if let Some(conflict) = inner.conflict(Some(id), login, email) {
            return Ok(Err(conflict));
        }

        let Some(user) = inner.users.get_mut(&id) else {
            return Ok(Ok(None));
        };

        if let Some(login) = &change.login {
            user.login = login.clone();
        }

        if let Some(email) = &change.email {
            user.email = email.clone();
        }

        if let Some(role) = change.role {
            user.role = role;
        }

        Ok(Ok(Some(user.clone())))
    }

    async fn delete_user(&self, id: UserId) -> Result<bool> {
        let mut inner = self.lock();

        if inner.users.remove(&id).is_none() {
            return Ok(false);
        }

        inner
            .sessions
            .retain(|_, s| s.user != id && s.impersonator != Some(id));
        inner.tokens.retain(|_, t| t.user != id);
        Ok(true)
    }

    async fn set_credential(
        &self,
        id: UserId,
        cred: &Credential,
        keep: Option<&str>,
    ) -> Result<bool> {
        let mut inner = self.lock_for_write();

        if inner
            .users
            .get(&id)
            .is_none_or(|u| u.access == Access::Revoked)
        {
            return Ok(false);
        }

        if !inner.set_credential(id, cred)? {
            return Ok(false);
        }

        inner.delete_sessions(id, keep);
        Ok(true)
    }

    async fn bind_google_sub(&self, id: UserId, sub: &str) -> Result<bool> {
        let mut inner = self.lock();

        if inner
            .users
            .values()
            .any(|u| u.id != id && u.google_sub.as_deref() == Some(sub))
        {
            return Ok(false);
        }

        let Some(user) = inner.users.get_mut(&id) else {
            return Ok(false);
        };

        match &user.google_sub {
            Some(bound) => Ok(bound == sub),
            None => {
                user.google_sub = Some(sub.to_owned());
                Ok(true)
            }
        }
    }

    async fn set_access(&self, id: UserId, access: Access) -> Result<bool> {
        let mut inner = self.lock();

        let Some(user) = inner.users.get_mut(&id) else {
            return Ok(false);
        };

        user.access = access;
        Ok(true)
    }

    async fn activate(&self, id: UserId) -> Result<bool> {
        let mut inner = self.lock_for_write();

        let Some(user) = inner.users.get_mut(&id) else {
            return Ok(false);
        };

        if user.access != Access::Pending {
            return Ok(false);
        }

        user.access = Access::Active;
        Ok(true)
    }

    async fn revoke(&self, id: UserId, now: Timestamp) -> Result<bool> {
        Ok(self.lock().revoke(id, now))
    }

    async fn create_session(&self, session: &Session) -> Result<()> {
        let mut inner = self.lock();
        let now = session.created_at;
        inner.sessions.retain(|_, s| !is_expired(s.expires_at, now));
        inner.sessions.insert(session.id.clone(), session.clone());
        Ok(())
    }

    async fn session(&self, id: &str) -> Result<Option<Session>> {
        Ok(self.lock().sessions.get(id).cloned())
    }

    async fn delete_session(&self, id: &str) -> Result<()> {
        self.lock().sessions.remove(id);
        Ok(())
    }

    async fn delete_sessions(&self, user: UserId, keep: Option<&str>) -> Result<()> {
        self.lock().delete_sessions(user, keep);
        Ok(())
    }

    async fn delete_expired_sessions(&self, now: Timestamp) -> Result<()> {
        self.lock()
            .sessions
            .retain(|_, s| !is_expired(s.expires_at, now));
        Ok(())
    }

    async fn create_token(&self, token: &Token, now: Timestamp) -> Result<()> {
        let mut inner = self.lock();
        inner.use_up_tokens(token.user, now);
        inner.tokens.insert(token.id.clone(), token.clone());
        Ok(())
    }

    async fn token(&self, id: &str) -> Result<Option<Token>> {
        Ok(self.lock().tokens.get(id).cloned())
    }

    async fn delete_expired_tokens(&self, before: Timestamp) -> Result<()> {
        self.lock()
            .tokens
            .retain(|_, t| !is_expired(t.expires_at, before));
        Ok(())
    }

    async fn use_up_tokens(&self, user: UserId, now: Timestamp) -> Result<()> {
        self.lock().use_up_tokens(user, now);
        Ok(())
    }

    async fn redeem_token(
        &self,
        token: &str,
        cred: &Credential,
        session: &Session,
        now: Timestamp,
    ) -> Result<bool> {
        let mut inner = self.lock();

        let Some(row) = inner.tokens.get(token) else {
            return Ok(false);
        };

        if row.used_at.is_some() {
            return Ok(false);
        }

        let user = row.user;

        // Checked before anything changes, so a failure changes nothing.
        if !inner.set_credential(user, cred)? {
            return Ok(false);
        }

        if let Some(row) = inner.tokens.get_mut(token) {
            row.used_at = Some(now);
        }

        inner.delete_sessions(user, None);
        inner.sessions.insert(session.id.clone(), session.clone());
        Ok(true)
    }

    async fn config_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self.lock().config.get(key).cloned())
    }

    async fn config_set(&self, key: &str, value: &str) -> Result<()> {
        self.lock().config.insert(key.to_owned(), value.to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Auth, generate_session_key};
    use crate::store::suite::{TestResult, store_suite};
    use crate::types::Role;

    store_suite!(MemoryStore::new());

    /// A user who registered with Google before subjects were recorded, which
    /// no `Store` method produces, so it is set up in the store's data.
    #[tokio::test]
    async fn google_users_without_a_subject_are_bound_on_sign_in() -> TestResult {
        let store = MemoryStore::new();
        let auth = Auth::builder(store.clone(), generate_session_key()).build();

        let new = NewUser {
            login: None,
            email: Some("legacy@example.com".to_owned()),
            role: Role::Regular,
        };
        let user = store.create_user(&new, Timestamp::now()).await?.unwrap();

        {
            let mut inner = store.lock();
            let legacy = inner.users.get_mut(&user.id).unwrap();
            legacy.method = Method::Google;
            legacy.access = Access::Active;
        }

        // The first sign-in matches them by email and binds the account.
        let (found, _) = auth
            .sign_in_google("sub:first", "Legacy@example.com")
            .await?;
        assert_eq!(found.id, user.id);
        assert_eq!(
            store.user(user.id).await?.unwrap().google_sub.as_deref(),
            Some("sub:first")
        );

        // Afterwards only that account signs in.
        assert!(
            auth.sign_in_google("sub:second", "legacy@example.com")
                .await
                .is_err()
        );
        auth.sign_in_google("sub:first", "new@example.com").await?;
        Ok(())
    }
}
