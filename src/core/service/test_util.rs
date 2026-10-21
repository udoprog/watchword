//! Helpers on [`Auth`] for an app's tests (feature `test-util`): users and
//! sessions made directly, without signing in through a route.

use std::borrow::ToOwned;

use jiff::Timestamp;

use super::{Auth, Result};
use crate::core::password::hash_password_cheaply;
use crate::core::{Actor, new_session_id, session_expiry};
use crate::store::{Credential, Session, User};
use crate::types::NewUser;

impl Auth {
    /// Creates an active user who signs in with `password`, for a test.
    ///
    /// `new` is checked and normalized as [`create_user`](Auth::create_user)
    /// does, and the user is created as [`import_user`](Auth::import_user)
    /// does, with no actor, then given the password, which makes them
    /// active. It sends the same [`AuthEvent`](crate::core::AuthEvent)s and
    /// [`AuditEvent`](crate::core::AuditEvent)s (from
    /// [`Actor::System`](crate::core::Actor::System)) as those steps. The
    /// password is hashed at bcrypt's lowest cost, so it is quick to hash and
    /// to check with [`sign_in_password`](Auth::sign_in_password), and it is
    /// not checked against the password rules, so a test may use a short one.
    ///
    /// Never reach this from a request: like `import_user`, it has no actor.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "test-util")))]
    pub async fn test_user(&self, new: &NewUser, password: &str) -> Result<User> {
        let user = self.import_user(new).await?;
        let password = password.to_owned();
        let hash = tokio::task::spawn_blocking(move || hash_password_cheaply(&password)).await??;
        self.set_credential(Actor::System, user.id, &Credential::Password(hash), None)
            .await
    }

    /// Creates and stores a session for `user`, not impersonated, which
    /// lasts the usual [`SESSION_LIFETIME`](crate::core::SESSION_LIFETIME),
    /// for a test to act as `user` without signing in.
    ///
    /// Use it as the actor's session of an operation such as
    /// [`create_user`](Auth::create_user), or send it with a request through
    /// [`cookie_header`](Auth::cookie_header). It is created whatever the
    /// user's access: [`session`](Auth::session) and the extractors still
    /// refuse it when the user may not hold one, as for any session.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "test-util")))]
    pub async fn test_session(&self, user: &User) -> Result<Session> {
        let now = Timestamp::now();

        let session = Session {
            id: new_session_id(),
            user: user.id,
            impersonator: None,
            created_at: now,
            expires_at: session_expiry(now),
        };

        self.store().create_session(&session).await?;
        Ok(session)
    }
}
