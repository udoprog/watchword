//! Cloudflare Access sign-in on [`Auth`] (feature `cloudflare`).
//!
//! Access vouches for an email, which finds an existing user; users are never
//! created. Signing in mints an ordinary session, so Access is consulted only
//! when signing in. A pending user who signs in becomes active, and a revoked
//! user is refused.

#[cfg(test)]
use std::string::String;
#[cfg(test)]
use std::vec::Vec;

use http::HeaderMap;

use super::{Actor, AuditEvent, Auth, AuthBuilder, AuthEvent, Result, require_admin};
use crate::store::{Session, User};
use crate::types::{Access, AuthError, CloudflareConfig};

impl AuthBuilder {
    /// The Cloudflare Access settings to run with while the store has none,
    /// such as settings from the app's environment or its earlier storage.
    /// `None` and settings that are not `enabled` both turn Access sign-in
    /// off. The default is `None`.
    ///
    /// Settings saved with [`Auth::set_cloudflare`] are kept in the store
    /// and win over these from then on, across restarts.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "cloudflare")))]
    pub fn cloudflare(mut self, config: Option<CloudflareConfig>) -> Self {
        self.cloudflare = config;
        self
    }
}

impl Auth {
    /// The Cloudflare Access settings: those kept in the store, or those
    /// given to [`AuthBuilder::cloudflare`] while the store has none, or
    /// `None` when neither has any. They are what an admin's settings page
    /// shows, enabled or not.
    ///
    /// The store is read once, the first time the settings are needed, which
    /// is also when they are logged. To have them logged at startup, call
    /// this there.
    ///
    /// Errors only when the store fails.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "cloudflare")))]
    pub async fn cloudflare(&self) -> Result<Option<CloudflareConfig>> {
        let provider = &self.inner.cloudflare;
        provider.load(self.store()).await?;
        Ok(provider.settings())
    }

    /// Stores the Cloudflare Access settings, under the store's `cloudflare`
    /// setting, and applies them, such as when an admin saves them on the
    /// settings page. Returns them as stored, with the team domain and the
    /// audience trimmed.
    ///
    /// Settings that are not `enabled` turn Access sign-in off. Settings
    /// that differ from the current ones are logged, with a warning when
    /// they are unsafe or let no one sign in; the same settings again change
    /// nothing.
    ///
    /// Sends [`AuditEvent::CloudflareChanged`] when the settings differ from
    /// the current ones, naming an admin impersonating `actor` through
    /// `session`.
    ///
    /// Admins only: [`AuthError::Forbidden`] unless `actor` is an active
    /// admin. An app moving settings it kept itself onto watchword passes
    /// them to [`AuthBuilder::cloudflare`], where they apply until an admin
    /// saves settings here.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "cloudflare")))]
    pub async fn set_cloudflare(
        &self,
        actor: &User,
        session: &Session,
        config: CloudflareConfig,
    ) -> Result<CloudflareConfig> {
        require_admin(actor)?;
        let (before, config) = self.inner.cloudflare.save(self.store(), config).await?;
        tracing::info!(user = %actor.id, "Cloudflare Access settings saved");

        if before.as_ref() != Some(&config) {
            self.audit(AuditEvent::CloudflareChanged {
                actor: Actor::of(actor, session),
                before,
                after: config.clone(),
            });
        }

        Ok(config)
    }

    /// Whether the request carries Cloudflare Access credentials that sign in
    /// an existing, not revoked user, as
    /// [`sign_in_cloudflare`](Auth::sign_in_cloudflare) would. This is
    /// [`AuthConfig::cloudflare`](crate::AuthConfig::cloudflare).
    ///
    /// When the request carries Access credentials that do not, the reason
    /// is logged as a warning, at most once a minute.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "cloudflare")))]
    pub async fn cloudflare_available(&self, headers: &HeaderMap) -> Result<bool> {
        Ok(self.cloudflare_user(headers).await?.is_some())
    }

    /// Signs in the user whose email the request's Cloudflare Access
    /// credentials vouch for, whatever their [`Method`](crate::Method).
    ///
    /// A pending user becomes active, because Access has vouched for their
    /// email. Anything else that is not an active user, including a revoked
    /// user, an unknown email and Access being disabled, is
    /// [`AuthError::Unauthorized`], with the reason logged as for
    /// [`cloudflare_available`](Auth::cloudflare_available).
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "cloudflare")))]
    pub async fn sign_in_cloudflare(&self, headers: &HeaderMap) -> Result<(User, Session)> {
        let mut user = self
            .cloudflare_user(headers)
            .await?
            .ok_or(AuthError::Unauthorized)?;

        if user.access == Access::Pending {
            // Only a user who is still pending is activated, so a revocation
            // since the read above is not undone.
            let activated = self.store().activate(user.id).await?;

            user = self
                .store()
                .user(user.id)
                .await?
                .ok_or(AuthError::Unauthorized)?;

            if activated {
                tracing::info!(user = %user.id, "Cloudflare Access activated a pending user");
                self.emit(AuthEvent::UserChanged(user.info()));

                self.audit(AuditEvent::Activated {
                    actor: Actor::System,
                    user: user.info(),
                });
            }
        }

        if user.access != Access::Active {
            return Err(AuthError::Unauthorized.into());
        }

        let session = self.create_session(user.id).await?;
        Ok((user, session))
    }

    /// The user the request's Access credentials sign in: an existing user
    /// with the vouched-for email who is not revoked.
    async fn cloudflare_user(&self, headers: &HeaderMap) -> Result<Option<User>> {
        let provider = &self.inner.cloudflare;
        provider.load(self.store()).await?;

        let Some(email) = provider.email(headers).await else {
            return Ok(None);
        };

        let Some(user) = self.store().user_by_email(&email).await? else {
            provider.warn(format!(
                "Cloudflare Access sign-in failed: no user has the email {email}"
            ));
            return Ok(None);
        };

        if user.access == Access::Revoked {
            provider.warn(format!(
                "Cloudflare Access sign-in failed: the user with the email {email} has had their access revoked"
            ));
            return Ok(None);
        }

        Ok(Some(user))
    }

    /// The Cloudflare Access warnings logged within the last minute.
    #[cfg(test)]
    pub(crate) fn cloudflare_warnings(&self) -> Vec<String> {
        self.inner.cloudflare.warnings()
    }
}

#[cfg(test)]
mod tests;
