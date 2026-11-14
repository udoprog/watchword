//! Google OAuth sign-in on [`Auth`] (feature `google`).
//!
//! The flow itself is in [`crate::google`]; this starts it for each purpose
//! and completes it with the verified account through the service's Google
//! paths: signing in, registering with a link, and switching to Google.

// The flow is driven by the `axum08` routes.
#![cfg_attr(not(feature = "axum08"), allow(dead_code))]

use std::borrow::ToOwned;
use std::string::String;
use std::sync::Arc;

use jiff::Timestamp;

use super::{Actor, AuditEvent, Auth, AuthBuilder, Error, Result, require_admin};
use crate::google::runtime::Google;
use crate::google::{Callback, Flow, GoogleConfig, Provider, Url};
use crate::is_same_origin_path;
use crate::store::{Session, User};
use crate::types::{AuthError, GoogleSettings, GoogleSettingsUpdate};

impl AuthBuilder {
    /// The Google OAuth client to sign in with, or `None` to offer no
    /// Google sign-in. The default is `None`.
    ///
    /// A client given here is fixed: it wins over any stored with
    /// [`Auth::set_google`], which refuses to change it, and
    /// [`Auth::google`] reports it as [`fixed`](GoogleSettings::fixed).
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "google")))]
    pub fn google(mut self, config: Option<GoogleConfig>) -> Self {
        self.google = config;
        self
    }

    /// Lets an admin set the Google OAuth client at runtime with
    /// [`Auth::set_google`], which keeps it in the store. Google redirects
    /// back under `public_url`, the URL the app is served at, as for
    /// [`GoogleConfig::new`]. Google sign-in is off until a client is set.
    /// Ignored when [`google`](Self::google) is given a client.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "google")))]
    pub fn google_public_url(mut self, public_url: Url) -> Self {
        self.google_public_url = Some(public_url);
        self
    }

    /// Lets an admin set both the Google OAuth client and the public URL at
    /// runtime with [`Auth::set_google`], so an app offers Google sign-in
    /// set up wholly from its settings page. Google sign-in is off until
    /// both are set. A URL given to
    /// [`google_public_url`](Self::google_public_url) is fixed and wins
    /// over a stored one; ignored when [`google`](Self::google) is given a
    /// client.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "google")))]
    pub fn google_at_runtime(mut self) -> Self {
        self.google_at_runtime = true;
        self
    }

    /// Points the Google client at other endpoints, such as a
    /// [`FakeGoogle`](crate::google::fake::FakeGoogle), so an app can test
    /// signing in with Google offline (features `test-util` and `google`).
    /// The default is Google's own,
    /// [`Endpoints::default`](crate::google::Endpoints).
    #[cfg(any(test, feature = "test-util"))]
    #[cfg_attr(
        watchword_docsrs,
        doc(cfg(all(feature = "google", feature = "test-util")))
    )]
    pub fn google_endpoints(mut self, endpoints: crate::google::Endpoints) -> Self {
        self.google_endpoints = endpoints;
        self
    }
}

/// What a Google callback came to.
#[derive(Debug)]
pub(crate) struct GoogleReturn {
    /// Where the sign-in it completes was to come back to: a path on this
    /// origin, encoded to be sent as a `Location`.
    pub(crate) next: Option<String>,
    /// The user and their new session, or why it failed.
    pub(crate) result: Result<(User, Session), GoogleFailure>,
}

/// Why a Google callback failed, as the `?error=` code it redirects with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GoogleFailure {
    /// No user can sign in with the account.
    UserNotFound,
    /// Anything else.
    AuthFailed,
}

impl GoogleFailure {
    /// The `?error=` code the sign-in page shows a message for.
    pub(crate) fn code(self) -> &'static str {
        match self {
            GoogleFailure::UserNotFound => "user-not-found",
            GoogleFailure::AuthFailed => "auth-failed",
        }
    }
}

impl Auth {
    /// The Google sign-in settings, or `None` when Google sign-in is neither
    /// given to [`AuthBuilder::google`] nor may be set at runtime (see
    /// [`AuthBuilder::google_public_url`] and
    /// [`AuthBuilder::google_at_runtime`]). The client secret is never
    /// returned, only whether one is set.
    ///
    /// Errors only when the store fails.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "google")))]
    pub async fn google(&self) -> Result<Option<GoogleSettings>> {
        let Some(google) = &self.inner.google else {
            return Ok(None);
        };

        Ok(Some(google.settings(self.store()).await?))
    }

    /// Stores the Google sign-in settings, under the store's `google`
    /// setting, and applies them at once. Returns them as
    /// [`google`](Auth::google) does. A missing or empty secret keeps the
    /// stored one, and so does a missing public URL; an empty one clears
    /// it, and one the app fixed is not changed. Settings that are enabled
    /// but lack a client id, a secret or a usable public URL leave Google
    /// sign-in off, with a warning logged.
    ///
    /// Changing the client ends the Google sign-ins in progress, which have
    /// to start again.
    ///
    /// Sends [`AuditEvent::GoogleChanged`] when the settings or the secret
    /// changed, naming an admin impersonating `actor` through `session`.
    ///
    /// Admins only: [`AuthError::Forbidden`] unless `actor` is an active
    /// admin, and also when the client is fixed with
    /// [`AuthBuilder::google`]. [`AuthError::NotFound`] when Google sign-in
    /// may not be set at runtime.
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "google")))]
    pub async fn set_google(
        &self,
        actor: &User,
        session: &Session,
        update: GoogleSettingsUpdate,
    ) -> Result<GoogleSettings> {
        require_admin(actor)?;

        let runtime = match &self.inner.google {
            Some(Google::Runtime(runtime)) => runtime,
            Some(Google::Fixed(_)) => return Err(AuthError::Forbidden.into()),
            None => return Err(AuthError::NotFound.into()),
        };

        let (before, after, secret_changed) = runtime.save(self.store(), update).await?;
        tracing::info!(user = %actor.id, "Google sign-in settings saved");

        if before != after || secret_changed {
            self.audit(AuditEvent::GoogleChanged {
                actor: Actor::of(actor, session),
                before,
                after: after.clone(),
                secret_changed,
            });
        }

        Ok(after)
    }

    /// The client to sign in with now, or `None` when Google sign-in is off.
    pub(crate) async fn google_provider(&self) -> Result<Option<Arc<Provider>>> {
        match &self.inner.google {
            Some(google) => Ok(google.provider(self.store()).await?),
            None => Ok(None),
        }
    }

    async fn google_client(&self) -> Result<Arc<Provider>> {
        Ok(self.google_provider().await?.ok_or(AuthError::NotFound)?)
    }

    /// Starts signing in with Google, returning where to send the browser.
    /// Once signed in, the browser comes back to `next` when it is a path on
    /// this origin (see [`is_same_origin_path`]); any other `next` is
    /// ignored. [`AuthError::NotFound`] when Google is not configured.
    pub(crate) async fn google_sign_in(&self, next: Option<&str>) -> Result<Url> {
        let provider = self.google_client().await?;
        let next = next.filter(|next| is_same_origin_path(next)).map(location);
        Ok(provider.start(Flow::SignIn { next }))
    }

    /// Starts registering, or resetting the credential, with the link
    /// `token` and Google. Errors as [`register_info`](Auth::register_info)
    /// does, and with [`AuthError::NotFound`] when Google is not configured.
    pub(crate) async fn google_register(&self, token: &str) -> Result<Url> {
        let provider = self.google_client().await?;
        self.usable_token(token, Timestamp::now()).await?;

        Ok(provider.start(Flow::Register {
            token: token.to_owned(),
        }))
    }

    /// Starts switching the `user` signed in with `session` to Google.
    /// Refused for a user who is not active, such as one being impersonated
    /// while pending.
    pub(crate) async fn google_link(&self, user: &User, session: &Session) -> Result<Url> {
        let provider = self.google_client().await?;

        if user.access != crate::types::Access::Active {
            return Err(AuthError::Forbidden.into());
        }

        Ok(provider.start(Flow::Link {
            user: user.id,
            impersonator: session.impersonator,
        }))
    }

    /// Completes a flow Google redirected back from, returning the user and
    /// their new session, and where a sign-in was to come back to (whether
    /// it succeeded or not). Every failure is logged.
    ///
    /// Registering or switching to Google replaces the user's credential,
    /// which ends all of their earlier sessions; the session returned is
    /// new. That includes the one that started switching, which the
    /// callback cannot see: the `SameSite=Strict` cookie is not sent on
    /// the redirect from Google.
    pub(crate) async fn google_callback(&self, callback: &Callback) -> GoogleReturn {
        let provider = match self.google_provider().await {
            Ok(Some(provider)) => provider,
            Ok(None) => {
                tracing::warn!("Google sign-in: a callback arrived, but Google is not configured");
                return GoogleReturn {
                    next: None,
                    result: Err(GoogleFailure::AuthFailed),
                };
            }
            Err(error) => {
                tracing::error!(
                    error = &error as &dyn std::error::Error,
                    "Google sign-in failed"
                );
                return GoogleReturn {
                    next: None,
                    result: Err(GoogleFailure::AuthFailed),
                };
            }
        };

        // Taken first, so the state is used up whatever Google answered, and
        // a sign-in that failed still knows where it was to come back to.
        let flow = callback
            .state
            .as_deref()
            .and_then(|state| provider.take(state));

        let next = match &flow {
            Some(Flow::SignIn { next }) => next.clone(),
            _ => None,
        };

        let result = self.complete_google(&provider, callback, flow).await;
        GoogleReturn { next, result }
    }

    async fn complete_google(
        &self,
        provider: &Provider,
        callback: &Callback,
        flow: Option<Flow>,
    ) -> Result<(User, Session), GoogleFailure> {
        if let Some(error) = &callback.error {
            tracing::info!(error, "Google sign-in: Google returned an error");
            return Err(GoogleFailure::AuthFailed);
        }

        let (Some(code), Some(_)) = (&callback.code, &callback.state) else {
            tracing::info!("Google sign-in: the callback has no code or state");
            return Err(GoogleFailure::AuthFailed);
        };

        let Some(flow) = flow else {
            tracing::info!("Google sign-in: unknown, expired or replayed state");
            return Err(GoogleFailure::AuthFailed);
        };

        let account = match provider.verify(code).await {
            Ok(account) => account,
            Err(error) => {
                tracing::warn!(
                    error = &error as &dyn std::error::Error,
                    "Google sign-in failed"
                );
                return Err(GoogleFailure::AuthFailed);
            }
        };

        let (sub, email) = (&account.sub, &account.email);

        let result = match &flow {
            Flow::SignIn { .. } => self.sign_in_google(sub, email).await,
            Flow::Register { token } => self.register_google(token, sub, email).await,
            Flow::Link { user, impersonator } => match self
                .switch_to_google(*user, *impersonator, None, sub, email)
                .await
            {
                Ok(user) => self
                    .create_session(user.id)
                    .await
                    .map(|session| (user, session)),
                Err(error) => Err(error),
            },
        };

        result.map_err(|error| {
            let failure = match (&flow, &error) {
                (Flow::SignIn { .. }, Error::Auth(AuthError::Unauthorized)) => {
                    GoogleFailure::UserNotFound
                }
                _ => GoogleFailure::AuthFailed,
            };

            match error.auth_error() {
                Some(refused) => tracing::info!(
                    email,
                    flow = flow_name(&flow),
                    error = %refused,
                    "Google sign-in refused"
                ),
                None => tracing::error!(
                    email,
                    flow = flow_name(&flow),
                    error = &error as &dyn std::error::Error,
                    "Google sign-in failed"
                ),
            }

            failure
        })
    }
}

/// The flow's purpose, for logs; a link's token is a credential.
fn flow_name(flow: &Flow) -> &'static str {
    match flow {
        Flow::SignIn { .. } => "sign-in",
        Flow::Register { .. } => "register",
        Flow::Link { .. } => "link",
    }
}

/// `next`, a path on this origin, as a `Location` header value: the bytes
/// that cannot be sent in a URL as they are (spaces, non-ASCII) are
/// percent-encoded, and everything else is kept, so its meaning is
/// unchanged. Nothing is normalized, since resolving `/.//host` to `//host`
/// would name another host.
fn location(next: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut out = String::with_capacity(next.len());

    for &b in next.as_bytes() {
        if b.is_ascii_graphic()
            && !matches!(b, b'"' | b'<' | b'>' | b'`' | b'{' | b'|' | b'}' | b'^')
        {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0xf)]));
        }
    }

    out
}

#[cfg(test)]
mod tests;
