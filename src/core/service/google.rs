//! Google OAuth sign-in on [`Auth`] (feature `google`).
//!
//! The flow itself is in [`crate::google`]; this starts it for each purpose
//! and completes it with the verified account through the service's Google
//! paths: signing in, registering with a link, and switching to Google.

// The flow is driven by the `axum` routes.
#![cfg_attr(not(feature = "axum"), allow(dead_code))]

use jiff::Timestamp;

use super::{Auth, AuthBuilder, Error, Result};
use crate::google::{Callback, Flow, GoogleConfig, Provider, Url};
use crate::store::{Session, User};
use crate::types::AuthError;

impl AuthBuilder {
    /// The Google OAuth client to sign in with, or `None` to offer no
    /// Google sign-in. The default is `None`.
    pub fn google(mut self, config: Option<GoogleConfig>) -> Self {
        self.google = config;
        self
    }

    /// Points the Google client at other endpoints, such as a
    /// [`FakeGoogle`](crate::google::fake::FakeGoogle), so an app can test
    /// signing in with Google offline (feature `test-util`). The default is
    /// Google's own, [`Endpoints::default`](crate::google::Endpoints).
    #[cfg(any(test, feature = "test-util"))]
    pub fn google_endpoints(mut self, endpoints: crate::google::Endpoints) -> Self {
        self.google_endpoints = endpoints;
        self
    }
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
    fn google_provider(&self) -> Result<&Provider> {
        Ok(self.inner.google.as_ref().ok_or(AuthError::NotFound)?)
    }

    /// Starts signing in with Google, returning where to send the browser.
    /// [`AuthError::NotFound`] when Google is not configured.
    pub(crate) fn google_sign_in(&self) -> Result<Url> {
        Ok(self.google_provider()?.start(Flow::SignIn))
    }

    /// Starts registering, or resetting the credential, with the link
    /// `token` and Google. Errors as [`register_info`](Auth::register_info)
    /// does, and with [`AuthError::NotFound`] when Google is not configured.
    pub(crate) async fn google_register(&self, token: &str) -> Result<Url> {
        let provider = self.google_provider()?;
        self.usable_token(token, Timestamp::now()).await?;

        Ok(provider.start(Flow::Register {
            token: token.to_owned(),
        }))
    }

    /// Starts switching the signed-in `user` to Google. Refused for a user
    /// who is not active, such as one being impersonated while pending.
    pub(crate) fn google_link(&self, user: &User) -> Result<Url> {
        let provider = self.google_provider()?;

        if user.access != crate::types::Access::Active {
            return Err(AuthError::Forbidden.into());
        }

        Ok(provider.start(Flow::Link { user: user.id }))
    }

    /// Completes a flow Google redirected back from, returning the user and
    /// their new session. Every failure is logged.
    ///
    /// Registering or switching to Google replaces the user's credential,
    /// which ends all of their earlier sessions; the session returned is
    /// new. That includes the one that started switching, which the
    /// callback cannot see: the `SameSite=Strict` cookie is not sent on
    /// the redirect from Google.
    pub(crate) async fn google_callback(
        &self,
        callback: &Callback,
    ) -> Result<(User, Session), GoogleFailure> {
        if let Some(error) = &callback.error {
            tracing::info!(error, "Google sign-in: Google returned an error");
            return Err(GoogleFailure::AuthFailed);
        }

        let (Some(code), Some(state)) = (&callback.code, &callback.state) else {
            tracing::info!("Google sign-in: the callback has no code or state");
            return Err(GoogleFailure::AuthFailed);
        };

        let Some(provider) = self.inner.google.as_ref() else {
            tracing::warn!("Google sign-in: a callback arrived, but Google is not configured");
            return Err(GoogleFailure::AuthFailed);
        };

        let Some(flow) = provider.take(state) else {
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
            Flow::SignIn => self.sign_in_google(sub, email).await,
            Flow::Register { token } => self.register_google(token, sub, email).await,
            Flow::Link { user } => match self.switch_to_google(*user, None, sub, email).await {
                Ok(user) => self
                    .create_session(user.id)
                    .await
                    .map(|session| (user, session)),
                Err(error) => Err(error),
            },
        };

        result.map_err(|error| {
            let failure = match (&flow, &error) {
                (Flow::SignIn, Error::Auth(AuthError::Unauthorized)) => GoogleFailure::UserNotFound,
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
        Flow::SignIn => "sign-in",
        Flow::Register { .. } => "register",
        Flow::Link { .. } => "link",
    }
}
