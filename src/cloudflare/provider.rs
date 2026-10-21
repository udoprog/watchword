//! The Cloudflare Access settings an [`Auth`](crate::Auth) runs with, which
//! the app may change at runtime, and the warnings it logs at most once a
//! minute about credentials that did not sign anyone in.

use std::borrow::ToOwned;
use std::collections::HashMap;
use std::error::Error as StdError;
use std::string::String;
use std::string::ToString;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant};
#[cfg(test)]
use std::vec::Vec;

use http::HeaderMap;

use super::{Access, Config, EMAIL_HEADER, HttpKeyFetcher, presents_access};
use crate::types::CloudflareConfig;

/// How often the same warning may be logged, so a client retrying every few
/// seconds does not flood the log.
const WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Cloudflare Access as the [`Auth`](crate::Auth) service runs it.
pub(crate) struct Provider {
    /// Shared by every [`Access`] made as the settings change, and made only
    /// once Access is first enabled.
    http: OnceLock<reqwest::Client>,
    state: RwLock<State>,
    /// When each warning was last logged.
    warned: Mutex<HashMap<String, Instant>>,
}

#[derive(Default)]
struct State {
    /// The settings when enabled, `None` when disabled.
    config: Option<CloudflareConfig>,
    access: Option<Arc<Access>>,
}

impl Provider {
    /// A provider with the initial settings, which are logged when given.
    /// `None` and disabled settings both turn it off.
    pub(crate) fn new(config: Option<CloudflareConfig>) -> Self {
        let provider = Self {
            http: OnceLock::new(),
            state: RwLock::default(),
            warned: Mutex::default(),
        };

        if let Some(config) = config {
            let mut state = provider
                .state
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            provider.apply(&mut state, Some(config).filter(|c| c.enabled));
        }

        provider
    }

    /// Applies new settings, logging them if they changed.
    pub(crate) fn set(&self, config: Option<CloudflareConfig>) {
        let config = config.filter(|c| c.enabled);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);

        if state.config != config {
            self.apply(&mut state, config);
        }
    }

    fn apply(&self, state: &mut State, config: Option<CloudflareConfig>) {
        log_settings(config.as_ref());

        state.access = config.as_ref().map(|config| {
            let http = self.http.get_or_init(reqwest::Client::new).clone();

            Arc::new(Access::with_fetcher(
                Config {
                    team_domain: config.team_domain.trim().to_owned(),
                    audience: config.audience.trim().to_owned(),
                    trust_email_header: config.trust_email_header,
                    verify_jwt: config.verify_jwt,
                },
                HttpKeyFetcher::new(http),
            ))
        });

        state.config = config;
    }

    /// The normalized email that Access vouches for in `headers`, if any.
    ///
    /// When the request carries Access credentials that are not accepted,
    /// the reason is logged as a warning. A request without any is simply
    /// signed out, which is not worth one.
    pub(crate) async fn email(&self, headers: &HeaderMap) -> Option<String> {
        let access = self
            .state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .access
            .clone();

        let presented = presents_access(headers);

        let Some(access) = access else {
            if presented {
                self.warn("Cloudflare Access sign-in is disabled, so the Access credentials on this request were ignored".to_owned());
            }

            return None;
        };

        match access.email(headers).await {
            Ok(email) => Some(email),
            Err(error) if presented => {
                self.warn(format!(
                    "Cloudflare Access sign-in failed: {}",
                    chain(&error)
                ));
                None
            }
            Err(error) => {
                tracing::debug!(%error, "Cloudflare Access did not identify the request");
                None
            }
        }
    }

    /// Logs a warning unless the same one was logged within the last minute.
    pub(crate) fn warn(&self, message: String) {
        let now = Instant::now();
        let mut warned = self.warned.lock().unwrap_or_else(PoisonError::into_inner);
        warned.retain(|_, at| now.duration_since(*at) < WARN_INTERVAL);

        if warned.contains_key(&message) {
            return;
        }

        tracing::warn!("{message}");
        warned.insert(message, now);
    }

    /// The warnings logged within the last minute.
    #[cfg(test)]
    pub(crate) fn warnings(&self) -> Vec<String> {
        let warned = self.warned.lock().unwrap_or_else(PoisonError::into_inner);
        warned.keys().cloned().collect()
    }
}

/// Logs the settings as they take effect, and warns about settings that are
/// unsafe or let no one sign in.
fn log_settings(config: Option<&CloudflareConfig>) {
    let Some(config) = config else {
        tracing::info!("Cloudflare Access sign-in is disabled");
        return;
    };

    if !config.verify_jwt {
        if config.trust_email_header {
            tracing::warn!(
                "SECURITY: Cloudflare Access sign-in trusts the {EMAIL_HEADER} header without verifying the Access token, so anyone who can reach this server without going through Cloudflare can sign in as any user by sending that header. Turn on Verify token unless the server is only reachable through Cloudflare."
            );
        } else {
            tracing::warn!(
                "Cloudflare Access sign-in is enabled, but neither Verify token nor Trust email header is, so no one can sign in through it"
            );
        }

        return;
    }

    if config.team_domain.trim().is_empty() || config.audience.trim().is_empty() {
        tracing::warn!(
            "Cloudflare Access sign-in is enabled, but its team domain or audience is empty, so no one can sign in through it"
        );
        return;
    }

    tracing::info!(
        team_domain = config.team_domain.trim(),
        verify_jwt = config.verify_jwt,
        trust_email_header = config.trust_email_header,
        "Cloudflare Access sign-in is enabled"
    );
}

/// An error with its causes, such as why the signing keys could not be
/// fetched.
fn chain(error: &dyn StdError) -> String {
    let mut out = error.to_string();
    let mut source = error.source();

    while let Some(error) = source {
        out.push_str(": ");
        out.push_str(&error.to_string());
        source = error.source();
    }

    out
}
