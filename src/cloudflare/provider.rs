//! The Cloudflare Access settings an [`Auth`](crate::Auth) runs with, which
//! it keeps in the store and an admin may change at runtime, and the warnings
//! it logs at most once a minute about credentials that did not sign anyone
//! in.

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
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

use super::{Access, Config, EMAIL_HEADER, HttpKeyFetcher, presents_access};
use crate::store::{DynStore, StoreError};
use crate::types::CloudflareConfig;

/// The store's setting that holds the Cloudflare Access settings, as JSON.
pub(crate) const SETTINGS_KEY: &str = "cloudflare";

/// How often the same warning may be logged, so a client retrying every few
/// seconds does not flood the log.
const WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Cloudflare Access as the [`Auth`](crate::Auth) service runs it.
pub(crate) struct Provider {
    /// The settings to run with while the store has none: those given to
    /// the builder.
    initial: Option<CloudflareConfig>,
    /// Set once the settings were read from the store.
    loaded: OnceCell<()>,
    /// Held while settings are stored and applied, so the store and the
    /// running settings agree when two admins save at once.
    saving: AsyncMutex<()>,
    /// Shared by every [`Access`] made as the settings change, and made only
    /// once Access is first enabled.
    http: OnceLock<reqwest::Client>,
    state: RwLock<State>,
    /// When each warning was last logged.
    warned: Mutex<HashMap<String, Instant>>,
}

#[derive(Default)]
struct State {
    /// The settings as stored or given, enabled or not.
    settings: Option<CloudflareConfig>,
    /// The settings when enabled, `None` when disabled.
    config: Option<CloudflareConfig>,
    access: Option<Arc<Access>>,
}

impl Provider {
    /// A provider that runs with `initial` until the store has settings of
    /// its own. Nothing is read or logged until [`load`](Self::load).
    pub(crate) fn new(initial: Option<CloudflareConfig>) -> Self {
        Self {
            initial,
            loaded: OnceCell::new(),
            saving: AsyncMutex::new(()),
            http: OnceLock::new(),
            state: RwLock::default(),
            warned: Mutex::default(),
        }
    }

    /// Reads the settings from the store the first time it is called, and
    /// logs them as they take effect. Stored settings win over the initial
    /// ones; settings that do not parse are logged as an error and the
    /// initial ones are used, so a damaged value does not break sign-in.
    /// A store failure is returned, and the next call tries again.
    pub(crate) async fn load(&self, store: &dyn DynStore) -> Result<(), StoreError> {
        self.loaded
            .get_or_try_init(|| async {
                let settings = match store.setting(SETTINGS_KEY).await? {
                    Some(stored) => match serde_json::from_str::<CloudflareConfig>(&stored) {
                        Ok(settings) => Some(settings),
                        Err(error) => {
                            tracing::error!(
                                "The stored Cloudflare Access settings are malformed, so the initial ones are used until an admin saves them again: {error}"
                            );
                            self.initial.clone()
                        }
                    },
                    None => self.initial.clone(),
                };

                let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);

                if let Some(settings) = settings {
                    self.apply(&mut state, settings);
                }

                Ok::<_, StoreError>(())
            })
            .await?;

        Ok(())
    }

    /// The settings as stored, or as given to the builder while the store
    /// has none. Call [`load`](Self::load) first.
    pub(crate) fn settings(&self) -> Option<CloudflareConfig> {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .settings
            .clone()
    }

    /// Stores `settings`, with the team domain and audience trimmed, and
    /// applies them, logging them if they changed. Returns the settings they
    /// replaced, as [`settings`](Self::settings) had them, and them as
    /// stored.
    pub(crate) async fn save(
        &self,
        store: &dyn DynStore,
        mut settings: CloudflareConfig,
    ) -> Result<(Option<CloudflareConfig>, CloudflareConfig), StoreError> {
        settings.team_domain = settings.team_domain.trim().to_owned();
        settings.audience = settings.audience.trim().to_owned();

        let json = serde_json::to_string(&settings)
            .map_err(|error| StoreError::new(format!("encoding the settings failed: {error}")))?;

        let _saving = self.saving.lock().await;
        // Loaded first, so a later first load cannot replace what is saved.
        self.load(store).await?;
        store.set_setting(SETTINGS_KEY, &json).await?;

        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        let before = state.settings.clone();
        self.apply(&mut state, settings.clone());
        Ok((before, settings))
    }

    /// Runs with `settings`, logging and rebuilding the verifier only when
    /// what is enabled changed, or on the first settings.
    fn apply(&self, state: &mut State, settings: CloudflareConfig) {
        let first = state.settings.is_none();
        let config = Some(settings.clone()).filter(|c| c.enabled);
        state.settings = Some(settings);

        if !first && state.config == config {
            return;
        }

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
