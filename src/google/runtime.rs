//! The Google client an [`Auth`](crate::Auth) runs with: one the app fixed
//! when it started, or one an admin keeps in the store and may change at
//! runtime.
//!
//! Changing the client replaces the [`Provider`] and with it the flows
//! pending on the old one, so a sign-in in progress at that moment fails
//! like an expired one and has to start again. A code Google issued to one
//! client cannot be exchanged by another anyway.

use std::borrow::ToOwned;
use std::boxed::Box;
use std::string::String;
use std::sync::{Arc, PoisonError, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex as AsyncMutex, OnceCell};

use super::{Endpoints, GoogleConfig, Provider, Url};
use crate::store::{DynStore, StoreError};
use crate::types::{GoogleSettings, GoogleSettingsUpdate};

/// The store's setting that holds the Google client, as JSON.
pub(crate) const SETTINGS_KEY: &str = "google";

/// The Google client as stored, secret included, so it has no `Debug`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct Stored {
    enabled: bool,
    client_id: String,
    client_secret: String,
    /// The public URL an admin set, used unless the app fixed one.
    public_url: Option<String>,
}

impl Stored {
    fn settings(&self, fixed: Option<&Url>) -> GoogleSettings {
        GoogleSettings {
            enabled: self.enabled,
            client_id: self.client_id.clone(),
            has_secret: !self.client_secret.is_empty(),
            fixed: false,
            public_url: match fixed {
                Some(url) => Some(url.as_str().to_owned()),
                None => self.public_url.clone(),
            },
            public_url_fixed: fixed.is_some(),
        }
    }
}

/// How the [`Auth`](crate::Auth) service gets its Google client.
pub(crate) enum Google {
    /// Given to [`AuthBuilder::google`](crate::AuthBuilder::google), which
    /// wins over anything stored.
    Fixed(Arc<Provider>),
    /// Kept in the store and set with
    /// [`Auth::set_google`](crate::Auth::set_google).
    Runtime(Box<Runtime>),
}

impl Google {
    pub(crate) fn fixed(config: GoogleConfig, endpoints: Endpoints) -> Self {
        Self::Fixed(Arc::new(Provider::new(config, endpoints)))
    }

    pub(crate) fn runtime(public_url: Option<Url>, endpoints: Endpoints) -> Self {
        Self::Runtime(Box::new(Runtime {
            public_url,
            endpoints,
            loaded: OnceCell::new(),
            saving: AsyncMutex::new(()),
            state: RwLock::default(),
        }))
    }

    /// The client to sign in with now, or `None` when Google sign-in is off.
    pub(crate) async fn provider(
        &self,
        store: &dyn DynStore,
    ) -> Result<Option<Arc<Provider>>, StoreError> {
        match self {
            Self::Fixed(provider) => Ok(Some(provider.clone())),
            Self::Runtime(runtime) => {
                runtime.load(store).await?;
                Ok(runtime.state().provider.clone())
            }
        }
    }

    pub(crate) async fn settings(
        &self,
        store: &dyn DynStore,
    ) -> Result<GoogleSettings, StoreError> {
        match self {
            Self::Fixed(provider) => {
                let config = provider.config();
                let mut public_url = config.redirect_url.clone();
                public_url.set_path("/");

                Ok(GoogleSettings {
                    enabled: true,
                    client_id: config.client_id.clone(),
                    has_secret: !config.client_secret.is_empty(),
                    fixed: true,
                    public_url: Some(public_url.as_str().to_owned()),
                    public_url_fixed: true,
                })
            }
            Self::Runtime(runtime) => {
                runtime.load(store).await?;
                Ok(runtime.settings(&runtime.state().stored))
            }
        }
    }
}

/// A Google client kept in the store.
pub(crate) struct Runtime {
    /// The app's public URL, which Google redirects back under, when the
    /// app fixed it; otherwise the stored one is used.
    public_url: Option<Url>,
    endpoints: Endpoints,
    /// Set once the client was read from the store.
    loaded: OnceCell<()>,
    /// Held while the client is stored and applied, so the store and the
    /// running client agree when two admins save at once.
    saving: AsyncMutex<()>,
    state: RwLock<State>,
}

#[derive(Default)]
struct State {
    stored: Stored,
    /// The client when enabled and complete.
    provider: Option<Arc<Provider>>,
}

impl Runtime {
    fn settings(&self, stored: &Stored) -> GoogleSettings {
        stored.settings(self.public_url.as_ref())
    }

    fn state(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reads the client from the store the first time it is called. One that
    /// does not parse is logged as an error and Google sign-in stays off
    /// until an admin saves it again. A store failure is returned, and the
    /// next call tries again.
    async fn load(&self, store: &dyn DynStore) -> Result<(), StoreError> {
        self.loaded
            .get_or_try_init(|| async {
                let stored = match store.setting(SETTINGS_KEY).await? {
                    Some(json) => serde_json::from_str::<Stored>(&json).unwrap_or_else(|error| {
                        tracing::error!(
                            "The stored Google sign-in settings are malformed, so Google sign-in is off until an admin saves them again: {error}"
                        );
                        Stored::default()
                    }),
                    None => Stored::default(),
                };

                let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
                self.apply(&mut state, stored, true);
                Ok::<_, StoreError>(())
            })
            .await?;

        Ok(())
    }

    /// Stores `update` and applies it, keeping the stored secret when it
    /// brings none. Returns the settings before and after, and whether the
    /// secret changed.
    pub(crate) async fn save(
        &self,
        store: &dyn DynStore,
        update: GoogleSettingsUpdate,
    ) -> Result<(GoogleSettings, GoogleSettings, bool), StoreError> {
        let _saving = self.saving.lock().await;
        // Loaded first, so a later first load cannot replace what is saved.
        self.load(store).await?;

        let before = self.state().stored.clone();

        let client_secret = match update.client_secret.as_deref().map(str::trim) {
            Some(secret) if !secret.is_empty() => secret.to_owned(),
            _ => before.client_secret.clone(),
        };

        let public_url = match update.public_url.as_deref().map(str::trim) {
            _ if self.public_url.is_some() => before.public_url.clone(),
            Some("") => None,
            Some(url) => Some(url.to_owned()),
            None => before.public_url.clone(),
        };

        let stored = Stored {
            enabled: update.enabled,
            client_id: update.client_id.trim().to_owned(),
            client_secret,
            public_url,
        };

        let json = serde_json::to_string(&stored)
            .map_err(|error| StoreError::new(format!("encoding the settings failed: {error}")))?;
        store.set_setting(SETTINGS_KEY, &json).await?;

        let secret_changed = stored.client_secret != before.client_secret;
        let after = self.settings(&stored);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        self.apply(&mut state, stored, false);
        Ok((self.settings(&before), after, secret_changed))
    }

    /// Runs with `stored`, replacing the client only when it changed, and
    /// logging what took effect.
    fn apply(&self, state: &mut State, stored: Stored, first: bool) {
        let public_url = match (&self.public_url, &stored.public_url) {
            (Some(url), _) => Some(Ok(url.clone())),
            (None, Some(url)) => Some(Url::parse(url)),
            (None, None) => None,
        };

        let config = match (stored.enabled, public_url) {
            (false, _) => None,
            (true, Some(Ok(public_url))) => {
                match GoogleConfig::new(
                    stored.client_id.clone(),
                    stored.client_secret.clone(),
                    &public_url,
                ) {
                    Ok(config) => Some(config),
                    Err(error) => {
                        tracing::warn!(
                            "Google sign-in is enabled, but no one can sign in through it: {error}"
                        );
                        None
                    }
                }
            }
            (true, Some(Err(error))) => {
                tracing::warn!(
                    "Google sign-in is enabled, but its public URL is not a URL, so no one can sign in through it: {error}"
                );
                None
            }
            (true, None) => {
                tracing::warn!(
                    "Google sign-in is enabled, but no public URL is set, so no one can sign in through it"
                );
                None
            }
        };

        state.stored = stored;

        let current = state.provider.as_ref().map(|provider| provider.config());

        if !first && current == config.as_ref() {
            return;
        }

        if current.is_some() {
            tracing::info!("Google sign-in changed, so sign-ins in progress must start again");
        }

        state.provider = match config {
            Some(config) => Some(Arc::new(Provider::new(config, self.endpoints.clone()))),
            None => {
                tracing::info!("Google sign-in is disabled");
                None
            }
        };
    }
}
