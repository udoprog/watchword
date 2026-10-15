//! Signing in with Google OAuth (the `google` feature).
//!
//! This is the OAuth authorization-code flow. Configure it with
//! [`AuthBuilder::google`](crate::AuthBuilder::google); the `axum08` feature
//! serves its routes:
//!
//! - `GET /api/auth/google` starts signing in.
//! - `GET /api/auth/google/register/{token}` starts registering, or resetting
//!   the credential, with a link.
//! - `GET /api/auth/google/link` starts switching the signed-in user to Google.
//! - `GET /api/auth/google/redirect` is where Google returns to, so the
//!   [`redirect_url`](GoogleConfig::redirect_url) registered with Google must
//!   have that path.
//!
//! Each started flow is remembered in memory, by its `state` parameter, for 10
//! minutes; at most 10 000 are kept, dropping the oldest. Google's answer is
//! checked with its `tokeninfo` endpoint, which must report the email as
//! verified. The account then signs in as the user it is bound to by its
//! subject, or, for a Google user who registered before subjects were
//! recorded, once by email. A Google account binds only one user.
//!
//! The callback redirects to `/` with the session cookie on success, and to
//! `/?error=user-not-found` (signing in with an account no user has) or
//! `/?error=auth-failed` (anything else) on failure; the reason is logged.

use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use lru::LruCache;
use serde::Deserialize;

pub use url::Url;

use crate::types::UserId;

#[cfg(all(feature = "axum08", any(test, feature = "test-util")))]
#[cfg_attr(
    watchword_docsrs,
    doc(cfg(all(feature = "axum08", feature = "test-util")))
)]
pub mod fake;

/// The path the callback is served at by the `axum08` routes, which the
/// [`redirect_url`](GoogleConfig::redirect_url) must have.
pub const REDIRECT_PATH: &str = "/api/auth/google/redirect";

/// How long a started flow may take to return from Google.
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);

/// The most flows kept pending at once. Starting one needs no authentication,
/// so past this the oldest is dropped.
const MAX_PENDING: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// The timeout of each request to Google.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The OAuth client registered with Google.
#[derive(Clone, PartialEq, Eq)]
pub struct GoogleConfig {
    /// The OAuth client id.
    pub client_id: String,
    /// The OAuth client secret.
    pub client_secret: String,
    /// The public URL Google redirects back to, as registered with Google,
    /// such as `https://example.com/api/auth/google/redirect`. Its path must
    /// be [`REDIRECT_PATH`].
    pub redirect_url: Url,
}

impl fmt::Debug for GoogleConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_url", &self.redirect_url.as_str())
            .finish()
    }
}

/// Google's OAuth endpoints. [`Endpoints::default`] is Google's own, which
/// is all an app uses in production; with the `test-util` feature,
/// [`AuthBuilder::google_endpoints`](crate::AuthBuilder::google_endpoints)
/// points the client elsewhere, such as at a [`fake::FakeGoogle`] (which
/// also needs `axum08`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// Where the browser is sent to sign in.
    pub auth: Url,
    /// Where the authorization code is exchanged for an access token.
    pub token: Url,
    /// Where the access token is checked for the account it grants.
    pub tokeninfo: Url,
}

impl Default for Endpoints {
    fn default() -> Self {
        let parse = |url| Url::parse(url).expect("Google's endpoints are valid URLs");

        Self {
            auth: parse("https://accounts.google.com/o/oauth2/v2/auth"),
            token: parse("https://www.googleapis.com/oauth2/v4/token"),
            tokeninfo: parse("https://www.googleapis.com/oauth2/v3/tokeninfo"),
        }
    }
}

/// What a started flow does once Google returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Flow {
    /// Sign in.
    SignIn,
    /// Register, or reset the credential, with the link `token`.
    Register { token: String },
    /// Switch the signed-in user to Google.
    Link { user: UserId },
}

/// Flows started but not yet returned from Google, keyed by their `state`
/// parameter.
///
/// Entries expire after a TTL and their number is bounded, since anyone can
/// start a flow.
pub(crate) struct PendingStates {
    ttl: Duration,
    // Entries are only ever inserted or removed, never touched, so the least
    // recently used entry is always the oldest.
    entries: LruCache<String, (Instant, Flow)>,
}

impl PendingStates {
    pub(crate) fn new(ttl: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            ttl,
            entries: LruCache::new(capacity),
        }
    }

    fn is_expired(&self, created: Instant, now: Instant) -> bool {
        now.saturating_duration_since(created) >= self.ttl
    }

    /// Records a newly started flow, dropping expired flows and, when full,
    /// the oldest one.
    pub(crate) fn insert(&mut self, state: String, flow: Flow, now: Instant) {
        while let Some((_, &(created, _))) = self.entries.peek_lru() {
            if !self.is_expired(created, now) {
                break;
            }

            self.entries.pop_lru();
        }

        self.entries.push(state, (now, flow));
    }

    /// Removes and returns the flow for `state`, unless it is unknown or has
    /// expired.
    pub(crate) fn take(&mut self, state: &str, now: Instant) -> Option<Flow> {
        let (created, flow) = self.entries.pop(state)?;

        if self.is_expired(created, now) {
            return None;
        }

        Some(flow)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The query Google redirects back with.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct Callback {
    pub(crate) code: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) error: Option<String>,
}

/// A Google account that Google vouched for.
#[derive(Debug)]
pub(crate) struct Account {
    /// The account's stable subject.
    pub(crate) sub: String,
    /// The account's verified email.
    pub(crate) email: String,
}

/// Why Google's answer could not be verified.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VerifyError {
    #[error("the {0} request failed")]
    Request(&'static str, #[source] reqwest::Error),
    #[error("the {0} response is malformed")]
    Malformed(&'static str, #[source] serde_json::Error),
    #[error("Google has not verified the email {0}")]
    Unverified(String),
    #[error("Google reported no subject for {0}")]
    NoSubject(String),
}

/// The configured Google client and its pending flows.
pub(crate) struct Provider {
    config: GoogleConfig,
    endpoints: Endpoints,
    http: reqwest::Client,
    pending: Mutex<PendingStates>,
}

impl Provider {
    pub(crate) fn new(config: GoogleConfig, endpoints: Endpoints) -> Self {
        if config.redirect_url.path() != REDIRECT_PATH {
            tracing::warn!(
                redirect_url = config.redirect_url.as_str(),
                "Google sign-in: the redirect URL's path is not {REDIRECT_PATH}, where the callback is served"
            );
        }

        tracing::info!(client_id = config.client_id, "Google sign-in enabled");

        Self {
            config,
            endpoints,
            http: reqwest::Client::new(),
            pending: Mutex::new(PendingStates::new(PENDING_TTL, MAX_PENDING)),
        }
    }

    /// Starts `flow`, returning the URL that sends the browser to Google.
    pub(crate) fn start(&self, flow: Flow) -> Url {
        let state = crate::core::new_token();
        let url = self.auth_url(&state);
        self.pending().insert(state, flow, Instant::now());
        url
    }

    /// The flow started with `state`, once.
    pub(crate) fn take(&self, state: &str) -> Option<Flow> {
        self.pending().take(state, Instant::now())
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, PendingStates> {
        // The states stay consistent whatever panicked while holding them.
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn auth_url(&self, state: &str) -> Url {
        let mut url = self.endpoints.auth.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", self.config.redirect_url.as_str())
            .append_pair("scope", "https://www.googleapis.com/auth/userinfo.email")
            .append_pair("state", state);
        url
    }

    /// Exchanges the authorization `code` and verifies the account it grants
    /// with `tokeninfo`, which must report a subject and a verified email.
    /// The email is returned lowercased.
    pub(crate) async fn verify(&self, code: &str) -> Result<Account, VerifyError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
        }

        #[derive(Deserialize)]
        struct TokenInfo {
            #[serde(default)]
            sub: String,
            email: String,
            email_verified: String,
        }

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("code", code)
            .append_pair("client_id", &self.config.client_id)
            .append_pair("client_secret", &self.config.client_secret)
            .append_pair("redirect_uri", self.config.redirect_url.as_str())
            .append_pair("grant_type", "authorization_code")
            .finish();

        let request = self
            .http
            .post(self.endpoints.token.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body);

        let token: TokenResponse = self.fetch("token exchange", request).await?;

        let mut url = self.endpoints.tokeninfo.clone();
        url.query_pairs_mut()
            .append_pair("access_token", &token.access_token);

        let info: TokenInfo = self.fetch("tokeninfo", self.http.get(url)).await?;

        if info.email_verified != "true" {
            return Err(VerifyError::Unverified(info.email));
        }

        if info.sub.is_empty() {
            return Err(VerifyError::NoSubject(info.email));
        }

        Ok(Account {
            sub: info.sub,
            email: info.email.to_lowercase(),
        })
    }

    async fn fetch<T>(
        &self,
        what: &'static str,
        request: reqwest::RequestBuilder,
    ) -> Result<T, VerifyError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let bytes = request
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| VerifyError::Request(what, e))?
            .bytes()
            .await
            .map_err(|e| VerifyError::Request(what, e))?;

        serde_json::from_slice(&bytes).map_err(|e| VerifyError::Malformed(what, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn states(capacity: usize) -> PendingStates {
        PendingStates::new(PENDING_TTL, NonZeroUsize::new(capacity).unwrap())
    }

    #[test]
    fn take_returns_pending_state_once() {
        let mut states = states(4);
        let now = Instant::now();

        states.insert("a".into(), Flow::SignIn, now);

        assert_eq!(
            states.take("a", now + Duration::from_secs(1)),
            Some(Flow::SignIn)
        );
        assert!(states.take("a", now + Duration::from_secs(1)).is_none());
        assert!(states.take("unknown", now).is_none());
    }

    #[test]
    fn take_rejects_expired_state() {
        let mut states = states(4);
        let now = Instant::now();

        states.insert("a".into(), Flow::SignIn, now);

        assert!(states.take("a", now + PENDING_TTL).is_none());
        assert_eq!(states.len(), 0);
    }

    #[test]
    fn insert_evicts_expired_states() {
        let mut states = states(16);
        let now = Instant::now();

        states.insert("old1".into(), Flow::SignIn, now);
        states.insert("old2".into(), Flow::SignIn, now + Duration::from_secs(60));
        states.insert("fresh".into(), Flow::SignIn, now + Duration::from_secs(120));

        // Past the TTL of the first two, but not of "fresh".
        let later = now + PENDING_TTL + Duration::from_secs(60);
        states.insert("new".into(), Flow::SignIn, later);

        assert_eq!(states.len(), 2);
        assert!(states.take("old1", later).is_none());
        assert!(states.take("old2", later).is_none());
        assert!(states.take("fresh", later).is_some());
        assert!(states.take("new", later).is_some());
    }

    #[test]
    fn insert_bounds_size_by_dropping_oldest() {
        let mut states = states(3);
        let now = Instant::now();

        for i in 0..10u64 {
            states.insert(format!("s{i}"), Flow::SignIn, now + Duration::from_secs(i));
        }

        assert_eq!(states.len(), 3);

        let at = now + Duration::from_secs(10);

        for i in 0..7 {
            assert!(states.take(&format!("s{i}"), at).is_none());
        }

        for i in 7..10 {
            assert!(states.take(&format!("s{i}"), at).is_some());
        }
    }

    #[test]
    fn auth_url_carries_the_client_and_state() {
        let provider = Provider::new(
            GoogleConfig {
                client_id: "client".to_owned(),
                client_secret: "secret".to_owned(),
                redirect_url: Url::parse("https://example.com/api/auth/google/redirect").unwrap(),
            },
            Endpoints::default(),
        );

        let url = provider.start(Flow::SignIn);
        assert_eq!(url.host_str(), Some("accounts.google.com"));

        let query = url.query_pairs().into_owned().collect::<Vec<_>>();
        let get = |key: &str| {
            query
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        };

        assert_eq!(get("response_type"), Some("code"));
        assert_eq!(get("client_id"), Some("client"));
        assert_eq!(
            get("redirect_uri"),
            Some("https://example.com/api/auth/google/redirect")
        );
        assert!(!query.iter().any(|(_, v)| v == "secret"));

        let state = get("state").unwrap();
        assert_eq!(provider.take(state), Some(Flow::SignIn));
        assert_eq!(provider.take(state), None);
    }

    #[test]
    fn debug_hides_the_secret() {
        let config = GoogleConfig {
            client_id: "client".to_owned(),
            client_secret: "secret".to_owned(),
            redirect_url: Url::parse("https://example.com/api/auth/google/redirect").unwrap(),
        };

        assert!(!format!("{config:?}").contains("\"secret\""));
    }
}
