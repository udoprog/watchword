//! A fake Google for testing Google sign-in offline (features `test-util`
//! and `axum`).
//!
//! [`FakeGoogle::start`] serves the token and tokeninfo endpoints on a local
//! port; point the service at it with
//! [`AuthBuilder::google_endpoints`](crate::AuthBuilder::google_endpoints).
//! The test plays the browser: it starts a flow through the app's routes,
//! hands the URL the app redirected to to [`FakeGoogle::approve`] with the
//! Google account to sign in as, and calls the callback URL that returns.
//!
//! ```no_run
//! # async fn test() -> std::io::Result<()> {
//! use watchword::google::fake::{FakeAccount, FakeGoogle};
//! use watchword::google::{GoogleConfig, REDIRECT_PATH, Url};
//! use watchword::{Auth, MemoryStore, generate_session_key};
//!
//! let config = GoogleConfig {
//!     client_id: "client".to_owned(),
//!     client_secret: "secret".to_owned(),
//!     redirect_url: Url::parse(&format!("https://app.example{REDIRECT_PATH}")).unwrap(),
//! };
//!
//! let google = FakeGoogle::start(&config).await?;
//!
//! let auth = Auth::builder(MemoryStore::new(), generate_session_key())
//!     .google(Some(config))
//!     .google_endpoints(google.endpoints())
//!     .build();
//!
//! // GET /api/auth/google answers with a redirect to `location`; then:
//! # let location = google.endpoints().auth;
//! let callback = google.approve(&location, FakeAccount::new("sub-1", "alice@example.com"));
//! // GET `callback` (its path and query) on the app signs in as the account.
//! # Ok(()) }
//! ```
//!
//! Like Google, the fake checks the client id, secret and redirect URL of
//! each token exchange, and answers `400 Bad Request` to a wrong one, to an
//! unknown or already used code, and to an unknown access token. A code and
//! its access token are good once each.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use axum::Router;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;

use super::{Endpoints, GoogleConfig, Url};

/// The Google account a code from the fake grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeAccount {
    /// The account's stable subject.
    pub sub: String,
    /// The account's email, as Google reports it.
    pub email: String,
    /// Whether Google has verified the email. The service refuses an
    /// unverified one.
    pub email_verified: bool,
}

impl FakeAccount {
    /// An account with subject `sub` and the verified email `email`.
    pub fn new(sub: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            sub: sub.into(),
            email: email.into(),
            email_verified: true,
        }
    }

    /// The same account with its email unverified.
    pub fn unverified(self) -> Self {
        Self {
            email_verified: false,
            ..self
        }
    }
}

/// A local server standing in for Google; see the [module](self).
///
/// The server stops when this is dropped.
pub struct FakeGoogle {
    endpoints: Endpoints,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

struct Shared {
    config: GoogleConfig,
    /// Authorization codes not yet exchanged.
    codes: Mutex<HashMap<String, FakeAccount>>,
    /// Access tokens not yet checked.
    tokens: Mutex<HashMap<String, FakeAccount>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl FakeGoogle {
    /// Serves a fake Google on a free port of 127.0.0.1, for the OAuth
    /// client `config`. It must run inside a Tokio runtime.
    pub async fn start(config: &GoogleConfig) -> std::io::Result<Self> {
        let shared = Arc::new(Shared {
            config: config.clone(),
            codes: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
        });

        let app = Router::new()
            .route("/token", post(token))
            .route("/tokeninfo", get(tokeninfo))
            .with_state(shared.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;

        let task = tokio::spawn(async move {
            // Serving only ends with an I/O error on the listener, after
            // which the fake answers nothing and the test fails visibly.
            let _ = axum::serve(listener, app).await;
        });

        let url = |path: &str| {
            Url::parse(&format!("http://{address}{path}")).expect("a local URL is valid")
        };

        Ok(Self {
            endpoints: Endpoints {
                auth: url("/auth"),
                token: url("/token"),
                tokeninfo: url("/tokeninfo"),
            },
            shared,
            task,
        })
    }

    /// The fake's endpoints, for
    /// [`AuthBuilder::google_endpoints`](crate::AuthBuilder::google_endpoints).
    ///
    /// The `auth` endpoint is not served: [`approve`](Self::approve) and
    /// [`deny`](Self::deny) stand in for the browser visiting it.
    pub fn endpoints(&self) -> Endpoints {
        self.endpoints.clone()
    }

    /// A new authorization code that grants `account`, good for one token
    /// exchange.
    pub fn code(&self, account: FakeAccount) -> String {
        let code = crate::core::new_token();
        lock(&self.shared.codes).insert(code.clone(), account);
        code
    }

    /// Signs in at `auth_url`, where the app sent the browser, as `account`,
    /// returning the callback URL Google would redirect back to: the
    /// configured redirect URL with a new [`code`](Self::code) and the
    /// flow's `state`.
    ///
    /// # Panics
    ///
    /// If `auth_url` is not the fake's `auth` endpoint, or does not carry
    /// this client's id, redirect URL and a state.
    pub fn approve(&self, auth_url: &Url, account: FakeAccount) -> Url {
        let state = self.check_auth_url(auth_url);
        let code = self.code(account);
        self.callback(&[("code", &code), ("state", &state)])
    }

    /// Refuses to sign in at `auth_url`, as a user cancelling at Google
    /// does, returning the callback URL with `error=access_denied`.
    ///
    /// # Panics
    ///
    /// As [`approve`](Self::approve).
    pub fn deny(&self, auth_url: &Url) -> Url {
        let state = self.check_auth_url(auth_url);
        self.callback(&[("error", "access_denied"), ("state", &state)])
    }

    /// Checks `auth_url` as Google would, returning its state.
    fn check_auth_url(&self, auth_url: &Url) -> String {
        let mut base = auth_url.clone();
        base.set_query(None);
        assert_eq!(
            base, self.endpoints.auth,
            "the app did not redirect to the fake Google"
        );

        let query: HashMap<_, _> = auth_url.query_pairs().into_owned().collect();
        let get = |key: &str| query.get(key).map(String::as_str);

        let config = &self.shared.config;
        assert_eq!(get("response_type"), Some("code"));
        assert_eq!(get("client_id"), Some(config.client_id.as_str()));
        assert_eq!(get("redirect_uri"), Some(config.redirect_url.as_str()));

        get("state")
            .expect("the authorization URL carries a state")
            .to_owned()
    }

    fn callback(&self, pairs: &[(&str, &str)]) -> Url {
        let mut url = self.shared.config.redirect_url.clone();
        url.query_pairs_mut().extend_pairs(pairs);
        url
    }
}

impl Drop for FakeGoogle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Google's answer to a bad request.
fn bad_request(error: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(json!({ "error": error })),
    )
        .into_response()
}

async fn token(State(shared): State<Arc<Shared>>, body: String) -> Response {
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let get = |key: &str| form.get(key).map(String::as_str);
    let config = &shared.config;

    if get("grant_type") != Some("authorization_code") {
        return bad_request("unsupported_grant_type");
    }

    if get("client_id") != Some(config.client_id.as_str())
        || get("client_secret") != Some(config.client_secret.as_str())
    {
        return bad_request("invalid_client");
    }

    if get("redirect_uri") != Some(config.redirect_url.as_str()) {
        return bad_request("redirect_uri_mismatch");
    }

    let Some(account) = get("code").and_then(|code| lock(&shared.codes).remove(code)) else {
        return bad_request("invalid_grant");
    };

    let access_token = crate::core::new_token();
    lock(&shared.tokens).insert(access_token.clone(), account);

    axum::Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3599,
    }))
    .into_response()
}

async fn tokeninfo(
    State(shared): State<Arc<Shared>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let account = query
        .get("access_token")
        .and_then(|token| lock(&shared.tokens).remove(token));

    let Some(account) = account else {
        return bad_request("invalid_token");
    };

    // Google reports `email_verified` as a string.
    axum::Json(json!({
        "aud": shared.config.client_id,
        "sub": account.sub,
        "email": account.email,
        "email_verified": account.email_verified.to_string(),
    }))
    .into_response()
}
