use std::borrow::Cow;
use std::borrow::ToOwned;
use std::boxed::Box;
use std::error::Error as StdError;
use std::fmt;
use std::net::IpAddr;
use std::string::String;
use std::string::ToString;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use std::vec::Vec;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cookie::{Cookie, SameSite};
use http::{HeaderMap, HeaderValue, header};
use jiff::Timestamp;
use tokio::sync::broadcast;
use tokio::time::MissedTickBehavior;

use super::throttle::LoginThrottle;
use super::{
    Actor, AuditEvent, PasswordError, TOKEN_LIFETIME, dummy_hash, generate_session_key,
    hash_password, is_expired, new_session_id, new_token, session_cookie, session_expiry,
    token_expiry, verify_password, verify_session_cookie,
};
use crate::store::{Credential, DynStore, Session, Store, StoreError, Token, TokenKind, User};
use crate::types::{
    Access, AuthError, Conflict, Impersonator, Invalid, Link, LoginRequest, Method, NewUser,
    PasswordChange, RegisterInfo, RegisterRequest, Role, UserChange, UserEntry, UserId, UserInfo,
    normalize_email, validate_password,
};

/// The setting [`load_or_create_key`] keeps the cookie key under.
const SESSION_KEY: &str = "session_key";

/// How many [`AuthEvent`]s a slow receiver may fall behind before it lags.
const EVENT_CAPACITY: usize = 256;

/// A hook added with [`AuthBuilder::audit`].
type AuditHook = Box<dyn Fn(&AuditEvent) + Send + Sync>;

/// When the session cookie is limited to HTTPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Secure {
    /// When the request reached the proxy in front of the server over HTTPS,
    /// as its `X-Forwarded-Proto` header says.
    #[default]
    Auto,
    /// Always.
    Always,
    /// Never.
    Never,
}

/// The session cookie's name and `Secure` flag. Its other attributes are
/// fixed: `HttpOnly`, `SameSite=Strict`, `Path=/` and a 30-day `Max-Age`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieConfig {
    /// The cookie's name, such as `track_session`.
    pub name: Cow<'static, str>,
    /// When the cookie is limited to HTTPS.
    pub secure: Secure,
}

impl CookieConfig {
    /// A cookie named `name`, with [`Secure::Auto`].
    pub fn new(name: impl Into<Cow<'static, str>>) -> Self {
        Self {
            name: name.into(),
            secure: Secure::Auto,
        }
    }
}

impl Default for CookieConfig {
    /// A cookie named `session`, with [`Secure::Auto`].
    fn default() -> Self {
        Self::new("session")
    }
}

/// Sent whenever auth state changes, for open sockets and live admin views.
/// Receive them with [`Auth::events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthEvent {
    /// The session with this id ended: signed out.
    SessionEnded(String),
    /// The user's sessions ended, except `keep`: signed out everywhere,
    /// revoked, deleted, or their credential changed.
    UserSessionsEnded {
        /// The user.
        user: UserId,
        /// The session that stays, if any.
        keep: Option<String>,
    },
    /// The user's role, email, login, access or credential changed. When
    /// the user is no longer an active admin, the sessions in which they
    /// impersonate someone ([`Session::impersonator`]) have ended.
    UserChanged(UserInfo),
    /// A user was created.
    UserCreated(UserInfo),
    /// The user was deleted, with their sessions and the sessions in which
    /// they impersonate someone.
    UserDeleted(UserId),
}

/// The error of an [`Auth`] operation: either an [`AuthError`] to answer
/// the request with, or an internal failure.
///
/// Classify one with [`auth_error`](Error::auth_error). Once it has passed
/// through `?` into an app's own error, such as an `anyhow::Error`, use
/// [`find_auth_error`](Error::find_auth_error) on that error rather than
/// downcasting it to [`AuthError`], which misses a refusal wrapped as
/// [`Error::Auth`] and so answers a `Forbidden` as an internal failure.
///
/// An internal failure's message carries its cause, such as `storage failed:
/// database is locked`, so logging it with `{error}` says what went wrong.
/// Its [`source`](StdError::source) continues below that cause, so
/// a chain printer such as `anyhow`'s `{:#}` does not repeat it. The message
/// is for logs: answer the client with something generic, as the `axum08`
/// integration and the musliweb05 `Connection` do.
#[derive(Debug)]
pub enum Error {
    /// The request is refused, as the [`AuthError`] says.
    Auth(AuthError),
    /// The store failed.
    Store(StoreError),
    /// Hashing a password failed.
    Password(PasswordError),
    /// A blocking task, such as hashing, panicked or was cancelled.
    Task(tokio::task::JoinError),
}

impl Error {
    /// The [`AuthError`] to answer with, or `None` for an internal failure.
    ///
    /// This is how to tell a refusal, which the client should see, from an
    /// internal failure, which it should not.
    pub fn auth_error(&self) -> Option<&AuthError> {
        match self {
            Error::Auth(error) => Some(error),
            _ => None,
        }
    }

    /// The [`AuthError`] somewhere in `error`'s chain of
    /// [`source`](StdError::source)s, whether bare or as an [`Error::Auth`],
    /// or `None` when the chain holds no refusal.
    ///
    /// For an app's own error that a watchword [`Error`] reached through
    /// `?`. With `anyhow`, pass `&*error`; an app error type that wraps
    /// [`Error`] has to name it as its [`source`](StdError::source).
    ///
    /// ```
    /// use watchword::AuthError;
    /// use watchword::core::Error;
    ///
    /// #[derive(Debug)]
    /// struct AppError(Error);
    ///
    /// impl std::fmt::Display for AppError {
    ///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    ///         f.write_str("the request failed")
    ///     }
    /// }
    ///
    /// impl std::error::Error for AppError {
    ///     fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    ///         Some(&self.0)
    ///     }
    /// }
    ///
    /// let error = AppError(Error::from(AuthError::Forbidden));
    /// assert_eq!(Error::find_auth_error(&error), Some(&AuthError::Forbidden));
    ///
    /// let error = AppError(Error::from(watchword::store::StoreError::new("disk full")));
    /// assert_eq!(Error::find_auth_error(&error), None);
    /// ```
    pub fn find_auth_error<'a>(mut error: &'a (dyn StdError + 'static)) -> Option<&'a AuthError> {
        loop {
            if let Some(error) = error.downcast_ref::<Error>() {
                return error.auth_error();
            }

            if let Some(error) = error.downcast_ref::<AuthError>() {
                return Some(error);
            }

            error = error.source()?;
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Auth(error) => error.fmt(f),
            Error::Store(error) => write!(f, "storage failed: {error}"),
            Error::Password(error) => error.fmt(f),
            Error::Task(error) => write!(f, "a blocking task failed: {error}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        // Each message already includes the wrapped error's, so the chain
        // continues with what is below it.
        match self {
            Error::Auth(error) => error.source(),
            Error::Store(error) => error.source(),
            Error::Password(error) => error.source(),
            Error::Task(error) => error.source(),
        }
    }
}

impl From<AuthError> for Error {
    fn from(error: AuthError) -> Self {
        Error::Auth(error)
    }
}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Error::Store(error)
    }
}

impl From<PasswordError> for Error {
    fn from(error: PasswordError) -> Self {
        Error::Password(error)
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(error: tokio::task::JoinError) -> Self {
        Error::Task(error)
    }
}

/// The result of an [`Auth`] operation.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Loads the key that signs session cookies from the store's `session_key`
/// setting, generating and storing one on first use.
///
/// Reads the key as standard padded base64 or unpadded base64url, so keys
/// stored in either encoding keep their existing sessions; a new key is
/// stored as standard base64.
pub async fn load_or_create_key<S>(store: &S) -> Result<[u8; 32], StoreError>
where
    S: Store,
{
    if let Some(stored) = store.config_get(SESSION_KEY).await? {
        let stored = stored.trim();

        let bytes = STANDARD
            .decode(stored)
            .or_else(|_| URL_SAFE_NO_PAD.decode(stored))
            .map_err(|_| StoreError::new("the stored session key is not base64"))?;

        return <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| StoreError::new("the stored session key is not 32 bytes"));
    }

    let key = generate_session_key();
    store.config_set(SESSION_KEY, &STANDARD.encode(key)).await?;
    Ok(key)
}

/// Builds an [`Auth`]; see [`Auth::builder`] and
/// [`Auth::builder_from_store`].
pub struct AuthBuilder {
    store: Box<dyn DynStore>,
    key: [u8; 32],
    cookie: CookieConfig,
    logins: bool,
    trusted_proxies: Vec<IpAddr>,
    impersonation: bool,
    prune_every: Option<Duration>,
    audit: Vec<AuditHook>,
    #[cfg(feature = "cloudflare")]
    cloudflare: Option<crate::types::CloudflareConfig>,
    #[cfg(feature = "google")]
    google: Option<crate::google::GoogleConfig>,
    #[cfg(feature = "google")]
    google_endpoints: crate::google::Endpoints,
}

impl AuthBuilder {
    /// The session cookie's name and `Secure` flag. The default is
    /// [`CookieConfig::default`].
    pub fn cookie(mut self, cookie: CookieConfig) -> Self {
        self.cookie = cookie;
        self
    }

    /// Whether users have login names or only emails.
    /// With `false`, every user needs an email, login names cannot be set,
    /// and password sign-in looks users up by email only. The default is
    /// `true`.
    pub fn logins(mut self, logins: bool) -> Self {
        self.logins = logins;
        self
    }

    /// Peers whose `CF-Connecting-IP` and `X-Forwarded-For` headers are
    /// believed when throttling sign-ins. The default is none.
    pub fn trusted_proxies(mut self, proxies: &[IpAddr]) -> Self {
        self.trusted_proxies = proxies.to_vec();
        self
    }

    /// Whether admins may impersonate other users. The default is `false`.
    pub fn impersonation(mut self, impersonation: bool) -> Self {
        self.impersonation = impersonation;
        self
    }

    /// Runs [`Auth::prune`] at [`build`](AuthBuilder::build) and then
    /// every `period`, on a task that ends once every clone of the
    /// [`Auth`] is dropped, logging a failure at `warn`. The default is
    /// `None`: nothing is pruned except by calling [`Auth::prune`].
    ///
    /// With `Some`, [`build`](AuthBuilder::build) must be called within a
    /// Tokio runtime.
    ///
    /// ```
    /// use std::time::Duration;
    /// use watchword::{Auth, MemoryStore};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let auth = Auth::builder_from_store(MemoryStore::new())
    ///     .await?
    ///     .prune_every(Some(Duration::from_secs(60 * 60)))
    ///     .build();
    /// # Ok(()) }
    /// ```
    ///
    /// # Panics
    ///
    /// If `period` is zero.
    pub fn prune_every(mut self, period: Option<Duration>) -> Self {
        assert!(
            period != Some(Duration::ZERO),
            "the prune period must be non-zero"
        );
        self.prune_every = period;
        self
    }

    /// Calls `hook` with an [`AuditEvent`] for each operation that changes
    /// a user, their links or their sessions on someone's behalf, saying who
    /// acted, for an app's audit log. Calling it again adds another hook.
    ///
    /// The hook runs synchronously, after the change is stored and before
    /// the operation returns, so no event is missed, unlike a slow
    /// [`events`](Auth::events) receiver, which lags. It must not block: to
    /// write to a database, send the event on to a task, such as through an
    /// unbounded channel.
    ///
    /// ```
    /// use watchword::{AuditEvent, Auth, MemoryStore};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AuditEvent>();
    ///
    /// let auth = Auth::builder_from_store(MemoryStore::new())
    ///     .await?
    ///     .audit(move |event| {
    ///         // The receiver is gone only when the app is shutting down.
    ///         let _ = tx.send(event.clone());
    ///     })
    ///     .build();
    ///
    /// tokio::spawn(async move {
    ///     while let Some(event) = rx.recv().await {
    ///         // Write `event.actor()`, `event.user()` and the event to the log.
    ///         # let _ = event;
    ///     }
    /// });
    /// # let _ = auth;
    /// # Ok(()) }
    /// ```
    pub fn audit<F>(mut self, hook: F) -> Self
    where
        F: Fn(&AuditEvent) + Send + Sync + 'static,
    {
        self.audit.push(Box::new(hook));
        self
    }

    /// Builds the service.
    ///
    /// # Panics
    ///
    /// Outside a Tokio runtime when [`prune_every`](AuthBuilder::prune_every)
    /// is set.
    pub fn build(self) -> Auth {
        let (events, _) = broadcast::channel(EVENT_CAPACITY);

        let auth = Auth {
            inner: Arc::new(Inner {
                store: self.store,
                key: self.key,
                cookie: self.cookie,
                logins: self.logins,
                impersonation: self.impersonation,
                audit: self.audit,
                throttle: LoginThrottle::new(&self.trusted_proxies),
                events,
                #[cfg(feature = "cloudflare")]
                cloudflare: crate::cloudflare::Provider::new(self.cloudflare),
                #[cfg(feature = "google")]
                google: self
                    .google
                    .map(|config| crate::google::Provider::new(config, self.google_endpoints)),
                #[cfg(feature = "axum08")]
                live: crate::axum08::LiveCache::default(),
            }),
        };

        if let Some(period) = self.prune_every {
            tokio::spawn(prune_periodically(Arc::downgrade(&auth.inner), period));
        }

        auth
    }
}

/// Prunes now and then every `period`, for as long as the service exists.
async fn prune_periodically(inner: Weak<Inner>, period: Duration) {
    let mut interval = tokio::time::interval(period);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        interval.tick().await;

        let Some(inner) = inner.upgrade() else {
            return;
        };

        if let Err(error) = (Auth { inner }).prune().await {
            tracing::warn!("Pruning expired sessions and links failed: {error}");
        }
    }
}

/// The authentication service: sessions, cookies, sign-in, registration
/// links and user management over a [`Store`], enforcing the rules of
/// `docs/design.md` section 3.
///
/// Cloning it is cheap and shares the same service.
///
/// Operations that act on behalf of a signed-in user take that user as
/// `actor`, as loaded for the current request. Admin operations refuse a
/// non-admin actor with [`AuthError::Forbidden`]. Operations that change
/// something also take the `session` the actor signed in with, so that the
/// [`AuditEvent`]s they send name an admin impersonating the actor
/// ([`Actor::User::impersonator`](Actor::User)).
#[derive(Clone)]
pub struct Auth {
    inner: Arc<Inner>,
}

struct Inner {
    store: Box<dyn DynStore>,
    key: [u8; 32],
    cookie: CookieConfig,
    logins: bool,
    impersonation: bool,
    audit: Vec<AuditHook>,
    throttle: LoginThrottle,
    events: broadcast::Sender<AuthEvent>,
    /// The Cloudflare Access settings and their log-once warnings.
    #[cfg(feature = "cloudflare")]
    cloudflare: crate::cloudflare::Provider,
    /// The Google OAuth client and its pending flows, when configured.
    #[cfg(feature = "google")]
    google: Option<crate::google::Provider>,
    /// Recently confirmed live sessions, for the `LiveSession` extractor.
    #[cfg(feature = "axum08")]
    live: crate::axum08::LiveCache,
}

impl Auth {
    /// Starts building the service over `store`, signing cookies with
    /// `session_key` (see [`load_or_create_key`]). To use the key the store
    /// keeps, use [`builder_from_store`](Auth::builder_from_store).
    pub fn builder<S>(store: S, session_key: [u8; 32]) -> AuthBuilder
    where
        S: Store,
    {
        AuthBuilder {
            store: Box::new(store),
            key: session_key,
            cookie: CookieConfig::default(),
            logins: true,
            trusted_proxies: Vec::new(),
            impersonation: false,
            prune_every: None,
            audit: Vec::new(),
            #[cfg(feature = "cloudflare")]
            cloudflare: None,
            #[cfg(feature = "google")]
            google: None,
            #[cfg(feature = "google")]
            google_endpoints: crate::google::Endpoints::default(),
        }
    }

    /// Starts building the service over `store`, signing cookies with the
    /// key the store keeps, which [`load_or_create_key`] loads or creates.
    ///
    /// This is how an app's server and its offline tools (an import, a
    /// backup restore, a recovery command) open the same store with the same
    /// key:
    ///
    /// ```
    /// use watchword::{Auth, MemoryStore};
    ///
    /// # #[tokio::main(flavor = "current_thread")]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let auth = Auth::builder_from_store(MemoryStore::new()).await?.build();
    /// # Ok(()) }
    /// ```
    pub async fn builder_from_store<S>(store: S) -> Result<AuthBuilder, StoreError>
    where
        S: Store,
    {
        let key = load_or_create_key(&store).await?;
        Ok(Self::builder(store, key))
    }

    fn store(&self) -> &dyn DynStore {
        &*self.inner.store
    }

    /// The cache behind the `LiveSession` extractor.
    #[cfg(feature = "axum08")]
    pub(crate) fn live_cache(&self) -> &crate::axum08::LiveCache {
        &self.inner.live
    }

    /// Whether users have login names; see [`AuthBuilder::logins`].
    pub fn uses_logins(&self) -> bool {
        self.inner.logins
    }

    /// Whether Google sign-in is configured; see `AuthBuilder::google`
    /// (feature `google`). This is [`AuthConfig::google`](crate::AuthConfig::google).
    pub fn offers_google(&self) -> bool {
        #[cfg(feature = "google")]
        {
            self.inner.google.is_some()
        }

        #[cfg(not(feature = "google"))]
        {
            false
        }
    }

    /// Whether admins may impersonate users; see
    /// [`AuthBuilder::impersonation`].
    pub fn allows_impersonation(&self) -> bool {
        self.inner.impersonation
    }

    /// Subscribes to [`AuthEvent`]s.
    pub fn events(&self) -> broadcast::Receiver<AuthEvent> {
        self.inner.events.subscribe()
    }

    fn emit(&self, event: AuthEvent) {
        #[cfg(feature = "axum08")]
        self.inner.live.forget(&event);

        // Nobody listening is fine.
        let _ = self.inner.events.send(event);
    }

    fn audit(&self, event: AuditEvent) {
        for hook in &self.inner.audit {
            hook(&event);
        }
    }

    /// The address a request from `peer` with `headers` is throttled by:
    /// the forwarded client address when `peer` is a trusted proxy,
    /// otherwise `peer`.
    pub fn client_address(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        self.inner.throttle.client_address(peer, headers)
    }

    /// The session id of the request's correctly signed session cookie, if
    /// it has one. The session may still have ended; see
    /// [`session`](Auth::session).
    pub fn session_id(&self, headers: &HeaderMap) -> Option<String> {
        let name = &*self.inner.cookie.name;

        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(Cookie::split_parse)
            .filter_map(|c| c.ok())
            .filter(|c| c.name() == name)
            .find_map(|c| verify_session_cookie(&self.inner.key, c.value()).map(str::to_owned))
    }

    /// The `Set-Cookie` value that signs in the session `session_id`, for a
    /// response to a request with `headers`.
    pub fn set_cookie(&self, headers: &HeaderMap, session_id: &str) -> HeaderValue {
        let cookie = session_cookie(
            &self.inner.cookie.name,
            &self.inner.key,
            session_id,
            self.secure(headers),
        );
        HeaderValue::try_from(cookie.to_string()).expect("session cookies are valid header values")
    }

    /// The `Cookie` request header that carries the session `session_id`:
    /// the `name=value` pair of [`set_cookie`](Auth::set_cookie) without its
    /// attributes, as a browser sends it back. For a test or a client that
    /// makes requests as a session, such as one from `Auth::test_session`
    /// (feature `test-util`).
    pub fn cookie_header(&self, session_id: &str) -> HeaderValue {
        let cookie = session_cookie(&self.inner.cookie.name, &self.inner.key, session_id, false);
        HeaderValue::try_from(cookie.stripped().to_string())
            .expect("session cookies are valid header values")
    }

    /// The `Set-Cookie` value that removes the session cookie.
    pub fn clear_cookie(&self, headers: &HeaderMap) -> HeaderValue {
        let cookie = Cookie::build((self.inner.cookie.name.clone(), ""))
            .http_only(true)
            .same_site(SameSite::Strict)
            .secure(self.secure(headers))
            .path("/")
            .max_age(cookie::time::Duration::ZERO)
            .build();
        HeaderValue::try_from(cookie.to_string()).expect("session cookies are valid header values")
    }

    fn secure(&self, headers: &HeaderMap) -> bool {
        match self.inner.cookie.secure {
            Secure::Auto => is_https(headers),
            Secure::Always => true,
            Secure::Never => false,
        }
    }

    /// The live session `session_id` and its user: `None` if the session
    /// does not exist, has expired, or its user was deleted or revoked, and
    /// for an impersonated session also when its
    /// [`impersonator`](Session::impersonator) is no longer an active admin
    /// (deleted, revoked or demoted), which deletes the session. Pending
    /// users hold a session only through impersonation.
    pub async fn session(&self, session_id: &str) -> Result<Option<(User, Session)>> {
        let Some(session) = self.store().session(session_id).await? else {
            return Ok(None);
        };

        if is_expired(session.expires_at, Timestamp::now()) {
            return Ok(None);
        }

        let Some(user) = self.store().user(session.user).await? else {
            return Ok(None);
        };

        // Revocation deletes the user's sessions, but one created
        // concurrently with it must not outlive it either.
        if user.access == Access::Revoked {
            return Ok(None);
        }

        // An impersonated session lasts only while its admin is an active
        // admin. Deleting the admin deletes it; revoking or demoting them
        // leaves the row, which is deleted here so that promoting them again
        // cannot bring it back.
        if let Some(id) = session.impersonator
            && !self
                .store()
                .user(id)
                .await?
                .is_some_and(|admin| is_active_admin(&admin))
        {
            self.store().delete_session(&session.id).await?;
            return Ok(None);
        }

        Ok(Some((user, session)))
    }

    /// Deletes the sessions that have expired, and the registration and
    /// reset links that expired more than [`TOKEN_LIFETIME`] ago, used or
    /// not. Until then an expired link still answers
    /// [`AuthError::Gone`] rather than [`AuthError::NotFound`].
    ///
    /// Creating a session may also delete expired sessions. Call it on a
    /// timer to keep the store small, or have
    /// [`AuthBuilder::prune_every`] do so.
    pub async fn prune(&self) -> Result<()> {
        let now = Timestamp::now();
        self.store().delete_expired_sessions(now).await?;
        self.store()
            .delete_expired_tokens(now - TOKEN_LIFETIME)
            .await?;
        Ok(())
    }

    fn new_session(user: UserId, now: Timestamp) -> Session {
        Session {
            id: new_session_id(),
            user,
            impersonator: None,
            created_at: now,
            expires_at: session_expiry(now),
        }
    }

    async fn create_session(&self, user: UserId) -> Result<Session> {
        self.insert_session(Self::new_session(user, Timestamp::now()))
            .await
    }

    async fn insert_session(&self, session: Session) -> Result<Session> {
        self.store().create_session(&session).await?;
        Ok(session)
    }

    /// What the frontend sees of `user`, signed in with `session`: their
    /// [`UserInfo`] with [`impersonated_by`](UserInfo::impersonated_by) set
    /// when an admin is acting as them.
    pub async fn session_info(&self, user: &User, session: &Session) -> Result<UserInfo> {
        let mut info = user.info();

        if let Some(id) = session.impersonator {
            // Deleting the admin deletes the session, so a missing admin
            // means one deleted just now; the session is still marked.
            let name = match self.store().user(id).await? {
                Some(admin) => admin.info().name().to_owned(),
                None => String::new(),
            };

            info.impersonated_by = Some(Impersonator { id, name });
        }

        Ok(info)
    }

    async fn user(&self, id: UserId) -> Result<User> {
        Ok(self.store().user(id).await?.ok_or(AuthError::NotFound)?)
    }

    /// Signs in with a login name or email and a password, from the client
    /// `address` (see [`client_address`](Auth::client_address)).
    ///
    /// Only active users with a password get a session. Every failure is
    /// [`AuthError::Unauthorized`] and takes as long as checking a password,
    /// and failures are throttled per address and per login with
    /// [`AuthError::TooManyRequests`].
    pub async fn sign_in_password(
        &self,
        address: IpAddr,
        request: &LoginRequest,
    ) -> Result<(User, Session)> {
        let throttle = &self.inner.throttle;

        if !throttle.allows(address, &request.login, Instant::now()) {
            return Err(AuthError::TooManyRequests.into());
        }

        let user = self.find_user(&request.login).await?;

        let hash = user
            .as_ref()
            .filter(|u| u.method == Method::Password)
            .and_then(|u| u.password_hash.clone());

        let password = request.password.clone();

        let verified = tokio::task::spawn_blocking(move || match hash {
            Some(hash) => verify_password(&password, &hash),
            None => {
                verify_password(&password, dummy_hash());
                false
            }
        })
        .await?;

        let user = match user {
            Some(user) if verified && user.access == Access::Active => user,
            _ => {
                throttle.fail(address, &request.login, Instant::now());
                return Err(AuthError::Unauthorized.into());
            }
        };

        throttle.succeed(&request.login);
        let session = self.create_session(user.id).await?;
        Ok((user, session))
    }

    /// The user named `name`, as password sign-in finds them: by login name
    /// first (trimmed, when logins are used), then by normalized email.
    /// `None` when neither names a user, or `name` is blank.
    ///
    /// It checks no actor, so an app gates it as it needs.
    pub async fn find_user(&self, name: &str) -> Result<Option<User>> {
        if self.inner.logins {
            let login = name.trim();

            if !login.is_empty()
                && let Some(user) = self.store().user_by_login(login).await?
            {
                return Ok(Some(user));
            }
        }

        let email = normalize_email(name);

        if email.is_empty() {
            return Ok(None);
        }

        Ok(self.store().user_by_email(&email).await?)
    }

    /// Ends the session `session_id`.
    pub async fn sign_out(&self, session_id: &str) -> Result<()> {
        self.store().delete_session(session_id).await?;
        self.emit(AuthEvent::SessionEnded(session_id.to_owned()));
        Ok(())
    }

    /// The token and its user, if the token can still be used:
    /// [`AuthError::NotFound`] for an unknown token or user,
    /// [`AuthError::Gone`] for a used, expired or no longer applicable one.
    async fn usable_token(&self, token: &str, now: Timestamp) -> Result<(Token, User)> {
        let token = self
            .store()
            .token(token)
            .await?
            .ok_or(AuthError::NotFound)?;

        let user = self.user(token.user).await?;

        if !token_usable(&token, &user, now) {
            return Err(AuthError::Gone.into());
        }

        Ok((token, user))
    }

    /// What the registration or reset link `token` is for.
    ///
    /// [`AuthError::NotFound`] for an unknown link, [`AuthError::Gone`] for
    /// one that was used or has expired.
    pub async fn register_info(&self, token: &str) -> Result<RegisterInfo> {
        let (_, user) = self.usable_token(token, Timestamp::now()).await?;

        Ok(RegisterInfo {
            login: user.login,
            email: user.email,
            google: self.offers_google(),
        })
    }

    /// Registers, or resets the credential, with the link `token` and a
    /// password. The user becomes active with a password, all of their
    /// sessions end, and the returned one is created.
    ///
    /// Errors as [`register_info`](Auth::register_info) does, and with
    /// [`AuthError::Invalid`] for an unacceptable password.
    pub async fn register(
        &self,
        token: &str,
        request: &RegisterRequest,
    ) -> Result<(User, Session)> {
        if let Some(invalid) = validate_password(&request.password) {
            return Err(AuthError::Invalid(invalid).into());
        }

        self.usable_token(token, Timestamp::now()).await?;
        let hash = hash_blocking(&request.password).await?;
        self.redeem(token, &Credential::Password(hash)).await
    }

    /// Registers, or resets the credential, with the link `token` and a
    /// verified Google account, binding it to the user.
    // For the Google provider, which calls it with an account it verified.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn register_google(
        &self,
        token: &str,
        sub: &str,
        email: &str,
    ) -> Result<(User, Session)> {
        let email = normalize_email(email);
        let (_, user) = self.usable_token(token, Timestamp::now()).await?;
        self.ensure_google_free(user.id, sub, &email).await?;

        let cred = Credential::Google {
            sub: sub.to_owned(),
            email,
        };

        self.redeem(token, &cred).await
    }

    async fn redeem(&self, token: &str, cred: &Credential) -> Result<(User, Session)> {
        let now = Timestamp::now();
        let user = self
            .store()
            .token(token)
            .await?
            .ok_or(AuthError::NotFound)?
            .user;
        let session = Self::new_session(user, now);

        // Using the token decides between concurrent registrations.
        if !self
            .store()
            .redeem_token(token, cred, &session, now)
            .await?
        {
            return Err(AuthError::Gone.into());
        }

        let user = self.user(user).await?;

        self.emit(AuthEvent::UserSessionsEnded {
            user: user.id,
            keep: Some(session.id.clone()),
        });
        self.emit(AuthEvent::UserChanged(user.info()));
        self.audit(AuditEvent::LinkRedeemed {
            actor: Actor::user(user.id),
            user: user.info(),
        });
        Ok((user, session))
    }

    /// Fails unless the Google account `sub` and its `email` can be given to
    /// the user `id`: the account must not be bound to another user, and no
    /// other user may have the email.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn ensure_google_free(&self, id: UserId, sub: &str, email: &str) -> Result<()> {
        if let Some(bound) = self.store().user_by_google_sub(sub).await?
            && bound.id != id
        {
            return Err(AuthError::Invalid(Invalid::GoogleAccountTaken).into());
        }

        if let Some(other) = self.store().user_by_email(email).await?
            && other.id != id
        {
            return Err(AuthError::Conflict(Conflict::Email).into());
        }

        Ok(())
    }

    /// Signs in with a verified Google account.
    ///
    /// The account signs in as the active Google user it is bound to. A
    /// Google user with no bound account yet is matched by email once, which
    /// binds it. Anything else is [`AuthError::Unauthorized`].
    // For the Google provider, which calls it with an account it verified.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn sign_in_google(&self, sub: &str, email: &str) -> Result<(User, Session)> {
        let user = match self.store().user_by_google_sub(sub).await? {
            Some(user) => user,
            None => {
                let email = normalize_email(email);

                let Some(user) = self.store().user_by_email(&email).await? else {
                    return Err(AuthError::Unauthorized.into());
                };

                // A user bound to another Google account cannot be signed in
                // to by whichever account has their email now.
                if user.method != Method::Google
                    || user.google_sub.is_some()
                    || user.access != Access::Active
                {
                    return Err(AuthError::Unauthorized.into());
                }

                // A concurrent sign-in may have bound another account.
                if !self.store().bind_google_sub(user.id, sub).await? {
                    return Err(AuthError::Unauthorized.into());
                }

                self.user(user.id).await?
            }
        };

        if user.method != Method::Google || user.access != Access::Active {
            return Err(AuthError::Unauthorized.into());
        }

        let session = self.create_session(user.id).await?;
        Ok((user, session))
    }

    /// Switches the active user `id` to a verified Google account: clears
    /// the password, binds the account, takes its email, and ends the user's
    /// sessions except `keep`.
    // For the Google provider, which calls it with an account it verified.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn switch_to_google(
        &self,
        id: UserId,
        impersonator: Option<UserId>,
        keep: Option<&str>,
        sub: &str,
        email: &str,
    ) -> Result<User> {
        // The flow started from a session, but access may have been revoked
        // since.
        let user = self.user(id).await?;

        if user.access != Access::Active {
            return Err(AuthError::Unauthorized.into());
        }

        let email = normalize_email(email);
        self.ensure_google_free(id, sub, &email).await?;

        let cred = Credential::Google {
            sub: sub.to_owned(),
            email,
        };

        let actor = Actor::User {
            user: id,
            impersonator,
        };

        self.set_credential(actor, id, &cred, keep).await
    }

    /// Sets the user's credential for `actor`, ending their sessions except
    /// `keep`.
    async fn set_credential(
        &self,
        actor: Actor,
        id: UserId,
        cred: &Credential,
        keep: Option<&str>,
    ) -> Result<User> {
        // Refused for a user revoked since the caller read them.
        if !self.store().set_credential(id, cred, keep).await? {
            self.user(id).await?;
            return Err(AuthError::Unauthorized.into());
        }

        let user = self.user(id).await?;

        self.emit(AuthEvent::UserSessionsEnded {
            user: id,
            keep: keep.map(str::to_owned),
        });
        self.emit(AuthEvent::UserChanged(user.info()));
        self.audit(AuditEvent::CredentialChanged {
            actor,
            user: user.info(),
        });
        Ok(user)
    }

    /// Changes the signed-in user's password, keeping `session` and ending
    /// their other sessions. A Google user sets a password this way, which
    /// switches them back to a password.
    ///
    /// The current password is required when one is set:
    /// [`AuthError::Invalid`] when it is wrong or the new one is not
    /// acceptable.
    pub async fn change_password(
        &self,
        user: &User,
        session: &Session,
        change: &PasswordChange,
    ) -> Result<User> {
        // The hash may have changed since the request loaded the user.
        let current = self.user(user.id).await?;

        if let Some(hash) = current.password_hash {
            let old = change.old_password.clone().unwrap_or_default();

            if !tokio::task::spawn_blocking(move || verify_password(&old, &hash)).await? {
                return Err(AuthError::Invalid(Invalid::PasswordIncorrect).into());
            }
        }

        if let Some(invalid) = validate_password(&change.new_password) {
            return Err(AuthError::Invalid(invalid).into());
        }

        let hash = hash_blocking(&change.new_password).await?;

        let cred = Credential::Password(hash);

        self.set_credential(Actor::of(user, session), user.id, &cred, Some(&session.id))
            .await
    }

    /// Every user, with their live link's expiry. Admins only.
    pub async fn users(&self, actor: &User) -> Result<Vec<UserEntry>> {
        require_admin(actor)?;

        let users = self.store().users(Timestamp::now()).await?;

        Ok(users
            .into_iter()
            .map(|(user, link_expires_at)| UserEntry {
                user: user.info(),
                link_expires_at,
            })
            .collect())
    }

    /// Creates a pending user and issues their registration link. Admins
    /// only.
    ///
    /// [`AuthError::Invalid`] without a login or email (an email when logins
    /// are not used), [`AuthError::Conflict`] when either is taken.
    pub async fn create_user(
        &self,
        actor: &User,
        session: &Session,
        new: &NewUser,
    ) -> Result<(UserEntry, Link)> {
        require_admin(actor)?;
        let (user, link) = self.create_pending(Actor::of(actor, session), new).await?;

        let entry = UserEntry {
            user: user.info(),
            link_expires_at: Some(link.expires_at),
        };

        Ok((entry, link))
    }

    async fn create_pending(&self, actor: Actor, new: &NewUser) -> Result<(User, Link)> {
        let now = Timestamp::now();
        let user = self.create(new, now).await?;
        self.emit(AuthEvent::UserCreated(user.info()));

        self.audit(AuditEvent::UserCreated {
            actor,
            user: user.info(),
        });

        let link = self.issue(actor, &user, now).await?;
        Ok((user, link))
    }

    /// Validates and normalizes `new` and stores the user, pending.
    async fn create(&self, new: &NewUser, now: Timestamp) -> Result<User> {
        let login = self.normalize_login(new.login.as_deref())?;
        let email = normalize_optional_email(new.email.as_deref());
        self.check_identity(login.as_deref(), email.as_deref())?;

        let new = NewUser {
            login,
            email,
            role: new.role,
        };

        let user = self
            .store()
            .create_user(&new, now)
            .await?
            .map_err(AuthError::Conflict)?;

        Ok(user)
    }

    /// Issues a new link to the user `id`, using up their earlier ones: a
    /// reset link for an active user, a registration link otherwise. A
    /// revoked user regains access by registering with it. Admins only.
    pub async fn issue_link(&self, actor: &User, session: &Session, id: UserId) -> Result<Link> {
        require_admin(actor)?;
        let user = self.user(id).await?;
        self.issue(Actor::of(actor, session), &user, Timestamp::now())
            .await
    }

    async fn issue(&self, actor: Actor, user: &User, now: Timestamp) -> Result<Link> {
        let kind = match user.access {
            Access::Active => TokenKind::Reset,
            Access::Pending | Access::Revoked => TokenKind::Registration,
        };

        let token = Token {
            id: new_token(),
            user: user.id,
            kind,
            expires_at: token_expiry(now),
            used_at: None,
        };

        self.store().create_token(&token, now).await?;

        self.audit(AuditEvent::LinkIssued {
            actor,
            user: user.id,
            expires_at: token.expires_at,
        });

        Ok(Link {
            token: token.id,
            expires_at: token.expires_at,
        })
    }

    /// Uses up the user's links, so none of them works. Admins only.
    pub async fn revoke_link(&self, actor: &User, session: &Session, id: UserId) -> Result<()> {
        require_admin(actor)?;
        self.user(id).await?;
        self.store().use_up_tokens(id, Timestamp::now()).await?;

        self.audit(AuditEvent::LinkRevoked {
            actor: Actor::of(actor, session),
            user: id,
        });

        Ok(())
    }

    /// Ends all of the user's sessions; they can sign in again. Admins
    /// only, and not on their own account.
    pub async fn sign_out_everywhere(
        &self,
        actor: &User,
        session: &Session,
        id: UserId,
    ) -> Result<()> {
        require_admin(actor)?;
        not_self(actor, id)?;
        self.user(id).await?;
        self.store().delete_sessions(id, None).await?;
        self.emit(AuthEvent::UserSessionsEnded {
            user: id,
            keep: None,
        });

        self.audit(AuditEvent::SignedOutEverywhere {
            actor: Actor::of(actor, session),
            user: id,
        });

        Ok(())
    }

    /// Revokes the user's access: they cannot sign in by any path, their
    /// password is cleared, their links are used up and their sessions end.
    /// A new link restores access. Admins only, and not on their own
    /// account.
    pub async fn revoke_access(&self, actor: &User, session: &Session, id: UserId) -> Result<User> {
        require_admin(actor)?;
        not_self(actor, id)?;

        // For the audit event; the store decides whether the user exists.
        let before = self.store().user(id).await?;

        if !self.store().revoke(id, Timestamp::now()).await? {
            return Err(AuthError::NotFound.into());
        }

        let user = self.user(id).await?;
        self.emit(AuthEvent::UserSessionsEnded {
            user: id,
            keep: None,
        });
        self.emit(AuthEvent::UserChanged(user.info()));

        self.audit(AuditEvent::AccessRevoked {
            actor: Actor::of(actor, session),
            before: before.as_ref().unwrap_or(&user).info(),
            after: user.info(),
        });

        Ok(user)
    }

    /// Sets the user's role. Admins only, and not their own role.
    pub async fn set_role(
        &self,
        actor: &User,
        session: &Session,
        id: UserId,
        role: Role,
    ) -> Result<User> {
        require_admin(actor)?;

        let change = UserChange {
            role: Some(role),
            ..UserChange::default()
        };

        self.update_user(actor, session, id, &change).await
    }

    /// Changes the user's login, email or role.
    ///
    /// Admins may change any user, except their own role. Anyone else may
    /// change only their own login and email, and a Google user's own email
    /// is the one Google verified, so it cannot be changed this way. The
    /// user must keep a login or an email (an email when logins are not
    /// used). [`AuthError::Conflict`] when the login or email is taken.
    pub async fn update_user(
        &self,
        actor: &User,
        session: &Session,
        id: UserId,
        change: &UserChange,
    ) -> Result<User> {
        let own = actor.id == id;

        if !own {
            require_admin(actor)?;
        }

        let user = self.user(id).await?;

        if own && change.role.is_some_and(|role| role != user.role) {
            return Err(AuthError::Forbidden.into());
        }

        let change = UserChange {
            login: match &change.login {
                Some(login) => Some(self.normalize_login(login.as_deref())?),
                None => None,
            },
            email: change
                .email
                .as_ref()
                .map(|email| normalize_optional_email(email.as_deref())),
            role: change.role,
        };

        if own
            && user.method == Method::Google
            && change
                .email
                .as_ref()
                .is_some_and(|email| *email != user.email)
        {
            return Err(AuthError::Invalid(Invalid::EmailManagedByGoogle).into());
        }

        let login = change.login.as_ref().unwrap_or(&user.login);
        let email = change.email.as_ref().unwrap_or(&user.email);
        self.check_identity(login.as_deref(), email.as_deref())?;

        let before = user.info();

        let user = self
            .store()
            .update_user(id, &change)
            .await?
            .map_err(AuthError::Conflict)?
            .ok_or(AuthError::NotFound)?;

        self.emit(AuthEvent::UserChanged(user.info()));
        let after = user.info();

        if before != after {
            self.audit(AuditEvent::UserUpdated {
                actor: Actor::of(actor, session),
                before,
                after,
            });
        }

        Ok(user)
    }

    /// Deletes the user, with their sessions and links. Admins only, and not
    /// their own account.
    pub async fn delete_user(&self, actor: &User, session: &Session, id: UserId) -> Result<()> {
        require_admin(actor)?;
        not_self(actor, id)?;

        // For the audit event; the store decides whether the user exists.
        let before = self.store().user(id).await?;

        if !self.store().delete_user(id).await? {
            return Err(AuthError::NotFound.into());
        }

        self.emit(AuthEvent::UserSessionsEnded {
            user: id,
            keep: None,
        });
        self.emit(AuthEvent::UserDeleted(id));

        // Deleted by another process between the two calls, if `None`: then
        // this call did not delete them, but the store said it did.
        if let Some(before) = before {
            self.audit(AuditEvent::UserDeleted {
                actor: Actor::of(actor, session),
                user: before.info(),
            });
        }

        Ok(())
    }

    /// Creates a session as the user `id`, for an admin to see what they
    /// see. The session records the admin as its
    /// [`impersonator`](Session::impersonator), which
    /// [`session_info`](Auth::session_info) shows and
    /// [`stop_impersonating`](Auth::stop_impersonating) returns to.
    ///
    /// Pending users can be impersonated, revoked ones cannot. Admins only,
    /// when [enabled](AuthBuilder::impersonation), not themselves, and not
    /// from `session` if it is itself impersonated (an admin acting as
    /// another admin), so that stopping always leads back to the admin who
    /// started.
    pub async fn impersonate(
        &self,
        actor: &User,
        session: &Session,
        id: UserId,
    ) -> Result<(User, Session)> {
        if !self.inner.impersonation {
            return Err(AuthError::Forbidden.into());
        }

        require_admin(actor)?;
        not_self(actor, id)?;

        if session.impersonator.is_some() {
            return Err(AuthError::Forbidden.into());
        }

        let user = self.user(id).await?;

        if user.access == Access::Revoked {
            return Err(AuthError::Forbidden.into());
        }

        let mut new = Self::new_session(user.id, Timestamp::now());
        new.impersonator = Some(actor.id);
        let new = self.insert_session(new).await?;

        self.audit(AuditEvent::ImpersonationStarted {
            admin: actor.id,
            user: user.id,
        });

        Ok((user, new))
    }

    /// Ends the impersonated `session` and creates a session for the admin
    /// who started it, returning the admin and the new session.
    ///
    /// [`AuthError::Forbidden`], with nothing changed, when `session` is not
    /// impersonated, or its admin is no longer an active admin. The latter
    /// only happens between loading `session` and this call, since
    /// [`session`](Auth::session) already ends such a session.
    pub async fn stop_impersonating(&self, session: &Session) -> Result<(User, Session)> {
        let Some(id) = session.impersonator else {
            return Err(AuthError::Forbidden.into());
        };

        let Some(admin) = self.store().user(id).await? else {
            return Err(AuthError::Forbidden.into());
        };

        if !is_active_admin(&admin) {
            return Err(AuthError::Forbidden.into());
        }

        self.sign_out(&session.id).await?;
        let new = self.create_session(admin.id).await?;

        self.audit(AuditEvent::ImpersonationStopped {
            admin: admin.id,
            user: session.user,
        });

        Ok((admin, new))
    }

    /// A trimmed login name. Setting one is [`AuthError::Invalid`] when
    /// logins are not used, and so is a blank one.
    fn normalize_login(&self, login: Option<&str>) -> Result<Option<String>, AuthError> {
        let Some(login) = login else {
            return Ok(None);
        };

        if !self.inner.logins {
            return Err(AuthError::Invalid(Invalid::LoginsDisabled));
        }

        let login = login.trim();

        if login.is_empty() {
            return Err(AuthError::Invalid(Invalid::LoginEmpty));
        }

        Ok(Some(login.to_owned()))
    }

    /// A user needs a login or an email, and an email when logins are not
    /// used.
    fn check_identity(&self, login: Option<&str>, email: Option<&str>) -> Result<(), AuthError> {
        if email.is_none() && !self.inner.logins {
            return Err(AuthError::Invalid(Invalid::EmailRequired));
        }

        if login.is_none() && email.is_none() {
            return Err(AuthError::Invalid(Invalid::LoginOrEmailRequired));
        }

        Ok(())
    }

    /// Brings up the first admin, so the option can stay set across
    /// restarts:
    ///
    /// - With no users, creates the admin, pending, and issues their
    ///   registration link: [`Bootstrap::Created`].
    /// - When the named admin is still pending, no active admin exists and
    ///   their link has expired (or was used up), issues a new one:
    ///   [`Bootstrap::Reissued`].
    /// - When that admin's link is still live, changes nothing:
    ///   [`Bootstrap::Pending`].
    /// - Otherwise, changes nothing: [`Bootstrap::Skipped`].
    ///
    /// It logs the outcome at `info`, with the link as a full URL under
    /// [`BootstrapAdmin::public_url`] if set, otherwise as the path. An app
    /// whose log the operator may not see prints the link itself, with
    /// [`Link::url`].
    pub async fn bootstrap_admin(&self, admin: &BootstrapAdmin) -> Result<Bootstrap> {
        let name = admin
            .email
            .as_deref()
            .or(admin.login.as_deref())
            .unwrap_or_default();

        let public_url = admin.public_url.as_deref();
        let now = Timestamp::now();

        if self.store().user_count().await? == 0 {
            let new = NewUser {
                login: admin.login.clone(),
                email: admin.email.clone(),
                role: Role::Admin,
            };

            let (_, link) = self.create_pending(Actor::System, &new).await?;
            log_bootstrap_link(name, "registration", public_url, &link);
            return Ok(Bootstrap::Created(link));
        }

        let Some(user) = self.pending_bootstrap_admin(admin).await? else {
            tracing::info!(
                "Bootstrap: skipped for {name}, since users already exist; \
                 the bootstrap admin only applies to an empty users table, \
                 or to its pending admin while no active admin exists"
            );
            return Ok(Bootstrap::Skipped);
        };

        let mut active_admin = false;
        let mut live = None;

        for (other, expires_at) in self.store().users(now).await? {
            active_admin |= is_active_admin(&other);

            if other.id == user.id {
                live = expires_at;
            }
        }

        if active_admin {
            tracing::info!(
                "Bootstrap: skipped for {name}, since an active admin exists \
                 to issue them a link"
            );
            return Ok(Bootstrap::Skipped);
        }

        if let Some(expires_at) = live {
            tracing::info!(
                "Bootstrap: {name} has not registered yet; \
                 their registration link works until {expires_at}"
            );
            return Ok(Bootstrap::Pending { expires_at });
        }

        let link = self.issue(Actor::System, &user, now).await?;
        log_bootstrap_link(name, "new registration", public_url, &link);
        Ok(Bootstrap::Reissued(link))
    }

    /// The user `admin` names, if they are a pending admin.
    async fn pending_bootstrap_admin(&self, admin: &BootstrapAdmin) -> Result<Option<User>> {
        let user = match (&admin.email, &admin.login) {
            (Some(email), _) => self.store().user_by_email(&normalize_email(email)).await?,
            (None, Some(login)) => self.store().user_by_login(login.trim()).await?,
            (None, None) => None,
        };

        Ok(user.filter(|user| user.access == Access::Pending && user.is_admin()))
    }

    /// Issues a new link to the user named `name`, for an app's own command
    /// line to recover an account with no admin to act: a reset link for an
    /// active user, a registration link otherwise, which restores a revoked
    /// user. It uses up the user's earlier links, as
    /// [`issue_link`](Auth::issue_link) does, but acts as the system, so it
    /// needs no actor; never expose it to a request.
    ///
    /// `name` is a login, or else an email, as for
    /// [`find_user`](Auth::find_user). [`AuthError::NotFound`] when neither
    /// names a user.
    pub async fn recovery_link(&self, name: &str) -> Result<Link> {
        let user = self.find_user(name).await?.ok_or(AuthError::NotFound)?;

        let link = self.issue(Actor::System, &user, Timestamp::now()).await?;
        tracing::info!(
            "Recovery: issued a link for {}, which works until {}",
            user.info().name(),
            link.expires_at
        );
        Ok(link)
    }

    /// Creates a pending user without issuing them a link, for an app's own
    /// import or backup-restore tool. It validates and normalizes `new` as
    /// [`create_user`](Auth::create_user) does and sends
    /// [`AuthEvent::UserCreated`] and [`AuditEvent::UserCreated`], but acts
    /// as the system, so it needs no actor; never expose it to a request.
    ///
    /// The user signs in once they have a link, from
    /// [`issue_link`](Auth::issue_link) or
    /// [`recovery_link`](Auth::recovery_link).
    ///
    /// [`AuthError::Invalid`] without a login or email (an email when logins
    /// are not used), [`AuthError::Conflict`] when either is taken.
    pub async fn import_user(&self, new: &NewUser) -> Result<User> {
        let user = self.create(new, Timestamp::now()).await?;
        self.emit(AuthEvent::UserCreated(user.info()));

        self.audit(AuditEvent::UserCreated {
            actor: Actor::System,
            user: user.info(),
        });

        Ok(user)
    }
}

fn log_bootstrap_link(name: &str, what: &str, public_url: Option<&str>, link: &Link) {
    let url = link.url(public_url);

    if public_url.is_some() {
        tracing::info!("Bootstrap: {what} URL for {name}: {url}");
    } else {
        tracing::info!(
            "Bootstrap: {what} link for {name}: {url} \
             (relative to the address the service is reached at; \
             set a public URL to log a full one)"
        );
    }
}

/// What [`Auth::bootstrap_admin`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bootstrap {
    /// There were no users: it created the admin, pending, with this
    /// registration link.
    Created(Link),
    /// The admin was still pending, with no active admin to act and no live
    /// link: it issued them this registration link, using up the earlier
    /// ones.
    Reissued(Link),
    /// The admin is still pending, and the link issued earlier works until
    /// `expires_at`. Its token was shown only when it was issued.
    Pending {
        /// When the outstanding link stops working.
        expires_at: Timestamp,
    },
    /// Users exist, and either the named admin is not a pending admin or an
    /// active admin exists to issue them a link: nothing changed.
    Skipped,
}

impl Bootstrap {
    /// The link issued this time, if any.
    pub fn link(&self) -> Option<&Link> {
        match self {
            Bootstrap::Created(link) | Bootstrap::Reissued(link) => Some(link),
            Bootstrap::Pending { .. } | Bootstrap::Skipped => None,
        }
    }
}

/// The first admin to create on an empty install; see
/// [`Auth::bootstrap_admin`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootstrapAdmin {
    /// The admin's email.
    pub email: Option<String>,
    /// The admin's login name.
    pub login: Option<String>,
    /// The URL the app is reached at, to log a full registration URL.
    pub public_url: Option<String>,
}

impl BootstrapAdmin {
    /// An admin named by an email or a login, such as the value of
    /// `--bootstrap-admin`: an email if it contains `@`, otherwise a login.
    pub fn new(name: &str) -> Self {
        if name.contains('@') {
            Self::email(name)
        } else {
            Self::login(name)
        }
    }

    /// An admin with the email `email`.
    pub fn email(email: impl Into<String>) -> Self {
        Self {
            email: Some(email.into()),
            ..Self::default()
        }
    }

    /// An admin with the login name `login`.
    pub fn login(login: impl Into<String>) -> Self {
        Self {
            login: Some(login.into()),
            ..Self::default()
        }
    }

    /// Logs a full registration URL under `url`, when it is set.
    pub fn public_url(mut self, url: Option<impl ToString>) -> Self {
        self.public_url = url.map(|url| url.to_string());
        self
    }
}

/// Whether the token can still be used by `user`, the user it was issued to.
///
/// Once a user has registered, a registration link can no longer set their
/// credential; only a reset link, deliberately issued afterwards, can.
pub(crate) fn token_usable(token: &Token, user: &User, now: Timestamp) -> bool {
    token.used_at.is_none()
        && !is_expired(token.expires_at, now)
        && (user.access != Access::Active || token.kind == TokenKind::Reset)
}

/// Whether `user` may act as an admin: by an admin operation, or as the
/// impersonator of a live session.
fn is_active_admin(user: &User) -> bool {
    user.access == Access::Active && user.is_admin()
}

/// Admin operations need an active admin: a pending admin has not
/// registered, and a revoked one may not act.
fn require_admin(actor: &User) -> Result<(), AuthError> {
    if !is_active_admin(actor) {
        return Err(AuthError::Forbidden);
    }

    Ok(())
}

fn not_self(actor: &User, id: UserId) -> Result<(), AuthError> {
    if actor.id == id {
        return Err(AuthError::Forbidden);
    }

    Ok(())
}

/// A normalized email, with a blank one meaning none.
fn normalize_optional_email(email: Option<&str>) -> Option<String> {
    email.map(normalize_email).filter(|e| !e.is_empty())
}

async fn hash_blocking(password: &str) -> Result<String> {
    let password = password.to_owned();
    Ok(tokio::task::spawn_blocking(move || hash_password(&password)).await??)
}

/// Whether the client reached the proxy in front of the server over HTTPS.
fn is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .is_some_and(|proto| proto.trim().eq_ignore_ascii_case("https"))
}

#[cfg(feature = "cloudflare")]
mod cloudflare;

#[cfg(feature = "google")]
mod google;

#[cfg(any(test, feature = "test-util"))]
mod test_util;

#[cfg(all(feature = "google", feature = "axum08"))]
pub(crate) use self::google::GoogleReturn;

#[cfg(test)]
mod tests;
