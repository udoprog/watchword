use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use core::fmt;

use axum08::extract::{Request, State};
use axum08::http::{HeaderMap, Method, header};
use axum08::middleware::Next;
use axum08::response::{IntoResponse, Redirect, Response};

use super::SignedIn;
use crate::Auth;
use crate::types::AuthError;

/// Whether watchword serves `path` without a session: the `/api/auth` routes
/// (which check sessions themselves, as their table in [`routes`] says) and
/// the frontend's `/register/{token}` pages that registration links point at.
///
/// [`RequireSession`] lets these through. An app that gates on its own can
/// ask this instead of naming watchword's paths, so a public route watchword
/// adds later is let through too.
///
/// ```
/// use watchword::axum08::is_public;
///
/// assert!(is_public("/api/auth/login"));
/// assert!(is_public("/register/abc"));
/// assert!(!is_public("/"));
/// assert!(!is_public("/api/notes"));
/// ```
///
/// [`routes`]: super::routes
pub fn is_public(path: &str) -> bool {
    path.starts_with("/api/auth/") || path.starts_with("/register/")
}

type Predicate = dyn Fn(&str) -> bool + Send + Sync;

/// The state of the [`require_session`] middleware, which gates every route
/// behind it on a live session.
///
/// It lets a request through when:
/// - its path is [public](is_public) to watchword, is the sign-in page, or
///   is one of the app's own public paths (see [`public`](Self::public),
///   such as the scripts, styles and wasm of the built frontend); or
/// - it is signed in, as for [`SignedIn`].
///
/// Otherwise a browser loading a page (a `GET` or `HEAD` outside `/api/`
/// that accepts `text/html`, as navigations do) is redirected to the sign-in
/// page with `?next=` naming the page it asked for, which watchword-yew023's
/// `AuthProvider` returns to once signed in. Any other request is answered
/// with [`AuthError::Unauthorized`] (401), and a store failure with a 500,
/// as the extractors do.
///
/// An `?error=` on the page asked for, such as the one the Google callback
/// redirects to `/` with, is moved to the sign-in page's own query, where
/// the sign-in page shows it. So is the `next` of `/?next=…` (with nothing
/// else but an `error`), which the callback adds for a sign-in that was to
/// return elsewhere.
///
/// A request let through with a session carries its [`SignedIn`] in the
/// request extensions, so the handlers' [`SignedIn`], [`Admin`] and
/// [`MaybeSignedIn`] extractors use it without reading the store again, and
/// a handler may take `Extension<SignedIn>`.
///
/// ```no_run
/// # extern crate axum08 as axum;
/// use watchword::axum08::{RequireSession, require_session, routes};
/// use watchword::{Auth, MemoryStore, generate_session_key};
/// use axum::Router;
/// use axum::middleware::from_fn_with_state;
/// use axum::routing::get;
///
/// let auth = Auth::builder(MemoryStore::new(), generate_session_key()).build();
///
/// let gate = RequireSession::new(auth.clone(), "/login")
///     .public(|path| path.starts_with("/assets/"));
///
/// let app: Router = Router::new()
///     .route("/api/notes", get(|| async { "[]" }))
///     .merge(routes())
///     .layer(from_fn_with_state(gate, require_session))
///     .with_state(auth);
/// ```
///
/// The middleware sees the request's path as the router it is layered on
/// sees it, so layer it on the outermost router rather than inside a
/// `nest`.
///
/// [`Admin`]: super::Admin
/// [`MaybeSignedIn`]: super::MaybeSignedIn
#[derive(Clone)]
pub struct RequireSession {
    auth: Auth,
    sign_in_path: Arc<str>,
    public: Option<Arc<Predicate>>,
}

impl RequireSession {
    /// Gates on `auth`'s sessions, sending a browser that is not signed in
    /// to `sign_in_path` (such as `/login`), which must be a path of the
    /// app's frontend that renders its `AuthProvider`. That path is public.
    pub fn new(auth: Auth, sign_in_path: &str) -> Self {
        Self {
            auth,
            sign_in_path: Arc::from(sign_in_path),
            public: None,
        }
    }

    /// Also lets through the paths `public` accepts, such as the files of
    /// the built frontend, which the sign-in page itself loads. Replaces an
    /// earlier predicate.
    pub fn public(mut self, public: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        self.public = Some(Arc::new(public));
        self
    }

    /// Whether `path` is let through without a session.
    fn is_public(&self, path: &str) -> bool {
        is_public(path)
            || path == &*self.sign_in_path
            || self.public.as_ref().is_some_and(|public| public(path))
    }

    /// The sign-in page, returning to `target` (a path and query) once
    /// signed in.
    fn sign_in_url(&self, target: &str) -> String {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));

        let mut error = None;
        let mut rest = Vec::new();

        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            match pair.strip_prefix("error=") {
                Some(value) if error.is_none() => error = Some(value),
                _ => rest.push(pair),
            }
        }

        let mut url = String::from(&*self.sign_in_path);
        let mut separator = '?';

        if let Some(error) = error {
            url.push(separator);
            url.push_str("error=");
            url.push_str(error);
            separator = '&';
        }

        // `/` with nothing but a `next`, as the Google callback redirects
        // with after a failed sign-in, already says where to return to.
        let own_next = match rest.as_slice() {
            [pair] if path == "/" => pair.strip_prefix("next="),
            _ => None,
        };

        if let Some(next) = own_next {
            url.push(separator);
            url.push_str("next=");
            url.push_str(next);
        } else if path != "/" || !rest.is_empty() {
            let mut next = String::from(path);

            if !rest.is_empty() {
                next.push('?');
                next.push_str(&rest.join("&"));
            }

            url.push(separator);
            url.push_str("next=");
            encode_into(&mut url, &next);
        }

        url
    }
}

impl fmt::Debug for RequireSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequireSession")
            .field("sign_in_path", &self.sign_in_path)
            .field("public", &self.public.is_some())
            .finish_non_exhaustive()
    }
}

/// The middleware that gates the routes behind it on a live session, as
/// [`RequireSession`] describes; layer it with
/// `axum::middleware::from_fn_with_state(gate, require_session)`.
pub async fn require_session(
    State(gate): State<RequireSession>,
    request: Request,
    next: Next,
) -> Response {
    if gate.is_public(request.uri().path()) {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();

    // Loading the session leaves it in the request's extensions, where the
    // handlers' own extractors find it.
    match SignedIn::load(&mut parts, &gate.auth).await {
        Ok(Some(..)) => next.run(Request::from_parts(parts, body)).await,
        Ok(None) => {
            if is_page_request(&parts.method, parts.uri.path(), &parts.headers) {
                let target = parts.uri.path_and_query().map_or("/", |p| p.as_str());
                Redirect::to(&gate.sign_in_url(target)).into_response()
            } else {
                AuthError::Unauthorized.into_response()
            }
        }
        Err(error) => error.into_response(),
    }
}

/// Whether a request is a browser loading a page, which is worth sending to
/// sign-in rather than refusing.
fn is_page_request(method: &Method, path: &str, headers: &HeaderMap) -> bool {
    (method == Method::GET || method == Method::HEAD)
        && !path.starts_with("/api/")
        && headers
            .get_all(header::ACCEPT)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| v.contains("text/html"))
}

/// Percent-encodes `value` as a query value, keeping only unreserved
/// characters and `/` as they are.
pub(super) fn encode_into(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0xf)]));
        }
    }
}

#[cfg(test)]
pub(super) fn sign_in_url(sign_in_path: &str, target: &str) -> String {
    let auth = Auth::builder(crate::MemoryStore::new(), crate::generate_session_key()).build();
    RequireSession::new(auth, sign_in_path).sign_in_url(target)
}
