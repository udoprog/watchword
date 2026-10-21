//! [`Transport`]: how the [`AuthService`](super::AuthService)'s requests
//! reach the server.

#[cfg(feature = "musliweb05")]
use core::cell::RefCell;
use core::future::Future;
use core::pin::Pin;
use std::boxed::Box;

#[cfg(feature = "musliweb05")]
use watchword_core::CookieChange;
use watchword_core::{AuthRequest, AuthResponse};

use super::Error;
use super::http;
#[cfg(feature = "musliweb05")]
use super::socket::SocketHandle;

/// The future a [`Transport`] answers with. It need not be `Send`, since the
/// browser has one thread.
pub type TransportFuture<'a> = Pin<Box<dyn Future<Output = Result<AuthResponse, Error>> + 'a>>;

/// Carries an [`AuthRequest`] to watchword's service and brings back its
/// [`AuthResponse`]: the seam under the [`AuthService`](super::AuthService)
/// that an app or a test supplies with
/// [`AuthService::new`](super::AuthService::new) and
/// [`AuthProvider`](super::AuthProvider)'s `service` prop.
///
/// The operations themselves are the service's, so a transport only moves
/// requests: a new operation in watchword is a new [`AuthRequest`] variant,
/// which a transport that forwards requests it does not know (such as to
/// [`HttpTransport`]) carries without a change.
///
/// # The session cookie
///
/// The requests whose [`AuthRequest::cookie`] is set (signing in and out,
/// registering, impersonating and stopping it) set, replace or clear the
/// `HttpOnly` session cookie, which only an HTTP response can do: a browser
/// transport sends them over HTTP, such as with [`http::send`]. A transport
/// that keeps a session of its own, such as a test's, takes the new session
/// from the server's answer to these, and forgets it on
/// [`CookieChange::Clear`](watchword_core::CookieChange::Clear).
///
/// # Errors
///
/// A refusal is the server's [`AuthError`](watchword_core::AuthError) as
/// [`Error::Auth`], which the components act on: a 401 makes the provider
/// check the session. A failure to carry the request is one of the other
/// [`Error`]s. The answer must be the [`AuthResponse`] the server's
/// `Auth::dispatch` gives for the request; the service fails any other with
/// [`Error::UnexpectedResponse`].
///
/// ```
/// use watchword_yew023::{AuthService, HttpTransport, Transport, TransportFuture};
/// use watchword_core::AuthRequest;
///
/// /// Logs each request, then sends it over HTTP.
/// struct Logged;
///
/// impl Transport for Logged {
///     fn send(&self, request: AuthRequest) -> TransportFuture<'_> {
///         println!("{request:?}");
///         HttpTransport.send(request)
///     }
/// }
///
/// let service = AuthService::new(Logged);
/// ```
pub trait Transport {
    /// Sends `request` and answers with the server's response.
    fn send(&self, request: AuthRequest) -> TransportFuture<'_>;
}

/// The transport that sends every request over HTTP, to watchword's
/// `/api/auth` routes on the page's origin, with [`http::send`]. The
/// [`AuthService`](super::AuthService)'s default outside an
/// [`AuthProvider`](super::AuthProvider).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HttpTransport;

impl Transport for HttpTransport {
    fn send(&self, request: AuthRequest) -> TransportFuture<'_> {
        Box::pin(http::send(request))
    }
}

/// The provider's transport when the app injects none: the socket handed
/// over with `set_socket` while it is open and speaks for this browser's
/// session, and HTTP otherwise.
///
/// A request the socket did not send, such as while it reconnects, or one
/// with no endpoint on it (the cookie operations, the config and link
/// info), goes over HTTP. After a request that
/// [replaced](CookieChange::Replace) the cookie, the socket still speaks for
/// the session its upgrade carried, so it is marked stale and requests go
/// over HTTP until it reconnects.
#[derive(Default)]
pub(super) struct DefaultTransport {
    #[cfg(feature = "musliweb05")]
    socket: RefCell<Option<SocketHandle>>,
}

impl DefaultTransport {
    /// Sends the requests over `socket` from now on.
    #[cfg(feature = "musliweb05")]
    pub(super) fn set_socket(&self, socket: Option<SocketHandle>) {
        *self.socket.borrow_mut() = socket;
    }
}

impl Transport for DefaultTransport {
    fn send(&self, request: AuthRequest) -> TransportFuture<'_> {
        #[cfg(feature = "musliweb05")]
        let socket = self.socket.borrow().clone();

        Box::pin(async move {
            #[cfg(feature = "musliweb05")]
            if let Some(socket) = &socket {
                if request.cookie().is_none()
                    && let Some(result) = socket.send(&request).await
                {
                    return result;
                }

                let replaces = request.cookie() == Some(CookieChange::Replace);
                let result = http::send(request).await;

                if replaces && result.is_ok() {
                    socket.mark_stale();
                }

                return result;
            }

            http::send(request).await
        })
    }
}
