//! The app's musli-web socket, as handed over with
//! [`AuthContext::set_socket`](super::AuthContext::set_socket).

use std::cell::Cell;
use std::rc::Rc;
use std::string::ToString;

use musli_web06::api;
use musli_web06::web03::prelude::ws;
use yew::Callback;

use watchword_core::PAGE_SESSION_HEADER;
use watchword_core::musliweb06::{
    AuthBroadcast, AuthUpdate, CloudflareRequest, DeleteUserRequest, GoogleRequest,
    IssueLinkRequest, MeRequest, RevokeAccessRequest, RevokeLinkRequest, SESSION_ENDED,
    SignOutUserRequest, UserUpdate, UsersRequest,
};
use watchword_core::{AuthError, AuthRequest, AuthResponse};

use super::Error;
use super::browser;

/// The connection metadata of the app's musli-web socket, for its
/// `ServiceBuilder::metadata`, which calls it on every connect and
/// reconnect: in a page an admin opened to impersonate someone, the page
/// session as [`PAGE_SESSION_HEADER`], so the socket speaks for that session
/// rather than the admin's cookie; nothing elsewhere.
///
/// ```ignore
/// let service = ws::connect(ws::Connect::location("ws"))
///     .metadata(watchword_yew023::socket_metadata)
///     .build();
/// ```
pub fn socket_metadata(metadata: &mut api::Metadata) {
    insert_page_session(metadata, browser::page_session().as_deref());
}

/// Inserts `page_session`, if any, into `metadata`.
pub(super) fn insert_page_session(metadata: &mut api::Metadata, page_session: Option<&str>) {
    if let Some(page_session) = page_session {
        metadata.insert(PAGE_SESSION_HEADER, page_session);
    }
}

/// What the provider follows of a socket's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Open,
    /// Closed, connecting or refused for any reason but [`SESSION_ENDED`].
    Closed,
    /// Refused with [`SESSION_ENDED`]: the session the socket stated has
    /// ended. musli-web does not reconnect it.
    SessionEnded,
}

impl SocketState {
    pub(super) fn from_state(state: &ws::State) -> Self {
        match state {
            ws::State::Open => Self::Open,
            ws::State::Refused(refused) => Self::from_refused(refused.code()),
            _ => Self::Closed,
        }
    }

    /// The state of a socket refused with `code`.
    pub(super) fn from_refused(code: u16) -> Self {
        if code == SESSION_ENDED {
            Self::SessionEnded
        } else {
            Self::Closed
        }
    }

    pub(super) fn is_open(self) -> bool {
        self == Self::Open
    }
}

/// A socket handed over to the provider, as the context carries it.
#[derive(Clone)]
pub(super) struct SocketHandle {
    inner: Rc<Inner>,
}

struct Inner {
    handle: ws::Handle,
    state: Rc<Cell<SocketState>>,
    _state: ws::StateListener,
}

impl SocketHandle {
    /// Follows `handle`'s state, calling `on_state` each time its
    /// [`SocketState`] changes.
    pub(super) fn new(handle: ws::Handle, on_state: Callback<SocketState>) -> Self {
        let current = Rc::new(Cell::new(SocketState::Closed));

        let (state, listener) = handle.on_state_change({
            let current = current.clone();

            move |state: ws::State| {
                let state = SocketState::from_state(&state);

                if current.replace(state) != state {
                    on_state.emit(state);
                }
            }
        });

        current.set(SocketState::from_state(&state));

        Self {
            inner: Rc::new(Inner {
                handle,
                state: current,
                _state: listener,
            }),
        }
    }

    /// The socket's state.
    pub(super) fn state(&self) -> SocketState {
        self.inner.state.get()
    }

    /// Whether the socket is open.
    pub(super) fn is_open(&self) -> bool {
        self.state().is_open()
    }

    /// The app's handle.
    pub(super) fn handle(&self) -> &ws::Handle {
        &self.inner.handle
    }

    /// Sends `body` over the socket and waits for the answer. `None` when
    /// musli-web did not send it since the socket is not connected (such as while it reconnects), so that nothing reached the
    /// server and the caller sends it over HTTP instead.
    ///
    /// A refusal is the server's typed [`AuthError`], as [`Error::Auth`]. A
    /// request the socket fails otherwise after sending it, such as when it
    /// closes before the answer or the server fails it with an internal
    /// error, is [`Error::Socket`]: the server may have acted on it, so it is
    /// not sent again.
    pub(super) async fn request<B>(
        &self,
        body: B,
    ) -> Option<Result<<B::Endpoint as api::Endpoint>::Response<'static>, Error>>
    where
        B: api::Request,
        for<'de> <B::Endpoint as api::Endpoint>::Response<'static>: api::DecodeBody<'de>,
    {
        match self.handle().call(body).await {
            Ok(value) => Some(Ok(value)),
            Err(error) if error.is_not_connected() => None,
            Err(error) => Some(Err(request_error(&error))),
        }
    }
}

impl SocketHandle {
    /// Sends `request` over its musli-web endpoint, as
    /// [`request`](Self::request) does. `None` also for a request with no
    /// endpoint, such as the cookie operations, which go over HTTP.
    pub(super) async fn send(&self, request: &AuthRequest) -> Option<Result<AuthResponse, Error>> {
        let result = match request {
            AuthRequest::Me => self.request(MeRequest).await?.map(AuthResponse::User),
            AuthRequest::UpdateAccount(change) => {
                self.request(change.clone()).await?.map(AuthResponse::User)
            }
            AuthRequest::ChangePassword(change) => {
                self.request(change.clone()).await?.map(AuthResponse::User)
            }
            AuthRequest::Users => self.request(UsersRequest).await?.map(AuthResponse::Users),
            AuthRequest::CreateUser(new) => self
                .request(new.clone())
                .await?
                .map(AuthResponse::CreatedUser),
            AuthRequest::UpdateUser { id, change } => self
                .request(UserUpdate {
                    id: *id,
                    change: change.clone(),
                })
                .await?
                .map(AuthResponse::User),
            AuthRequest::DeleteUser { id } => self
                .request(DeleteUserRequest { id: *id })
                .await?
                .map(|()| AuthResponse::Done),
            AuthRequest::IssueLink { id } => self
                .request(IssueLinkRequest { id: *id })
                .await?
                .map(AuthResponse::Link),
            AuthRequest::RevokeLink { id } => self
                .request(RevokeLinkRequest { id: *id })
                .await?
                .map(|()| AuthResponse::Done),
            AuthRequest::SignOutUser { id } => self
                .request(SignOutUserRequest { id: *id })
                .await?
                .map(|()| AuthResponse::Done),
            AuthRequest::RevokeAccess { id } => self
                .request(RevokeAccessRequest { id: *id })
                .await?
                .map(AuthResponse::User),
            AuthRequest::Cloudflare => self
                .request(CloudflareRequest)
                .await?
                .map(AuthResponse::Cloudflare),
            AuthRequest::SetCloudflare(config) => self
                .request(config.clone())
                .await?
                .map(AuthResponse::Cloudflare),
            AuthRequest::Google => self.request(GoogleRequest).await?.map(AuthResponse::Google),
            AuthRequest::SetGoogle(update) => self
                .request(update.clone())
                .await?
                .map(AuthResponse::Google),
            _ => return None,
        };

        Some(result)
    }
}

impl PartialEq for SocketHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }
}

/// The [`Error`] of a request the socket failed after sending it: the
/// [`AuthError`] the server refused it with, or the socket's error.
fn request_error(error: &ws::Error) -> Error {
    match error.server_error::<AuthError>() {
        Ok(Some(error)) => Error::Auth(error),
        Ok(None) | Err(..) => Error::Socket(error.to_string()),
    }
}

/// The socket an app handed over, with a listener for watchword's
/// broadcasts on it. Dropping it stops listening.
#[derive(Default)]
pub(super) struct Socket {
    handle: Option<SocketHandle>,
    _listener: ws::Listener,
}

impl Socket {
    /// The socket, if one is set.
    pub(super) fn handle(&self) -> Option<&SocketHandle> {
        self.handle.as_ref()
    }

    /// Listens on `handle` instead, calling `on_update` with each
    /// [`AuthUpdate`]. The same socket again changes nothing.
    pub(super) fn set(&mut self, handle: Option<&SocketHandle>, on_update: Callback<AuthUpdate>) {
        if self.handle.as_ref() == handle {
            return;
        }

        *self = match handle {
            Some(handle) => Self {
                handle: Some(handle.clone()),
                _listener: listen(handle.handle(), on_update),
            },
            None => Self::default(),
        };
    }
}

/// Calls `on_update` with each [`AuthBroadcast`] on `handle`, until the
/// returned listener is dropped. A broadcast that does not decode, such as
/// from a newer server, is dropped.
fn listen(handle: &ws::Handle, on_update: Callback<AuthUpdate>) -> ws::Listener {
    handle.on_broadcast::<AuthBroadcast>(
        move |result: Result<ws::Packet<AuthBroadcast>, ws::Error>| {
            if let Ok(update) = result.and_then(|packet| packet.decode_event()) {
                on_update.emit(update);
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::pin;
    use std::task::{Context, Poll, Waker};

    use musli_web06::web03::prelude::ws;
    use yew::Callback;

    use watchword_core::musliweb06::MeRequest;

    use watchword_core::PAGE_SESSION_HEADER;
    use watchword_core::musliweb06::SESSION_ENDED;

    use super::{Error, SocketHandle, SocketState, insert_page_session, request_error};

    fn poll<F: Future>(future: F) -> Poll<F::Output> {
        pin!(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn unsent_request_falls_back() {
        // A handle without a service is not connected, so nothing is sent.
        let socket = SocketHandle::new(ws::Handle::default(), Callback::noop());
        let answer = poll(socket.request(MeRequest));
        assert!(matches!(answer, Poll::Ready(None)));
    }

    #[test]
    fn socket_without_service_is_closed() {
        let socket = SocketHandle::new(ws::Handle::default(), Callback::noop());
        assert!(!socket.is_open());
    }

    #[test]
    fn metadata_carries_the_page_session() {
        let mut metadata = ws::Metadata::new();
        insert_page_session(&mut metadata, Some("credential"));
        assert_eq!(metadata.get(PAGE_SESSION_HEADER), Some("credential"));
        assert_eq!(metadata.len(), 1);
    }

    #[test]
    fn metadata_without_a_page_session_is_empty() {
        let mut metadata = ws::Metadata::new();
        insert_page_session(&mut metadata, None);
        assert!(metadata.is_empty());

        // Off the browser there is no page session.
        super::socket_metadata(&mut metadata);
        assert!(metadata.is_empty());
    }

    #[test]
    fn only_session_ended_ends_the_session() {
        assert_eq!(
            SocketState::from_refused(SESSION_ENDED),
            SocketState::SessionEnded
        );
        assert_eq!(SocketState::from_refused(4000), SocketState::Closed);
        assert_eq!(SocketState::from_state(&ws::State::Open), SocketState::Open);
        assert_eq!(
            SocketState::from_state(&ws::State::Closed),
            SocketState::Closed
        );
    }

    #[test]
    fn untyped_error_is_socket_error() {
        let error = request_error(&ws::Error::message("internal error"));
        assert!(matches!(error, Error::Socket(..)));
    }
}
