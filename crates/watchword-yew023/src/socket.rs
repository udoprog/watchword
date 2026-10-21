//! The app's musli-web socket, as handed over with
//! [`AuthContext::set_socket`](super::AuthContext::set_socket).

use std::cell::Cell;
use std::rc::Rc;
use std::string::ToString;

use musli_web05::api;
use musli_web05::web03::prelude::ws;
use yew::Callback;

use watchword_core::AuthError;
use watchword_core::musliweb05::{AuthBroadcast, AuthUpdate};

use super::http::Error;

/// A socket handed over to the provider, as the context carries it. Clones
/// share whether the socket is stale.
#[derive(Clone)]
pub(super) struct SocketHandle {
    inner: Rc<Inner>,
}

struct Inner {
    handle: ws::Handle,
    stale: Rc<Cell<bool>>,
    open: Rc<Cell<bool>>,
    _state: ws::StateListener,
}

impl SocketHandle {
    /// Follows `handle`'s state, calling `on_state` with whether it is open
    /// each time that changes.
    pub(super) fn new(handle: ws::Handle, on_state: Callback<bool>) -> Self {
        let stale = Rc::new(Cell::new(false));
        let open = Rc::new(Cell::new(false));

        // The socket's session is the one its upgrade carried, so once it
        // closes, its reconnect carries the browser's current one.
        let (state, listener) = handle.on_state_change({
            let stale = stale.clone();
            let open = open.clone();

            move |state: ws::State| {
                if !state.is_open() {
                    stale.set(false);
                }

                if open.replace(state.is_open()) != state.is_open() {
                    on_state.emit(state.is_open());
                }
            }
        });

        open.set(state.is_open());

        Self {
            inner: Rc::new(Inner {
                handle,
                stale,
                open,
                _state: listener,
            }),
        }
    }

    /// Whether the socket is open.
    pub(super) fn is_open(&self) -> bool {
        self.inner.open.get()
    }

    /// The app's handle.
    pub(super) fn handle(&self) -> &ws::Handle {
        &self.inner.handle
    }

    /// Marks the socket as speaking for a session this browser no longer
    /// uses, after a response replaced the session cookie (impersonating,
    /// and stopping it). Until the socket closes, requests go over HTTP and
    /// its [`AuthUpdate::Me`] is ignored.
    pub(super) fn mark_stale(&self) {
        self.inner.stale.set(true);
    }

    /// Whether the socket is [stale](Self::mark_stale).
    pub(super) fn is_stale(&self) -> bool {
        self.inner.stale.get()
    }

    /// Sends `body` over the socket and waits for the answer. `None` when the
    /// socket is stale, or musli-web did not send it since the socket is not
    /// connected (such as while it reconnects), so that nothing reached the
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
        if self.is_stale() {
            return None;
        }

        match self.handle().call(body).await {
            Ok(value) => Some(Ok(value)),
            Err(error) if error.is_not_connected() => None,
            Err(error) => Some(Err(request_error(&error))),
        }
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
    /// [`AuthUpdate`]. Returns whether the socket changed.
    pub(super) fn set(
        &mut self,
        handle: Option<&SocketHandle>,
        on_update: Callback<AuthUpdate>,
    ) -> bool {
        if self.handle.as_ref() == handle {
            return false;
        }

        *self = match handle {
            Some(handle) => Self {
                handle: Some(handle.clone()),
                _listener: listen(handle.handle(), on_update),
            },
            None => Self::default(),
        };

        true
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

    use musli_web05::web03::prelude::ws;
    use yew::Callback;

    use watchword_core::musliweb05::MeRequest;

    use super::{Error, SocketHandle, request_error};

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
    fn stale_socket_falls_back() {
        let socket = SocketHandle::new(ws::Handle::default(), Callback::noop());
        assert!(!socket.is_stale());

        socket.clone().mark_stale();
        assert!(socket.is_stale());

        let answer = poll(socket.request(MeRequest));
        assert!(matches!(answer, Poll::Ready(None)));
    }

    #[test]
    fn untyped_error_is_socket_error() {
        let error = request_error(&ws::Error::message("internal error"));
        assert!(matches!(error, Error::Socket(..)));
    }
}
