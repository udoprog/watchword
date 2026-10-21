//! The app's musli-web socket, as handed over with
//! [`AuthContext::set_socket`](super::AuthContext::set_socket).

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::string::String;
use std::string::ToString;
use std::task::{Context, Poll, Waker};

use musli_web04::api;
use musli_web04::web03::prelude::ws;
use yew::Callback;

use watchword_core::AuthError;
use watchword_core::musliweb04::{AuthBroadcast, AuthUpdate};

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
    _state: ws::StateListener,
}

impl SocketHandle {
    pub(super) fn new(handle: ws::Handle) -> Self {
        let stale = Rc::new(Cell::new(false));

        // The socket's session is the one its upgrade carried, so once it
        // closes, its reconnect carries the browser's current one.
        let (_, state) = handle.on_state_change({
            let stale = stale.clone();

            move |state: ws::State| {
                if !state.is_open() {
                    stale.set(false);
                }
            }
        });

        Self {
            inner: Rc::new(Inner {
                handle,
                stale,
                _state: state,
            }),
        }
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
    /// socket is stale, or musli-web refuses to send it (such as while the
    /// socket reconnects), so that nothing reached the server and the caller
    /// sends it over HTTP instead.
    ///
    /// A request the socket fails after sending, such as when it closes
    /// before the answer or the server answers with a request error, is
    /// [`Error::Socket`]: the server may have acted on it, so it is not sent
    /// again.
    pub(super) async fn request<B, T>(&self, body: B) -> Option<Result<T, Error>>
    where
        B: api::Request,
        T: 'static,
        Result<T, AuthError>: for<'de> api::DecodeBody<'de>,
    {
        if self.is_stale() {
            return None;
        }

        let slot = Rc::new(Slot::default());
        let sender = Sender(slot.clone());

        let request = self
            .handle()
            .request()
            .body(body)
            .on_raw_packet(move |result: Result<ws::RawPacket, ws::Error>| {
                sender.send(decode(result));
            })
            .send();

        // musli-web fails a request it could not send before `send` returns.
        if !request.is_pending() && slot.value.borrow().as_ref().is_some_and(Result::is_err) {
            return None;
        }

        Some(
            Answer {
                slot,
                _request: request,
            }
            .await,
        )
    }
}

impl PartialEq for SocketHandle {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.inner, &other.inner)
    }
}

fn decode<T>(result: Result<ws::RawPacket, ws::Error>) -> Result<T, Error>
where
    Result<T, AuthError>: for<'de> api::DecodeBody<'de>,
{
    let packet = result.map_err(socket_error)?;
    packet
        .decode::<Result<T, AuthError>>()
        .map_err(socket_error)?
        .map_err(Error::Auth)
}

fn socket_error(error: ws::Error) -> Error {
    Error::Socket(error.to_string())
}

/// Where a request's callback leaves its answer for [`Answer`].
struct Slot<T> {
    value: RefCell<Option<Result<T, Error>>>,
    waker: RefCell<Option<Waker>>,
}

impl<T> Default for Slot<T> {
    fn default() -> Self {
        Self {
            value: RefCell::new(None),
            waker: RefCell::new(None),
        }
    }
}

/// The request's side of a [`Slot`]. musli-web drops a request's callback
/// without calling it when the socket service itself goes away, so dropping
/// an unanswered sender answers with an error, rather than leaving the
/// request waiting forever.
struct Sender<T>(Rc<Slot<T>>);

impl<T> Sender<T> {
    fn send(&self, value: Result<T, Error>) {
        let mut slot = self.0.value.borrow_mut();

        if slot.is_none() {
            *slot = Some(value);
            drop(slot);

            if let Some(waker) = self.0.waker.borrow_mut().take() {
                waker.wake();
            }
        }
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.send(Err(Error::Socket(String::from(
            "the socket closed before answering",
        ))));
    }
}

/// The answer to a request. Dropping it cancels the request.
struct Answer<T> {
    slot: Rc<Slot<T>>,
    _request: ws::Request,
}

impl<T> Future for Answer<T> {
    type Output = Result<T, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(value) = self.slot.value.borrow_mut().take() {
            return Poll::Ready(value);
        }

        *self.slot.waker.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
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
    use std::boxed::Box;
    use std::future::Future;
    use std::pin::pin;
    use std::rc::Rc;
    use std::task::{Context, Poll, Waker};

    use musli_web04::web03::prelude::ws;

    use watchword_core::UserInfo;
    use watchword_core::musliweb04::MeRequest;

    use super::{Answer, Error, Sender, Slot, SocketHandle, decode};

    fn poll<F: Future>(future: F) -> Poll<F::Output> {
        pin!(future).poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn unsent_request_falls_back() {
        // A handle without a service refuses before sending anything.
        let socket = SocketHandle::new(ws::Handle::default());
        let answer = poll(socket.request::<_, UserInfo>(MeRequest));
        assert!(matches!(answer, Poll::Ready(None)));
    }

    #[test]
    fn stale_socket_falls_back() {
        let socket = SocketHandle::new(ws::Handle::default());
        assert!(!socket.is_stale());

        socket.clone().mark_stale();
        assert!(socket.is_stale());

        let answer = poll(socket.request::<_, UserInfo>(MeRequest));
        assert!(matches!(answer, Poll::Ready(None)));
    }

    #[test]
    fn dropped_request_answers_with_error() {
        let slot = Rc::new(Slot::<()>::default());
        let sender = Sender(slot.clone());

        let mut answer = Box::pin(Answer {
            slot,
            _request: ws::Request::new(),
        });

        let mut cx = Context::from_waker(Waker::noop());
        assert!(answer.as_mut().poll(&mut cx).is_pending());

        drop(sender);

        assert!(matches!(
            answer.as_mut().poll(&mut cx),
            Poll::Ready(Err(Error::Socket(..)))
        ));
    }

    #[test]
    fn first_answer_wins() {
        let slot = Rc::new(Slot::<u32>::default());
        let sender = Sender(slot.clone());
        sender.send(Ok(1));
        drop(sender);

        let answer = Answer {
            slot,
            _request: ws::Request::new(),
        };

        assert!(matches!(poll(answer), Poll::Ready(Ok(1))));
    }

    #[test]
    fn empty_packet_is_socket_error() {
        let result = decode::<UserInfo>(Ok(ws::RawPacket::empty()));
        assert!(matches!(result, Err(Error::Socket(..))));
    }
}
