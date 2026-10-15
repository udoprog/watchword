//! The app's musli-web socket, as handed over with
//! [`AuthContext::set_socket`](super::AuthContext::set_socket).

use musli_web04::web03::prelude::ws;
use yew::Callback;

use watchword_core::musliweb04::{AuthBroadcast, AuthUpdate};

/// The socket an app handed over, with a listener for watchword's
/// broadcasts on it. Dropping it stops listening.
#[derive(Default)]
pub(super) struct Socket {
    handle: Option<ws::Handle>,
    _listener: ws::Listener,
}

impl Socket {
    /// The socket's handle, if one is set.
    pub(super) fn handle(&self) -> Option<&ws::Handle> {
        self.handle.as_ref()
    }

    /// Listens on `handle` instead, calling `on_update` with each
    /// [`AuthUpdate`]. Returns whether the socket changed.
    pub(super) fn set(
        &mut self,
        handle: Option<&ws::Handle>,
        on_update: Callback<AuthUpdate>,
    ) -> bool {
        if self.handle.as_ref() == handle {
            return false;
        }

        *self = match handle {
            Some(handle) => Self {
                handle: Some(handle.clone()),
                _listener: listen(handle, on_update),
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
