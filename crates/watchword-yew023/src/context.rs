use std::rc::Rc;

#[cfg(feature = "musliweb04")]
use musli_web04::web03::prelude::ws;
use yew::prelude::*;

use watchword_core::{AuthConfig, UserInfo};

use super::client::Client;
#[cfg(feature = "musliweb04")]
use super::socket::SocketHandle;

/// The signed-in user and what the app can do about the session, given by
/// [`AuthProvider`](super::AuthProvider) to its children. Get it with
/// [`use_auth`], or with `ctx.link().context::<AuthContext>(..)` in a struct
/// component.
#[derive(Clone, PartialEq)]
pub struct AuthContext {
    /// The signed-in user.
    pub user: Rc<UserInfo>,
    /// What the server offers, from `GET /api/auth/config`.
    pub config: AuthConfig,
    pub(super) sign_out: Callback<()>,
    pub(super) refresh: Callback<()>,
    pub(super) set_user: Callback<UserInfo>,
    pub(super) check_session: Callback<()>,
    /// The app's socket, from [`AuthContext::set_socket`].
    #[cfg(feature = "musliweb04")]
    pub(super) socket: Option<SocketHandle>,
    #[cfg(feature = "musliweb04")]
    pub(super) set_socket: Callback<Option<ws::Handle>>,
}

impl AuthContext {
    /// Whether the signed-in user is an admin.
    pub fn is_admin(&self) -> bool {
        self.user.is_admin()
    }

    /// Signs out and shows the sign-in page. The session is forgotten here
    /// even if the server cannot be reached; it then expires on the server.
    pub fn sign_out(&self) {
        self.sign_out.emit(());
    }

    /// Fetches the user and the config again, such as after the app learns
    /// that the user changed. With a socket from
    /// [`set_socket`](AuthContext::set_socket) (feature `musliweb04`), the
    /// user is asked for over it while it is open. A 401 shows the sign-in
    /// page with the provider's `signed_out_notice`; other failures keep what
    /// is shown.
    pub fn refresh(&self) {
        self.refresh.emit(());
    }

    /// Replaces the signed-in user, such as with the [`UserInfo`] an account
    /// route answered with. A copy of the same user without
    /// [`impersonated_by`](UserInfo::impersonated_by), such as from an admin
    /// route, keeps the current one.
    pub fn set_user(&self, user: UserInfo) {
        self.set_user.emit(user);
    }

    /// Asks the server whether the session is still live, such as when the
    /// app's socket closes. A 401 shows the sign-in page with the provider's
    /// `signed_out_notice`; other failures, such as the server being down,
    /// keep the user signed in. A check while one is in flight is dropped.
    pub fn check_session(&self) {
        self.check_session.emit(());
    }

    /// Hands watchword the app's musli-web socket, or takes it back with
    /// `None`. Open the socket inside [`AuthProvider`](super::AuthProvider),
    /// since its upgrade needs the session, and pass its handle here once it
    /// exists; passing the same handle again does nothing.
    ///
    /// With a socket, the components follow the server's
    /// [`AuthBroadcast`](watchword_core::musliweb04::AuthBroadcast): an
    /// [`AuthUpdate::Me`](watchword_core::musliweb04::AuthUpdate::Me)
    /// replaces [`user`](AuthContext::user), and
    /// [`AdminUsers`](super::AdminUsers) applies the user-list updates in
    /// place.
    ///
    /// The components also send the account and admin operations, and
    /// [`refresh`](AuthContext::refresh)'s user, over the socket while it is
    /// open, and over HTTP while it is not, such as while it reconnects. A
    /// request the socket fails after sending it is not sent again, and fails
    /// with [`http::Error::Socket`](super::http::Error::Socket). Signing in
    /// and out, registering, impersonating, the config and
    /// [`check_session`](AuthContext::check_session) always use HTTP. After
    /// impersonating, or stopping it, the socket still speaks for the
    /// session its upgrade carried, so the components use HTTP until it
    /// next closes and reconnects with the new session cookie.
    ///
    /// The socket is forgotten when the session ends, so a later sign-in
    /// hands over the new one.
    ///
    /// ```ignore
    /// let auth = use_auth();
    /// auth.set_socket(Some(service.handle().clone()));
    /// ```
    #[cfg(feature = "musliweb04")]
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "musliweb04")))]
    pub fn set_socket(&self, socket: Option<ws::Handle>) {
        self.set_socket.emit(socket);
    }

    /// The transport for the account and admin requests: the socket, when
    /// one is handed over, and HTTP.
    pub(super) fn client(&self) -> Client {
        Client {
            #[cfg(feature = "musliweb04")]
            socket: self.socket.clone(),
        }
    }
}

/// The [`AuthContext`] of the enclosing [`AuthProvider`](super::AuthProvider).
///
/// # Panics
///
/// Panics outside an `AuthProvider`, whose children are only rendered once
/// a user is signed in.
#[hook]
pub fn use_auth() -> AuthContext {
    use_context::<AuthContext>().expect("use_auth() must be called inside <AuthProvider>")
}
