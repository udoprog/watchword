use core::ops::Deref;
use std::rc::Rc;

#[cfg(feature = "musliweb04")]
use musli_web04::web03::prelude::ws;
use yew::context::ContextHandle;
use yew::prelude::*;

#[cfg(feature = "musliweb04")]
use watchword_core::musliweb04::AuthUpdate;
use watchword_core::{AuthConfig, UserInfo};

use super::client::Client;
use super::listener::Listener;
#[cfg(feature = "musliweb04")]
use super::listener::Subscribers;
#[cfg(feature = "musliweb04")]
use super::socket::SocketHandle;
use super::users::{Users, UsersStore};

/// The signed-in user and what the app can do about the session, given by
/// [`AuthProvider`](super::AuthProvider) to its children. Get it with
/// [`use_auth`], or with [`AuthSubscription`] in a struct component.
///
/// The provider gives a new context whenever the user or the config
/// changes, such as when an admin changes the user's role elsewhere and the
/// server broadcasts it (feature `musliweb04`), so a component that reads
/// the context through [`use_auth`], [`use_is_admin`] or [`AuthSubscription`]
/// renders again with it. An app does not need to forward watchword's
/// events into its own broadcasts for that: see also
/// [`on_update`](AuthContext::on_update) for the updates themselves and
/// [`use_users`](super::use_users) for the users list.
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
    /// The users list shared inside the provider.
    pub(super) users: UsersStore,
    /// The app's listeners for the socket's updates.
    #[cfg(feature = "musliweb04")]
    pub(super) updates: Subscribers<AuthUpdate>,
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
    /// app learns that it may have ended. With a socket from
    /// [`set_socket`](AuthContext::set_socket) (feature `musliweb04`), this
    /// runs by itself when the socket closes. A 401 shows the sign-in page with the provider's
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
    /// The provider also [checks the session](AuthContext::check_session)
    /// when the socket closes after being open, and every 10 seconds while
    /// it stays closed, including when it is handed over closed. Browsers do
    /// not say why a WebSocket upgrade failed, so an upgrade refused because
    /// the session ended only shows as a socket that closes or does not
    /// open; a 401 from the check then shows the sign-in page. The app needs
    /// no state listener of its own for this, and should take the socket
    /// back with `None` if it drops it while signed in, since a dropped
    /// socket stays closed.
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

    /// The users list shared inside the provider, as it is now, and a
    /// listener that calls `callback` with it each time it changes, for a
    /// struct component. The list is fetched when the first component asks
    /// for it; see [`Users`]. Function components use
    /// [`use_users`](super::use_users).
    ///
    /// ```ignore
    /// struct Groups {
    ///     auth: AuthSubscription,
    ///     users: Users,
    ///     _users: Listener,
    /// }
    ///
    /// enum Msg {
    ///     Auth(AuthContext),
    ///     Users(Users),
    /// }
    ///
    /// impl Component for Groups {
    ///     type Message = Msg;
    ///     type Properties = ();
    ///
    ///     fn create(ctx: &Context<Self>) -> Self {
    ///         let auth = AuthSubscription::new(ctx, Msg::Auth);
    ///         let (users, _users) = auth.subscribe_users(ctx.link().callback(Msg::Users));
    ///         Self { auth, users, _users }
    ///     }
    ///
    ///     fn update(&mut self, _: &Context<Self>, msg: Msg) -> bool {
    ///         match msg {
    ///             Msg::Auth(auth) => self.auth.set(auth),
    ///             Msg::Users(users) => {
    ///                 self.users = users;
    ///                 true
    ///             }
    ///         }
    ///     }
    ///
    ///     // ..
    /// }
    /// ```
    pub fn subscribe_users(&self, callback: Callback<Users>) -> (Users, Listener) {
        self.users.subscribe(callback)
    }

    /// Calls `callback` with each [`AuthUpdate`] the server broadcasts on the
    /// socket handed over with [`set_socket`](AuthContext::set_socket), after
    /// watchword's own components have applied it, until the listener is
    /// dropped. Function components use [`use_auth_update`].
    ///
    /// Most app components need neither this nor a broadcast of their own:
    /// the context follows [`AuthUpdate::Me`] (so [`use_auth`] and
    /// [`AuthSubscription`] render again with the new user), and
    /// [`use_users`](super::use_users) follows the user-list updates. This
    /// is for an app that acts on a change itself, such as reloading its own
    /// data when the user's role changes; the context only shows the new
    /// user once the provider renders again, so read the user from the
    /// update.
    ///
    /// An update for the session before impersonating or stopping it, which
    /// the provider ignores, is not passed on.
    #[cfg(feature = "musliweb04")]
    #[cfg_attr(watchword_docsrs, doc(cfg(feature = "musliweb04")))]
    pub fn on_update(&self, callback: Callback<AuthUpdate>) -> Listener {
        self.updates.subscribe(callback)
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

/// Whether the signed-in user is an admin, following changes to their role.
/// `false` outside an [`AuthProvider`](super::AuthProvider), where nobody is
/// signed in.
#[hook]
pub fn use_is_admin() -> bool {
    use_context::<AuthContext>().is_some_and(|auth| auth.is_admin())
}

/// Calls `f` with each [`AuthUpdate`] the server broadcasts, as
/// [`AuthContext::on_update`] does, for as long as the component lives. The
/// latest `f` given is the one called.
///
/// ```ignore
/// let reload = reload.clone();
///
/// use_auth_update(move |update| {
///     if let AuthUpdate::Me(user) = update {
///         reload.emit(user.role);
///     }
/// });
/// ```
///
/// # Panics
///
/// Panics outside an [`AuthProvider`](super::AuthProvider).
#[cfg(feature = "musliweb04")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "musliweb04")))]
#[hook]
pub fn use_auth_update<F>(f: F)
where
    F: Fn(AuthUpdate) + 'static,
{
    let auth = use_auth();
    let latest = use_mut_ref(|| None::<Rc<dyn Fn(AuthUpdate)>>);
    *latest.borrow_mut() = Some(Rc::new(f));

    let _listener = use_memo(auth.updates.clone(), move |updates| {
        updates.subscribe(Callback::from(move |update| {
            // Not borrowed while `f` runs, which may render this again.
            let f = latest.borrow().clone();

            if let Some(f) = f {
                f(update);
            }
        }))
    });
}

/// The [`AuthContext`] for a struct component, kept current: it subscribes
/// to the context with a message of the component's, so the component
/// renders again when the user, their role or the config changes, where
/// reading the context once with `Callback::noop()` would not.
///
/// ```ignore
/// struct Page {
///     auth: AuthSubscription,
/// }
///
/// enum Msg {
///     Auth(AuthContext),
/// }
///
/// impl Component for Page {
///     type Message = Msg;
///     type Properties = ();
///
///     fn create(ctx: &Context<Self>) -> Self {
///         Self {
///             auth: AuthSubscription::new(ctx, Msg::Auth),
///         }
///     }
///
///     fn update(&mut self, _: &Context<Self>, msg: Msg) -> bool {
///         match msg {
///             Msg::Auth(auth) => self.auth.set(auth),
///         }
///     }
///
///     fn view(&self, _: &Context<Self>) -> Html {
///         html! {
///             if self.auth.is_admin() {
///                 <a href="/admin">{"Admin"}</a>
///             }
///         }
///     }
/// }
/// ```
pub struct AuthSubscription {
    context: AuthContext,
    _handle: ContextHandle<AuthContext>,
}

impl AuthSubscription {
    /// Subscribes `ctx`'s component to the context, sending it the message
    /// `on_change` makes from each new one; pass that to
    /// [`set`](AuthSubscription::set).
    ///
    /// # Panics
    ///
    /// Panics outside an [`AuthProvider`](super::AuthProvider).
    pub fn new<C, M, F>(ctx: &Context<C>, on_change: F) -> Self
    where
        C: Component,
        M: Into<C::Message>,
        F: Fn(AuthContext) -> M + 'static,
    {
        let (context, handle) = ctx
            .link()
            .context::<AuthContext>(ctx.link().callback(on_change))
            .expect("AuthSubscription must be made inside <AuthProvider>");

        Self {
            context,
            _handle: handle,
        }
    }

    /// Replaces the context with a new one from the provider, returning
    /// whether it changed, which is whether to render again.
    pub fn set(&mut self, context: AuthContext) -> bool {
        if self.context == context {
            return false;
        }

        self.context = context;
        true
    }
}

impl Deref for AuthSubscription {
    type Target = AuthContext;

    fn deref(&self) -> &AuthContext {
        &self.context
    }
}
