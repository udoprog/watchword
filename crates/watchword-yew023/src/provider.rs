use std::rc::Rc;
#[cfg(feature = "musliweb04")]
use std::time::Duration;

#[cfg(feature = "musliweb04")]
use musli_web04::web03::prelude::ws;
use phrasebook01::Phrases;
use yew::context::ContextHandle;
use yew::prelude::*;

use super::browser;
use super::client::Client;
use super::context::AuthContext;
use super::http::{self, Error};
use super::l10n;
#[cfg(feature = "musliweb04")]
use super::listener::Subscribers;
use super::register::Register;
use super::sign_in::SignIn;
#[cfg(feature = "musliweb04")]
use super::socket::{Socket, SocketHandle};
use super::users::UsersStore;
#[cfg(feature = "musliweb04")]
use watchword_core::musliweb04::AuthUpdate;
use watchword_core::{AuthConfig, UserInfo};

/// The properties of [`AuthProvider`].
#[derive(Properties, PartialEq)]
pub struct AuthProviderProps {
    /// The app's name, shown on the splash, sign-in and registration pages.
    #[prop_or_default]
    pub title: Option<AttrValue>,
    /// Shown on the sign-in page when the session ends under the user, as
    /// found by [`AuthContext::check_session`] or [`AuthContext::refresh`].
    /// Defaults to the message `watchword-session-ended`, "Your session has
    /// ended. Sign in again."
    #[prop_or_default]
    pub signed_out_notice: Option<AttrValue>,
    /// Classes added to the splash, sign-in and registration pages.
    #[prop_or_default]
    pub class: Classes,
    /// The app's sign-in page, such as `/login`: the path watchword's
    /// `axum08::RequireSession` sends a browser to with a `?next=`. A user
    /// who is signed in there already goes on to its `?next=`, and one who
    /// signs in there without one goes to `/`, so the app never renders
    /// this path itself.
    #[prop_or_default]
    pub sign_in_path: Option<AttrValue>,
    /// The app, rendered once a user is signed in.
    #[prop_or_default]
    pub children: Html,
}

/// The gate in front of the app.
///
/// It fetches `/api/auth/config` and `/api/auth/me`, showing a splash while
/// loading and a splash with Retry when the server is unreachable. Signed
/// out, it shows [`SignIn`]; on a `/register/{token}` page it shows
/// [`Register`]. Once a user is signed in it renders its children with an
/// [`AuthContext`], available through [`use_auth`](super::use_auth).
///
/// Signing in returns to a `?next=` in the URL, as watchword's
/// `axum08::RequireSession` redirects with, before the children are
/// rendered, so the app's router starts on that page. Only a path on this
/// origin is followed (never `//host` or a URL with a scheme); any other
/// `next` is dropped. See also
/// [`sign_in_path`](AuthProviderProps::sign_in_path). Sign-in with Google
/// leaves the page and comes back to the same `next` (checked again by the
/// server), or else to the page it left.
///
/// With the `musliweb04` feature and a socket handed over with
/// [`AuthContext::set_socket`], it also follows the server's
/// [`AuthUpdate::Me`](watchword_core::musliweb04::AuthUpdate::Me) (and the
/// user [`Resync`](watchword_core::musliweb04::AuthUpdate::Resync) carries),
/// so a change to the user made elsewhere, such as an admin changing their
/// role, shows at once. It passes each update on to the app's
/// [`AuthContext::on_update`] listeners, and the user-list updates to the
/// shared [`Users`](super::Users).
///
/// Its text, and that of the pages it shows, comes from the
/// [`Phrases`](phrasebook01::Phrases) the app provides around it, falling
/// back to watchword's English (see [`L10N`](super::L10N)).
pub struct AuthProvider {
    state: State,
    phrases: Phrases,
    /// Keeps this subscribed to the app's phrases.
    _phrases: Option<ContextHandle<Phrases>>,
    config: Option<AuthConfig>,
    register_token: Option<AttrValue>,
    checking: bool,
    on_signed_in: Callback<UserInfo>,
    sign_out: Callback<()>,
    refresh: Callback<()>,
    set_user: Callback<UserInfo>,
    check_session: Callback<()>,
    retry: Callback<MouseEvent>,
    #[cfg(feature = "musliweb04")]
    socket: Socket,
    #[cfg(feature = "musliweb04")]
    set_socket: Callback<Option<ws::Handle>>,
    #[cfg(feature = "musliweb04")]
    on_update: Callback<AuthUpdate>,
    #[cfg(feature = "musliweb04")]
    on_socket_state: Callback<bool>,
    /// Counts the socket's changes, so that a [`Msg::SocketClosed`] from
    /// before the latest one is ignored.
    #[cfg(feature = "musliweb04")]
    socket_watch: u64,
    /// The users list the children share.
    users: UsersStore,
    /// The app's listeners for the socket's updates.
    #[cfg(feature = "musliweb04")]
    updates: Subscribers<AuthUpdate>,
}

/// How often the session is checked while the app's socket stays closed.
/// musli-web retries the socket with backoff up to a few seconds, and the
/// browser does not say why an upgrade failed, so a socket refused for an
/// ended session only shows as one that does not open.
#[cfg(feature = "musliweb04")]
const CLOSED_SOCKET_CHECK: Duration = Duration::from_secs(10);

enum State {
    Loading,
    /// The server could not be reached or answered with an error.
    Unreachable(Error),
    SignedOut {
        /// Whether the session ended under the user.
        ended: bool,
    },
    Register,
    SignedIn(Rc<UserInfo>),
}

/// The messages of [`AuthProvider`].
pub enum Msg {
    Load,
    Loaded {
        config: Result<AuthConfig, Error>,
        me: Option<Result<UserInfo, Error>>,
    },
    SignedIn(UserInfo),
    SignOut,
    SignedOut,
    Refresh,
    Refreshed {
        config: Result<AuthConfig, Error>,
        me: Result<UserInfo, Error>,
    },
    SetUser(UserInfo),
    CheckSession,
    Checked(Result<UserInfo, Error>),
    #[cfg(feature = "musliweb04")]
    SetSocket(Option<ws::Handle>),
    #[cfg(feature = "musliweb04")]
    Update(AuthUpdate),
    /// The socket opened (`true`) or closed (`false`).
    #[cfg(feature = "musliweb04")]
    SocketState(bool),
    /// The socket has stayed closed for [`CLOSED_SOCKET_CHECK`] since the
    /// [`socket_watch`](AuthProvider::socket_watch) this carries.
    #[cfg(feature = "musliweb04")]
    SocketClosed(u64),
    Phrases(Phrases),
}

impl Component for AuthProvider {
    type Message = Msg;
    type Properties = AuthProviderProps;

    fn create(ctx: &Context<Self>) -> Self {
        let link = ctx.link();
        link.send_message(Msg::Load);
        let check_session = link.callback(|()| Msg::CheckSession);

        let context = link.context::<Phrases>(link.callback(Msg::Phrases));
        let phrases = l10n::phrases(context.as_ref().map(|(phrases, _)| phrases.clone()));

        Self {
            state: State::Loading,
            phrases,
            _phrases: context.map(|(_, handle)| handle),
            config: None,
            register_token: browser::register_token().map(AttrValue::from),
            checking: false,
            on_signed_in: link.callback(Msg::SignedIn),
            sign_out: link.callback(|()| Msg::SignOut),
            refresh: link.callback(|()| Msg::Refresh),
            set_user: link.callback(Msg::SetUser),
            check_session: check_session.clone(),
            retry: link.callback(|_| Msg::Load),
            #[cfg(feature = "musliweb04")]
            socket: Socket::default(),
            #[cfg(feature = "musliweb04")]
            set_socket: link.callback(Msg::SetSocket),
            #[cfg(feature = "musliweb04")]
            on_update: link.callback(Msg::Update),
            #[cfg(feature = "musliweb04")]
            on_socket_state: link.callback(Msg::SocketState),
            #[cfg(feature = "musliweb04")]
            socket_watch: 0,
            users: UsersStore::new(Client::default(), check_session),
            #[cfg(feature = "musliweb04")]
            updates: Subscribers::default(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Load => {
                self.state = State::Loading;
                let register = self.register_token.is_some();

                ctx.link().send_future(async move {
                    let config = http::config().await;

                    // A link's page does not need the user, and the user is
                    // not worth asking for without the config.
                    let me = match &config {
                        Ok(..) if !register => Some(http::me().await),
                        _ => None,
                    };

                    Msg::Loaded { config, me }
                });
            }
            Msg::Loaded { config, me } => {
                let config = match config {
                    Ok(config) => config,
                    Err(error) => {
                        self.state = State::Unreachable(error);
                        return true;
                    }
                };

                self.config = Some(config);

                if self.register_token.is_none() && matches!(me, Some(Ok(..))) {
                    browser::return_after_sign_in(ctx.props().sign_in_path.as_deref(), true);
                }

                self.state = match me {
                    _ if self.register_token.is_some() => State::Register,
                    Some(Ok(user)) => State::SignedIn(Rc::new(user)),
                    Some(Err(error)) if error.is_unauthorized() => {
                        State::SignedOut { ended: false }
                    }
                    Some(Err(error)) => State::Unreachable(error),
                    None => State::SignedOut { ended: false },
                };
            }
            Msg::SignedIn(user) => {
                if self.register_token.take().is_some() {
                    browser::replace_url("/");
                } else {
                    browser::return_after_sign_in(ctx.props().sign_in_path.as_deref(), false);
                }

                self.signed_in_as(user);
            }
            Msg::SignOut => {
                ctx.link().send_future(async {
                    // The session is forgotten here either way; a failed
                    // request leaves it to expire on the server.
                    let _ = http::logout().await;
                    Msg::SignedOut
                });

                return false;
            }
            Msg::SignedOut => {
                browser::replace_url("/");
                self.state = State::SignedOut { ended: false };
            }
            Msg::Refresh => {
                let client = self.client();

                ctx.link().send_future(async move {
                    Msg::Refreshed {
                        config: http::config().await,
                        me: client.me().await,
                    }
                });

                return false;
            }
            Msg::Refreshed { config, me } => {
                if let Ok(config) = config {
                    self.config = Some(config);
                }

                self.session_answer(me);
            }
            Msg::SetUser(user) => {
                let State::SignedIn(current) = &self.state else {
                    return false;
                };

                let user = replace_user(current, user);
                self.signed_in_as(user);
            }
            Msg::CheckSession => {
                self.check_session(ctx);
                return false;
            }
            Msg::Checked(me) => {
                self.checking = false;
                self.session_answer(me);
            }
            #[cfg(feature = "musliweb04")]
            Msg::SetSocket(handle) => {
                if !matches!(self.state, State::SignedIn(..)) {
                    return false;
                }

                if self.socket.handle().map(SocketHandle::handle) == handle.as_ref() {
                    return false;
                }

                let handle =
                    handle.map(|handle| SocketHandle::new(handle, self.on_socket_state.clone()));
                let changed = self.socket.set(handle.as_ref(), self.on_update.clone());
                self.users.set_client(self.client());

                // A socket handed over closed may be refused already. The
                // session was just checked to show the app, so the first
                // check waits.
                self.socket_watch += 1;

                if handle.as_ref().is_some_and(|handle| !handle.is_open()) {
                    self.watch_closed_socket(ctx);
                }

                return changed;
            }
            #[cfg(feature = "musliweb04")]
            Msg::SocketState(open) => {
                // Only the current socket's changes count.
                if !matches!(self.state, State::SignedIn(..))
                    || self.socket.handle().map(SocketHandle::is_open) != Some(open)
                {
                    return false;
                }

                self.socket_watch += 1;

                // Closing after being open: the session may have ended, such
                // as by being revoked. While it stays closed, its reconnects
                // may be refused for the same reason.
                if !open {
                    self.check_session(ctx);
                    self.watch_closed_socket(ctx);
                }

                return false;
            }
            #[cfg(feature = "musliweb04")]
            Msg::SocketClosed(watch) => {
                if watch != self.socket_watch
                    || !matches!(self.state, State::SignedIn(..))
                    || !self.socket.handle().is_some_and(|handle| !handle.is_open())
                {
                    return false;
                }

                self.check_session(ctx);
                self.watch_closed_socket(ctx);
                return false;
            }
            #[cfg(feature = "musliweb04")]
            Msg::Update(update) => {
                if !matches!(self.state, State::SignedIn(..)) {
                    return false;
                }

                // A stale socket's user is the session's before impersonating
                // or stopping it, not this browser's.
                let stale = self.socket.handle().is_some_and(SocketHandle::is_stale);

                // `Resync`, after the server missed updates, carries the user
                // as `Me` does. `Me` is set as the server answers `Me`,
                // impersonation marker included, so it replaces the user as
                // it is.
                let user = match &update {
                    AuthUpdate::Me(user) | AuthUpdate::Resync(user) => {
                        if stale {
                            return false;
                        }

                        Some(user.clone())
                    }
                    _ => None,
                };

                self.users.apply(update.clone());
                self.updates.emit(update);

                let Some(user) = user else {
                    return false;
                };

                self.signed_in_as(user);
            }
            Msg::Phrases(phrases) => {
                self.phrases = l10n::phrases(Some(phrases));
            }
        }

        true
    }

    /// Every change of state renders, so this sees each one.
    fn rendered(&mut self, _: &Context<Self>, _: bool) {
        if matches!(self.state, State::SignedIn(..)) {
            return;
        }

        // The socket belongs to the session: the app's own, inside the
        // children, closes with it, and a new sign-in opens another.
        #[cfg(feature = "musliweb04")]
        if self.socket.handle().is_some() {
            self.socket = Socket::default();
            self.users.set_client(self.client());
        }

        // So is the users list.
        self.users.clear();
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let props = ctx.props();

        let config = self.config.unwrap_or(AuthConfig {
            password: false,
            google: false,
            cloudflare: false,
            logins: false,
        });

        match &self.state {
            State::Loading => html! {
                <main class={classes!("auth-page", "auth-splash", props.class.clone())} aria-busy="true">
                    if let Some(title) = &props.title {
                        <p class="auth-title">{title.clone()}</p>
                    }
                </main>
            },
            State::Unreachable(error) => html! {
                <main class={classes!("auth-page", "auth-splash", props.class.clone())}>
                    if let Some(title) = &props.title {
                        <p class="auth-title">{title.clone()}</p>
                    }

                    <div class="auth-message" role="alert">
                        <p class="auth-error">{unreachable(&self.phrases, error)}</p>
                    </div>

                    <div class="auth-actions">
                        <button type="button" class="auth-retry" onclick={self.retry.clone()}>{self.phrases.text("watchword-retry")}</button>
                    </div>
                </main>
            },
            State::SignedOut { ended } => html! {
                <SignIn
                    {config}
                    on_sign_in={self.on_signed_in.clone()}
                    notice={ended.then(|| self.signed_out_notice(props))}
                    title={props.title.clone()}
                    class={props.class.clone()}
                />
            },
            State::Register => match &self.register_token {
                Some(token) => html! {
                    <Register
                        token={token.clone()}
                        on_register={self.on_signed_in.clone()}
                        title={props.title.clone()}
                        class={props.class.clone()}
                    />
                },
                None => Html::default(),
            },
            State::SignedIn(user) => {
                let context = AuthContext {
                    user: user.clone(),
                    config,
                    sign_out: self.sign_out.clone(),
                    refresh: self.refresh.clone(),
                    set_user: self.set_user.clone(),
                    check_session: self.check_session.clone(),
                    #[cfg(feature = "musliweb04")]
                    socket: self.socket.handle().cloned(),
                    #[cfg(feature = "musliweb04")]
                    set_socket: self.set_socket.clone(),
                    users: self.users.clone(),
                    #[cfg(feature = "musliweb04")]
                    updates: self.updates.clone(),
                };

                html! {
                    <ContextProvider<AuthContext> {context}>
                        {props.children.clone()}
                    </ContextProvider<AuthContext>>
                }
            }
        }
    }
}

impl AuthProvider {
    /// Asks the server whether the session is still live, unless a check is
    /// in flight.
    fn check_session(&mut self, ctx: &Context<Self>) {
        if self.checking {
            return;
        }

        self.checking = true;
        ctx.link()
            .send_future(async { Msg::Checked(http::me().await) });
    }

    /// Sends [`Msg::SocketClosed`] after [`CLOSED_SOCKET_CHECK`], for the
    /// current [`socket_watch`](Self::socket_watch).
    #[cfg(feature = "musliweb04")]
    fn watch_closed_socket(&self, ctx: &Context<Self>) {
        let watch = self.socket_watch;

        ctx.link().send_future(async move {
            yew::platform::time::sleep(CLOSED_SOCKET_CHECK).await;
            Msg::SocketClosed(watch)
        });
    }

    /// The transport for the requests that can use the socket.
    fn client(&self) -> Client {
        Client {
            #[cfg(feature = "musliweb04")]
            socket: self.socket.handle().cloned(),
        }
    }

    /// The notice shown when the session ended under the user.
    fn signed_out_notice(&self, props: &AuthProviderProps) -> AttrValue {
        match &props.signed_out_notice {
            Some(notice) => notice.clone(),
            None => l10n::text(&self.phrases, "watchword-session-ended"),
        }
    }

    /// Shows `user` as the signed-in user. When it is someone else, their
    /// role changed, or the impersonation did, the users list was for the
    /// session as it was, so it is fetched again.
    fn signed_in_as(&mut self, user: UserInfo) {
        if let State::SignedIn(current) = &self.state
            && !same_rights(current, &user)
        {
            self.users.invalidate();
        }

        self.state = State::SignedIn(Rc::new(user));
    }

    /// Applies what the server said about the session to a signed-in user:
    /// a new user replaces it, and a 401 ends the session. Other failures,
    /// and answers arriving after signing out, change nothing.
    fn session_answer(&mut self, me: Result<UserInfo, Error>) {
        if !matches!(self.state, State::SignedIn(..)) {
            return;
        }

        match me {
            Ok(user) => {
                self.signed_in_as(user);
            }
            Err(error) if error.is_unauthorized() => {
                self.state = State::SignedOut { ended: true };
            }
            Err(..) => {}
        }
    }
}

/// The signed-in user after [`AuthContext::set_user`] with `new`. Only the
/// answers about the own user mark an impersonated session, so an unmarked
/// copy of the same user, such as from the admin routes, keeps the mark: the
/// session is the same until the user changes.
pub(super) fn replace_user(current: &UserInfo, mut new: UserInfo) -> UserInfo {
    if new.id == current.id && new.impersonated_by.is_none() {
        new.impersonated_by = current.impersonated_by.clone();
    }

    new
}

/// Whether `a` and `b` are the same user with the same role, under the same
/// impersonation, so that what they may list is the same.
pub(super) fn same_rights(a: &UserInfo, b: &UserInfo) -> bool {
    a.id == b.id && a.role == b.role && a.impersonated_by == b.impersonated_by
}

fn unreachable(phrases: &Phrases, error: &Error) -> AttrValue {
    match error {
        Error::Network(..) => l10n::text(phrases, "watchword-error-unreachable"),
        error => l10n::failed(phrases, "watchword-failed-checking-session", error),
    }
}
