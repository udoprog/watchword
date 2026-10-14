use std::rc::Rc;

use yew::prelude::*;

use super::browser;
use super::context::AuthContext;
use super::http::{self, Error};
use super::register::Register;
use super::sign_in::SignIn;
use crate::types::{AuthConfig, UserInfo};

/// The default `signed_out_notice` of [`AuthProvider`].
pub const SESSION_ENDED: &str = "Your session has ended. Sign in again.";

/// The properties of [`AuthProvider`].
#[derive(Properties, PartialEq)]
pub struct AuthProviderProps {
    /// The app's name, shown on the splash, sign-in and registration pages.
    #[prop_or_default]
    pub title: Option<AttrValue>,
    /// Shown on the sign-in page when the session ends under the user, as
    /// found by [`AuthContext::check_session`] or [`AuthContext::refresh`].
    #[prop_or(AttrValue::Static(SESSION_ENDED))]
    pub signed_out_notice: AttrValue,
    /// Classes added to the splash, sign-in and registration pages.
    #[prop_or_default]
    pub class: Classes,
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
pub struct AuthProvider {
    state: State,
    config: Option<AuthConfig>,
    register_token: Option<AttrValue>,
    checking: bool,
    on_signed_in: Callback<UserInfo>,
    sign_out: Callback<()>,
    refresh: Callback<()>,
    set_user: Callback<UserInfo>,
    check_session: Callback<()>,
    retry: Callback<MouseEvent>,
}

enum State {
    Loading,
    /// The server could not be reached or answered with an error.
    Unreachable(AttrValue),
    SignedOut {
        notice: Option<AttrValue>,
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
}

impl Component for AuthProvider {
    type Message = Msg;
    type Properties = AuthProviderProps;

    fn create(ctx: &Context<Self>) -> Self {
        let link = ctx.link();
        link.send_message(Msg::Load);

        Self {
            state: State::Loading,
            config: None,
            register_token: browser::register_token().map(AttrValue::from),
            checking: false,
            on_signed_in: link.callback(Msg::SignedIn),
            sign_out: link.callback(|()| Msg::SignOut),
            refresh: link.callback(|()| Msg::Refresh),
            set_user: link.callback(Msg::SetUser),
            check_session: link.callback(|()| Msg::CheckSession),
            retry: link.callback(|_| Msg::Load),
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
                        self.state = State::Unreachable(unreachable(&error));
                        return true;
                    }
                };

                self.config = Some(config);

                self.state = match me {
                    _ if self.register_token.is_some() => State::Register,
                    Some(Ok(user)) => State::SignedIn(Rc::new(user)),
                    Some(Err(error)) if error.is_unauthorized() => {
                        State::SignedOut { notice: None }
                    }
                    Some(Err(error)) => State::Unreachable(unreachable(&error)),
                    None => State::SignedOut { notice: None },
                };
            }
            Msg::SignedIn(user) => {
                if self.register_token.take().is_some() {
                    browser::replace_url("/");
                }

                self.state = State::SignedIn(Rc::new(user));
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
                self.state = State::SignedOut { notice: None };
            }
            Msg::Refresh => {
                ctx.link().send_future(async {
                    Msg::Refreshed {
                        config: http::config().await,
                        me: http::me().await,
                    }
                });

                return false;
            }
            Msg::Refreshed { config, me } => {
                if let Ok(config) = config {
                    self.config = Some(config);
                }

                self.session_answer(ctx, me);
            }
            Msg::SetUser(user) => {
                if !matches!(self.state, State::SignedIn(..)) {
                    return false;
                }

                self.state = State::SignedIn(Rc::new(user));
            }
            Msg::CheckSession => {
                if self.checking {
                    return false;
                }

                self.checking = true;
                ctx.link()
                    .send_future(async { Msg::Checked(http::me().await) });
                return false;
            }
            Msg::Checked(me) => {
                self.checking = false;
                self.session_answer(ctx, me);
            }
        }

        true
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
            State::Unreachable(message) => html! {
                <main class={classes!("auth-page", "auth-splash", props.class.clone())}>
                    if let Some(title) = &props.title {
                        <p class="auth-title">{title.clone()}</p>
                    }

                    <div class="auth-message" role="alert">
                        <p class="auth-error">{message.clone()}</p>
                    </div>

                    <div class="auth-actions">
                        <button type="button" class="auth-retry" onclick={self.retry.clone()}>{"Retry"}</button>
                    </div>
                </main>
            },
            State::SignedOut { notice } => html! {
                <SignIn
                    {config}
                    on_sign_in={self.on_signed_in.clone()}
                    notice={notice.clone()}
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
    /// Applies what the server said about the session to a signed-in user:
    /// a new user replaces it, and a 401 ends the session. Other failures,
    /// and answers arriving after signing out, change nothing.
    fn session_answer(&mut self, ctx: &Context<Self>, me: Result<UserInfo, Error>) {
        if !matches!(self.state, State::SignedIn(..)) {
            return;
        }

        match me {
            Ok(user) => {
                self.state = State::SignedIn(Rc::new(user));
            }
            Err(error) if error.is_unauthorized() => {
                self.state = State::SignedOut {
                    notice: Some(ctx.props().signed_out_notice.clone()),
                };
            }
            Err(..) => {}
        }
    }
}

fn unreachable(error: &Error) -> AttrValue {
    match error {
        Error::Network(..) => AttrValue::from("Could not reach the server."),
        error => AttrValue::from(format!(
            "The server could not be asked who is signed in: {error}."
        )),
    }
}
