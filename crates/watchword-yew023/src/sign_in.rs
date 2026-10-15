use yew::platform::spawn_local;
use yew::prelude::*;

use super::browser;
use super::http::{self, Error};
use watchword_core::{AuthConfig, AuthError, LoginRequest, UserInfo};

/// The properties of [`SignIn`].
#[derive(Properties, PartialEq)]
pub struct SignInProps {
    /// Which methods to offer.
    pub config: AuthConfig,
    /// Called with the user once signed in.
    pub on_sign_in: Callback<UserInfo>,
    /// Shown above the form, such as why the user has to sign in again.
    #[prop_or_default]
    pub notice: Option<AttrValue>,
    /// The app's name, shown above the heading.
    #[prop_or_default]
    pub title: Option<AttrValue>,
    /// Classes added to the page.
    #[prop_or_default]
    pub class: Classes,
}

/// The sign-in page, offering the enabled methods: a login (or email) and
/// password form when `config.password` is set, "Sign in with Cloudflare"
/// when `config.cloudflare` is, and "Sign in with Google" when
/// `config.google` is.
///
/// An `?error=` the server redirected with, such as from a failed Google
/// sign-in, is shown and removed from the URL.
#[function_component]
pub fn SignIn(props: &SignInProps) -> Html {
    let login = use_state(String::new);
    let password = use_state(String::new);
    let busy = use_state(|| false);
    let error = use_state(|| None::<AttrValue>);

    {
        let error = error.clone();

        use_effect_with((), move |_| {
            if let Some(code) = browser::take_query_error() {
                error.set(Some(AttrValue::Static(query_error_message(&code))));
            }
        });
    }

    let logins = props.config.logins;

    let on_login_input = {
        let login = login.clone();
        Callback::from(move |e: InputEvent| login.set(browser::input_value(&e)))
    };

    let on_password_input = {
        let password = password.clone();
        Callback::from(move |e: InputEvent| password.set(browser::input_value(&e)))
    };

    let onsubmit = {
        let login = login.clone();
        let password = password.clone();
        let busy = busy.clone();
        let error = error.clone();
        let on_sign_in = props.on_sign_in.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();

            if *busy {
                return;
            }

            busy.set(true);
            error.set(None);

            let request = LoginRequest {
                login: (*login).clone(),
                password: (*password).clone(),
            };

            let busy = busy.clone();
            let error = error.clone();
            let on_sign_in = on_sign_in.clone();

            spawn_local(async move {
                match http::login(&request).await {
                    Ok(user) => on_sign_in.emit(user),
                    Err(e) => {
                        error.set(Some(login_error(&e, logins)));
                        busy.set(false);
                    }
                }
            });
        })
    };

    let on_cloudflare = {
        let busy = busy.clone();
        let error = error.clone();
        let on_sign_in = props.on_sign_in.clone();

        Callback::from(move |_: MouseEvent| {
            if *busy {
                return;
            }

            busy.set(true);
            error.set(None);

            let busy = busy.clone();
            let error = error.clone();
            let on_sign_in = on_sign_in.clone();

            spawn_local(async move {
                match http::cloudflare().await {
                    Ok(user) => on_sign_in.emit(user),
                    Err(e) => {
                        error.set(Some(cloudflare_error(&e)));
                        busy.set(false);
                    }
                }
            });
        })
    };

    let config = props.config;
    let any = config.password || config.cloudflare || config.google;

    let (login_label, login_type, login_autocomplete) = if logins {
        ("Login or email", "text", "username")
    } else {
        ("Email", "email", "email")
    };

    html! {
        <main class={classes!("auth-page", props.class.clone())}>
            <div class="auth-card">
                if let Some(title) = &props.title {
                    <p class="auth-title">{title.clone()}</p>
                }

                <h1 class="auth-heading">{"Sign in"}</h1>

                <div class="auth-message" role="alert">
                    if let Some(error) = &*error {
                        <p class="auth-error">{error.clone()}</p>
                    } else if let Some(notice) = &props.notice {
                        <p class="auth-notice">{notice.clone()}</p>
                    }
                </div>

                if config.password {
                    <form class="auth-form" {onsubmit}>
                        <div class="auth-field">
                            <label for="auth-login">{login_label}</label>
                            <input
                                id="auth-login"
                                class="auth-input"
                                type={login_type}
                                autocomplete={login_autocomplete}
                                autocapitalize="none"
                                spellcheck="false"
                                required=true
                                value={(*login).clone()}
                                oninput={on_login_input}
                                disabled={*busy}
                            />
                        </div>

                        <div class="auth-field">
                            <label for="auth-password">{"Password"}</label>
                            <input
                                id="auth-password"
                                class="auth-input"
                                type="password"
                                autocomplete="current-password"
                                required=true
                                value={(*password).clone()}
                                oninput={on_password_input}
                                disabled={*busy}
                            />
                        </div>

                        <div class="auth-actions">
                            <button type="submit" class="auth-submit" disabled={*busy}>{"Sign in"}</button>
                        </div>
                    </form>
                }

                if config.cloudflare || config.google {
                    <div class="auth-alternatives">
                        if config.cloudflare {
                            <button type="button" class="auth-cloudflare" onclick={on_cloudflare} disabled={*busy}>
                                {"Sign in with Cloudflare"}
                            </button>
                        }

                        if config.google {
                            <a class="auth-google" href={http::GOOGLE_SIGN_IN}>{"Sign in with Google"}</a>
                        }
                    </div>
                }

                if !any {
                    <p class="auth-error">{"No way to sign in is enabled."}</p>
                }
            </div>
        </main>
    }
}

fn login_error(error: &Error, logins: bool) -> AttrValue {
    match error {
        Error::Auth(AuthError::Unauthorized) if logins => {
            AttrValue::from("Wrong login or password.")
        }
        Error::Auth(AuthError::Unauthorized) => AttrValue::from("Wrong email or password."),
        Error::Auth(AuthError::TooManyRequests) => {
            AttrValue::from("Too many failed sign-ins. Try again in a few minutes.")
        }
        Error::Auth(AuthError::Forbidden) => AttrValue::from("This account may not sign in."),
        Error::Auth(AuthError::Invalid(message)) => AttrValue::from(message.clone()),
        Error::Network(..) => AttrValue::from("Could not reach the server."),
        error => AttrValue::from(format!("Signing in failed: {error}.")),
    }
}

fn cloudflare_error(error: &Error) -> AttrValue {
    match error {
        Error::Auth(AuthError::Unauthorized | AuthError::Forbidden) => {
            AttrValue::from("Cloudflare could not sign you in. Reload to try again.")
        }
        error => login_error(error, true),
    }
}

/// The message for an `?error=` code the server redirected with. The codes
/// are territory's Google sign-in errors.
pub(super) fn query_error_message(code: &str) -> &'static str {
    match code {
        "auth-failed" => "Authentication failed.",
        "user-not-found" => "User not found.",
        _ => "Signing in failed.",
    }
}
