use std::rc::Rc;
use std::string::String;

use phrasebook02::Phrases;
use phrasebook02::yew023::use_phrases_with;
use yew::platform::spawn_local;
use yew::prelude::*;

use super::Error;
use super::browser;
use super::http;
use super::l10n;
use super::service::use_auth_service;
use watchword_core::phrasebookcatalog01::L10N;
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
/// `config.google` is. Signing in with Google comes back to the URL's
/// `?next=` when it is a path on this origin, or else to this page.
///
/// An `?error=` the server redirected with, such as from a failed Google
/// sign-in, is shown and removed from the URL.
#[function_component]
pub fn SignIn(props: &SignInProps) -> Html {
    let service = use_auth_service();
    let phrases = use_phrases_with(&L10N);
    let login = use_state(String::new);
    let password = use_state(String::new);
    let busy = use_state(|| false);
    let error = use_state(|| None::<AttrValue>);

    {
        let error = error.clone();
        let phrases = phrases.clone();

        use_effect_with((), move |_| {
            if let Some(code) = browser::take_query_error() {
                error.set(Some(AttrValue::from(query_error_message(&phrases, &code))));
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
        let phrases = phrases.clone();
        let service = service.clone();

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
            let phrases = phrases.clone();
            let service = service.clone();

            spawn_local(async move {
                match service.login(request).await {
                    Ok(user) => on_sign_in.emit(user),
                    Err(e) => {
                        error.set(Some(login_error(&phrases, &e, logins)));
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
        let phrases = phrases.clone();
        let service = service.clone();

        Callback::from(move |_: MouseEvent| {
            if *busy {
                return;
            }

            busy.set(true);
            error.set(None);

            let busy = busy.clone();
            let error = error.clone();
            let on_sign_in = on_sign_in.clone();
            let phrases = phrases.clone();
            let service = service.clone();

            spawn_local(async move {
                match service.cloudflare_sign_in().await {
                    Ok(user) => on_sign_in.emit(user),
                    Err(e) => {
                        error.set(Some(cloudflare_error(&phrases, &e)));
                        busy.set(false);
                    }
                }
            });
        })
    };

    let config = props.config;
    let any = config.password || config.cloudflare || config.google;

    let (login_label, login_type, login_autocomplete) = if logins {
        ("watchword-login-or-email", "text", "username")
    } else {
        ("watchword-email", "email", "email")
    };

    html! {
        <main class={classes!("auth-page", props.class.clone())}>
            <div class="auth-card">
                if let Some(title) = &props.title {
                    <p class="auth-title">{title.clone()}</p>
                }

                <h1 class="auth-heading">{phrases.text("watchword-sign-in")}</h1>

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
                            <label for="auth-login">{phrases.text(login_label)}</label>
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
                            <label for="auth-password">{phrases.text("watchword-password")}</label>
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
                            <button type="submit" class="auth-submit" disabled={*busy}>{phrases.text("watchword-sign-in")}</button>
                        </div>
                    </form>
                }

                if config.cloudflare || config.google {
                    <div class="auth-alternatives">
                        if config.cloudflare {
                            <button type="button" class="auth-cloudflare" onclick={on_cloudflare} disabled={*busy}>
                                {phrases.text("watchword-sign-in-cloudflare")}
                            </button>
                        }

                        if config.google {
                            <a class="auth-google" href={browser::google_sign_in(http::GOOGLE_SIGN_IN)}>{phrases.text("watchword-sign-in-google")}</a>
                        }
                    </div>
                }

                if !any {
                    <p class="auth-error">{phrases.text("watchword-sign-in-none")}</p>
                }
            </div>
        </main>
    }
}

fn login_error(phrases: &Phrases, error: &Error, logins: bool) -> AttrValue {
    let id = match error {
        Error::Auth(AuthError::Unauthorized) if logins => "watchword-sign-in-wrong-login",
        Error::Auth(AuthError::Unauthorized) => "watchword-sign-in-wrong-email",
        Error::Auth(AuthError::TooManyRequests) => "watchword-sign-in-too-many",
        Error::Auth(AuthError::Forbidden) => "watchword-sign-in-forbidden",
        Error::Auth(AuthError::Invalid(invalid)) => {
            return AttrValue::from(l10n::invalid(phrases, invalid));
        }
        Error::Network(..) => "watchword-error-unreachable",
        error => return l10n::failed(phrases, "watchword-failed-signing-in", error),
    };

    l10n::text(phrases, id)
}

fn cloudflare_error(phrases: &Phrases, error: &Error) -> AttrValue {
    match error {
        Error::Auth(AuthError::Unauthorized | AuthError::Forbidden) => {
            l10n::text(phrases, "watchword-sign-in-cloudflare-failed")
        }
        error => login_error(phrases, error, true),
    }
}

/// The message for an `?error=` code the server redirected with, such as
/// the errors of Google sign-in.
pub(super) fn query_error_message(phrases: &Phrases, code: &str) -> Rc<str> {
    phrases.text(match code {
        "auth-failed" => "watchword-query-auth-failed",
        "user-not-found" => "watchword-query-user-not-found",
        _ => "watchword-query-failed",
    })
}
