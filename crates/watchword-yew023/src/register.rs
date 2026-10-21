use std::string::String;

use phrasebook01::Phrases;
use yew::platform::spawn_local;
use yew::prelude::*;

use super::browser;
use super::http::{self, Error};
use super::l10n::{self, use_phrases};
use watchword_core::{AuthError, RegisterInfo, RegisterRequest, UserInfo, validate_password};

/// The properties of [`Register`].
#[derive(Properties, PartialEq)]
pub struct RegisterProps {
    /// The link's token, from the `/register/{token}` URL.
    pub token: AttrValue,
    /// Called with the user once registered and signed in.
    pub on_register: Callback<UserInfo>,
    /// The app's name, shown above the heading.
    #[prop_or_default]
    pub title: Option<AttrValue>,
    /// Classes added to the page.
    #[prop_or_default]
    pub class: Classes,
}

#[derive(Clone, PartialEq)]
enum Link {
    Loading,
    Valid(RegisterInfo),
    Invalid(AttrValue),
}

/// The page of a registration or reset link: it shows the user's login and
/// email read-only, then the password and its confirmation, then "Sign up
/// with Google" when the server offers it. Setting the password signs the
/// user in.
#[function_component]
pub fn Register(props: &RegisterProps) -> Html {
    let phrases = use_phrases();
    let link = use_state(|| Link::Loading);
    let password = use_state(String::new);
    let confirm = use_state(String::new);
    let busy = use_state(|| false);
    let error = use_state(|| None::<AttrValue>);

    {
        let link = link.clone();
        let phrases = phrases.clone();

        use_effect_with(props.token.clone(), move |token| {
            let token = token.clone();
            link.set(Link::Loading);

            spawn_local(async move {
                link.set(match http::register_info(&token).await {
                    Ok(info) => Link::Valid(info),
                    Err(e) => Link::Invalid(link_error(&phrases, &e)),
                });
            });
        });
    }

    let on_password_input = {
        let password = password.clone();
        Callback::from(move |e: InputEvent| password.set(browser::input_value(&e)))
    };

    let on_confirm_input = {
        let confirm = confirm.clone();
        Callback::from(move |e: InputEvent| confirm.set(browser::input_value(&e)))
    };

    let onsubmit = {
        let token = props.token.clone();
        let link = link.clone();
        let password = password.clone();
        let confirm = confirm.clone();
        let busy = busy.clone();
        let error = error.clone();
        let on_register = props.on_register.clone();
        let phrases = phrases.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();

            if *busy {
                return;
            }

            if let Some(invalid) = validate_password(&password) {
                error.set(Some(AttrValue::from(l10n::invalid(&phrases, &invalid))));
                return;
            }

            if *password != *confirm {
                error.set(Some(l10n::text(&phrases, "watchword-passwords-differ")));
                return;
            }

            busy.set(true);
            error.set(None);

            let token = token.clone();
            let request = RegisterRequest {
                password: (*password).clone(),
            };
            let link = link.clone();
            let busy = busy.clone();
            let error = error.clone();
            let on_register = on_register.clone();
            let phrases = phrases.clone();

            spawn_local(async move {
                match http::register(&token, &request).await {
                    Ok(user) => on_register.emit(user),
                    Err(e @ Error::Auth(AuthError::NotFound | AuthError::Gone)) => {
                        link.set(Link::Invalid(link_error(&phrases, &e)));
                        busy.set(false);
                    }
                    Err(Error::Auth(AuthError::Invalid(invalid))) => {
                        error.set(Some(AttrValue::from(l10n::invalid(&phrases, &invalid))));
                        busy.set(false);
                    }
                    Err(Error::Network(..)) => {
                        error.set(Some(l10n::text(&phrases, "watchword-error-unreachable")));
                        busy.set(false);
                    }
                    Err(e) => {
                        error.set(Some(l10n::failed(
                            &phrases,
                            "watchword-failed-setting-password",
                            &e,
                        )));
                        busy.set(false);
                    }
                }
            });
        })
    };

    let body = match &*link {
        Link::Loading => html! {
            <p class="auth-status" role="status">{phrases.text("watchword-register-checking")}</p>
        },
        Link::Invalid(message) => html! {
            <div class="auth-message" role="alert">
                <p class="auth-error">{message.clone()}</p>
            </div>
        },
        Link::Valid(info) => html! {
            <>
                <div class="auth-message" role="alert">
                    if let Some(error) = &*error {
                        <p class="auth-error">{error.clone()}</p>
                    }
                </div>

                <form class="auth-form" {onsubmit}>
                    if let Some(login) = &info.login {
                        <div class="auth-field">
                            <span class="auth-label">{phrases.text("watchword-login")}</span>
                            <span class="auth-value">{login.clone()}</span>
                        </div>
                    }

                    if let Some(email) = &info.email {
                        <div class="auth-field">
                            <span class="auth-label">{phrases.text("watchword-email")}</span>
                            <span class="auth-value">{email.clone()}</span>
                        </div>
                    }

                    <div class="auth-field">
                        <label for="auth-password">{phrases.text("watchword-password")}</label>
                        <input
                            id="auth-password"
                            class="auth-input"
                            type="password"
                            autocomplete="new-password"
                            required=true
                            value={(*password).clone()}
                            oninput={on_password_input}
                            disabled={*busy}
                        />
                    </div>

                    <div class="auth-field">
                        <label for="auth-confirm">{phrases.text("watchword-confirm-password")}</label>
                        <input
                            id="auth-confirm"
                            class="auth-input"
                            type="password"
                            autocomplete="new-password"
                            required=true
                            value={(*confirm).clone()}
                            oninput={on_confirm_input}
                            disabled={*busy}
                        />
                    </div>

                    <div class="auth-actions">
                        <button type="submit" class="auth-submit" disabled={*busy}>{phrases.text("watchword-set-password")}</button>
                    </div>
                </form>

                if info.google {
                    <div class="auth-alternatives">
                        <a class="auth-google" href={http::google_register_url(&props.token)}>
                            {phrases.text("watchword-sign-up-google")}
                        </a>
                    </div>
                }
            </>
        },
    };

    html! {
        <main class={classes!("auth-page", props.class.clone())}>
            <div class="auth-card">
                if let Some(title) = &props.title {
                    <p class="auth-title">{title.clone()}</p>
                }

                <h1 class="auth-heading">{phrases.text("watchword-register-heading")}</h1>
                {body}
            </div>
        </main>
    }
}

fn link_error(phrases: &Phrases, error: &Error) -> AttrValue {
    let id = match error {
        Error::Auth(AuthError::NotFound) => "watchword-link-invalid",
        Error::Auth(AuthError::Gone) => "watchword-link-gone",
        Error::Network(..) => "watchword-error-unreachable-reload",
        error => return l10n::failed(phrases, "watchword-failed-checking-link", error),
    };

    l10n::text(phrases, id)
}
