use yew::platform::spawn_local;
use yew::prelude::*;

use super::browser;
use super::http::{self, Error};
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
    let link = use_state(|| Link::Loading);
    let password = use_state(String::new);
    let confirm = use_state(String::new);
    let busy = use_state(|| false);
    let error = use_state(|| None::<AttrValue>);

    {
        let link = link.clone();

        use_effect_with(props.token.clone(), move |token| {
            let token = token.clone();
            link.set(Link::Loading);

            spawn_local(async move {
                link.set(match http::register_info(&token).await {
                    Ok(info) => Link::Valid(info),
                    Err(e) => Link::Invalid(link_error(&e)),
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

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();

            if *busy {
                return;
            }

            if let Some(message) = validate_password(&password) {
                error.set(Some(AttrValue::Static(message)));
                return;
            }

            if *password != *confirm {
                error.set(Some(AttrValue::from("The passwords do not match.")));
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

            spawn_local(async move {
                match http::register(&token, &request).await {
                    Ok(user) => on_register.emit(user),
                    Err(e @ Error::Auth(AuthError::NotFound | AuthError::Gone)) => {
                        link.set(Link::Invalid(link_error(&e)));
                        busy.set(false);
                    }
                    Err(Error::Auth(AuthError::Invalid(message))) => {
                        error.set(Some(AttrValue::from(message)));
                        busy.set(false);
                    }
                    Err(Error::Network(..)) => {
                        error.set(Some(AttrValue::from("Could not reach the server.")));
                        busy.set(false);
                    }
                    Err(e) => {
                        error.set(Some(AttrValue::from(format!(
                            "Setting the password failed: {e}."
                        ))));
                        busy.set(false);
                    }
                }
            });
        })
    };

    let body = match &*link {
        Link::Loading => html! {
            <p class="auth-status" role="status">{"Checking the link…"}</p>
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
                            <span class="auth-label">{"Login"}</span>
                            <span class="auth-value">{login.clone()}</span>
                        </div>
                    }

                    if let Some(email) = &info.email {
                        <div class="auth-field">
                            <span class="auth-label">{"Email"}</span>
                            <span class="auth-value">{email.clone()}</span>
                        </div>
                    }

                    <div class="auth-field">
                        <label for="auth-password">{"Password"}</label>
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
                        <label for="auth-confirm">{"Confirm password"}</label>
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
                        <button type="submit" class="auth-submit" disabled={*busy}>{"Set password"}</button>
                    </div>
                </form>

                if info.google {
                    <div class="auth-alternatives">
                        <a class="auth-google" href={http::google_register_url(&props.token)}>
                            {"Sign up with Google"}
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

                <h1 class="auth-heading">{"Choose a password"}</h1>
                {body}
            </div>
        </main>
    }
}

fn link_error(error: &Error) -> AttrValue {
    match error {
        Error::Auth(AuthError::NotFound) => AttrValue::from("This link is not valid."),
        Error::Auth(AuthError::Gone) => AttrValue::from(
            "This link has already been used or has expired. Ask an administrator for a new one.",
        ),
        Error::Network(..) => AttrValue::from("Could not reach the server. Reload to try again."),
        error => AttrValue::from(format!("The link could not be checked: {error}.")),
    }
}
