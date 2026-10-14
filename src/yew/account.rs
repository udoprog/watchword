use yew::platform::spawn_local;
use yew::prelude::*;

use super::browser;
use super::context::use_auth;
use super::form::{error_message, identity_change, optional};
use super::http::{self, Error};
use crate::types::{
    AuthError, Method, PasswordChange, Role, UserChange, UserInfo, validate_password,
};

/// The properties of [`AccountPanel`].
#[derive(Properties, PartialEq)]
pub struct AccountPanelProps {
    /// Classes added to the panel.
    #[prop_or_default]
    pub class: Classes,
}

/// The signed-in user's account: their role and sign-in method, their login
/// (when the app uses logins) and email, changing or setting the password,
/// switching to Google (when the server offers it), and Sign out.
///
/// Changes go to `PATCH /api/auth/account` and
/// `POST /api/auth/account/password`, and the user they answer with replaces
/// the one in the [`AuthContext`](super::AuthContext). The app wraps the
/// panel in a page or a modal. Use it inside
/// [`AuthProvider`](super::AuthProvider).
#[function_component]
pub fn AccountPanel(props: &AccountPanelProps) -> Html {
    let auth = use_auth();
    let user = auth.user.clone();
    let logins = auth.config.logins;
    let google_method = user.method == Method::Google;

    html! {
        <section class={classes!("auth-account", props.class.clone())}>
            <h2 class="auth-heading">{"Account"}</h2>

            <div class="auth-details">
                <div class="auth-field">
                    <span class="auth-label">{"Role"}</span>
                    <span class="auth-value">{role_name(user.role)}</span>
                </div>

                <div class="auth-field">
                    <span class="auth-label">{"Signs in with"}</span>
                    <span class="auth-value">{method_name(user.method)}</span>
                </div>
            </div>

            <ProfileForm user={user.clone()} {logins} />
            <PasswordForm user={user.clone()} />

            if auth.config.google {
                <div class="auth-alternatives">
                    if google_method {
                        <a class="auth-google" href={http::GOOGLE_LINK}>{"Switch to another Google account"}</a>
                    } else {
                        <p class="auth-hint">
                            {"Switching to Google removes your password and signs you out everywhere else."}
                        </p>
                        <a class="auth-google" href={http::GOOGLE_LINK}>{"Switch to Google"}</a>
                    }
                </div>
            }

            <div class="auth-actions">
                <button
                    type="button"
                    class="auth-sign-out"
                    onclick={Callback::from(move |_: MouseEvent| auth.sign_out())}
                >
                    {"Sign out"}
                </button>
            </div>
        </section>
    }
}

#[derive(Properties, PartialEq)]
struct ProfileFormProps {
    user: std::rc::Rc<UserInfo>,
    logins: bool,
}

/// The login and email form.
#[function_component]
fn ProfileForm(props: &ProfileFormProps) -> Html {
    let auth = use_auth();
    let login = use_state(|| props.user.login.clone().unwrap_or_default());
    let email = use_state(|| props.user.email.clone().unwrap_or_default());
    let busy = use_state(|| false);
    let message = use_state(|| None::<Message>);

    // Follow the user when it changes under the form, such as after saving.
    {
        let login = login.clone();
        let email = email.clone();

        use_effect_with(props.user.clone(), move |user| {
            login.set(user.login.clone().unwrap_or_default());
            email.set(user.email.clone().unwrap_or_default());
        });
    }

    let logins = props.logins;
    let google_method = props.user.method == Method::Google;
    let change = account_change(&props.user, &login, &email, logins);
    let unchanged = matches!(&change, Ok(change) if *change == UserChange::default());

    let on_login_input = {
        let login = login.clone();
        Callback::from(move |e: InputEvent| login.set(browser::input_value(&e)))
    };

    let on_email_input = {
        let email = email.clone();
        Callback::from(move |e: InputEvent| email.set(browser::input_value(&e)))
    };

    let onsubmit = {
        let busy = busy.clone();
        let message = message.clone();
        let auth = auth.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();

            if *busy {
                return;
            }

            let change = match &change {
                Ok(change) if *change == UserChange::default() => return,
                Ok(change) => change.clone(),
                Err(error) => {
                    message.set(Some(Message::Error(AttrValue::Static(error))));
                    return;
                }
            };

            busy.set(true);
            message.set(None);

            let busy = busy.clone();
            let message = message.clone();
            let auth = auth.clone();

            spawn_local(async move {
                match http::update_account(&change).await {
                    Ok(user) => {
                        message.set(Some(Message::Notice(AttrValue::Static("Saved."))));
                        auth.set_user(user);
                    }
                    Err(e) => {
                        message.set(Some(Message::Error(error_message(&e, "Saving"))));
                        check_unauthorized(&auth, &e);
                    }
                }

                busy.set(false);
            });
        })
    };

    html! {
        <form class="auth-form auth-profile" {onsubmit}>
            <h3 class="auth-subheading">{"Profile"}</h3>
            {render_message(&message)}

            if logins {
                <div class="auth-field">
                    <label for="auth-account-login">{"Login"}</label>
                    <input
                        id="auth-account-login"
                        class="auth-input"
                        type="text"
                        autocomplete="username"
                        autocapitalize="none"
                        spellcheck="false"
                        value={(*login).clone()}
                        oninput={on_login_input}
                        disabled={*busy}
                    />
                    <span class="auth-hint">{"Sign in with this name or your email."}</span>
                </div>
            }

            <div class="auth-field">
                <label for="auth-account-email">{"Email"}</label>
                <input
                    id="auth-account-email"
                    class="auth-input"
                    type="email"
                    autocomplete="email"
                    required={!logins}
                    value={(*email).clone()}
                    oninput={on_email_input}
                    disabled={*busy || google_method}
                />
            </div>

            if google_method {
                <p class="auth-hint">{"Your email is the one of your Google account."}</p>
            } else if logins {
                <p class="auth-hint">{"Optional. Leave empty to remove it."}</p>
            }

            <div class="auth-actions">
                <button type="submit" class="auth-submit" disabled={*busy || unchanged}>{"Save"}</button>
            </div>
        </form>
    }
}

#[derive(Properties, PartialEq)]
struct PasswordFormProps {
    user: std::rc::Rc<UserInfo>,
}

/// The change or set password form.
#[function_component]
fn PasswordForm(props: &PasswordFormProps) -> Html {
    let auth = use_auth();
    let old_password = use_state(String::new);
    let new_password = use_state(String::new);
    let confirm = use_state(String::new);
    let busy = use_state(|| false);
    let message = use_state(|| None::<Message>);

    let has_password = props.user.has_password;
    let google_method = props.user.method == Method::Google;

    let input = |state: &UseStateHandle<String>| {
        let state = state.clone();
        Callback::from(move |e: InputEvent| state.set(browser::input_value(&e)))
    };

    let on_old_input = input(&old_password);
    let on_new_input = input(&new_password);
    let on_confirm_input = input(&confirm);

    let onsubmit = {
        let old_password = old_password.clone();
        let new_password = new_password.clone();
        let confirm = confirm.clone();
        let busy = busy.clone();
        let message = message.clone();
        let auth = auth.clone();

        Callback::from(move |e: SubmitEvent| {
            e.prevent_default();

            if *busy {
                return;
            }

            if let Some(error) = validate_password(&new_password) {
                message.set(Some(Message::Error(AttrValue::Static(error))));
                return;
            }

            if *new_password != *confirm {
                message.set(Some(Message::Error(AttrValue::Static(
                    "The passwords do not match.",
                ))));
                return;
            }

            busy.set(true);
            message.set(None);

            let request = PasswordChange {
                old_password: has_password.then(|| (*old_password).clone()),
                new_password: (*new_password).clone(),
            };

            let old_password = old_password.clone();
            let new_password = new_password.clone();
            let confirm = confirm.clone();
            let busy = busy.clone();
            let message = message.clone();
            let auth = auth.clone();

            spawn_local(async move {
                match http::change_password(&request).await {
                    Ok(user) => {
                        old_password.set(String::new());
                        new_password.set(String::new());
                        confirm.set(String::new());
                        let notice = if has_password {
                            "Password changed. Your other sessions were signed out."
                        } else {
                            "Password set. Your other sessions were signed out."
                        };
                        message.set(Some(Message::Notice(AttrValue::Static(notice))));
                        auth.set_user(user);
                    }
                    // With a session (else the check below signs out), a
                    // 401 here is the current password being wrong.
                    Err(e @ Error::Auth(AuthError::Unauthorized)) => {
                        message.set(Some(Message::Error(AttrValue::Static(
                            "The current password is wrong.",
                        ))));
                        check_unauthorized(&auth, &e);
                    }
                    Err(e) => {
                        message.set(Some(Message::Error(error_message(
                            &e,
                            "Changing the password",
                        ))));
                    }
                }

                busy.set(false);
            });
        })
    };

    let (heading, submit) = if has_password {
        ("Change password", "Change password")
    } else {
        ("Set a password", "Set password")
    };

    html! {
        <form class="auth-form auth-password" {onsubmit}>
            <h3 class="auth-subheading">{heading}</h3>
            {render_message(&message)}

            if google_method {
                <p class="auth-hint">
                    {"Setting a password switches you from Google to the password and signs you out everywhere else."}
                </p>
            } else {
                <p class="auth-hint">{"Changing the password signs you out everywhere else."}</p>
            }

            if has_password {
                <div class="auth-field">
                    <label for="auth-old-password">{"Current password"}</label>
                    <input
                        id="auth-old-password"
                        class="auth-input"
                        type="password"
                        autocomplete="current-password"
                        required=true
                        value={(*old_password).clone()}
                        oninput={on_old_input}
                        disabled={*busy}
                    />
                </div>
            }

            <div class="auth-field">
                <label for="auth-new-password">{"New password"}</label>
                <input
                    id="auth-new-password"
                    class="auth-input"
                    type="password"
                    autocomplete="new-password"
                    required=true
                    value={(*new_password).clone()}
                    oninput={on_new_input}
                    disabled={*busy}
                />
            </div>

            <div class="auth-field">
                <label for="auth-confirm-password">{"Confirm new password"}</label>
                <input
                    id="auth-confirm-password"
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
                <button type="submit" class="auth-submit" disabled={*busy}>{submit}</button>
            </div>
        </form>
    }
}

/// A form's outcome, shown above it.
#[derive(Clone, PartialEq)]
enum Message {
    Error(AttrValue),
    Notice(AttrValue),
}

fn render_message(message: &Option<Message>) -> Html {
    html! {
        <div class="auth-message" role="alert">
            {match message {
                Some(Message::Error(error)) => html! { <p class="auth-error">{error.clone()}</p> },
                Some(Message::Notice(notice)) => html! { <p class="auth-notice">{notice.clone()}</p> },
                None => Html::default(),
            }}
        </div>
    }
}

/// Asks the provider to check the session after a 401, which signs out if it
/// has ended.
fn check_unauthorized(auth: &super::AuthContext, error: &Error) {
    if error.is_unauthorized() {
        auth.check_session();
    }
}

pub(super) fn role_name(role: Role) -> &'static str {
    match role {
        Role::Admin => "Administrator",
        Role::Regular => "Regular user",
    }
}

fn method_name(method: Method) -> &'static str {
    match method {
        Method::Password => "Password",
        Method::Google => "Google",
    }
}

/// The change to the user's own login and email that the form's inputs
/// make, or why it cannot be saved. The login is only considered with
/// `logins`, and the email not for a Google user, whose email is their
/// Google account's.
pub(super) fn account_change(
    user: &UserInfo,
    login: &str,
    email: &str,
    logins: bool,
) -> Result<UserChange, &'static str> {
    let login = if logins {
        optional(login)
    } else {
        user.login.clone()
    };

    let email = if user.method == Method::Google {
        user.email.clone()
    } else {
        optional(email)
    };

    identity_change(
        (user.login.as_deref(), user.email.as_deref()),
        login,
        email,
        logins,
    )
}
