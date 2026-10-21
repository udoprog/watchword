use std::borrow::ToOwned;
use std::string::String;
use std::string::ToString;

use phrasebook02::yew023::use_phrases_with;
use phrasebook02::{Phrases, args};
use yew::platform::spawn_local;
use yew::prelude::*;

use super::Error;
use super::context::use_auth;
use super::l10n;
use super::service::use_auth_service;
use watchword_core::phrasebook02::L10N;
use watchword_core::{AuthError, UserInfo};

/// The properties of [`UserMenu`].
#[derive(Properties, PartialEq)]
pub struct UserMenuProps {
    /// Called when the user picks Account, such as to show
    /// [`AccountPanel`](super::AccountPanel).
    pub on_account: Callback<()>,
    /// Called when an admin picks Users, such as to show
    /// [`AdminUsers`](super::AdminUsers). The item is only shown to admins.
    pub on_admin: Callback<()>,
    /// Called once Stop impersonating has signed the admin back in, such as
    /// to show [`AdminUsers`](super::AdminUsers) again.
    #[prop_or_default]
    pub on_stop_impersonating: Callback<()>,
    /// Classes added to the menu.
    #[prop_or_default]
    pub class: Classes,
}

/// A menu under the signed-in user's name with Account, Users (for admins
/// only) and Sign out.
///
/// While an admin impersonates the user ([`UserInfo::impersonated_by`]), a
/// banner before the menu button says whom they are acting as, with a Stop
/// impersonating button that signs the admin back in (see
/// [`AuthService::stop_impersonating`](super::AuthService::stop_impersonating)).
///
/// The menu is a button that opens a list; picking an item closes it. Use it
/// inside [`AuthProvider`](super::AuthProvider).
#[function_component]
pub fn UserMenu(props: &UserMenuProps) -> Html {
    let auth = use_auth();
    let service = use_auth_service();
    let phrases = use_phrases_with(&L10N);
    let open = use_state(|| false);
    let stopping = use_state(|| false);
    let stop_error = use_state(|| None::<AttrValue>);

    let toggle = {
        let open = open.clone();
        Callback::from(move |_: MouseEvent| open.set(!*open))
    };

    let item = |callback: Callback<()>| {
        let open = open.clone();
        Callback::from(move |_: MouseEvent| {
            open.set(false);
            callback.emit(());
        })
    };

    let on_account = item(props.on_account.clone());
    let on_admin = item(props.on_admin.clone());
    let on_sign_out = {
        let auth = auth.clone();
        item(Callback::from(move |()| auth.sign_out()))
    };

    let on_stop = {
        let auth = auth.clone();
        let service = service.clone();
        let stopping = stopping.clone();
        let stop_error = stop_error.clone();
        let done = props.on_stop_impersonating.clone();
        let phrases = phrases.clone();

        Callback::from(move |_: MouseEvent| {
            if *stopping {
                return;
            }

            stopping.set(true);
            stop_error.set(None);

            let auth = auth.clone();
            let service = service.clone();
            let stopping = stopping.clone();
            let stop_error = stop_error.clone();
            let done = done.clone();
            let phrases = phrases.clone();

            spawn_local(async move {
                // The provider's transport stops using a socket that speaks
                // for the session this replaced.
                match service.stop_impersonating().await {
                    Ok(admin) => {
                        auth.set_user(admin);
                        done.emit(());
                    }
                    Err(error) => {
                        stop_error.set(Some(stop_error_message(&phrases, &error)));

                        if error.is_unauthorized() {
                            auth.check_session();
                        }
                    }
                }

                stopping.set(false);
            });
        })
    };

    let banner = impersonation_banner(&phrases, &auth.user).map(|text| {
        html! {
            <div class="auth-impersonating" role="status">
                <span class="auth-impersonating-text">{text}</span>
                <button
                    type="button"
                    class="auth-stop-impersonating"
                    onclick={on_stop}
                    disabled={*stopping}
                >
                    {phrases.text("watchword-stop-impersonating")}
                </button>
                if let Some(error) = &*stop_error {
                    <span class="auth-error">{error.clone()}</span>
                }
            </div>
        }
    });

    html! {
        <nav class={classes!("auth-menu", (*open).then_some("auth-open"), props.class.clone())}>
            {banner}

            <button
                type="button"
                class="auth-menu-button"
                aria-haspopup="true"
                aria-expanded={(*open).to_string()}
                onclick={toggle}
            >
                <span class="auth-name">{auth.user.name().to_owned()}</span>
            </button>

            if *open {
                <ul class="auth-menu-items">
                    <li>
                        <button type="button" class="auth-menu-item" onclick={on_account}>{phrases.text("watchword-account")}</button>
                    </li>

                    if auth.is_admin() {
                        <li>
                            <button type="button" class="auth-menu-item" onclick={on_admin}>{phrases.text("watchword-users")}</button>
                        </li>
                    }

                    <li>
                        <button type="button" class="auth-menu-item auth-sign-out" onclick={on_sign_out}>{phrases.text("watchword-sign-out")}</button>
                    </li>
                </ul>
            }
        </nav>
    }
}

/// The banner's text while an admin impersonates `user`, naming the user and
/// the admin; `None` when the session is the user's own.
pub(super) fn impersonation_banner(phrases: &Phrases, user: &UserInfo) -> Option<String> {
    let by = user.impersonated_by.as_ref()?;

    Some(if by.name.is_empty() {
        phrases.msg("watchword-impersonating", &args!(user = user.name()))
    } else {
        phrases.msg(
            "watchword-impersonating-as",
            &args!(user = user.name(), admin = by.name.as_str()),
        )
    })
}

/// Why Stop impersonating failed. A refusal means the admin can no longer
/// come back, so the way out is signing out.
pub(super) fn stop_error_message(phrases: &Phrases, error: &Error) -> AttrValue {
    match error {
        Error::Auth(AuthError::Forbidden) => l10n::text(phrases, "watchword-stop-forbidden"),
        error => l10n::error_message(phrases, error, "watchword-failed-stopping"),
    }
}
