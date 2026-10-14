use yew::prelude::*;

use super::context::use_auth;

/// The properties of [`UserMenu`].
#[derive(Properties, PartialEq)]
pub struct UserMenuProps {
    /// Called when the user picks Account, such as to show
    /// [`AccountPanel`](super::AccountPanel).
    pub on_account: Callback<()>,
    /// Called when an admin picks Users, such as to show
    /// [`AdminUsers`](super::AdminUsers). The item is only shown to admins.
    pub on_admin: Callback<()>,
    /// Classes added to the menu.
    #[prop_or_default]
    pub class: Classes,
}

/// A menu under the signed-in user's name with Account, Users (for admins
/// only) and Sign out.
///
/// The menu is a button that opens a list; picking an item closes it. Use it
/// inside [`AuthProvider`](super::AuthProvider).
#[function_component]
pub fn UserMenu(props: &UserMenuProps) -> Html {
    let auth = use_auth();
    let open = use_state(|| false);

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

    html! {
        <nav class={classes!("auth-menu", (*open).then_some("auth-open"), props.class.clone())}>
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
                        <button type="button" class="auth-menu-item" onclick={on_account}>{"Account"}</button>
                    </li>

                    if auth.is_admin() {
                        <li>
                            <button type="button" class="auth-menu-item" onclick={on_admin}>{"Users"}</button>
                        </li>
                    }

                    <li>
                        <button type="button" class="auth-menu-item auth-sign-out" onclick={on_sign_out}>{"Sign out"}</button>
                    </li>
                </ul>
            }
        </nav>
    }
}
