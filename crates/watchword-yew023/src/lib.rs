//! [<img alt="github" src="https://img.shields.io/badge/github-udoprog/watchword-8da0cb?style=for-the-badge&logo=github" height="20">](https://github.com/udoprog/watchword)
//! [<img alt="crates.io" src="https://img.shields.io/crates/v/watchword-yew023.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/watchword-yew023)
//! [<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-watchword--yew023-66c2a5?style=for-the-badge&logoColor=white&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">](https://docs.rs/watchword-yew023)
//!
//! [watchword]'s frontend for [Yew] 0.23: the sign-in, registration, account
//! and user management components, the auth context and hook, and the HTTP
//! client for watchword's `/api/auth` routes. Built for
//! `wasm32-unknown-unknown`.
//!
//! Apps take it through watchword's `yew023` feature, as `watchword::yew023`,
//! so a frontend needs only one dependency:
//!
//! ```toml
//! [dependencies]
//! auth = { package = "watchword", version = "0.1", features = ["yew023"] }
//! ```
//!
//! It is a crate of its own because yew's macros expand to `::yew::` paths, so
//! its code must depend on yew under the key `yew`. A later yew gets a crate of
//! its own beside it, so an app moves to it when it chooses. Released in
//! lockstep with watchword.
//!
//! <br>
//!
//! ## Usage
//!
//! Wrap the app in [`AuthProvider`]. It signs the user in (or registers them
//! from a `/register/{token}` link) before rendering its children, and gives
//! them an [`AuthContext`] through [`use_auth`]:
//!
//! ```ignore
//! use watchword::yew023::{AuthProvider, use_auth};
//! use yew::prelude::*;
//!
//! #[function_component]
//! fn Root() -> Html {
//!     html! {
//!         <AuthProvider title="My App">
//!             <App />
//!         </AuthProvider>
//!     }
//! }
//!
//! #[function_component]
//! fn App() -> Html {
//!     let auth = use_auth();
//!     let onclick = Callback::from(move |_| auth.sign_out());
//!     html! { <button {onclick}>{"Sign out"}</button> }
//! }
//! ```
//!
//! Inside the provider, [`UserMenu`] gives the signed-in user Account, Users
//! (for admins), Sign out, and a way back while an admin impersonates them.
//! [`AccountPanel`] is the user's own account, [`AdminUsers`] manages users
//! for admins, and [`CloudflareSettings`] edits the Cloudflare Access
//! settings an app stores. They talk to the server through [`http`].
//!
//! <br>
//!
//! ## With a musli-web socket
//!
//! With the `musliweb04` feature (watchword's `musliweb04` and `yew023`
//! together), an app that talks to its server over a [musli-web] 0.4
//! WebSocket hands its handle to the context once the socket is open inside
//! [`AuthProvider`]:
//!
//! ```ignore
//! let auth = use_auth();
//! auth.set_socket(Some(service.handle().clone()));
//! ```
//!
//! The components then follow the server's `AuthBroadcast`: the context's
//! user is replaced when it changes elsewhere, and [`AdminUsers`] applies
//! users created, changed and deleted by others in place, so the app no
//! longer bumps its `refresh` prop. The account and admin requests go over
//! the socket too while it is open, and over HTTP while it reconnects;
//! signing in and out, registration and impersonation always use HTTP.
//!
//! <br>
//!
//! ## Translating
//!
//! The components look their text up through [phrasebook] 0.1: in the
//! `Phrases` the app provides with `ContextProvider<Phrases>`, falling back to
//! watchword's own English messages, [`L10N`], for any message the app's
//! phrasebook lacks. Without a provider they render that English, so an app
//! that does not translate needs nothing.
//!
//! The messages are the `watchword-*` ids of [`locales/en-US.ftl`][ftl]. To
//! translate them, an app adds those ids to its own `.ftl` resources and adds
//! watchword's catalog after its own, so its messages win:
//!
//! ```ignore
//! let book = Phrasebook::builder()
//!     .language(Lang::EN_US, "English")
//!     .language(SV_SE, "Svenska")
//!     .catalog(&APP)
//!     .catalog(&auth::yew023::L10N)
//!     .build();
//! ```
//!
//! Errors from the server, including why a request is invalid, are phrased
//! from their codes here, so they are translated the same way.
//! [`AuthProvider`]'s `signed_out_notice` and [`CloudflareSettings`]'s
//! `app_name` override their messages when given.
//!
//! <br>
//!
//! ## Styling
//!
//! The components render plain semantic HTML with stable class names and take
//! a `class` prop that is added to their outermost element. The class names
//! are:
//!
//! | Class | Element |
//! |---|---|
//! | `auth-page` | the outermost `<main>` of the splash, sign-in and registration pages |
//! | `auth-splash` | the splash while loading or when the server is unreachable |
//! | `auth-card` | the box holding a page's content |
//! | `auth-title` | the app's title, when given |
//! | `auth-heading` | the page's `<h1>` |
//! | `auth-message` | the live region holding `auth-error` and `auth-notice` |
//! | `auth-error` | an error |
//! | `auth-notice` | a notice, such as that the session has ended |
//! | `auth-status` | progress, such as checking a link |
//! | `auth-form` | a form |
//! | `auth-field` | a label with its input or value |
//! | `auth-label` | the label of a read-only value |
//! | `auth-input` | a text or password input |
//! | `auth-value` | a read-only value, such as the login on a registration page |
//! | `auth-actions` | a row of buttons |
//! | `auth-submit` | a form's submit button |
//! | `auth-retry` | the splash's Retry button |
//! | `auth-alternatives` | the other sign-in methods |
//! | `auth-cloudflare` | the "Sign in with Cloudflare" button |
//! | `auth-google` | the "Sign in with Google" or "Sign up with Google" link, or "Switch to Google" on the account panel |
//! | `auth-hint` | help text under a field or form |
//! | `auth-subheading` | a form's `<h3>` inside a panel |
//! | `auth-account` | the outermost `<section>` of [`AccountPanel`] |
//! | `auth-details` | the account's role and sign-in method |
//! | `auth-profile` | the account's login and email form |
//! | `auth-password` | the account's change or set password form |
//! | `auth-sign-out` | a Sign out button |
//! | `auth-menu` | the outermost `<nav>` of [`UserMenu`], with `auth-open` while open |
//! | `auth-menu-button` | the button that opens the menu |
//! | `auth-name` | the user's name in the menu button |
//! | `auth-menu-items` | the open menu's `<ul>` |
//! | `auth-menu-item` | an item of the menu |
//! | `auth-impersonating` | the banner in the menu while an admin impersonates the user, holding `auth-impersonating-text` and the `auth-stop-impersonating` button |
//! | `auth-admin-users` | the outermost `<section>` of [`AdminUsers`] |
//! | `auth-toolbar` | the heading row of the users list |
//! | `auth-add` | the Add user button |
//! | `auth-add-user` | the add user form |
//! | `auth-filter` | the filter input and its `auth-clear` button |
//! | `auth-users` | the users `<table>` |
//! | `auth-user` | a user's row, with `auth-me` on the admin's own |
//! | `auth-user-login`, `auth-user-email`, `auth-user-role`, `auth-user-access`, `auth-user-link`, `auth-user-actions` | the cells of a row |
//! | `auth-badge` | the "you" badge on the admin's own row |
//! | `auth-user-extra` | the app's `extra` content under a user |
//! | `auth-muted` | a missing value, such as "No email" |
//! | `auth-select` | a role select |
//! | `auth-access` | a user's account state, with `auth-pending`, `auth-active` or `auth-revoked` |
//! | `auth-link-state` | when a user's link expires, or "No link" |
//! | `auth-link` | a link shown once: its `auth-link-url` input, `auth-copy` button and hint |
//! | `auth-danger` | a destructive button, such as Delete |
//! | `auth-confirm` | an inline confirmation, with `auth-confirm-no` and `auth-confirm-yes` |
//! | `auth-pages` | the paging row: `auth-previous`, `auth-page-number` and `auth-next` |
//! | `auth-hidden` | text for screen readers only, which the app should hide visually |
//! | `auth-cloudflare-settings` | the outermost `<section>` of [`CloudflareSettings`] |
//! | `auth-instructions` | the Cloudflare setup instructions |
//! | `auth-toggle` | a field with a checkbox |
//!
//! [`AccountPanel`]: https://docs.rs/watchword-yew023/latest/watchword_yew023/struct.AccountPanel.html
//! [`AdminUsers`]: https://docs.rs/watchword-yew023/latest/watchword_yew023/struct.AdminUsers.html
//! [`AuthContext`]: https://docs.rs/watchword-yew023/latest/watchword_yew023/struct.AuthContext.html
//! [`AuthProvider`]: https://docs.rs/watchword-yew023/latest/watchword_yew023/struct.AuthProvider.html
//! [`CloudflareSettings`]: https://docs.rs/watchword-yew023/latest/watchword_yew023/struct.CloudflareSettings.html
//! [`http`]: https://docs.rs/watchword-yew023/latest/watchword_yew023/http/index.html
//! [`L10N`]: https://docs.rs/watchword-yew023/latest/watchword_yew023/static.L10N.html
//! [`use_auth`]: https://docs.rs/watchword-yew023/latest/watchword_yew023/fn.use_auth.html
//! [`UserMenu`]: https://docs.rs/watchword-yew023/latest/watchword_yew023/struct.UserMenu.html
//! [ftl]: https://github.com/udoprog/watchword/blob/main/crates/watchword-yew023/locales/en-US.ftl
//! [musli-web]: https://docs.rs/musli-web
//! [phrasebook]: https://docs.rs/phrasebook
//! [watchword]: https://docs.rs/watchword
//! [Yew]: https://yew.rs

#![cfg_attr(watchword_docsrs, feature(doc_cfg))]

pub mod http;

mod account;
mod admin_users;
mod browser;
mod client;
mod cloudflare_settings;
mod context;
mod form;
mod l10n;
mod provider;
mod register;
mod sign_in;
#[cfg(feature = "musliweb04")]
mod socket;
mod user_menu;

#[cfg(test)]
mod tests;

pub use self::account::{AccountPanel, AccountPanelProps};
pub use self::admin_users::{AdminUsers, AdminUsersProps, PAGE_SIZE, UsersQuery};
pub use self::cloudflare_settings::{CloudflareSettings, CloudflareSettingsProps};
pub use self::context::{AuthContext, use_auth};
pub use self::l10n::L10N;
pub use self::provider::{AuthProvider, AuthProviderProps};
pub use self::register::{Register, RegisterProps};
pub use self::sign_in::{SignIn, SignInProps};
pub use self::user_menu::{UserMenu, UserMenuProps};
