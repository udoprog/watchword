//! Yew components, the auth context and hook, and the HTTP client (the `yew`
//! feature).
//!
//! Wrap the app in [`AuthProvider`]. It signs the user in (or registers them
//! from a `/register/{token}` link) before rendering its children, and gives
//! them an [`AuthContext`] through [`use_auth`]:
//!
//! ```ignore
//! use auth::yew::{AuthProvider, use_auth};
//! use yew::prelude::*;
//!
//! #[function_component]
//! fn Root() -> Html {
//!     html! {
//!         <AuthProvider title="Track">
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
//! (for admins) and Sign out, [`AccountPanel`] is the user's own account,
//! [`AdminUsers`] manages users for admins, and [`CloudflareSettings`] edits
//! the Cloudflare Access settings an app stores. They talk to the server
//! through [`http`].
//!
//! # Styling
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

pub mod http;

mod account;
mod admin_users;
mod browser;
mod cloudflare_settings;
mod context;
mod form;
mod provider;
mod register;
mod sign_in;
mod user_menu;

#[cfg(test)]
mod tests;

pub use self::account::{AccountPanel, AccountPanelProps};
pub use self::admin_users::{AdminUsers, AdminUsersProps, PAGE_SIZE, UsersQuery};
pub use self::cloudflare_settings::{CloudflareSettings, CloudflareSettingsProps};
pub use self::context::{AuthContext, use_auth};
pub use self::provider::{AuthProvider, AuthProviderProps, SESSION_ENDED};
pub use self::register::{Register, RegisterProps};
pub use self::sign_in::{SignIn, SignInProps};
pub use self::user_menu::{UserMenu, UserMenuProps};
