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
//! | `auth-google` | the "Sign in with Google" or "Sign up with Google" link |

pub mod http;

mod browser;
mod context;
mod provider;
mod register;
mod sign_in;

#[cfg(test)]
mod tests;

pub use self::context::{AuthContext, use_auth};
pub use self::provider::{AuthProvider, AuthProviderProps, SESSION_ENDED};
pub use self::register::{Register, RegisterProps};
pub use self::sign_in::{SignIn, SignInProps};
