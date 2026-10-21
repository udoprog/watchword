//! The server core: password hashing, session ids and link tokens, signed
//! session cookies, and the [`Auth`] service that enforces the sign-in and
//! user-management rules over a [`Store`](crate::store::Store).
//!
//! Needs the `server` feature. Nothing here depends on a web framework.

mod audit;
mod cookie;
mod guard;
mod password;
mod service;
mod session;
mod throttle;

pub use self::audit::{Actor, AuditEvent};
pub use self::cookie::{generate_session_key, session_cookie, verify_session_cookie};
pub use self::guard::SessionGuard;
pub use self::password::{PasswordError, dummy_hash, hash_password, verify_password};
#[cfg(all(feature = "google", feature = "axum08"))]
pub(crate) use self::service::GoogleReturn;
pub use self::service::{
    Auth, AuthBuilder, AuthEvent, Bootstrap, BootstrapAdmin, CookieConfig, Error, Result, Secure,
    load_or_create_key,
};
pub use self::session::{
    SESSION_LIFETIME, SESSION_LIFETIME_DAYS, TOKEN_LIFETIME, is_expired, new_session_id, new_token,
    session_expiry, token_expiry,
};
