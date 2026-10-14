//! The server core: password hashing, session ids and link tokens, and signed
//! session cookies.
//!
//! Needs the `server` feature. Nothing here touches storage or a web
//! framework.

mod cookie;
mod password;
mod session;

pub use self::cookie::{generate_session_key, session_cookie, verify_session_cookie};
pub use self::password::{PasswordError, dummy_hash, hash_password, verify_password};
pub use self::session::{
    SESSION_LIFETIME, SESSION_LIFETIME_DAYS, TOKEN_LIFETIME, is_expired, new_session_id, new_token,
    session_expiry, token_expiry,
};
