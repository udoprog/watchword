//! Authentication for axum + Yew applications, in layers selected by cargo
//! features:
//!
//! | Feature | Module |
//! |---|---|
//! | *(none)* | [`types`]: ids, roles, account state, wire types, [`AuthError`], validation |
//! | `musli` | musli `Encode`/`Decode` on the wire types |
//! | `server` | `core`: password hashing, ids, signed session cookies, the `Auth` service; `store`: the `Store` trait and `MemoryStore` |
//! | `cloudflare` | `cloudflare`: Cloudflare Access (implies `server`) |
//! | `google` | `google`: Google OAuth (implies `server`) |
//! | `axum` | `axum`: extractors, routes, WebSocket session guard (implies `server`) |
//! | `sqll` | `sqll`: a SQLite store (implies `server`) |
//! | `yew` | `yew`: components, context, hook, HTTP client |
//! | `test-util` | `AuthBuilder::google_endpoints`, to test Google sign-in offline; with `axum`, the fake Google `google::fake` (implies `google`) |
//!
//! Server-only and browser-only dependencies never share a feature, so a
//! wasm frontend takes `yew` without pulling in server code. The design is
//! recorded in `docs/design.md`.

pub mod types;

#[cfg(feature = "server")]
pub mod core;

#[cfg(feature = "server")]
pub mod store;

#[cfg(feature = "cloudflare")]
pub mod cloudflare;

#[cfg(feature = "google")]
pub mod google;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "sqll")]
pub mod sqll;

#[cfg(feature = "yew")]
pub mod yew;

pub use self::types::{
    Access, AuthConfig, AuthError, CloudflareConfig, Conflict, CreatedUser, Impersonator, Link,
    LoginRequest, MIN_PASSWORD_LEN, Method, NewUser, PasswordChange, RegisterInfo, RegisterRequest,
    Role, UserChange, UserEntry, UserId, UserInfo, normalize_email, validate_password,
};

#[cfg(feature = "server")]
pub use self::core::{
    Auth, AuthBuilder, AuthEvent, BootstrapAdmin, CookieConfig, PasswordError, SESSION_LIFETIME,
    Secure, TOKEN_LIFETIME, dummy_hash, generate_session_key, hash_password, is_expired,
    load_or_create_key, new_session_id, new_token, session_cookie, session_expiry, token_expiry,
    verify_password, verify_session_cookie,
};

#[cfg(feature = "server")]
pub use self::store::{MemoryStore, Store};

#[cfg(feature = "google")]
pub use self::google::GoogleConfig;
#[cfg(feature = "sqll")]
pub use self::sqll::SqllStore;
