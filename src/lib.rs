//! Authentication for axum servers and Yew frontends: password, Cloudflare
//! Access and Google sign-in, sessions and user management. It is shared by
//! track, army and territory, and grew out of `crates/auth` in track.
//!
//! The design, including the full API each layer grows into, is in
//! [`docs/design.md`].
//!
//! <br>
//!
//! ## Features
//!
//! Each layer sits behind a cargo feature, so an app takes only what it uses.
//! Server-only and browser-only dependencies never share a feature, so a wasm
//! frontend can take `yew` without pulling in server code. No feature is on by
//! default. On docs.rs, items that need a feature are marked with it.
//!
//! | Feature | Module | What it provides |
//! |---|---|---|
//! | *(none)* | [`types`] | `UserId`, `Role`, `Access`, `Method`, the wire types (`UserInfo`, `AuthConfig`, `LoginRequest`, `CreatedUser`, ...), `AuthError`, `validate_password`, `normalize_email` |
//! | `musli` | | musli `Encode`/`Decode` on the wire types |
//! | `server` | [`core`], [`store`] | bcrypt password hashing with `dummy_hash` timing, session ids and link tokens, HMAC-signed session cookies; the `Auth` service (sign-in, registration links, user management, sign-in throttle, `AuthEvent`s, bootstrap admin); the `Store` trait and `MemoryStore` |
//! | `cloudflare` | [`cloudflare`] | Cloudflare Access JWT verification with a pluggable `KeyFetcher` (implies `server`) |
//! | `google` | [`google`] | Google OAuth: `GoogleConfig` for `AuthBuilder::google`; with `axum`, `routes()` serves its start, registration, account-switch and callback routes (implies `server`) |
//! | `axum` | [`axum`] | the `SignedIn`, `Admin`, `MaybeSignedIn` and `LiveSession` extractors, `routes()` for the `/api/auth` JSON routes, and `Auth::guard` for WebSocket sessions, plus the Cloudflare and Google routes when those features are on (implies `server`) |
//! | `sqll` | [`sqll`] | `SqllStore`, a `Store` over SQLite on a sqll 0.14 pool (its own, or nested in the app's), its `SCHEMA`, and the one-time migrations for track and territory in `docs/sqll/` (implies `server`) |
//! | `test-util` | [`google::fake`] | for an app's tests: `AuthBuilder::google_endpoints`, and with `axum` `FakeGoogle`, a local fake Google to sign in through offline (implies `google`) |
//! | `yew` | [`yew`] | `AuthProvider`, `use_auth`, `SignIn`, `Register`, `AccountPanel`, `UserMenu`, `AdminUsers`, `CloudflareSettings` and the `http` client |
//!
//! The most-used names are re-exported at the crate root.
//!
//! <br>
//!
//! ## Using it
//!
//! The crate is not published. Depend on it by path; the package and the library
//! are both named `watchword`, and a dependency key of `auth` keeps code
//! referring to it as `auth`:
//!
//! ```toml
//! [dependencies]
//! # Server crate.
//! auth = { package = "watchword", path = "../watchword", features = ["axum", "cloudflare"] }
//! # Frontend crate.
//! auth = { package = "watchword", path = "../watchword", features = ["yew"] }
//! ```
//!
//! Adjust the path to where this repository is checked out relative to the
//! depending crate.
//!
//! <br>
//!
//! ## Example app
//!
//! [`examples/app`] is an axum server and a Yew frontend wired up with all three
//! sign-in methods, `MemoryStore` and a WebSocket held open for the session: a
//! reference for apps taking the library, and a way to try the components by
//! hand. It is its own cargo workspace, so it adds nothing to the library's
//! builds or lockfile.
//!
//! Build the frontend with [trunk], then run the server, which serves it:
//!
//! ```sh
//! cd examples/app/frontend && trunk build
//! cd examples/app && cargo run -p watchword-example-server -- --bind 127.0.0.1:8080
//! ```
//!
//! The server prints a registration link for the bootstrap admin (`admin` by
//! default, `--bootstrap-admin NAME` to change it); open it to choose a password
//! and sign in. Everything is in memory, so a restart starts over. Google sign-in
//! is on when `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set, with the
//! OAuth client's redirect URL at `PUBLIC_URL/api/auth/google/redirect`
//! (`--public-url`, by default `http://` plus the bind address). Cloudflare Access
//! is configured on the app's Settings page, or from `CLOUDFLARE_TEAM_DOMAIN` and
//! `CLOUDFLARE_AUDIENCE`; `CLOUDFLARE_TRUST_EMAIL_HEADER=1` accepts Access's email
//! header alone, for local testing only. `--help` lists the options.
//!
//! trunk builds with the `wasm-bindgen` CLI matching `examples/app/Cargo.lock`,
//! downloading it unless it is installed or already in trunk's cache.
//!
//! [`axum`]: https://docs.rs/watchword/latest/watchword/axum/index.html
//! [`cloudflare`]: https://docs.rs/watchword/latest/watchword/cloudflare/index.html
//! [`core`]: https://docs.rs/watchword/latest/watchword/core/index.html
//! [`docs/design.md`]: https://github.com/udoprog/watchword/blob/main/docs/design.md
//! [`examples/app`]: https://github.com/udoprog/watchword/tree/main/examples/app
//! [`google::fake`]: https://docs.rs/watchword/latest/watchword/google/fake/index.html
//! [`google`]: https://docs.rs/watchword/latest/watchword/google/index.html
//! [`sqll`]: https://docs.rs/watchword/latest/watchword/sqll/index.html
//! [`store`]: https://docs.rs/watchword/latest/watchword/store/index.html
//! [`types`]: https://docs.rs/watchword/latest/watchword/types/index.html
//! [`yew`]: https://docs.rs/watchword/latest/watchword/yew/index.html
//! [trunk]: https://trunkrs.dev

#![cfg_attr(watchword_docsrs, feature(doc_cfg))]

pub mod types;

#[cfg(feature = "server")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "server")))]
pub mod core;

#[cfg(feature = "server")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "server")))]
pub mod store;

#[cfg(feature = "cloudflare")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "cloudflare")))]
pub mod cloudflare;

#[cfg(feature = "google")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "google")))]
pub mod google;

#[cfg(feature = "axum")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "axum")))]
pub mod axum;

#[cfg(feature = "sqll")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "sqll")))]
pub mod sqll;

#[cfg(feature = "yew")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "yew")))]
pub mod yew;

pub use self::types::{
    Access, AuthConfig, AuthError, CloudflareConfig, Conflict, CreatedUser, Impersonator, Link,
    LoginRequest, MIN_PASSWORD_LEN, Method, NewUser, PasswordChange, RegisterInfo, RegisterRequest,
    Role, UserChange, UserEntry, UserId, UserInfo, normalize_email, validate_password,
};

#[cfg(feature = "server")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "server")))]
pub use self::core::{
    Auth, AuthBuilder, AuthEvent, BootstrapAdmin, CookieConfig, PasswordError, SESSION_LIFETIME,
    Secure, TOKEN_LIFETIME, dummy_hash, generate_session_key, hash_password, is_expired,
    load_or_create_key, new_session_id, new_token, session_cookie, session_expiry, token_expiry,
    verify_password, verify_session_cookie,
};

#[cfg(feature = "server")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "server")))]
pub use self::store::{MemoryStore, Store};

#[cfg(feature = "google")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "google")))]
pub use self::google::GoogleConfig;
#[cfg(feature = "sqll")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "sqll")))]
pub use self::sqll::SqllStore;
