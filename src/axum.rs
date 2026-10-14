//! axum integration (the `axum` feature): extractors, the `/api/auth` JSON
//! routes and the WebSocket session guard.
//!
//! Every extractor and the routes need [`Auth`](crate::Auth) to be
//! extractable from the app's state, through `FromRef`. An app whose state
//! *is* the `Auth` gets that for free; otherwise derive or implement
//! `FromRef<AppState> for Auth`.
//!
//! ```no_run
//! use std::net::SocketAddr;
//!
//! use auth::axum::{SignedIn, routes};
//! use auth::{Auth, MemoryStore, generate_session_key};
//! use axum::Router;
//! use axum::routing::get;
//!
//! # async fn run() -> std::io::Result<()> {
//! let auth = Auth::builder(MemoryStore::new(), generate_session_key()).build();
//!
//! let app = Router::new()
//!     .route("/api/hello", get(|user: SignedIn| async move { format!("Hello {}", user.user.id) }))
//!     .merge(routes())
//!     .with_state(auth);
//!
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
//! // The sign-in route throttles by the client's address, so serve with
//! // connect info.
//! axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
//! # }
//! ```
//!
//! Errors are answered as an [`AuthError`](crate::AuthError) JSON body with
//! its [status](crate::AuthError::status), and internal failures (such as
//! the store failing) as a 500 that is logged with `tracing`. Both
//! [`AuthError`](crate::AuthError) and [`core::Error`](crate::core::Error)
//! implement `IntoResponse`, so an app's own handlers can return them too.
//!
//! The design is in `docs/design.md`, section 2.6.

mod error;
mod extract;
#[cfg(feature = "google")]
mod google;
mod guard;
mod live;
mod routes;

#[cfg(test)]
mod tests;

pub use self::extract::{Admin, LiveSession, MaybeSignedIn, SignedIn};
pub use self::guard::SessionGuard;
pub(crate) use self::live::LiveCache;
pub use self::routes::routes;
