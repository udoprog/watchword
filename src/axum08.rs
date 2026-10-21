//! axum 0.8 integration (the `axum08` feature): extractors and the
//! `/api/auth` JSON routes. A WebSocket watches its session with
//! [`Auth::guard`](crate::Auth::guard), which needs no axum.
//!
//! Every extractor and the routes need [`Auth`](crate::Auth) to be
//! extractable from the app's state, through `FromRef`. An app whose state
//! *is* the `Auth` gets that for free; otherwise derive or implement
//! `FromRef<AppState> for Auth`.
//!
//! ```no_run
//! # extern crate axum08 as axum;
//! use std::net::SocketAddr;
//!
//! use watchword::axum08::{SignedIn, routes};
//! use watchword::{Auth, MemoryStore, generate_session_key};
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
//! An app gates its own routes with the same extractors: [`SignedIn`] for a
//! signed-in user and [`Admin`] for an admin, both read from the store on
//! every request. On a WebSocket, which outlives roles and sessions, its own
//! requests are gated per request instead: on a musli-web socket with
//! `musliweb04::Connection::signed_in` and `Connection::require_admin`,
//! which answer as these extractors do, or, for the role as last seen
//! without a store read, with the socket's
//! [`SessionGuard::user`](crate::core::SessionGuard::user) and
//! [`watch_user`](crate::core::SessionGuard::watch_user).
//!
//! To gate a whole site, pages included, layer [`require_session`] on the
//! router: it lets watchword's [public](is_public) routes through, answers
//! 401 to API requests and sends a browser to the sign-in page with a
//! `?next=` back to the page it asked for (see [`RequireSession`]).
//!
//! The design is in `docs/design.md`, section 2.5.

mod error;
mod extract;
mod gate;
#[cfg(feature = "google")]
mod google;
mod live;
mod routes;

#[cfg(test)]
mod tests;

pub use self::extract::{Admin, LiveSession, MaybeSignedIn, SignedIn};
pub use self::gate::{RequireSession, is_public, require_session};
pub(crate) use self::live::LiveCache;
pub use self::routes::routes;
