//! watchword's account and user-management operations, and its live updates,
//! as [musli-web] 0.4 API types, so an app can carry them on the musli-web
//! WebSocket it already has.
//!
//! The endpoints and [`AuthBroadcast`] form their own `define!` list beside
//! the app's: one connection carries both, as long as their ids differ.
//! watchword owns the ids 32000–32255 and pins each of its types to one of
//! them, so an app's own implicit ids, which count up from 1, never clash with
//! them. A released id never changes meaning.
//!
//! Every response is `Result<T, AuthError>`, so a frontend gets the same
//! structured [`AuthError`] over the socket as over HTTP. Each request body is
//! its own type here, since musli-web ties a request type to one endpoint.
//!
//! | Endpoint | Id | Request | Response's `Ok` |
//! |---|---|---|---|
//! | [`Me`] | 32000 | [`MeRequest`] | [`UserInfo`] |
//! | [`UpdateAccount`] | 32001 | [`UserChange`] | [`UserInfo`] |
//! | [`ChangePassword`] | 32002 | [`PasswordChange`] | [`UserInfo`] |
//! | [`Users`] | 32003 | [`UsersRequest`] | `Vec<`[`UserEntry`]`>` |
//! | [`CreateUser`] | 32004 | [`NewUser`] | [`CreatedUser`] |
//! | [`UpdateUser`] | 32005 | [`UserUpdate`] | [`UserInfo`] |
//! | [`DeleteUser`] | 32006 | [`DeleteUserRequest`] | `()` |
//! | [`IssueLink`] | 32007 | [`IssueLinkRequest`] | [`Link`] |
//! | [`RevokeLink`] | 32008 | [`RevokeLinkRequest`] | `()` |
//! | [`SignOutUser`] | 32009 | [`SignOutUserRequest`] | `()` |
//! | [`RevokeAccess`] | 32010 | [`RevokeAccessRequest`] | [`UserInfo`] |
//!
//! [`AuthBroadcast`] (32100) carries [`AuthUpdate`]s.
//!
//! The types are those of `watchword_core::musliweb04`, which an app's
//! wasm-safe `api` crate can use. With `axum08` as well, the server side is
//! here too: a `Connection` (`musliweb04` and `axum08`) turns each
//! [`AuthEvent`](crate::AuthEvent) into the [`AuthUpdate`] one socket may
//! see.
//!
//! The design is in `docs/design.md`, section 2.7.
//!
//! [`AuthError`]: crate::AuthError
//! [`UserInfo`]: crate::UserInfo
//! [`UserChange`]: crate::UserChange
//! [`PasswordChange`]: crate::PasswordChange
//! [`UserEntry`]: crate::UserEntry
//! [`NewUser`]: crate::NewUser
//! [`CreatedUser`]: crate::CreatedUser
//! [`Link`]: crate::Link
//! [musli-web]: https://docs.rs/musli-web

#[doc(inline)]
pub use watchword_core::musliweb04::*;

#[cfg(feature = "axum08")]
mod connection;

#[cfg(feature = "axum08")]
#[cfg_attr(watchword_docsrs, doc(cfg(feature = "axum08")))]
pub use self::connection::Connection;

#[cfg(all(test, feature = "axum08"))]
mod tests;
