//! The Google OAuth routes (features `axum` and `google`); see
//! [`crate::google`].

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRef, Query, State};
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;

use super::SignedIn;
use super::routes::Token;
use crate::Auth;
use crate::core::Error;
use crate::google::{Callback, REDIRECT_PATH};

/// `GET /api/auth/google`, `/google/register/{token}`, `/google/link` and the
/// callback at [`REDIRECT_PATH`].
pub(super) fn routes<S>() -> Router<S>
where
    Auth: FromRef<S>,
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/api/auth/google", get(sign_in))
        .route("/api/auth/google/register/{token}", get(register))
        .route("/api/auth/google/link", get(link))
        .route(REDIRECT_PATH, get(callback))
}

async fn sign_in(State(auth): State<Auth>) -> Result<Redirect, Error> {
    Ok(Redirect::to(auth.google_sign_in()?.as_str()))
}

async fn register(State(auth): State<Auth>, Token(token): Token) -> Result<Redirect, Error> {
    Ok(Redirect::to(auth.google_register(&token).await?.as_str()))
}

async fn link(
    State(auth): State<Auth>,
    SignedIn { user, .. }: SignedIn,
) -> Result<Redirect, Error> {
    Ok(Redirect::to(auth.google_link(&user)?.as_str()))
}

async fn callback(
    State(auth): State<Auth>,
    headers: HeaderMap,
    query: Result<Query<Callback>, QueryRejection>,
) -> Response {
    // A malformed query fails like a missing code.
    let callback = query.map(|Query(callback)| callback).unwrap_or_default();

    match auth.google_callback(&callback).await {
        Ok((_, session)) => {
            let cookie = auth.set_cookie(&headers, &session.id);
            ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
        }
        Err(failure) => Redirect::to(&format!("/?error={}", failure.code())).into_response(),
    }
}
