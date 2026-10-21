//! The Google OAuth routes (features `axum08` and `google`); see
//! [`crate::google`].

use std::string::String;

use axum08::Router;
use axum08::extract::rejection::QueryRejection;
use axum08::extract::{FromRef, Query, State};
use axum08::http::{HeaderMap, header};
use axum08::response::{IntoResponse, Redirect, Response};
use axum08::routing::get;
use serde::Deserialize;

use super::SignedIn;
use super::gate::encode_into;
use super::routes::Token;
use crate::Auth;
use crate::core::{Error, GoogleReturn};
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

/// The query of `GET /api/auth/google`.
#[derive(Default, Deserialize)]
struct SignInQuery {
    next: Option<String>,
}

async fn sign_in(
    State(auth): State<Auth>,
    query: Result<Query<SignInQuery>, QueryRejection>,
) -> Result<Redirect, Error> {
    // A malformed query is as good as none.
    let query = query.map(|Query(query)| query).unwrap_or_default();
    Ok(Redirect::to(
        auth.google_sign_in(query.next.as_deref())?.as_str(),
    ))
}

async fn register(State(auth): State<Auth>, Token(token): Token) -> Result<Redirect, Error> {
    Ok(Redirect::to(auth.google_register(&token).await?.as_str()))
}

async fn link(
    State(auth): State<Auth>,
    SignedIn { user, session }: SignedIn,
) -> Result<Redirect, Error> {
    Ok(Redirect::to(auth.google_link(&user, &session)?.as_str()))
}

async fn callback(
    State(auth): State<Auth>,
    headers: HeaderMap,
    query: Result<Query<Callback>, QueryRejection>,
) -> Response {
    // A malformed query fails like a missing code.
    let callback = query.map(|Query(callback)| callback).unwrap_or_default();

    let GoogleReturn { next, result } = auth.google_callback(&callback).await;

    match result {
        Ok((_, session)) => {
            let cookie = auth.set_cookie(&headers, &session.id);
            let to = next.as_deref().unwrap_or("/");
            ([(header::SET_COOKIE, cookie)], Redirect::to(to)).into_response()
        }
        Err(failure) => {
            // The sign-in page, wherever the gate puts it, keeps `next` for
            // trying again.
            let mut url = format!("/?error={}", failure.code());

            if let Some(next) = &next {
                url.push_str("&next=");
                encode_into(&mut url, next);
            }

            Redirect::to(&url).into_response()
        }
    }
}
