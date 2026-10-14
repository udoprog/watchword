use std::net::SocketAddr;

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, FromRef, FromRequest, FromRequestParts, Path, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;

use super::{Admin, SignedIn};
use crate::Auth;
use crate::core::Error;
use crate::store::{Session, User};
use crate::types::{
    AuthConfig, AuthError, CreatedUser, Link, LoginRequest, NewUser, PasswordChange, RegisterInfo,
    RegisterRequest, UserChange, UserEntry, UserId, UserInfo,
};

/// The library's `/api/auth` JSON routes, to merge into the app's router.
///
/// | Route | Who | What |
/// |---|---|---|
/// | `GET /api/auth/config` | anyone | [`AuthConfig`] |
/// | `GET /api/auth/me` | signed in | [`UserInfo`] |
/// | `POST /api/auth/login` | anyone | [`LoginRequest`] → [`UserInfo`] + cookie; throttled |
/// | `POST /api/auth/logout` | anyone | 204; ends the session and clears the cookie |
/// | `GET /api/auth/register/{token}` | anyone | [`RegisterInfo`]; 404 unknown, 410 used or expired |
/// | `POST /api/auth/register/{token}` | anyone | [`RegisterRequest`] → [`UserInfo`] + cookie; ends the user's other sessions |
/// | `POST /api/auth/account/password` | signed in | [`PasswordChange`] → [`UserInfo`]; keeps this session, ends the others |
/// | `PATCH /api/auth/account` | signed in | [`UserChange`] of the own login or email → [`UserInfo`] |
/// | `GET /api/auth/users` | admin | `Vec<`[`UserEntry`]`>` |
/// | `POST /api/auth/users` | admin | [`NewUser`] → [`CreatedUser`] |
/// | `PATCH /api/auth/users/{id}` | admin | [`UserChange`] → [`UserInfo`]; not the own role |
/// | `DELETE /api/auth/users/{id}` | admin | 204; not self |
/// | `POST /api/auth/users/{id}/link` | admin | [`Link`], using up the user's earlier links |
/// | `DELETE /api/auth/users/{id}/link` | admin | 204; uses up the user's links |
/// | `POST /api/auth/users/{id}/sign-out` | admin | 204; ends all of the user's sessions |
/// | `POST /api/auth/users/{id}/revoke` | admin | [`UserInfo`]; revokes access; not self |
/// | `POST /api/auth/users/{id}/impersonate` | admin, if enabled | [`UserInfo`] + cookie for a session as that user; not self, not revoked |
///
/// `{id}` is the decimal [`UserId`]. Errors are an [`AuthError`] body with
/// its status: 401, 403, 404, 409, 410, 429, or 400 with a message, which a
/// malformed JSON body also gets.
///
/// `POST /api/auth/login` throttles by the client's address, so the app must
/// be served with `into_make_service_with_connect_info::<SocketAddr>()`;
/// without it, sign-in fails with a logged 500. Behind a reverse proxy, list
/// it in [`AuthBuilder::trusted_proxies`](crate::AuthBuilder::trusted_proxies).
pub fn routes<S>() -> Router<S>
where
    Auth: FromRef<S>,
    S: Clone + Send + Sync + 'static,
{
    // SEAM(card D, feature `cloudflare`): `POST /api/auth/cloudflare`, which
    // signs in with the request's Access credentials (`Auth::sign_in_cloudflare`)
    // and answers `UserInfo` + cookie as `login` does, goes here once the
    // Cloudflare provider lands. See also `config` below.
    //
    // SEAM(card E, feature `google`): `GET /api/auth/google`,
    // `GET /api/auth/google/register/{token}`, `GET /api/auth/google/link`
    // (signed in) and the callback at the path of the configured
    // `redirect_url` (default `/api/auth/google/redirect`) go here once the
    // Google provider lands. `register_info` below then reports `google`.
    Router::new()
        .route("/api/auth/config", get(config))
        .route("/api/auth/me", get(me))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route(
            "/api/auth/register/{token}",
            get(register_info).post(register),
        )
        .route("/api/auth/account", axum::routing::patch(update_account))
        .route("/api/auth/account/password", post(change_password))
        .route("/api/auth/users", get(users).post(create_user))
        .route(
            "/api/auth/users/{id}",
            axum::routing::patch(update_user).delete(delete_user),
        )
        .route(
            "/api/auth/users/{id}/link",
            post(issue_link).delete(revoke_link),
        )
        .route("/api/auth/users/{id}/sign-out", post(sign_out_everywhere))
        .route("/api/auth/users/{id}/revoke", post(revoke_access))
        .route("/api/auth/users/{id}/impersonate", post(impersonate))
}

/// A JSON body whose rejection is [`AuthError::Invalid`], so a malformed
/// request gets the same error body as every other refusal.
struct Body<T>(T);

impl<T, S> FromRequest<S> for Body<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(request, state).await {
            Ok(Json(value)) => Ok(Body(value)),
            Err(rejection) => Err(invalid_body(rejection).into()),
        }
    }
}

fn invalid_body(rejection: JsonRejection) -> AuthError {
    AuthError::Invalid(format!("Invalid request: {}", rejection.body_text()))
}

/// The `{id}` of a user route; anything but a decimal id is
/// [`AuthError::NotFound`].
struct Id(UserId);

impl<S> FromRequestParts<S> for Id
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<u64>::from_request_parts(parts, state).await {
            Ok(Path(id)) => Ok(Id(UserId(id))),
            Err(_) => Err(AuthError::NotFound.into()),
        }
    }
}

/// The `{token}` of a link route.
struct Token(String);

impl<S> FromRequestParts<S> for Token
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<String>::from_request_parts(parts, state).await {
            Ok(Path(token)) => Ok(Token(token)),
            Err(_) => Err(AuthError::NotFound.into()),
        }
    }
}

/// The peer's address, when the app is served with connect info.
struct Peer(Option<SocketAddr>);

impl<S> FromRequestParts<S> for Peer
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let peer = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .ok()
            .map(|ConnectInfo(addr)| addr);
        Ok(Peer(peer))
    }
}

/// Answers `user` with a cookie that signs in `session`.
fn signed_in(auth: &Auth, headers: &HeaderMap, user: &User, session: &Session) -> Response {
    let cookie = auth.set_cookie(headers, &session.id);
    ([(header::SET_COOKIE, cookie)], Json(user.info())).into_response()
}

fn cookie_header(value: HeaderValue) -> [(header::HeaderName, HeaderValue); 1] {
    [(header::SET_COOKIE, value)]
}

async fn config(State(auth): State<Auth>) -> Json<AuthConfig> {
    Json(AuthConfig {
        password: true,
        // SEAM(card E): whether Google sign-in is configured.
        google: false,
        // SEAM(card D): whether this request presents Access credentials
        // that map to a user (`presents_access`); takes the request headers.
        cloudflare: false,
        logins: auth.uses_logins(),
    })
}

async fn me(signed_in: SignedIn) -> Json<UserInfo> {
    Json(signed_in.user.info())
}

async fn login(
    State(auth): State<Auth>,
    Peer(peer): Peer,
    headers: HeaderMap,
    Body(request): Body<LoginRequest>,
) -> Result<Response, Error> {
    let Some(peer) = peer else {
        tracing::error!(
            "auth: sign-in needs the client's address; serve the app with \
             `into_make_service_with_connect_info::<SocketAddr>()`"
        );
        return Ok((StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response());
    };

    let address = auth.client_address(peer.ip(), &headers);
    let (user, session) = auth.sign_in_password(address, &request).await?;
    Ok(signed_in(&auth, &headers, &user, &session))
}

async fn logout(State(auth): State<Auth>, headers: HeaderMap) -> Result<Response, Error> {
    if let Some(id) = auth.session_id(&headers) {
        auth.sign_out(&id).await?;
    }

    let clear = auth.clear_cookie(&headers);
    Ok((StatusCode::NO_CONTENT, cookie_header(clear)).into_response())
}

async fn register_info(
    State(auth): State<Auth>,
    Token(token): Token,
) -> Result<Json<RegisterInfo>, Error> {
    // SEAM(card E): `google` is set by `Auth::register_info` once Google is
    // configurable.
    Ok(Json(auth.register_info(&token).await?))
}

async fn register(
    State(auth): State<Auth>,
    Token(token): Token,
    headers: HeaderMap,
    Body(request): Body<RegisterRequest>,
) -> Result<Response, Error> {
    let (user, session) = auth.register(&token, &request).await?;
    Ok(signed_in(&auth, &headers, &user, &session))
}

async fn change_password(
    State(auth): State<Auth>,
    SignedIn { user, session }: SignedIn,
    Body(change): Body<PasswordChange>,
) -> Result<Json<UserInfo>, Error> {
    let user = auth.change_password(&user, &session, &change).await?;
    Ok(Json(user.info()))
}

async fn update_account(
    State(auth): State<Auth>,
    SignedIn { user, .. }: SignedIn,
    Body(change): Body<UserChange>,
) -> Result<Json<UserInfo>, Error> {
    if change.role.is_some() {
        return Err(AuthError::Invalid("The role cannot be changed here.".to_owned()).into());
    }

    let user = auth.update_user(&user, user.id, &change).await?;
    Ok(Json(user.info()))
}

async fn users(
    State(auth): State<Auth>,
    Admin(admin): Admin,
) -> Result<Json<Vec<UserEntry>>, Error> {
    Ok(Json(auth.users(&admin.user).await?))
}

async fn create_user(
    State(auth): State<Auth>,
    Admin(admin): Admin,
    Body(new): Body<NewUser>,
) -> Result<Json<CreatedUser>, Error> {
    let (entry, link) = auth.create_user(&admin.user, &new).await?;
    Ok(Json(CreatedUser { entry, link }))
}

async fn update_user(
    State(auth): State<Auth>,
    Admin(admin): Admin,
    Id(id): Id,
    Body(change): Body<UserChange>,
) -> Result<Json<UserInfo>, Error> {
    let user = auth.update_user(&admin.user, id, &change).await?;
    Ok(Json(user.info()))
}

async fn delete_user(
    State(auth): State<Auth>,
    Admin(admin): Admin,
    Id(id): Id,
) -> Result<StatusCode, Error> {
    auth.delete_user(&admin.user, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn issue_link(
    State(auth): State<Auth>,
    Admin(admin): Admin,
    Id(id): Id,
) -> Result<Json<Link>, Error> {
    Ok(Json(auth.issue_link(&admin.user, id).await?))
}

async fn revoke_link(
    State(auth): State<Auth>,
    Admin(admin): Admin,
    Id(id): Id,
) -> Result<StatusCode, Error> {
    auth.revoke_link(&admin.user, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn sign_out_everywhere(
    State(auth): State<Auth>,
    Admin(admin): Admin,
    Id(id): Id,
) -> Result<StatusCode, Error> {
    auth.sign_out_everywhere(&admin.user, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_access(
    State(auth): State<Auth>,
    Admin(admin): Admin,
    Id(id): Id,
) -> Result<Json<UserInfo>, Error> {
    let user = auth.revoke_access(&admin.user, id).await?;
    Ok(Json(user.info()))
}

async fn impersonate(
    State(auth): State<Auth>,
    Admin(admin): Admin,
    Id(id): Id,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let (user, session) = auth.impersonate(&admin.user, id).await?;
    Ok(signed_in(&auth, &headers, &user, &session))
}
