use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;

use crate::Auth;
use crate::core::Error;
use crate::store::{Session, User};
use crate::types::AuthError;

/// The signed-in user and their session, loaded fresh for each request.
///
/// Rejects with [`AuthError::Unauthorized`] (401) unless the request's
/// session cookie names a live session of an active user, or of a pending
/// user an admin impersonates. An impersonated session is live only while
/// its admin is still an active admin. Since the user (and for an
/// impersonated session its admin) is read from the store on every request,
/// a role change or revocation applies to the next one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIn {
    /// The user, as stored now.
    pub user: User,
    /// The session the request is signed in with.
    pub session: Session,
}

impl SignedIn {
    async fn load(parts: &mut Parts, auth: &Auth) -> Result<Option<Self>, Error> {
        // Another extractor in the same handler may have loaded it already.
        if let Some(signed_in) = parts.extensions.get::<SignedIn>() {
            return Ok(Some(signed_in.clone()));
        }

        let Some(id) = auth.session_id(&parts.headers) else {
            return Ok(None);
        };

        let Some((user, session)) = auth.session(&id).await? else {
            return Ok(None);
        };

        let signed_in = SignedIn { user, session };
        parts.extensions.insert(signed_in.clone());
        Ok(Some(signed_in))
    }
}

impl<S> FromRequestParts<S> for SignedIn
where
    Auth: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = Auth::from_ref(state);

        match Self::load(parts, &auth).await? {
            Some(signed_in) => Ok(signed_in),
            None => Err(AuthError::Unauthorized.into()),
        }
    }
}

/// A signed-in admin.
///
/// Rejects as [`SignedIn`] does, and with [`AuthError::Forbidden`] (403)
/// unless the user is an admin now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admin(pub SignedIn);

impl<S> FromRequestParts<S> for Admin
where
    Auth: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let signed_in = SignedIn::from_request_parts(parts, state).await?;

        if !signed_in.user.is_admin() {
            return Err(AuthError::Forbidden.into());
        }

        Ok(Admin(signed_in))
    }
}

/// The signed-in user, if there is one, for routes that anyone may use.
///
/// Rejects only when the store fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaybeSignedIn(pub Option<SignedIn>);

impl<S> FromRequestParts<S> for MaybeSignedIn
where
    Auth: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = Auth::from_ref(state);
        Ok(MaybeSignedIn(SignedIn::load(parts, &auth).await?))
    }
}

/// The id of the request's live session, without loading its user, for hot
/// routes such as map tiles or images.
///
/// A session confirmed live is believed for 10 seconds without asking the
/// store again, for up to 1024 sessions. Signing out, revoking or deleting a
/// user through [`Auth`] ends the session here at once, and so does revoking,
/// demoting or deleting the admin who impersonates in it; the 10 seconds only
/// delay noticing a session ended in another process.
///
/// Rejects with [`AuthError::Unauthorized`] (401) as [`SignedIn`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveSession(pub String);

impl<S> FromRequestParts<S> for LiveSession
where
    Auth: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth = Auth::from_ref(state);

        let Some(id) = auth.session_id(&parts.headers) else {
            return Err(AuthError::Unauthorized.into());
        };

        if !auth.session_live(&id).await? {
            return Err(AuthError::Unauthorized.into());
        }

        Ok(LiveSession(id))
    }
}
