use std::rc::Rc;

use yew::prelude::*;

use crate::types::{AuthConfig, UserInfo};

/// The signed-in user and what the app can do about the session, given by
/// [`AuthProvider`](super::AuthProvider) to its children. Get it with
/// [`use_auth`], or with `ctx.link().context::<AuthContext>(..)` in a struct
/// component.
#[derive(Clone, PartialEq)]
pub struct AuthContext {
    /// The signed-in user.
    pub user: Rc<UserInfo>,
    /// What the server offers, from `GET /api/auth/config`.
    pub config: AuthConfig,
    pub(super) sign_out: Callback<()>,
    pub(super) refresh: Callback<()>,
    pub(super) set_user: Callback<UserInfo>,
    pub(super) check_session: Callback<()>,
}

impl AuthContext {
    /// Whether the signed-in user is an admin.
    pub fn is_admin(&self) -> bool {
        self.user.is_admin()
    }

    /// Signs out and shows the sign-in page. The session is forgotten here
    /// even if the server cannot be reached; it then expires on the server.
    pub fn sign_out(&self) {
        self.sign_out.emit(());
    }

    /// Fetches the user and the config again, such as after the app learns
    /// that the user changed. A 401 shows the sign-in page with the
    /// provider's `signed_out_notice`; other failures keep what is shown.
    pub fn refresh(&self) {
        self.refresh.emit(());
    }

    /// Replaces the signed-in user, such as with the [`UserInfo`] an account
    /// route answered with. A copy of the same user without
    /// [`impersonated_by`](UserInfo::impersonated_by), such as from an admin
    /// route, keeps the current one.
    pub fn set_user(&self, user: UserInfo) {
        self.set_user.emit(user);
    }

    /// Asks the server whether the session is still live, such as when the
    /// app's socket closes. A 401 shows the sign-in page with the provider's
    /// `signed_out_notice`; other failures, such as the server being down,
    /// keep the user signed in. A check while one is in flight is dropped.
    pub fn check_session(&self) {
        self.check_session.emit(());
    }
}

/// The [`AuthContext`] of the enclosing [`AuthProvider`](super::AuthProvider).
///
/// # Panics
///
/// Panics outside an `AuthProvider`, whose children are only rendered once
/// a user is signed in.
#[hook]
pub fn use_auth() -> AuthContext {
    use_context::<AuthContext>().expect("use_auth() must be called inside <AuthProvider>")
}
