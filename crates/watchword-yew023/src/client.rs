//! How the components make the requests that can use the app's socket.
//!
//! With the `musliweb05` feature and a socket handed over with
//! [`AuthContext::set_socket`](super::AuthContext::set_socket), each request
//! goes over the socket while it is open, and over [`http`] otherwise, so a
//! request made while the socket reconnects still works. The operations that
//! cannot use the socket (signing in and out, registering, impersonating,
//! the config, and checking the session) are always made with [`http`].

use std::vec::Vec;

#[cfg(feature = "musliweb05")]
use watchword_core::musliweb05::{
    CloudflareRequest, DeleteUserRequest, IssueLinkRequest, MeRequest, RevokeAccessRequest,
    RevokeLinkRequest, SignOutUserRequest, UserUpdate, UsersRequest,
};
use watchword_core::{
    CloudflareConfig, CreatedUser, Link, NewUser, PasswordChange, UserChange, UserEntry, UserId,
    UserInfo,
};

use super::http::{self, Error};
#[cfg(feature = "musliweb05")]
use super::socket::SocketHandle;

/// Sends `$body` over the client's socket and returns its answer, if the
/// socket took it; otherwise carries on to the HTTP request after it.
macro_rules! over_socket {
    ($client:expr, $body:expr) => {
        #[cfg(feature = "musliweb05")]
        {
            if let Some(socket) = &$client.socket {
                if let Some(result) = socket.request($body).await {
                    return result;
                }
            }
        }
    };
}

/// The transport for the account and admin requests: the app's socket when
/// one is handed over and open, HTTP otherwise.
#[derive(Clone, Default)]
pub(super) struct Client {
    #[cfg(feature = "musliweb05")]
    pub(super) socket: Option<SocketHandle>,
}

impl Client {
    /// After a response replaced the session cookie, such as when
    /// impersonating, the socket still speaks for the session its upgrade
    /// carried: requests go over HTTP until it reconnects.
    pub(super) fn session_replaced(&self) {
        #[cfg(feature = "musliweb05")]
        if let Some(socket) = &self.socket {
            socket.mark_stale();
        }
    }

    /// The signed-in user, like [`http::me`].
    pub(super) async fn me(&self) -> Result<UserInfo, Error> {
        over_socket!(self, MeRequest);
        http::me().await
    }

    /// Like [`http::update_account`].
    pub(super) async fn update_account(&self, change: &UserChange) -> Result<UserInfo, Error> {
        over_socket!(self, change.clone());
        http::update_account(change).await
    }

    /// Like [`http::change_password`].
    pub(super) async fn change_password(
        &self,
        request: &PasswordChange,
    ) -> Result<UserInfo, Error> {
        over_socket!(self, request.clone());
        http::change_password(request).await
    }

    /// Like [`http::users`].
    pub(super) async fn users(&self) -> Result<Vec<UserEntry>, Error> {
        over_socket!(self, UsersRequest);
        http::users().await
    }

    /// Like [`http::create_user`].
    pub(super) async fn create_user(&self, new: &NewUser) -> Result<CreatedUser, Error> {
        over_socket!(self, new.clone());
        http::create_user(new).await
    }

    /// Like [`http::update_user`].
    pub(super) async fn update_user(
        &self,
        id: UserId,
        change: &UserChange,
    ) -> Result<UserInfo, Error> {
        over_socket!(
            self,
            UserUpdate {
                id,
                change: change.clone(),
            }
        );
        http::update_user(id, change).await
    }

    /// Like [`http::delete_user`].
    pub(super) async fn delete_user(&self, id: UserId) -> Result<(), Error> {
        over_socket!(self, DeleteUserRequest { id });
        http::delete_user(id).await
    }

    /// Like [`http::issue_link`].
    pub(super) async fn issue_link(&self, id: UserId) -> Result<Link, Error> {
        over_socket!(self, IssueLinkRequest { id });
        http::issue_link(id).await
    }

    /// Like [`http::revoke_link`].
    pub(super) async fn revoke_link(&self, id: UserId) -> Result<(), Error> {
        over_socket!(self, RevokeLinkRequest { id });
        http::revoke_link(id).await
    }

    /// Like [`http::sign_out_user`].
    pub(super) async fn sign_out_user(&self, id: UserId) -> Result<(), Error> {
        over_socket!(self, SignOutUserRequest { id });
        http::sign_out_user(id).await
    }

    /// Like [`http::cloudflare_settings`].
    pub(super) async fn cloudflare_settings(&self) -> Result<CloudflareConfig, Error> {
        over_socket!(self, CloudflareRequest);
        http::cloudflare_settings().await
    }

    /// Like [`http::set_cloudflare_settings`].
    pub(super) async fn set_cloudflare_settings(
        &self,
        config: &CloudflareConfig,
    ) -> Result<CloudflareConfig, Error> {
        over_socket!(self, config.clone());
        http::set_cloudflare_settings(config).await
    }

    /// Like [`http::revoke_access`].
    pub(super) async fn revoke_access(&self, id: UserId) -> Result<(), Error> {
        #[cfg(feature = "musliweb05")]
        if let Some(socket) = &self.socket {
            let request = socket.request::<_, UserInfo>(RevokeAccessRequest { id });

            if let Some(result) = request.await {
                return result.map(drop);
            }
        }

        http::revoke_access(id).await
    }
}
