//! Actor-attributed records of what [`Auth`](super::Auth) operations did,
//! for an app's audit log.

use jiff::Timestamp;

use crate::store::{Session, User};
use crate::types::{UserId, UserInfo};

/// Who performed an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Actor {
    /// A signed-in user, acting through their session.
    User {
        /// The session's user.
        user: UserId,
        /// The admin impersonating `user` in that session, if any: the
        /// person who actually acted.
        impersonator: Option<UserId>,
    },
    /// The app itself, through an operation that takes no actor:
    /// [`bootstrap_admin`](super::Auth::bootstrap_admin),
    /// [`recovery_link`](super::Auth::recovery_link),
    /// [`import_user`](super::Auth::import_user), or Cloudflare Access
    /// activating a pending user.
    System,
}

impl Actor {
    /// The user signed in with `session`, as loaded for the request.
    pub fn of(user: &User, session: &Session) -> Self {
        Self::User {
            user: user.id,
            impersonator: session.impersonator,
        }
    }

    /// The user acting with no admin impersonating them.
    pub fn user(user: UserId) -> Self {
        Self::User {
            user,
            impersonator: None,
        }
    }

    /// The person responsible: the impersonating admin if there is one,
    /// otherwise the user; `None` for [`Actor::System`].
    pub fn responsible(&self) -> Option<UserId> {
        match *self {
            Self::User { user, impersonator } => Some(impersonator.unwrap_or(user)),
            Self::System => None,
        }
    }
}

/// What an [`Auth`](super::Auth) operation did, who did it, and to whom,
/// for an app's audit log. Receive them with
/// [`AuthBuilder::audit`](super::AuthBuilder::audit).
///
/// Each is sent once, after the change is stored. Read-only operations,
/// sign-ins and sign-outs send none.
///
/// Unlike an [`AuthEvent`](super::AuthEvent), which says what state changed
/// so that open sockets can follow it, this says which operation ran: one
/// operation may send several `AuthEvent`s but sends one `AuditEvent`, and
/// operations that change nothing a socket sees, such as issuing a link or
/// impersonating, send one too.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditEvent {
    /// A user was created, pending:
    /// [`create_user`](super::Auth::create_user) by an admin, or
    /// [`bootstrap_admin`](super::Auth::bootstrap_admin) and
    /// [`import_user`](super::Auth::import_user) by the system.
    UserCreated {
        /// Who created them.
        actor: Actor,
        /// The user as created.
        user: UserInfo,
    },
    /// A user's login, email or role changed:
    /// [`update_user`](super::Auth::update_user) or
    /// [`set_role`](super::Auth::set_role). Not sent when nothing changed.
    UserUpdated {
        /// Who changed them: an admin, or the user themselves.
        actor: Actor,
        /// The user before the change.
        before: UserInfo,
        /// The user after the change.
        after: UserInfo,
    },
    /// An admin revoked the user's access, with
    /// [`revoke_access`](super::Auth::revoke_access).
    AccessRevoked {
        /// The admin.
        actor: Actor,
        /// The user before the change.
        before: UserInfo,
        /// The user after the change, revoked.
        after: UserInfo,
    },
    /// Cloudflare Access activated a pending user who signed in through it.
    Activated {
        /// Always [`Actor::System`].
        actor: Actor,
        /// The user, now active.
        user: UserInfo,
    },
    /// An admin deleted the user, with
    /// [`delete_user`](super::Auth::delete_user).
    UserDeleted {
        /// The admin.
        actor: Actor,
        /// The user as they were just before.
        user: UserInfo,
    },
    /// An admin ended all of the user's sessions, with
    /// [`sign_out_everywhere`](super::Auth::sign_out_everywhere).
    SignedOutEverywhere {
        /// The admin.
        actor: Actor,
        /// The user.
        user: UserId,
    },
    /// A registration or reset link was issued, using up the user's
    /// earlier ones: [`issue_link`](super::Auth::issue_link) and
    /// [`create_user`](super::Auth::create_user) by an admin, or
    /// [`bootstrap_admin`](super::Auth::bootstrap_admin) and
    /// [`recovery_link`](super::Auth::recovery_link) by the system.
    LinkIssued {
        /// Who issued it.
        actor: Actor,
        /// The user it is for.
        user: UserId,
        /// When it expires.
        expires_at: Timestamp,
    },
    /// An admin used up the user's links, with
    /// [`revoke_link`](super::Auth::revoke_link).
    LinkRevoked {
        /// The admin.
        actor: Actor,
        /// The user.
        user: UserId,
    },
    /// The user registered, or reset their credential, with a link: their
    /// other sessions ended.
    LinkRedeemed {
        /// The user, through the session the link signed in.
        actor: Actor,
        /// The user after the change, active.
        user: UserInfo,
    },
    /// The user changed their own credential, keeping the session they
    /// acted from and ending their others: a new password, or a switch to
    /// a Google account.
    CredentialChanged {
        /// The user, possibly impersonated.
        actor: Actor,
        /// The user after the change.
        user: UserInfo,
    },
    /// An admin started impersonating the user, with
    /// [`impersonate`](super::Auth::impersonate).
    ImpersonationStarted {
        /// The admin.
        admin: UserId,
        /// The impersonated user.
        user: UserId,
    },
    /// An admin stopped impersonating the user, with
    /// [`stop_impersonating`](super::Auth::stop_impersonating).
    ImpersonationStopped {
        /// The admin.
        admin: UserId,
        /// The impersonated user.
        user: UserId,
    },
}

impl AuditEvent {
    /// Who performed the operation. For impersonation it is the admin.
    pub fn actor(&self) -> Actor {
        match self {
            Self::UserCreated { actor, .. }
            | Self::UserUpdated { actor, .. }
            | Self::AccessRevoked { actor, .. }
            | Self::Activated { actor, .. }
            | Self::UserDeleted { actor, .. }
            | Self::SignedOutEverywhere { actor, .. }
            | Self::LinkIssued { actor, .. }
            | Self::LinkRevoked { actor, .. }
            | Self::LinkRedeemed { actor, .. }
            | Self::CredentialChanged { actor, .. } => *actor,
            Self::ImpersonationStarted { admin, .. } | Self::ImpersonationStopped { admin, .. } => {
                Actor::user(*admin)
            }
        }
    }

    /// The user the operation acted on.
    pub fn user(&self) -> UserId {
        match self {
            Self::UserCreated { user, .. }
            | Self::Activated { user, .. }
            | Self::UserDeleted { user, .. }
            | Self::LinkRedeemed { user, .. }
            | Self::CredentialChanged { user, .. } => user.id,
            Self::UserUpdated { after, .. } | Self::AccessRevoked { after, .. } => after.id,
            Self::SignedOutEverywhere { user, .. }
            | Self::LinkIssued { user, .. }
            | Self::LinkRevoked { user, .. }
            | Self::ImpersonationStarted { user, .. }
            | Self::ImpersonationStopped { user, .. } => *user,
        }
    }
}
