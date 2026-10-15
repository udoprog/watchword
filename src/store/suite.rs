//! Tests of [`Auth`] over any [`Store`], so that every store runs the same
//! suite: `store_suite!(expr)` defines one `#[tokio::test]` per test, each
//! over a fresh store made by `expr` (evaluated inside the async test, so it
//! may `.await`).
//!
//! Ported from territory's `auth/tests.rs` and `bootstrap/tests.rs`, with
//! tests of the rules track and the design add.

use std::error::Error as StdError;
use std::net::IpAddr;

use jiff::{SignedDuration, Timestamp};

use super::{Credential, Session, Store, Token, TokenKind, User};
use crate::core::{Auth, AuthEvent, BootstrapAdmin, Error, generate_session_key, new_token};
use crate::types::{
    Access, AuthError, Conflict, LoginRequest, Method, NewUser, PasswordChange, RegisterRequest,
    Role, UserChange, UserId,
};

pub(crate) type TestResult = Result<(), Box<dyn StdError>>;

const PASSWORD: &str = "correct horse battery staple";
const ADMIN: &str = "admin@example.com";

macro_rules! store_suite {
    ($open:expr) => {
        $crate::store::suite::store_suite! {
            @tests $open,
            revoked_users_cannot_get_a_session_through_any_login_path,
            revoked_google_user_cannot_sign_in_with_old_method,
            unregistered_users_cannot_sign_in,
            reinvited_users_can_register_again,
            google_login_only_matches_google_registrations,
            registered_users_only_accept_reset_tokens,
            pending_and_reinvited_users_get_registration_tokens,
            replacing_credentials_through_google_ends_sessions,
            google_users_are_bound_by_subject,
            replacing_credentials_replaces_the_google_subject,
            a_google_account_binds_only_one_user,
            bootstraps_an_admin_into_an_empty_store,
            bootstraps_an_admin_by_login,
            bootstrap_is_skipped_once_users_exist,
            password_sign_in_by_login_or_email,
            password_sign_in_by_email_only_without_logins,
            password_sign_in_is_throttled,
            registering_ends_other_sessions,
            links_expire_and_are_single_use,
            issuing_a_link_uses_up_earlier_ones,
            changing_the_password_keeps_this_session,
            sessions_expire_and_are_pruned,
            sign_out_and_sign_out_everywhere,
            admin_operations_need_an_admin,
            admins_cannot_act_on_themselves,
            update_user_rules,
            identity_rules,
            delete_user_removes_sessions_and_links,
            impersonation,
            events_are_sent,
            users_lists_live_links,
            activation_only_changes_pending_users,
            credentials_are_not_set_on_revoked_users,
        }
    };

    (@tests $open:expr, $($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() -> $crate::store::suite::TestResult {
                $crate::store::suite::$name($open).await
            }
        )*
    };
}

pub(crate) use store_suite;

fn ip() -> IpAddr {
    IpAddr::from([192, 0, 2, 1])
}

/// The stable subject of the Google account owning `email`.
fn sub(email: &str) -> String {
    format!("sub:{email}")
}

/// The [`AuthError`] of a failed operation; panics on success or an
/// internal failure.
#[track_caller]
fn refused<T>(result: Result<T, Error>) -> AuthError {
    match result {
        Ok(_) => panic!("expected the operation to be refused"),
        Err(Error::Auth(error)) => error,
        Err(error) => panic!("expected an AuthError, got {error}"),
    }
}

struct Env<S> {
    store: S,
    auth: Auth,
    admin: User,
}

async fn env<S>(store: S) -> Result<Env<S>, Box<dyn StdError>>
where
    S: Store + Clone,
{
    env_with(store, |b| b.impersonation(true)).await
}

async fn env_with<S>(
    store: S,
    build: impl FnOnce(crate::core::AuthBuilder) -> crate::core::AuthBuilder,
) -> Result<Env<S>, Box<dyn StdError>>
where
    S: Store + Clone,
{
    let auth = build(Auth::builder(store.clone(), generate_session_key())).build();

    let new = NewUser {
        login: Some("admin".to_owned()),
        email: Some(ADMIN.to_owned()),
        role: Role::Admin,
    };

    let admin = store
        .create_user(&new, Timestamp::now())
        .await?
        .expect("no conflict");
    store.set_access(admin.id, Access::Active).await?;
    let admin = store.user(admin.id).await?.expect("admin");

    Ok(Env { store, auth, admin })
}

impl<S> Env<S>
where
    S: Store,
{
    async fn reload(&self, id: UserId) -> Result<User, Box<dyn StdError>> {
        Ok(self.store.user(id).await?.ok_or("user not found")?)
    }

    /// Invites a regular user by email, returning the user and their link.
    async fn invite(&self, email: &str) -> Result<(User, String), Box<dyn StdError>> {
        let new = NewUser {
            login: None,
            email: Some(email.to_owned()),
            role: Role::Regular,
        };

        let (entry, link) = self.auth.create_user(&self.admin, &new).await?;
        Ok((self.reload(entry.user.id).await?, link.token))
    }

    async fn issue(&self, id: UserId) -> Result<String, Box<dyn StdError>> {
        Ok(self.auth.issue_link(&self.admin, id).await?.token)
    }

    /// Whether `token` can currently be used.
    async fn usable(&self, token: &str) -> bool {
        self.auth.register_info(token).await.is_ok()
    }

    async fn token_kind(&self, token: &str) -> Result<TokenKind, Box<dyn StdError>> {
        Ok(self.store.token(token).await?.ok_or("token missing")?.kind)
    }

    async fn password_user(&self, email: &str) -> Result<User, Box<dyn StdError>> {
        let (user, token) = self.invite(email).await?;
        let request = RegisterRequest {
            password: PASSWORD.to_owned(),
        };
        self.auth.register(&token, &request).await?;
        self.reload(user.id).await
    }

    async fn google_user(&self, email: &str) -> Result<User, Box<dyn StdError>> {
        let (user, token) = self.invite(email).await?;
        let (registered, _) = self
            .auth
            .register_google(&token, &sub(email), email)
            .await?;
        assert_eq!(registered.id, user.id);
        self.reload(user.id).await
    }

    async fn password_login(&self, name: &str, password: &str) -> Result<(User, Session), Error> {
        let request = LoginRequest {
            login: name.to_owned(),
            password: password.to_owned(),
        };

        self.auth.sign_in_password(ip(), &request).await
    }

    /// Signs in with the Google account owning `email`.
    async fn google_login(&self, email: &str) -> Result<(User, Session), Error> {
        self.auth.sign_in_google(&sub(email), email).await
    }

    /// A session for the user, created directly in the store.
    async fn session(&self, user: UserId) -> Result<String, Box<dyn StdError>> {
        Ok(self.plain_session(user).await?.id)
    }

    /// A session for the user that is not impersonated, created directly in
    /// the store.
    async fn plain_session(&self, user: UserId) -> Result<Session, Box<dyn StdError>> {
        let now = Timestamp::now();

        let session = Session {
            id: crate::core::new_session_id(),
            user,
            impersonator: None,
            created_at: now,
            expires_at: crate::core::session_expiry(now),
        };

        self.store.create_session(&session).await?;
        Ok(session)
    }

    async fn live(&self, session: &str) -> Result<bool, Box<dyn StdError>> {
        Ok(self.auth.session(session).await?.is_some())
    }

    /// Asserts that no sign-in path gives `user` a session.
    async fn assert_locked_out(&self, user: &User, tokens: &[String]) -> TestResult {
        let email = user.email.as_deref().ok_or("no email")?;

        assert!(
            self.password_login(email, PASSWORD).await.is_err(),
            "password login"
        );
        assert!(self.google_login(email).await.is_err(), "google login");
        assert!(
            self.auth
                .switch_to_google(user.id, None, &sub(email), email)
                .await
                .is_err(),
            "switch to google"
        );

        for token in tokens {
            assert!(!self.usable(token).await, "link still usable");
            assert!(
                self.auth
                    .register_google(token, &sub(email), email)
                    .await
                    .is_err(),
                "google registration"
            );
        }

        Ok(())
    }
}

pub(crate) async fn revoked_users_cannot_get_a_session_through_any_login_path<S>(
    store: S,
) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let plain = env.password_user("plain@example.com").await?;
    let google = env.google_user("google@example.com").await?;

    // Both can sign in before they are revoked.
    env.password_login("plain@example.com", PASSWORD).await?;
    env.google_login("google@example.com").await?;

    let mut tokens = Vec::new();
    let mut sessions = Vec::new();

    for user in [&plain, &google] {
        // An outstanding link and a session from before the revocation.
        tokens.push(env.issue(user.id).await?);
        sessions.push(env.session(user.id).await?);
    }

    env.auth.revoke_access(&env.admin, plain.id).await?;
    env.auth.revoke_access(&env.admin, google.id).await?;

    for (user, token) in [&plain, &google].into_iter().zip(&tokens) {
        let user = env.reload(user.id).await?;
        assert_eq!(user.access, Access::Revoked);
        assert!(user.password_hash.is_none());
        env.assert_locked_out(&user, std::slice::from_ref(token))
            .await?;
        let mine = env.plain_session(env.admin.id).await?;
        assert_eq!(
            refused(env.auth.impersonate(&env.admin, &mine, user.id).await),
            AuthError::Forbidden
        );

        // A session created concurrently with the revocation is rejected
        // too.
        let late = env.session(user.id).await?;
        assert!(!env.live(&late).await?);
    }

    for session in &sessions {
        assert!(!env.live(session).await?);
    }

    Ok(())
}

pub(crate) async fn revoked_google_user_cannot_sign_in_with_old_method<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    // A revoked user whose stored method is Google is not treated as a
    // Google registration.
    let user = env.password_user("someone@example.com").await?;
    let cred = Credential::Google {
        sub: sub("someone@example.com"),
        email: "someone@example.com".to_owned(),
    };
    env.store.set_credential(user.id, &cred, None).await?;
    env.store.revoke(user.id, Timestamp::now()).await?;

    let user = env.reload(user.id).await?;
    assert_eq!(user.method, Method::Google);
    assert_eq!(user.access, Access::Revoked);
    env.assert_locked_out(&user, &[]).await?;
    Ok(())
}

pub(crate) async fn unregistered_users_cannot_sign_in<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let (user, token) = env.invite("invited@example.com").await?;
    assert_eq!(user.access, Access::Pending);

    assert!(
        env.password_login("invited@example.com", PASSWORD)
            .await
            .is_err()
    );
    assert!(env.google_login("invited@example.com").await.is_err());

    // Even when marked as a Google user without registering.
    let cred = Credential::Google {
        sub: sub("invited@example.com"),
        email: "invited@example.com".to_owned(),
    };
    env.store.set_credential(user.id, &cred, None).await?;
    env.store.set_access(user.id, Access::Pending).await?;
    assert!(env.google_login("invited@example.com").await.is_err());

    // Their link still works, and signs them in.
    let (registered, _) = env
        .auth
        .register_google(&token, &sub("invited@example.com"), "invited@example.com")
        .await?;
    assert_eq!(registered.id, user.id);
    env.google_login("invited@example.com").await?;
    Ok(())
}

pub(crate) async fn reinvited_users_can_register_again<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.google_user("back@example.com").await?;
    env.auth.revoke_access(&env.admin, user.id).await?;
    assert!(env.google_login("back@example.com").await.is_err());

    let token = env.issue(user.id).await?;
    env.auth
        .register_google(&token, &sub("back@example.com"), "back@example.com")
        .await?;

    assert_eq!(env.reload(user.id).await?.access, Access::Active);
    env.google_login("back@example.com").await?;

    // The same holds with a password.
    let user = env.password_user("plain@example.com").await?;
    env.auth.revoke_access(&env.admin, user.id).await?;
    let token = env.issue(user.id).await?;
    let request = RegisterRequest {
        password: "another password".to_owned(),
    };
    env.auth.register(&token, &request).await?;
    env.password_login("plain@example.com", "another password")
        .await?;
    Ok(())
}

pub(crate) async fn google_login_only_matches_google_registrations<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    // A password user's email isn't bound to a Google identity, since they
    // can change it to any address.
    let user = env.password_user("password@example.com").await?;
    assert!(env.google_login("password@example.com").await.is_err());
    env.password_login("password@example.com", PASSWORD).await?;
    assert_eq!(
        refused(env.password_login("password@example.com", "wrong").await),
        AuthError::Unauthorized
    );

    // Switching to Google binds it.
    let user = env
        .auth
        .switch_to_google(
            user.id,
            None,
            &sub("password@example.com"),
            "password@example.com",
        )
        .await?;
    assert_eq!(user.method, Method::Google);
    assert!(user.password_hash.is_none());
    env.google_login("password@example.com").await?;
    assert!(
        env.password_login("password@example.com", PASSWORD)
            .await
            .is_err()
    );
    Ok(())
}

pub(crate) async fn registered_users_only_accept_reset_tokens<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let plain = env.password_user("plain@example.com").await?;
    let google = env.google_user("google@example.com").await?;

    for user in [&plain, &google] {
        // A registration link left over from before they registered can't
        // take over the account.
        let now = Timestamp::now();
        let stale = Token {
            id: new_token(),
            user: user.id,
            kind: TokenKind::Registration,
            expires_at: crate::core::token_expiry(now),
            used_at: None,
        };
        env.store.create_token(&stale, now).await?;

        assert_eq!(
            refused(env.auth.register_info(&stale.id).await),
            AuthError::Gone
        );
        assert!(
            env.auth
                .register_google(&stale.id, "sub:attacker", "attacker@example.com")
                .await
                .is_err(),
            "stale link accepted"
        );
        let request = RegisterRequest {
            password: "attacker password".to_owned(),
        };
        assert_eq!(
            refused(env.auth.register(&stale.id, &request).await),
            AuthError::Gone
        );

        let user = env.reload(user.id).await?;
        assert_eq!(user.access, Access::Active);
        assert_ne!(user.email.as_deref(), Some("attacker@example.com"));
    }

    // A link an admin deliberately issues to a registered user resets their
    // credential.
    let reset = env.issue(plain.id).await?;
    assert_eq!(env.token_kind(&reset).await?, TokenKind::Reset);
    assert!(env.usable(&reset).await);

    env.auth
        .register_google(&reset, &sub("plain@example.com"), "plain@example.com")
        .await?;
    env.google_login("plain@example.com").await?;

    // Once used, the reset link is spent.
    assert!(!env.usable(&reset).await);
    Ok(())
}

pub(crate) async fn pending_and_reinvited_users_get_registration_tokens<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let (_, token) = env.invite("invited@example.com").await?;
    assert_eq!(env.token_kind(&token).await?, TokenKind::Registration);
    assert!(env.usable(&token).await);

    let user = env.password_user("back@example.com").await?;
    env.auth.revoke_access(&env.admin, user.id).await?;
    let token = env.issue(user.id).await?;
    assert_eq!(env.token_kind(&token).await?, TokenKind::Registration);
    assert!(env.usable(&token).await);
    Ok(())
}

pub(crate) async fn replacing_credentials_through_google_ends_sessions<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.password_user("switch@example.com").await?;
    let other = env.password_user("other@example.com").await?;
    let kept = env.session(other.id).await?;

    // Switching to Google ends the sessions signed in with the password,
    // except the one switching.
    let old = env.session(user.id).await?;
    let current = env.session(user.id).await?;
    env.auth
        .switch_to_google(
            user.id,
            Some(&current),
            &sub("switch@example.com"),
            "switch@example.com",
        )
        .await?;
    assert!(!env.live(&old).await?);
    assert!(env.live(&current).await?);

    // So does a reset link used through Google, the current session too.
    let old = env.session(user.id).await?;
    let reset = env.issue(user.id).await?;
    env.auth
        .register_google(&reset, &sub("switch@example.com"), "switch@example.com")
        .await?;
    assert!(!env.live(&old).await?);
    assert!(!env.live(&current).await?);

    // Signing in doesn't.
    let old = env.session(user.id).await?;
    env.google_login("switch@example.com").await?;
    assert!(env.live(&old).await?);

    assert!(env.live(&kept).await?);
    Ok(())
}

pub(crate) async fn google_users_are_bound_by_subject<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.google_user("bound@example.com").await?;
    assert_eq!(user.google_sub, Some(sub("bound@example.com")));

    // Another Google account that now has their email can't sign in as them.
    assert!(
        env.auth
            .sign_in_google("sub:someone-else", "bound@example.com")
            .await
            .is_err()
    );

    // Their own account can, even after its email changed at Google.
    let (found, _) = env
        .auth
        .sign_in_google(&sub("bound@example.com"), "renamed@example.com")
        .await?;
    assert_eq!(found.id, user.id);

    // An admin changing their email doesn't change which account signs in.
    let change = UserChange {
        email: Some(Some("changed@example.com".to_owned())),
        ..UserChange::default()
    };
    env.auth.update_user(&env.admin, user.id, &change).await?;
    assert!(env.google_login("changed@example.com").await.is_err());
    let (found, _) = env
        .auth
        .sign_in_google(&sub("bound@example.com"), "bound@example.com")
        .await?;
    assert_eq!(found.id, user.id);
    assert_eq!(found.email.as_deref(), Some("changed@example.com"));
    Ok(())
}

pub(crate) async fn replacing_credentials_replaces_the_google_subject<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    // A reset link used through another Google account rebinds the user.
    let user = env.google_user("reset@example.com").await?;
    let reset = env.issue(user.id).await?;
    env.auth
        .register_google(&reset, "sub:new", "reset@example.com")
        .await?;
    assert!(env.google_login("reset@example.com").await.is_err());
    env.auth
        .sign_in_google("sub:new", "reset@example.com")
        .await?;

    // Changing to a password unbinds it, and needs no old password.
    let session = env.session(user.id).await?;
    let session = env.store.session(&session).await?.ok_or("no session")?;
    let change = PasswordChange {
        old_password: None,
        new_password: PASSWORD.to_owned(),
    };
    let user = env.auth.change_password(&user, &session, &change).await?;
    assert_eq!(user.method, Method::Password);
    assert!(user.google_sub.is_none());
    assert!(
        env.auth
            .sign_in_google("sub:new", "reset@example.com")
            .await
            .is_err()
    );
    env.password_login("reset@example.com", PASSWORD).await?;

    // Switching back to Google binds the account used to switch.
    env.auth
        .switch_to_google(user.id, None, "sub:switched", "reset@example.com")
        .await?;
    assert_eq!(
        env.reload(user.id).await?.google_sub.as_deref(),
        Some("sub:switched")
    );
    env.auth
        .sign_in_google("sub:switched", "reset@example.com")
        .await?;
    Ok(())
}

pub(crate) async fn a_google_account_binds_only_one_user<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let first = env.google_user("first@example.com").await?;
    let taken = sub("first@example.com");

    // Registering another user with the same account fails and leaves their
    // link usable.
    let (second, token) = env.invite("second@example.com").await?;
    assert!(
        env.auth
            .register_google(&token, &taken, "second@example.com")
            .await
            .is_err()
    );
    assert!(env.usable(&token).await);
    assert_eq!(env.reload(second.id).await?.access, Access::Pending);

    // So does switching another user to it.
    let plain = env.password_user("plain@example.com").await?;
    assert!(
        env.auth
            .switch_to_google(plain.id, None, &taken, "plain@example.com")
            .await
            .is_err()
    );
    let plain = env.reload(plain.id).await?;
    assert_eq!(plain.method, Method::Password);
    assert!(plain.google_sub.is_none());

    // A Google account whose email belongs to another user can't be taken
    // either.
    assert_eq!(
        refused(
            env.auth
                .switch_to_google(plain.id, None, "sub:other", "first@example.com")
                .await
        ),
        AuthError::Conflict(Conflict::Email)
    );

    // It still signs in as the first user.
    let (found, _) = env.auth.sign_in_google(&taken, "first@example.com").await?;
    assert_eq!(found.id, first.id);
    Ok(())
}

fn token_of(url: &str) -> Result<&str, Box<dyn StdError>> {
    Ok(url
        .rsplit_once("/register/")
        .map(|(_, token)| token)
        .ok_or("not a registration url")?)
}

pub(crate) async fn bootstraps_an_admin_into_an_empty_store<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let auth = Auth::builder(store.clone(), generate_session_key())
        .logins(false)
        .build();

    let admin =
        BootstrapAdmin::new("Admin@Example.com").public_url(Some("https://maps.example.com/"));
    let url = auth.bootstrap_admin(&admin).await?.ok_or("skipped")?;
    assert!(
        url.starts_with("https://maps.example.com/register/"),
        "{url}"
    );

    let user = store
        .user_by_email("admin@example.com")
        .await?
        .ok_or("admin missing")?;
    assert_eq!(user.role, Role::Admin);
    assert_eq!(user.access, Access::Pending);
    assert!(user.password_hash.is_none());

    let token = store.token(token_of(&url)?).await?.ok_or("token missing")?;
    assert_eq!(token.user, user.id);
    assert_eq!(token.kind, TokenKind::Registration);

    let info = auth.register_info(token_of(&url)?).await?;
    assert_eq!(info.email.as_deref(), Some("admin@example.com"));
    Ok(())
}

pub(crate) async fn bootstraps_an_admin_by_login<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    // Without logins, a login name can't name the admin.
    let auth = Auth::builder(store.clone(), generate_session_key())
        .logins(false)
        .build();
    assert!(matches!(
        refused(auth.bootstrap_admin(&BootstrapAdmin::new("root")).await),
        AuthError::Invalid(_)
    ));
    assert_eq!(store.user_count().await?, 0);

    let auth = Auth::builder(store.clone(), generate_session_key()).build();
    let url = auth
        .bootstrap_admin(&BootstrapAdmin::new("root").public_url(None::<String>))
        .await?
        .ok_or("skipped")?;
    assert!(url.starts_with("/register/"), "{url}");

    let user = store.user_by_login("root").await?.ok_or("admin missing")?;
    assert_eq!(user.role, Role::Admin);
    assert_eq!(user.email, None);

    // Registering activates them, and they sign in by login.
    let request = RegisterRequest {
        password: PASSWORD.to_owned(),
    };
    auth.register(token_of(&url)?, &request).await?;
    let request = LoginRequest {
        login: "root".to_owned(),
        password: PASSWORD.to_owned(),
    };
    let (user, _) = auth.sign_in_password(ip(), &request).await?;
    assert_eq!(user.access, Access::Active);
    Ok(())
}

pub(crate) async fn bootstrap_is_skipped_once_users_exist<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let auth = Auth::builder(store.clone(), generate_session_key()).build();
    let admin = BootstrapAdmin::email(ADMIN);

    let url = auth.bootstrap_admin(&admin).await?.ok_or("skipped")?;

    // The admin registers and is later demoted.
    let request = RegisterRequest {
        password: PASSWORD.to_owned(),
    };
    let (user, _) = auth.register(token_of(&url)?, &request).await?;
    let change = UserChange {
        role: Some(Role::Regular),
        ..UserChange::default()
    };
    store
        .update_user(user.id, &change)
        .await?
        .expect("no conflict");
    let hash = store.user(user.id).await?.ok_or("gone")?.password_hash;

    // Restarting with the option still set changes nothing.
    assert!(auth.bootstrap_admin(&admin).await?.is_none());

    // Nor does naming another email.
    let other = BootstrapAdmin::email("other@example.com");
    assert!(auth.bootstrap_admin(&other).await?.is_none());
    assert!(store.user_by_email("other@example.com").await?.is_none());

    let user = store.user(user.id).await?.ok_or("admin missing")?;
    assert_eq!(user.role, Role::Regular);
    assert_eq!(user.access, Access::Active);
    assert_eq!(user.password_hash, hash);
    assert_eq!(store.user_count().await?, 1);

    // No new link was issued.
    let users = store.users(Timestamp::now()).await?;
    assert!(users.iter().all(|(_, link)| link.is_none()));
    Ok(())
}

pub(crate) async fn password_sign_in_by_login_or_email<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let new = NewUser {
        login: Some(" alice ".to_owned()),
        email: Some(" Alice@Example.com ".to_owned()),
        role: Role::Regular,
    };
    let (entry, link) = env.auth.create_user(&env.admin, &new).await?;
    assert_eq!(entry.user.login.as_deref(), Some("alice"));
    assert_eq!(entry.user.email.as_deref(), Some("alice@example.com"));

    // Pending users can't sign in.
    let request = RegisterRequest {
        password: PASSWORD.to_owned(),
    };
    assert!(env.password_login("alice", PASSWORD).await.is_err());
    env.auth.register(&link.token, &request).await?;

    for name in ["alice", " alice", "ALICE@example.com", "alice@example.com"] {
        let (user, session) = env.password_login(name, PASSWORD).await?;
        assert_eq!(user.id, entry.user.id);
        assert!(env.live(&session.id).await?);
    }

    // Login names are case sensitive.
    assert!(env.password_login("Alice", PASSWORD).await.is_err());
    assert_eq!(
        refused(env.password_login("nobody", PASSWORD).await),
        AuthError::Unauthorized
    );
    Ok(())
}

pub(crate) async fn password_sign_in_by_email_only_without_logins<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env_with(store, |b| b.logins(false)).await?;

    // The admin has the login `admin`, which isn't looked up.
    let session = env.session(env.admin.id).await?;
    let session = env.store.session(&session).await?.ok_or("no session")?;
    let change = PasswordChange {
        old_password: None,
        new_password: PASSWORD.to_owned(),
    };
    env.auth
        .change_password(&env.admin, &session, &change)
        .await?;
    assert!(env.password_login("admin", PASSWORD).await.is_err());
    env.password_login(ADMIN, PASSWORD).await?;
    Ok(())
}

pub(crate) async fn password_sign_in_is_throttled<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;
    env.password_user("victim@example.com").await?;

    for _ in 0..10 {
        assert_eq!(
            refused(env.password_login("victim@example.com", "wrong").await),
            AuthError::Unauthorized
        );
    }

    // Even the right password is refused now.
    assert_eq!(
        refused(env.password_login("Victim@example.com", PASSWORD).await),
        AuthError::TooManyRequests
    );
    Ok(())
}

pub(crate) async fn registering_ends_other_sessions<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.password_user("user@example.com").await?;
    let old = env.session(user.id).await?;

    let reset = env.issue(user.id).await?;
    assert_eq!(env.token_kind(&reset).await?, TokenKind::Reset);
    let request = RegisterRequest {
        password: "new password".to_owned(),
    };
    let (_, session) = env.auth.register(&reset, &request).await?;

    assert!(!env.live(&old).await?);
    assert!(env.live(&session.id).await?);
    assert!(
        env.password_login("user@example.com", PASSWORD)
            .await
            .is_err()
    );
    env.password_login("user@example.com", "new password")
        .await?;

    // A weak password is refused before the link is used.
    let reset = env.issue(user.id).await?;
    let request = RegisterRequest {
        password: "short".to_owned(),
    };
    assert!(matches!(
        refused(env.auth.register(&reset, &request).await),
        AuthError::Invalid(_)
    ));
    assert!(env.usable(&reset).await);
    Ok(())
}

pub(crate) async fn links_expire_and_are_single_use<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    assert_eq!(
        refused(env.auth.register_info("no-such-link").await),
        AuthError::NotFound
    );

    let (user, token) = env.invite("user@example.com").await?;

    let request = RegisterRequest {
        password: PASSWORD.to_owned(),
    };
    env.auth.register(&token, &request).await?;
    assert_eq!(
        refused(env.auth.register(&token, &request).await),
        AuthError::Gone
    );

    let now = Timestamp::now();
    let expired = Token {
        id: new_token(),
        user: user.id,
        kind: TokenKind::Reset,
        expires_at: now - SignedDuration::from_secs(1),
        used_at: None,
    };
    env.store.create_token(&expired, now).await?;
    assert_eq!(
        refused(env.auth.register_info(&expired.id).await),
        AuthError::Gone
    );
    assert_eq!(
        refused(env.auth.register(&expired.id, &request).await),
        AuthError::Gone
    );
    Ok(())
}

pub(crate) async fn issuing_a_link_uses_up_earlier_ones<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let (user, first) = env.invite("user@example.com").await?;
    let second = env.issue(user.id).await?;
    assert!(!env.usable(&first).await);
    assert!(env.usable(&second).await);

    env.auth.revoke_link(&env.admin, user.id).await?;
    assert!(!env.usable(&second).await);
    assert_eq!(env.reload(user.id).await?.access, Access::Pending);
    Ok(())
}

pub(crate) async fn changing_the_password_keeps_this_session<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.password_user("user@example.com").await?;
    let (_, current) = env.password_login("user@example.com", PASSWORD).await?;
    let other = env.session(user.id).await?;

    let wrong = PasswordChange {
        old_password: Some("wrong".to_owned()),
        new_password: "new password".to_owned(),
    };
    assert!(matches!(
        refused(env.auth.change_password(&user, &current, &wrong).await),
        AuthError::Invalid(_)
    ));

    let missing = PasswordChange {
        old_password: None,
        new_password: "new password".to_owned(),
    };
    assert!(matches!(
        refused(env.auth.change_password(&user, &current, &missing).await),
        AuthError::Invalid(_)
    ));

    let weak = PasswordChange {
        old_password: Some(PASSWORD.to_owned()),
        new_password: "short".to_owned(),
    };
    assert!(matches!(
        refused(env.auth.change_password(&user, &current, &weak).await),
        AuthError::Invalid(_)
    ));
    assert!(env.live(&other).await?);

    let change = PasswordChange {
        old_password: Some(PASSWORD.to_owned()),
        new_password: "new password".to_owned(),
    };
    env.auth.change_password(&user, &current, &change).await?;
    assert!(env.live(&current.id).await?);
    assert!(!env.live(&other).await?);
    env.password_login("user@example.com", "new password")
        .await?;
    Ok(())
}

pub(crate) async fn sessions_expire_and_are_pruned<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let now = Timestamp::now();
    let expired = Session {
        id: crate::core::new_session_id(),
        user: env.admin.id,
        impersonator: None,
        created_at: now - SignedDuration::from_hours(24),
        expires_at: now - SignedDuration::from_secs(1),
    };
    env.store.create_session(&expired).await?;
    assert!(!env.live(&expired.id).await?);

    env.auth.prune().await?;
    assert!(env.store.session(&expired.id).await?.is_none());
    Ok(())
}

pub(crate) async fn sign_out_and_sign_out_everywhere<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.password_user("user@example.com").await?;
    let a = env.session(user.id).await?;
    let b = env.session(user.id).await?;
    let c = env.session(user.id).await?;

    env.auth.sign_out(&a).await?;
    assert!(!env.live(&a).await?);
    assert!(env.live(&b).await?);

    env.auth.sign_out_everywhere(&env.admin, user.id).await?;
    assert!(!env.live(&b).await?);
    assert!(!env.live(&c).await?);

    // Unlike revoking access, they can sign in again.
    env.password_login("user@example.com", PASSWORD).await?;
    Ok(())
}

pub(crate) async fn admin_operations_need_an_admin<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.password_user("user@example.com").await?;
    let other = env.password_user("other@example.com").await?;
    let id = other.id;

    let new = NewUser {
        login: None,
        email: Some("new@example.com".to_owned()),
        role: Role::Regular,
    };
    let change = UserChange {
        email: Some(Some("x@example.com".to_owned())),
        ..UserChange::default()
    };

    let forbidden = AuthError::Forbidden;
    assert_eq!(refused(env.auth.users(&user).await), forbidden);
    assert_eq!(refused(env.auth.create_user(&user, &new).await), forbidden);
    assert_eq!(refused(env.auth.issue_link(&user, id).await), forbidden);
    assert_eq!(refused(env.auth.revoke_link(&user, id).await), forbidden);
    assert_eq!(
        refused(env.auth.sign_out_everywhere(&user, id).await),
        forbidden
    );
    assert_eq!(refused(env.auth.revoke_access(&user, id).await), forbidden);
    assert_eq!(
        refused(env.auth.set_role(&user, id, Role::Admin).await),
        forbidden
    );
    assert_eq!(
        refused(env.auth.update_user(&user, id, &change).await),
        forbidden
    );
    assert_eq!(refused(env.auth.delete_user(&user, id).await), forbidden);
    let theirs = env.plain_session(user.id).await?;
    assert_eq!(
        refused(env.auth.impersonate(&user, &theirs, id).await),
        forbidden
    );

    // Nor can a user make themselves an admin.
    assert_eq!(
        refused(env.auth.set_role(&user, user.id, Role::Admin).await),
        forbidden
    );
    let promote = UserChange {
        role: Some(Role::Admin),
        ..UserChange::default()
    };
    assert_eq!(
        refused(env.auth.update_user(&user, user.id, &promote).await),
        forbidden
    );
    assert_eq!(env.reload(user.id).await?.role, Role::Regular);

    // Unknown users are not found.
    let missing = UserId(u64::MAX);
    assert_eq!(
        refused(env.auth.issue_link(&env.admin, missing).await),
        AuthError::NotFound
    );
    assert_eq!(
        refused(env.auth.delete_user(&env.admin, missing).await),
        AuthError::NotFound
    );
    assert_eq!(
        refused(env.auth.revoke_access(&env.admin, missing).await),
        AuthError::NotFound
    );
    Ok(())
}

pub(crate) async fn admins_cannot_act_on_themselves<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;
    let me = env.admin.id;

    let forbidden = AuthError::Forbidden;
    assert_eq!(
        refused(env.auth.set_role(&env.admin, me, Role::Regular).await),
        forbidden
    );
    assert_eq!(
        refused(env.auth.revoke_access(&env.admin, me).await),
        forbidden
    );
    assert_eq!(
        refused(env.auth.sign_out_everywhere(&env.admin, me).await),
        forbidden
    );
    assert_eq!(
        refused(env.auth.delete_user(&env.admin, me).await),
        forbidden
    );
    let mine = env.plain_session(me).await?;
    assert_eq!(
        refused(env.auth.impersonate(&env.admin, &mine, me).await),
        forbidden
    );

    let admin = env.reload(me).await?;
    assert_eq!(admin.role, Role::Admin);
    assert_eq!(admin.access, Access::Active);

    // Admins can change the role of others.
    let user = env.password_user("user@example.com").await?;
    let user = env.auth.set_role(&env.admin, user.id, Role::Admin).await?;
    assert_eq!(user.role, Role::Admin);
    Ok(())
}

pub(crate) async fn update_user_rules<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.password_user("user@example.com").await?;
    let google = env.google_user("google@example.com").await?;

    // Users change their own login and email.
    let change = UserChange {
        login: Some(Some(" user ".to_owned())),
        email: Some(Some(" New@Example.com ".to_owned())),
        role: None,
    };
    let updated = env.auth.update_user(&user, user.id, &change).await?;
    assert_eq!(updated.login.as_deref(), Some("user"));
    assert_eq!(updated.email.as_deref(), Some("new@example.com"));

    // But not another user's.
    assert_eq!(
        refused(env.auth.update_user(&user, google.id, &change).await),
        AuthError::Forbidden
    );

    // Taken logins and emails conflict.
    let taken = UserChange {
        login: Some(Some("admin".to_owned())),
        ..UserChange::default()
    };
    assert_eq!(
        refused(env.auth.update_user(&user, user.id, &taken).await),
        AuthError::Conflict(Conflict::Login)
    );
    let taken = UserChange {
        email: Some(Some("GOOGLE@example.com".to_owned())),
        ..UserChange::default()
    };
    assert_eq!(
        refused(env.auth.update_user(&user, user.id, &taken).await),
        AuthError::Conflict(Conflict::Email)
    );

    // A Google user's own email is Google's.
    let change = UserChange {
        email: Some(Some("elsewhere@example.com".to_owned())),
        ..UserChange::default()
    };
    assert!(matches!(
        refused(env.auth.update_user(&google, google.id, &change).await),
        AuthError::Invalid(_)
    ));

    // An admin may change it, and it is then the user's.
    let updated = env.auth.update_user(&env.admin, google.id, &change).await?;
    assert_eq!(updated.email.as_deref(), Some("elsewhere@example.com"));

    // A user keeps at least one of login and email; a blank email clears it.
    let clear_email = UserChange {
        email: Some(Some("  ".to_owned())),
        ..UserChange::default()
    };
    let updated = env.auth.update_user(&user, user.id, &clear_email).await?;
    assert_eq!(updated.email, None);
    let clear_login = UserChange {
        login: Some(None),
        ..UserChange::default()
    };
    assert!(matches!(
        refused(env.auth.update_user(&user, user.id, &clear_login).await),
        AuthError::Invalid(_)
    ));
    let blank_login = UserChange {
        login: Some(Some(" ".to_owned())),
        ..UserChange::default()
    };
    assert!(matches!(
        refused(env.auth.update_user(&user, user.id, &blank_login).await),
        AuthError::Invalid(_)
    ));
    Ok(())
}

pub(crate) async fn identity_rules<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store.clone()).await?;

    let nameless = NewUser {
        login: None,
        email: Some(" ".to_owned()),
        role: Role::Regular,
    };
    assert!(matches!(
        refused(env.auth.create_user(&env.admin, &nameless).await),
        AuthError::Invalid(_)
    ));

    let login_only = NewUser {
        login: Some("bob".to_owned()),
        email: None,
        role: Role::Regular,
    };
    env.auth.create_user(&env.admin, &login_only).await?;
    assert_eq!(
        refused(env.auth.create_user(&env.admin, &login_only).await),
        AuthError::Conflict(Conflict::Login)
    );

    let email = NewUser {
        login: None,
        email: Some("ADMIN@example.com".to_owned()),
        role: Role::Regular,
    };
    assert_eq!(
        refused(env.auth.create_user(&env.admin, &email).await),
        AuthError::Conflict(Conflict::Email)
    );

    // Without logins, an email is required and logins can't be set.
    let auth = Auth::builder(store, generate_session_key())
        .logins(false)
        .build();
    assert!(matches!(
        refused(auth.create_user(&env.admin, &login_only).await),
        AuthError::Invalid(_)
    ));
    let both = NewUser {
        login: Some("carol".to_owned()),
        email: Some("carol@example.com".to_owned()),
        role: Role::Regular,
    };
    assert!(matches!(
        refused(auth.create_user(&env.admin, &both).await),
        AuthError::Invalid(_)
    ));

    let (entry, _) = auth
        .create_user(
            &env.admin,
            &NewUser {
                login: None,
                ..both
            },
        )
        .await?;
    let user = env.reload(entry.user.id).await?;
    let clear = UserChange {
        email: Some(None),
        ..UserChange::default()
    };
    assert!(matches!(
        refused(auth.update_user(&env.admin, user.id, &clear).await),
        AuthError::Invalid(_)
    ));
    Ok(())
}

pub(crate) async fn delete_user_removes_sessions_and_links<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.password_user("user@example.com").await?;
    let session = env.session(user.id).await?;
    let link = env.issue(user.id).await?;

    env.auth.delete_user(&env.admin, user.id).await?;
    assert!(env.store.user(user.id).await?.is_none());
    assert!(env.store.session(&session).await?.is_none());
    assert!(env.store.token(&link).await?.is_none());
    assert!(
        env.password_login("user@example.com", PASSWORD)
            .await
            .is_err()
    );
    Ok(())
}

pub(crate) async fn impersonation<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store.clone()).await?;
    let mine = env.plain_session(env.admin.id).await?;
    let forbidden = AuthError::Forbidden;

    // A session that is not impersonated says so.
    let info = env.auth.session_info(&env.admin, &mine).await?;
    assert_eq!(info, env.admin.info());
    assert_eq!(info.impersonated_by, None);

    // Pending users can be impersonated, and the session records the admin,
    // in the store too.
    let (pending, _) = env.invite("pending@example.com").await?;
    let (user, session) = env.auth.impersonate(&env.admin, &mine, pending.id).await?;
    assert_eq!(user.id, pending.id);
    assert_eq!(session.impersonator, Some(env.admin.id));
    assert!(env.live(&session.id).await?);
    let stored = env.store.session(&session.id).await?.ok_or("no session")?;
    assert_eq!(stored.impersonator, Some(env.admin.id));

    let info = env.auth.session_info(&user, &session).await?;
    let by = info.impersonated_by.expect("marked as impersonated");
    assert_eq!(by.id, env.admin.id);
    assert_eq!(by.name, "admin");

    // The admin's own session is untouched.
    assert!(env.live(&mine.id).await?);

    // Stopping is only for impersonated sessions.
    assert_eq!(refused(env.auth.stop_impersonating(&mine).await), forbidden);

    // Stopping ends the impersonated session and signs the admin in again.
    let (admin, back) = env.auth.stop_impersonating(&session).await?;
    assert_eq!(admin.id, env.admin.id);
    assert_eq!(back.user, env.admin.id);
    assert_eq!(back.impersonator, None);
    assert!(env.live(&back.id).await?);
    assert!(!env.live(&session.id).await?);
    assert!(env.store.session(&session.id).await?.is_none());
    assert_eq!(
        env.auth.session_info(&admin, &back).await?.impersonated_by,
        None
    );

    // An admin acting as another admin cannot impersonate from there, so
    // stopping always leads back to the admin who started.
    let other = env.password_user("other@example.com").await?;
    env.auth.set_role(&env.admin, other.id, Role::Admin).await?;
    let other = env.reload(other.id).await?;
    let (_, as_other) = env.auth.impersonate(&env.admin, &mine, other.id).await?;
    assert_eq!(
        refused(env.auth.impersonate(&other, &as_other, pending.id).await),
        forbidden
    );

    // An impersonated session ends once its admin is no longer an active
    // admin, here changed in the store as another process would. One
    // loaded before still cannot go back to them, and finding it dead
    // deletes it, so that promoting the admin again does not revive it.
    let (_, session) = env.auth.impersonate(&env.admin, &mine, pending.id).await?;
    let demote = UserChange {
        role: Some(Role::Regular),
        ..UserChange::default()
    };
    env.store
        .update_user(env.admin.id, &demote)
        .await?
        .expect("no conflict");
    assert_eq!(
        refused(env.auth.stop_impersonating(&session).await),
        forbidden
    );
    assert!(!env.live(&session.id).await?);
    assert!(env.store.session(&session.id).await?.is_none());

    let promote = UserChange {
        role: Some(Role::Admin),
        ..UserChange::default()
    };
    env.store
        .update_user(env.admin.id, &promote)
        .await?
        .expect("no conflict");
    assert!(!env.live(&session.id).await?);

    // The same for a revoked admin. Their own sessions end with the
    // revocation; the impersonated one is not theirs.
    let (_, session) = env.auth.impersonate(&env.admin, &mine, pending.id).await?;
    assert!(env.live(&session.id).await?);
    env.store.revoke(env.admin.id, Timestamp::now()).await?;
    assert!(env.store.session(&session.id).await?.is_some());
    assert_eq!(
        refused(env.auth.stop_impersonating(&session).await),
        forbidden
    );
    assert!(!env.live(&session.id).await?);
    assert!(env.store.session(&session.id).await?.is_none());

    // Deleting the admin ends the sessions they impersonate in.
    env.store.delete_user(env.admin.id).await?;
    assert!(env.store.session(&session.id).await?.is_none());
    assert!(env.store.session(&as_other.id).await?.is_none());
    assert!(env.live(&env.session(pending.id).await?).await?);

    // Not when disabled.
    let auth = Auth::builder(store, generate_session_key()).build();
    let theirs = env.plain_session(other.id).await?;
    assert_eq!(
        refused(auth.impersonate(&other, &theirs, pending.id).await),
        forbidden
    );
    Ok(())
}

pub(crate) async fn events_are_sent<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;
    let mut events = env.auth.events();

    let (user, _) = env.invite("user@example.com").await?;
    assert!(matches!(events.try_recv()?, AuthEvent::UserCreated(info) if info.id == user.id));

    let request = RegisterRequest {
        password: PASSWORD.to_owned(),
    };
    let token = env.issue(user.id).await?;
    let (_, session) = env.auth.register(&token, &request).await?;
    assert_eq!(
        events.try_recv()?,
        AuthEvent::UserSessionsEnded {
            user: user.id,
            keep: Some(session.id.clone()),
        }
    );
    assert!(
        matches!(events.try_recv()?, AuthEvent::UserChanged(info) if info.access == Access::Active)
    );

    env.auth.sign_out(&session.id).await?;
    assert_eq!(events.try_recv()?, AuthEvent::SessionEnded(session.id));

    env.auth.set_role(&env.admin, user.id, Role::Admin).await?;
    assert!(matches!(events.try_recv()?, AuthEvent::UserChanged(info) if info.role == Role::Admin));

    env.auth.revoke_access(&env.admin, user.id).await?;
    assert_eq!(
        events.try_recv()?,
        AuthEvent::UserSessionsEnded {
            user: user.id,
            keep: None,
        }
    );
    assert!(
        matches!(events.try_recv()?, AuthEvent::UserChanged(info) if info.access == Access::Revoked)
    );

    env.auth.delete_user(&env.admin, user.id).await?;
    assert_eq!(
        events.try_recv()?,
        AuthEvent::UserSessionsEnded {
            user: user.id,
            keep: None,
        }
    );
    assert_eq!(events.try_recv()?, AuthEvent::UserDeleted(user.id));
    assert!(events.try_recv().is_err());
    Ok(())
}

pub(crate) async fn users_lists_live_links<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let (pending, link) = env.invite("pending@example.com").await?;
    let active = env.password_user("active@example.com").await?;

    let users = env.auth.users(&env.admin).await?;
    let ids: Vec<_> = users.iter().map(|e| e.user.id).collect();
    assert_eq!(ids, [env.admin.id, pending.id, active.id]);

    let entry = |id| users.iter().find(|e| e.user.id == id).expect("listed");
    let link_expires_at = env.store.token(&link).await?.ok_or("missing")?.expires_at;
    assert_eq!(entry(pending.id).link_expires_at, Some(link_expires_at));
    assert_eq!(entry(active.id).link_expires_at, None);
    assert!(entry(active.id).user.has_password);
    assert!(!entry(pending.id).user.has_password);
    Ok(())
}

pub(crate) async fn activation_only_changes_pending_users<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let (pending, _) = env.invite("pending@example.com").await?;
    assert!(env.store.activate(pending.id).await?);
    assert_eq!(env.reload(pending.id).await?.access, Access::Active);

    // Activating again reports no change.
    assert!(!env.store.activate(pending.id).await?);
    assert_eq!(env.reload(pending.id).await?.access, Access::Active);

    // A revocation that lands after the caller read a pending user is not
    // undone.
    let (revoked, _) = env.invite("revoked@example.com").await?;
    assert!(env.store.revoke(revoked.id, Timestamp::now()).await?);
    assert!(!env.store.activate(revoked.id).await?);
    assert_eq!(env.reload(revoked.id).await?.access, Access::Revoked);

    assert!(!env.store.activate(UserId(9999)).await?);
    Ok(())
}

pub(crate) async fn credentials_are_not_set_on_revoked_users<S>(store: S) -> TestResult
where
    S: Store + Clone,
{
    let env = env(store).await?;

    let user = env.password_user("someone@example.com").await?;
    let (_, session) = env.password_login("someone@example.com", PASSWORD).await?;
    assert!(env.store.revoke(user.id, Timestamp::now()).await?);

    let cred = Credential::Google {
        sub: sub("someone@example.com"),
        email: "someone@example.com".to_owned(),
    };
    assert!(!env.store.set_credential(user.id, &cred, None).await?);
    let hash = Credential::Password("hash".to_owned());
    assert!(
        !env.store
            .set_credential(user.id, &hash, Some(&session.id))
            .await?
    );

    let after = env.reload(user.id).await?;
    assert_eq!(after.access, Access::Revoked);
    assert_eq!(after.method, Method::Password);
    assert_eq!(after.google_sub, None);
    assert_eq!(after.password_hash, None);

    // A link still restores a revoked user.
    let token = env.issue(user.id).await?;
    let request = RegisterRequest {
        password: PASSWORD.to_owned(),
    };
    env.auth.register(&token, &request).await?;
    assert_eq!(env.reload(user.id).await?.access, Access::Active);
    Ok(())
}
