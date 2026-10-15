use jiff::Timestamp;

use super::account::account_change;
use super::admin_users::{link_url, matches_filter, page_bounds, relative_time};
use super::browser::{register_token_from_path, strip_query_param};
use super::cloudflare_settings::header_unverified;
use super::form::identity_change;
use super::http::{CreatedUser, Error};
use super::provider::replace_user;
use super::sign_in::query_error_message;
use super::user_menu::{impersonation_banner, stop_error_message};
use watchword_core::{
    Access, AuthError, CloudflareConfig, Impersonator, Link, Method, Role, UserChange, UserEntry,
    UserId, UserInfo,
};

fn user(login: Option<&str>, email: Option<&str>, method: Method) -> UserInfo {
    UserInfo {
        id: UserId(1),
        login: login.map(str::to_owned),
        email: email.map(str::to_owned),
        role: Role::Regular,
        access: Access::Active,
        method,
        has_password: method == Method::Password,
        created_at: Timestamp::UNIX_EPOCH,
        impersonated_by: None,
    }
}

#[test]
fn register_token() {
    assert_eq!(register_token_from_path("/register/abc-_1"), Some("abc-_1"));
    assert_eq!(register_token_from_path("/register/abc/"), Some("abc"));
    assert_eq!(register_token_from_path("/register/"), None);
    assert_eq!(register_token_from_path("/register/a/b"), None);
    assert_eq!(register_token_from_path("/"), None);
    assert_eq!(register_token_from_path("/users/register/abc"), None);
}

#[test]
fn strip_error_param() {
    assert_eq!(
        strip_query_param("?error=auth-failed", "error"),
        (Some("auth-failed".to_owned()), String::new())
    );
    assert_eq!(
        strip_query_param("?a=1&error=user-not-found&b", "error"),
        (Some("user-not-found".to_owned()), "?a=1&b".to_owned())
    );
    assert_eq!(
        strip_query_param("?a=1", "error"),
        (None, "?a=1".to_owned())
    );
    assert_eq!(strip_query_param("", "error"), (None, String::new()));
    assert_eq!(
        strip_query_param("?errors=1&error=", "error"),
        (Some(String::new()), "?errors=1".to_owned())
    );
}

#[test]
fn query_error_messages() {
    assert_eq!(query_error_message("auth-failed"), "Authentication failed.");
    assert_eq!(query_error_message("user-not-found"), "User not found.");
    assert_eq!(query_error_message("<script>"), "Signing in failed.");
}

#[test]
fn identity_changes() {
    let some = |s: &str| Some(s.to_owned());

    assert_eq!(
        identity_change((Some("a"), None), some("a"), None, true),
        Ok(UserChange::default())
    );
    assert_eq!(
        identity_change((Some("a"), None), some("b"), some("b@x"), true),
        Ok(UserChange {
            login: Some(some("b")),
            email: Some(some("b@x")),
            role: None,
        })
    );
    assert_eq!(
        identity_change((Some("a"), Some("a@x")), some("a"), None, true),
        Ok(UserChange {
            email: Some(None),
            ..UserChange::default()
        })
    );
    assert_eq!(
        identity_change((Some("a"), None), None, None, true),
        Err("A login or an email is required.")
    );
    assert_eq!(
        identity_change((None, Some("a@x")), None, None, false),
        Err("An email is required.")
    );
}

#[test]
fn account_changes() {
    let password = user(Some("root"), None, Method::Password);

    // Inputs are trimmed, and an empty one clears its field.
    assert_eq!(
        account_change(&password, " root ", " a@x ", true),
        Ok(UserChange {
            email: Some(Some("a@x".to_owned())),
            ..UserChange::default()
        })
    );
    assert_eq!(
        account_change(&password, "", "", true),
        Err("A login or an email is required.")
    );

    // Without logins the login input is ignored, and an email is required.
    let email_only = user(None, Some("a@x"), Method::Password);
    assert_eq!(
        account_change(&email_only, "ignored", "a@x", false),
        Ok(UserChange::default())
    );
    assert_eq!(
        account_change(&email_only, "", "", false),
        Err("An email is required.")
    );

    // A Google user's email is their Google account's.
    let google = user(Some("g"), Some("g@x"), Method::Google);
    assert_eq!(
        account_change(&google, "g", "other@x", true),
        Ok(UserChange::default())
    );
}

#[test]
fn filter_users() {
    let u = user(Some("Root"), Some("Admin@Example.com"), Method::Password);
    assert!(matches_filter(&u, ""));
    assert!(matches_filter(&u, "  "));
    assert!(matches_filter(&u, "roo"));
    assert!(matches_filter(&u, "EXAMPLE"));
    assert!(!matches_filter(&u, "nobody"));
    assert!(!matches_filter(&user(None, None, Method::Password), "a"));
}

#[test]
fn pages() {
    assert_eq!(page_bounds(0, 6, 0), (0, 1, 0..0));
    assert_eq!(page_bounds(6, 6, 0), (0, 1, 0..6));
    assert_eq!(page_bounds(7, 6, 1), (1, 2, 6..7));
    // A page past the end shows the last one.
    assert_eq!(page_bounds(7, 6, 5), (1, 2, 6..7));
}

#[test]
fn relative_times() {
    let now = Timestamp::from_second(1_000_000).unwrap();
    let at = |s: i64| Timestamp::from_second(1_000_000 + s).unwrap();
    assert_eq!(relative_time(now, at(-5)), "now");
    assert_eq!(relative_time(now, at(30)), "in less than a minute");
    assert_eq!(relative_time(now, at(60)), "in 1 minute");
    assert_eq!(relative_time(now, at(7_199)), "in 1 hour");
    assert_eq!(relative_time(now, at(7 * 86_400)), "in 7 days");
}

#[test]
fn link_urls() {
    assert_eq!(
        link_url("https://example.com", "abc-_"),
        "https://example.com/register/abc-_"
    );
}

#[test]
fn cloudflare_header_warning() {
    let config = CloudflareConfig {
        enabled: true,
        trust_email_header: true,
        verify_jwt: false,
        ..CloudflareConfig::default()
    };
    assert!(header_unverified(&config));
    assert!(!header_unverified(&CloudflareConfig {
        verify_jwt: true,
        ..config.clone()
    }));
    assert!(!header_unverified(&CloudflareConfig {
        enabled: false,
        ..config.clone()
    }));
    assert!(!header_unverified(&CloudflareConfig {
        trust_email_header: false,
        ..config
    }));
}

/// The JSON form of `POST /api/auth/users`, which the server must answer
/// with.
#[test]
fn created_user_json() {
    let created = CreatedUser {
        entry: UserEntry {
            user: user(Some("a"), None, Method::Password),
            link_expires_at: Some(Timestamp::UNIX_EPOCH),
        },
        link: Link {
            token: "t".to_owned(),
            expires_at: Timestamp::UNIX_EPOCH,
        },
    };

    let json = serde_json::to_value(&created).unwrap();
    assert_eq!(json["entry"]["user"]["login"], "a");
    assert_eq!(json["link"]["token"], "t");
    assert_eq!(
        serde_json::from_value::<CreatedUser>(json).unwrap(),
        created
    );
}

fn impersonated(by: &str) -> UserInfo {
    UserInfo {
        impersonated_by: Some(Impersonator {
            id: UserId(9),
            name: by.to_owned(),
        }),
        ..user(Some("pat"), None, Method::Password)
    }
}

#[test]
fn impersonation_banners() {
    assert_eq!(
        impersonation_banner(&user(Some("pat"), None, Method::Password)),
        None
    );
    assert_eq!(
        impersonation_banner(&impersonated("root")).as_deref(),
        Some("Impersonating pat as root.")
    );
    assert_eq!(
        impersonation_banner(&impersonated("")).as_deref(),
        Some("Impersonating pat.")
    );
}

#[test]
fn stop_errors() {
    assert_eq!(
        stop_error_message(&Error::Auth(AuthError::Forbidden)),
        "You can no longer return to your admin account. Sign out instead."
    );
    assert_eq!(
        stop_error_message(&Error::Network("down".into())),
        "Could not reach the server."
    );
}

#[test]
fn replacing_the_user_keeps_the_impersonation() {
    let current = impersonated("root");

    // An unmarked copy of the same user, such as from an admin route.
    let mut renamed = user(Some("patty"), None, Method::Password);
    let kept = replace_user(&current, renamed.clone());
    assert_eq!(kept.login.as_deref(), Some("patty"));
    assert_eq!(kept.impersonated_by, current.impersonated_by);

    // A marked one is taken as it is.
    renamed.impersonated_by = Some(Impersonator {
        id: UserId(8),
        name: "other".into(),
    });
    assert_eq!(replace_user(&current, renamed.clone()), renamed);

    // Another user, such as the admin after stopping, is taken as it is.
    let mut admin = user(Some("root"), None, Method::Password);
    admin.id = UserId(9);
    assert_eq!(replace_user(&current, admin.clone()), admin);
}
