use jiff::Timestamp;
use phrasebook01::{Catalog, Lang, Phrasebook, Phrases, Source, check};

use super::account::account_change;
use super::admin_users::{link_url, matches_filter, page_bounds, relative_time};
use super::browser::{register_token_from_path, strip_query_param};
use super::cloudflare_settings::header_unverified;
use super::form::identity_change;
use super::http::{CreatedUser, Error};
use super::l10n::{self, L10N, error_message, split_around};
use super::provider::replace_user;
use super::sign_in::query_error_message;
use super::user_menu::{impersonation_banner, stop_error_message};
use watchword_core::{
    Access, AuthError, CloudflareConfig, Conflict, Impersonator, Invalid, Link, Method, Role,
    UserChange, UserEntry, UserId, UserInfo,
};

/// watchword's own English, as rendered without a provider.
fn en() -> Phrases {
    Phrases::from_catalog(&L10N)
}

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
    let en = en();
    assert_eq!(
        &*query_error_message(&en, "auth-failed"),
        "Authentication failed."
    );
    assert_eq!(
        &*query_error_message(&en, "user-not-found"),
        "User not found."
    );
    assert_eq!(&*query_error_message(&en, "<script>"), "Signing in failed.");
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
        Err(Invalid::LoginOrEmailRequired)
    );
    assert_eq!(
        identity_change((None, Some("a@x")), None, None, false),
        Err(Invalid::EmailRequired)
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
        Err(Invalid::LoginOrEmailRequired)
    );

    // Without logins the login input is ignored, and an email is required.
    let email_only = user(None, Some("a@x"), Method::Password);
    assert_eq!(
        account_change(&email_only, "ignored", "a@x", false),
        Ok(UserChange::default())
    );
    assert_eq!(
        account_change(&email_only, "", "", false),
        Err(Invalid::EmailRequired)
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
    let en = en();
    assert_eq!(relative_time(&en, now, at(-5)), "now");
    assert_eq!(relative_time(&en, now, at(0)), "now");
    assert_eq!(relative_time(&en, now, at(30)), "in less than a minute");
    assert_eq!(relative_time(&en, now, at(60)), "in 1 minute");
    assert_eq!(relative_time(&en, now, at(150)), "in 2 minutes");
    assert_eq!(relative_time(&en, now, at(7_199)), "in 1 hour");
    assert_eq!(relative_time(&en, now, at(7_200)), "in 2 hours");
    assert_eq!(relative_time(&en, now, at(86_400)), "in 1 day");
    assert_eq!(relative_time(&en, now, at(7 * 86_400)), "in 7 days");
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
    let en = en();
    assert_eq!(
        impersonation_banner(&en, &user(Some("pat"), None, Method::Password)),
        None
    );
    assert_eq!(
        impersonation_banner(&en, &impersonated("root")).as_deref(),
        Some("Impersonating pat as root.")
    );
    assert_eq!(
        impersonation_banner(&en, &impersonated("")).as_deref(),
        Some("Impersonating pat.")
    );
}

#[test]
fn stop_errors() {
    let en = en();
    assert_eq!(
        stop_error_message(&en, &Error::Auth(AuthError::Forbidden)),
        "You can no longer return to your admin account. Sign out instead."
    );
    assert_eq!(
        stop_error_message(&en, &Error::Network("down".into())),
        "Could not reach the server."
    );
    assert_eq!(
        stop_error_message(&en, &Error::Status(502)),
        "Stopping failed: the server answered with HTTP 502."
    );
}

/// The catalog parses, every id has the prefix, and every message formats.
#[test]
fn catalog() {
    check::catalog(&L10N).unwrap();
}

/// Every `watchword-` id the code names is in the catalog, and every message
/// in the catalog is used.
#[test]
fn catalog_matches_the_code() {
    let defined = check::ids(&L10N, Lang::EN_US);
    let mut used = Vec::new();

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");

    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();

        if path.extension().is_none_or(|e| e != "rs") || path.ends_with("tests.rs") {
            continue;
        }

        let source = std::fs::read_to_string(&path).unwrap();

        for (start, _) in source.match_indices("\"watchword-") {
            let rest = &source[start + 1..];
            let id = &rest[..rest.find('"').unwrap()];

            // The catalog's prefix.
            if id == "watchword-" {
                continue;
            }

            assert!(
                defined.iter().any(|d| d == id),
                "{}: {id} is not in locales/en-US.ftl",
                path.display()
            );

            used.push(id.to_owned());
        }
    }

    for id in &defined {
        assert!(used.contains(id), "{id} in locales/en-US.ftl is not used");
    }
}

/// Every reason has a message, the same English as watchword-core's.
#[test]
fn invalid_messages() {
    let en = en();

    let reasons = [
        Invalid::PasswordTooShort { min: 8 },
        Invalid::PasswordTooShort { min: 1 },
        Invalid::PasswordIncorrect,
        Invalid::EmailRequired,
        Invalid::LoginOrEmailRequired,
        Invalid::LoginEmpty,
        Invalid::LoginsDisabled,
        Invalid::EmailManagedByGoogle,
        Invalid::GoogleAccountTaken,
        Invalid::RoleNotChangeable,
        Invalid::MalformedRequest,
        Invalid::Unknown,
    ];

    for reason in reasons {
        let message = l10n::invalid(&en, &reason);

        if reason == (Invalid::PasswordTooShort { min: 1 }) {
            assert_eq!(message, "Must be at least 1 character.");
        } else {
            assert_eq!(message, reason.to_string());
        }
    }
}

#[test]
fn error_messages() {
    let en = en();
    let message = |error: Error| error_message(&en, &error, "watchword-failed-saving");

    assert_eq!(
        message(Error::Auth(AuthError::Conflict(Conflict::Email))),
        "That email is already taken."
    );
    assert_eq!(
        message(Error::Auth(AuthError::Invalid(Invalid::PasswordTooShort {
            min: 8
        }))),
        "Must be at least 8 characters."
    );
    assert_eq!(
        message(Error::Auth(AuthError::Unauthorized)),
        "Your session has ended. Sign in again."
    );
    assert_eq!(
        message(Error::Auth(AuthError::Gone)),
        "Saving failed: the link was used or has expired."
    );
    assert_eq!(
        message(Error::Status(500)),
        "Saving failed: the server answered with HTTP 500."
    );
}

/// An app's translations win, and what it lacks comes from watchword's
/// English, whether or not it added watchword's catalog.
#[test]
fn translated_by_the_app() {
    const SV_SE: Lang = Lang::new("sv-SE");

    static APP: Catalog = Catalog::new(
        "app",
        &[
            Source::new(Lang::EN_US, "title = Title\n"),
            Source::new(
                SV_SE,
                "title = Titel\nwatchword-sign-in = Logga in\nwatchword-impersonating = Agerar som { $user }.\n",
            ),
        ],
    );

    for with_catalog in [true, false] {
        let mut builder = Phrasebook::builder()
            .language(Lang::EN_US, "English")
            .language(SV_SE, "Svenska")
            .catalog(&APP);

        if with_catalog {
            builder = builder.catalog(&L10N);
        }

        let sv = l10n::phrases(Some(builder.build().phrases(SV_SE)));

        assert_eq!(&*sv.text("watchword-sign-in"), "Logga in");
        assert_eq!(&*sv.text("watchword-sign-out"), "Sign out");
        assert_eq!(
            impersonation_banner(&sv, &impersonated("")).as_deref(),
            Some("Agerar som pat.")
        );
    }
}

#[test]
fn split_around_a_mark() {
    assert_eq!(
        split_around("Delete \u{E000}?", "\u{E000}"),
        Some(("Delete ", "?"))
    );
    assert_eq!(split_around("\u{E000}", "\u{E000}"), Some(("", "")));
    assert_eq!(split_around("Delete?", "\u{E000}"), None);
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

#[cfg(feature = "musliweb04")]
#[test]
fn broadcasts_apply_to_the_users_list() {
    use std::collections::HashMap;

    use super::admin_users::apply_update;
    use watchword_core::musliweb04::AuthUpdate;

    let expires = Timestamp::UNIX_EPOCH;

    let with_id = |id, login: &str, access| UserInfo {
        id: UserId(id),
        access,
        ..user(Some(login), None, Method::Password)
    };

    let link = |token: &str| Link {
        token: token.into(),
        expires_at: expires,
    };

    let mut users = vec![
        UserEntry {
            user: with_id(1, "root", Access::Active),
            link_expires_at: None,
        },
        UserEntry {
            user: with_id(2, "patty", Access::Pending),
            link_expires_at: Some(expires),
        },
    ];

    let mut links = HashMap::from([(UserId(2), link("t"))]);

    // The own user is the provider's.
    let me = AuthUpdate::Me(with_id(1, "renamed", Access::Active));
    assert!(!apply_update(&mut users, &mut links, me));
    assert_eq!(users[0].user.login.as_deref(), Some("root"));

    // A change that leaves the links alone applies in place.
    let mut admin = with_id(2, "patty", Access::Pending);
    admin.role = Role::Admin;
    let changed = AuthUpdate::UserChanged(admin);
    assert!(!apply_update(&mut users, &mut links, changed));
    assert_eq!(users[1].user.role, Role::Admin);
    assert_eq!(users[1].link_expires_at, Some(expires));
    assert!(links.contains_key(&UserId(2)));

    // Registering uses up the link, so the list is fetched again.
    let registered = AuthUpdate::UserChanged(with_id(2, "patty", Access::Active));
    assert!(apply_update(&mut users, &mut links, registered));
    assert_eq!(users[1].user.access, Access::Active);
    assert_eq!(users[1].link_expires_at, None);
    assert!(!links.contains_key(&UserId(2)));

    // A change to a user not shown fetches the list again.
    let unknown = AuthUpdate::UserChanged(with_id(7, "ghost", Access::Active));
    assert!(apply_update(&mut users, &mut links, unknown));
    assert_eq!(users.len(), 2);

    // A user created elsewhere shows at once; their link needs the list.
    let created = AuthUpdate::UserCreated(with_id(3, "new", Access::Pending));
    assert!(apply_update(&mut users, &mut links, created.clone()));
    assert_eq!(users[2].user.id, UserId(3));
    assert_eq!(users[2].link_expires_at, None);

    // One already added here keeps the link its answer carried.
    users[2].link_expires_at = Some(expires);
    assert!(!apply_update(&mut users, &mut links, created));
    assert_eq!(users.len(), 3);
    assert_eq!(users[2].link_expires_at, Some(expires));

    // A deleted user goes, with their link.
    links.insert(UserId(3), link("u"));
    let deleted = AuthUpdate::UserDeleted(UserId(3));
    assert!(!apply_update(&mut users, &mut links, deleted));
    assert_eq!(users.len(), 2);
    assert!(links.is_empty());

    // Missed updates fetch the list again, leaving it as it is meanwhile.
    links.insert(UserId(2), link("v"));
    let resync = AuthUpdate::Resync(with_id(1, "renamed", Access::Active));
    assert!(apply_update(&mut users, &mut links, resync));
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].user.login.as_deref(), Some("root"));
    assert!(links.contains_key(&UserId(2)));
}
