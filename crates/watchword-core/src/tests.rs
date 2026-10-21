use alloc::borrow::ToOwned;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use serde_json::{Value, json};

use super::*;

fn at(s: &str) -> Timestamp {
    s.parse().unwrap()
}

fn user() -> UserInfo {
    UserInfo {
        id: UserId(7),
        login: Some("root".into()),
        email: Some("root@example.com".into()),
        role: Role::Admin,
        access: Access::Active,
        method: Method::Password,
        has_password: true,
        created_at: at("2026-10-01T12:00:00Z"),
        impersonated_by: None,
    }
}

/// The default verifies the Access JWT and trusts nothing else, so an app
/// that only fills in the domain and audience is safe.
#[test]
fn cloudflare_default_verifies_jwt() {
    let config = CloudflareConfig::default();
    assert!(!config.enabled);
    assert!(config.team_domain.is_empty());
    assert!(config.audience.is_empty());
    assert!(!config.trust_email_header);
    assert!(config.verify_jwt);
}

/// A field missing from the JSON takes its default, so settings without
/// `verify_jwt` still verify the token.
#[test]
fn cloudflare_missing_fields_are_safe() {
    let config: CloudflareConfig = serde_json::from_value(json!({
        "enabled": true,
        "team_domain": "example.cloudflareaccess.com",
        "audience": "aud",
    }))
    .unwrap();

    assert!(config.enabled);
    assert!(config.verify_jwt);
    assert!(!config.trust_email_header);

    let config: CloudflareConfig = serde_json::from_value(json!({})).unwrap();
    assert_eq!(config, CloudflareConfig::default());
}

#[test]
fn names_round_trip() {
    for role in [Role::Admin, Role::Regular] {
        assert_eq!(role.as_str().parse::<Role>(), Ok(role));
        assert_eq!(serde_json::to_value(role).unwrap(), json!(role.as_str()));
    }

    for access in [Access::Pending, Access::Active, Access::Revoked] {
        assert_eq!(access.as_str().parse::<Access>(), Ok(access));
        assert_eq!(
            serde_json::to_value(access).unwrap(),
            json!(access.as_str())
        );
    }

    for method in [Method::Password, Method::Google] {
        assert_eq!(method.as_str().parse::<Method>(), Ok(method));
        assert_eq!(
            serde_json::to_value(method).unwrap(),
            json!(method.as_str())
        );
    }

    assert_eq!("Admin".parse::<Role>(), Err(UnknownRole));
    assert_eq!("".parse::<Access>(), Err(UnknownAccess));
    assert_eq!("cloudflare".parse::<Method>(), Err(UnknownMethod));
}

#[test]
fn email_normalization() {
    assert_eq!(normalize_email("  Foo@Example.COM \n"), "foo@example.com");
}

#[test]
fn password_validation() {
    assert_eq!(
        validate_password("1234567"),
        Some(Invalid::PasswordTooShort { min: 8 })
    );
    assert_eq!(validate_password("12345678"), None);
}

/// Every reason, with its wire form and English message.
fn invalid_cases() -> Vec<(Invalid, Value, &'static str)> {
    vec![
        (
            Invalid::PasswordTooShort { min: 8 },
            json!({"reason": "password_too_short", "min": 8}),
            "Must be at least 8 characters.",
        ),
        (
            Invalid::PasswordIncorrect,
            json!({"reason": "password_incorrect"}),
            "The current password is incorrect.",
        ),
        (
            Invalid::EmailRequired,
            json!({"reason": "email_required"}),
            "An email is required.",
        ),
        (
            Invalid::LoginOrEmailRequired,
            json!({"reason": "login_or_email_required"}),
            "A login or an email is required.",
        ),
        (
            Invalid::LoginEmpty,
            json!({"reason": "login_empty"}),
            "The login cannot be empty.",
        ),
        (
            Invalid::LoginsDisabled,
            json!({"reason": "logins_disabled"}),
            "Login names are not used.",
        ),
        (
            Invalid::EmailManagedByGoogle,
            json!({"reason": "email_managed_by_google"}),
            "Your email is managed by your Google account.",
        ),
        (
            Invalid::GoogleAccountTaken,
            json!({"reason": "google_account_taken"}),
            "This Google account is already linked to another user.",
        ),
        (
            Invalid::RoleNotChangeable,
            json!({"reason": "role_not_changeable"}),
            "The role cannot be changed here.",
        ),
        (
            Invalid::MalformedRequest,
            json!({"reason": "malformed_request"}),
            "The request is malformed.",
        ),
        (
            Invalid::Unknown,
            json!({"reason": "unknown"}),
            "The request is invalid.",
        ),
    ]
}

/// A reason from a newer server decodes as `Unknown`, parameters and all.
#[test]
fn invalid_unknown_json() {
    let wire = json!({"error": "invalid", "detail": {"reason": "password_too_long", "max": 72}});
    assert_eq!(
        serde_json::from_value::<AuthError>(wire).unwrap(),
        AuthError::Invalid(Invalid::Unknown)
    );
    assert_eq!(
        serde_json::from_value::<Invalid>(json!({"reason": "new"})).unwrap(),
        Invalid::Unknown
    );
}

/// A reason from a newer server decodes as `Unknown` over musli's
/// upgrade-safe formats too (musli-web's default is `wire`), and the value
/// after it still decodes. `storage` and `packed` cannot skip an unknown
/// value, so they need the same model on both ends.
#[cfg(feature = "musli02")]
#[test]
fn invalid_unknown_musli() {
    /// `Invalid` as a newer version might have it.
    #[derive(musli::Encode)]
    #[allow(dead_code)]
    enum Newer {
        PasswordTooShort { min: usize },
        PasswordIncorrect,
        EmailRequired,
        LoginOrEmailRequired,
        LoginEmpty,
        LoginsDisabled,
        EmailManagedByGoogle,
        GoogleAccountTaken,
        RoleNotChangeable,
        MalformedRequest,
        Unknown,
        PasswordTooLong { max: usize, hint: String },
    }

    let newer = vec![
        Newer::PasswordTooLong {
            max: 72,
            hint: "shorter".into(),
        },
        Newer::PasswordTooShort { min: 8 },
    ];

    let expected = [Invalid::Unknown, Invalid::PasswordTooShort { min: 8 }];

    let bytes = musli::wire::to_vec(&newer).unwrap();
    let decoded: Vec<Invalid> = musli::wire::from_slice(&bytes).unwrap();
    assert_eq!(decoded, expected);

    let bytes = musli::descriptive::to_vec(&newer).unwrap();
    let decoded: Vec<Invalid> = musli::descriptive::from_slice(&bytes).unwrap();
    assert_eq!(decoded, expected);
}

/// A reason is a stable code with parameters on the wire, and English only
/// in its message.
#[test]
fn invalid_json() {
    for (invalid, value, message) in invalid_cases() {
        assert_eq!(serde_json::to_value(&invalid).unwrap(), value);
        assert_eq!(
            serde_json::from_value::<Invalid>(value.clone()).unwrap(),
            invalid
        );
        assert_eq!(invalid.to_string(), message);

        let error = AuthError::Invalid(invalid);
        let wire = json!({"error": "invalid", "detail": value});
        assert_eq!(serde_json::to_value(&error).unwrap(), wire);
        assert_eq!(serde_json::from_value::<AuthError>(wire).unwrap(), error);
        assert_eq!(error.status(), 400);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn link_path_and_url() {
    let link = Link {
        token: "abc".to_owned(),
        expires_at: at("2026-10-08T12:00:00Z"),
    };
    assert_eq!(link.path(), "/register/abc");
    assert_eq!(link.url(None), "/register/abc");
    assert_eq!(
        link.url(Some("https://maps.example.com")),
        "https://maps.example.com/register/abc"
    );
    assert_eq!(
        link.url(Some("https://example.com/maps/")),
        "https://example.com/maps/register/abc"
    );
}

#[test]
fn user_name() {
    let mut user = user();
    assert_eq!(user.name(), "root");
    assert!(user.is_admin());

    user.login = None;
    assert_eq!(user.name(), "root@example.com");

    user.email = None;
    user.role = Role::Regular;
    assert_eq!(user.name(), "");
    assert!(!user.is_admin());
}

#[test]
fn user_json() {
    let value = serde_json::to_value(user()).unwrap();

    assert_eq!(
        value,
        json!({
            "id": 7,
            "login": "root",
            "email": "root@example.com",
            "role": "admin",
            "access": "active",
            "method": "password",
            "has_password": true,
            "created_at": "2026-10-01T12:00:00Z",
        })
    );

    assert_eq!(serde_json::from_value::<UserInfo>(value).unwrap(), user());
}

#[test]
fn impersonated_user_json() {
    let mut impersonated = user();
    impersonated.impersonated_by = Some(Impersonator {
        id: UserId(1),
        name: "boss".into(),
    });

    let value = serde_json::to_value(&impersonated).unwrap();
    assert_eq!(value["impersonated_by"], json!({ "id": 1, "name": "boss" }));
    assert_eq!(
        serde_json::from_value::<UserInfo>(value).unwrap(),
        impersonated
    );
}

#[test]
fn user_change_json() {
    let cases = [
        (UserChange::default(), json!({})),
        (
            UserChange {
                login: Some(None),
                email: Some(Some("a@example.com".into())),
                role: Some(Role::Regular),
            },
            json!({"login": null, "email": "a@example.com", "role": "regular"}),
        ),
    ];

    for (change, value) in cases {
        assert_eq!(serde_json::to_value(&change).unwrap(), value);
        assert_eq!(serde_json::from_value::<UserChange>(value).unwrap(), change);
    }
}

#[test]
fn auth_error_json() {
    let cases = [
        (
            AuthError::Unauthorized,
            json!({"error": "unauthorized"}),
            401,
        ),
        (AuthError::Forbidden, json!({"error": "forbidden"}), 403),
        (AuthError::NotFound, json!({"error": "not_found"}), 404),
        (AuthError::Gone, json!({"error": "gone"}), 410),
        (
            AuthError::TooManyRequests,
            json!({"error": "too_many_requests"}),
            429,
        ),
        (
            AuthError::Conflict(Conflict::Email),
            json!({"error": "conflict", "detail": "email"}),
            409,
        ),
        (
            AuthError::Invalid(Invalid::PasswordTooShort { min: 8 }),
            json!({"error": "invalid", "detail": {"reason": "password_too_short", "min": 8}}),
            400,
        ),
    ];

    for (error, value, status) in cases {
        assert_eq!(serde_json::to_value(&error).unwrap(), value);
        assert_eq!(serde_json::from_value::<AuthError>(value).unwrap(), error);
        assert_eq!(error.status(), status);
    }

    assert_eq!(
        AuthError::Conflict(Conflict::Login).to_string(),
        "login is already taken"
    );
}

#[test]
fn entry_json() {
    let entry = UserEntry {
        user: user(),
        link_expires_at: None,
    };

    let value = serde_json::to_value(&entry).unwrap();
    assert_eq!(value["link_expires_at"], Value::Null);
    assert_eq!(serde_json::from_value::<UserEntry>(value).unwrap(), entry);
}

/// The answer to `POST /api/auth/users`, as the axum route sends it and
/// the Yew client reads it.
#[test]
fn created_user_json() {
    let created = CreatedUser {
        entry: UserEntry {
            user: user(),
            link_expires_at: Some(at("2026-10-08T12:00:00Z")),
        },
        link: Link {
            token: "t".to_owned(),
            expires_at: at("2026-10-08T12:00:00Z"),
        },
    };

    let json = serde_json::to_value(&created).unwrap();
    assert_eq!(json["entry"]["user"]["login"], "root");
    assert_eq!(json["link"]["token"], "t");
    assert_eq!(json.as_object().unwrap().len(), 2);
    assert_eq!(
        serde_json::from_value::<CreatedUser>(json).unwrap(),
        created
    );
}

#[cfg(feature = "musli02")]
#[test]
fn musli_round_trip() {
    fn round_trip<T>(value: T)
    where
        T: core::fmt::Debug
            + PartialEq
            + Encode<musli::mode::Binary>
            + for<'de> Decode<'de, musli::mode::Binary, musli::alloc::Global>,
    {
        let bytes = musli::storage::to_vec(&value).unwrap();
        let decoded: T = musli::storage::from_slice(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    let mut impersonated = user();
    impersonated.impersonated_by = Some(Impersonator {
        id: UserId(1),
        name: "boss".into(),
    });
    round_trip(impersonated);

    for link_expires_at in [None, Some(at("2026-10-08T00:00:00.5Z"))] {
        round_trip(UserEntry {
            user: user(),
            link_expires_at,
        });
    }

    round_trip(Link {
        token: "abc".into(),
        expires_at: at("2026-10-08T00:00:00Z"),
    });
    round_trip(UserChange {
        login: Some(None),
        email: None,
        role: Some(Role::Admin),
    });
    round_trip(AuthError::Conflict(Conflict::Login));

    for (invalid, _, _) in invalid_cases() {
        round_trip(invalid.clone());
        round_trip(AuthError::Invalid(invalid));
    }
}

#[cfg(feature = "musliweb05")]
mod musliweb05 {
    use musli_web05::api::{Id, MessageId};

    use super::*;
    use crate::musliweb05::*;

    /// The ids are part of the wire format: a released id never changes
    /// meaning.
    #[test]
    fn ids_are_pinned() {
        let ids: [(MessageId, u16); 14] = [
            (Me::ID, 32000),
            (UpdateAccount::ID, 32001),
            (ChangePassword::ID, 32002),
            (Users::ID, 32003),
            (CreateUser::ID, 32004),
            (UpdateUser::ID, 32005),
            (DeleteUser::ID, 32006),
            (IssueLink::ID, 32007),
            (RevokeLink::ID, 32008),
            (SignOutUser::ID, 32009),
            (RevokeAccess::ID, 32010),
            (Cloudflare::ID, 32011),
            (SetCloudflare::ID, 32012),
            (AuthBroadcast::ID, 32100),
        ];

        for (id, expected) in ids {
            assert_eq!(id.get(), expected, "{:?}", debug_id(id));
            assert!(is_watchword_id(id));
        }

        assert_eq!(Request::from_id(Me::ID), Request::Me);
        assert_eq!(Request::from_id(RevokeAccess::ID), Request::RevokeAccess);
        assert_eq!(Event::from_id(AuthBroadcast::ID), Event::AuthBroadcast);

        let app = MessageId::new(1).unwrap();
        assert_eq!(Request::from_id(app), Request::Unknown(app));
        assert!(!is_watchword_id(app));
        assert!(!is_watchword_id(MessageId::new(FIRST_ID - 1).unwrap()));
        assert!(is_watchword_id(MessageId::new(LAST_ID).unwrap()));
        assert!(!is_watchword_id(MessageId::new(LAST_ID + 1).unwrap()));
    }

    #[test]
    fn bodies_round_trip() {
        fn round_trip<T>(value: T)
        where
            T: core::fmt::Debug
                + PartialEq
                + Encode<musli::mode::Binary>
                + for<'de> Decode<'de, musli::mode::Binary, musli::alloc::Global>,
        {
            let bytes = musli::storage::to_vec(&value).unwrap();
            let decoded: T = musli::storage::from_slice(&bytes).unwrap();
            assert_eq!(decoded, value);
        }

        round_trip(MeRequest);
        round_trip(UsersRequest);
        round_trip(UserUpdate {
            id: UserId(3),
            change: UserChange {
                login: Some(Some("new".into())),
                email: Some(None),
                role: None,
            },
        });
        round_trip(DeleteUserRequest { id: UserId(3) });
        round_trip(RevokeAccessRequest { id: UserId(3) });
        round_trip(CloudflareRequest);
        round_trip(CloudflareConfig::default());
        round_trip(Ok::<_, AuthError>(CloudflareConfig {
            enabled: true,
            team_domain: "example.cloudflareaccess.com".into(),
            audience: "aud".into(),
            trust_email_header: true,
            verify_jwt: false,
        }));

        round_trip(Ok::<_, AuthError>(user()));
        round_trip(Err::<UserInfo, _>(AuthError::Invalid(
            Invalid::PasswordTooShort { min: 8 },
        )));
        round_trip(Ok::<(), AuthError>(()));
        round_trip(Err::<(), _>(AuthError::Forbidden));

        round_trip(AuthUpdate::Me(user()));
        round_trip(AuthUpdate::UserCreated(user()));
        round_trip(AuthUpdate::UserChanged(user()));
        round_trip(AuthUpdate::UserDeleted(UserId(3)));
        round_trip(AuthUpdate::Resync(user()));
    }
}

#[test]
fn user_id_conversions() {
    const ID: UserId = UserId::new(7);
    assert_eq!(ID.get(), 7);
    assert_eq!(UserId::from(7u64), ID);
    assert_eq!(u64::from(ID), 7);

    assert_eq!(UserId::try_from(7i64), Ok(ID));
    assert!(UserId::try_from(-1i64).is_err());
    assert_eq!(i64::try_from(ID), Ok(7));
    assert_eq!(i64::try_from(UserId(i64::MAX as u64)), Ok(i64::MAX));
    assert!(i64::try_from(UserId(i64::MAX as u64 + 1)).is_err());
}

/// The rule a `?next=` is followed by, on values already decoded: a path on
/// this origin, and never a way to another host.
#[test]
fn same_origin_paths() {
    for good in [
        "/",
        "/notes",
        "/notes?q=1#top",
        "/a b/\u{e5}",
        "/%2F%2Fhost",
        "/.//evil.example",
        "/notes//x",
    ] {
        assert!(is_same_origin_path(good), "{good:?}");
    }

    for bad in [
        "",
        "notes",
        "//evil.example",
        "///evil.example",
        "/\\evil.example",
        "\\/evil.example",
        "\\\\evil.example",
        "/notes\\x",
        "https://evil.example",
        "javascript:alert(1)",
        "/\t/evil.example",
        "/\n/evil.example",
        "/\r/evil.example",
        "/\0",
        "/\u{7f}",
        " //evil.example",
        "\t//evil.example",
    ] {
        assert!(!is_same_origin_path(bad), "{bad:?}");
    }
}
