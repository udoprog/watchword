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
    assert!(validate_password("1234567").is_some());
    assert!(validate_password("12345678").is_none());
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
            AuthError::Invalid("Must be at least 8 characters.".into()),
            json!({"error": "invalid", "detail": "Must be at least 8 characters."}),
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

#[cfg(feature = "musli01")]
#[test]
fn musli_round_trip() {
    fn round_trip<T>(value: T)
    where
        T: std::fmt::Debug
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
    round_trip(AuthError::Invalid("no".into()));
}
