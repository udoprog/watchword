use super::browser::{register_token_from_path, strip_query_param};
use super::sign_in::query_error_message;

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
