//! Form helpers shared by the account and admin components: messages for
//! failed requests, and the login and email change an edit makes.

use yew::AttrValue;

use super::http::Error;
use watchword_core::{AuthError, Conflict, UserChange};

/// The message for a failed request, where `failed` says what failed, such
/// as "Saving".
pub(super) fn error_message(error: &Error, failed: &str) -> AttrValue {
    match error {
        Error::Auth(AuthError::Conflict(Conflict::Login)) => {
            AttrValue::from("That login is already taken.")
        }
        Error::Auth(AuthError::Conflict(Conflict::Email)) => {
            AttrValue::from("That email is already taken.")
        }
        Error::Auth(AuthError::Invalid(invalid)) => AttrValue::from(invalid.to_string()),
        Error::Auth(AuthError::Unauthorized) => {
            AttrValue::from("Your session has ended. Sign in again.")
        }
        Error::Auth(AuthError::Forbidden) => AttrValue::from("You are not allowed to do that."),
        Error::Auth(AuthError::NotFound) => AttrValue::from("That user no longer exists."),
        Error::Network(..) => AttrValue::from("Could not reach the server."),
        error => AttrValue::from(format!("{failed} failed: {error}.")),
    }
}

/// Trims an input, mapping an empty one to `None`.
pub(super) fn optional(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// The change from a user's `current` login and email to the edited ones, or
/// why it cannot be saved. A user needs a login or an email, and an email
/// when the app does not use `logins`. Inputs are trimmed, and an empty one
/// clears its field.
pub(super) fn identity_change(
    current: (Option<&str>, Option<&str>),
    login: Option<String>,
    email: Option<String>,
    logins: bool,
) -> Result<UserChange, &'static str> {
    if !logins && email.is_none() {
        return Err("An email is required.");
    }

    if login.is_none() && email.is_none() {
        return Err("A login or an email is required.");
    }

    let (current_login, current_email) = current;
    let mut change = UserChange::default();

    if login.as_deref() != current_login {
        change.login = Some(login);
    }

    if email.as_deref() != current_email {
        change.email = Some(email);
    }

    Ok(change)
}
