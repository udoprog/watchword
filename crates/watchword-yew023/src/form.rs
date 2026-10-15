//! Form helpers shared by the account and admin components: the login and
//! email change an edit makes.

use watchword_core::{Invalid, UserChange};

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
) -> Result<UserChange, Invalid> {
    if !logins && email.is_none() {
        return Err(Invalid::EmailRequired);
    }

    if login.is_none() && email.is_none() {
        return Err(Invalid::LoginOrEmailRequired);
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
