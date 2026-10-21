//! watchword's messages: the handle the components look them up in, backed by
//! watchword-core's catalog, and the messages for failed requests.

use std::borrow::ToOwned;
use std::rc::Rc;
use std::string::String;
use std::string::ToString;

use phrasebook02::yew023::or_catalog;
use phrasebook02::{Args, Phrases, args};
use yew::prelude::*;

use super::http::Error;
use watchword_core::phrasebook02::L10N;
use watchword_core::{AuthError, Conflict, Invalid, Role};

/// The provided handle backed by [`L10N`], or `L10N` alone.
#[hook]
pub(super) fn use_phrases() -> Phrases {
    or_catalog(use_context::<Phrases>(), &L10N)
}

/// The same for a struct component, from what its context subscription
/// returned.
pub(super) fn phrases(provided: Option<Phrases>) -> Phrases {
    or_catalog(provided, &L10N)
}

/// The message for why a request is invalid.
pub(super) fn invalid(phrases: &Phrases, invalid: &Invalid) -> String {
    let id = match invalid {
        Invalid::PasswordTooShort { min } => {
            return phrases.msg("watchword-invalid-password-too-short", &args!(min = *min));
        }
        Invalid::PasswordIncorrect => "watchword-invalid-password-incorrect",
        Invalid::EmailRequired => "watchword-invalid-email-required",
        Invalid::LoginOrEmailRequired => "watchword-invalid-login-or-email-required",
        Invalid::LoginEmpty => "watchword-invalid-login-empty",
        Invalid::LoginsDisabled => "watchword-invalid-logins-disabled",
        Invalid::EmailManagedByGoogle => "watchword-invalid-email-managed-by-google",
        Invalid::GoogleAccountTaken => "watchword-invalid-google-account-taken",
        Invalid::RoleNotChangeable => "watchword-invalid-role-not-changeable",
        Invalid::MalformedRequest => "watchword-invalid-malformed-request",
        Invalid::Unknown => "watchword-invalid-unknown",
        // A reason added to watchword-core without a message here, which the
        // tests rule out: its English is better than nothing.
        invalid => return invalid.to_string(),
    };

    phrases.text(id).to_string()
}

/// The cause of a failed request, to place in a `watchword-failed-` message.
pub(super) fn cause(phrases: &Phrases, error: &Error) -> String {
    let id = match error {
        Error::Status(status) => {
            return phrases.msg("watchword-cause-status", &args!(status = *status));
        }
        Error::Network(detail) => {
            return phrases.msg("watchword-cause-network", &args!(detail = detail.as_str()));
        }
        Error::Socket(detail) => {
            return phrases.msg("watchword-cause-socket", &args!(detail = detail.as_str()));
        }
        Error::Auth(AuthError::Invalid(reason)) => return invalid(phrases, reason),
        Error::Auth(AuthError::Unauthorized) => "watchword-cause-unauthorized",
        Error::Auth(AuthError::Forbidden) => "watchword-cause-forbidden",
        Error::Auth(AuthError::NotFound) => "watchword-cause-not-found",
        Error::Auth(AuthError::Gone) => "watchword-cause-gone",
        Error::Auth(AuthError::TooManyRequests) => "watchword-cause-too-many-requests",
        Error::Auth(AuthError::Conflict(Conflict::Login)) => "watchword-cause-login-taken",
        Error::Auth(AuthError::Conflict(Conflict::Email)) => "watchword-cause-email-taken",
    };

    phrases.text(id).to_string()
}

/// A `watchword-failed-` message, such as `watchword-failed-saving`, with the
/// cause of `error`.
pub(super) fn failed(phrases: &Phrases, id: &str, error: &Error) -> AttrValue {
    let error = cause(phrases, error);
    AttrValue::from(phrases.msg(id, &args!(error = error.as_str())))
}

/// The message for a failed request of the account and admin forms, where
/// `failed` is the `watchword-failed-` message for an unexpected failure.
pub(super) fn error_message(phrases: &Phrases, error: &Error, failed_id: &str) -> AttrValue {
    let id = match error {
        Error::Auth(AuthError::Conflict(Conflict::Login)) => "watchword-error-login-taken",
        Error::Auth(AuthError::Conflict(Conflict::Email)) => "watchword-error-email-taken",
        Error::Auth(AuthError::Invalid(reason)) => {
            return AttrValue::from(invalid(phrases, reason));
        }
        Error::Auth(AuthError::Unauthorized) => "watchword-session-ended",
        Error::Auth(AuthError::Forbidden) => "watchword-error-forbidden",
        Error::Auth(AuthError::NotFound) => "watchword-error-user-not-found",
        Error::Network(..) => "watchword-error-unreachable",
        error => return failed(phrases, failed_id, error),
    };

    text(phrases, id)
}

/// A message without arguments, as an attribute value.
pub(super) fn text(phrases: &Phrases, id: &str) -> AttrValue {
    AttrValue::from(phrases.text(id))
}

/// The name of a role.
pub(super) fn role_name(phrases: &Phrases, role: Role) -> Rc<str> {
    phrases.text(match role {
        Role::Admin => "watchword-role-admin",
        Role::Regular => "watchword-role-regular",
    })
}

/// The message `id` with its argument `name` set to `value` and wrapped by
/// `wrap`, such as a user's name in `<strong>`, wherever the translation
/// places it.
pub(super) fn placed(
    phrases: &Phrases,
    id: &str,
    name: &'static str,
    value: &str,
    wrap: impl FnOnce(String) -> Html,
) -> Html {
    let text = phrases.msg(id, &Args::new().with(name, MARK));

    match split_around(&text, MARK) {
        Some((before, after)) => html! {
            <>{before.to_owned()}{wrap(value.to_owned())}{after.to_owned()}</>
        },
        // A translation without the argument, or a missing message.
        None => html! { {text} },
    }
}

/// Stands in for an argument [`placed`] wraps: a private use character, which
/// no message contains.
const MARK: &str = "\u{E000}";

/// The text before and after the first occurrence of `mark`.
pub(super) fn split_around<'a>(text: &'a str, mark: &str) -> Option<(&'a str, &'a str)> {
    let start = text.find(mark)?;
    Some((&text[..start], &text[start + mark.len()..]))
}
