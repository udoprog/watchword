//! The bits of the browser the components touch: the location, history and
//! input values.

use web_sys::wasm_bindgen::JsValue;
use yew::{InputEvent, TargetCast};

/// The token of a `/register/{token}` page, if this is one.
pub(super) fn register_token() -> Option<String> {
    let path = web_sys::window()?.location().pathname().ok()?;
    register_token_from_path(&path).map(str::to_owned)
}

pub(super) fn register_token_from_path(path: &str) -> Option<&str> {
    let token = path.strip_prefix("/register/")?.trim_end_matches('/');

    if token.is_empty() || token.contains('/') {
        return None;
    }

    Some(token)
}

/// Removes `?error=` from the URL, returning its value.
pub(super) fn take_query_error() -> Option<String> {
    let location = web_sys::window()?.location();
    let search = location.search().ok()?;
    let (error, rest) = strip_query_param(&search, "error");
    let error = error?;
    let path = location.pathname().ok()?;
    let hash = location.hash().unwrap_or_default();
    replace_url(&format!("{path}{rest}{hash}"));
    Some(error)
}

/// Splits `name` out of a `?a=1&b=2` query string, returning its first value
/// and the query string without it (empty when nothing is left).
pub(super) fn strip_query_param(search: &str, name: &str) -> (Option<String>, String) {
    let query = search.strip_prefix('?').unwrap_or(search);
    let mut value = None;
    let mut rest = Vec::new();

    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, v) = pair.split_once('=').unwrap_or((pair, ""));

        if key == name {
            value.get_or_insert_with(|| v.to_owned());
        } else {
            rest.push(pair);
        }
    }

    let rest = if rest.is_empty() {
        String::new()
    } else {
        format!("?{}", rest.join("&"))
    };

    (value, rest)
}

/// Replaces the URL without navigating or adding a history entry.
pub(super) fn replace_url(url: &str) {
    if let Some(history) = web_sys::window().and_then(|w| w.history().ok()) {
        // Failing to tidy the URL is harmless: it only shows a stale path.
        let _ = history.replace_state_with_url(&JsValue::NULL, "", Some(url));
    }
}

/// The value of the input an `input` event came from.
pub(super) fn input_value(e: &InputEvent) -> String {
    let input: web_sys::HtmlInputElement = e.target_unchecked_into();
    input.value()
}
