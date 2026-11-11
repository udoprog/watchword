//! The bits of the browser the components touch: the location, history and
//! input values.

use std::borrow::ToOwned;
use std::string::String;
use std::vec::Vec;

use watchword_core::{PAGE_SESSION_HEADER, is_same_origin_path};
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

/// Where to go once signed in, if not where the browser is: the URL to
/// replace the current one with, or `None` to stay.
///
/// A `?next=` that is a path on this origin (see [`safe_next`]) is gone to;
/// one that is not is dropped from the URL. On `sign_in_path` without a
/// usable `next`, it is `/`. When the user was signed in already on load
/// (`on_load`), only `sign_in_path` is left, since elsewhere `next` may be
/// the app's own.
pub(super) fn return_url(
    path: &str,
    search: &str,
    hash: &str,
    sign_in_path: Option<&str>,
    on_load: bool,
) -> Option<String> {
    let on_sign_in_page = sign_in_path == Some(path);

    if on_load && !on_sign_in_page {
        return None;
    }

    let (next, rest) = strip_query_param(search, "next");

    if let Some(target) = next.as_deref().and_then(safe_next) {
        return Some(target);
    }

    if on_sign_in_page {
        return Some("/".to_owned());
    }

    next.is_some().then(|| format!("{path}{rest}{hash}"))
}

/// Decodes a `?next=` value, returning it only when it is a path on this
/// origin, by watchword-core's [`is_same_origin_path`]: it starts with a
/// single `/` and holds no backslash or control character, so it can never
/// name another host (`//host`, `/\host`, or `/<tab>/host`, which browsers
/// read as `//host`) or a scheme.
pub(super) fn safe_next(value: &str) -> Option<String> {
    let decoded = percent_decode(value)?;
    is_same_origin_path(&decoded).then_some(decoded)
}

/// Where "Sign in with Google" starts, given the browser's location: the
/// Google route with a `?next=` naming where to come back to. That is the
/// URL's own usable `next` (see [`safe_next`]), or else this page without
/// one (nor an `?error=` the sign-in page shows), so that signing in with
/// Google returns where signing in with a password would. On `/` it carries
/// none, since `/` is where it returns to by default.
pub(super) fn google_sign_in_url(base: &str, path: &str, search: &str, hash: &str) -> String {
    let (next, rest) = strip_query_param(search, "next");
    let (_, rest) = strip_query_param(&rest, "error");

    let target = match next.as_deref().and_then(safe_next) {
        Some(target) => target,
        None => format!("{path}{rest}{hash}"),
    };

    if target == "/" || !is_same_origin_path(&target) {
        return base.to_owned();
    }

    let mut url = format!("{base}?next=");
    encode_into(&mut url, &target);
    url
}

/// Percent-encodes `value` as a query value, keeping only unreserved
/// characters and `/` as they are.
fn encode_into(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0xf)]));
        }
    }
}

/// [`google_sign_in_url`] for the browser's current location.
pub(super) fn google_sign_in(base: &str) -> String {
    let Some(location) = web_sys::window().map(|w| w.location()) else {
        return base.to_owned();
    };

    let path = location.pathname().unwrap_or_default();
    let search = location.search().unwrap_or_default();
    let hash = location.hash().unwrap_or_default();
    google_sign_in_url(base, &path, &search, &hash)
}

/// Decodes `%XX` escapes, failing on a malformed escape or a result that is
/// not UTF-8.
fn percent_decode(value: &str) -> Option<String> {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();

    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = char::from(bytes.next()?).to_digit(16)?;
            let lo = char::from(bytes.next()?).to_digit(16)?;
            out.push(u8::try_from(hi * 16 + lo).ok()?);
        } else {
            out.push(b);
        }
    }

    String::from_utf8(out).ok()
}

/// Goes to where [`return_url`] says, for the browser's current location.
pub(super) fn return_after_sign_in(sign_in_path: Option<&str>, on_load: bool) {
    let Some(location) = web_sys::window().map(|w| w.location()) else {
        return;
    };

    let (Ok(path), Ok(search)) = (location.pathname(), location.search()) else {
        return;
    };

    let hash = location.hash().unwrap_or_default();

    if let Some(url) = return_url(&path, &search, &hash, sign_in_path, on_load) {
        replace_url(&url);
    }
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

/// The value of the select an event came from.
pub(super) fn select_value(e: &yew::Event) -> String {
    let select: web_sys::HtmlSelectElement = e.target_unchecked_into();
    select.value()
}

/// Whether the checkbox an event came from is checked.
pub(super) fn checked(e: &yew::Event) -> bool {
    let input: web_sys::HtmlInputElement = e.target_unchecked_into();
    input.checked()
}

/// The value of the input an event, such as `change`, came from.
pub(super) fn event_value(e: &yew::Event) -> String {
    let input: web_sys::HtmlInputElement = e.target_unchecked_into();
    input.value()
}

/// The page's origin, such as `https://example.com`.
pub(super) fn origin() -> String {
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default()
}

/// The page session of an impersonated page (decision 33): its credential,
/// kept in `sessionStorage` under [`PAGE_SESSION_HEADER`]. `None` outside a
/// browser.
pub(super) fn page_session() -> Option<String> {
    if !cfg!(target_arch = "wasm32") {
        return None;
    }

    let storage = web_sys::window()?.session_storage().ok()??;
    let credential = storage.get_item(PAGE_SESSION_HEADER).ok()??;
    (!credential.is_empty()).then_some(credential)
}

/// Forgets the page session, so the page's requests carry only the cookie.
pub(super) fn drop_page_session() {
    if !cfg!(target_arch = "wasm32") {
        return;
    }

    if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok().flatten()) {
        let _ = storage.remove_item(PAGE_SESSION_HEADER);
    }
}

/// Readies an impersonated page before anything renders: every same-origin
/// `fetch` from now on carries the page session unless it set the header
/// itself, and `window.opener` is cleared so this page and the admin's stay
/// unrelated.
pub(super) fn enter_impersonated_page() {
    if !cfg!(target_arch = "wasm32") {
        return;
    }

    let Some(window) = web_sys::window() else {
        return;
    };

    let _ = window.set_opener(&JsValue::NULL);
    wrap_fetch(&window);
}

thread_local! {
    static FETCH_WRAPPED: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Replaces `window.fetch` with one that adds the page session's header,
/// once per page.
fn wrap_fetch(window: &web_sys::Window) {
    use web_sys::js_sys::{Array, Function, Promise, Reflect};
    use web_sys::wasm_bindgen::JsCast;
    use web_sys::wasm_bindgen::closure::Closure;

    if FETCH_WRAPPED.replace(true) {
        return;
    }

    let fetch = JsValue::from_str("fetch");

    let Some(original) = Reflect::get(window, &fetch)
        .ok()
        .and_then(|f| f.dyn_into::<Function>().ok())
    else {
        return;
    };

    let Some(request_class) = Reflect::get(window, &JsValue::from_str("Request"))
        .ok()
        .and_then(|f| f.dyn_into::<Function>().ok())
    else {
        return;
    };

    let target = window.clone();

    let wrapper = Closure::<dyn Fn(JsValue, JsValue) -> JsValue>::new(
        move |input: JsValue, init: JsValue| {
            // A request the browser refuses to build is passed on as it is,
            // so it fails as it would have.
            let request = Reflect::construct(&request_class, &Array::of2(&input, &init))
                .ok()
                .and_then(|request| request.dyn_into::<web_sys::Request>().ok());

            let Some(request) = request else {
                return original
                    .call2(&target, &input, &init)
                    .unwrap_or_else(|error| Promise::reject(&error).into());
            };

            // Read at each request: Stop or an ended session drops it.
            if let Some(credential) = page_session() {
                let origin = target.location().origin().unwrap_or_default();
                let headers = request.headers();

                if is_same_origin_url(&request.url(), &origin)
                    && !headers.has(PAGE_SESSION_HEADER).unwrap_or(true)
                {
                    let _ = headers.set(PAGE_SESSION_HEADER, &credential);
                }
            }

            original
                .call1(&target, &request)
                .unwrap_or_else(|error| Promise::reject(&error).into())
        },
    );

    if Reflect::set(window, &fetch, wrapper.as_ref()).is_ok() {
        // The wrapper lives as long as the page.
        wrapper.forget();
    }
}

/// Whether the absolute `url` is on `origin`, such as `https://example.com`.
pub(super) fn is_same_origin_url(url: &str, origin: &str) -> bool {
    !origin.is_empty()
        && url
            .strip_prefix(origin)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '?', '#']))
}

/// Closes the page, or when the browser refuses (a page a script did not
/// open), loads `/` instead.
pub(super) fn close_page() {
    if !cfg!(target_arch = "wasm32") {
        return;
    }

    let Some(window) = web_sys::window() else {
        return;
    };

    let _ = window.close();

    if !window.closed().unwrap_or(false) {
        let _ = window.location().set_href("/");
    }
}

/// Opens an empty same-origin page, keeping its handle, or `None` when the
/// browser blocked it (or outside a browser). Called in a click, so that
/// popup blockers allow it.
pub(super) fn open_empty_page() -> Option<web_sys::Window> {
    if !cfg!(target_arch = "wasm32") {
        return None;
    }

    web_sys::window()?.open().ok()?
}

/// Hands `credential` to a page from [`open_empty_page`] as its page session
/// and sends it to `url`, replacing the empty page in its history. Returns
/// whether the browser allowed both.
pub(super) fn hand_over_page(page: &web_sys::Window, credential: &str, url: &str) -> bool {
    let Some(storage) = page.session_storage().ok().flatten() else {
        return false;
    };

    storage.set_item(PAGE_SESSION_HEADER, credential).is_ok()
        && page.location().replace(url).is_ok()
}

/// Closes a page from [`open_empty_page`].
pub(super) fn close_opened_page(page: &web_sys::Window) {
    let _ = page.close();
}

/// Copies text to the clipboard, returning whether the browser allowed it.
pub(super) async fn copy_text(text: &str) -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };

    let promise = window.navigator().clipboard().write_text(text);
    wasm_bindgen_futures::JsFuture::from(promise).await.is_ok()
}
