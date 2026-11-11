//! Media in an impersonated page (decision 33): [`MediaUrl`],
//! [`use_media_url`] and [`download`] load what the browser would fetch by
//! itself with the page session, and the provider's watcher clears what was
//! not loaded so.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::string::String;
use std::time::Duration;
use std::vec::Vec;

use yew::prelude::*;

use super::Error;
use super::browser;
use super::http;

/// What a fetch of a URL came to, shared by every [`MediaUrl`] of it.
type Outcome = Rc<OnceCell<Result<AttrValue, Error>>>;

/// How long an object URL made for [`download`] is kept. The browser gives
/// no sign of having read it, so it is revoked once a save has surely
/// started.
const DOWNLOAD_LIFETIME: Duration = Duration::from_secs(30);

thread_local! {
    static SHARED: RefCell<Shared<web_sys::AbortController>> = RefCell::new(Shared::default());
    static SESSION_CHECK: RefCell<Option<Callback<()>>> = const { RefCell::new(None) };
    static PRIVATE_MEDIA: RefCell<Vec<AttrValue>> = const { RefCell::new(Vec::new()) };
}

/// The object URLs of a page, by the URL fetched, each counted by its users.
/// `A` aborts a fetch, which the browser's `AbortController` does.
pub(super) struct Shared<A> {
    entries: HashMap<String, Entry<A>>,
    next: u64,
}

impl<A> Default for Shared<A> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            next: 0,
        }
    }
}

struct Entry<A> {
    /// Tells this fetch apart from a later one of the same URL.
    generation: u64,
    outcome: Outcome,
    users: Vec<(u64, Callback<()>)>,
    /// Aborts the fetch while it is in flight.
    abort: Option<A>,
}

/// What is left to do once the last user of a URL has gone.
#[derive(Debug, PartialEq)]
pub(super) enum Released<A> {
    /// Abort the fetch still in flight.
    Abort(A),
    /// Revoke the object URL.
    Revoke(AttrValue),
}

impl<A> Shared<A> {
    /// Adds a user of `url`, told with `on_change` when its fetch ends. The
    /// first user starts the fetch with `start`, given the generation to
    /// [`finish`](Self::finish) it with; it returns what aborts it. Returns
    /// the user's id and the shared outcome.
    pub(super) fn acquire(
        &mut self,
        url: &str,
        on_change: Callback<()>,
        start: impl FnOnce(u64) -> Option<A>,
    ) -> (u64, Outcome) {
        let user = self.next();

        if let Some(entry) = self.entries.get_mut(url) {
            entry.users.push((user, on_change));
            return (user, entry.outcome.clone());
        }

        let generation = self.next();
        let outcome = Outcome::default();

        let entry = Entry {
            generation,
            outcome: outcome.clone(),
            users: vec![(user, on_change)],
            abort: None,
        };

        self.entries.insert(url.into(), entry);
        let abort = start(generation);

        if let Some(entry) = self.entries.get_mut(url) {
            entry.abort = abort;
        }

        (user, outcome)
    }

    /// Removes a user of `url`. Once none is left, the URL is forgotten and
    /// its fetch is aborted, or its object URL revoked.
    pub(super) fn release(&mut self, url: &str, user: u64) -> Option<Released<A>> {
        let entry = self.entries.get_mut(url)?;
        entry.users.retain(|(id, _)| *id != user);

        if !entry.users.is_empty() {
            return None;
        }

        let entry = self.entries.remove(url)?;

        match entry.outcome.get() {
            None => entry.abort.map(Released::Abort),
            Some(Ok(src)) => Some(Released::Revoke(src.clone())),
            Some(Err(..)) => None,
        }
    }

    /// Records the end of the fetch of `url` started as `generation`,
    /// returning the callbacks of its users to call, and an object URL to
    /// revoke at once when nobody uses it any more.
    pub(super) fn finish(
        &mut self,
        url: &str,
        generation: u64,
        result: Result<AttrValue, Error>,
    ) -> (Vec<Callback<()>>, Option<AttrValue>) {
        let entry = match self.entries.get_mut(url) {
            Some(entry) if entry.generation == generation && entry.outcome.get().is_none() => entry,
            _ => return (Vec::new(), result.ok()),
        };

        entry.abort = None;
        let _ = entry.outcome.set(result);
        let notify = entry.users.iter().map(|(_, cb)| cb.clone()).collect();
        (notify, None)
    }

    /// The number of users of `url`.
    #[cfg(test)]
    pub(super) fn users(&self, url: &str) -> usize {
        self.entries.get(url).map_or(0, |entry| entry.users.len())
    }

    fn next(&mut self) -> u64 {
        self.next += 1;
        self.next
    }
}

/// Whether the absolute `url` is on `origin` with a path under one of
/// `prefixes`, such as `/api/`.
pub(super) fn is_private(url: &str, origin: &str, prefixes: &[AttrValue]) -> bool {
    if !browser::is_same_origin_url(url, origin) {
        return false;
    }

    let rest = &url[origin.len()..];
    prefixes
        .iter()
        .any(|prefix| rest.starts_with(prefix.as_str()))
}

/// The file name a `Content-Disposition` header gives, preferring an
/// RFC 5987 `filename*` over `filename`, without any directory.
pub(super) fn content_disposition_filename(value: &str) -> Option<String> {
    let mut plain = None;
    let mut extended = None;

    for param in value.split(';').skip(1) {
        let Some((key, value)) = param.split_once('=') else {
            continue;
        };

        let value = value.trim();

        match key.trim().to_ascii_lowercase().as_str() {
            "filename*" => {
                // charset'language'percent-encoded
                let mut parts = value.splitn(3, '\'');

                if let (Some(charset), Some(_), Some(encoded)) =
                    (parts.next(), parts.next(), parts.next())
                    && charset.eq_ignore_ascii_case("utf-8")
                {
                    extended = browser::percent_decode(encoded);
                }
            }
            "filename" => {
                plain = Some(
                    match value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                        Some(quoted) => quoted.replace("\\\"", "\"").replace("\\\\", "\\"),
                        None => value.into(),
                    },
                );
            }
            _ => {}
        }
    }

    let name = extended.or(plain)?;
    let name = name.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    (!name.is_empty()).then(|| name.into())
}

/// The last path segment of `url`, decoded, for a download without a name.
pub(super) fn url_filename(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();

    match browser::percent_decode(last) {
        Some(name) if !name.is_empty() => name,
        _ => String::from("download"),
    }
}

/// Readies media in an impersonated page: a 401 loading one emits
/// `check_session`, and media under `prefixes` the app did not load through
/// [`MediaUrl`] are cleared.
pub(super) fn enter_impersonated_page(prefixes: Vec<AttrValue>, check_session: Callback<()>) {
    SESSION_CHECK.with_borrow_mut(|check| *check = Some(check_session));
    set_private_media(prefixes);

    browser::watch_media(|url| {
        let origin = browser::origin();
        PRIVATE_MEDIA.with_borrow(|prefixes| is_private(url, &origin, prefixes))
    });
}

/// Sets the prefixes the watcher clears media under.
pub(super) fn set_private_media(prefixes: Vec<AttrValue>) {
    PRIVATE_MEDIA.with_borrow_mut(|current| *current = prefixes);
}

/// The URL to fetch `url` from with the page session, or `None` when it is
/// used as it is: outside an impersonated page, or on another origin.
fn fetched_url(url: &str) -> Option<String> {
    browser::page_session()?;
    let resolved = browser::resolve_url(url)?;
    browser::is_same_origin_url(&resolved, &browser::origin()).then_some(resolved)
}

/// Fetches `url` with the page session, returning its body and the
/// `Content-Disposition` header. A 401 checks the session, so an ended one
/// ends the page.
async fn fetch_blob(
    url: &str,
    signal: Option<&web_sys::AbortSignal>,
) -> Result<(web_sys::Blob, Option<String>), Error> {
    let result = async {
        let response = http::get(url).abort_signal(signal).send().await?;
        let response = http::check(response).await?;
        let disposition = response.headers().get("content-disposition");
        let response = web_sys::Response::from(response);

        match browser::response_blob(&response).await {
            Some(blob) => Ok((blob, disposition)),
            None => Err(Error::Network(format!("could not read {url}"))),
        }
    }
    .await;

    if result.as_ref().is_err_and(Error::is_unauthorized)
        && let Some(check) = SESSION_CHECK.with_borrow(Clone::clone)
    {
        check.emit(());
    }

    result
}

/// The fetch of [`MediaUrl`]: `url` into an object URL, given to its users.
async fn load_shared(url: String, generation: u64, signal: Option<web_sys::AbortSignal>) {
    let result = match fetch_blob(&url, signal.as_ref()).await {
        Ok((blob, _)) => browser::create_object_url(&blob)
            .map(AttrValue::from)
            .ok_or_else(|| Error::Network(format!("could not show {url}"))),
        Err(error) => Err(error),
    };

    let (notify, orphan) = SHARED.with_borrow_mut(|shared| shared.finish(&url, generation, result));

    if let Some(orphan) = orphan {
        browser::revoke_object_url(&orphan);
    }

    for callback in notify {
        callback.emit(());
    }
}

/// A URL for media the browser would fetch by itself, such as an `<img>`'s
/// `src`, that loads as the page's user also in a page an admin opened to
/// impersonate someone.
///
/// The browser's own requests for media carry only the cookie, which in
/// such a page is the admin's. So there, a same-origin `MediaUrl` fetches
/// its URL with the page's session and gives an
/// [object URL](https://developer.mozilla.org/en-US/docs/Web/API/URL/createObjectURL_static)
/// of the body; elsewhere it is the URL itself, at once, so normal pages
/// keep streaming, range requests and the HTTP cache. Use it unconditionally
/// for signed-in media: in an impersonated page, [`AuthProvider`] clears
/// such media that did not load through it (see
/// [`private_media`](super::AuthProviderProps::private_media)).
///
/// The object URLs are shared by URL and counted, so an image shown twice is
/// fetched once. Dropping the last `MediaUrl` (and its clones) of a URL
/// revokes its object URL, or aborts its fetch while loading. A 401 checks
/// the session, so an ended impersonation ends the page.
///
/// In an impersonated page audio and video download whole before they play,
/// and nothing is cached across loads of the page.
///
/// A struct component keeps one in a field, made with [`MediaUrl::load`] and
/// a callback that renders again; a function component uses
/// [`use_media_url`].
///
/// ```
/// use watchword_yew023::MediaUrl;
/// use yew::prelude::*;
///
/// struct Avatar {
///     media: MediaUrl,
/// }
///
/// impl Component for Avatar {
///     type Message = ();
///     type Properties = ();
///
///     fn create(ctx: &Context<Self>) -> Self {
///         let media = MediaUrl::load("/api/avatar", ctx.link().callback(|()| ()));
///         Self { media }
///     }
///
///     fn update(&mut self, _: &Context<Self>, (): ()) -> bool {
///         true
///     }
///
///     fn view(&self, _: &Context<Self>) -> Html {
///         html! { <img src={self.media.src()} alt="" /> }
///     }
/// }
/// ```
///
/// [`AuthProvider`]: super::AuthProvider
#[derive(Clone, PartialEq)]
pub struct MediaUrl {
    url: AttrValue,
    lease: Option<Rc<Lease>>,
}

struct Lease {
    resolved: String,
    user: u64,
    outcome: Outcome,
}

impl PartialEq for Lease {
    fn eq(&self, other: &Self) -> bool {
        self.user == other.user
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let released = SHARED.with_borrow_mut(|shared| shared.release(&self.resolved, self.user));

        match released {
            Some(Released::Abort(abort)) => abort.abort(),
            Some(Released::Revoke(src)) => browser::revoke_object_url(&src),
            None => {}
        }
    }
}

impl MediaUrl {
    /// Loads `url`, emitting `on_change` once it has loaded or failed. Only
    /// a fetch, in an impersonated page, ever emits it.
    pub fn load(url: impl Into<AttrValue>, on_change: Callback<()>) -> Self {
        let url = url.into();

        let lease = fetched_url(&url).map(|resolved| {
            let (user, outcome) = SHARED.with_borrow_mut(|shared| {
                shared.acquire(&resolved, on_change, |generation| {
                    let abort = browser::abort_controller();
                    let signal = abort.as_ref().map(web_sys::AbortController::signal);
                    wasm_bindgen_futures::spawn_local(load_shared(
                        resolved.clone(),
                        generation,
                        signal,
                    ));
                    abort
                })
            });

            Rc::new(Lease {
                resolved,
                user,
                outcome,
            })
        });

        Self { url, lease }
    }

    /// The URL loaded, as given.
    pub fn url(&self) -> &AttrValue {
        &self.url
    }

    /// What to put in the element's `src`: the URL, or in an impersonated
    /// page the object URL of its body, which is `None` while loading or
    /// once it failed.
    pub fn src(&self) -> Option<AttrValue> {
        match &self.lease {
            None => Some(self.url.clone()),
            Some(lease) => lease.outcome.get()?.as_ref().ok().cloned(),
        }
    }

    /// Whether it is still loading.
    pub fn is_loading(&self) -> bool {
        self.lease
            .as_ref()
            .is_some_and(|lease| lease.outcome.get().is_none())
    }

    /// Why it failed to load, if it did.
    pub fn error(&self) -> Option<&Error> {
        self.lease.as_ref()?.outcome.get()?.as_ref().err()
    }
}

impl std::fmt::Debug for MediaUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaUrl")
            .field("url", &self.url)
            .field("src", &self.src())
            .field("error", &self.error())
            .finish()
    }
}

/// A [`MediaUrl`] of `url` for a function component, loaded again when
/// `url` changes, which renders the component again once it has loaded.
///
/// ```
/// use watchword_yew023::use_media_url;
/// use yew::prelude::*;
///
/// #[function_component]
/// fn Avatar() -> Html {
///     let media = use_media_url("/api/avatar");
///
///     html! { <img src={media.src()} alt="" /> }
/// }
/// ```
#[hook]
pub fn use_media_url<U>(url: U) -> MediaUrl
where
    U: Into<AttrValue>,
{
    let url = url.into();
    let update = use_force_update();
    let current = use_mut_ref(|| None::<MediaUrl>);
    let mut current = current.borrow_mut();

    match &*current {
        Some(media) if *media.url() == url => media.clone(),
        _ => {
            let media = MediaUrl::load(url, Callback::from(move |()| update.force_update()));
            *current = Some(media.clone());
            media
        }
    }
}

/// Saves the file at `url`, from a click handler, as `filename` or else the
/// name the server or the URL gives.
///
/// Outside a page an admin opened to impersonate someone it clicks an
/// `<a download>`. In one, it fetches the file with the page's session
/// first and saves an object URL of it, since the browser's own download
/// would carry only the admin's cookie; failures go to the console, and a
/// 401 checks the session, as for [`MediaUrl`].
pub fn download(url: &str, filename: Option<&str>) {
    let Some(resolved) = fetched_url(url) else {
        browser::click_download(url, filename.unwrap_or_default());
        return;
    };

    let filename = filename.map(String::from);

    wasm_bindgen_futures::spawn_local(async move {
        let (blob, disposition) = match fetch_blob(&resolved, None).await {
            Ok(fetched) => fetched,
            Err(error) => {
                browser::console_error(&format!(
                    "watchword: downloading {resolved} failed: {error}"
                ));
                return;
            }
        };

        let name = filename
            .or_else(|| {
                disposition
                    .as_deref()
                    .and_then(content_disposition_filename)
            })
            .unwrap_or_else(|| url_filename(&resolved));

        let Some(src) = browser::create_object_url(&blob) else {
            return;
        };

        browser::click_download(&src, &name);
        yew::platform::time::sleep(DOWNLOAD_LIFETIME).await;
        browser::revoke_object_url(&src);
    });
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;
    use std::vec::Vec;

    use yew::{AttrValue, Callback};

    use super::{Released, Shared, content_disposition_filename, is_private, url_filename};
    use crate::Error;

    const URL: &str = "https://example.com/api/a.png";

    fn counter() -> (Rc<Cell<u32>>, Callback<()>) {
        let count = Rc::new(Cell::new(0));
        let counted = count.clone();
        (
            count,
            Callback::from(move |()| counted.set(counted.get() + 1)),
        )
    }

    #[test]
    fn shared_per_url() {
        let mut shared = Shared::<&str>::default();
        let mut starts = Vec::new();
        let (a, on_a) = counter();
        let (b, on_b) = counter();

        let (user_a, outcome_a) = shared.acquire(URL, on_a, |g| {
            starts.push(g);
            Some("abort")
        });

        let (user_b, outcome_b) = shared.acquire(URL, on_b, |_| panic!("fetched twice"));
        assert_eq!(starts.len(), 1);
        assert!(Rc::ptr_eq(&outcome_a, &outcome_b));
        assert_eq!(shared.users(URL), 2);

        let (notify, orphan) = shared.finish(URL, starts[0], Ok(AttrValue::from("blob:1")));
        assert_eq!(orphan, None);
        notify.iter().for_each(|cb| cb.emit(()));
        assert_eq!((a.get(), b.get()), (1, 1));
        assert_eq!(outcome_a.get(), Some(&Ok(AttrValue::from("blob:1"))));

        assert_eq!(shared.release(URL, user_a), None);
        assert_eq!(
            shared.release(URL, user_b),
            Some(Released::Revoke(AttrValue::from("blob:1")))
        );
        assert_eq!(shared.users(URL), 0);
    }

    #[test]
    fn dropped_while_loading_aborts() {
        let mut shared = Shared::<&str>::default();
        let mut generation = 0;
        let (user, _) = shared.acquire(URL, Callback::noop(), |g| {
            generation = g;
            Some("abort")
        });

        assert_eq!(shared.release(URL, user), Some(Released::Abort("abort")));

        // A fetch that finishes anyway is revoked at once.
        let (notify, orphan) = shared.finish(URL, generation, Ok(AttrValue::from("blob:1")));
        assert!(notify.is_empty());
        assert_eq!(orphan, Some(AttrValue::from("blob:1")));
    }

    #[test]
    fn later_load_starts_again() {
        let mut shared = Shared::<&str>::default();
        let mut first = 0;
        let (user, _) = shared.acquire(URL, Callback::noop(), |g| {
            first = g;
            None
        });
        assert_eq!(shared.release(URL, user), None);

        let mut second = 0;
        let (_, outcome) = shared.acquire(URL, Callback::noop(), |g| {
            second = g;
            None
        });
        assert_ne!(first, second);

        // The first fetch's answer is not the second's.
        let (notify, orphan) = shared.finish(URL, first, Ok(AttrValue::from("blob:1")));
        assert!(notify.is_empty());
        assert_eq!(orphan, Some(AttrValue::from("blob:1")));
        assert_eq!(outcome.get(), None);
    }

    #[test]
    fn failures_are_kept_and_not_revoked() {
        let mut shared = Shared::<&str>::default();
        let mut generation = 0;
        let (user, outcome) = shared.acquire(URL, Callback::noop(), |g| {
            generation = g;
            None
        });

        shared.finish(URL, generation, Err(Error::Status(500)));
        assert_eq!(outcome.get(), Some(&Err(Error::Status(500))));
        let (_, again) = shared.acquire(URL, Callback::noop(), |_| panic!("fetched twice"));
        assert!(Rc::ptr_eq(&outcome, &again));
        assert_eq!(shared.release(URL, user), None);
    }

    #[test]
    fn private_prefixes() {
        let origin = "https://example.com";
        let prefixes = [AttrValue::from("/api/"), AttrValue::from("/media/")];

        assert!(is_private(
            "https://example.com/api/a.png",
            origin,
            &prefixes
        ));
        assert!(is_private(
            "https://example.com/media/x?y=1",
            origin,
            &prefixes
        ));
        assert!(!is_private(
            "https://example.com/apix/a.png",
            origin,
            &prefixes
        ));
        assert!(!is_private(
            "https://example.com/static/a.png",
            origin,
            &prefixes
        ));
        assert!(!is_private(
            "https://example.com.evil/api/a",
            origin,
            &prefixes
        ));
        assert!(!is_private(
            "https://other.com/api/a.png",
            origin,
            &prefixes
        ));
        assert!(!is_private(
            "blob:https://example.com/0b1c-2d3e",
            origin,
            &prefixes
        ));
        assert!(!is_private("data:image/png;base64,AAAA", origin, &prefixes));
        assert!(!is_private("https://example.com/api/a", "", &prefixes));
        assert!(!is_private("https://example.com/api/a", origin, &[]));
    }

    #[test]
    fn disposition_names() {
        let name = content_disposition_filename;
        assert_eq!(
            name("attachment; filename=\"a b.txt\"").as_deref(),
            Some("a b.txt")
        );
        assert_eq!(
            name("attachment; filename=plain.txt").as_deref(),
            Some("plain.txt")
        );
        assert_eq!(
            name("attachment; filename=\"x.txt\"; filename*=UTF-8''%C3%A9t%C3%A9.txt").as_deref(),
            Some("été.txt")
        );
        assert_eq!(
            name("attachment; filename=\"../../etc/passwd\"").as_deref(),
            Some("passwd")
        );
        assert_eq!(name("attachment; filename=\"\"").as_deref(), None);
        assert_eq!(name("inline").as_deref(), None);
    }

    #[test]
    fn url_names() {
        assert_eq!(
            url_filename("https://example.com/api/r%C3%A9.pdf?x=1"),
            "ré.pdf"
        );
        assert_eq!(url_filename("https://example.com/api/"), "download");
    }
}
