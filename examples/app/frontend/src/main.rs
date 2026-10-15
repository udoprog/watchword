//! The watchword example frontend: `AuthProvider` in front of a small app
//! with the user menu, the account panel, admin user management and the
//! Cloudflare Access settings, plus a socket that lives as long as the
//! session.

use std::rc::Rc;

use auth::CloudflareConfig;
use auth::yew023::{
    AccountPanel, AdminUsers, AuthProvider, CloudflareSettings, UserMenu, UsersQuery, use_auth,
};
use gloo_net::http::Request;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{CloseEvent, MessageEvent, WebSocket};
use yew::prelude::*;

const TITLE: &str = "watchword example";

fn main() {
    yew::Renderer::<Root>::new().render();
}

#[function_component]
fn Root() -> Html {
    html! {
        <AuthProvider title={TITLE}>
            <App />
        </AuthProvider>
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Home,
    Account,
    Users,
    Settings,
}

#[function_component]
fn App() -> Html {
    let auth = use_auth();
    let page = use_state(|| Page::Home);
    let users_refresh = use_reducer(Counter::default);
    let query = use_state(UsersQuery::default);

    use_session_socket(users_refresh.dispatcher());

    let go = |to: Page| {
        let page = page.clone();
        Callback::from(move |()| page.set(to))
    };

    let nav = |to: Page, label: &'static str| {
        let onclick = go(to).reform(|_: MouseEvent| ());
        let current = (*page == to).then_some("page");
        html! { <button type="button" class="nav-item" aria-current={current} {onclick}>{label}</button> }
    };

    // An admin's own admin pages fall back to Home once they stop being one.
    let shown = match *page {
        Page::Users | Page::Settings if !auth.is_admin() => Page::Home,
        page => page,
    };

    let content = match shown {
        Page::Home => html! { <Home /> },
        Page::Account => html! {
            <section class="panel">
                <AccountPanel />
            </section>
        },
        Page::Users => {
            // After impersonating, the cookie is the other user's: load them.
            let on_impersonate = {
                let auth = auth.clone();
                let page = page.clone();
                Callback::from(move |_| {
                    page.set(Page::Home);
                    auth.refresh();
                })
            };
            let on_query_change = {
                let query = query.clone();
                Callback::from(move |q| query.set(q))
            };

            html! {
                <section class="panel wide">
                    <AdminUsers
                        me={auth.user.clone()}
                        refresh={users_refresh.0}
                        query={(*query).clone()}
                        {on_query_change}
                        {on_impersonate}
                    />
                </section>
            }
        }
        Page::Settings => html! { <Settings /> },
    };

    html! {
        <>
            <header class="top">
                <span class="brand">{TITLE}</span>
                <nav class="nav">
                    {nav(Page::Home, "Home")}
                    if auth.is_admin() {
                        {nav(Page::Settings, "Settings")}
                    }
                </nav>
                <UserMenu
                    on_account={go(Page::Account)}
                    on_admin={go(Page::Users)}
                    on_stop_impersonating={go(Page::Users)}
                />
            </header>
            <main class="content">{content}</main>
        </>
    }
}

/// Counts `users` messages, for the `refresh` prop of `AdminUsers`.
#[derive(Default, PartialEq)]
struct Counter(u64);

impl Reducible for Counter {
    type Action = ();

    fn reduce(self: Rc<Self>, (): ()) -> Rc<Self> {
        Rc::new(Counter(self.0 + 1))
    }
}

#[function_component]
fn Home() -> Html {
    let auth = use_auth();
    let user = &auth.user;

    html! {
        <section class="panel">
            <h1>{format!("Hello, {}", user.name())}</h1>
            <p>
                {format!("You are signed in as {}, ", user.name())}
                {if auth.is_admin() { "an admin." } else { "a regular user." }}
            </p>
            <p>
                {"Use the menu under your name for your account"}
                if auth.is_admin() { {", the users (add one to get a registration link)"} }
                {" and to sign out."}
                if auth.is_admin() { {" Settings holds the Cloudflare Access configuration."} }
            </p>
            <p class="hint">
                {"This page holds a WebSocket open for the session. Signing out elsewhere, being revoked or deleted closes it, and the app then shows the sign-in page with \"Your session has ended\"."}
            </p>
        </section>
    }
}

/// The Cloudflare Access settings, stored by the server in its own state
/// (`/api/example/cloudflare`), as an app keeps them in its settings.
#[function_component]
fn Settings() -> Html {
    let auth = use_auth();
    let value = use_state(|| None::<CloudflareConfig>);
    let saving = use_state(|| false);
    let error = use_state(|| None::<String>);

    {
        let value = value.clone();
        let error = error.clone();
        use_effect_with((), move |()| {
            wasm_bindgen_futures::spawn_local(async move {
                match fetch_json(Request::get("/api/example/cloudflare").build()).await {
                    Ok(config) => value.set(Some(config)),
                    Err(e) => error.set(Some(e)),
                }
            });
        });
    }

    let on_change = {
        let value = value.clone();
        let saving = saving.clone();
        let error = error.clone();
        Callback::from(move |config: CloudflareConfig| {
            let value = value.clone();
            let saving = saving.clone();
            let error = error.clone();
            let auth = auth.clone();
            saving.set(true);

            wasm_bindgen_futures::spawn_local(async move {
                let request = Request::put("/api/example/cloudflare").json(&config);

                match fetch_json(request).await {
                    Ok(config) => {
                        value.set(Some(config));
                        error.set(None);
                        // The config's `cloudflare` flag may have changed.
                        auth.refresh();
                    }
                    Err(e) => error.set(Some(e)),
                }

                saving.set(false);
            });
        })
    };

    html! {
        <section class="panel wide">
            if let Some(e) = &*error {
                <p class="auth-error" role="alert">{e.clone()}</p>
            }
            if let Some(config) = &*value {
                <CloudflareSettings value={config.clone()} {on_change} app_name={TITLE} disabled={*saving} />
            } else if error.is_none() {
                <p class="auth-status">{"Loading..."}</p>
            }
        </section>
    }
}

/// Sends `request` and decodes its JSON answer, with errors as text.
async fn fetch_json<T>(request: Result<Request, gloo_net::Error>) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    let response = request
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.ok() {
        return Err(format!("The server answered {}.", response.status()));
    }

    response.json().await.map_err(|e| e.to_string())
}

/// Keeps `/api/example/ws` open while signed in.
///
/// A `user` message updates the signed-in user, a `users` message bumps
/// `users_refresh` (the `refresh` prop of `AdminUsers`), and when the socket
/// closes the session is checked: a 401 shows the sign-in page with "Your
/// session has ended". Otherwise it reconnects after a few seconds.
#[hook]
fn use_session_socket(users_refresh: UseReducerDispatcher<Counter>) {
    let auth = use_auth();
    let generation = use_state(|| 0u32);

    use_effect_with(*generation, move |_| {
        let socket = open_socket();

        let on_message = {
            let auth = auth.clone();
            let users_refresh = users_refresh.clone();

            Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
                let Some(text) = e.data().as_string() else {
                    return;
                };

                let Ok(message) = serde_json::from_str::<serde_json::Value>(&text) else {
                    return;
                };

                match message["type"].as_str() {
                    Some("user") => {
                        if let Ok(user) = serde_json::from_value(message["user"].clone()) {
                            auth.set_user(user);
                        }
                    }
                    Some("users") => users_refresh.dispatch(()),
                    _ => {}
                }
            })
        };

        let on_close = {
            let generation = generation.clone();

            Closure::<dyn FnMut(CloseEvent)>::new(move |_: CloseEvent| {
                auth.check_session();

                // If the session is still live (the server restarted, say),
                // reconnect; if not, this component is gone by then.
                let generation = generation.clone();
                let reconnect = Closure::once_into_js(move || generation.set(*generation + 1));

                if let Some(window) = web_sys::window() {
                    let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
                        reconnect.unchecked_ref(),
                        3000,
                    );
                }
            })
        };

        if let Some(socket) = &socket {
            socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        }

        move || {
            if let Some(socket) = socket {
                socket.set_onmessage(None);
                socket.set_onclose(None);
                let _ = socket.close();
            }

            drop((on_message, on_close));
        }
    });
}

fn open_socket() -> Option<WebSocket> {
    let location = web_sys::window()?.location();
    let scheme = if location.protocol().ok()? == "https:" {
        "wss"
    } else {
        "ws"
    };
    let url = format!("{scheme}://{}/api/example/ws", location.host().ok()?);
    WebSocket::new(&url).ok()
}
