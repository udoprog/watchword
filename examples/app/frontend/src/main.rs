//! The watchword example frontend: `AuthProvider` in front of a small app
//! with the user menu, the account panel, admin user management and the
//! Cloudflare Access settings, plus a musli-web socket that lives as long as
//! the session.
//!
//! The socket is the wiring of `docs/design.md` section 2.7, opened in
//! [`App`]: handed to watchword with `set_socket`, it carries the
//! components' account and admin requests and the server's `AuthBroadcast`,
//! beside the app's own API (the `api` crate).

use std::cell::RefCell;
use std::rc::Rc;

use auth::CloudflareConfig;
use auth::yew023::{
    AccountPanel, AdminUsers, AuthProvider, CloudflareSettings, UserMenu, UsersQuery, use_auth,
};
use gloo_net::http::Request;
use musli_web::web03::prelude::ws;
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
    let query = use_state(UsersQuery::default);
    // The app's musli-web socket, `/api/example/ws`, open while signed in
    // since `App` only renders then.
    //
    // - `set_socket` gives watchword the handle once. From then on the
    //   account panel, the admin page and `refresh()` send their requests
    //   over it while it is open, and over HTTP while it reconnects.
    //   `AuthProvider` follows the server's `AuthBroadcast` for the user, and
    //   `AdminUsers` for its list, so the list needs no `refresh` prop.
    // - When the socket closes, or stays closed, `AuthProvider` checks the
    //   session over HTTP: a 401 shows the sign-in page with "Your session
    //   has ended", which unmounts the app and so drops the socket.
    //   Otherwise musli-web reconnects by itself, with backoff.
    // - The socket speaks for the session its upgrade carried. Impersonating,
    //   and stopping it, replace the session cookie, so the app calls
    //   `reconnect` then. Until the socket reconnects watchword marks it stale
    //   and uses HTTP, so the requests are right either way; reconnecting puts
    //   them, and the live updates, back on the socket.
    let service = use_memo((), |()| {
        ws::connect(ws::Connect::location("/api/example/ws"))
            .close_before_unload()
            .build()
    });

    {
        let auth = auth.clone();
        let handle = service.handle().clone();
        use_effect_with((), move |()| auth.set_socket(Some(handle)));
    }

    // Closes the socket and opens it again, so that its upgrade carries the
    // current session cookie.
    let reconnect = {
        let service = service.clone();

        use_callback((), move |(), _| {
            service.close();
            service.open();
        })
    };

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
        Page::Home => html! { <Home socket={service.handle().clone()} /> },
        Page::Account => html! {
            <section class="panel">
                <AccountPanel />
            </section>
        },
        Page::Users => {
            // After impersonating, the cookie is the other user's: reconnect
            // the socket, which still speaks for the admin's session, and
            // load them.
            let on_impersonate = {
                let auth = auth.clone();
                let page = page.clone();
                let reconnect = reconnect.clone();
                Callback::from(move |_| {
                    page.set(Page::Home);
                    reconnect.emit(());
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
                        query={(*query).clone()}
                        {on_query_change}
                        {on_impersonate}
                    />
                </section>
            }
        }
        Page::Settings => html! { <Settings /> },
    };

    // Stopping replaces the cookie with the admin's session again, so the
    // socket reconnects with it too.
    let on_stop_impersonating = {
        let to_users = go(Page::Users);
        let reconnect = reconnect.clone();
        Callback::from(move |()| {
            reconnect.emit(());
            to_users.emit(());
        })
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
                    {on_stop_impersonating}
                />
            </header>
            <main class="content">{content}</main>
        </>
    }
}

#[derive(Properties, PartialEq)]
struct HomeProps {
    socket: ws::Handle,
}

#[function_component]
fn Home(props: &HomeProps) -> Html {
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
            <ServerStatus socket={props.socket.clone()} />
            <p class="hint">
                {"The app holds a WebSocket open for the session. It carries the account and user-management requests and their live updates (open Users in two windows to see one follow the other), and the app's own requests, such as the status above. Signing out elsewhere, being revoked or deleted closes it, and the app then shows the sign-in page with \"Your session has ended\"."}
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

#[derive(Properties, PartialEq)]
struct ServerStatusProps {
    socket: ws::Handle,
}

/// The server's status, from the app's own `Status` endpoint, asked for
/// each time the socket opens.
#[function_component]
fn ServerStatus(props: &ServerStatusProps) -> Html {
    let status = use_state(|| None::<Result<api::StatusResponse, String>>);

    {
        let status = status.clone();

        use_effect_with(props.socket.clone(), move |socket| {
            let request = Rc::new(RefCell::new(ws::Request::default()));

            let ask = {
                let socket = socket.clone();
                let request = request.clone();

                move || {
                    let status = status.clone();

                    let sent = socket
                        .request()
                        .body(api::StatusRequest)
                        .on_packet(move |packet: Result<ws::Packet<api::Status>, ws::Error>| {
                            let response = packet.and_then(|packet| packet.decode());
                            status.set(Some(response.map_err(|e| e.to_string())));
                        })
                        .send();

                    *request.borrow_mut() = sent;
                }
            };

            let (state, listener) = socket.on_state_change({
                let ask = ask.clone();

                move |state: ws::State| {
                    if state.is_open() {
                        ask();
                    }
                }
            });

            if state.is_open() {
                ask();
            }

            move || drop((listener, request))
        });
    }

    let text = match &*status {
        None => "Server: waiting for the socket.".to_owned(),
        Some(Ok(status)) => format!(
            "Server: up {} s, {} socket(s) open.",
            status.uptime, status.sockets
        ),
        Some(Err(error)) => format!("Server: {error}"),
    };

    html! { <p class="hint">{text}</p> }
}
