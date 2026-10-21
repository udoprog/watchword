//! The watchword example server: axum with a `MemoryStore` and all three
//! sign-in methods, serving the trunk-built frontend.
//!
//! Simple auth works out of the box: on an empty store the server logs a
//! registration link for the bootstrap admin. Google and Cloudflare Access
//! are configured through the environment (and Cloudflare also at runtime,
//! on the frontend's Settings page). See `--help`.
//!
//! The frontend keeps a musli-web socket open for the session at
//! `/api/example/ws`. It carries the app's own API (the `api` crate) and
//! watchword's account and user-management requests and live updates, the
//! wiring of `docs/design.md` section 2.7: see [`ws`].
//!
//! Everything is in memory, so a restart starts over with a new bootstrap
//! link.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use auth::axum08::{Admin, SignedIn};
use auth::musliweb04::Connection;
use auth::{Auth, BootstrapAdmin, CloudflareConfig, GoogleConfig, MemoryStore};
use axum::extract::ws::{WebSocket, WebSocketUpgrade};
use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use musli_web::ws;
use tokio::sync::broadcast::error::RecvError;
use tower_http::services::{ServeDir, ServeFile};
use url::Url;

const HELP: &str = "\
The watchword example server.

Usage: watchword-example-server [OPTIONS]

Options:
  --bind ADDR              Address to listen on [default: 127.0.0.1:8080]
  --dist DIR               The trunk-built frontend [default: ../frontend/dist]
  --public-url URL         The URL the app is reached at, for the bootstrap
                           link and the Google redirect [default: http://ADDR]
  --bootstrap-admin NAME   The first admin's login, or email if it has an @
                           [default: admin]
  --no-impersonation       Turn off admin impersonation
  -h, --help               Print this help

Environment:
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
      Enable Google sign-in with this OAuth client. Its redirect URL is
      PUBLIC_URL/api/auth/google/redirect; register that with Google.
  CLOUDFLARE_TEAM_DOMAIN, CLOUDFLARE_AUDIENCE
      Enable Cloudflare Access sign-in, verifying the Access JWT.
  CLOUDFLARE_TRUST_EMAIL_HEADER=1
      Also accept Access's email header (and, without the JWT settings, only
      it: for local testing, never on a server reachable around Access).
  RUST_LOG
      Log filter [default: info]
";

/// The app's state: the auth service, the Cloudflare settings the app
/// stores (here in memory) and applies with `Auth::set_cloudflare`, and what
/// the app's own `Status` endpoint reports.
#[derive(Clone)]
struct AppState {
    auth: Auth,
    cloudflare: Arc<Mutex<CloudflareConfig>>,
    started: Instant,
    sockets: Arc<AtomicU32>,
}

impl FromRef<AppState> for Auth {
    fn from_ref(state: &AppState) -> Self {
        state.auth.clone()
    }
}

struct Args {
    bind: SocketAddr,
    dist: PathBuf,
    public_url: Option<Url>,
    bootstrap_admin: String,
    impersonation: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
        dist: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../frontend/dist"),
        public_url: None,
        bootstrap_admin: "admin".to_owned(),
        impersonation: true,
    };

    let mut it = std::env::args().skip(1);

    while let Some(arg) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{arg} needs a value"));

        match arg.as_str() {
            "--bind" => args.bind = value()?.parse().map_err(|e| format!("--bind: {e}"))?,
            "--dist" => args.dist = value()?.into(),
            "--public-url" => {
                args.public_url = Some(value()?.parse().map_err(|e| format!("--public-url: {e}"))?)
            }
            "--bootstrap-admin" => args.bootstrap_admin = value()?,
            "--no-impersonation" => args.impersonation = false,
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}; see --help")),
        }
    }

    Ok(args)
}

/// Google from `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, with the
/// callback at the library's fixed path under the public URL.
fn google_config(public_url: &Url) -> Option<GoogleConfig> {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").ok()?;
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").ok()?;
    let redirect_url = public_url.join(auth::google::REDIRECT_PATH).ok()?;

    Some(GoogleConfig {
        client_id,
        client_secret,
        redirect_url,
    })
}

/// The initial Cloudflare Access settings, from the environment.
fn cloudflare_config() -> CloudflareConfig {
    let var = |name| std::env::var(name).unwrap_or_default();
    let team_domain = var("CLOUDFLARE_TEAM_DOMAIN");
    let audience = var("CLOUDFLARE_AUDIENCE");
    let verify_jwt = !team_domain.is_empty() && !audience.is_empty();
    let trust_email_header = matches!(var("CLOUDFLARE_TRUST_EMAIL_HEADER").as_str(), "1" | "true");

    CloudflareConfig {
        enabled: verify_jwt || trust_email_header,
        team_domain,
        audience,
        trust_email_header,
        verify_jwt,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = match parse_args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(2);
        }
    };

    let public_url = match args.public_url {
        Some(url) => url,
        None => format!("http://{}", args.bind).parse()?,
    };

    let google = google_config(&public_url);
    let cloudflare = cloudflare_config();

    tracing::info!(
        "Methods: password; Google {}; Cloudflare Access {}",
        if google.is_some() {
            "on"
        } else {
            "off (set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)"
        },
        if cloudflare.enabled {
            "on"
        } else {
            "off (enable it on the Settings page)"
        },
    );

    // An app keeps its session key in its database with
    // `auth::load_or_create_key`; in memory there is nothing to keep.
    let store = MemoryStore::new();
    let key = auth::load_or_create_key(&store).await?;

    let auth = Auth::builder(store, key)
        .cookie(auth::CookieConfig::new("example_session"))
        .logins(true)
        .impersonation(args.impersonation)
        .google(google)
        .cloudflare(Some(cloudflare.clone()))
        .build();

    let bootstrap = BootstrapAdmin::new(&args.bootstrap_admin).public_url(Some(&public_url));

    // The library logs the link too; print it where the operator looks. The
    // store is in memory, so every start creates the admin afresh, but a
    // persistent store also gets a new link here once the first one expires
    // unused.
    if let Some(link) = auth.bootstrap_admin(&bootstrap).await?.link() {
        println!(
            "\nSign up as the first admin ({}): {}\n",
            args.bootstrap_admin,
            link.url(Some(public_url.as_str()))
        );
    }

    // Expired sessions and links are pruned now and then.
    tokio::spawn({
        let auth = auth.clone();

        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));

            loop {
                interval.tick().await;

                if let Err(error) = auth.prune().await {
                    tracing::warn!("Pruning sessions and links failed: {error}");
                }
            }
        }
    });

    let state = AppState {
        auth,
        cloudflare: Arc::new(Mutex::new(cloudflare)),
        started: Instant::now(),
        sockets: Arc::new(AtomicU32::new(0)),
    };

    let index = args.dist.join("index.html");

    if !index.is_file() {
        tracing::warn!(
            "{} is missing; build the frontend with `trunk build` in examples/app/frontend",
            index.display()
        );
    }

    // Frontend routes such as `/register/{token}` get index.html.
    let frontend = ServeDir::new(&args.dist).fallback(ServeFile::new(index));

    let app = Router::new()
        .route(
            "/api/example/cloudflare",
            get(get_cloudflare).put(put_cloudflare),
        )
        .route("/api/example/ws", get(ws))
        .merge(auth::axum08::routes())
        .route(
            "/api/{*rest}",
            axum::routing::any(|| async { StatusCode::NOT_FOUND }),
        )
        .fallback_service(frontend)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.bind).await?;
    tracing::info!("Listening on http://{}", listener.local_addr()?);

    // The sign-in route throttles by the client's address.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;

    Ok(())
}

/// `GET /api/example/cloudflare`: the stored Cloudflare Access settings.
async fn get_cloudflare(State(state): State<AppState>, _: Admin) -> Json<CloudflareConfig> {
    Json(state.cloudflare.lock().unwrap().clone())
}

/// `PUT /api/example/cloudflare`: stores the settings and applies them.
async fn put_cloudflare(
    State(state): State<AppState>,
    _: Admin,
    Json(config): Json<CloudflareConfig>,
) -> Json<CloudflareConfig> {
    *state.cloudflare.lock().unwrap() = config.clone();
    state.auth.set_cloudflare(Some(config.clone()));
    Json(config)
}

/// `GET /api/example/ws`: the app's musli-web socket, which lives as long
/// as the session.
///
/// The upgrade needs a session, so the route extracts [`SignedIn`] as any
/// other route does, and watchword's [`Connection`] is made from it here.
/// The socket then carries:
///
/// - the app's own requests (`api::Request`), answered by [`Handler`];
/// - watchword's account and admin requests: [`Handler`] hands every id the
///   app's API does not know to [`Connection::handle`], which answers those
///   in watchword's band (32000–32255);
/// - watchword's `AuthBroadcast`: each `AuthEvent` goes through
///   [`Connection::update`], which passes on what this socket's user may see.
///
/// It closes when the session ends ([`Auth::guard`]), after which the
/// frontend calls `check_session()` and shows the sign-in page.
async fn ws(State(state): State<AppState>, user: SignedIn, upgrade: WebSocketUpgrade) -> Response {
    let conn = Connection::new(state.auth.clone(), &user);
    upgrade.on_upgrade(move |socket| session_socket(state, user, conn, socket))
}

async fn session_socket(state: AppState, user: SignedIn, conn: Connection, socket: WebSocket) {
    let guard = state.auth.guard(&user.user, &user.session);
    let mut events = state.auth.events();

    let handler = Handler {
        state: state.clone(),
        conn: conn.clone(),
    };

    // Nothing can be sent before the client has negotiated a format.
    let mut server = match musli_web::axum08::server(socket, handler).connect().await {
        Ok(server) => server,
        Err(error) => {
            tracing::debug!("Socket negotiation failed: {error}");
            return;
        }
    };

    state.sockets.fetch_add(1, Ordering::Relaxed);

    loop {
        tokio::select! {
            // Dropping the server closes the socket.
            _ = guard.ended() => break,
            event = events.recv() => {
                let update = match event {
                    Ok(event) => conn.update(&event).await,
                    // Events were missed: the page fetches again what it
                    // shows, and the guard re-checks the session itself.
                    Err(RecvError::Lagged(..)) => conn.lagged().await,
                    Err(RecvError::Closed) => break,
                };

                let update = match update {
                    Ok(update) => update,
                    Err(error) => {
                        tracing::warn!("Filtering an auth event failed: {error}");
                        continue;
                    }
                };

                if let Some(update) = update
                    && let Err(error) = server.broadcast(update)
                {
                    tracing::warn!("Broadcasting an auth update failed: {error}");
                    break;
                }
            }
            result = server.run() => {
                if let Err(error) = result {
                    tracing::debug!("Socket closed: {error}");
                }

                break;
            }
        }
    }

    state.sockets.fetch_sub(1, Ordering::Relaxed);
}

/// Answers the socket's requests: the app's own, and watchword's through
/// [`Connection::handle`].
#[derive(Clone)]
struct Handler {
    state: AppState,
    conn: Connection,
}

impl ws::Handler for Handler {
    type Id = api::Request;
    type Response = auth::core::Result<bool>;

    async fn handle(
        &self,
        id: api::Request,
        incoming: &mut ws::Incoming<'_>,
        outgoing: &mut ws::Outgoing<'_>,
    ) -> Self::Response {
        match id {
            api::Request::Status => {
                let Some(api::StatusRequest) = incoming.read() else {
                    return Ok(false);
                };

                // The app's own requests are gated as watchword's are: the
                // session is read again, so one that has ended since the
                // upgrade is refused (`conn.require_admin()` for an admin-only
                // request). A refusal is `Error::Auth`, which musli-web sends
                // as the request's error; the guard closes the socket next.
                self.conn.signed_in().await?;

                outgoing.write(api::StatusResponse {
                    uptime: self.state.started.elapsed().as_secs(),
                    sockets: self.state.sockets.load(Ordering::Relaxed),
                });

                Ok(true)
            }
            // Every id the app's API does not know: watchword answers its
            // own and returns `Ok(false)` for the rest, which musli-web
            // reports to the client as an unknown request.
            api::Request::Unknown(id) => self.conn.handle(id, incoming, outgoing).await,
        }
    }
}
