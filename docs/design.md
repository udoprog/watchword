# watchword design

watchword carries the authentication of an axum + Yew application across every
layer: the sign-in methods themselves (Cloudflare Access, Google OAuth, and
simple login/email + password with invite links and a bootstrap admin), session
and token handling, storage, the HTTP routes and extractors, WebSocket session
auth, the wire types, and the Yew pages and components. An app supplies its
storage, its styling and its own routes; it should not have to implement any
part of signing in or managing users itself.

This document records:

1. the layout of the crates and the cargo features that select each layer;
2. the API of each layer;
3. the decisions behind the API's shape, and their reasons.

The crate docs (`src/lib.rs`, each module's docs and the items' own docs) are
authoritative for the details; this document explains why the API is shaped as
it is.

## 1. Layout and features

### 1.1 Crates

The repository is a workspace of three crates, versioned and released in
lockstep, each pinning the others with an exact `=` version (as musli-web pins
musli-web-macros):

- **watchword-core**: the types of section 2.1 (`UserId`, `Role`, `Access`,
  `Method`, the wire types, `AuthError`, `validate_password`,
  `normalize_email`). Safe for wasm32, and `no_std`: with neither `std` (on
  by default) nor `alloc` it has only the plain types (`UserId`, `Role`,
  `Access`, `Method`, `Conflict`, `AuthConfig`, `MIN_PASSWORD_LEN`), and
  `alloc` adds those holding strings. Its `musli01` feature adds musli's
  derives, its `musliweb04` feature the musli-web API types of 2.7, and its
  `axum08` feature `IntoResponse` for `AuthError`, and its `sqll014` feature
  sqll 0.14's `BindValue`, `Bind` and `FromColumn` for `UserId`, `Role`,
  `Access` and `Method` (Rust's orphan rule keeps these impls in the crate
  defining the types). Neither `axum08` nor `sqll014` is for wasm32.
- **watchword-yew023**: everything for yew 0.23 (components, context,
  `use_auth`, the HTTP client and browser helpers). It depends on yew under the
  key `yew`, because yew's macros (`html!`, `#[function_component]`,
  `#[derive(Properties)]`, `#[hook]`) expand to `::yew::` paths, and on
  watchword-core rather than watchword. yew needs the standard library, so
  everything in it is behind its `std` feature (on by default).
- **watchword**: everything else, behind features. It re-exports watchword-core
  as `watchword::types` and at its root, and watchword-yew023 as
  `watchword::yew023` behind the `yew023` feature, so a frontend needs only
  `watchword = { features = ["yew023"] }`.

A single crate with disjoint features was the first layout. It stopped working
once yew was versioned (1.2): yew's macros hardcode `::yew::` paths, so yew code
can only live in a crate whose own dependency key is `yew`. A later yew is
another crate, `watchword-yew024`, beside the first. The cost is three
manifests released in lockstep.

The server-only dependencies (bcrypt, aws-lc-rs, tokio, axum, reqwest, sqll) and
the browser-only ones (yew, gloo-net, web-sys) sit behind disjoint features, so
trunk's wasm build of a frontend crate is free of server code. Apps commonly
compile their frontend crate on the host too, under `cargo clippy
--workspace`, so a host build with both feature sets enabled at once must also
compile; CI covers that with `--all-features`.

### 1.2 Versioned dependencies

yew, axum, sqll and musli are not 1.0 and change a lot between releases.
Everything tied to one version of such a crate that appears in watchword's
public API goes under a feature named after its version (`yew023` for yew
0.23), with the dependency key and module named the same way, so watchword can
support several versions side by side and an app upgrades when it chooses. A
dependency used only internally stays unversioned, since it can be upgraded
without breaking anyone. Version-specific items live only under their
versioned module and are not re-exported at the root, so the root never
changes meaning when the lead version moves. Doc examples for apps write
`# extern crate axum08 as axum;` to keep the app's idiomatic `axum::` paths.

Two things follow from the rule:

- `Auth::guard` is in `core` and takes the store's `User` and `Session`, not
  axum's `SignedIn`, so a later `axum09` can use it too.
- `cloudflare::HttpKeyFetcher::new(reqwest::Client)` is crate-private, keeping
  reqwest out of the API; apps use `HttpKeyFetcher::default()`.

jiff 0.2 is in the API through the types' `Timestamp` fields and is not
versioned: that would mean restructuring the types.

phrasebook 0.1 is in the API through `L10N`, a `phrasebook::Catalog`, and the
`Phrases` context the components read, so its dependency key, feature and
module are `phrasebook01`. The catalog (`L10N` and `locales/en-US.ftl`) lives
in watchword-core as `watchword_core::phrasebook01::L10N`, behind its
`phrasebook01` feature, so a native tool that needs only the messages (army's
`check-l10n`, which checks an app's `.ftl` against the ids of the catalogs it
takes) gets them without building yew, gloo-net, web-sys and
wasm-bindgen-futures. A feature on watchword-core rather than a
`watchword-l10n` crate: the catalog is a static and a `.ftl` file with no
dependency but phrasebook, core is already released in lockstep and taken by
every frontend, and a fourth crate would add a lockstep release and a docs.rs
page for one item. The feature implies `std`, since phrasebook 0.1 has no
`no_std` support (no `std`/`alloc` features of its own). watchword's
`phrasebook01` feature re-exports the module as `watchword::phrasebook01`;
`yew023` implies it. In watchword-yew023 phrasebook is not optional (every
component's text goes through it), so it turns on `watchword-core/phrasebook01`
with its `std` feature and re-exports `L10N` at its root, where it has always
been: a later phrasebook would come with a yew of its own, hence with a new
`watchword-yew0NN` crate anyway, while watchword-core would add a
`phrasebook0N` module beside this one.

### 1.3 Features

Only `std` is on by default. All three crates are `no_std` with the usual
`std` and `alloc` features, so a crate that takes watchword with
`default-features = false` names `std` or `alloc`; adding them later would
have broken every such crate. `std` implies `alloc`, and each forwards to the
dependencies that have the same feature. The server layers run on tokio and
axum and imply `std`; there is no `no_std` story for them. jiff is taken
without its default features, so the time zone databases it does not need for
`Timestamp` stay out of every frontend.

| Feature | Enables | Pulls in |
|---|---|---|
| *(none)* | `types` (watchword-core): `UserId`, `Role`, `Access`, `Method`, `Conflict`, `AuthConfig`, `MIN_PASSWORD_LEN` | serde, jiff (no time zones), thiserror, all without default features |
| `alloc` | the rest of `types`: the wire types, `AuthError`, `validate_password`, `normalize_email` | their `alloc` |
| `std` *(default)* | `alloc`, and std for the dependencies (and watchword-yew023) | their `std` |
| `musli01` | `Encode`/`Decode` on the types, so an app can embed them in its own WebSocket messages | musli-core 0.1 |
| `server` | `std` + `core` (hashing, ids, cookies, the `Auth` service, throttle, events, bootstrap, `SessionGuard`) and `store` (`Store`, `MemoryStore`) | base64, bcrypt, cookie, hmac, http, rand, sha2, tokio (rt, sync, time), tracing |
| `cloudflare` | `server` + the Cloudflare Access provider | aws-lc-rs, reqwest, serde_json |
| `google` | `server` + the Google OAuth provider (`GoogleConfig`) | reqwest, serde_json, url, lru |
| `axum08` | `server` + extractors and `routes()` for axum 0.8 | axum 0.8 |
| `sqll014` | `server` + `SqllStore`, a `Store` over SQLite on a sqll 0.14 pool, its `SCHEMA`, `MIGRATIONS` and `check_schema`, and watchword-core's `sqll014`: the sqll column traits on `UserId` (an integer with the same bits), `Role`, `Access` and `Method` (their names) | sqll 0.14 (`derive`, `pool`, `typed`, `threadsafe`; no default features, the app picks `bundled`) |
| `phrasebook01` | `std` + `watchword::phrasebook01` (watchword-core's): `L10N`, the components' messages as a phrasebook catalog, without yew, for native tools such as an l10n checker | phrasebook 0.1 (no features) |
| `yew023` | `std` + `phrasebook01` + watchword-yew023: components, context, hook, HTTP client, and `L10N` re-exported | yew 0.23, gloo-net, web-sys, wasm-bindgen-futures, phrasebook 0.1 (`yew023`) |
| `test-util` | `server` + for apps' tests: `Auth::test_user` and `Auth::test_session` (2.2), the store conformance suite as `store_suite!` (2.3); with `google` also `AuthBuilder::google_endpoints`, and with `google` and `axum08` `google::fake::FakeGoogle` (2.4) | nothing more |
| `musliweb04` *(2.7)* | `alloc` + `musli01` + `watchword::musliweb04`: the auth endpoints and broadcast as musli-web 0.4 API types; with `axum08` also `musliweb04::Connection`, the server handler; with `yew023` `AuthContext::set_socket`, through which the components follow the broadcasts and send their requests over the socket | musli-web 0.4 (`api`; `ws` with `axum08`; `web03` with `yew023`) |

The modules are `watchword::{types, core, store, cloudflare, google, axum08,
sqll014, musliweb04, phrasebook01, yew023}`, and the most-used names that need no versioned feature are
re-exported at the root.

## 2. API

### 2.1 Types (always available)

```rust
pub struct UserId(pub u64);              // new/get (const), From u64 both ways, TryFrom i64 both ways (checked)
pub enum Role { Admin, Regular }         // serde lowercase
pub enum Access { Pending, Active, Revoked }
pub enum Method { Password, Google }     // the user's stored credential; see decision 4

/// What the frontend and the admin pages see of a user.
pub struct UserInfo {
    pub id: UserId,
    pub login: Option<String>,
    pub email: Option<String>,
    pub role: Role,
    pub access: Access,
    pub method: Method,
    pub has_password: bool,
    pub created_at: Timestamp,
    /// The admin acting as this user, on the answers about the request's own
    /// user (`me`, impersonate, account routes); see decision 12.
    pub impersonated_by: Option<Impersonator>,   // omitted from JSON when None
}
impl UserInfo { pub fn name(&self) -> &str; pub fn is_admin(&self) -> bool; }

/// The admin behind an impersonated session.
pub struct Impersonator { pub id: UserId, pub name: String }

/// A user in the admin list.
pub struct UserEntry { pub user: UserInfo, pub link_expires_at: Option<Timestamp> }

/// A newly created user and their registration link, shown once.
pub struct CreatedUser { pub entry: UserEntry, pub link: Link }

/// What the sign-in page offers, from `GET /api/auth/config`.
pub struct AuthConfig {
    pub password: bool,
    pub google: bool,
    pub cloudflare: bool,     // this request carries Access credentials that map to a user
    pub logins: bool,         // the app uses login names, or only emails
}

pub struct LoginRequest { pub login: String, pub password: String }
pub struct RegisterInfo { pub login: Option<String>, pub email: Option<String>, pub google: bool }
pub struct RegisterRequest { pub password: String }
pub struct Link { pub token: String, pub expires_at: Timestamp }   // shown once
Link::path() -> String                     // `/register/{token}`, the frontend's route
Link::url(public_url: Option<&str>) -> String  // a full URL under the app's public URL, else the path
pub struct NewUser { pub login: Option<String>, pub email: Option<String>, pub role: Role }
pub struct UserChange { pub login: Option<Option<String>>, pub email: Option<Option<String>>, pub role: Option<Role> }
pub struct PasswordChange { pub old_password: Option<String>, pub new_password: String }
pub struct CloudflareConfig { pub enabled: bool, pub team_domain: String, pub audience: String,
                              pub trust_email_header: bool, pub verify_jwt: bool }
                              // Default: disabled, header untrusted, verify_jwt on
pub enum AuthError { Unauthorized, Forbidden, NotFound, Gone, TooManyRequests,
                     Conflict(Conflict), Invalid(Invalid) }   // JSON body of 4xx responses
pub enum Conflict { Login, Email }
#[non_exhaustive]
pub enum Invalid { PasswordTooShort { min: usize }, PasswordIncorrect, EmailRequired,
                   LoginOrEmailRequired, LoginEmpty, LoginsDisabled, EmailManagedByGoogle,
                   GoogleAccountTaken, RoleNotChangeable, MalformedRequest,
                   Unknown }   // a newer server's reason; new reasons go after it
```

An error is sent as `{"error":"<code>"}`, with a `detail` for the two that
carry one: `{"error":"conflict","detail":"email"}` and, for an invalid
request, its reason as a stable code with its parameters, such as
`{"error":"invalid","detail":{"reason":"password_too_short","min":8}}`. No
English goes on the wire: `Display` on `AuthError` and `Invalid` gives an
English message, and a frontend may phrase the code in its own language
instead. `Invalid` is `#[non_exhaustive]`, so a reason can be added without a
breaking release. `validate_password` returns the `Invalid` reason, so the
frontend checks a password the same way the server does.

A frontend older than its server (a page loaded before a deploy) meets reasons
it does not know. Those decode as `Invalid::Unknown`, dropping their
parameters, and the components say "The request is invalid." (decision 22):
over JSON through `#[serde(other)]`, and over musli through
`#[musli(default)]` in the formats that can skip a value, `wire` (musli-web's
default) and `descriptive`. `storage` and `packed` cannot skip an unknown
value, so with those both ends need the same version anyway. A server never
sends `Unknown`. musli numbers variants by position, so a new reason goes at
the end, after `Unknown`.

### 2.2 Server core (`server`)

The primitives:

- `hash_password`, `verify_password` and `dummy_hash` hash and check passwords
  (bcrypt at the default cost).
- `new_session_id` and `new_token` make ids (16 random bytes, base64url).
- `generate_session_key`, `session_cookie` and `verify_session_cookie` make the
  key and build and check the cookie, whose value is
  `{id}.{b64url(HMAC-SHA256(key, id))}`.
- `SESSION_LIFETIME` (30 days, fixed) and `TOKEN_LIFETIME` (7 days) set the
  lifetimes; `session_expiry`, `token_expiry` and `is_expired` apply them.

On top of them is the service, `Auth`, which is `Clone` and is a single `Arc`
inside:

```rust
let auth = Auth::builder_from_store(store).await? // key from the store's `session_key` setting
    .cookie(CookieConfig::new("app_session"))   // default name `session`, `Secure::Auto`
    .logins(true)                               // accept login names, not only emails
    .trusted_proxies(&trusted_proxies)
    .cloudflare(cloudflare_config)              // feature `cloudflare`; Option, used while the store has none
    .google(google_config)                      // feature `google`; Option
    .impersonation(true)
    .prune_every(Some(Duration::from_secs(3600)))  // run `prune` now and hourly; default None
    .audit(|event: &AuditEvent| { /* send to the app's audit log */ })  // repeatable
    .build();

auth.cloudflare().await?;                      // -> Option<CloudflareConfig>, as stored or else as built
auth.set_cloudflare(&admin, &session, config).await?;  // -> CloudflareConfig as stored; admin; stores and applies
auth.bootstrap_admin(&BootstrapAdmin::new(name).public_url(public_url)).await?;  // -> Bootstrap
auth.recovery_link(name).await?;                // -> Link, for the app's own CLI; no actor
auth.import_user(&new_user).await?;             // -> User, pending, no link; for imports; no actor
auth.find_user(name).await?;                    // -> Option<User>, by login, then email
auth.events() -> broadcast::Receiver<AuthEvent>;
auth.prune().await?;                            // delete expired sessions and long-expired links
```

`builder_from_store(store)` is `Auth::builder` with the key
`load_or_create_key(&store)` returns, for apps that keep the key in their
store; `Auth::builder` takes a key from elsewhere. `load_or_create_key` reads
the key as standard base64 or unpadded base64url, so keys stored by an app's
earlier implementation keep their sessions valid; a new key is stored as
standard base64. `BootstrapAdmin::new` takes an email if the name contains
`@`, otherwise a login, as for a `--bootstrap-admin` option;
`BootstrapAdmin::email` and `::login` say which explicitly.

```rust
/// What `bootstrap_admin` did (decision 6).
pub enum Bootstrap {
    Created(Link),                       // no users: the admin, pending, and their registration link
    Reissued(Link),                      // still pending, no active admin, link expired: a new one
    Pending { expires_at: Timestamp },   // still pending, and the earlier link is live
    Skipped,                             // anything else: nothing changed
}
Bootstrap::link() -> Option<&Link>       // the link issued this time
```

`bootstrap_admin` logs the outcome at `info`, the link as `Link::url` under
`BootstrapAdmin::public_url`. An app whose log the operator may not see prints
the link itself from `Bootstrap::link`, as the example app does; the token is
never shown again, so `Pending` carries only the expiry.

`recovery_link(name)` issues a link to the user named by `name` (a login, or
else an email; `AuthError::NotFound` otherwise), as `issue_link` does but with
no actor: a reset link for an active user, a registration link otherwise. It
is for an app's own command line, such as `track issue-link <login>`, to let in
a user no admin can act for (a locked-out last admin, say), and must never be
reachable from a request.

`import_user(&new)` creates a pending user without issuing a link, for an
app's own import or backup-restore tool: it validates and normalizes `new`
as `create_user` does (login trimmed, email normalized, the identity rules of
section 3, `Conflict` when either is taken) and sends `UserCreated`, but has
no actor, so like `recovery_link` it must never be reachable from a request.
The user gets a link later, from `issue_link` or `recovery_link`.
`find_user(name)` finds a user as password sign-in does: by trimmed login
first when logins are used, then by normalized email; `None` for a blank
name. It checks no actor.

An offline tool (an import, a restore, a recovery command) uses `Auth`
rather than the `Store` directly, so it applies the same rules and keeps the
same key: it opens the app's store, builds with `builder_from_store`, calls
these operations, and exits. Events it sends reach nobody, since no server
shares its `Auth`; a running server reads the new users from the store.

The operations behind the routes are public methods too, so an app can call
them from its own handlers or tests: `sign_in_password`, `sign_in_cloudflare`,
`sign_out`, `register_info`, `register`, `change_password`, `users`,
`create_user`, `issue_link`, `revoke_link`, `sign_out_everywhere`,
`revoke_access`, `set_role`, `update_user`, `delete_user`, `impersonate` and
`stop_impersonating`. Those that change something on a signed-in user's
behalf take the actor and the session they signed in with
(`create_user(&admin, &session, &new)`, `set_role(&admin, &session, id,
role)`, and so on; `change_password` and `impersonate` already did), so their
audit events name an admin impersonating the actor; `users` only reads, and
takes the actor alone. Each one enforces the rules of section 3: who may act on
whom, never on oneself, token usability, and ending sessions. An admin
operation needs an *active* admin as its actor: a pending admin, who has not
registered, and a revoked one are refused with `Forbidden`. Around them,
`session(id)` loads a live session and its user, `session_info(&user,
&session)` gives the `UserInfo` of the request's own user, marked when
impersonated, `cloudflare_available(&headers)` answers `AuthConfig::cloudflare`,
and `session_id`, `set_cookie`, `clear_cookie` and `client_address` read and
write the cookie and the client's address for a framework integration.
`cookie_header(session_id)` is the request's `Cookie` header for a session
(`set_cookie`'s `name=value` pair without its attributes), for a test or a
client making requests as that session, so none splits a `Set-Cookie` by hand.

For an app's tests, the `test-util` feature adds two helpers that skip the
sign-in routes. `test_user(&new, password)` creates an active user with that
password, as `import_user` followed by setting the password does (the same
checks, events and audit events, with no actor), hashed at bcrypt's lowest
cost so that signing in with it is quick and short test passwords are
accepted. `test_session(&user)` creates and stores an ordinary session for the
user, to pass as the actor's session or to send with `cookie_header`; it is
created whatever the user's access, and `session` and the extractors judge it
like any other. Neither may be reachable from a request.

Operations fail with `core::Error`: either an `AuthError` to answer the request
with (`Error::auth_error`), or an internal failure (store, hashing, a blocking
task). An internal failure's message carries its cause (`storage failed:
database is locked`), so a log line with `{error}` says what failed, and its
`source` continues below that cause, so a chain printer does not repeat it. The
message is for logs only: the HTTP integration answers `internal error`, and
the socket's `RequestError` does too. An app that has carried the error into
its own type through `?` (an `anyhow::Error`, say) classifies it with
`Error::find_auth_error(&*error)`, which looks through the source chain for an
`AuthError`, bare or as `Error::Auth`; downcasting to `AuthError` alone misses
the wrapped one and turns a refusal into an internal failure.

```rust
/// Sent whenever auth state changes, for open sockets and live admin views.
pub enum AuthEvent {
    SessionEnded(String),                                         // signed out
    UserSessionsEnded { user: UserId, keep: Option<String> },     // sign out everywhere, revoke, delete, credential change
    UserChanged(UserInfo),                                        // role, email, login, access, credential
    UserCreated(UserInfo),
    UserDeleted(UserId),
}
```

`AuthEvent`s say what state changed, for sockets that follow it. For an
app's audit log, `AuthBuilder::audit` hooks receive an `AuditEvent` per
operation instead, saying who acted on whom (decision 25):

```rust
pub enum Actor {                          // #[non_exhaustive]
    User { user: UserId, impersonator: Option<UserId> },   // Actor::of(&user, &session)
    System,                               // bootstrap, recovery_link, import_user, Cloudflare activation
}
Actor::responsible() -> Option<UserId>    // the impersonator if any, else the user

pub enum AuditEvent {                     // #[non_exhaustive]; sent after the change is stored
    UserCreated { actor, user: UserInfo },                  // create_user, bootstrap_admin, import_user
    UserUpdated { actor, before: UserInfo, after: UserInfo }, // update_user, set_role; not when unchanged
    AccessRevoked { actor, before: UserInfo, after: UserInfo },
    Activated { actor, user: UserInfo },                    // Cloudflare Access activated a pending user
    UserDeleted { actor, user: UserInfo },                  // as they were
    SignedOutEverywhere { actor, user: UserId },
    LinkIssued { actor, user: UserId, expires_at: Timestamp }, // also by create_user, bootstrap, recovery
    LinkRevoked { actor, user: UserId },
    LinkRedeemed { actor, user: UserInfo },                 // registered or reset with a link
    CredentialChanged { actor, user: UserInfo },            // change_password, switch to Google
    ImpersonationStarted { admin: UserId, user: UserId },
    ImpersonationStopped { admin: UserId, user: UserId },
    CloudflareChanged { actor, before: Option<CloudflareConfig>, after: CloudflareConfig }, // feature `cloudflare`; set_cloudflare, not when unchanged
}
AuditEvent::actor() -> Actor              // the admin, for impersonation
AuditEvent::user() -> Option<UserId>      // the user acted on; None for CloudflareChanged
```

Sign-ins, sign-outs and reads send none.

An impersonated session also ends with its admin's standing (decision 12): a
`UserChanged` of the admin that leaves them not an active admin, or their
`UserDeleted`, ends the sessions they impersonate in, with no event of its own.

The sign-in throttle limits failed password sign-ins per client address (30
per 15 minutes; IPv6 grouped by /64) and per login (10 per 15 minutes). The
client address comes from `CF-Connecting-IP` or `X-Forwarded-For` only when the
peer is a trusted proxy.

### 2.3 Storage (`server`)

There is one trait, because several operations must be atomic across users,
sessions and tokens. Its methods return `impl Future + Send`, and `Auth` erases
the store internally, so neither `Auth` nor the extractors carry a type
parameter. Every method takes the time from the caller, which keeps tests
deterministic. Emails reach the store already normalized and are compared
exactly. A store only keeps records and makes the documented multi-record
changes atomic; `Auth` enforces every rule.

```rust
pub trait Store: Send + Sync + 'static {
    // Users
    fn user(&self, id: UserId) -> impl Future<Output = Result<Option<User>>> + Send;
    fn user_by_email(&self, email: &str) -> ...;          // normalized
    fn user_by_login(&self, login: &str) -> ...;
    fn user_by_google_sub(&self, sub: &str) -> ...;
    fn users(&self, now: Timestamp) -> ...Vec<(User, Option<Timestamp>)>;  // with live link expiry
    fn user_count(&self) -> ...u64;
    fn create_user(&self, new: &NewUser, now: Timestamp) -> ...Result<User, Conflict>;  // pending, no credential
    fn update_user(&self, id: UserId, change: &UserChange) -> ...Result<Option<User>, Conflict>;
    /// Deletes the user with their sessions and tokens, and the sessions in
    /// which they impersonate someone.
    fn delete_user(&self, id: UserId) -> ...bool;
    /// Sets the credential (and the method to match), marks the user active,
    /// and deletes the user's sessions except `keep`. Refuses (false) a
    /// revoked user, so a concurrent revoke is not undone.
    fn set_credential(&self, id: UserId, cred: &Credential, keep: Option<&str>) -> ...bool;
    /// Binds a Google subject only if the user has none or the same one.
    fn bind_google_sub(&self, id: UserId, sub: &str) -> ...bool;
    fn set_access(&self, id: UserId, access: Access) -> ...bool;
    /// Pending -> active only, atomically; false when the user is not pending
    /// (such as one revoked since it was read). Every activation outside a
    /// link goes through this, never a read followed by `set_access`.
    fn activate(&self, id: UserId) -> ...bool;
    /// access=revoked, password cleared, unused tokens used up, sessions deleted.
    fn revoke(&self, id: UserId, now: Timestamp) -> ...bool;

    // Sessions
    fn create_session(&self, s: &Session) -> ...;            // may prune expired ones
    fn session(&self, id: &str) -> ...Option<Session>;       // expired or not
    fn delete_session(&self, id: &str) -> ...;
    fn delete_sessions(&self, user: UserId, keep: Option<&str>) -> ...;
    fn delete_expired_sessions(&self, now: Timestamp) -> ...;

    // Tokens
    /// Inserts the token and uses up the user's other unused ones.
    fn create_token(&self, t: &Token, now: Timestamp) -> ...;
    fn token(&self, id: &str) -> ...Option<Token>;           // used or not
    fn delete_expired_tokens(&self, before: Timestamp) -> ...;  // used or not
    fn use_up_tokens(&self, user: UserId, now: Timestamp) -> ...;
    /// In one transaction: marks the token used if it is still unused (else
    /// returns false), sets the credential as `set_credential` does, deletes
    /// all of the user's sessions and creates `session`.
    fn redeem_token(&self, token: &str, cred: &Credential, session: &Session, now: Timestamp) -> ...bool;

    // Settings
    fn config_get(&self, key: &str) -> ...Option<String>;    // session_key; cloudflare (JSON)
    fn config_set(&self, key: &str, value: &str) -> ...;
}

pub struct User { pub id: UserId, pub login: Option<String>, pub email: Option<String>, pub role: Role,
                  pub access: Access, pub method: Method, pub password_hash: Option<String>,
                  pub google_sub: Option<String>, pub created_at: Timestamp }
pub struct Session { pub id: String, pub user: UserId, pub impersonator: Option<UserId> /* the admin acting as `user` */,
                     pub created_at: Timestamp, pub expires_at: Timestamp }
pub struct Token { pub id: String, pub user: UserId, pub kind: TokenKind, pub expires_at: Timestamp, pub used_at: Option<Timestamp> }
pub enum TokenKind { Registration, Reset }
pub enum Credential { Password(String /* hash */), Google { sub: String, email: String } }
```

Store failures are a `StoreError`, which boxes any error.

The library ships `MemoryStore`, used by its own tests and the example app, and,
behind `sqll014`, `SqllStore`. The crate's store conformance suite, the
tests of `Auth`'s rules that depend on what a store keeps, runs against both.
With `test-util` it is public as `watchword::store_suite!(expr)`, which
defines one `#[test]` per test, each over a fresh store from `expr`
(evaluated in the test's async context, so it may `.await`) on a
current-thread tokio runtime of its own. An app runs it over its own `Store`,
or over `SqllStore` on its own migrated schema, instead of re-testing
watchword's sign-in and user-management behaviour; the functions it calls
are hidden, and new tests arrive in minor releases.

`SqllStore` works on a sqll `Pool`. It exports its statement collections,
`watchword::sqll014::Read` and `watchword::sqll014::Write`. An app nests these
in its own pool's collections with `#[sql(statements)]` and implements `AsMut`
to reach them, so auth shares the app's single write connection;
`SqllStore::new(pool)` then takes the app's `Arc<Pool<R, W>>`. A store over a
pool of its own is `SqllStore<Read, Write>`. The pool prepares its statements
when it opens, so the schema must be in place first. The schema:

| Table | Columns |
|---|---|
| `users` | `id` INTEGER PRIMARY KEY, `login` TEXT UNIQUE, `email` TEXT UNIQUE, `role` TEXT, `access` TEXT, `method` TEXT, `password_hash` TEXT, `google_sub` TEXT UNIQUE, `created_at` INTEGER ms |
| `sessions` | `id` TEXT PRIMARY KEY, `user_id` → users, `impersonator_id` → users (NULL unless impersonated), `created_at` and `expires_at` INTEGER ms |
| `auth_tokens` | `id` TEXT PRIMARY KEY, `user_id` → users, `kind` TEXT (`registration`/`reset`), `expires_at` and `used_at` INTEGER ms |
| `config` | `key` TEXT PRIMARY KEY, `value` TEXT |

`watchword::sqll014::SCHEMA` creates the tables in a new database. An app keeps
its own columns on `users` (with defaults, since the store inserts only its
own) and its own tables referencing `users (id)`; the store reads and writes
only its own columns. An app's SQL may read the store's columns (they change
only through a new migration), binding and reading `UserId`, `Role`, `Access`
and `Method` directly, but changes them only through the `Store`. The store deletes a user's sessions and links itself
rather than relying on `ON DELETE CASCADE`, since an app's connections may not
enable foreign keys.

The tables ship in two forms that end up the same, so apps stop copying SQL
out of watchword by hand:

- `watchword::sqll014::MIGRATIONS: &[(&str, &str)]`, ordered `(id, sql)`
  pairs: `watchword-0001-tables` (the tables as first released, frozen), then
  each change since (`watchword-0002-sessions-impersonator`, an `ALTER TABLE`
  adding `sessions.impersonator_id`). Ids are stable and prefixed so they sit
  in an app's own migrations table; a release only appends. This is the shape
  sqll's `Migrations` runner takes (on sqll main, after 0.14.7), so watchword
  exports plain data and depends on no runner: an app hands the pairs to a
  runner, or splices them into its own list, leaving out the ids its own
  migrations already did (a copied base schema did `watchword-0001-tables`).
  The SQL lives in `src/sqll014/migrations/`.
- `SCHEMA`, what all migrations add up to, for creating a new database in one
  step (a runner's fresh schema). Rerunning it changes nothing and adds no
  columns, so it does not upgrade. A test checks that `SCHEMA` and
  `MIGRATIONS` produce the same tables, indexes and foreign keys.

`watchword::sqll014::check_schema(&Connection)` checks that every table and
column the store uses exists, and fails with a `sqll014::Error` naming each
one missing and the migration that adds it, so an app run on a stale database
fails at startup (at the end of its pool's write setup) with a readable error
rather than when a statement fails to prepare. It checks names only, and
ignores the app's own tables and columns.

### 2.4 Sign-in methods

- **Password** (`server`). The user is found by login, then by normalized
  email; with `logins(false)`, by email only. An unknown user and a user without
  a password are verified against the dummy hash, in `spawn_blocking`, so every
  failure takes as long as checking a password. The throttle applies. Only
  active users get a session.
- **Cloudflare Access** (`cloudflare`). `cloudflare::Access` checks the Access
  JWT against the team's keys (with key caching and a rate-limited refetch), or
  trusts the email header when configured to. `Auth` keeps the settings
  itself, as JSON under the store's `cloudflare` setting: they are read once,
  when first needed (`Auth::cloudflare` reads them at startup if the app wants
  them logged then), and the builder's `cloudflare` settings apply while the
  store has none. A stored value missing a field takes `CloudflareConfig`'s
  default for it (`#[serde(default)]`), so it verifies the JWT; one that does
  not parse is logged as an error and the builder's apply, so a damaged value
  cannot break the sign-in page. An admin changes them at runtime
  (`set_cloudflare`, or the routes and socket endpoints below), which stores
  them with the team domain and audience trimmed and applies them at once. It
  logs changed settings with a warning when
  they are unsafe, and logs credentials that sign no one in at most once a
  minute. `presents_access` tells whether a request carries Access credentials
  at all. The verified email finds the user, and users are never created.
  Signing in mints an ordinary session through an explicit `POST`, so Access is
  consulted only when signing in. A *pending* user who signs in through Access
  becomes active, because Access has vouched for the email. A revoked user is
  refused.
- **Google OAuth** (`google`).
  - The authorization-code flow, with an in-memory pending-state LRU (10
    minutes, 10 000 entries).
  - The `tokeninfo` check, which requires `email_verified`.
  - Sign-in by `google_sub`, with a one-time email match for Google users who
    have no subject yet.
  - Registration through a link, and "switch to Google" from the account page.
  - One Google account binds only one user.

  The provider takes a `GoogleConfig { client_id, client_secret, redirect_url }`,
  built with `GoogleConfig::new(client_id, client_secret, public_url: &Url) ->
  Result<GoogleConfig, GoogleConfigError>`: it refuses an empty id or secret
  and a public URL that is not `http`/`https` or has a path, query or fragment,
  and derives `redirect_url` as `REDIRECT_PATH` under the public URL, so the
  path cannot be set wrong. The fields stay public for a callback reached some
  other way (a proxy stripping a prefix), where the provider only warns when
  the path is not `REDIRECT_PATH`.
  It is reached only through the routes (2.5); the callback redirects to the
  sign-in's `next` (below), or `/`, on success, or to `/?error=auth-failed`
  or `/?error=user-not-found` on failure, with `&next=` after it when the
  sign-in had one, so trying again still returns there.

  `GET /api/auth/google?next=…` takes the page to come back to. It is kept
  only when `watchword_core::is_same_origin_path` holds for it once decoded,
  the same rule watchword-yew023 follows a `next` by, and is remembered with
  the flow's state in memory (never in the redirect to Google). The callback
  takes the state before looking at Google's answer, so a denied or failed
  sign-in still knows its `next`. It is sent as a `Location` with only the
  bytes a URL cannot hold as they are (spaces, non-ASCII) percent-encoded,
  and never normalized, since resolving `/.//host` would give `//host`.

  Google's endpoints are `google::Endpoints` (`auth`, `token`, `tokeninfo`),
  whose `Default` is Google's own; production always uses it. For an app to
  test a Google sign-in, registration through a link, or switching to Google
  without the network, `test-util` with `google` adds
  `AuthBuilder::google_endpoints(Endpoints)`, and with `axum08` also
  `google::fake::FakeGoogle`: a local server on `127.0.0.1:0` serving the
  token and tokeninfo endpoints for one `GoogleConfig`. The test plays the
  browser: `FakeGoogle::approve(auth_url, FakeAccount::new(sub, email))`
  checks the authorization URL the app redirected to and returns the callback
  URL with a fresh code and the flow's state, `deny` returns one with
  `error=access_denied`, `code(account)` mints a bare code, and
  `FakeAccount::unverified` clears `email_verified`. Like Google, the fake
  checks the client id, secret and redirect URL of each exchange, and a code
  and its access token work once. The crate's own Google route tests use it.

### 2.5 axum integration (`axum08`)

```rust
// Extractors; each needs `Auth: FromRef<S>`.
SignedIn { user: User, session: Session }   // 401 without a live session of an active (or impersonated pending) user; an impersonated one only while its admin is an active admin
Admin(SignedIn)                             // 403 unless the user is an active admin *now*
MaybeSignedIn(Option<SignedIn>)
LiveSession(String)                         // the session id; liveness only, cached for 10 s, for hot asset routes

// Routes, merged into the app's router.
pub fn routes<S>() -> Router<S> where Auth: FromRef<S>, S: Clone + Send + Sync + 'static;

// Gating a whole site, pages included.
pub fn is_public(path: &str) -> bool;       // `/api/auth/…` and `/register/…`
let gate = RequireSession::new(auth.clone(), "/login")
    .public(|path| path.starts_with("/assets/"));   // the app's own public paths
router.layer(axum::middleware::from_fn_with_state(gate, require_session));

// WebSocket: resolves when the socket's session has ended, for the app's select! loop.
// In `core` (feature `server`): it takes the user and session, not an axum type.
let guard = auth.guard(&signed_in.user, &signed_in.session);
tokio::select! {
    _ = guard.ended() => break,              // sign out, revoke, credential change, delete, expiry; the impersonating admin revoked, demoted or deleted
    info = guard.changed() => { /* UserInfo: role/email changed, e.g. reload the app's per-user data */ }
    ...
}
guard.user()         // UserInfo as last seen, no store read
guard.watch_user()   // tokio watch::Receiver<UserInfo> of the same, cloneable, for the app's request handler
```

`SignedIn` and `Admin` read the user from the store on every request, so a role
change or revocation applies to the next one. `LiveSession` believes a session
confirmed live for 10 seconds, for up to 1024 sessions; signing out, revoking or
deleting through `Auth` ends it there at once, so the 10 seconds only delay
noticing a session ended in another process.

Each of these, and `require_session`, loads the session once per request and
leaves the `SignedIn` in the request's extensions, where the others (and an
`Extension<SignedIn>`) find it.

`require_session` lets through watchword's public paths, the sign-in path and
the app's own (`public`), and any request with a live session. Otherwise a
page load (`GET`/`HEAD` outside `/api/` accepting `text/html`) is redirected
(303) to `{sign_in_path}?next={path and query}`, `next` omitted for `/`, and
anything else gets 401 (a store failure 500). An `error=` in the requested
query moves to the sign-in URL's own query, so the Google callback's
`/?error=…` still reaches the sign-in page; so does the `next` of a `/`
whose query is otherwise only that `error`, the shape of a failed Google
sign-in's redirect, instead of being nested in a `next` of its own. It is a plain `from_fn`
middleware with its state rather than a `Layer` of its own, since naming a
layer type would add `tower-layer` and `tower-service` to the public API.
Decision 24.

The guard (`core::SessionGuard`) subscribes to `AuthEvent`s and sleeps until the
session expires. On broadcast lag, and every 5 minutes, it re-checks the
session in the store, so a session deleted by another process still ends the
socket. A guard on an impersonated session also follows its admin's
`UserChanged` and `UserDeleted`, so revoking, demoting or deleting the admin
ends it at once.

The guard keeps the user as last seen (`SessionGuard::user`, and
`watch_user` for a cloneable `watch::Receiver<UserInfo>`), so a socket can
gate its own requests on the role without a store lookup per request or per
broadcast. It is current as of the last event or re-check, so a change made
in another process may reach it up to 5 minutes late; a check that must not
let a stale role through reads the store instead (`Auth::session`, or
`Connection::require_admin` in 2.7). For an impersonated session it is the
impersonated user, without the `impersonated_by` marker. Decision 23.

The routes are all JSON. Their errors are `AuthError` with the matching status:
401, 403, 404, 409, 410, 429, or 400 with an `Invalid` reason. A malformed
JSON body is `Invalid::MalformedRequest`; why it was rejected is logged at
debug level, not sent. `POST /api/auth/login` throttles by the client's address, so
the app is served with `into_make_service_with_connect_info::<SocketAddr>()`.

| Route | Who | What |
|---|---|---|
| `GET /api/auth/config` | anyone | `AuthConfig` |
| `GET /api/auth/me` | signed in | `UserInfo`, with `impersonated_by` when an admin is acting as the user |
| `POST /api/auth/login` | anyone | `LoginRequest` → `UserInfo` + cookie; throttled |
| `POST /api/auth/cloudflare` | anyone, feature `cloudflare` | → `UserInfo` + cookie; activates a pending user |
| `GET /api/auth/cloudflare` | admin, feature `cloudflare` | `CloudflareConfig` as stored, or its default when there is none |
| `PUT /api/auth/cloudflare` | admin, feature `cloudflare` | `CloudflareConfig` → `CloudflareConfig` as stored; applies it |
| `GET /api/auth/google`, `/google/register/{token}`, `/google/link` | anyone / anyone / signed in | redirect to Google; the first takes `?next=`, a same-origin path to come back to; 404 unless Google is configured |
| `GET /api/auth/google/redirect` (`watchword::google::REDIRECT_PATH`; `redirect_url` must use this path, a different one is logged as a warning) | Google | callback; cookie + redirect to the sign-in's `next` or `/`, or `/?error=user-not-found` / `/?error=auth-failed` (`&next=` kept) |
| `POST /api/auth/logout` | anyone | 204, deletes the session, clears the cookie |
| `GET /api/auth/register/{token}` | anyone | `RegisterInfo`; 404 unknown, 410 used or expired |
| `POST /api/auth/register/{token}` | anyone | `RegisterRequest` → `UserInfo` + cookie; ends the user's other sessions |
| `POST /api/auth/account/password` | signed in | `PasswordChange` → `UserInfo`; keeps this session, ends the others; switches a Google user to password |
| `PATCH /api/auth/account` | signed in | `UserChange` (own login/email; not role; not email of a Google user) → `UserInfo` |
| `GET /api/auth/users` | admin | `Vec<UserEntry>` |
| `POST /api/auth/users` | admin | `NewUser` → `CreatedUser` |
| `PATCH /api/auth/users/{id}` | admin | `UserChange` → `UserInfo` (not own role) |
| `DELETE /api/auth/users/{id}` | admin | 204; not self |
| `POST`/`DELETE /api/auth/users/{id}/link` | admin | issue (`Link`) / use up the links (204) |
| `POST /api/auth/users/{id}/sign-out` | admin | 204; sign out everywhere |
| `POST /api/auth/users/{id}/revoke` | admin | `UserInfo`; revoke access; not self |
| `POST /api/auth/users/{id}/impersonate` | admin, if enabled | `UserInfo` (with `impersonated_by`) + cookie for a session as that user that records the admin; not self, not revoked, not from an impersonated session |
| `POST /api/auth/impersonate/stop` | signed in, impersonated | `UserInfo` + cookie for a new session as the admin, ending the impersonated one; 403 unless the session is impersonated (401 once its admin is no longer an active admin, which ends it; 403 if that happens while the request runs) |

`{id}` is the decimal `UserId`. Registration and reset links point at the
frontend route `/register/{token}`, which `<AuthProvider>` serves.

### 2.6 Yew components (`yew023`)

The components render plain semantic HTML with stable `auth-*` class names and
take a `class` prop. Each app styles them with its own CSS.

Their text goes through phrasebook (decision 21). Every string, including the
messages for errors and `Invalid` reasons (phrased from their codes, not from
`Display`), is a message in `crates/watchword-core/locales/en-US.ftl` under
the `watchword-` prefix, shipped as `pub static L10N: phrasebook::Catalog` in
watchword-core's `phrasebook01` module (see 1.2) and re-exported here.
Each function component reads `or_catalog(use_context::<Phrases>(), &L10N)`;
the struct components (`AuthProvider`, `AdminUsers`) subscribe to the same
context and keep the handle. So without a provider, or with an app phrasebook
that never added `L10N`, they render watchword's English, and an app
translates them by adding `watchword-*` ids to its own catalog, which it adds
before `L10N` so its messages win. Arguments are placed by the message
(`Delete { $name }?`), and where the components style an argument (the name in
`<strong>`, the host in `<code>`), they wrap whatever the translation puts in
its place. Tests run `phrasebook::check::catalog` on `L10N` and check that the
ids the code names and the ids the catalog defines are the same set. They talk to the
server through `watchword::yew023::http`, which uses gloo-net with same-origin
cookies, so the library does not depend on the app's gloo version.

- `<AuthProvider>` is the gate.
  - It fetches `/api/auth/config` and `/api/auth/me`.
  - It shows a splash with Retry while loading or when the server is
    unreachable.
  - It shows `<SignIn>` when signed out, and `<Register>` on `/register/{token}`.
    Otherwise it renders its children with an `AuthContext`.
  - Props: `title` (the app's name), `signed_out_notice`, which overrides
    the "session has ended" message `watchword-session-ended`, and
    `sign_in_path`, the page `RequireSession` redirects to.
  - Signing in returns to the URL's `?next=` before the children render,
    so the app's router starts there. Only a same-origin path is followed:
    it must start with a single `/` and hold no `\` or control character
    once decoded (no `//host`, `/\host`, `/<tab>/host` or scheme); any other
    `next` is dropped. On `sign_in_path` a signed-in user goes to `next` or
    `/`, also when already signed in on load. The rule is
    `watchword_core::is_same_origin_path`, which the server's Google sign-in
    shares. "Sign in with Google" leaves the page with `?next=` set to the
    URL's usable `next`, or else to the page itself (none on `/`), and comes
    back there.
- `use_auth() -> AuthContext` gives `user: Rc<UserInfo>`, `config`,
  `is_admin()`, `sign_out()`, `refresh()`, `set_user(UserInfo)` and
  `check_session()`.
  - `check_session()` asks `GET /api/auth/me` whether the session is still
    live. A 401 there shows `<SignIn>` with the signed-out notice, so a user
    whose session ended elsewhere finds out instead of facing a dead page.
    With a socket from `set_socket` the provider calls it itself when the
    socket closes (see 2.7); an app without one calls it when it suspects the
    session ended.
- App components follow the context rather than watchword's events
  (decision 27). The provider gives a new `AuthContext` whenever the user,
  their role or the config changes, so:
  - `use_auth()` and `use_is_admin() -> bool` (false outside a provider)
    render a function component again on each change;
  - `AuthSubscription::new(ctx, Msg::Auth)` does the same for a struct
    component: it subscribes to the context with the component's message,
    derefs to the `AuthContext`, and `set(context) -> bool` takes the new
    one in `update`;
  - `use_users() -> Users` and `AuthContext::subscribe_users(callback) ->
    (Users, Listener)` give the users list shared with `<AdminUsers>`
    (below);
  - with `musliweb04`, `AuthContext::on_update(callback) -> Listener` and
    `use_auth_update(f)` pass on each `AuthUpdate` the socket brings, after
    the provider and the shared list applied it, except the stale socket's
    `Me`/`Resync` the provider ignores.
  `Listener` unsubscribes on drop.
- The users list is one per provider (`Users`, behind an `Rc` in the
  context). It is fetched when the first component subscribes, kept current
  by what `<AdminUsers>` changes and by the socket's user-list updates
  (fetching again when an update cannot say enough, as 2.7 describes), and
  dropped when the last subscriber goes, so the next fetches it fresh. It is
  fetched again, or dropped, when the signed-in user's id, role or
  impersonation changes, and dropped on sign-out. `Users` is a snapshot:
  `entries()`, `get(id)`, `is_loading()`, `error()` (until a fetch
  succeeds; a list already shown is kept) and `reload()`; each change is a
  new one, equal only to itself. A 401 on the fetch checks the session.
- `<SignIn config on_sign_in notice title>` offers the enabled methods: a
  login/email + password form, "Sign in with Cloudflare" when
  `config.cloudflare` is set, and "Sign in with Google" when `config.google`
  is set. It shows `?error=` messages and strips them from the URL.
- `<Register token on_register title>` shows the login and email read-only,
  then the password and confirmation fields, then "Sign up with Google" when it
  is enabled.
- `<AccountPanel>` covers the role, login (when `logins`), email, change or set
  password, switching to Google, and sign out. The app wraps it in a page or a
  modal.
- `<UserMenu on_account on_admin on_stop_impersonating>` shows the user's name,
  Account, Users (for admins only) and Sign out. While an admin impersonates
  the user it also shows a banner, "Impersonating {user} as {admin}.", with a
  Stop impersonating button that calls `http::stop_impersonating`, sets the
  admin as the user and calls `on_stop_impersonating` (optional).
- `<AdminUsers>` covers:
  - the user list, filtered and paged by `query: UsersQuery` (`page_size`,
    default `PAGE_SIZE`), with `on_query_change` so an app can keep the query
    in its URL;
  - status icons and the link state;
  - add user, edit login/email, role select, new or revoked link (shown once,
    with Copy), sign out everywhere, revoke access, impersonate (when
    `on_impersonate` is set) and delete.

  It shows the provider's shared `Users`, and keeps one of its own outside a
  provider. Its other props are `me: Option<Rc<UserInfo>>` (the admin whose
  row offers no self-actions; defaults to the context's user, so it is only
  needed outside a provider), `refresh: u64` (bump it to refetch, the same as
  `Users::reload`, for an app without a socket), and
  `extra: Callback<UserInfo, Html>` for the app's own columns, such as group
  membership.
- `<AdminCloudflare app_name on_saved>` is the Cloudflare Access settings page
  for admins. It loads the settings watchword keeps (`GET
  /api/auth/cloudflare`, or `Cloudflare` over the socket), shows
  `<CloudflareSettings>`, and saves each change as it is made (`PUT`, or
  `SetCloudflare`), disabling the form meanwhile and putting the old settings
  back if the save fails. After a save it refreshes the context, since
  `AuthConfig::cloudflare` may have changed, and calls `on_saved` with the
  settings as stored. A 404 says the server is built without Cloudflare
  Access.
- `<CloudflareSettings value on_change app_name disabled>` is its form alone,
  for an app that places the fields in a form of its own: setup instructions,
  the fields, and a warning when the header is trusted without verifying the
  token. `app_name` overrides the message `watchword-cloudflare-the-app` ("the
  app") in the instructions.

### 2.7 musli-web integration (`musliweb04`)

*Status: built are the types (`watchword::musliweb04`), the server's
`Connection` (`new`, `update`, `lagged`, `handle`, `handles`, the
accessors `signed_in`, `require_admin`, `user_id` and `session_id`, and
`updates`, the socket loop's auth arm as an `Updates`), and the components
following the broadcasts and sending their requests over the socket
(`AuthContext::set_socket`). `examples/app` is wired this way and is the
reference for an app. Decisions 13, 16–20 and 23 record why it is shaped this
way.*

An app whose frontend already talks to its server over a musli-web WebSocket
can carry watchword's account and user-management operations, and its live
updates, on that same connection. The HTTP routes of 2.5 stay; this is a
second transport for the operations that can use it, not a replacement.

#### What musli-web 0.4 gives and constrains

- `musli_web::define! { ... }` turns each `pub type X;` with an `impl
  Endpoint for X` or `impl Broadcast for X` into a type with a `const ID:
  MessageId` (a `NonZeroU16`). Without `#[musli(id = N)]`, ids are assigned
  from 1 in declaration order, separately in each `define!` call, and
  endpoints and broadcasts share one id space. Two crates' implicit ids
  therefore always clash. Explicit ids must be in 1..=32767; musli-web reserves
  the rest.
- Each call also generates `Request` and `Event` enums implementing
  `api::Id`, with an `Unknown(MessageId)` arm. There is no syntax for merging
  two lists.
- The macro expands to absolute `::musli_web::` paths, so the crate calling it
  must see musli-web under that name.
- On the server, a connection has one `ws::Handler` with one `type Id`;
  `Incoming::read::<T>()` decodes the request body and `Outgoing::write`
  answers it. `Server::broadcast` takes any `api::Event`, from any `define!`.
- On the client, `web03::Handle` is not typed by any API: one handle carries
  requests and broadcasts of any number of `define!` lists, as long as the ids
  differ. It reconnects by itself, with backoff.

#### Types: `watchword::musliweb04` (feature `musliweb04`)

The definitions live in watchword-core, which is wasm-safe and is what an
app's shared `api` crate already depends on (through `watchword` with
`musli01`). watchword-core depends on musli-web under the versioned key
`musli-web04` (`default-features = false, features = ["api"]`) and makes the
macro's paths resolve with `extern crate musli_web04 as musli_web;` at its
root, under the feature. The module is re-exported as `watchword::musliweb04`.

```rust
musli_web::api::define! {
    #[musli(id = 32000)] pub type Me;            // MeRequest -> Result<UserInfo, AuthError>, with impersonated_by
    #[musli(id = 32001)] pub type UpdateAccount; // UserChange -> Result<UserInfo, AuthError>; own login/email
    #[musli(id = 32002)] pub type ChangePassword;// PasswordChange -> Result<UserInfo, AuthError>
    #[musli(id = 32003)] pub type Users;         // UsersRequest -> Result<Vec<UserEntry>, AuthError>; admin
    #[musli(id = 32004)] pub type CreateUser;    // NewUser -> Result<CreatedUser, AuthError>; admin
    #[musli(id = 32005)] pub type UpdateUser;    // UserUpdate { id, change } -> Result<UserInfo, AuthError>; admin
    #[musli(id = 32006)] pub type DeleteUser;    // DeleteUserRequest { id } -> Result<(), AuthError>; admin
    #[musli(id = 32007)] pub type IssueLink;     // IssueLinkRequest { id } -> Result<Link, AuthError>; admin
    #[musli(id = 32008)] pub type RevokeLink;    // RevokeLinkRequest { id } -> Result<(), AuthError>; admin
    #[musli(id = 32009)] pub type SignOutUser;   // SignOutUserRequest { id } -> Result<(), AuthError>; admin, sign out everywhere
    #[musli(id = 32010)] pub type RevokeAccess;  // RevokeAccessRequest { id } -> Result<UserInfo, AuthError>; admin
    #[musli(id = 32011)] pub type Cloudflare;    // CloudflareRequest -> Result<CloudflareConfig, AuthError>; admin
    #[musli(id = 32012)] pub type SetCloudflare; // CloudflareConfig -> Result<CloudflareConfig, AuthError>; admin
    #[musli(id = 32100)] pub type AuthBroadcast; // event AuthUpdate
}

pub enum AuthUpdate {
    Me(UserInfo),           // the connection's own user changed (role, login, email, credential)
    UserCreated(UserInfo),  // admins only
    UserChanged(UserInfo),  // admins only
    UserDeleted(UserId),    // admins only
    Resync(UserInfo),       // admins only: updates were missed; carries Me, refetch the list
}
```

`Cloudflare` and `SetCloudflare` were added after the first eleven, taking the
next free ids; the ones before kept theirs. A server without the `cloudflare`
feature answers an admin's request for them with `AuthError::NotFound`, as it
has no route for them.

The request bodies are small structs in the module (`MeRequest`,
`UsersRequest`, `CloudflareRequest`, `UserUpdate { id, change }`, and a `{ id }` struct per
endpoint that only names its target user, such as `DeleteUserRequest`) or the
existing wire types (`UserChange`, `PasswordChange`, `NewUser`,
`CloudflareConfig`). One shared
`UserTarget { id }` cannot serve those five endpoints: `define!` implements
`api::Request` for each request type with its endpoint as `type Endpoint`, so
a type can be the request of only one endpoint. Every response is
`Result<T, AuthError>`, which musli encodes (musli-core implements
`Encode`/`Decode` for `Result`, so it meets `Endpoint::Response`'s bound
directly), so the frontend gets the same structured `AuthError` it gets over
HTTP. An internal failure (store, hashing) is an `Err` from the handler, which
musli-web sends as a request error, the analogue of HTTP 500.

**Ids.** watchword owns the band 32000–32255 and pins every id in it
explicitly. An app keeps its own implicit ids, which start at 1 and never
reach the band, or pins its own ids below it. A released id never changes
meaning; a new endpoint takes the next free id in the band, and a removed one
leaves its id unused. The module exports the band as `FIRST_ID` and
`LAST_ID`, and `is_watchword_id(id)` tests an id against it. Pinning keeps
watchword's ids stable whatever order its definitions are in, and the band
makes a clash a matter of an app defining over 31 999 types.

The app's `api` crate does not list watchword's types in its own `define!`
(musli-web has no syntax for that): they are a second list on the same
connection. The app takes `watchword` with `musliweb04` in its `api` crate
and may re-export the module.

#### Server: `watchword::musliweb04::Connection` (`musliweb04` + `axum08`)

musli-web's server side (`ws::Handler`, `Incoming`, `Outgoing`) needs its
`ws` feature, which builds on axum 0.8, so the handler exists when both
`musliweb04` and `axum08` are on (`musli-web04?/ws` is enabled by `axum08`).

```rust
// At upgrade, from the `SignedIn` the app's /ws route already extracts:
let conn = watchword::musliweb04::Connection::new(auth.clone(), &signed_in);

// In the app's Handler::handle, in the arm for ids its own API does not know:
api::Request::Unknown(id) => conn.handle(id, incoming, outgoing).await,   // -> Result<bool, RequestError>

// Before negotiating the socket, the loop's auth arm: the session's guard and
// the event receiver, filtered through `update` and `lagged` below.
let mut updates = conn.updates();
let Some(Ok(mut server)) = updates.unless_ended(connect).await else { return };   // stops a stalled negotiation once the session ends

// In the app's connection loop, next to server.run():
update = updates.next() => {
    let Some(update) = update else { break };   // None once the session ended
    server.broadcast(update)?;
}

// Or, by hand, with the app's own guard and receiver:
event = events.recv() => {
    let update = match event {
        Ok(event) => conn.update(&event).await?,
        Err(RecvError::Lagged(..)) => conn.lagged().await?,
        Err(RecvError::Closed) => break,
    };

    if let Some(update) = update {
        server.broadcast(update)?;
    }
}
```

- `Connection` holds the `Auth` and the `SignedIn` of the upgrade (behind an
  `Arc`, for the guard `updates` starts). It is `Clone` and cheap, so it sits
  inside the app's own handler.
- `updates()` returns an `Updates`, which owns the `Auth::guard` of the
  upgrade's session and an `Auth::events` receiver, subscribed when it is
  made, so it is taken before negotiating. `next()` yields the next update to
  broadcast: each event through `update`, a lag through `lagged`, skipping
  what the connection may not see, and `None` once the guard says the session
  ended (and from then on); a store failure is logged at error level and the
  event skipped. It is cancel safe as a `select!` branch: an event received
  by a cancelled call is kept for the next. `unless_ended(future)` runs a
  step, such as the musli-web negotiation, only while the session lasts.
  `guard()` and `connection()` give the parts. Every app's loop carried the
  same arm before; a loop that needs more (the guard's `changed`, say) keeps
  it by hand with `update` and `lagged`.
- `handle` returns `Ok(false)` for an id outside watchword's band, which the
  app treats as it treats its own unknown ids. For watchword's ids it decodes
  the body, re-reads the session and its user through `Auth::session` (as
  `SignedIn` does on every HTTP request), answers `Unauthorized` when the
  session has ended, and calls the same `Auth` operation the HTTP route calls,
  with the fresh user as the actor. Admin rights, never-on-oneself, the
  impersonation rules and the rest of section 3 are enforced inside those
  operations, so an app cannot route a request around them and a role change
  applies to the next request on an open socket.
- `update` maps an `AuthEvent` to the `AuthUpdate` this connection may see:
  `Me` for its own user's `UserChanged` (as `session_info`, so an impersonated
  session keeps its marker), and the user-list events only while the
  connection's user is an active admin, re-read when such an event arrives.
  Session-ending events are not forwarded: the app's `guard.ended()` closes the
  socket, as today.
- `lagged` stands in for the events the app's receiver dropped when
  `recv()` answers `RecvError::Lagged`: `Resync` with the connection's own
  user (as `session_info` gives it) while that user is an active admin, `Me`
  for anyone else, and nothing once the session has ended. A regular user
  sees nothing of the missed events but their own user, so a `Me` covers
  them; an admin's page may also show the user list, which it fetches again
  on `Resync`. The guard re-checks the session itself on lag.

The app's own requests on the socket are gated with the same checks:

```rust
conn.signed_in().await?       // -> (User, Session) as stored now; AuthError::Unauthorized once the session ended
conn.require_admin().await?   // -> User; AuthError::Forbidden unless an admin now (as the `Admin` extractor)
conn.user_id()                // UserId the upgrade carried (the impersonated user for an impersonated session)
conn.session_id()             // &str
```

Both async accessors re-read the session through `Auth::session`, as
`handle` does for watchword's endpoints, and return `core::Error`: a refusal
is `Error::Auth(AuthError)`, and anything else is the store failing, which
an app must not answer as "not an admin". `handle` uses them itself.

An app that hand-writes a combined `api::Id` instead of delegating its
`Unknown` arm can do so; `Connection::handles(id)` (or `is_watchword_id`, from
the types) says whether an id is watchword's.

As built: `handle` returns `Ok(false)` for any id that is not one of
watchword's endpoints, inside the band too (such as `AuthBroadcast`'s, or one
a newer client knows), and `handles` is true for exactly the ids `handle`
answers. The admin endpoints refuse a user who is not an admin with
`Forbidden` before calling the operation, as the HTTP `Admin` extractor does,
so `UpdateUser` on oneself is refused for a regular user over both
transports; `UpdateAccount` refuses a role change with `RoleNotChangeable` as
its route does. A body that does not decode also gives `Ok(false)`, and
musli-web answers the request with the decode error. An internal failure is
logged by `handle`, at error level with its cause, and returned as the `Err`:
a `musliweb04::RequestError`, the app handler's error type, whose message
musli-web sends as the request error. It shows a refusal as its `AuthError`
and an internal failure as just `internal error`, so a cause never reaches
the client. The app's own requests convert into it with `?` (from
`core::Error`, `AuthError` or `StoreError`); the app logs their internal
failures itself, and does not log again what `handle` returns, which is
already logged.

#### Frontend: the components' socket transport (`musliweb04` + `yew023`)

The `/ws` upgrade needs a session, so an app opens its socket inside
`<AuthProvider>`, after sign-in. It hands the handle to watchword once:

```rust
let auth = use_auth();                      // or ctx.link().context::<AuthContext>()
auth.set_socket(Some(service.handle().clone()));   // a musli_web::web03::Handle
```

From then on `AuthContext` sends the operations of the band through the
socket while its state is open, and over HTTP otherwise, so a request made
while the socket reconnects still works. `refresh()` uses `Me`.
`<AccountPanel>` and `<AdminUsers>` take their client from the context, so an
app passes no new props whether it hands its own components the handle as a
prop or through a `ContextProvider`. With a socket, `<AuthProvider>` listens
for `AuthBroadcast`: `Me` replaces the context's user, and the shared users
list (2.6), which `<AdminUsers>` shows, applies
`UserCreated`/`UserChanged`/`UserDeleted` in place, so its `refresh` prop is
no longer needed (it stays for HTTP-only apps). On `Resync` the provider
replaces the user as for `Me` and the list is fetched again. Every update is
then passed to the app's `on_update` listeners. `http::Error`
gains a variant for a socket request error.

As built: watchword-yew023 has a `musliweb04` feature, which watchword's
`musliweb04` turns on with `yew023`. `set_socket` with the handle already set
does nothing, and the socket is forgotten whenever the provider leaves the
signed-in state, so the next sign-in hands over its own.

The provider also follows the socket's state to notice an ended session.
Browsers do not expose a refused upgrade's status, so a 401 on `/ws` only
shows as a socket that closes or never opens. The provider runs
`check_session()` when the socket goes from open to closed, and every 10
seconds while it stays closed, including when it was handed over closed (the
provider has just checked the session to show the app, so that first check
waits). musli-web emits a state change only on open/closed transitions, not
for each failed reconnect, so the repeated check is a timer rather than a
count of failures; musli-web itself retries with backoff up to 4 seconds. A
check while one is in flight is dropped. Apps used to do this themselves and
disagreed on when (on every close, only after being open, or polling); they
can drop their own listener, though calling `check_session()` as well only
checks twice. The provider is the only listener on the socket, and hands
the user-list updates to the shared list. A broadcast carries no link
state (issuing and revoking a link emit no `AuthEvent`), so the list
applies each update in place and fetches the list again only when it cannot
know the links: for a user created elsewhere (shown at once, without a link
until the list answers), when a user's account state or sign-in method
changes (registering and revoking access use up the links), for a user not in
the list, and when a load was in flight. `<AdminUsers>` keeps the links it
issued (shown once) itself, and drops each once the list no longer shows that
user with a live link. A password reset through a link
changes nothing a broadcast shows, so that link's expiry stays shown until the
list is next fetched.

As built, the requests: the components take a crate-private client from the
context, which sends each operation of the band over the socket and falls
back to HTTP only when musli-web refuses the request before sending it (the
socket is not open), so nothing reaches the server twice. A request the
socket fails after sending it, such as when the socket closes before the
answer or the server answers with a request error, fails with
`http::Error::Socket`. The public `http` functions stay HTTP-only. Admin
`RevokeAccess` answers with the user over the socket and with nothing over
HTTP; the client drops the user, as the component did not use it.

Impersonating does not end the admin's session, and the socket's server-side
`Connection` keeps the session its upgrade carried. So after
`POST .../impersonate` or `/impersonate/stop` replaces the cookie, an open
socket still speaks for the earlier session: `Me` over it would answer the
admin, and its `AuthUpdate::Me` would put the admin back. The components
that make those two requests mark the socket stale, and while it is stale
the requests go over HTTP and `<AuthProvider>` ignores its `Me`. It stops
being stale when it next closes: its reconnect upgrades with the new
cookie. An app that keeps its socket open across impersonation therefore
runs on HTTP until it reconnects, which it may do itself when its user
changes. musli-web reconnects cleanly with `Service::close` and then
`Service::open`: `close` reports the socket closed at once, which clears
the stale mark, and `open` upgrades again with the current cookie, keeping
the same `Handle`, so nothing is handed over again. `examples/app` does
this from `<AdminUsers>`'s `on_impersonate` and `<UserMenu>`'s
`on_stop_impersonating`, which both run after the components marked the
socket stale.

The example's wiring, as a reference: a shared `api` crate with the app's
own `define!` list (implicit ids), next to which watchword's list rides on
the same socket. The server's `/ws` route extracts `SignedIn`, makes the
`Connection` from it, and its `ws::Handler` answers the app's ids and
delegates `Unknown(id)` to `conn.handle`. It takes `conn.updates()` first,
negotiates through `updates.unless_ended`, and its connection loop selects
over `server.run()` and `updates.next()`, broadcasting each update and
dropping the server, which closes the socket, once `next` gives `None`. The frontend builds the web03
`Service` once inside `<AuthProvider>`, hands its handle over with
`set_socket`, which then checks the session whenever the socket closes;
musli-web reconnects by itself while the session lives.

watchword-yew023 takes musli-web under `musli-web04` with `web03`; it calls
no musli-web macros, so it needs no alias.

#### What stays HTTP, and why

| Operation | Why it cannot use the socket |
|---|---|
| `GET /api/auth/config`, the first `GET /api/auth/me` | `<AuthProvider>` needs them to decide between the sign-in page and the app, before any socket exists; the upgrade requires a session |
| `check_session()` (`GET /api/auth/me`) | it runs because the socket closed or does not open |
| `POST /api/auth/login`, `/logout`, `/cloudflare` | they set or clear the `HttpOnly` session cookie, which only an HTTP response can do; there is no socket before sign-in |
| Cloudflare Access | the credentials are the Access JWT and headers on an HTTP request, checked when signing in (and by `config` for `AuthConfig::cloudflare`) |
| `GET`/`POST /api/auth/register/{token}` | the user is signed out; registering sets the cookie |
| `/api/auth/google*` | browser navigations: redirects to Google and its callback, which sets the cookie |
| `POST /api/auth/users/{id}/impersonate`, `/impersonate/stop` | each replaces the session cookie with a new session, which also invalidates the socket the request would come from |

All other account and admin operations are in the band. The HTTP routes for
them remain, for apps without musli-web and as the fallback while a socket is
down. watchword has no per-session list or revoke operation; when one is
added it goes into both transports.

#### Adopting it before a release

An app moves onto unreleased watchword changes with a patch in its workspace
`Cargo.toml`, keeping its `version = "0.1"` requirements as they are:

```toml
[patch.crates-io]
watchword = { path = "../watchword" }
watchword-core = { path = "../watchword/crates/watchword-core" }
watchword-yew023 = { path = "../watchword/crates/watchword-yew023" }
```

All three are patched together, because they pin each other exactly. A patch
applies only while the local version satisfies the app's requirement: once
watchword's version is bumped past it (0.1 to 0.2), cargo ignores the patch with
a warning until the app's requirement is raised to match. The patch is removed
once the release is on crates.io.

## 3. Decisions

1. **Identity: logins optional, emails optional, at least one required.** Some
   apps sign in by login name and have users without an email (such as a
   first admin named `root`); others are email-only. A user has an optional
   unique `login` and an optional unique `email`, and needs at least one.
   Password sign-in tries the login, then the normalized email.
   `logins(false)` hides login fields and requires an email. Cloudflare and
   Google always match on email. Requiring an email everywhere would drop
   sign-in by login name and force an email on every user; requiring a login
   everywhere would make email-only apps invent and show logins. Both
   optional costs one column and a builder flag.
2. **Account state: `Access` is pending, active or revoked.** A user created by
   an admin is pending until they register with their link.
   - Pending users cannot sign in, except through Cloudflare Access, which
     activates them: Access has already vouched for the email, and an app
     behind Access expects its users to get in without a registration step.
   - Revoked users cannot sign in by any path.
   - A new link restores a revoked user.
3. **Sign out everywhere and revoke access are distinct actions.** "Sign out
   everywhere" ends the user's sessions and lets them sign in again, for a lost
   device. "Revoke access" blocks the user: access becomes revoked, the
   password is cleared, links are used up and sessions end. Both are offered,
   under names that say which is which.
4. **One stored credential per user, switchable.** `Method` is `Password` or
   `Google`, exclusively.
   - A password user can switch to Google, which clears the password and binds
     the subject.
   - A Google user can set a password, which switches them back.
   - Cloudflare Access is not a stored credential. It identifies any active or
     pending user by email, whatever their method.
   - Both of these changes end the user's other sessions.

   Linking Google alongside a password would be more flexible, but needs more
   account UI and rules (such as never unlinking the last method); one method
   is the smallest model that works.
5. **Two token kinds, chosen when the link is issued.** `Reset` for active
   users, `Registration` otherwise. A token is usable while unused and
   unexpired, and, for an active user, only if it is a reset link, so a
   registration link issued before the user registered stops working once they
   have. Issuing a link uses up the user's earlier links. Links are single use
   and last 7 days.
6. **First admin: a bootstrap link, no default password.**
   `Auth::bootstrap_admin` creates a pending admin from an email or login when
   there are no users, and logs (and returns) their registration link, a full
   URL when the app's public URL is known. The option stays set across
   restarts: while the named admin is still a pending admin and no active
   admin exists, a restart after their link expired issues a new one
   (`Bootstrap::Reissued`), and one while it is live changes nothing
   (`Bootstrap::Pending`). Otherwise it does nothing once users exist. A
   seeded default password would be a standing risk on every new install.

   Only an active admin can revoke a link on purpose, so a pending admin with
   no live link and no active admin around has one that expired or was used
   up, and reissuing it lets in nobody new. The same reasoning makes admin
   operations need an active admin: a pending admin acting through the
   service (as apps did to reissue the bootstrap link themselves) would be an
   admin who never proved they hold the link. For any other lockout, an app's
   CLI calls `Auth::recovery_link`, which acts as the system.
7. **Cookie.** The cookie name is configurable. `Secure` is set automatically
   from `X-Forwarded-Proto` (`Secure::Auto`), with `Secure::Always` and
   `Secure::Never` also available. The other attributes are fixed:
   `HttpOnly`, `SameSite=Strict`, `Path=/`, and a 30-day `Max-Age` without
   `Expires`. The value format is fixed and keyed by the store's
   `session_key`, so sessions survive restarts and an app whose cookies already
   use this format keeps them.
8. **Expired sessions and links** are pruned: sessions on session creation
   (the store may), and both by `auth.prune()`, which an app calls itself or
   has `AuthBuilder::prune_every` run on a timer. `prune` deletes a link,
   used or not, only once it expired longer ago than `TOKEN_LIFETIME`, so a
   recently expired link still answers `Gone` (the UI's "link expired")
   rather than `NotFound`. Reads always check the expiry, and a pruned link
   reads as no live link in `UserEntry::link_expires_at` and
   `bootstrap_admin` just as an expired one does, so pruning only keeps the
   store small.
9. **Throttling and dummy-hash timing apply to every password sign-in**, so
   neither guessing passwords nor probing for user names gets cheaper.
10. **WebSocket end-of-session: every signal.** The guard combines an expiry
    timer, `AuthEvent` matching, a re-check on broadcast lag and a 5-minute
    re-check. Events end a socket at once when the change goes through this
    process's `Auth`; the re-checks catch changes made by another process on
    the same store.
11. **Role changes** apply per request (`Admin` re-reads the user) and are pushed
    as `AuthEvent::UserChanged`. Sockets see them through `guard.changed()`.
12. **Impersonation**, behind `.impersonation(true)`, lets an admin act as a
    user to see what they see, with a marker and a way back. The session
    records the admin (`Session::impersonator`, `sessions.impersonator_id`), the
    own user's `UserInfo` carries `impersonated_by`, `UserMenu` shows a banner,
    and `POST /api/auth/impersonate/stop` ends the impersonated session and
    signs the admin in again. Pending users can be impersonated, revoked ones
    cannot. Impersonating from an impersonated session is refused, so stopping
    always returns to the admin who started. The admin's own session is left
    alone when impersonating (its cookie is replaced, and it expires).

    An impersonated session lives only while its admin is an active admin.
    Deleting the admin deletes the sessions they impersonate in. Revoking or
    demoting them makes `Auth::session` treat those sessions as ended, at the
    cost of one extra user lookup for impersonated sessions only, and it
    deletes each such session it finds, so promoting the admin again cannot
    revive it; a session nobody touches in between survives a
    demote-then-promote, since the store cannot find sessions by impersonator.
    Guards and the `LiveSession` cache end them at once on the admin's
    `UserChanged` or `UserDeleted`, with no new event. `stop` keeps its 403 for
    an admin who is no longer an active admin, but an ended session is refused
    with 401 before it gets there.
13. **Transport: the library's own JSON routes, and optionally the app's
    socket.** Account and admin operations are HTTP JSON routes, so the
    components are self-contained, an app writes no user endpoints, and an app
    without a WebSocket needs nothing more. An app with a musli-web socket can
    also carry them, and the live updates, on it (2.7): watchword
    defines the endpoints and the handler, so the app still writes no user
    endpoints, and the components need no app-supplied client trait because
    musli-web's handle is untyped. The HTTP routes stay, both for apps without
    musli-web and as the fallback while a socket reconnects.
14. **Storage: the `Store` trait is the API, and `SqllStore` ships too.** An
    app on another database implements `Store`; an app on sqll takes
    `SqllStore` over the documented schema instead of writing the same few
    hundred lines of queries again, migrating its auth tables to that schema
    once.
15. **Timestamps** in the library are `jiff::Timestamp`. `SqllStore` stores
    them as INTEGER milliseconds since the Unix epoch.
16. **The socket layer is additive, and is built broadcasts first.** Keeping
    HTTP for everything costs the apps nothing today, since the components
    already make every request themselves. What it leaves to each app is
    pushing auth changes to open pages: each app forwards `AuthEvent`s in its
    own shape (marker broadcasts that make the page refetch over HTTP, the
    wire types embedded in the app's own event enum, or nothing), and an admin
    page without that never sees another admin's changes. A shared
    `AuthBroadcast` with a per-connection filter (`Connection::update`)
    replaces those with one thing the components consume themselves, and is
    most of the gain. Moving the requests too gives one connection, one place
    where liveness and admin rights are checked, and one error path, for a
    modest cost: the request types, one delegating match arm in the app, and
    a second transport in the components. Removing the HTTP routes would break
    every app without musli-web, and the sign-in operations cannot move at all
    (2.7), so it is not proposed.
17. **Ids: a pinned band, not a merged list.** musli-web numbers each
    `define!` list from 1 and cannot merge lists, so watchword pins all of its
    ids explicitly in 32000–32255 and the app delegates the ids its own
    `Request` does not know (`Unknown(id)`) to `Connection::handle`. Making
    apps pin their own ids instead would renumber their existing protocols;
    a hand-written combined `Id` type works too but asks every app for more
    code than one match arm. The band is part of the wire format: a released
    id never changes meaning.
18. **Admin checks stay in `Auth`, and the session is re-read per request.**
    A socket lives for hours while roles and sessions change. `Connection`
    loads the session and user through `Auth::session` for every request, as
    the HTTP extractors do, and the operations check admin rights and the
    other rules themselves, so the socket path cannot drift from the HTTP
    path and an app cannot skip a check by routing a request differently. The
    cost is one store read per request, the same as over HTTP.
19. **musli-web is a versioned dependency, aliased for its macro.** musli-web
    0.4 is not 1.0 and appears in the API (`Handle`, `Incoming`, the
    generated types), so the feature, dependency key and module are
    `musliweb04`/`musli-web04`/`musliweb04` (1.2). `define!` expands to
    `::musli_web::` paths, which `extern crate musli_web04 as musli_web;` in
    watchword-core satisfies without giving up the versioned key. That alias
    is crate-wide, so a later `musliweb05` cannot sit beside it in the same
    crate; when that comes, one of the two moves into a crate of its own
    (`watchword-musliweb05`), as yew did in 1.1, without changing the
    `watchword::musliweb0N` paths apps use.
20. **A lagged event stream resyncs the page with one update.** `Auth::events`
    is a bounded broadcast channel, so a slow socket loop can miss events and
    nothing replays them. Rather than replay or a per-socket queue,
    `Connection::lagged` sends one `AuthUpdate::Resync` carrying the user, as
    `Me` does, and the page fetches its user list again; a non-admin, who
    sees nothing else, gets a plain `Me`. `Resync` is a new variant at the end
    of `AuthUpdate`, so the encoding of the existing ones is unchanged and a
    client that does not know it drops the broadcast, as it drops any that
    does not decode. Carrying the user saves the page a `Me` round trip; a
    separate users-changed signal next to a `Me` would need two broadcasts
    for one lag.
21. **The components' text goes through phrasebook, with English built in.**
    Apps translate their own pages with phrasebook; a library that renders
    English inline, or takes a prop per string, leaves holes in a translated
    page, and props cannot cover error messages built deep inside a
    component. With the strings as `watchword-*` messages in a catalog of
    watchword's own, an app translates them in the same `.ftl` files as its
    other text, and one that does not translate changes nothing: the
    fallback to `L10N` needs no provider. The props that overrode text
    (`signed_out_notice`, `app_name`) stay as optional overrides of their
    messages; `SESSION_ENDED`, an English constant, is gone in 0.2.
22. **Unknown reasons decode as `Invalid::Unknown`.** A frontend is often
    older than its server for a while: a page left open across a deploy, or
    a cached build. Without a catch-all variant, a new reason makes the whole
    error body undecodable, which the components show as an unexpected HTTP
    400 with no hint that the request was refused for a reason. A unit
    catch-all costs one variant and keeps the error an `AuthError::Invalid`
    that says the request is invalid; its parameters are dropped, since an
    older frontend could not phrase them anyway. serde's `#[serde(other)]`
    and musli's `#[musli(default)]` both decode an unknown tag to a unit
    variant, so the two wire formats agree. The alternative, a variant
    carrying the raw code and parameters, would need a hand-written
    deserializer per format for a message nobody can translate.
23. **Apps gate their own socket requests with watchword's checks.** Every
    app with a socket also has requests of its own that need a signed-in
    user or an admin, and each re-implemented what `Connection` did
    privately: a copied session wrapper, a store lookup per check that
    answered "forbidden" when the store failed, or an admin flag kept by
    hand and re-queried after a lag. `Connection::signed_in` and
    `require_admin` are now public, with the same refusals as the HTTP
    extractors and the store failure kept apart from them, and the guard
    exposes the user it already follows (`user`, `watch_user`) for a check
    that may use the role as last seen. The store-reading pair is the safe
    default; the guard's copy saves a lookup where a few minutes' staleness
    across processes is acceptable. A `watch::Receiver` is handed out
    rather than a wrapper type: tokio is already in the API through
    `Auth::events`, and it is what the guard holds.
24. **A session gate for whole sites, with watchword's public paths
    built in.** An app that serves its frontend behind a session wrote its
    own middleware, hard-coding watchword's public prefixes (`/api/auth/`,
    `/register/`), so a public route watchword added later would have been
    refused there without any error. `is_public` names them in one place
    and `require_session` builds the usual gate on it: 401 for the API, a
    redirect to sign-in with `?next=` for pages. The `next` value is only
    ever followed by the frontend as a same-origin path, since the sign-in
    page is reachable by anyone with any query and an unchecked `next`
    would be an open redirect. The rule lives in watchword-core
    (`is_same_origin_path`, needing no feature) so the server's Google
    sign-in, which follows a `next` itself, checks exactly what the
    frontend does. The extensions cache of `SignedIn` is now
    documented, since apps behind the gate rely on it.
25. **Audit events are their own type, delivered by a hook.** Apps keep
    audit logs of admin actions, and `AuthEvent` said what changed but not
    who changed it or what it was before, so army reconstructed them by
    parsing request paths and diffing its users table around each request.
    Putting an actor on `AuthEvent` instead was rejected for three reasons.
    An `AuthEvent` describes an effect, and one operation sends several
    (revoking sends `UserSessionsEnded` and `UserChanged`), where an audit
    log wants one entry per operation with its before and after. Operations
    that change nothing a socket sees (issuing or revoking a link,
    impersonating) would wake every socket's guard for nothing. And the
    broadcast drops events for a receiver that falls 256 behind, which the
    guard survives by re-checking, but an audit log cannot. So `AuditEvent`
    is a separate `#[non_exhaustive]` enum, and `AuthBuilder::audit` hooks
    are called synchronously after each change is stored, so none is missed;
    a hook that writes to a database forwards the event to a task through
    an unbounded channel. The actor includes the impersonating admin, which
    is why the changing operations now take the actor's session: an admin
    impersonating another admin, or a user whose password an impersonating
    admin changes, is otherwise recorded as the wrong person. Sign-ins and
    sign-outs are left out for now; adding them is a new variant, not a
    breaking change.
26. **watchword keeps the Cloudflare Access settings.** Every app that
    offered Access stored the settings itself, served them to an admin page
    of its own and re-seeded `Auth` on each change, because `Auth` had a
    setter and nothing else. `Auth` now stores them under one key of the
    store's settings, which every store already has for `session_key`, and
    serves them over admin routes, socket endpoints and `<AdminCloudflare>`.
    The store is read lazily, on first use, rather than in `build`, so
    `build` stays synchronous and `Auth::builder` (which has no async step)
    stores them too. The builder's settings are the fallback, not a seed
    written to the store, so an app's environment-provided settings apply
    until an admin saves, and a restart with other environment settings does
    not overwrite what an admin saved. Saving takes the admin as `actor`, per
    decision 18, and their session, per decision 25, sending
    `AuditEvent::CloudflareChanged` with the settings before and after, so
    an app's audit log records who changed them; reading does not, so an
    app can read and log them at startup. That event acts on no user, so
    `AuditEvent::user` returns an `Option`.
27. **App components follow the context and share the users list.** Apps
    had no supported way to follow auth changes, so they mirrored
    watchword's events into broadcasts of their own: territory turned
    `AuthEvent::User*` into its own event kind (the only reason its API
    crate needed watchword's wire types), set the user from it although the
    provider already follows `Me`, and its groups page fetched the users a
    second time beside `<AdminUsers>`; track's struct components read the
    context once with `Callback::noop()` and never saw a role change; and
    `<AdminUsers>` required `me`, which it could read from the context.
    The provider already re-renders its children with a new context on each
    change, so the fix is to make reading it right easy: `use_is_admin`, and
    `AuthSubscription` for struct components, which must subscribe with a
    message of their own to render again (yew has no message-less way). The
    users list moves out of `<AdminUsers>` into the provider, fetched on
    first use and dropped with the last user of it, so two components on
    one page fetch it once and both follow the broadcasts; keeping it only
    while subscribed keeps a non-admin's page from fetching it, and an
    HTTP-only app's admin page fresh on each visit. `on_update` is for the
    rest: code that acts on an update itself. On the server the counterpart
    is decision 23: the app's authorization reads the session guard or
    `Connection::require_admin`, not a mirrored event. `AdminUsers.me`
    becomes `Option` (breaking for struct-literal props; `html!` users are
    unaffected through yew's `T -> Option<T>` prop conversion).
28. **`test-util` is for any app's tests, not only Google's.** It began as
    the fake Google and implied `google`, so apps without Google wrote their
    own sign-in helpers: each turned a `Set-Cookie` into a `Cookie` by
    splitting at `;`, built sessions by hand, precomputed bcrypt hashes for
    speed, and re-tested watchword's login, throttling and registration
    rules. Now `test-util` implies only `server` and carries `test_user`,
    `test_session` and the store suite, while the Google parts need `google`
    as well, so an app's tests do not pull in reqwest for a provider it does
    not use. That breaks an app that took `test-util` alone for
    `google_endpoints` or `FakeGoogle`; it adds `google`. `cookie_header` is
    under `server` rather than `test-util`, since a client making requests
    as a session needs it too. The store suite is exported as a macro over
    hidden functions rather than as named public tests, so it can grow
    without each test becoming API; it runs each test on its own runtime so
    an app needs no tokio `macros` for it.
