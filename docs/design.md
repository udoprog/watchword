# yew-auth design

yew-auth carries the authentication of an axum + Yew application across every
layer: the sign-in methods themselves (Cloudflare Access, Google OAuth, and
simple email/login + password with invite links and a bootstrap admin), session
and token handling, storage, the HTTP routes and extractors, WebSocket session
auth, the wire types, and the Yew pages and components. Its first consumers are
track and territory; army is next.

This document records:

1. a survey of how track and territory do auth today, and where they differ;
2. the layered API and the cargo features that select each layer;
3. the decisions that settle each difference;
4. how track and territory each wire it up, and what each deletes;
5. the open questions that need the user's decision;
6. the implementation cards, with their dependencies.

The survey was done read-only against track at `49dcf8c` and territory at
`154ff85`.

## 1. Survey

### 1.1 What each app has

| Concern | track | territory |
|---|---|---|
| Sign-in methods | Password (by login *or* email), Cloudflare Access | Password (by email), Google OAuth |
| User identity | `login` (required, unique) + `email` (optional, unique) | `email` (required, unique) |
| Roles | `admin`, `regular` | `admin`, `regular` |
| Account state | none; a user exists or not | `access`: `pending` → `active` → `revoked` |
| Sign-in method per user | password if `password_hash` is set; any user whose email Access vouches for | `auth_method`: `plain` or `google`, exclusive; Google is bound by `google_sub` |
| Tokens | one kind, "login link": registration *and* reset; one live per user; 7 days; single use | `registration` or `reset` (by the user's access when issued); one live per user; 7 days; single use |
| First admin | migration seeds `root` / `root` (bcrypt) | `BOOTSTRAP_EMAIL` creates a pending admin when there are no users and logs a `/register/{token}` link (`PUBLIC_URL` makes it absolute) |
| Session | DB row, 30 days fixed, 16 random bytes base64url | same |
| Cookie | `track_session` = `{id}.{b64url(HMAC-SHA256(key,id))}`, HttpOnly, SameSite=Strict, Path=/, Max-Age 30d, `Secure` when `X-Forwarded-Proto: https` | `territory_session`, same value format and attributes plus `Expires`, **never** `Secure` |
| Cookie key | 32 random bytes in the `config` table under `session_key` | same |
| Expired sessions | pruned on every session creation | pruned at startup and then hourly |
| Throttling | in memory, per client address (30 per 15 min; IPv6 by /64) and per login (10 per 15 min); trusted proxies give `CF-Connecting-IP` / `X-Forwarded-For` | none |
| Timing | an unknown user is verified against a dummy hash | an unknown user returns early |
| Role change | takes effect on the next request (role re-read from the DB) | takes effect live (WS `AtomicBool` updated by the `UserInfoChanged` broadcast) |
| "Revoke access" | `RevokeUserAccess` = sign out everywhere (delete sessions); the user can sign in again | `RevokeUserAccess` = `access=revoked`, clear password, invalidate tokens, delete sessions; a new link restores access |
| Credential change | change password keeps this session, ends the others; redeeming a link ends all sessions | the same, plus switching to Google ends all sessions |
| Impersonation | none | admin `POST /api/auth/impersonate/{hex}` replaces the admin's cookie with a session of the target (not revoked; pending users allowed) |
| WS upgrade | `AuthUser` extractor (cookie), 401 before upgrade | `try_auth` (cookie), 401 before upgrade |
| WS session end | in-memory `Revoke` broadcast (`User`, `Session`, `OtherSessions{keep}`), plus a re-check every 5 minutes, plus a re-check on broadcast lag | `SessionEnded` broadcast (`Session`, `UserExcept{keep}`) plus `UserAccessRevoked` on the app broadcast, a timer that fires at session expiry, plus a re-check on lag |
| Other cookie-authenticated routes | image proxy (no auth) | map tiles: liveness cached for 10 s in an LRU of 1024 |
| Who is signed in (frontend) | `GET /api/auth/me` at startup; when the socket is closed it polls `me` every 10 s and shows "Your session has ended" on 401 | `GET /api/auth/me` and `GET /api/config` (`{title, google_login}`) at startup; no detection of a session ending later |
| Methods shown at sign-in | `GET /api/auth/cloudflare` → whether *this request* carries Access credentials that map to a user | `google_login` from `/api/config` |
| User management transport | musli-web WebSocket requests, admin-checked per request | musli-web WebSocket requests, admin-checked per request; changes broadcast to admins and the affected user |
| Admin UI | `/users` page: list, add (login, email, role; makes a link), role select, new link / revoke link (shown once, copy), sign out everywhere, delete | `/admin` page: filter + paging in the URL, list with status icon and groups, add (email, role), edit email, new link / revoke link, revoke access, impersonate, delete, role select; live-updated |
| Account UI | `/account` page: role, edit login, edit email, change/set password, sign out | modal: edit email (not for Google users), change password or "set password" (switches to plain), "switch to Google" |
| Cloudflare config | runtime, in the app's settings (`enabled`, `team_domain`, `audience`, `trust_email_header`, `verify_jwt`), editable on an admin Settings page | n/a |
| Google config | n/a | CLI/env at startup: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URL` |
| Storage | `sqll` 0.14 (SQLite), timestamps as INTEGER ms | `sqll` 0.14 (SQLite), timestamps as RFC 3339 TEXT |
| Wire format | HTTP JSON for sign-in/registration; musli for WS; `api::User {id, login, email, role, has_password, created_at}` | HTTP JSON for sign-in/registration; musli for WS; `api::UserInfo {id, email, role, auth_method, access}`, `api::User` adds `pending_token`, `group_ids` |
| `UserId` | `u64` newtype | `u64` newtype (shown as hex in URLs) |

Both apps already share the core primitives that now live in this crate
(track's `crates/auth`): bcrypt at the default cost, 16-byte base64url ids, the
cookie value format, 30-day sessions and 7-day tokens. Hashes and cookies are
therefore interchangeable, so neither app's users lose their passwords or
sessions when they move.

### 1.2 Differences that need a decision

1. **Identity**: track signs in by login or email, and its users may have no
   email. Territory has email only.
2. **Account state**: territory has pending/active/revoked. Track has no state,
   and lets a user without a password sign in through Cloudflare straight away.
3. **What "revoke access" means**: sign out everywhere (track), or block the
   user (territory).
4. **Credentials per user**: track allows password plus Cloudflare on any user.
   Territory makes password and Google exclusive.
5. **Token kinds**: one kind (track), or registration vs reset (territory).
6. **First admin**: seeded `root`/`root` (track), or a bootstrap link (territory).
7. **Cookie `Secure` flag, pruning, throttling and dummy-hash timing**: territory
   lacks each of them.
8. **WS end-of-session detection**: a periodic re-check (track), or an expiry
   timer (territory).
9. **Role-change propagation**: re-read per request (track), or pushed live
   (territory).
10. **Transport for account and admin operations**: both apps use their own
    musli-web WebSocket protocol, which the library cannot share as-is.
11. **Frontend detection of an ended session**: track has it, territory has not.
12. **Storage schema**: same engine, different columns and timestamp encodings.

Section 3 settles each of these. Items 1, 4, 6, 10 and 12 are also listed as
open questions in section 5, because they change user-visible behaviour or the
shape of the library.

## 2. Layered API

### 2.1 Layout and features

The crate stays a single package, `yew-auth` (lib name `auth`), with features.
The server-only dependencies (bcrypt, aws-lc-rs, tokio, axum, reqwest, sqll) and
the browser-only ones (yew, gloo-net, web-sys) sit behind disjoint features.
That keeps trunk's wasm build of a frontend crate free of server code. Both apps
already compile their frontend crate on the host under
`cargo clippy --workspace`, so a host build with both feature sets enabled at
once must also compile; CI covers that with `--all-features`. The open
questions list the split into a workspace as the alternative.

| Feature | Enables | Pulls in |
|---|---|---|
| *(none)* | `types`: `UserId`, `Role`, `Access`, `Method`, wire types, `validate_password`, `normalize_email`, `MIN_PASSWORD_LEN` | serde, jiff |
| `musli` | `Encode`/`Decode` on the wire types, so an app can embed them in its own WS messages | musli-core |
| `server` | `core` (hashing, ids, cookies, tokens), `Store`, `Auth`, throttle, events, bootstrap | bcrypt, hmac, sha2, rand, cookie, http, tokio (sync, time) |
| `cloudflare` | `server` + the Cloudflare Access provider | aws-lc-rs, reqwest |
| `google` | `server` + the Google OAuth provider | reqwest, url, lru |
| `axum` | `server` + extractors, routes, WS session guard | axum 0.8 |
| `sqll` | `server` + `SqllStore`, a `Store` over SQLite with a fixed schema and its migration SQL (see open question 4) | sqll 0.14 |
| `yew` | components, context, hook, HTTP client | yew 0.23, gloo-net, web-sys, wasm-bindgen-futures |

The modules are `auth::{types, core, store, cloudflare, google, axum, sqll, yew}`,
and the most-used names are re-exported at the root. The existing
`cloudflare.rs`, `cookie.rs`, `password.rs` and `session.rs` move under `core`
and `cloudflare` largely unchanged.

### 2.2 Types (always available)

```rust
pub struct UserId(pub u64);              // apps convert to and from their own u64 ids
pub enum Role { Admin, Regular }         // serde lowercase, as both apps
pub enum Access { Pending, Active, Revoked }
pub enum Method { Password, Google }     // the user's stored credential; see 3.4

/// What the frontend and the admin pages see of a user.
pub struct UserInfo {
    pub id: UserId,
    pub login: Option<String>,           // see open question 1
    pub email: Option<String>,
    pub role: Role,
    pub access: Access,
    pub method: Method,
    pub has_password: bool,
    pub created_at: Timestamp,
}
impl UserInfo { pub fn name(&self) -> &str; pub fn is_admin(&self) -> bool; }

/// A user in the admin list.
pub struct UserEntry { pub user: UserInfo, pub link_expires_at: Option<Timestamp> }

/// What the sign-in page offers, from `GET /api/auth/config`.
pub struct AuthConfig {
    pub password: bool,
    pub google: bool,
    pub cloudflare: bool,     // this request carries Access credentials that map to a user
    pub logins: bool,         // the app uses login names (track) or only emails (territory)
}

pub struct LoginRequest { pub login: String, pub password: String }
pub struct RegisterInfo { pub login: Option<String>, pub email: Option<String>, pub google: bool }
pub struct RegisterRequest { pub password: String }
pub struct Link { pub token: String, pub expires_at: Timestamp }   // shown once
pub struct NewUser { pub login: Option<String>, pub email: Option<String>, pub role: Role }
pub struct UserChange { pub login: Option<Option<String>>, pub email: Option<Option<String>>, pub role: Option<Role> }
pub struct PasswordChange { pub old_password: Option<String>, pub new_password: String }
pub struct CloudflareConfig { pub enabled: bool, pub team_domain: String, pub audience: String,
                              pub trust_email_header: bool, pub verify_jwt: bool }  // track's api::CloudflareAccess
pub enum AuthError { Unauthorized, Forbidden, NotFound, Gone, TooManyRequests,
                     Conflict(Conflict), Invalid(String) }   // JSON body of 4xx responses
pub enum Conflict { Login, Email }
```

### 2.3 Server core (`server`)

Most of these primitives already exist:

- `hash_password`, `verify_password` and `dummy_hash` hash and check passwords.
- `new_session_id` and `new_token` make ids.
- `session_cookie` and `verify_session_cookie` build and check the cookie, now
  with a `CookieConfig`.
- `SESSION_LIFETIME` and `TOKEN_LIFETIME` set the lifetimes.

The new piece is the service, `Auth`, which is `Clone` and is a single `Arc`
inside:

```rust
let auth = Auth::builder(store, session_key)
    .cookie(CookieConfig { name: "track_session", secure: Secure::Auto })
    .logins(true)                       // accept login names, not only emails
    .trusted_proxies(&args.trusted_proxy)
    .cloudflare(cloudflare_config)      // feature `cloudflare`; Option, changeable later
    .google(google_config)              // feature `google`; Option
    .impersonation(true)                // territory
    .build();

auth.set_cloudflare(Option<CloudflareConfig>);   // track applies Settings changes
auth.bootstrap_admin(&BootstrapAdmin { email, login, public_url }).await?;  // no-op when users exist
auth.load_or_create_key(&store).await?;          // helper over Store::config_get/set
auth.events() -> broadcast::Receiver<AuthEvent>;
```

The operations behind the routes are public methods too, so an app can call
them from its own handlers or tests: `sign_in_password`, `sign_in_cloudflare`,
`sign_out`, `register`, `issue_link`, `revoke_link`, `sign_out_everywhere`,
`revoke_access`, `set_role`, `update_user`, `delete_user`, `change_password`
and `impersonate`. Each one enforces the rules in section 3: who may act on
whom, never on oneself, token usability, and ending sessions.

```rust
/// Sent whenever auth state changes, for open sockets and live admin views.
pub enum AuthEvent {
    SessionEnded(SessionId),
    UserSessionsEnded { user: UserId, keep: Option<SessionId> },   // revoke, delete, credential change
    UserChanged(UserInfo),                                         // role, email, login, access
    UserCreated(UserInfo),
    UserDeleted(UserId),
}
```

The throttle is track's `LoginThrottle` as it stands: per address and per login,
trusted proxies, and IPv6 grouped by /64. It applies to password sign-in.

### 2.4 Storage (`server`)

There is one trait, because several operations must be atomic across users,
sessions and tokens. It uses `async fn` in the trait with `Send` futures, and
`Auth` erases it internally, so neither `Auth` nor the extractors carry a type
parameter. Every method takes the time from the caller, which keeps tests
deterministic.

```rust
pub trait Store: Send + Sync + 'static {
    // Users
    async fn user(&self, id: UserId) -> Result<Option<User>>;
    async fn user_by_email(&self, email: &str) -> Result<Option<User>>;    // normalized
    async fn user_by_login(&self, login: &str) -> Result<Option<User>>;
    async fn user_by_google_sub(&self, sub: &str) -> Result<Option<User>>;
    async fn users(&self, now: Timestamp) -> Result<Vec<(User, Option<Timestamp>)>>;  // with live link expiry
    async fn user_count(&self) -> Result<u64>;
    async fn create_user(&self, new: &NewUser, now: Timestamp) -> Result<Result<User, Conflict>>;
    async fn update_user(&self, id: UserId, change: &UserChange) -> Result<Result<Option<User>, Conflict>>;
    async fn delete_user(&self, id: UserId) -> Result<bool>;               // sessions and tokens go with it
    /// Sets the credential (password hash, or Google subject and email),
    /// marks the user active, and deletes the user's sessions except `keep`.
    async fn set_credential(&self, id: UserId, cred: &Credential, keep: Option<&str>) -> Result<bool>;
    /// Binds a Google subject only if the user has none or the same one.
    async fn bind_google_sub(&self, id: UserId, sub: &str) -> Result<bool>;
    async fn set_access(&self, id: UserId, access: Access) -> Result<bool>;
    /// access=revoked, password cleared, unused tokens used up, sessions deleted.
    async fn revoke(&self, id: UserId, now: Timestamp) -> Result<bool>;

    // Sessions
    async fn create_session(&self, s: &Session) -> Result<()>;            // may prune expired ones
    async fn session(&self, id: &str) -> Result<Option<Session>>;
    async fn delete_session(&self, id: &str) -> Result<()>;
    async fn delete_sessions(&self, user: UserId, keep: Option<&str>) -> Result<()>;
    async fn delete_expired_sessions(&self, now: Timestamp) -> Result<()>;

    // Tokens
    /// Inserts the token and uses up the user's other unused ones.
    async fn create_token(&self, t: &Token) -> Result<()>;
    async fn token(&self, id: &str) -> Result<Option<Token>>;
    async fn use_up_tokens(&self, user: UserId, now: Timestamp) -> Result<()>;
    /// In one transaction: marks the token used if it is still unused (else
    /// returns false), sets the credential, activates the user, deletes all of
    /// the user's sessions and creates `session`.
    async fn redeem_token(&self, token: &str, cred: &Credential, session: &Session, now: Timestamp) -> Result<bool>;

    // Settings
    async fn config_get(&self, key: &str) -> Result<Option<String>>;     // session_key
    async fn config_set(&self, key: &str, value: &str) -> Result<()>;
}

pub struct User { pub id: UserId, pub login: Option<String>, pub email: Option<String>, pub role: Role,
                  pub access: Access, pub method: Method, pub password_hash: Option<String>,
                  pub google_sub: Option<String>, pub created_at: Timestamp }
pub struct Session { pub id: String, pub user: UserId, pub created_at: Timestamp, pub expires_at: Timestamp }
pub struct Token { pub id: String, pub user: UserId, pub kind: TokenKind, pub expires_at: Timestamp, pub used_at: Option<Timestamp> }
pub enum TokenKind { Registration, Reset }
pub enum Credential { Password(String /* hash */), Google { sub: String, email: String } }
```

The library ships `MemoryStore`, used by its own tests and examples, and,
behind `sqll`, `SqllStore`, which works over tables `users`, `sessions` and
`auth_tokens` with a documented set of columns and the migration SQL. An app
keeps its own columns and foreign keys on `users` (track's per-user data,
territory's groups), and the store reads and writes only its own columns (see
open question 4).

### 2.5 Providers

- **Password** (`server`). The user is found by login or email. With
  `logins(false)`, the user is found by email only. An unknown user and a user
  without a password are verified against the dummy hash, in `spawn_blocking`.
  The throttle applies. Only active users get a session.
- **Cloudflare Access** (`cloudflare`). This is the existing `cloudflare::Access`
  (JWT check against the team's keys, an optional email header, key caching,
  rate-limited refetch), plus track's identity glue: runtime reconfiguration,
  log-once warnings, and `presents_access`. The verified email finds the user,
  and users are never created. Signing in mints an ordinary session, as track
  does, through an explicit `POST`, so Access is consulted only when signing in.
  A *pending* user who signs in through Access becomes active, because Access
  has vouched for the email (this keeps track's behaviour). A revoked user is
  refused.
- **Google OAuth** (`google`). This is territory's flow, moved as-is:
  - the authorization-code flow with an in-memory pending-state LRU (10 minutes,
    10 000 entries);
  - the `tokeninfo` check, which needs `email_verified`;
  - sign-in by `google_sub`, with a one-time email match for Google users who
    have no subject yet;
  - registration through a link, and "switch to Google" from the account page;
  - `ensure_unbound`, so one Google account binds only one user.

  The provider takes a `GoogleConfig { client_id, client_secret, redirect_url }`.
  The callback redirects to `/` on success, or to `/?error=auth-failed` or
  `/?error=user-not-found` on failure.

### 2.6 axum integration (`axum`)

```rust
// Extractors; each needs `Auth: FromRef<S>`.
SignedIn { user: User, session: Session }   // 401 without a live session of an active (or impersonated pending) user
Admin(SignedIn)                             // 403 unless the user is an admin *now*
MaybeSignedIn(Option<SignedIn>)
LiveSession(SessionId)                      // liveness only, cached for 10 s (territory's tile cache), for hot asset routes

// Routes, merged into the app's router.
pub fn routes<S>() -> Router<S> where Auth: FromRef<S>, S: Clone + Send + Sync + 'static;

// WebSocket: resolves when the socket's session has ended, for the app's select! loop.
let mut guard = auth.guard(&signed_in);
tokio::select! {
    end = guard.ended() => break,            // logout, revoke, credential change, delete, expiry
    change = guard.changed() => { /* UserInfo: role/email changed, e.g. reload groups, admin flag */ }
    ...
}
```

The guard subscribes to `AuthEvent`s. It sleeps until the session expires, as
territory does. On broadcast lag, and every 5 minutes as track does, it
re-checks the session, so a session deleted by another process still ends the
socket.

The routes are all JSON. Their errors are `AuthError` with the matching status:
401, 403, 404, 409, 410, 429, or 400 with a message.

| Route | Who | What |
|---|---|---|
| `GET /api/auth/config` | anyone | `AuthConfig` (replaces track's `GET /api/auth/cloudflare` and the auth half of territory's `/api/config`) |
| `GET /api/auth/me` | signed in | `UserInfo` |
| `POST /api/auth/login` | anyone | `LoginRequest` → `UserInfo` + cookie; throttled |
| `POST /api/auth/cloudflare` | anyone | → `UserInfo` + cookie |
| `GET /api/auth/google`, `/google/register/{token}`, `/google/link` | anyone / anyone / signed in | redirect to Google |
| `GET <redirect_url path>` (default `/api/auth/google/redirect`) | Google | callback; cookie + redirect |
| `POST /api/auth/logout` | anyone | 204, deletes the session, clears the cookie |
| `GET /api/auth/register/{token}` | anyone | `RegisterInfo`; 404 unknown, 410 used or expired |
| `POST /api/auth/register/{token}` | anyone | `RegisterRequest` → `UserInfo` + cookie; ends the user's other sessions |
| `POST /api/auth/account/password` | signed in | `PasswordChange` → `UserInfo`; keeps this session, ends the others; switches a Google user to password |
| `PATCH /api/auth/account` | signed in | `UserChange` (own login/email; not role; not email of a Google user) → `UserInfo` |
| `GET /api/auth/users` | admin | `Vec<UserEntry>` |
| `POST /api/auth/users` | admin | `NewUser` → `UserEntry` + `Link` |
| `PATCH /api/auth/users/{id}` | admin | `UserChange` → `UserInfo` (not own role) |
| `DELETE /api/auth/users/{id}` | admin | not self |
| `POST`/`DELETE /api/auth/users/{id}/link` | admin | issue (`Link`) / use up the link |
| `POST /api/auth/users/{id}/sign-out` | admin | sign out everywhere (track's behaviour) |
| `POST /api/auth/users/{id}/revoke` | admin | revoke access (territory's behaviour); not self |
| `POST /api/auth/users/{id}/impersonate` | admin, if enabled | cookie for a session as that user; not self, not revoked |

The frontend route `/register/{token}` that links point to is unchanged in both
apps. Links already handed out therefore keep working, because only the API
path moves (from `/api/register/{token}` to `/api/auth/register/{token}`).

### 2.7 Yew components (`yew`)

The components render plain semantic HTML with stable `auth-*` class names and
take a `class` prop. Each app styles them with its own CSS. They talk to the
server through `auth::yew::http`, which uses gloo-net with same-origin cookies,
so the library does not depend on the app's gloo version.

- `<AuthProvider>` is the gate.
  - It fetches `/api/auth/config` and `/api/auth/me`.
  - It shows a splash with Retry while loading or when the server is
    unreachable.
  - It shows `<SignIn>` when signed out, and `<Register>` on `/register/{token}`.
    Otherwise it renders its children with an `AuthContext`.
  - Props: `title`, and `signed_out_notice` for the "session has ended" text.
  - It replaces track's `Root` gating and territory's `Root` auth state.
- `use_auth() -> AuthContext` gives `user: Rc<UserInfo>`, `config`,
  `is_admin()`, `sign_out()`, `refresh()`, `set_user(UserInfo)` and
  `check_session()`.
  - `check_session()` is what the app calls when its socket closes. A 401 there
    shows `<SignIn>` with "Your session has ended. Sign in again." This is
    track's behaviour, and territory gains it.
- `<SignIn>` offers the enabled methods: a login/email + password form, "Sign
  in with Cloudflare" when `config.cloudflare` is set, and "Sign in with Google"
  when `config.google` is set. It shows `?error=` messages and strips them from
  the URL.
- `<Register token>` shows the login and email read-only, then the password
  and confirmation fields, then "Sign up with Google" when it is enabled.
- `<AccountPanel>` covers the role, login (when `logins`), email, change or set
  password, switching to or linking Google, and sign out. The app wraps it in a
  page (track) or a modal (territory).
- `<UserMenu on_account on_admin>` shows the user's name, Account, Users (for
  admins only) and Sign out.
- `<AdminUsers>` covers:
  - the user list, with the filter and paging as props plus `on_query_change`,
    so territory can keep them in its URL;
  - status icons and the link state;
  - add user, edit login/email, role select, new or revoked link (shown once,
    with Copy), sign out everywhere, revoke access, impersonate (when enabled)
    and delete.

  Its props are `me`, `on_impersonate`, `refresh: u64` (bump it to refetch when
  the app forwards an `AuthEvent`), and `extra: Callback<UserInfo, Html>` for
  app columns such as territory's groups.
- `<CloudflareSettings value on_change>` is track's Settings page form: setup
  instructions, the fields, and a warning when the header is trusted without
  verifying the token. The app stores the value in its own settings and calls
  `auth.set_cloudflare`.

## 3. Decisions

1. **Identity.** A user has an optional unique `login` and an optional unique
   `email`, and needs at least one of them. Password sign-in tries the login,
   then the normalized email. `logins(false)` (territory) hides login fields and
   requires an email. Cloudflare and Google always match on email. This
   preserves both apps without rewriting identities. *Open question 1.*
2. **Account state.** Adopt territory's `Access`.
   - Pending users cannot sign in, except through Cloudflare Access, which
     activates them (this preserves track).
   - Revoked users cannot sign in by any path.
   - A new link restores a revoked user.
   - Track migrates every existing user to `active`.
3. **Revoke vs sign out.** Keep both, under distinct names: "Sign out
   everywhere" (track's `RevokeUserAccess`) and "Revoke access" (territory's).
   Neither app loses an action.
4. **Credentials per user.** Adopt territory's exclusive `Method`.
   - A password user can switch to Google, which clears the password and binds
     the subject.
   - A Google user can set a password, which switches them back.
   - Cloudflare Access is not a stored credential. It identifies any active or
     pending user by email, whatever their method.
   - Both of these changes end the user's other sessions.

   *Open question 2.*
5. **Tokens.** Adopt territory's two kinds, chosen when the link is issued
   (`Reset` for active users, `Registration` otherwise), with its usability
   rule. Issuing a link uses up the user's earlier links. Links are single use
   and last 7 days. For track this changes nothing visible.
6. **First admin.** `Auth::bootstrap_admin` creates a pending admin from an
   email or login when there are no users, and logs the link. *Open
   question 3.*
7. **Cookie.** The cookie name is configurable. `Secure` is set automatically
   from `X-Forwarded-Proto` (track), with `Secure::Always` and `Secure::Never`
   also available. `Expires` is not set; `Max-Age` alone is kept. The value
   format is unchanged, so existing sessions survive the move.
8. **Expired sessions** are pruned on session creation (track) and by
   `auth.prune()` for apps that want a timer. Reads always check the expiry.
9. **Throttling and dummy-hash timing** apply to every password sign-in.
   Territory gains both.
10. **WS end-of-session**: an expiry timer, event matching, a re-check on lag and
    a 5-minute re-check, which is the union of the two apps.
11. **Role changes** apply per request (`Admin` re-reads the user) and are pushed
    as `AuthEvent::UserChanged`. Sockets see them through `guard.changed()`.
12. **Impersonation** is territory's behaviour, behind `.impersonation(true)`.
13. **Transport.** Account and admin operations move to the JSON routes above,
    out of each app's WebSocket protocol. Live updates reach the admin page
    through the app forwarding `AuthEvent`s. *Open question 4.*
14. **Storage** goes through the `Store` trait. A `SqllStore` ships too. *Open
    question 5.*
15. **Timestamps** in the library are `jiff::Timestamp`. `SqllStore` stores
    them as INTEGER milliseconds, as track does (territory migrates its auth
    columns; see open question 5).

## 4. Wiring up each app

### 4.1 track

**Server** (`crates/track`):

```toml
yew-auth = { path = "../../../yew-auth", features = ["axum", "cloudflare", "sqll"] }
```

```rust
let store = auth::sqll::SqllStore::new(db.pool());          // or TrackStore(db) implementing Store
let key = auth::load_or_create_key(&store).await?;
let auth = Auth::builder(store, key)
    .cookie(CookieConfig::new("track_session"))
    .logins(true)
    .trusted_proxies(trusted_proxies)
    .cloudflare(config.cloudflare_access.enabled.then(|| config.cloudflare_access.clone().into()))
    .build();
// on Settings change: auth.set_cloudflare(...)
// router: .merge(auth::axum::routes())
// ws_handler: `user: SignedIn`, `let mut guard = state.auth.guard(&user)` in the select! loop,
//   replacing the revocation receiver and session_check interval.
// ws authorize: `requires_admin` keeps the app's own admin requests; is_admin uses auth.
```

The migration adds `access` (all existing users become `active`), `method`
(`password`) and `google_sub` to `users`. It renames `login_tokens` to
`auth_tokens` and adds `kind`. The `root`/`root` seed stays only for databases
that already have it.

**Deletes or shrinks:**

| Server | Frontend |
|---|---|
| `identity.rs`: all but the app's `AuthUser` → `SignedIn` alias | `page/login.rs` |
| `login_throttle.rs` | `page/register.rs` |
| `http.rs`: the whole file | `page/account.rs` (its route renders `<AccountPanel>`) |
| `db/users.rs`: sessions, tokens, users CRUD and `session_key` (about 550 of 659 lines; `default_owner` stays) | `page/users.rs` (its route renders `<AdminUsers>`) |
| `ws/users.rs` | `root.rs` (becomes `<AuthProvider>`) |
| the user arms of `ws.rs`'s dispatch, `Refused` variants, `session_valid` | auth functions in `http.rs` |
| `api`: `User`, `UserRole`, `CloudflareAccess` (becomes `auth::CloudflareConfig`), the 10 user endpoints and their request/response types, `LoginLink` | Cloudflare page body in `page/settings.rs` (renders `<CloudflareSettings>`) |
| | `is_admin(ctx)` (becomes `use_auth().is_admin()`) |

### 4.2 territory

**Server** (`crates/territory`):

```toml
yew-auth = { path = "../../../yew-auth", features = ["axum", "google", "sqll"] }
```

```rust
let auth = Auth::builder(store, key)
    .cookie(CookieConfig::new("territory_session"))
    .logins(false)
    .google(google_config)               // from the existing GOOGLE_* args
    .impersonation(true)
    .build();
if let Some(email) = &args.bootstrap_email {
    auth.bootstrap_admin(&BootstrapAdmin::email(email).public_url(args.public_url.clone())).await?;
}
// router: .merge(auth::axum::routes()); /api/config keeps only `title`
// tiles: `LiveSession` extractor replaces the cookie check and SessionCache
// ws: `SignedIn` + guard; guard.changed() updates `admin` and reloads groups;
//   forward AuthEvent::{UserCreated, UserChanged, UserDeleted} into the app broadcast
//   so the admin page's `refresh` and the groups column stay live.
```

The migration renames `auth_method` `plain` → `password`, renames
`registration_tokens` to `auth_tokens`, and converts the auth timestamps to
INTEGER ms (`SqllStore`'s schema).

**Deletes or shrinks:**

| Server | Frontend |
|---|---|
| `auth.rs` and `auth/tests.rs` (the tests move to the library) | `login_page.rs` |
| `session.rs` and its tests | `register_page.rs` |
| `bootstrap.rs` and its tests | `account_modal.rs` (the modal wraps `<AccountPanel>`) |
| `google_oauth.rs` | `admin_users.rs` (wraps `<AdminUsers extra=groups>`) |
| `http.rs`: all but `config` | `user_info.rs` |
| `proxy.rs`: `SessionCache` and the cookie check | auth functions in `http.rs`, auth state in `root.rs` |
| `events.rs`: `SessionEnded` | |
| `ws/users.rs`: all but group handling | |
| `ws.rs`: the expiry timer and the `SessionEnded` / lag handling | |
| `db`: user, session and token functions and their tests (they move to `SqllStore`) | |
| `api`: `UserRole`, `AuthMethod`, `UserAccess`, `UserInfo`, the user endpoints, `QueryError`, `validate_password` | |

**What territory gains:** throttling, constant-time unknown-user handling,
`Secure` cookies behind HTTPS, "sign out everywhere", detection of an ended
session in the frontend, and Cloudflare Access if it is ever put behind Access.

### 4.3 army

army has a placeholder `Session {}` in `web.rs`. It would take `SignedIn` on
the upgrade and `<AuthProvider>` in the frontend, and implement nothing itself.
This is a useful check on whether the API is small enough.

## 5. Open questions

The user approved the design on 2026-10-14 and chose the recommended option
for every question below, marked **(chosen)**. The other options stay for the
record.

1. **User identity: login names, emails, or both?**
   - **(chosen) Both optional, at least one required.** track keeps logins
     (and `root` without an email). territory turns logins off and stays
     email-only. This costs one optional column and a builder flag.
   - Email required everywhere. This is simpler, but track's `root` and any
     email-less users need an email, and signing in by login name goes away.
   - Login required everywhere. territory would copy emails into logins and
     show both.
2. **Can one user have both a password and Google?**
   - **(chosen) No: one method, switchable (territory's model).** It is
     already tested in territory and is the smallest model. Cloudflare Access
     still works for any user by email.
   - Yes: link and unlink Google alongside a password. This is more flexible,
     but adds account UI and rules (for example, never unlink the last method).
3. **track's first admin on a fresh install.**
   - **(chosen) A bootstrap link** (`--bootstrap-admin <email|login>`,
     logged at startup), as territory does. No default password.
   - Keep seeding `root` / `root` for new track databases.
4. **Transport for account and admin operations.**
   - **(chosen) The library's own JSON routes.** The components are then
     self-contained, and both apps delete their WS user endpoints. Live admin
     updates come from the app forwarding `AuthEvent`s.
   - Keep them on each app's musli-web WebSocket. The library would provide
     handler functions and musli wire types, and each app keeps its own
     endpoint definitions and components wiring. This is more code per app,
     and the components would need an app-supplied client trait.
5. **Storage: ship a SQLite store, or traits only?**
   - **(chosen) Both.** The `Store` trait is the API, and a `sqll`
     feature ships `SqllStore` over a documented schema with migration SQL,
     because both apps use sqll 0.14 and would otherwise write nearly the same
     ~500 lines. Each app migrates its auth columns to that schema once
     (territory converts timestamps to INTEGER ms).
   - Traits only. Each app implements `Store` over its existing schema and
     keeps its timestamp encoding, with no schema migration but duplicated
     code.
6. **Crate layout.**
   - **(chosen) One crate with disjoint features**, as now.
   - A workspace: `yew-auth` (types), `yew-auth-server`, `yew-auth-yew`. This
     isolates wasm and server dependency trees at the cost of three manifests
     and path dependencies.

## 6. Implementation cards

The board's two original cards, 00170ba3 (server side) and ec24345c (Yew
components), were too large and are replaced by the breakdown below, which
lets workers run in parallel.

| # | Card | Depends on | Notes |
|---|---|---|---|
| A | **Types and feature layout**: the feature table; `types` module (`UserId`, `Role`, `Access`, `Method`, wire types, `AuthError`, validation); `musli` feature; move existing modules under `core`/`cloudflare`; CI over `--no-default-features`, each feature, `--all-features`, and `--target wasm32-unknown-unknown --features yew` | design | small; unblocks everything |
| B | **`Store` trait, `MemoryStore`, and the `Auth` service**: builder, cookie config, key helper, throttle (from track), `AuthEvent`, bootstrap, and all operations with the rules of section 3; port territory's `auth/tests.rs` and `bootstrap/tests.rs` and track's throttle tests against `MemoryStore` | A | the core of the server side |
| C | **`SqllStore`**: schema, migration SQL, implementation; run B's store tests against it | B | kept: open question 5 chose it |
| D | **Cloudflare provider**: track's identity glue (runtime config, log-once warnings, pending → active) on top of the existing `cloudflare` module | B | can run alongside E and F |
| E | **Google provider**: port territory's `google_oauth.rs` and its state tests | B | can run alongside D and F |
| F | **axum integration**: extractors, `routes()`, `guard()` for sockets, `LiveSession` cache; route-level tests with `MemoryStore` and `tower::ServiceExt` | B (routes for D and E are wired when those land, behind their features) | |
| G | **Yew foundation**: `http` client, `AuthProvider`, `AuthContext` / `use_auth`, `SignIn`, `Register` | A (and F's route shapes, fixed by this document) | can start after A |
| H | **Yew account and admin**: `AccountPanel`, `UserMenu`, `AdminUsers`, `CloudflareSettings` | G | |
| I | **Example app** in `examples/`: axum + Yew with `MemoryStore`, all three methods, for manual checks and as the consumers' reference | F, H | |

After these cards, moving track and territory onto yew-auth belongs on their
own boards (section 4 is their checklist). This board does not change either
repository.
