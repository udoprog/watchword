# watchword

[<img alt="github" src="https://img.shields.io/badge/github-udoprog/watchword-8da0cb?style=for-the-badge&logo=github" height="20">](https://github.com/udoprog/watchword)
[<img alt="crates.io" src="https://img.shields.io/crates/v/watchword.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/watchword)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-watchword-66c2a5?style=for-the-badge&logoColor=white&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">](https://docs.rs/watchword)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/udoprog/watchword/ci.yml?branch=main&style=for-the-badge" height="20">](https://github.com/udoprog/watchword/actions?query=branch%3Amain)

Authentication for axum servers and Yew frontends: password, Cloudflare
Access and Google sign-in, sessions and user management.

The design, including the full API each layer grows into, is in
[`docs/design.md`].

<br>

## Features

Each layer sits behind a cargo feature, so an app takes only what it uses.
Server-only and browser-only dependencies never share a feature, so a wasm
frontend can take `yew023` without pulling in server code. Only `std` is on
by default. On docs.rs, items that need a feature are marked with it.

The crate is `no_std`. With `default-features = false` and neither `std`
nor `alloc`, it has only the plain types (`UserId`, `Role`, `Access`,
`Method`, `Conflict`, `AuthConfig`, `MIN_PASSWORD_LEN`, `is_same_origin_path`); `alloc` adds the
rest of [`types`]. The server layers and `yew023` imply `std`.

A dependency that is not yet 1.0 and appears in the API is named after its
version: its feature (and module, if it has one) is `axum08` for axum
0.8, `sqll015` for sqll 0.15, `musli02` for musli 0.2, `musliweb05` for
musli-web 0.5, `phrasebook02` for phrasebook 0.2 and `yew023` for yew
0.23. A later version is added beside it, so a watchword upgrade never
forces an app onto a new axum, sqll, musli, musli-web, phrasebook or yew,
and an app moves when it chooses.

| Feature | Module | What it provides |
|---|---|---|
| *(none)* | [`types`] | `UserId`, `Role`, `Access`, `Method`, `Conflict`, `AuthConfig`, `MIN_PASSWORD_LEN` and `is_same_origin_path`, from the [watchword-core] crate |
| `alloc` | [`types`] | the wire types (`UserInfo`, `LoginRequest`, `CreatedUser`, ...), `AuthError` and its `Invalid` reasons, `validate_password`, `normalize_email` |
| `std` *(default)* | | `alloc`, and the standard library for the dependencies that have it |
| `musli02` | | musli 0.2 `Encode`/`Decode` on the types |
| `musliweb05` | [`musliweb05`] | for musli-web 0.5: the account, user-management and Cloudflare Access settings endpoints and the `AuthBroadcast` of live auth changes, as API types an app carries on its own musli-web WebSocket, with their ids pinned in 32000–32255; with `axum08`, `Connection`, which answers those endpoints on one socket and turns `AuthEvent`s into the updates it may see; with `yew023`, `AuthContext::set_socket`, through which the components follow those broadcasts (implies `alloc` and `musli02`) |
| `server` | [`core`], [`store`] | bcrypt password hashing with `dummy_hash` timing, session ids and link tokens, HMAC-signed session cookies; the `Auth` service (sign-in, registration links, user management, sign-in throttle, `AuthEvent`s and actor-attributed `AuditEvent`s, bootstrap admin) and `Auth::guard` for WebSocket sessions; the `Store` trait and `MemoryStore` (implies `std`) |
| `cloudflare` | [`cloudflare`] | Cloudflare Access JWT verification with a pluggable `KeyFetcher`; `Auth::cloudflare` and `Auth::set_cloudflare`, which keep the settings in the store; with `axum08`, admin routes for them (implies `server`) |
| `google` | [`google`] | Google OAuth: `GoogleConfig::new` for `AuthBuilder::google`; with `axum08`, `routes()` serves its start, registration, account-switch and callback routes (implies `server`) |
| `axum08` | [`axum08`] | for axum 0.8: the `SignedIn`, `Admin`, `MaybeSignedIn` and `LiveSession` extractors and `routes()` for the `/api/auth` JSON routes, plus the Cloudflare and Google routes when those features are on (implies `server`) |
| `sqll015` | | sqll 0.15 `BindValue`, `Bind` and `FromColumn` on `UserId` (an integer with the same bits), `Role`, `Access` and `Method` (their names), from the [watchword-core] crate, for an app's own `Store` over SQLite such as [`examples/sqll-store`]; no storage of its own |
| `test-util` | [`store_suite!`], [`google::fake`] | for an app's tests: `Auth::test_user` and `Auth::test_session`, an active user and a session without signing in; `store_suite!`, watchword's store conformance suite, to run over the app's own `Store`; with `google`, `AuthBuilder::google_endpoints`, and with `google` and `axum08` also `FakeGoogle`, a local fake Google to sign in through offline (implies `server`) |
| `phrasebook02` | [`phrasebook02`] | `L10N`, watchword's messages (the text of the `yew023` components) as a [phrasebook] 0.1 catalog, for a native tool such as an app's localization checker that needs them without building yew, from the [watchword-core] crate (implies `std`) |
| `yew023` | [`yew023`] | for yew 0.23: `AuthProvider`, `use_auth`, `SignIn`, `Register`, `AccountPanel`, `UserMenu`, `AdminUsers`, `AdminCloudflare`, `CloudflareSettings`, the `http` client and `L10N`, the components' messages as a [phrasebook] catalog, from the [watchword-yew023] crate (implies `std` and `phrasebook02`) |

The most-used names that do not depend on a versioned feature are
re-exported at the crate root.

<br>

## Using it

Add it from crates.io with the features each crate needs. An app whose
frontend talks to its server over a [musli-web] 0.5 WebSocket, as the
[example app](#example-app) does, takes `musliweb05` on both sides: the
server answers the components' requests and sends them live updates on
that socket, and the frontend hands the socket to the components. An app
that uses only HTTP leaves it out of both.

```toml
# The server crate.
[dependencies]
watchword = { version = "0.3", features = ["axum08", "cloudflare", "google", "musliweb05"] }

[dev-dependencies]
watchword = { version = "0.3", features = ["test-util"] }
```

```toml
# The frontend crate, built for wasm32-unknown-unknown.
[dependencies]
watchword = { version = "0.3", features = ["yew023", "musliweb05"] }
```

Take only the sign-in methods the app offers: `cloudflare` and `google`
each add one, and password sign-in is always there. `test-util`, under
`dev-dependencies`, gives the app's tests users and sessions without going
through sign-in, and the store conformance suite.

<br>

## Storage

watchword keeps users, sessions, registration links and settings through
the [`Store`] trait, which each app implements over its own database, with
its own tables and migrations: the shape of user data differs between
apps, and only the app knows how to fill its own columns. watchword ships
no tables or migrations, only `MemoryStore`, which keeps everything in
memory, for tests and trying things out.

Start from [`examples/sqll-store`], a complete `Store` over SQLite with
sqll 0.15 (taking the `sqll015` feature), and change its tables to the
app's. The [`Store`] docs say what each method must do atomically, and the
store conformance suite, [`store_suite!`] (feature `test-util`), checks
the result from the app's tests:

```sh
cargo test --example sqll-store --features test-util,sqll015
```

The examples here refer to the crate as `watchword`. An app may give the
dependency a shorter key, such as `auth = { package = "watchword", ... }`,
and then writes `auth::` where these docs write `watchword::`.

Then build an `Auth` over a store and serve its routes, as the [`axum08`]
module shows, and wrap the frontend in `AuthProvider`, as the [`yew023`]
module shows.

<br>

## Example app

[`examples/app`] is an axum server and a Yew frontend wired up with all three
sign-in methods, `MemoryStore` and a musli-web WebSocket held open for the
session, which carries the components' account and admin requests and live
updates beside the app's own API (`musliweb05`): a reference for apps taking
the library, and a way to try the components by hand. It is its own cargo
workspace, so it adds nothing to the library's builds or lockfile.

Build the frontend with [trunk], then run the server, which serves it:

```sh
cd examples/app/frontend && trunk build
cd examples/app && cargo run -p watchword-example-server -- --bind 127.0.0.1:8080
```

The server prints a registration link for the bootstrap admin (`admin` by
default, `--bootstrap-admin NAME` to change it); open it to choose a password
and sign in. Everything is in memory, so a restart starts over. Google sign-in
is on when `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` are set, with the
OAuth client's redirect URL at `PUBLIC_URL/api/auth/google/redirect`
(`--public-url`, by default `http://` plus the bind address). Cloudflare Access
is configured on the app's Settings page, which watchword serves, or from
`CLOUDFLARE_TEAM_DOMAIN` and `CLOUDFLARE_AUDIENCE` until saved there; `CLOUDFLARE_TRUST_EMAIL_HEADER=1` accepts Access's email
header alone, for local testing only. `--help` lists the options.

trunk builds with the `wasm-bindgen` CLI matching `examples/app/Cargo.lock`,
downloading it unless it is installed or already in trunk's cache.

[`axum08`]: https://docs.rs/watchword/latest/watchword/axum08/index.html
[`cloudflare`]: https://docs.rs/watchword/latest/watchword/cloudflare/index.html
[`core`]: https://docs.rs/watchword/latest/watchword/core/index.html
[`docs/design.md`]: https://github.com/udoprog/watchword/blob/main/docs/design.md
[`examples/app`]: https://github.com/udoprog/watchword/tree/main/examples/app
[`examples/sqll-store`]: https://github.com/udoprog/watchword/tree/main/examples/sqll-store
[`google::fake`]: https://docs.rs/watchword/latest/watchword/google/fake/index.html
[`google`]: https://docs.rs/watchword/latest/watchword/google/index.html
[`musliweb05`]: https://docs.rs/watchword/latest/watchword/musliweb05/index.html
[`phrasebook02`]: https://docs.rs/watchword/latest/watchword/phrasebook02/index.html
[`store_suite!`]: https://docs.rs/watchword/latest/watchword/macro.store_suite.html
[`store`]: https://docs.rs/watchword/latest/watchword/store/index.html
[`Store`]: https://docs.rs/watchword/latest/watchword/store/trait.Store.html
[`types`]: https://docs.rs/watchword/latest/watchword/types/index.html
[`yew023`]: https://docs.rs/watchword/latest/watchword/yew023/index.html
[musli-web]: https://docs.rs/musli-web
[phrasebook]: https://docs.rs/phrasebook
[trunk]: https://trunkrs.dev
[watchword-core]: https://docs.rs/watchword-core
[watchword-yew023]: https://docs.rs/watchword-yew023
