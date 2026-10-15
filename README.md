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
frontend can take `yew023` without pulling in server code. No feature is on
by default. On docs.rs, items that need a feature are marked with it.

A dependency that is not yet 1.0 and appears in the API is named after its
version: its feature and module are `axum08` for axum 0.8, `sqll014` for
sqll 0.14, `musli01` for musli 0.1 and `yew023` for yew 0.23. A later
version is added beside it, so a watchword upgrade never forces an app onto
a new axum, sqll, musli or yew, and an app moves when it chooses.

| Feature | Module | What it provides |
|---|---|---|
| *(none)* | [`types`] | `UserId`, `Role`, `Access`, `Method`, the wire types (`UserInfo`, `AuthConfig`, `LoginRequest`, `CreatedUser`, ...), `AuthError` and its `Invalid` reasons, `validate_password`, `normalize_email`, from the [watchword-core] crate |
| `musli01` | | musli 0.1 `Encode`/`Decode` on the wire types |
| `server` | [`core`], [`store`] | bcrypt password hashing with `dummy_hash` timing, session ids and link tokens, HMAC-signed session cookies; the `Auth` service (sign-in, registration links, user management, sign-in throttle, `AuthEvent`s, bootstrap admin) and `Auth::guard` for WebSocket sessions; the `Store` trait and `MemoryStore` |
| `cloudflare` | [`cloudflare`] | Cloudflare Access JWT verification with a pluggable `KeyFetcher` (implies `server`) |
| `google` | [`google`] | Google OAuth: `GoogleConfig` for `AuthBuilder::google`; with `axum08`, `routes()` serves its start, registration, account-switch and callback routes (implies `server`) |
| `axum08` | [`axum08`] | for axum 0.8: the `SignedIn`, `Admin`, `MaybeSignedIn` and `LiveSession` extractors and `routes()` for the `/api/auth` JSON routes, plus the Cloudflare and Google routes when those features are on (implies `server`) |
| `sqll014` | [`sqll014`] | `SqllStore`, a `Store` over SQLite on a sqll 0.14 pool (its own, or nested in the app's), its `SCHEMA`, and `docs/sqll/impersonator.sql`, the one-time upgrade for a database created with an older schema (implies `server`) |
| `test-util` | [`google::fake`] | for an app's tests: `AuthBuilder::google_endpoints`, and with `axum08` `FakeGoogle`, a local fake Google to sign in through offline (implies `google`) |
| `yew023` | [`yew023`] | for yew 0.23: `AuthProvider`, `use_auth`, `SignIn`, `Register`, `AccountPanel`, `UserMenu`, `AdminUsers`, `CloudflareSettings` and the `http` client, from the [watchword-yew023] crate |

The most-used names that do not depend on a versioned feature are
re-exported at the crate root.

<br>

## Using it

Add it from crates.io with the features each crate needs. The package and
the library are both named `watchword`; a dependency key of `auth` keeps
code referring to it as `auth`:

```toml
[dependencies]
# Server crate.
auth = { package = "watchword", version = "0.1", features = ["axum08", "cloudflare"] }
# Frontend crate.
auth = { package = "watchword", version = "0.1", features = ["yew023"] }
```

<br>

## Example app

[`examples/app`] is an axum server and a Yew frontend wired up with all three
sign-in methods, `MemoryStore` and a WebSocket held open for the session: a
reference for apps taking the library, and a way to try the components by
hand. It is its own cargo workspace, so it adds nothing to the library's
builds or lockfile.

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
is configured on the app's Settings page, or from `CLOUDFLARE_TEAM_DOMAIN` and
`CLOUDFLARE_AUDIENCE`; `CLOUDFLARE_TRUST_EMAIL_HEADER=1` accepts Access's email
header alone, for local testing only. `--help` lists the options.

trunk builds with the `wasm-bindgen` CLI matching `examples/app/Cargo.lock`,
downloading it unless it is installed or already in trunk's cache.

[`axum08`]: https://docs.rs/watchword/latest/watchword/axum08/index.html
[`cloudflare`]: https://docs.rs/watchword/latest/watchword/cloudflare/index.html
[`core`]: https://docs.rs/watchword/latest/watchword/core/index.html
[`docs/design.md`]: https://github.com/udoprog/watchword/blob/main/docs/design.md
[`examples/app`]: https://github.com/udoprog/watchword/tree/main/examples/app
[`google::fake`]: https://docs.rs/watchword/latest/watchword/google/fake/index.html
[`google`]: https://docs.rs/watchword/latest/watchword/google/index.html
[`sqll014`]: https://docs.rs/watchword/latest/watchword/sqll014/index.html
[`store`]: https://docs.rs/watchword/latest/watchword/store/index.html
[`types`]: https://docs.rs/watchword/latest/watchword/types/index.html
[`yew023`]: https://docs.rs/watchword/latest/watchword/yew023/index.html
[trunk]: https://trunkrs.dev
[watchword-core]: https://docs.rs/watchword-core
[watchword-yew023]: https://docs.rs/watchword-yew023
