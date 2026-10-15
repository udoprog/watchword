# yew-auth

Authentication shared by the Rust web apps (axum server, Yew/WASM frontend)
in this family: track, army and territory. It grew out of `crates/auth` in
track, history included, and keeps the library name `auth`.

The design, including the full API each layer grows into, is recorded in
[docs/design.md](docs/design.md).

## Features

Each layer sits behind a cargo feature, so an app takes only what it uses.
Server-only and browser-only dependencies never share a feature, so a wasm
frontend can take `yew` without pulling in server code. No feature is on by
default.

| Feature | Module | What it provides |
|---|---|---|
| *(none)* | `auth::types` | `UserId`, `Role`, `Access`, `Method`, the wire types (`UserInfo`, `AuthConfig`, `LoginRequest`, `CreatedUser`, ...), `AuthError`, `validate_password`, `normalize_email` |
| `musli` | | musli `Encode`/`Decode` on the wire types |
| `server` | `auth::core`, `auth::store` | bcrypt password hashing with `dummy_hash` timing, session ids and link tokens, HMAC-signed session cookies; the `Auth` service (sign-in, registration links, user management, sign-in throttle, `AuthEvent`s, bootstrap admin); the `Store` trait and `MemoryStore` |
| `cloudflare` | `auth::cloudflare` | Cloudflare Access JWT verification with a pluggable `KeyFetcher` (implies `server`) |
| `google` | `auth::google` | Google OAuth: `GoogleConfig` for `AuthBuilder::google`; with `axum`, `routes()` serves its start, registration, account-switch and callback routes (implies `server`) |
| `axum` | `auth::axum` | the `SignedIn`, `Admin`, `MaybeSignedIn` and `LiveSession` extractors, `routes()` for the `/api/auth` JSON routes, and `Auth::guard` for WebSocket sessions, plus the Cloudflare and Google routes when those features are on (implies `server`) |
| `sqll` | `auth::sqll` | `SqllStore`, a `Store` over SQLite on a sqll 0.14 pool (its own, or nested in the app's), its `SCHEMA`, and the one-time migrations for track and territory in `docs/sqll/` (implies `server`) |
| `test-util` | `auth::google::fake` | for an app's tests: `AuthBuilder::google_endpoints`, and with `axum` `FakeGoogle`, a local fake Google to sign in through offline (implies `google`) |
| `yew` | `auth::yew` | `AuthProvider`, `use_auth`, `SignIn`, `Register`, `AccountPanel`, `UserMenu`, `AdminUsers`, `CloudflareSettings` and the `http` client |

The most-used names are re-exported at the crate root.

## Using it

The crate is not published. Depend on it by path; the package is named
`yew-auth` and the library `auth`, so code refers to it as `auth`:

```toml
[dependencies]
# Server crate.
auth = { package = "yew-auth", path = "../yew-auth", features = ["axum", "cloudflare"] }
# Frontend crate.
auth = { package = "yew-auth", path = "../yew-auth", features = ["yew"] }
```

Adjust the path to where this repository is checked out relative to the
depending crate.

## Example app

[`examples/app`](examples/app) is an axum server and a Yew frontend wired up
with all three sign-in methods, `MemoryStore` and a WebSocket held open for
the session: a reference for apps taking the library, and a way to try the
components by hand. It is its own cargo workspace, so it adds nothing to the
library's builds or lockfile.

Build the frontend with [trunk](https://trunkrs.dev), then run the server,
which serves it:

```sh
cd examples/app/frontend && trunk build
cd examples/app && cargo run -p yew-auth-example-server -- --bind 127.0.0.1:8080
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

trunk builds with the `wasm-bindgen` CLI matching `examples/app/Cargo.lock`
(0.2.129), downloading it unless it is installed or already in trunk's cache.

When a change touches the example or the API it uses, also run:

```sh
cd examples/app && cargo clippy -p yew-auth-example-server -- -D warnings
cd examples/app && cargo clippy -p yew-auth-example-frontend --target wasm32-unknown-unknown -- -D warnings
cd examples/app && cargo fmt --all --check
cd examples/app/frontend && trunk build
```

## Checks

Run every one of these before handing off a change, one at a time with
`CARGO_BUILD_JOBS=4`. Each feature is checked alone, because a feature that
only compiles alongside another breaks the apps that take it alone.

```sh
cargo fmt --check
cargo clippy --all-targets --no-default-features -- -D warnings
cargo clippy --all-targets --no-default-features --features musli -- -D warnings
cargo clippy --all-targets --no-default-features --features server -- -D warnings
cargo clippy --all-targets --no-default-features --features cloudflare -- -D warnings
cargo clippy --all-targets --no-default-features --features google -- -D warnings
cargo clippy --all-targets --no-default-features --features axum -- -D warnings
cargo clippy --all-targets --no-default-features --features sqll -- -D warnings
cargo clippy --all-targets --no-default-features --features yew -- -D warnings
cargo clippy --all-targets --no-default-features --features test-util -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test --no-default-features
cargo test --all-features
cargo check --target wasm32-unknown-unknown --no-default-features --features yew
cargo check --target wasm32-unknown-unknown --no-default-features --features yew,musli
```

The wasm checks need the target: `rustup target add wasm32-unknown-unknown`.
A plain `cargo test` builds no features and runs only the `types` tests.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.
