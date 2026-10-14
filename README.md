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
| *(none)* | `auth::types` | `UserId`, `Role`, `Access`, `Method`, the wire types (`UserInfo`, `AuthConfig`, `LoginRequest`, ...), `AuthError`, `validate_password`, `normalize_email` |
| `musli` | | musli `Encode`/`Decode` on the wire types |
| `server` | `auth::core` | bcrypt password hashing with `dummy_hash` timing, session ids and link tokens, HMAC-signed session cookies |
| `cloudflare` | `auth::cloudflare` | Cloudflare Access JWT verification with a pluggable `KeyFetcher` (implies `server`) |
| `google` | `auth::google` | Google OAuth (implies `server`; not implemented yet) |
| `axum` | `auth::axum` | extractors, routes, WebSocket session guard (implies `server`; not implemented yet) |
| `sqll` | `auth::sqll` | `SqllStore` over SQLite (implies `server`; not implemented yet) |
| `yew` | `auth::yew` | `AuthProvider`, `use_auth`, `SignIn`, `Register` and the `http` client (account and admin components not implemented yet) |

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
