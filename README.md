# yew-auth

Storage-agnostic authentication primitives shared by the Rust web apps
(axum server, Yew/WASM frontend) in this family: track, army and territory.

It was extracted from `crates/auth` in track, history included, and keeps
the same library name and API, `auth`.

## What it provides

- **Roles**: `UserRole` (`Admin`, `Regular`) with string conversion, and
  `normalize_email` for case-insensitive lookups.
- **Passwords**: `hash_password`, `verify_password` and `validate_password`
  (bcrypt, `MIN_PASSWORD_LEN`), plus `dummy_hash` so unknown users cost as
  much to check as known ones.
- **Sessions and login tokens**: `new_session_id`, `new_login_token`,
  `session_expiry`, `login_token_expiry` and `is_expired`.
- **Signed session cookies**: `generate_session_key`, `session_cookie` and
  `verify_session_cookie` (HMAC-SHA256).
- **Cloudflare Access**: `cloudflare::Access` verifies the Access JWT
  against the team's signing keys, with a pluggable `KeyFetcher`, and can
  optionally trust the authenticated-email header.

It has no database and no web framework dependency: storing users and
sessions, and wiring cookies into requests, is up to the application.

## Using it

The crate is not published. Depend on it by path; the package is named
`yew-auth` and the library `auth`, so code refers to it as `auth`:

```toml
[dependencies]
auth = { package = "yew-auth", path = "../yew-auth" }
```

Adjust the path to where this repository is checked out relative to the
depending crate.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.
