# watchword-core

[<img alt="github" src="https://img.shields.io/badge/github-udoprog/watchword-8da0cb?style=for-the-badge&logo=github" height="20">](https://github.com/udoprog/watchword)
[<img alt="crates.io" src="https://img.shields.io/crates/v/watchword-core.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/watchword-core)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-watchword--core-66c2a5?style=for-the-badge&logoColor=white&logo=data:image/svg+xml;base64,PHN2ZyByb2xlPSJpbWciIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgdmlld0JveD0iMCAwIDUxMiA1MTIiPjxwYXRoIGZpbGw9IiNmNWY1ZjUiIGQ9Ik00ODguNiAyNTAuMkwzOTIgMjE0VjEwNS41YzAtMTUtOS4zLTI4LjQtMjMuNC0zMy43bC0xMDAtMzcuNWMtOC4xLTMuMS0xNy4xLTMuMS0yNS4zIDBsLTEwMCAzNy41Yy0xNC4xIDUuMy0yMy40IDE4LjctMjMuNCAzMy43VjIxNGwtOTYuNiAzNi4yQzkuMyAyNTUuNSAwIDI2OC45IDAgMjgzLjlWMzk0YzAgMTMuNiA3LjcgMjYuMSAxOS45IDMyLjJsMTAwIDUwYzEwLjEgNS4xIDIyLjEgNS4xIDMyLjIgMGwxMDMuOS01MiAxMDMuOSA1MmMxMC4xIDUuMSAyMi4xIDUuMSAzMi4yIDBsMTAwLTUwYzEyLjItNi4xIDE5LjktMTguNiAxOS45LTMyLjJWMjgzLjljMC0xNS05LjMtMjguNC0yMy40LTMzLjd6TTM1OCAyMTQuOGwtODUgMzEuOXYtNjguMmw4NS0zN3Y3My4zek0xNTQgMTA0LjFsMTAyLTM4LjIgMTAyIDM4LjJ2LjZsLTEwMiA0MS40LTEwMi00MS40di0uNnptODQgMjkxLjFsLTg1IDQyLjV2LTc5LjFsODUtMzguOHY3NS40em0wLTExMmwtMTAyIDQxLjQtMTAyLTQxLjR2LS42bDEwMi0zOC4yIDEwMiAzOC4ydi42em0yNDAgMTEybC04NSA0Mi41di03OS4xbDg1LTM4Ljh2NzUuNHptMC0xMTJsLTEwMiA0MS40LTEwMi00MS40di0uNmwxMDItMzguMiAxMDIgMzguMnYuNnoiPjwvcGF0aD48L3N2Zz4K" height="20">](https://docs.rs/watchword-core)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/udoprog/watchword/ci.yml?branch=main&style=for-the-badge" height="20">](https://github.com/udoprog/watchword/actions?query=branch%3Amain)

The types [watchword]'s server and frontends share: identities, roles,
account state, the JSON wire types of the `/api/auth` routes,
[`AuthError`], and input validation.

Apps normally use these through watchword, which re-exports them as
`watchword::types` and at its crate root, or through a frontend crate such
as `watchword-yew023`. Released in lockstep with watchword.

<br>

## Features

The crate is `no_std`, and safe to build for `wasm32-unknown-unknown` with
any feature but `axum08` and `sqll014`. Only `std` is on by default.

| Feature | What it provides |
|---|---|
| *(none)* | `UserId`, `Role`, `Access`, `Method`, `Conflict`, `AuthConfig` and `MIN_PASSWORD_LEN` |
| `alloc` | the wire types that hold strings (`UserInfo`, `LoginRequest`, `CreatedUser`, ...), [`AuthError`] and its `Invalid` reasons, `validate_password` and `normalize_email` |
| `std` *(default)* | `alloc`, and the standard library for the dependencies that have it |
| `musli01` | musli 0.1 `Encode`/`Decode` on the types, so an app can embed them in its own WebSocket messages |
| `musliweb04` | `alloc` + `musli01` + [`musliweb04`]: the account, user-management and Cloudflare Access settings endpoints and `AuthBroadcast` as musli-web 0.4 API types, with their ids pinned in 32000–32255 |
| `axum08` | `std` + axum 0.8 `IntoResponse` for [`AuthError`], answering with its JSON body and status; watchword's `axum08` feature turns it on (not for wasm) |
| `sqll014` | `std` + sqll 0.14 `BindValue`, `Bind` and `FromColumn` for `UserId` (an integer with the same bits, as watchword's `SqllStore` stores it) and for `Role`, `Access` and `Method` (their names as text), so an app's own statements bind and read them directly; watchword's `sqll014` feature turns it on. It takes sqll with `threadsafe` only; the app names `bundled` or links its own SQLite (not for wasm) |
| `phrasebook01` | `std` + [`phrasebook01`]: `L10N`, watchword's messages (the text of its Yew components) as a [phrasebook] 0.1 catalog, for a tool such as an app's localization checker that needs them without building a frontend; watchword-yew023 re-exports it, and watchword's `phrasebook01` and `yew023` features turn it on |

[`AuthError`]: https://docs.rs/watchword-core/latest/watchword_core/enum.AuthError.html
[`musliweb04`]: https://docs.rs/watchword-core/latest/watchword_core/musliweb04/index.html
[`phrasebook01`]: https://docs.rs/watchword-core/latest/watchword_core/phrasebook01/index.html
[phrasebook]: https://docs.rs/phrasebook
[watchword]: https://docs.rs/watchword
