//! The example app's own musli-web API, shared by its server and frontend.
//!
//! Its types take implicit ids, which count up from 1, so they never reach
//! watchword's band (32000–32255). The list includes watchword's endpoints
//! and `AuthBroadcast` as `Auth`, so one socket carries both and musli-web
//! checks at compile time that no id is used twice. The server passes the
//! `Request::Auth` requests to `watchword::musliweb05::Connection::handle`.

use musli::{Decode, Encode};

/// Asks for [`StatusResponse`].
#[derive(Debug, Encode, Decode)]
pub struct StatusRequest;

/// The server's status, as the home page shows it.
#[derive(Debug, Clone, PartialEq, Encode, Decode)]
pub struct StatusResponse {
    /// Seconds since the server started.
    pub uptime: u64,
    /// The sockets open now, this one included.
    pub sockets: u32,
}

musli_web::api::define! {
    /// The server's status: an endpoint of the app's own, beside
    /// watchword's on the same socket.
    pub type Status;

    impl Endpoint for Status {
        impl Request for StatusRequest;
        type Response<'de> = StatusResponse;
    }

    /// watchword's account and user-management endpoints and its
    /// `AuthBroadcast`.
    include watchword_core::musliweb05 as Auth;
}
