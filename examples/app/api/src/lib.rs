//! The example app's own musli-web API, shared by its server and frontend.
//!
//! Its types take implicit ids, which count up from 1, so they never reach
//! watchword's band (32000–32255). watchword's endpoints and
//! `AuthBroadcast` are not listed here: musli-web cannot merge two `define!`
//! lists, so they are a second list on the same socket. The server delegates
//! the ids this list does not know, `Request::Unknown(id)`, to
//! `watchword::musliweb05::Connection::handle`.

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
}
