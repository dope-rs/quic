pub mod client;
pub mod conn;
pub mod early_data;
pub mod endpoint;
pub mod frame;
pub mod hp;
pub mod mux;
pub mod new_reno;
pub mod pacer;
pub mod packet;
pub mod packet_protection;
pub mod pmtud;
pub mod pn_space;
pub mod qkdf;
pub mod rtt;
pub mod secrets;
pub mod stream;
mod time;
pub mod transport_params;
pub mod varint;

pub use client::{BackoffPolicy, Client, EndpointSpec, Protocol, SendError, SlotId};
pub use conn::{
    Conn, ConnClientAuth, ConnConfig, ConnError, ConnHandle, DatagramCcMode, DatagramError,
    SessionTicket, State as ConnState, StreamError, StreamEvent,
};
pub use endpoint::Endpoint;
pub use mux::{Handler, Mux};
pub use transport_params::TpError;

/// Mutual-TLS types for [`ConnConfig::client_auth`]/[`ConnConfig::client_cert`], re-exported from `shin`.
pub mod client_auth {
    pub use shin::client::ClientCertSource;
    pub use shin::server::{ClientAuth, ClientCertVerifier, ClientIdentity};
}
