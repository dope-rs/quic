macro_rules! impl_error {
    ($type:ty { $($pattern:pat => $message:literal),+ $(,)? }) => {
        impl std::fmt::Display for $type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(match self {
                    $($pattern => $message),+
                })
            }
        }

        impl std::error::Error for $type {}
    };
}

pub mod client;
mod clock;
pub mod conn;
pub mod early_data;
pub mod endpoint;
mod errors;
pub mod frame;
mod hp;
pub mod mux;
mod new_reno;
mod pacer;
pub mod packet;
pub mod packet_protection;
mod pmtud;
mod pn_space;
pub mod qkdf;
mod range_buffer;
mod rtt;
mod secrets;
mod stream;
pub mod transport_params;
pub mod varint;

pub use client::{
    BackoffPolicy, Client, EndpointSpec, PathStats, PooledClient, PooledEndpointSpec, Protocol,
    SlotId,
};
pub use endpoint::{
    Endpoint, PooledControl, PooledEndpoint, PooledRetainedControl, PooledRetainedEndpoint,
    RetainedControl, RetainedEndpoint,
};
pub use errors::{ConnectError, TrySendError};
pub use mux::{Handler, Mux, PooledMux};
pub use o3::buffer::CapacityError;
pub use stream::{INLINE_SEND_CAPACITY, ReceiveBuffer, RecvBuffer, SendBuffer};
pub use transport_params::TransportParameterError;

pub mod client_auth {
    pub use shin::client::config::Identity;
    pub use shin::server::{
        config::ClientAuth, config::ClientAuthVerifier, config::ClientCertVerifier,
        config::ClientIdentity,
    };
}
