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
pub mod errors;
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
#[doc(hidden)]
pub mod range_buffer;
mod rtt;
mod secrets;
#[doc(hidden)]
pub mod stream;
pub mod transport_params;
pub mod varint;

pub use client::{
    BackoffPolicy, Client, EndpointSpec, PathStats, PooledDialer, PooledEndpointSpec, Protocol,
    SlotId,
};
pub use endpoint::{
    Endpoint, PooledControl, PooledRetainedControl, PooledRetainedSocket, PooledSocket,
    RetainedControl, RetainedSocket,
};
pub use errors::{ConnectFailure, SendFailure};
pub use mux::{Handler, Mux, PooledRouter};
pub use o3::buffer::CapacityError;
pub use stream::{INLINE_SEND_CAPACITY, ReceiveBuffer, RecvBuffer, SendBuffer};
pub use transport_params::TransportParameterError;

pub mod client_auth;
