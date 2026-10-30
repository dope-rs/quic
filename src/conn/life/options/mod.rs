use crate::{conn, proto::datagram::Size, proto::param};
use conn::{machine::storage, stream};
use storage::capacity;

pub mod builder;
mod dgram;
mod journals;
mod path;
mod security;
mod streams;

pub use dgram::Dgram;
pub(in crate::conn) use dgram::{Capacity, Datagrams};
pub use journals::Journals;
pub use path::Path;
pub(in crate::conn) use path::{Flow, Identity, Transport};
pub use security::Security;
pub use streams::Streams;
pub(in crate::conn) use streams::{Limits, Parts};

/// Protocol-ready connection options produced by one checked builder.
pub struct Options {
    pub(in crate::conn) transport: Transport,
    pub(in crate::conn) datagrams: Datagrams,
    pub(in crate::conn) streams: Limits,
    pub(in crate::conn) journals: capacity::Capacities,
    pub(crate) security: Security,
}

impl Default for Options {
    fn default() -> Self {
        const PATH: (Transport, [stream::Count; 2]) = const {
            match Path::DEFAULT.try_prove() {
                Ok(value) => value,
                Err(_) => panic!("path"),
            }
        };
        Self {
            transport: PATH.0,
            datagrams: const {
                match Dgram::DEFAULT.try_prove() {
                    Ok(value) => value,
                    Err(_) => panic!("datagrams"),
                }
            },
            streams: const {
                match Streams::DEFAULT.try_prove(PATH.1) {
                    Ok(value) => value,
                    Err(_) => panic!("streams"),
                }
            },
            journals: capacity::Capacities::default(),
            security: Security::default(),
        }
    }
}

impl Options {
    pub fn builder() -> builder::Builder {
        builder::Builder {
            path: Path::default(),
            dgrams: Dgram::default(),
            streams: Streams::default(),
            journals: Journals::default(),
            security: Security::default(),
        }
    }

    pub fn into_builder(self) -> builder::Builder {
        let Self {
            transport: path,
            datagrams: dgrams,
            streams,
            journals,
            security,
        } = self;
        builder::Builder {
            path: path.into_draft(),
            dgrams: dgrams.into_draft(),
            streams: streams.into_draft(),
            journals: Journals::from(journals),
            security,
        }
    }

    pub const fn params(&self) -> &param::Set {
        self.transport.params()
    }

    pub const fn max_pmtu(&self) -> u64 {
        self.transport.max_pmtu().get()
    }

    pub(crate) fn cap_udp(&mut self, cap: Size) {
        self.transport.cap_udp(cap);
    }

    pub(crate) fn packet_max(&self) -> usize {
        self.transport.max_pmtu().get() as usize
    }

    pub(crate) fn packet_cap(&self, out: usize) -> Option<Size> {
        Size::new(self.packet_max().min(out) as u32)
    }

    pub(crate) fn copy(&self) -> Self {
        Self {
            transport: self.transport.copy(),
            datagrams: self.datagrams,
            streams: self.streams.copy(),
            journals: self.journals,
            security: Security {
                stateless_reset_secret: self.security.stateless_reset_secret.clone(),
                require_address_validation: self.security.require_address_validation,
                retry_token_secret: self.security.retry_token_secret.clone(),
            },
        }
    }
}

impl TryFrom<param::Set> for Options {
    type Error = builder::Invalid;

    fn try_from(params: param::Set) -> Result<Self, Self::Error> {
        Self::builder()
            .transport(|path| path.params(params))
            .try_build()
    }
}
