mod builder;
mod codec;
mod error;

pub use builder::Builder;
pub use codec::Codec;
pub use error::Error;

use o3::alloc;

use crate::proto::datagram;
use crate::wire::packet;
use crate::wire::varint;
use packet::cid;

/// Client-role proto parameters bound to the connection ID that will be
/// authenticated by TLS. The borrow keeps the identity and parameters
/// together from binding through encoding.
#[must_use = "bound parameters must be encoded into the matching TLS connection"]
pub struct Client<'a> {
    params: &'a Set,
    local_cid: cid::Ref<'a>,
}

/// Server-role proto parameters bound to the complete connection identity
/// and optional stateless-reset capability that will be authenticated by TLS.
#[must_use = "bound parameters must be encoded into the matching TLS connection"]
pub struct Server<'a> {
    params: &'a Set,
    local_cid: cid::Ref<'a>,
    original_dcid: cid::Ref<'a>,
    retry_scid: Option<cid::Ref<'a>>,
    stateless_reset_token: Option<&'a [u8; 16]>,
}

impl Client<'_> {
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), alloc::Error> {
        Codec::encode_vec(
            self.params,
            out,
            codec::Ids {
                initial: self.local_cid,
                original: None,
                retry: None,
            },
            None,
        )
    }
}

impl Server<'_> {
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), alloc::Error> {
        Codec::encode_vec(
            self.params,
            out,
            codec::Ids {
                initial: self.local_cid,
                original: Some(self.original_dcid),
                retry: self.retry_scid,
            },
            self.stateless_reset_token,
        )
    }
}

pub const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u64 = 65527;
pub const DEFAULT_ACK_DELAY_EXPONENT: u8 = 3;
pub const DEFAULT_MAX_ACK_DELAY_MS: u16 = 25;
pub const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// Numerically validated QUIC proto parameters.
/// Unvalidated input enters through [`Builder`]; connection identity is bound
/// only by role binding or wire decoding.
#[derive(Clone, PartialEq, Eq)]
pub struct Set {
    timing: Timing,
    flow: Flow,
    identity: Identity,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Timing {
    max_idle_timeout_ms: varint::VarInt,
    ack_delay_exponent: varint::VarInt,
    max_ack_delay_ms: varint::VarInt,
}

impl Timing {
    pub const fn idle_ms(&self) -> u64 {
        self.max_idle_timeout_ms.get()
    }

    pub const fn ack_exponent(&self) -> u8 {
        self.ack_delay_exponent.get() as u8
    }

    pub const fn ack_ms(&self) -> u16 {
        self.max_ack_delay_ms.get() as u16
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Flow {
    max_udp_payload_size: varint::VarInt,
    initial_max_data: varint::VarInt,
    initial_max_stream_data_bidi_local: varint::VarInt,
    initial_max_stream_data_bidi_remote: varint::VarInt,
    initial_max_stream_data_uni: varint::VarInt,
    initial_max_streams_bidi: varint::VarInt,
    initial_max_streams_uni: varint::VarInt,
    max_datagram_frame_size: Option<varint::VarInt>,
}

impl Flow {
    pub const fn udp_max(&self) -> u64 {
        self.max_udp_payload_size.get()
    }

    fn cap_udp(&mut self, ceiling: datagram::Size) {
        let ceiling = u64::from(ceiling.get());
        let capped = self.max_udp_payload_size.get().min(ceiling);
        self.max_udp_payload_size = varint::VarInt::from_u16(capped as u16);
    }

    pub const fn initial_data(&self) -> varint::VarInt {
        self.initial_max_data
    }

    pub const fn local_bidi(&self) -> varint::VarInt {
        self.initial_max_stream_data_bidi_local
    }

    pub const fn remote_bidi(&self) -> varint::VarInt {
        self.initial_max_stream_data_bidi_remote
    }

    pub const fn stream_uni(&self) -> varint::VarInt {
        self.initial_max_stream_data_uni
    }

    pub const fn bidi_count(&self) -> u64 {
        self.initial_max_streams_bidi.get()
    }

    pub const fn uni_count(&self) -> u64 {
        self.initial_max_streams_uni.get()
    }

    pub const fn datagram(&self) -> Option<u64> {
        match self.max_datagram_frame_size {
            Some(value) => Some(value.get()),
            None => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    disable_active_migration: bool,
    preferred_address: bool,
    active_connection_id_limit: varint::VarInt,
    initial_source_connection_id: Option<cid::Id>,
    original_destination_connection_id: Option<cid::Id>,
    retry_source_connection_id: Option<cid::Id>,
    stateless_reset_token: Option<[u8; 16]>,
}

impl Identity {
    pub const fn is_fixed(&self) -> bool {
        self.disable_active_migration
    }

    pub const fn cid_limit(&self) -> u64 {
        self.active_connection_id_limit.get()
    }

    pub const fn initial(&self) -> Option<&cid::Id> {
        self.initial_source_connection_id.as_ref()
    }

    pub const fn original(&self) -> Option<&cid::Id> {
        self.original_destination_connection_id.as_ref()
    }

    pub const fn retry(&self) -> Option<&cid::Id> {
        self.retry_source_connection_id.as_ref()
    }

    pub const fn reset(&self) -> Option<[u8; 16]> {
        self.stateless_reset_token
    }

    pub(crate) const fn has_address(&self) -> bool {
        self.preferred_address
    }
}

impl Default for Set {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Set {
    pub(crate) const DEFAULT: Self = Self {
        timing: Timing {
            max_idle_timeout_ms: varint::VarInt::ZERO,
            ack_delay_exponent: varint::VarInt::from_u8(3),
            max_ack_delay_ms: varint::VarInt::from_u8(25),
        },
        flow: Flow {
            max_udp_payload_size: varint::VarInt::from_u16(65_527),
            initial_max_data: varint::VarInt::ZERO,
            initial_max_stream_data_bidi_local: varint::VarInt::ZERO,
            initial_max_stream_data_bidi_remote: varint::VarInt::ZERO,
            initial_max_stream_data_uni: varint::VarInt::ZERO,
            initial_max_streams_bidi: varint::VarInt::ZERO,
            initial_max_streams_uni: varint::VarInt::ZERO,
            max_datagram_frame_size: None,
        },
        identity: Identity {
            disable_active_migration: false,
            preferred_address: false,
            active_connection_id_limit: varint::VarInt::from_u8(2),
            initial_source_connection_id: None,
            original_destination_connection_id: None,
            retry_source_connection_id: None,
            stateless_reset_token: None,
        },
    };

    pub fn builder() -> Builder {
        Builder {
            identity: Self::DEFAULT.identity,
            timing: builder::TimingDraft {
                idle: 0,
                ack_exp: u64::from(DEFAULT_ACK_DELAY_EXPONENT),
                ack_ms: u64::from(DEFAULT_MAX_ACK_DELAY_MS),
            },
            flow: builder::FlowDraft {
                udp: DEFAULT_MAX_UDP_PAYLOAD_SIZE,
                data: 0,
                local: 0,
                remote: 0,
                uni: 0,
                bidi: 0,
                unis: 0,
                dgram: None,
            },
            cid: DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
        }
    }

    pub fn to_builder(&self) -> Builder {
        Builder {
            timing: builder::TimingDraft {
                idle: self.timing.max_idle_timeout_ms.get(),
                ack_exp: self.timing.ack_delay_exponent.get(),
                ack_ms: self.timing.max_ack_delay_ms.get(),
            },
            flow: builder::FlowDraft {
                udp: self.flow.max_udp_payload_size.get(),
                data: self.flow.initial_max_data.get(),
                local: self.flow.initial_max_stream_data_bidi_local.get(),
                remote: self.flow.initial_max_stream_data_bidi_remote.get(),
                uni: self.flow.initial_max_stream_data_uni.get(),
                bidi: self.flow.initial_max_streams_bidi.get(),
                unis: self.flow.initial_max_streams_uni.get(),
                dgram: self.flow.max_datagram_frame_size.map(varint::VarInt::get),
            },
            cid: self.identity.active_connection_id_limit.get(),
            identity: self.identity.clone(),
        }
    }

    pub(crate) fn cap_udp(&mut self, ceiling: datagram::Size) {
        self.flow.cap_udp(ceiling);
    }

    pub const fn timing(&self) -> &Timing {
        &self.timing
    }

    pub const fn flow(&self) -> &Flow {
        &self.flow
    }

    pub const fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn bind_client<'a>(&'a self, local: &'a cid::Id) -> Client<'a> {
        Client {
            params: self,
            local_cid: local.as_ref_id(),
        }
    }

    pub fn bind_server<'a>(
        &'a self,
        local: &'a cid::Id,
        original: &'a cid::Id,
        retry: Option<&'a cid::Id>,
        reset: Option<&'a [u8; 16]>,
    ) -> Server<'a> {
        Server {
            params: self,
            local_cid: local.as_ref_id(),
            original_dcid: original.as_ref_id(),
            retry_scid: retry.map(cid::Id::as_ref_id),
            stateless_reset_token: reset,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), error::Error> {
        builder::UDP.check(self.flow.max_udp_payload_size.get())?;
        builder::BIDI.check(self.flow.initial_max_streams_bidi.get())?;
        builder::UNIS.check(self.flow.initial_max_streams_uni.get())?;
        builder::ACK_EXP.check(self.timing.ack_delay_exponent.get())?;
        builder::ACK_MS.check(self.timing.max_ack_delay_ms.get())?;
        builder::CID.check(self.identity.active_connection_id_limit.get())?;
        Ok(())
    }
}
