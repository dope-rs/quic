use crate::{proto::param, wire::varint};
use param::codec;

pub(super) struct Limit {
    id: u8,
    minimum: u64,
    maximum: u64,
}

impl Limit {
    fn try_bind(&self, value: u64) -> Result<varint::VarInt, param::Error> {
        self.check(value)?;
        varint::VarInt::new(value).ok_or_else(|| self.error(value))
    }

    pub(super) fn check(&self, value: u64) -> Result<(), param::Error> {
        if value < self.minimum || value > self.maximum {
            return Err(self.error(value));
        }
        Ok(())
    }

    fn error(&self, value: u64) -> param::Error {
        param::Error::OutOfRange {
            id: u64::from(self.id),
            value,
            minimum: self.minimum,
            maximum: self.maximum,
        }
    }
}

const IDLE: Limit = Limit {
    id: codec::ID_MAX_IDLE_TIMEOUT,
    minimum: 0,
    maximum: varint::VarInt::MAX,
};
pub(super) const UDP: Limit = Limit {
    id: codec::ID_MAX_UDP_PAYLOAD_SIZE,
    minimum: 1200,
    maximum: varint::VarInt::MAX,
};
const DATA: Limit = Limit {
    id: codec::ID_INITIAL_MAX_DATA,
    minimum: 0,
    maximum: varint::VarInt::MAX,
};
const LOCAL: Limit = Limit {
    id: codec::ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
    minimum: 0,
    maximum: varint::VarInt::MAX,
};
const REMOTE: Limit = Limit {
    id: codec::ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    minimum: 0,
    maximum: varint::VarInt::MAX,
};
const STREAM_UNI: Limit = Limit {
    id: codec::ID_INITIAL_MAX_STREAM_DATA_UNI,
    minimum: 0,
    maximum: varint::VarInt::MAX,
};
pub(super) const BIDI: Limit = Limit {
    id: codec::ID_INITIAL_MAX_STREAMS_BIDI,
    minimum: 0,
    maximum: 1_u64 << 60,
};
pub(super) const UNIS: Limit = Limit {
    id: codec::ID_INITIAL_MAX_STREAMS_UNI,
    minimum: 0,
    maximum: 1_u64 << 60,
};
pub(super) const ACK_EXP: Limit = Limit {
    id: codec::ID_ACK_DELAY_EXPONENT,
    minimum: 0,
    maximum: 20,
};
pub(super) const ACK_MS: Limit = Limit {
    id: codec::ID_MAX_ACK_DELAY,
    minimum: 0,
    maximum: (1_u64 << 14) - 1,
};
pub(super) const CID: Limit = Limit {
    id: codec::ID_ACTIVE_CONNECTION_ID_LIMIT,
    minimum: 2,
    maximum: varint::VarInt::MAX,
};
const DGRAM: Limit = Limit {
    id: codec::ID_MAX_DATAGRAM_FRAME_SIZE,
    minimum: 0,
    maximum: varint::VarInt::MAX,
};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct TimingDraft {
    pub(super) idle: u64,
    pub(super) ack_exp: u64,
    pub(super) ack_ms: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct FlowDraft {
    pub(super) udp: u64,
    pub(super) data: u64,
    pub(super) local: u64,
    pub(super) remote: u64,
    pub(super) uni: u64,
    pub(super) bidi: u64,
    pub(super) unis: u64,
    pub(super) dgram: Option<u64>,
}

/// Mutable construction state, promoted only after numerical validation.
#[derive(Clone, PartialEq, Eq)]
#[must_use = "proto-parameter builders must be promoted with try_build"]
pub struct Builder {
    pub(super) identity: param::Identity,
    pub(super) timing: TimingDraft,
    pub(super) flow: FlowDraft,
    pub(super) cid: u64,
}

impl Builder {
    pub fn idle_ms(mut self, value: u64) -> Self {
        self.timing.idle = value;
        self
    }

    pub fn udp_max(mut self, value: u64) -> Self {
        self.flow.udp = value;
        self
    }

    pub fn initial_data(mut self, value: u64) -> Self {
        self.flow.data = value;
        self
    }

    pub fn local_bidi(mut self, value: u64) -> Self {
        self.flow.local = value;
        self
    }

    pub fn remote_bidi(mut self, value: u64) -> Self {
        self.flow.remote = value;
        self
    }

    pub fn stream_uni(mut self, value: u64) -> Self {
        self.flow.uni = value;
        self
    }

    pub fn bidi_count(mut self, value: u64) -> Self {
        self.flow.bidi = value;
        self
    }

    pub fn uni_count(mut self, value: u64) -> Self {
        self.flow.unis = value;
        self
    }

    pub fn ack_exponent(mut self, value: u64) -> Self {
        self.timing.ack_exp = value;
        self
    }

    pub fn ack_ms(mut self, value: u64) -> Self {
        self.timing.ack_ms = value;
        self
    }

    pub fn fixed(mut self, value: bool) -> Self {
        self.identity.disable_active_migration = value;
        self
    }

    pub fn cid_limit(mut self, value: u64) -> Self {
        self.cid = value;
        self
    }

    pub fn datagram(mut self, value: Option<u64>) -> Self {
        self.flow.dgram = value;
        self
    }

    pub fn try_build(self) -> Result<param::Set, param::Error> {
        let idle = IDLE.try_bind(self.timing.idle)?;
        let mut flow = param::Flow {
            max_udp_payload_size: UDP.try_bind(self.flow.udp)?,
            initial_max_data: DATA.try_bind(self.flow.data)?,
            initial_max_stream_data_bidi_local: LOCAL.try_bind(self.flow.local)?,
            initial_max_stream_data_bidi_remote: REMOTE.try_bind(self.flow.remote)?,
            initial_max_stream_data_uni: STREAM_UNI.try_bind(self.flow.uni)?,
            initial_max_streams_bidi: BIDI.try_bind(self.flow.bidi)?,
            initial_max_streams_uni: UNIS.try_bind(self.flow.unis)?,
            max_datagram_frame_size: None,
        };
        let timing = param::Timing {
            max_idle_timeout_ms: idle,
            ack_delay_exponent: ACK_EXP.try_bind(self.timing.ack_exp)?,
            max_ack_delay_ms: ACK_MS.try_bind(self.timing.ack_ms)?,
        };
        let mut identity = self.identity;
        identity.active_connection_id_limit = CID.try_bind(self.cid)?;
        flow.max_datagram_frame_size = match self.flow.dgram {
            Some(value) => Some(DGRAM.try_bind(value)?),
            None => None,
        };
        Ok(param::Set {
            timing,
            flow,
            identity,
        })
    }
}
