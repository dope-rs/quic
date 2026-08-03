use super::delivery::{self, Control, Handle, Stream};
use super::{Epoch, PACKET_CONTROL_CAPACITY, PACKET_STREAM_CAPACITY};
use o3::collections::CopyArrayVec;

#[derive(Debug, Clone, Copy)]
pub(super) struct Delivery<T> {
    pub(super) record: T,
    pub(super) probe: Option<Handle<T>>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Crypto {
    Pending {
        offset: u64,
        len: usize,
    },
    Retransmit {
        index: usize,
        offset: u64,
        len: usize,
    },
}

pub(super) struct Packet {
    pub(super) epoch: Epoch,
    pub(super) pn: u64,
    pub(super) bytes: usize,
    pub(super) ack_eliciting: bool,
    pub(super) in_flight: bool,
    pub(super) ack_included: bool,
    pub(super) crypto: Option<Crypto>,
    pub(super) crypto_probe: Option<Delivery<delivery::Crypto>>,
    pub(super) controls: CopyArrayVec<Delivery<Control>, PACKET_CONTROL_CAPACITY>,
    pub(super) streams: CopyArrayVec<Delivery<Stream>, PACKET_STREAM_CAPACITY>,
    pub(super) early_data: bool,
    pub(super) datagram: bool,
    pub(super) close: bool,
    pub(super) pmtud_probe: Option<u64>,
    pub(super) pto_probe: bool,
}

impl Packet {
    pub(super) fn new(epoch: Epoch, pn: u64) -> Self {
        Self {
            epoch,
            pn,
            bytes: 0,
            ack_eliciting: false,
            in_flight: false,
            ack_included: false,
            crypto: None,
            crypto_probe: None,
            controls: CopyArrayVec::new(),
            streams: CopyArrayVec::new(),
            early_data: false,
            datagram: false,
            close: false,
            pmtud_probe: None,
            pto_probe: false,
        }
    }

    pub(super) fn push_control(&mut self, record: Control) -> bool {
        self.push_control_delivery(Delivery {
            record,
            probe: None,
        })
    }

    pub(super) fn contains_control(&self, record: Control) -> bool {
        self.controls
            .as_slice()
            .iter()
            .any(|delivery| delivery.record == record)
    }

    pub(super) fn push_control_delivery(&mut self, delivery: Delivery<Control>) -> bool {
        self.controls.push(delivery).is_ok()
    }

    pub(super) fn push_stream(&mut self, record: Stream) -> bool {
        self.push_stream_delivery(Delivery {
            record,
            probe: None,
        })
    }

    pub(super) fn push_stream_delivery(&mut self, delivery: Delivery<Stream>) -> bool {
        self.streams.push(delivery).is_ok()
    }
}
