use super::delivery::{ControlRecord, CryptoRecord, DeliveryHandle, StreamRecord};
use super::{Epoch, PACKET_CONTROL_CAPACITY, PACKET_STREAM_CAPACITY};

pub(super) struct PeerStreamSendState {
    pub(super) limit: u64,
    pub(super) final_offset: Option<u64>,
    pub(super) deliveries: usize,
    pub(super) retransmits: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct DeliveryCommit<T> {
    pub(super) record: T,
    pub(super) probe: Option<DeliveryHandle>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum CryptoCommit {
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

pub(super) struct PacketCommit {
    pub(super) epoch: Epoch,
    pub(super) pn: u64,
    pub(super) bytes: usize,
    pub(super) ack_eliciting: bool,
    pub(super) in_flight: bool,
    pub(super) ack_included: bool,
    pub(super) crypto: Option<CryptoCommit>,
    pub(super) crypto_probe: Option<DeliveryCommit<CryptoRecord>>,
    pub(super) controls: [Option<DeliveryCommit<ControlRecord>>; PACKET_CONTROL_CAPACITY],
    pub(super) control_len: usize,
    pub(super) streams: [Option<DeliveryCommit<StreamRecord>>; PACKET_STREAM_CAPACITY],
    pub(super) stream_len: usize,
    pub(super) early_data: bool,
    pub(super) datagram: bool,
    pub(super) close: bool,
    pub(super) pmtud_probe: Option<u64>,
    pub(super) pto_probe: bool,
}

impl PacketCommit {
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
            controls: [None; PACKET_CONTROL_CAPACITY],
            control_len: 0,
            streams: [None; PACKET_STREAM_CAPACITY],
            stream_len: 0,
            early_data: false,
            datagram: false,
            close: false,
            pmtud_probe: None,
            pto_probe: false,
        }
    }

    pub(super) fn push_control(&mut self, record: ControlRecord) -> bool {
        self.push_control_delivery(DeliveryCommit {
            record,
            probe: None,
        })
    }

    pub(super) fn push_control_delivery(
        &mut self,
        delivery: DeliveryCommit<ControlRecord>,
    ) -> bool {
        let Some(slot) = self.controls.get_mut(self.control_len) else {
            return false;
        };
        *slot = Some(delivery);
        self.control_len += 1;
        true
    }

    pub(super) fn push_stream(&mut self, record: StreamRecord) -> bool {
        self.push_stream_delivery(DeliveryCommit {
            record,
            probe: None,
        })
    }

    pub(super) fn push_stream_delivery(&mut self, delivery: DeliveryCommit<StreamRecord>) -> bool {
        let Some(slot) = self.streams.get_mut(self.stream_len) else {
            return false;
        };
        *slot = Some(delivery);
        self.stream_len += 1;
        true
    }
}
