use super::delivery::{self, Control, Handle, Stream};
use super::{Epoch, PACKET_CONTROL_CAPACITY, PACKET_STREAM_CAPACITY};
use o3::collections::fixed::array::CopyInline;

#[derive(Debug, Clone, Copy)]
pub(super) struct Delivery<T> {
    pub(super) record: T,
    /// A generation-checked selected slot, probe, or retransmission.
    pub(super) tracked: Option<Handle<T>>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ControlDelivery {
    pub(super) record: Control,
    pub(super) handle: Handle<Control>,
}

pub(super) struct Packet {
    pub(super) epoch: Epoch,
    pub(super) pn: u64,
    pub(super) bytes: usize,
    pub(super) ack_eliciting: bool,
    pub(super) in_flight: bool,
    pub(super) ack_included: bool,
    pub(super) crypto: Option<Delivery<delivery::Crypto>>,
    pub(super) controls: CopyInline<ControlDelivery, PACKET_CONTROL_CAPACITY>,
    pub(super) streams: CopyInline<Delivery<Stream>, PACKET_STREAM_CAPACITY>,
    pub(super) early_data: bool,
    pub(super) datagram: bool,
    pub(super) close: bool,
    pub(super) pmtud_probe: Option<u64>,
    pub(super) pto_probe: bool,
}

pub(super) struct Datagram {
    pub(super) pn: u64,
    pub(super) bytes: usize,
    pub(super) ack_included: bool,
    pub(super) datagram: bool,
    pub(super) in_flight: bool,
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
            controls: CopyInline::new(),
            streams: CopyInline::new(),
            early_data: false,
            datagram: false,
            close: false,
            pmtud_probe: None,
            pto_probe: false,
        }
    }

    pub(super) fn contains_control(&self, record: Control) -> bool {
        self.controls
            .as_slice()
            .iter()
            .any(|delivery| delivery.record == record)
    }

    pub(super) fn push_control_delivery(
        &mut self,
        record: Control,
        handle: Handle<Control>,
    ) -> bool {
        self.controls
            .push(ControlDelivery { record, handle })
            .is_ok()
    }

    pub(super) fn push_stream(&mut self, record: Stream) -> bool {
        self.push_stream_delivery(Delivery {
            record,
            tracked: None,
        })
    }

    pub(super) fn push_stream_delivery(&mut self, delivery: Delivery<Stream>) -> bool {
        self.streams.push(delivery).is_ok()
    }
}

const _: () =
    assert!(std::mem::size_of::<ControlDelivery>() == std::mem::size_of::<Delivery<Control>>());
