use crate::conn;
use crate::conn::delivery;
use o3::collections::fixed::array;

#[derive(Debug, Clone, Copy)]
pub(super) struct Delivery<T> {
    pub(super) record: T,
    /// A generation-checked selected slot, probe, or retransmission.
    pub(super) tracked: Option<delivery::Handle<T>>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ControlDelivery {
    pub(super) record: delivery::Control,
    pub(super) handle: delivery::Handle<delivery::Control>,
}

pub(super) struct Packet {
    pub(super) epoch: conn::Epoch,
    pub(super) pn: u64,
    pub(super) bytes: usize,
    pub(super) ack_eliciting: bool,
    pub(super) in_flight: bool,
    pub(super) ack_included: bool,
    pub(super) crypto: Option<Delivery<delivery::Crypto>>,
    pub(super) controls: array::CopyInline<ControlDelivery, { conn::PACKET_CONTROL_CAPACITY }>,
    pub(super) streams:
        array::CopyInline<Delivery<delivery::Stream>, { conn::PACKET_STREAM_CAPACITY }>,
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
    pub(super) fn new(epoch: conn::Epoch, pn: u64) -> Self {
        Self {
            epoch,
            pn,
            bytes: 0,
            ack_eliciting: false,
            in_flight: false,
            ack_included: false,
            crypto: None,
            controls: array::CopyInline::new(),
            streams: array::CopyInline::new(),
            early_data: false,
            datagram: false,
            close: false,
            pmtud_probe: None,
            pto_probe: false,
        }
    }

    pub(super) fn contains_control(&self, record: delivery::Control) -> bool {
        self.controls
            .as_slice()
            .iter()
            .any(|delivery| delivery.record == record)
    }

    pub(super) fn push_control_delivery(
        &mut self,
        record: delivery::Control,
        handle: delivery::Handle<delivery::Control>,
    ) -> bool {
        self.controls
            .push(ControlDelivery { record, handle })
            .is_ok()
    }

    pub(super) fn push_stream(&mut self, record: delivery::Stream) -> bool {
        self.push_stream_delivery(Delivery {
            record,
            tracked: None,
        })
    }

    pub(super) fn push_stream_delivery(&mut self, delivery: Delivery<delivery::Stream>) -> bool {
        self.streams.push(delivery).is_ok()
    }
}

const _: () = assert!(
    std::mem::size_of::<ControlDelivery>() == std::mem::size_of::<Delivery<delivery::Control>>()
);
