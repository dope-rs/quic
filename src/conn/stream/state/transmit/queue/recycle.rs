use crate::conn::output::control;
use crate::conn::stream::resident::slot;
use crate::conn::stream::state::transmit::log::journal;
use crate::conn::stream::state::transmit::queue;
use crate::stream::outbound;
use crate::wire::varint;

/// Exclusive owners required to detach and recycle one send entry.
pub(in crate::conn) struct Recycle<'a> {
    control: &'a mut control::Pending,
    deliveries: &'a mut journal::Journal,
}

impl<'a> Recycle<'a> {
    pub(in crate::conn) fn new(
        ctrl: &'a mut control::Pending,
        log: &'a mut journal::Journal,
    ) -> Self {
        Self {
            control: ctrl,
            deliveries: log,
        }
    }
}

impl slot::Recycle for Recycle<'_> {
    type Value = queue::Entry;

    fn recycle(self, value: &mut Self::Value) {
        self.control.clear(&mut value.reset_stream);
        self.control.remove(&mut value.credit.blocked);
        if let Some(group) = value.delivery_group.take() {
            self.deliveries.cancel(group);
        }
        value.stream = outbound::Sender::default();
        value.credit = queue::Credit::new(varint::VarInt::ZERO);
    }
}

const _: () = assert!(std::mem::size_of::<Recycle<'_>>() == 2 * std::mem::size_of::<usize>());
