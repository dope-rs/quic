use crate::conn::output::control;
use crate::conn::stream::state::transmit::queue;
use control::{encode, journal::storage, kind};
use o3::buffer;

/// Holds the original credit owner and control storage for one advisory selection.
pub(in crate::conn) struct Blocked<'a, T> {
    pending: &'a mut control::Pending,
    credit: T,
}

impl<'a, T> Blocked<'a, T> {
    pub(in crate::conn) fn new(pending: &'a mut control::Pending, credit: T) -> Self {
        Self { pending, credit }
    }
}

impl<K> Blocked<'_, &mut queue::Credit<K>> {
    fn send<E: From<control::Admission>>(
        self,
        record: encode::Blocked,
        emit: impl for<'b> FnOnce(encode::Selected<'b>) -> Result<(), E>,
    ) -> Result<(), E> {
        let probe = self.pending.probe.view();
        if let Some(key) = self.credit.blocked {
            let Some(slot) = self.pending.storage.owner(key) else {
                return Ok(());
            };
            return match slot.entry().status {
                storage::Status::Queued => {
                    emit(encode::Selected::blocked(slot.revision(), record, probe))
                }
                storage::Status::InFlight { .. } => Ok(()),
            };
        }
        let slot = self.pending.storage.try_insert(record.record())?;
        self.credit.blocked = Some(slot.owner());
        emit(encode::Selected::blocked(slot.revision(), record, probe))
    }
}

impl Blocked<'_, &mut queue::Credit<kind::DataBlocked>> {
    pub(in crate::conn) fn try_data<E: From<control::Admission>>(
        self,
        emit: impl for<'b> FnOnce(encode::Selected<'b>) -> Result<(), E>,
    ) -> Result<(), E> {
        let record = encode::Blocked::Data(self.credit.limit());
        self.send(record, emit)
    }
}

impl<D: buffer::raw::Segment> Blocked<'_, &mut queue::Occupied<'_, D>> {
    pub(in crate::conn) fn try_stream<E: From<control::Admission>>(
        self,
        emit: impl for<'b> FnOnce(encode::Selected<'b>) -> Result<(), E>,
    ) -> Result<(), E> {
        let id = self.credit.id();
        let credit = self.credit.credit_mut();
        let record = encode::Blocked::Stream(id, credit.limit());
        Blocked::new(self.pending, credit).send(record, emit)
    }
}

const _: () = {
    assert!(
        std::mem::size_of::<Blocked<'static, &'static mut queue::Credit<kind::DataBlocked>>>()
            == 16
    );
    assert!(
        std::mem::size_of::<
            Blocked<'static, &'static mut queue::Occupied<'static, o3::buffer::storage::Shared>>,
        >() == 16
    );
};
