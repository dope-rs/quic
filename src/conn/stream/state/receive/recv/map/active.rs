use std::mem;

use crate::conn::output::control::{self, journal::records};
use crate::conn::stream::event::queue::readable;
use crate::conn::stream::resident::slot::{plane, store};
use crate::conn::stream::state::receive::recv::{self, map};
use crate::stream::Recv;
use crate::wire::{stream, varint};

pub(in crate::conn) struct Active<'a, B: Recv> {
    pub(in crate::conn::stream::state::receive::recv::map) inner:
        store::Active<'a, map::Side, recv::Entry<B>, Option<readable::Handle>, plane::HeadOnly>,
}

impl<B: Recv> Active<'_, B> {
    pub(in crate::conn) fn id(&self) -> stream::Id {
        self.inner.id()
    }

    pub(in crate::conn) fn has_credit(&mut self) -> bool {
        self.inner.get_mut().state.has_credit()
    }

    pub(in crate::conn) fn try_credit(
        &mut self,
        base: varint::VarInt,
        ctrl: &mut records::Records<&mut control::Pending>,
    ) -> Result<(), control::Admission> {
        let id = self.id();
        let stream = &mut self.inner.get_mut().state;
        ctrl.try_stream(&mut stream.max_stream_data, id, stream.credit.limit(base))?;
        stream.clear_credit();
        Ok(())
    }

    pub(in crate::conn) fn try_stop(
        &mut self,
        ctrl: &mut records::Records<&mut control::Pending>,
    ) -> Result<bool, control::Admission> {
        let id = self.id();
        let Some(stop) = self.inner.get_mut().state.stop_sending.deferred() else {
            return Ok(false);
        };
        stop.try_queue(ctrl, id)?;
        Ok(true)
    }

    pub(in crate::conn) fn has_deferred(&mut self) -> bool {
        self.inner.get_mut().state.has_deferred()
    }

    pub(in crate::conn) fn deactivate(self) {
        self.inner.deactivate();
    }

    pub(in crate::conn) fn move_to_back(self) {
        self.inner.move_to_back();
    }
}

const _: () = assert!(
    mem::size_of::<Active<'static, Vec<u8>>>()
        == mem::size_of::<
            store::Active<
                'static,
                map::Side,
                recv::Entry<Vec<u8>>,
                Option<readable::Handle>,
                plane::HeadOnly,
            >,
        >()
);
