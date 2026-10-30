use crate::conn::output::journals::stack;
use o3::depot::capacity;

use crate::conn::output::control::revision;
use crate::conn::output::delivery;
use crate::conn::output::journals::{self, controls, streams};

pub(in crate::conn::output) struct Pools {
    controls: stack::raw::Slab<revision::Key, controls::Tag>,
    streams: stack::raw::Slab<delivery::Handle<delivery::Stream>, streams::Tag>,
}

pub(in crate::conn::output::journals) struct Backing<'a> {
    controls: stack::raw::Growth<'a, revision::Key, controls::Tag>,
    streams: stack::raw::Growth<'a, delivery::Handle<delivery::Stream>, streams::Tag>,
}

impl Backing<'_> {
    pub(in crate::conn::output::journals) fn commit(self) {
        self.controls.commit();
        self.streams.commit();
    }
}

impl Pools {
    pub(in crate::conn::output::journals) fn new(controls: u16, streams: u16) -> Self {
        Self {
            controls: stack::raw::Slab::with_limit(controls),
            streams: stack::raw::Slab::with_limit(streams),
        }
    }

    pub(in crate::conn::output::journals) fn entry<'a>(
        &'a mut self,
        packet: &'a mut journals::Packet,
    ) -> journals::Entry<'a> {
        journals::Entry::new(packet, &mut self.controls, &mut self.streams)
    }

    pub(in crate::conn::output::journals) fn drain<'a>(
        &'a mut self,
        packet: &mut journals::Packet,
    ) -> (
        stack::raw::Drain<'a, revision::Key, controls::Tag>,
        stack::raw::Drain<'a, delivery::Handle<delivery::Stream>, streams::Tag>,
    ) {
        // SAFETY: every packet head is created empty and can only enter this table.
        let controls = unsafe { self.controls.drain(&mut packet.carriers.controls) };
        // SAFETY: the stream head has the same structural association as above.
        let streams = unsafe { self.streams.drain(&mut packet.carriers.streams) };
        (controls, streams)
    }

    pub(in crate::conn::output::journals) fn has_room(
        &self,
        controls: usize,
        streams: usize,
    ) -> bool {
        self.controls.available() >= controls && self.streams.available() >= streams
    }

    pub(in crate::conn::output::journals) fn can_admit(&self, demand: journals::Demand) -> bool {
        let (controls, streams) = demand.counts();
        self.controls.available() >= usize::from(controls.get())
            && self.streams.available() >= usize::from(streams.get())
    }

    pub(in crate::conn::output::journals) fn try_grow(
        &mut self,
        demand: journals::Demand,
    ) -> Result<Backing<'_>, capacity::Reason> {
        let (control, stream) = demand.counts();
        let Self {
            controls, streams, ..
        } = self;
        let controls = controls.try_grow(usize::from(control.get()))?;
        let streams = streams.try_grow(usize::from(stream.get()))?;
        Ok(Backing { controls, streams })
    }

    pub(in crate::conn::output::journals) fn resident(&self) -> usize {
        self.controls.bytes().saturating_add(self.streams.bytes())
    }
}

const _: () = assert!(std::mem::size_of::<Pools>() == 4 * std::mem::size_of::<usize>());
const _: () = assert!(std::mem::size_of::<Backing<'static>>() == 6 * std::mem::size_of::<usize>());
