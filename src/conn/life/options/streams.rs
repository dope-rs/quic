use std::num;

use o3::depot::capacity;

use crate::conn;
use crate::conn::life::options::builder;
use crate::wire::ranges;
use conn::stream::{self, event::queue};

pub struct Streams {
    events: usize,
    receive_segments: usize,
    max_send_bytes: usize,
    max_send_resident: usize,
    send_segments: usize,
    local_bidi: usize,
    local_uni: usize,
}

pub(in crate::conn) struct Limits {
    events: queue::Plan,
    receive_segments: Parts,
    max_send_bytes: num::NonZero<usize>,
    max_send_resident: num::NonZero<usize>,
    send_segments: Parts,
    local: [stream::Count; 2],
    peer: [stream::Count; 2],
    capacities: stream::Capacities,
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::conn) struct Parts(num::NonZero<usize>);

impl Streams {
    pub(super) const DEFAULT: Self = Self {
        events: queue::Plan::DEFAULT.get(),
        receive_segments: ranges::MAX,
        max_send_bytes: 64 * 1024 * 1024,
        max_send_resident: 64 * 1024 * 1024,
        send_segments: 4096,
        local_bidi: 1024,
        local_uni: 1024,
    };

    pub fn events(mut self, value: usize) -> Self {
        self.events = value;
        self
    }

    pub fn recv_parts(mut self, value: usize) -> Self {
        self.receive_segments = value;
        self
    }

    pub fn send_bytes(mut self, value: usize) -> Self {
        self.max_send_bytes = value;
        self
    }

    pub fn resident(mut self, value: usize) -> Self {
        self.max_send_resident = value;
        self
    }

    pub fn send_parts(mut self, value: usize) -> Self {
        self.send_segments = value;
        self
    }

    pub fn local_bidi(mut self, value: usize) -> Self {
        self.local_bidi = value;
        self
    }

    pub fn local_uni(mut self, value: usize) -> Self {
        self.local_uni = value;
        self
    }

    pub(super) const fn try_prove(
        self,
        peer: [stream::Count; 2],
    ) -> Result<Limits, builder::Invalid> {
        let events = match queue::Plan::try_new(self.events) {
            Ok(events) => events,
            Err(error) => return Err(error),
        };
        let Some(recv) = Parts::new(self.receive_segments) else {
            return Err(builder::Invalid::ReceiveSegments {
                actual: self.receive_segments,
                minimum: 1,
                maximum: conn::MAX_QUEUE_CAPACITY,
            });
        };
        let Some(bytes) = num::NonZero::new(self.max_send_bytes) else {
            return Err(builder::Invalid::SendBytes {
                actual: self.max_send_bytes,
                minimum: 1,
                maximum: usize::MAX,
            });
        };
        let Some(resident) = num::NonZero::new(self.max_send_resident) else {
            return Err(builder::Invalid::SendResident {
                actual: self.max_send_resident,
                minimum: 1,
                maximum: usize::MAX,
            });
        };
        let Some(send) = Parts::new(self.send_segments) else {
            return Err(builder::Invalid::SendSegments {
                actual: self.send_segments,
                minimum: 1,
                maximum: conn::MAX_QUEUE_CAPACITY,
            });
        };
        let Some(bidi) = stream::Count::from_usize(self.local_bidi) else {
            return Err(builder::Invalid::LocalBidi {
                actual: self.local_bidi,
                minimum: 0,
                maximum: conn::MAX_STREAMS as usize,
            });
        };
        let Some(uni) = stream::Count::from_usize(self.local_uni) else {
            return Err(builder::Invalid::LocalUni {
                actual: self.local_uni,
                minimum: 0,
                maximum: conn::MAX_STREAMS as usize,
            });
        };
        let local = [bidi, uni];
        Ok(Limits {
            events,
            receive_segments: recv,
            max_send_bytes: bytes,
            max_send_resident: resident,
            send_segments: send,
            local,
            peer,
            capacities: stream::Capacities::new(local, peer),
        })
    }
}

impl Parts {
    const fn new(value: usize) -> Option<Self> {
        match num::NonZero::new(value) {
            Some(value) if value.get() <= conn::MAX_QUEUE_CAPACITY => Some(Self(value)),
            _ => None,
        }
    }
}

impl capacity::Extent for Parts {
    fn get(self) -> usize {
        self.0.get()
    }
}

impl Limits {
    pub(in crate::conn) const fn events(&self) -> queue::Plan {
        self.events
    }

    pub(in crate::conn) const fn capacities(&self) -> stream::Capacities {
        self.capacities
    }

    pub(in crate::conn) const fn recv_parts(&self) -> Parts {
        self.receive_segments
    }

    pub(in crate::conn) const fn send_bytes(&self) -> num::NonZero<usize> {
        self.max_send_bytes
    }

    pub(in crate::conn) const fn resident(&self) -> num::NonZero<usize> {
        self.max_send_resident
    }

    pub(in crate::conn) const fn send_parts(&self) -> Parts {
        self.send_segments
    }

    pub(in crate::conn) const fn local(&self) -> [stream::Count; 2] {
        self.local
    }

    pub(in crate::conn) const fn peer(&self) -> [stream::Count; 2] {
        self.peer
    }

    pub(super) const fn into_draft(self) -> Streams {
        Streams {
            events: self.events.get(),
            receive_segments: self.receive_segments.0.get(),
            max_send_bytes: self.max_send_bytes.get(),
            max_send_resident: self.max_send_resident.get(),
            send_segments: self.send_segments.0.get(),
            local_bidi: self.local[0].get(),
            local_uni: self.local[1].get(),
        }
    }

    pub(super) const fn copy(&self) -> Self {
        Self {
            events: self.events,
            receive_segments: self.receive_segments,
            max_send_bytes: self.max_send_bytes,
            max_send_resident: self.max_send_resident,
            send_segments: self.send_segments,
            local: self.local,
            peer: self.peer,
            capacities: self.capacities,
        }
    }
}

impl Default for Streams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const _: () = {
    assert!(std::mem::size_of::<Parts>() == std::mem::size_of::<usize>());
    assert!(std::mem::size_of::<Option<Parts>>() == std::mem::size_of::<Parts>());
    assert!(
        std::mem::size_of::<Limits>()
            <= std::mem::size_of::<Streams>()
                + std::mem::size_of::<queue::Plan>()
                + std::mem::size_of::<[stream::Count; 2]>()
                + std::mem::size_of::<stream::Capacities>()
    );
};
