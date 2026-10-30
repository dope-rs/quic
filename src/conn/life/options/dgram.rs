use o3::base::num::bounded;

use crate::conn;
use crate::conn::life::options::builder;

pub struct Dgram {
    pending: usize,
    incoming: usize,
}

pub(in crate::conn) type Capacity = bounded::Usize<{ conn::MAX_QUEUE_CAPACITY }>;

#[derive(Clone, Copy)]
pub(in crate::conn) struct Datagrams {
    pending: Capacity,
    incoming: Capacity,
}

impl Dgram {
    pub(super) const DEFAULT: Self = Self {
        pending: 1024,
        incoming: 1024,
    };

    pub fn pending(mut self, value: usize) -> Self {
        self.pending = value;
        self
    }

    pub fn incoming(mut self, value: usize) -> Self {
        self.incoming = value;
        self
    }

    pub(super) const fn try_prove(self) -> Result<Datagrams, builder::Invalid> {
        let Ok(pending) = Capacity::ZERO.try_add(self.pending) else {
            return Err(builder::Invalid::PendingDatagrams {
                actual: self.pending,
                minimum: 0,
                maximum: conn::MAX_QUEUE_CAPACITY,
            });
        };
        let Ok(incoming) = Capacity::ZERO.try_add(self.incoming) else {
            return Err(builder::Invalid::IncomingDatagrams {
                actual: self.incoming,
                minimum: 0,
                maximum: conn::MAX_QUEUE_CAPACITY,
            });
        };
        Ok(Datagrams { pending, incoming })
    }
}

impl Datagrams {
    pub(in crate::conn) const fn pending(&self) -> Capacity {
        self.pending
    }

    pub(in crate::conn) const fn incoming(&self) -> Capacity {
        self.incoming
    }

    pub(super) const fn into_draft(self) -> Dgram {
        Dgram {
            pending: self.pending.get(),
            incoming: self.incoming.get(),
        }
    }
}

impl Default for Dgram {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const _: () = {
    assert!(std::mem::size_of::<Capacity>() == std::mem::size_of::<usize>());
    assert!(std::mem::size_of::<Datagrams>() == std::mem::size_of::<Dgram>());
};
