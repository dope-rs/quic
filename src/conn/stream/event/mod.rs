pub(in crate::conn) mod queue;

use crate::runtime::brand;

use o3::buffer::{self, resident};

use std::mem;

use crate::conn::stream::id;
use crate::{conn, stream};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Item<'conn> {
    Writable,
    Readable {
        id: id::Receive<'conn>,
    },
    Reset {
        id: id::Receive<'conn>,
        error_code: crate::errors::Code,
    },
    Stopped {
        id: id::Send<'conn>,
        error_code: crate::errors::Code,
    },
}

impl<'conn> Item<'conn> {
    fn bind(brand: brand::Token<'conn>, event: queue::Record) -> Self {
        match event {
            queue::Record::Writable => Self::Writable,
            queue::Record::Readable { id, .. } => Self::Readable {
                id: id::Receive::new(brand, id),
            },
            queue::Record::Reset {
                id,
                error_code: code,
            } => Self::Reset {
                id: id::Receive::new(brand, id),
                error_code: code,
            },
            queue::Record::Stopped {
                id,
                error_code: code,
            } => Self::Stopped {
                id: id::Send::new(brand, id),
                error_code: code,
            },
        }
    }
}

/// Scoped stream event queue.
#[repr(transparent)]
pub struct Queue<
    'access,
    'conn,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool,
    D: buffer::raw::Segment,
> {
    connection: &'access mut conn::Machine<DOMAIN, B, D>,
    brand: brand::Token<'conn>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Queue<'_, 'conn, DOMAIN, B, RECONCILE, D>
{
    pub(super) fn new<'access>(
        conn: &'access mut conn::Machine<DOMAIN, B, D>,
        brand: brand::Token<'conn>,
    ) -> Queue<'access, 'conn, DOMAIN, B, RECONCILE, D> {
        Queue {
            connection: conn,
            brand,
        }
    }

    pub fn poll(&mut self) -> Option<Item<'conn>> {
        let event = self
            .connection
            .streams
            .poll_event()
            .map(|event| Item::bind(self.brand, event));
        if event.is_some() {
            self.connection.record::<RECONCILE>(conn::Effects::NOTIFY);
        }
        event
    }
}

const _: () = {
    assert!(
        mem::size_of::<Queue<'static, 'static, 0, Vec<u8>, false, resident::Shared<'static>>>()
            == mem::size_of::<&mut conn::Machine<0, Vec<u8>, resident::Shared<'static>>>()
    );
};
