use crate::{proto::datagram::Size, runtime::brand};
use o3::{buffer, mem::slot};

use std::net;

use crate::conn::wire::path;
use crate::{conn, stream};
use conn::scope;
use path::local::Assigned;

mod raw;

pub(in crate::runtime) struct Slot<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T>
{
    pub(in crate::runtime) conn: conn::Connection<DOMAIN, B, D>,
    alias: slot::Storage<Assigned>,
    pub(in crate::runtime) tls: Option<T>,
    pub(in crate::runtime) connection: C,
    pub(in crate::runtime) peer_addr: net::SocketAddr,
    pub(in crate::runtime) max_packet_bytes: Size,
    flags: Flags,
}

struct Flags {
    notified_established: bool,
    first_flush: bool,
    stream_first: bool,
}

impl<C, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, T> Slot<C, DOMAIN, B, D, T> {
    pub(in crate::runtime) const fn is_first(&self) -> bool {
        self.flags.first_flush
    }

    pub(in crate::runtime) fn new(
        conn: conn::Connection<DOMAIN, B, D>,
        tls: Option<T>,
        app: C,
        peer: net::SocketAddr,
        limit: Size,
    ) -> Self {
        Self {
            conn,
            alias: slot::Storage::new(()),
            tls,
            connection: app,
            peer_addr: peer,
            max_packet_bytes: limit,
            flags: Flags {
                notified_established: false,
                first_flush: true,
                stream_first: false,
            },
        }
    }

    pub(in crate::runtime) fn access<'loan, const TRACK: bool>(
        &'loan mut self,
        brand: brand::Token<'loan>,
    ) -> Access<'loan, C, DOMAIN, B, D, T, TRACK> {
        Access {
            conn: scope::Access::new(self.conn.machine_mut(), brand),
            tls: &mut self.tls,
            connection: &mut self.connection,
            peer_addr: &mut self.peer_addr,
            notified_established: &mut self.flags.notified_established,
            max_packet_bytes: &mut self.max_packet_bytes,
            first_flush: &mut self.flags.first_flush,
            stream_first: &mut self.flags.stream_first,
        }
    }
}

pub(in crate::runtime) struct Access<
    'loan,
    C,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
    T,
    const TRACK: bool,
> {
    pub(in crate::runtime) conn: scope::Access<'loan, DOMAIN, B, TRACK, D>,
    pub(in crate::runtime) tls: &'loan mut Option<T>,
    pub(in crate::runtime) connection: &'loan mut C,
    pub(in crate::runtime) peer_addr: &'loan mut net::SocketAddr,
    pub(in crate::runtime) notified_established: &'loan mut bool,
    pub(in crate::runtime) max_packet_bytes: &'loan mut Size,
    pub(in crate::runtime) first_flush: &'loan mut bool,
    pub(in crate::runtime) stream_first: &'loan mut bool,
}

#[derive(Default)]
pub(in crate::runtime) struct Epoch {
    generation: u32,
    used: bool,
}

impl Epoch {
    pub(in crate::runtime) const fn get(&self) -> u32 {
        self.generation
    }

    pub(in crate::runtime) fn matches(&self, epoch: u32) -> bool {
        self.used && self.generation == epoch
    }

    pub(in crate::runtime) fn claim(&mut self) -> Option<u32> {
        let epoch = if self.used {
            self.generation.checked_add(1)
        } else {
            self.used = true;
            Some(0)
        };
        if let Some(epoch) = epoch {
            self.generation = epoch;
        }
        epoch
    }
}
