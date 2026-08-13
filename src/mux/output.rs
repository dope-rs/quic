use std::iter;
use std::time;

use o3::collections::queue::fixed;

use crate::conn;
use crate::stream;

use super::drive::DriveOps as _;
use crate::mux;

pub(super) struct Storage {
    pub(super) pending: fixed::Fifo<mux::Outgoing>,
    pub(super) packets: usize,
    pub(super) bytes: usize,
    pub(super) bytes_capacity: usize,
    pub(super) batch: Option<conn::packet::Gso>,
    pub(super) recycled: Vec<Vec<u8>>,
}

impl Storage {
    pub(super) fn new(capacity: usize, bytes_capacity: usize) -> Self {
        Self {
            pending: fixed::Fifo::with_capacity(capacity),
            packets: 0,
            bytes: 0,
            bytes_capacity,
            batch: None,
            recycled: Vec::with_capacity(capacity),
        }
    }

    pub(super) fn take_packet(&mut self, required: usize) -> Option<Vec<u8>> {
        let mut packet = self.recycled.pop().unwrap_or_default();
        packet.clear();
        if packet.try_reserve_exact(required).is_err() {
            self.recycle_packet(packet);
            return None;
        }
        Some(packet)
    }

    pub(super) fn recycle_packet(&mut self, mut packet: Vec<u8>) {
        packet.clear();
        if let Some(batch) = self.batch.as_mut()
            && batch.buf.capacity() == 0
        {
            batch.buf = packet;
            return;
        }
        if self.recycled.len() < self.recycled.capacity() {
            self.recycled.push(packet);
        }
    }
}

pub(crate) trait State {
    fn has_buffered_output(&self) -> bool;
}

impl<
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> State for mux::Router<'tls, H, P, DOMAIN, B>
{
    fn has_buffered_output(&self) -> bool {
        !self.outgoing.pending.is_empty()
    }
}

pub struct Queue<'a, 'tls, H, P, const DOMAIN: u8, B: stream::ReceiveBuffer = Vec<u8>>
where
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
{
    mux: &'a mut mux::Router<'tls, H, P, DOMAIN, B>,
}

impl<
    'a,
    'tls,
    H: mux::Handler<DOMAIN, B>,
    P: conn::server::Policy,
    const DOMAIN: u8,
    B: stream::ReceiveBuffer,
> Queue<'a, 'tls, H, P, DOMAIN, B>
{
    pub(super) fn new(mux: &'a mut mux::Router<'tls, H, P, DOMAIN, B>) -> Self {
        Self { mux }
    }

    pub fn drain(mut self) -> impl Iterator<Item = mux::Outgoing> + 'a {
        let now = time::Instant::now();
        let mut work_remaining = if self.mux.lifecycle.shutting_down {
            0
        } else {
            mux::DIRECT_DRIVE_BUDGET
        };
        let mut output_remaining = work_remaining;
        iter::from_fn(move || {
            loop {
                if output_remaining == 0 {
                    return None;
                }
                if let Some(outgoing) = self.pop() {
                    output_remaining -= 1;
                    return Some(outgoing);
                }
                if work_remaining == 0 || !self.mux.drive_one_inner(now) {
                    return None;
                }
                work_remaining -= 1;
            }
        })
    }

    pub fn capacity(&self) -> usize {
        self.mux.outgoing.pending.capacity()
    }

    pub fn len(&self) -> usize {
        self.mux.outgoing.packets
    }

    pub fn is_empty(&self) -> bool {
        self.mux.outgoing.pending.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.mux.outgoing.bytes
    }

    pub fn bytes_capacity(&self) -> usize {
        self.mux.outgoing.bytes_capacity
    }

    /// Returns a completed outgoing allocation to this Mux's packet pool.
    ///
    /// Custom transports should call this after they no longer access the
    /// packet. The integrated endpoint does so automatically after the kernel
    /// releases the send buffer.
    pub fn recycle(&mut self, outgoing: mux::Outgoing) {
        self.mux.outgoing.recycle_packet(outgoing.into_storage());
    }

    pub(crate) fn pop(&mut self) -> Option<mux::Outgoing> {
        let outgoing = self.mux.outgoing.pending.pop_front()?;
        self.mux.outgoing.packets -= outgoing.packets();
        self.mux.outgoing.bytes -= outgoing.bytes();
        Some(outgoing)
    }

    pub(crate) fn push_front(&mut self, outgoing: mux::Outgoing) -> Result<(), mux::Outgoing> {
        let packets = outgoing.packets();
        let bytes = outgoing.bytes();
        self.mux.outgoing.pending.push_front(outgoing)?;
        self.mux.outgoing.packets += packets;
        self.mux.outgoing.bytes += bytes;
        Ok(())
    }

    pub fn drive_bounded(&mut self, now: time::Instant) -> usize {
        if self.mux.lifecycle.shutting_down {
            return 0;
        }
        let mut driven = 0;
        while driven != mux::DIRECT_DRIVE_BUDGET && self.mux.drive_one_inner(now) {
            driven += 1;
        }
        driven
    }
}
