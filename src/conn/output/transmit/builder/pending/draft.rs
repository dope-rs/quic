use crate::conn::output::transmit::builder::pending::records::Records;
use crate::{
    conn::{
        self,
        output::{control::encode, transmit},
        stream::state::transmit::log::journal,
        wire::{crypto::tx, tls},
    },
    proto::recovery::numbers,
    stream,
};
use o3::buffer::{self, resident};
use std::mem;

/// Consumes the packet writer before its selected CRYPTO operation is reserved.
pub(super) struct Draft<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment, C = ()> {
    pub(super) records: Records<'a, DOMAIN, B, D>,
    pub(super) destination: transmit::Destination,
    pub(super) crypto: C,
}

pub(super) struct Context<'a, const DOMAIN: u8> {
    pub(super) keys: tls::Borrow<'a, DOMAIN>,
    pub(super) spaces: &'a mut [numbers::PnSpace; 3],
    pub(super) scratch: &'a mut conn::Scratch,
}

impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> Draft<'a, DOMAIN, B, D> {
    pub(super) fn conn(&self) -> &conn::Machine<DOMAIN, B, D> {
        self.records.conn()
    }

    pub(super) fn controls(&self) -> &[encode::Written] {
        self.records.controls()
    }

    pub(super) fn streams(&self) -> &[journal::Entry] {
        self.records.streams()
    }

    pub(super) fn destination(&self) -> transmit::Destination {
        self.destination
    }

    pub(super) fn cancel(self) -> &'a mut conn::Scratch {
        self.records.cancel().into_scratch()
    }
}

// SAFETY: Draft consumes the original packet writer and its selections. Its
// mutable context contains only disjoint keys, packet numbers, and scratch.
// The consuming output has no CRYPTO selection that could be committed twice.
unsafe impl<'a, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment> tx::raw::Owner
    for Draft<'a, DOMAIN, B, D>
{
    type Input = Draft<'a, DOMAIN, B, D, Option<tx::Commit>>;
    type Output = Records<'a, DOMAIN, B, D>;
    type Context<'b>
        = Context<'b, DOMAIN>
    where
        Self: 'b;

    fn tx(&self) -> &tx::Tx {
        &self.records.conn().handshake.crypto
    }

    fn select(input: Self::Input) -> (Self, Option<tx::Commit>) {
        let Draft {
            records,
            destination: target,
            crypto,
        } = input;
        (
            Self {
                records,
                destination: target,
                crypto: (),
            },
            crypto,
        )
    }

    fn reject(self, selected: tx::Commit) -> Self::Input {
        let Self {
            records,
            destination: target,
            crypto: (),
        } = self;
        Draft {
            records,
            destination: target,
            crypto: Some(selected),
        }
    }

    fn parts(&mut self) -> (&mut tx::Tx, Self::Context<'_>) {
        self.records.parts()
    }

    fn finish(self) -> Self::Output {
        self.records
    }
}

const _: () = {
    assert!(mem::size_of::<Context<'static, 0>>() == 3 * mem::size_of::<usize>());
    assert!(mem::size_of::<tls::Borrow<'static, 0>>() == mem::size_of::<usize>());
    assert!(
        mem::size_of::<Draft<'static, 0, Vec<u8>, resident::Shared<'static>, Option<tx::Commit>>>()
            == mem::size_of::<Draft<'static, 0, Vec<u8>, resident::Shared<'static>>>()
                + mem::size_of::<Option<tx::Commit>>()
    );
    assert!(
        mem::size_of::<tx::Prepared<Draft<'static, 0, Vec<u8>, resident::Shared<'static>>>>()
            <= mem::size_of::<Draft<'static, 0, Vec<u8>, resident::Shared<'static>>>()
                + mem::size_of::<tx::Commit>()
                + 2 * mem::size_of::<usize>()
    );
};
