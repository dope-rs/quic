use crate::conn::wire::ingress::events;
use o3::buffer;

use std::{mem, ops, time};

use crate::{conn, security::crypto, stream, wire::packet};
use conn::wire::ingress;
use frames::sources;
use ingress::frames;
use packet::{cid, kind, long};

pub(in crate::conn::wire::ingress) trait LongKind:
    kind::Long
{
    const FRAME_KIND: frames::PacketKind;
}

impl LongKind for kind::Initial {
    const FRAME_KIND: frames::PacketKind = frames::PacketKind::INITIAL;
}

impl LongKind for kind::Handshake {
    const FRAME_KIND: frames::PacketKind = frames::PacketKind::HANDSHAKE;
}

impl LongKind for kind::ZeroRtt {
    const FRAME_KIND: frames::PacketKind = frames::PacketKind::ZERO_RTT;
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub(in crate::conn::wire::ingress) enum Cid {
    None,
    Short(cid::Len, time::Duration),
}

/// Authenticated body owning the packet storage from which it was derived.
#[must_use = "an authenticated packet body must be committed or deliberately dropped"]
pub(in crate::conn) struct Packet<P: buffer::raw::Source> {
    packet: P,
    meta: frames::PacketMeta,
    body: ops::Range<usize>,
    cid: Cid,
}

impl<P: long::Buffer> Packet<P> {
    pub(in crate::conn::wire::ingress) fn long<K: LongKind>(
        plain: long::Decrypted<K, P>,
        now: time::Instant,
    ) -> Self {
        let (pn, packet, body) = plain.into_bound();
        Self {
            packet,
            meta: frames::PacketMeta::new(K::FRAME_KIND, pn, now),
            body,
            cid: Cid::None,
        }
    }

    pub(in crate::conn::wire::ingress) fn one_rtt(
        opened: crypto::Opened<P>,
        now: time::Instant,
        pto: time::Duration,
    ) -> Self {
        let width = opened.cid_len();
        let (pn, packet, body) = opened.into_parts();
        Self {
            packet,
            meta: frames::PacketMeta::new(frames::PacketKind::ONE_RTT, pn, now),
            body,
            cid: Cid::Short(width, pto),
        }
    }
}

impl<P: buffer::raw::Source> Packet<P> {
    pub(super) fn freeze(self) -> Packet<P::Output>
    where
        P: buffer::raw::Freeze,
    {
        Packet {
            packet: self.packet.freeze(),
            meta: self.meta,
            body: self.body,
            cid: self.cid,
        }
    }

    pub(super) fn with<R>(self, read: impl FnOnce(&P, Packet<&[u8]>) -> R) -> R {
        let Self {
            packet,
            meta,
            body,
            cid,
        } = self;
        let auth = Packet {
            packet: packet.as_ref(),
            meta,
            body,
            cid,
        };
        read(&packet, auth)
    }

    pub(super) fn borrow(&self) -> (frames::PacketMeta, usize, &[u8]) {
        (self.meta, self.body.start, self.body())
    }

    fn body(&self) -> &[u8] {
        // SAFETY: both constructors transfer the authenticated range together
        // with its stable owner, which freezing and shared projection preserve.
        unsafe { self.packet.as_ref().get_unchecked(self.body.clone()) }
    }

    pub(super) fn cid(&self) -> Option<(&[u8], time::Duration)> {
        let Cid::Short(width, pto) = self.cid else {
            return None;
        };
        // SAFETY: one_rtt transfers the width from the original short header
        // through Opened; freezing and shared projection preserve that source.
        let bytes = unsafe { self.packet.as_ref().get_unchecked(1..width.end()) };
        Some((bytes, pto))
    }
}

/// Static authenticated-owner projection into the frame source used by commit.
pub(in crate::conn) trait Policy<
    P: long::Buffer,
    const DOMAIN: u8,
    B: stream::Recv,
    const RECONCILE: bool,
    D: buffer::raw::Segment,
>: Copy
{
    fn try_process<E>(
        self,
        input: &mut ingress::Input<'_, DOMAIN, B, RECONCILE, D>,
        packet: Packet<P>,
        hooks: &mut E,
    ) -> Result<(), conn::Error>
    where
        E: events::Sink;
}

#[derive(Clone, Copy)]
pub(in crate::conn) struct Copied;

impl<'a, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Policy<&'a mut [u8], DOMAIN, B, RECONCILE, D> for Copied
{
    fn try_process<E>(
        self,
        input: &mut ingress::Input<'_, DOMAIN, B, RECONCILE, D>,
        auth: Packet<&'a mut [u8]>,
        hooks: &mut E,
    ) -> Result<(), conn::Error>
    where
        E: events::Sink,
    {
        use frames::ingest;

        let id = auth.cid().map(|(bytes, pto)| frames::PacketCid {
            routed: input.context.route(),
            bytes,
            pto,
        });
        ingest::Ingest::new(input).try_process(
            auth.meta,
            id,
            auth.body(),
            sources::Copied::<B>::new(),
            hooks,
        )
    }
}

const _: () = {
    assert!(mem::size_of::<Cid>() <= 24);
    assert!(!mem::needs_drop::<Packet<&'static mut [u8]>>());
};
const _: () = assert!(mem::size_of::<Copied>() == 0);
