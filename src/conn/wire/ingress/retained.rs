use crate::conn::wire::ingress::events;

use std::time;

use dope::manifold::network::datagram::packet;
use o3::buffer::{self, storage::provided};

use crate::conn;
use crate::stream;
use crate::wire::packet::long;
use stream::retain;

use crate::conn::wire::ingress::frames;
use crate::conn::wire::ingress::{self, bodies, receiver};
use frames::sources;

impl<
    'd,
    const DOMAIN: u8,
    const RECONCILE: bool,
    const ADAPTIVE: bool,
    D: buffer::raw::Segment,
    P: long::Buffer + buffer::raw::Freeze,
> bodies::Policy<P, DOMAIN, stream::RecvBuffer<'d, ADAPTIVE>, RECONCILE, D> for packet::Retainer<'d>
where
    P::Output: packet::Backing<Storage: provided::Frozen<'d, Account: retain::Retain<'d>>>,
{
    fn try_process<E>(
        self,
        input: &mut ingress::Input<'_, DOMAIN, stream::RecvBuffer<'d, ADAPTIVE>, RECONCILE, D>,
        auth: bodies::Packet<P>,
        views: &mut E,
    ) -> Result<(), conn::Error>
    where
        E: events::Sink,
    {
        use frames::ingest;

        auth.freeze().with(|packet, auth| {
            let id = auth.cid().map(|(bytes, pto)| frames::PacketCid {
                routed: input.context.route(),
                bytes,
                pto,
            });
            let (meta, start, bytes) = auth.borrow();
            let source = sources::Retained::new(packet, self, start);
            ingest::Ingest::new(input).try_process(meta, id, bytes, source, views)
        })
    }
}

impl<'a, 'd, const DOMAIN: u8, const RECONCILE: bool, const ADAPTIVE: bool, D: buffer::raw::Segment>
    ingress::Input<'a, DOMAIN, stream::RecvBuffer<'d, ADAPTIVE>, RECONCILE, D>
{
    pub(crate) fn recv<
        'turn,
        E: events::Sink,
        T: provided::Mutable<'d, Account: retain::Retain<'d>>,
    >(
        &mut self,
        packet: packet::Packet<'turn, 'd, T>,
        keep: packet::Retainer<'d>,
        now: time::Instant,
        sink: &mut E,
    ) -> Result<(), conn::Error> {
        receiver::Receiver::new(self, now, sink).run(packet, keep)
    }
}
