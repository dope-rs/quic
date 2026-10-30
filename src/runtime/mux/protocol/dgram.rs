use std::{net, time};

use crate::{conn, errors, proto::datagram, runtime::mux, stream};
use conn::id;
use mux::{auth, handler, protocol, router};

pub(crate) trait Dgram<
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    const DOMAIN: u8,
    B: stream::Recv,
>
{
    fn try_send(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        data: Vec<u8>,
        now: time::Instant,
    ) -> Result<(), errors::SendFailure<Vec<u8>>>;

    fn try_packet<'pool>(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        packet: datagram::Packet<'pool>,
        now: time::Instant,
    ) -> Result<
        (net::SocketAddr, datagram::Sealed<'pool>),
        errors::SendFailure<datagram::Packet<'pool>>,
    >;
}

impl<'a, 'tls, H, const DOMAIN: u8, B, A> Dgram<A, H, DOMAIN, B>
    for protocol::Io<'a, 'tls, H, DOMAIN, B, A>
where
    A: auth::Mode<DOMAIN>,
    H: handler::Handler<DOMAIN, B, A::Send, A::Identity>,
    B: stream::Recv,
{
    fn try_send(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        data: Vec<u8>,
        now: time::Instant,
    ) -> Result<(), errors::SendFailure<Vec<u8>>> {
        let mut mux = router::Turn::new(self.mux.as_mut());
        let result = mux.external(handle, now, data, |mut slot, data| {
            slot.conn.datagrams().try_send(data)
        });
        match result {
            Ok(result) => result,
            Err((errors::Access::Closed | errors::Access::InvalidHandle, data)) => {
                Err(errors::SendFailure::Closed(data))
            }
        }
    }

    fn try_packet<'pool>(
        &mut self,
        handle: id::Handle<A::Identity, DOMAIN>,
        packet: datagram::Packet<'pool>,
        now: time::Instant,
    ) -> Result<
        (net::SocketAddr, datagram::Sealed<'pool>),
        errors::SendFailure<datagram::Packet<'pool>>,
    > {
        let mut mux = router::Turn::new(self.mux.as_mut());
        let result = mux.external(handle, now, packet, |mut slot, packet| {
            let peer = *slot.peer_addr;
            let mtu = slot.max_packet_bytes.get() as usize;
            let packet = slot.conn.output().try_packet(packet, now, mtu)?;
            Ok((peer, packet))
        });
        match result {
            Ok(result) => result,
            Err((errors::Access::Closed | errors::Access::InvalidHandle, packet)) => {
                Err(errors::SendFailure::Closed(packet))
            }
        }
    }
}
