use crate::stream::retain;
use o3::buffer;
use o3::buffer::storage::provided::Mutable;
use std::{net, time};

use dope::manifold::network::datagram::packet;

use crate::runtime::mux::handler::hook::wire::cert;
use crate::runtime::mux::{auth, handler, protocol};
use crate::{errors, proto::epoch, stream};
use protocol::recv;
use recv::Recv as _;

pub trait Input<'d, D: buffer::raw::Segment>: stream::Recv {
    fn recv<'turn, 'tls, const ID: u8, H, M, T: Mutable<'d, Account: retain::Retain<'d>>>(
        io: &mut protocol::Io<'_, 'tls, H, ID, Self, M>,
        addr: net::SocketAddr,
        packet: packet::Packet<'turn, 'd, T>,
        keep: packet::Retainer<'d>,
        now: time::Instant,
    ) -> Result<(), errors::Receive>
    where
        H: handler::Handler<ID, Self, D, M::Identity> + cert::Sink<ID, M::Identity>,
        M: auth::Mode<ID, Send = D>;
}

impl<'d, D: buffer::raw::Segment> Input<'d, D> for Vec<u8> {
    fn recv<'turn, 'tls, const ID: u8, H, M, T: Mutable<'d, Account: retain::Retain<'d>>>(
        io: &mut protocol::Io<'_, 'tls, H, ID, Self, M>,
        addr: net::SocketAddr,
        mut packet: packet::Packet<'turn, 'd, T>,
        _: packet::Retainer<'d>,
        now: time::Instant,
    ) -> Result<(), errors::Receive>
    where
        H: handler::Handler<ID, Self, D, M::Identity> + cert::Sink<ID, M::Identity>,
        M: auth::Mode<ID, Send = D>,
    {
        io.recv_input(addr, packet.as_mut(), (), now, epoch::WALL_CLOCK)
    }
}

impl<'d, D: buffer::raw::Segment, const ADAPTIVE: bool> Input<'d, D>
    for stream::RecvBuffer<'d, ADAPTIVE>
{
    fn recv<'turn, 'tls, const ID: u8, H, M, T: Mutable<'d, Account: retain::Retain<'d>>>(
        io: &mut protocol::Io<'_, 'tls, H, ID, Self, M>,
        addr: net::SocketAddr,
        packet: packet::Packet<'turn, 'd, T>,
        keep: packet::Retainer<'d>,
        now: time::Instant,
    ) -> Result<(), errors::Receive>
    where
        H: handler::Handler<ID, Self, D, M::Identity> + cert::Sink<ID, M::Identity>,
        M: auth::Mode<ID, Send = D>,
    {
        io.recv_input(addr, packet, keep, now, epoch::WALL_CLOCK)
    }
}
