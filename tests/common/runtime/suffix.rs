use std::{cell::Cell, net::SocketAddr, pin::Pin, rc::Rc};

use dope::core::{
    driver::{
        retained,
        route::KeyTag,
        schedule::{self, app, clock},
    },
    io::datagram::ReceiveError,
};
use dope::manifold::network::datagram::{self, hook, packet, send};
use dope_quic::runtime::endpoint::Payload;
use dope_test::harness::observe::VecCellExt as _;
use dope_test::harness::signals::Gate;
use hook::{app::Schedule, ingress::Time};
use o3::{base::cell::region, buffer::pool};

type Observations<T> = Cell<Vec<T>>;

pub struct Sender {
    pub addr: SocketAddr,
    pub pending: Option<Payload<pool::Cursor>>,
    pub observed: Rc<Observed>,
    pub settled: Gate,
}

#[derive(Default)]
pub struct Observed {
    pub received: Observations<Result<(SocketAddr, usize), ReceiveError>>,
    pub rejected: Cell<Option<datagram::Rejected<Payload<pool::Cursor>>>>,
    pub settlements: Observations<(send::Outcome, Result<Vec<u8>, Returned>)>,
}

#[derive(Debug)]
pub enum Returned {
    Owned,
    Packet,
    Pooled,
}

impl<'d> datagram::Ingress<'d, KeyTag<0>> for Sender {
    type Hooks = hook::Set<
        hook::Disabled,
        hook::Disabled,
        hook::Disabled,
        Schedule,
        hook::Enabled,
        Payload<pool::Cursor>,
    >;
    type Mode = Time;
}

impl<'d> datagram::Time<'d, KeyTag<0>> for Sender {
    fn packet<'turn>(
        self: Pin<&mut Self>,
        packet: Result<(SocketAddr, packet::Packet<'turn, 'd>), ReceiveError>,
        _: clock::Moment<'d>,
        _: &mut region::Token<region::Identity<'d, 1>>,
    ) {
        self.observed
            .received
            .push(packet.map(|(addr, packet)| (addr, packet.len())));
        self.settled.hit();
    }
}

impl<'d> datagram::Application<'d, KeyTag<0>> for Sender {
    fn pre_park<'turn>(
        self: Pin<&mut Self>,
        socket: Pin<&mut datagram::Socket<'d, KeyTag<0>, Payload<pool::Cursor>>>,
        _: clock::Moment<'d>,
        _: app::Work<'turn, 'd>,
        _: &mut retained::Context<'_, '_, 'd>,
    ) {
        let this = self.get_mut();
        if let Some(payload) = this.pending.take()
            && let Err(rejected) = socket.queue_pooled(payload, this.addr)
        {
            this.observed.rejected.set(Some(rejected));
            this.settled.hit();
        }
    }

    fn progress(
        self: Pin<&Self>,
        _: clock::Clock<'_, 'd>,
        _: &region::Token<region::Identity<'d, 1>>,
    ) -> schedule::Progress<'d> {
        if self.pending.is_some() {
            schedule::Progress::Runnable
        } else {
            schedule::Progress::Quiescent
        }
    }
}

impl<'d> datagram::Settlement<'d, KeyTag<0>> for Sender {
    fn settle<'turn>(
        self: Pin<&mut Self>,
        done: send::Settlement<'turn, 'd, KeyTag<0>, Payload<pool::Cursor>>,
        _: &mut region::Token<region::Identity<'d, 1>>,
    ) {
        let (_, _, outcome, payload, _) = done.into_parts();
        let returned = match payload {
            send::Payload::Buffer(payload) => match payload.into_inner() {
                Payload::Retry(payload) => Ok(payload.into_storage()),
                Payload::Pooled(_) => Err(Returned::Pooled),
            },
            send::Payload::Owned(_) => Err(Returned::Owned),
            send::Payload::Packet(_) => Err(Returned::Packet),
        };
        self.observed.settlements.push((outcome, returned));
        self.settled.hit();
    }
}

#[pin_project::pin_project]
#[derive(dope::Application)]
pub struct App<'d> {
    #[pin]
    #[manifold]
    pub endpoint: datagram::Endpoint<'d, KeyTag<0>, Sender, Payload<pool::Cursor>>,
}
