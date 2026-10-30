use crate::common::retry::{
    Finish,
    traces::Immediate,
    writable::{Callback, Connected, Peer, PeerError},
};
use dope::core::driver::schedule::clock;
use dope::runtime::control;
use dope_quic::client::{self, auth};
use dope_quic::errors::SendFailure;
use dope_quic::proto::datagram::{self, Arena, Packet};
use dope_quic::runtime::endpoint::control::SendError;
use std::{cell::Cell, rc::Rc, time::Duration};

pub const PAYLOAD: &[u8] = b"same sender after another connection is full";

pub enum Error<'pool> {
    Timeout,
    Peer(PeerError),
    Deadline(clock::Range<Duration>),
    Datagram(SendFailure<Vec<u8>>),
    Acquire(datagram::Error),
    Sender(SendError),
    Accepted,
    Rejected(SendFailure<Packet<'pool>>),
    Returned {
        expected: *const u8,
        actual: *const u8,
        available: usize,
        packet: Packet<'pool>,
    },
    Delivered(usize),
}

pub enum Phase<'pool> {
    Pending(Option<Packet<'pool>>),
    Sent,
}

#[pin_project::pin_project]
#[derive(dope::Application)]
#[dispatcher(driver = 'd)]
#[coordinate]
pub struct App<'d, 'pool, F>
where
    F: for<'a> FnMut(Result<client::SlotId, Callback<'a>>) + Unpin,
{
    #[pin]
    #[manifold(control)]
    pub client: client::Dialer<'pool, 'd, 1, Connected<F>, Immediate, auth::Owned>,
    #[dispatcher(state)]
    pub peer: Peer,
    #[dispatcher(state)]
    pub arena: &'pool Arena,
    #[dispatcher(state)]
    pub phase: Phase<'pool>,
    #[dispatcher(state)]
    pub finish: Finish,
    #[dispatcher(state)]
    pub error: Rc<Cell<Option<Error<'pool>>>>,
    #[dispatcher(state)]
    pub timeout: clock::Deadline<'d>,
    #[dispatcher(schedule)]
    pub next: clock::Deadline<'d>,
}

impl<'d, 'pool, F> App<'d, 'pool, F>
where
    F: for<'a> FnMut(Result<client::SlotId, Callback<'a>>) + Unpin,
{
    fn coordinate(mut this: app_coord::Fields<'_, 'd, 'pool, F>) -> control::Flow {
        if this.finish.stop.is_none() {
            return control::Flow::Idle;
        }
        if let Err(error) = Self::try_progress(&mut this) {
            this.error.set(Some(error));
            this.finish.fire();
        }
        control::Flow::Idle
    }

    fn try_progress(this: &mut app_coord::Fields<'_, 'd, 'pool, F>) -> Result<(), Error<'pool>> {
        if this.timeout.is_due(this.step.now()) {
            return Err(Error::Timeout);
        }
        this.client.take();
        this.peer
            .poll(this.step.now().into_raw())
            .map_err(Error::Peer)?;
        *this.next = this
            .step
            .now()
            .try_add(Duration::from_millis(1))
            .map_err(Error::Deadline)?;
        let pending = match &mut *this.phase {
            Phase::Pending(pending) => pending,
            Phase::Sent => {
                let received = this.peer.datagrams();
                let count = received.iter().filter(|(_, data)| data == PAYLOAD).count();
                if count != 0 && this.arena.available() == 1 {
                    if count != 1 {
                        return Err(Error::Delivered(count));
                    }
                    this.finish.fire();
                }
                return Ok(());
            }
        };
        if this.client.protocol().len() != 2 {
            return Ok(());
        }
        let first = client::SlotId::from_index(0);
        let second = client::SlotId::from_index(1);
        this.client
            .at(this.step.clock())
            .try_datagram(first, vec![0])
            .map_err(Error::Datagram)?;
        let packet = match pending.take() {
            Some(packet) => packet,
            None => {
                let mut packet = this
                    .arena
                    .try_acquire(PAYLOAD.len())
                    .map_err(Error::Acquire)?;
                packet.payload_mut().copy_from_slice(PAYLOAD);
                packet
            }
        };
        let pointer = packet.payload().as_ptr();
        let sender = this
            .client
            .at(this.step.clock())
            .try_sender()
            .map_err(Error::Sender)?;
        let rejected = match sender.try_send(first, packet) {
            Err(rejected) => rejected,
            Ok(()) => return Err(Error::Accepted),
        };
        let (sender, cause) = rejected.into_parts();
        let SendFailure::Full(packet) = cause else {
            return Err(Error::Rejected(cause));
        };
        let actual = packet.payload().as_ptr();
        let free = this.arena.available();
        if actual != pointer || free != 0 {
            return Err(Error::Returned {
                expected: pointer,
                actual,
                available: free,
                packet,
            });
        }
        match sender.try_send(second, packet) {
            Ok(()) => *this.phase = Phase::Sent,
            Err(rejected) => {
                let (sender, cause) = rejected.into_parts();
                drop(sender);
                let SendFailure::Full(packet) = cause else {
                    return Err(Error::Rejected(cause));
                };
                *pending = Some(packet);
            }
        }
        Ok(())
    }
}
