use crate::common::retry::queue::{Observed, Phase, State};
use dope_quic::conn::id;
use dope_quic::runtime::mux::handler::{self, hook, net};
use hook::{
    life::{close, closing, create, ready},
    set,
    wire::{cert, endpoint, ingress, packet, socket},
    writable,
};
use o3::buffer::resident;
use std::{pin::Pin, rc::Rc};

pub struct Events<'d, F>(pub Rc<State<'d, F>>);

impl<'d, F: for<'a> FnMut(Observed<'a>)>
    handler::Handler<1, Vec<u8>, resident::Shared<'d>, id::Driver<'d>> for Events<'d, F>
{
    type Connection = ();
    type Create = create::Unit;
    type Events = set::Set<
        set::On,
        set::Off,
        set::Off,
        set::Off,
        set::Off,
        set::On,
        ingress::Off,
        packet::On,
        endpoint::Off,
        closing::Off,
        close::Off,
        writable::On,
    >;
}

impl<'d, F: for<'a> FnMut(Observed<'a>)>
    ready::Sink<1, Vec<u8>, resident::Shared<'d>, id::Driver<'d>> for Events<'d, F>
{
    fn established(
        event: ready::Event<'_, Self, 1, Vec<u8>, resident::Shared<'d>, id::Driver<'d>>,
    ) {
        let (this, _, handle, _) = event.into();
        this.0.connected.set(Some(handle));
    }
}

impl<'d, F: for<'a> FnMut(Observed<'a>)> cert::Sink<1, id::Driver<'d>> for Events<'d, F> {
    fn certificate(event: cert::Event<'_, '_, Self, 1, id::Driver<'d>>) {
        let (this, _, _, cause) = event.into_parts();
        (this.0.observe.borrow_mut())(Observed::Certificate(cause));
    }
}

impl<'d, F: for<'a> FnMut(Observed<'a>)>
    packet::Sink<1, Vec<u8>, resident::Shared<'d>, id::Driver<'d>> for Events<'d, F>
{
    fn packet(event: packet::Event<'_, Self>) {
        let (this, _, cause, _) = event.into_parts();
        (this.0.observe.borrow_mut())(Observed::Packet(cause));
    }
}

impl<'d, F: for<'a> FnMut(Observed<'a>)>
    writable::Sink<1, Vec<u8>, resident::Shared<'d>, id::Driver<'d>> for Events<'d, F>
{
    fn writable(self: Pin<&mut Self>) {
        self.0.writable.set(self.0.writable.get() + 1);
        self.0.pending.set(true);
    }

    fn has_writable(&self) -> bool {
        self.0.pending.get()
    }

    fn clear(self: Pin<&mut Self>) {
        self.0.pending.set(false);
    }
}

impl<'d, F: for<'a> FnMut(Observed<'a>)>
    socket::Sink<1, Vec<u8>, resident::Shared<'d>, id::Driver<'d>> for Events<'d, F>
{
    fn socket(event: socket::Event<'_, Self, 1, id::Driver<'d>>) {
        let (this, event) = event.into_parts();
        let state = &this.0;
        match event {
            net::Event::Transmit(error) => {
                (state.observe.borrow_mut())(Observed::Transmit(error.into_parts().1))
            }
            net::Event::Accepted(accepted) => {
                state.active.set(state.active.get() + 1);
                let mut records = state.records.get();
                let index = match state.phase.get() {
                    Phase::First => Some(0),
                    Phase::Blocked => {
                        (state.observe.borrow_mut())(Observed::Blocked);
                        return;
                    }
                    Phase::Release if records[1].owner.is_none() => Some(1),
                    _ => None,
                };
                if let Some(index) = index {
                    (state.observe.borrow_mut())(Observed::ReplacedOwner(
                        records[index].owner.is_some(),
                    ));
                    records[index].owner = Some(accepted.owner());
                    state.records.set(records);
                }
            }
            net::Event::Transferred(transfer) => {
                let mut records = state.records.get();
                for record in &mut records {
                    if record.owner == Some(transfer.from()) {
                        (state.observe.borrow_mut())(Observed::ReplacedFlight(
                            record.flight.is_some(),
                        ));
                        record.flight = Some(transfer.to());
                    }
                }
                state.records.set(records);
            }
            net::Event::Settled(settled) => {
                let active = state.active.get().checked_sub(1);
                (state.observe.borrow_mut())(Observed::Active(active));
                let Some(active) = active else {
                    return;
                };
                state.active.set(active);
                for record in state.records.get() {
                    if record.flight != Some(settled.owner()) {
                        continue;
                    }
                    (state.observe.borrow_mut())(Observed::Settled {
                        outcome: settled.outcome(),
                        wire: settled.payload(),
                        pointer: record.pointer,
                    });
                    state.completed.set(state.completed.get() + 1);
                }
            }
            net::Event::Receive { error, .. } => {
                (state.observe.borrow_mut())(Observed::Receive(error))
            }
            net::Event::Rejected { error, .. } => {
                (state.observe.borrow_mut())(Observed::Rejected(error))
            }
        }
    }
}
