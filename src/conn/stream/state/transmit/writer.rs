use crate::stream::release;

use o3::buffer::{self, resident::Shared};

use std::mem;

use crate::wire::stream::{Direction, Id, Initiator};
use crate::{conn, stream};
use conn::stream::{Error, SendOutcome, resident, state::transmit};
use send::admit;
use stream::send;
use transmit::request;

/// The single unbranded send kernel used by the branded access API.
#[repr(transparent)]
pub(in crate::conn) struct Writer<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
{
    connection: &'conn mut conn::Machine<DOMAIN, B, D>,
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Writer<'conn, DOMAIN, B, D>
{
    pub(in crate::conn) fn new(machine: &'conn mut conn::Machine<DOMAIN, B, D>) -> Self {
        Self {
            connection: machine,
        }
    }

    pub(in crate::conn) fn is_available(machine: &conn::Machine<DOMAIN, B, D>) -> bool {
        (machine.egress.lifecycle.state == conn::State::Established
            || matches!(machine.peer.local, Initiator::Client)
                && machine.egress.lifecycle.state == conn::State::Handshaking
                && machine.handshake.keys.long.early().is_some()
                && machine.peer.transport_params.is_some())
            && !machine.is_closing()
    }

    pub(in crate::conn) fn open(&mut self, dir: Direction) -> Result<resident::Local, Error> {
        let ready = Self::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).open_local(
            dir,
            self.connection.peer.transport_params.as_ref(),
            ready,
        )
    }

    pub(in crate::conn) fn send(&mut self, id: Id, data: &[u8]) -> Result<(), Error> {
        let ready = Self::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).send_bytes(
            id,
            data,
            self.connection.peer.transport_params.as_ref(),
            ready,
        )
    }

    pub(in crate::conn) fn try_buffer(
        &mut self,
        id: Id,
        data: send::Buffer<D>,
    ) -> SendOutcome<send::Buffer<D>> {
        let ready = Self::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).send_batch(
            id,
            data,
            self.connection.peer.transport_params.as_ref(),
            ready,
        )
    }

    pub(in crate::conn) fn try_parts(
        &mut self,
        id: Id,
        parts: send::Parts<D>,
    ) -> SendOutcome<send::Parts<D>> {
        let ready = Self::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).send_batch(
            id,
            parts,
            self.connection.peer.transport_params.as_ref(),
            ready,
        )
    }

    pub(in crate::conn) fn try_admit<C, W>(
        &mut self,
        id: Id,
        owner: W,
        commit: C,
    ) -> admit::Outcome<D, C, Error, W>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        let ready = Self::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).send_with(
            id,
            owner,
            self.connection.peer.transport_params.as_ref(),
            ready,
            commit,
        )
    }

    pub(in crate::conn) fn try_local<C, W>(
        &mut self,
        resident: resident::Local,
        owner: W,
        commit: C,
    ) -> admit::Outcome<D, C, resident::Error, W>
    where
        C: admit::Commit<D, W>,
        W: send::raw::Batch<D>,
    {
        let ready = Self::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).try_send(
            resident,
            owner,
            self.connection.peer.transport_params.as_ref(),
            ready,
            commit,
        )
    }

    pub(in crate::conn) fn try_prepare(
        &mut self,
        resident: resident::Local,
    ) -> Result<(), resident::Error> {
        let ready = Self::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).try_prepare(
            resident,
            self.connection.peer.transport_params.as_ref(),
            ready,
        )
    }

    pub(in crate::conn) fn finish(&mut self, id: Id) -> Result<(), Error> {
        let ready = Self::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).send_fin(
            id,
            self.connection.peer.transport_params.as_ref(),
            ready,
        )
    }

    pub(in crate::conn) fn reset(
        &mut self,
        id: Id,
        code: crate::errors::Code,
    ) -> Result<(), Error> {
        let ready = Self::is_available(self.connection);
        transmit::Sender::new(&mut self.connection.streams).reset(
            id,
            code,
            self.connection.peer.transport_params.as_ref(),
            ready,
            &mut self.connection.control,
        )
    }

    pub(in crate::conn) fn reset_with<E: release::Sink>(
        &mut self,
        id: Id,
        code: crate::errors::Code,
        sink: &mut E,
    ) -> Result<(), Error> {
        let ready = Self::is_available(self.connection);
        let request = request::Request::new(
            id,
            code,
            self.connection.peer.transport_params.as_ref(),
            ready,
            &mut self.connection.control,
            sink,
        );
        request.apply(&mut transmit::Sender::new(&mut self.connection.streams))
    }

    pub(in crate::conn) fn try_reset<E: release::Sink>(
        &mut self,
        local: resident::Local,
        code: crate::errors::Code,
        sink: &mut E,
    ) -> Result<(), resident::Error> {
        let ready = Self::is_available(self.connection);
        let request = request::Request::new(
            local,
            code,
            self.connection.peer.transport_params.as_ref(),
            ready,
            &mut self.connection.control,
            sink,
        );
        request.try_apply(&mut transmit::Sender::new(&mut self.connection.streams))
    }
}

const _: () = {
    assert!(
        mem::size_of::<Writer<'static, 0, Vec<u8>, Shared<'static>>>()
            == mem::size_of::<&mut conn::Machine<0, Vec<u8>, Shared<'static>>>()
    );
    assert!(
        mem::align_of::<Writer<'static, 0, Vec<u8>, Shared<'static>>>()
            == mem::align_of::<&mut conn::Machine<0, Vec<u8>, Shared<'static>>>()
    );
};
