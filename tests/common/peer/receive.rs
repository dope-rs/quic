use dope_quic::conn::stream::recv::hold;
use dope_quic::conn::{Connection, stream};
use dope_quic::errors::Code;
use dope_quic::stream::{Capacity, Recv};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    Resolve(stream::Error),
    Capacity(Capacity),
}

pub struct Receive<'conn, const DOMAIN: u8, B: Recv> {
    conn: &'conn mut Connection<DOMAIN, B>,
}

impl<'conn, const DOMAIN: u8, B: Recv> Receive<'conn, DOMAIN, B> {
    pub(super) fn new(conn: &'conn mut Connection<DOMAIN, B>) -> Self {
        Self { conn }
    }

    pub fn recv(
        &mut self,
        stream: impl Into<super::ReceiveId>,
        dst: &mut Vec<u8>,
    ) -> Result<usize, Error> {
        let id = stream.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams.view().resolve_recv(id).map_err(Error::Resolve)?;
            streams.receive().recv(stream, dst).map_err(Error::Capacity)
        })
    }

    pub fn recv_owned(
        &mut self,
        stream: impl Into<super::ReceiveId>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let id = stream.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams.view().resolve_recv(id).map_err(Error::Resolve)?;
            streams
                .receive()
                .recv_owned(stream)
                .map_err(Error::Capacity)
        })
    }

    pub fn recv_buffer(
        &mut self,
        stream: impl Into<super::ReceiveId>,
    ) -> Result<Option<B>, stream::Error> {
        let id = stream.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams.view().resolve_recv(id)?;
            Ok(streams.receive().recv_buffer(stream))
        })
    }

    pub fn hold(
        &mut self,
        stream: impl Into<super::ReceiveId>,
    ) -> Result<Option<hold::Detached<B>>, stream::Error> {
        let id = stream.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams.view().resolve_recv(id)?;
            let mut receive = streams.receive();
            Ok(receive.hold(stream).map(|held| held.detach(&mut receive)))
        })
    }

    pub fn stop(
        &mut self,
        stream: impl Into<super::ReceiveId>,
        code: Code,
    ) -> Result<(), stream::Error> {
        let id = stream.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams.view().resolve_recv(id)?;
            streams.receive().stop(stream, code)
        })
    }
}
