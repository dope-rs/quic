//! Admission and discard receipts retain the original write operation at the commit boundary.

use dope_quic::conn::Connection;
use dope_quic::conn::stream;
use dope_quic::errors::Code;
use dope_quic::stream::{Recv, send};
use o3::buffer::storage;

pub struct Send<'conn, const DOMAIN: u8, B: Recv> {
    conn: &'conn mut Connection<DOMAIN, B>,
}

impl<'conn, const DOMAIN: u8, B: Recv> Send<'conn, DOMAIN, B> {
    pub(super) fn new(conn: &'conn mut Connection<DOMAIN, B>) -> Self {
        Self { conn }
    }

    pub fn open_bidi(&mut self) -> Result<super::BidiId, stream::Error> {
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            streams.send().open_bidi().map(|id| super::BidiId(id.id()))
        })
    }

    pub fn open_uni(&mut self) -> Result<super::SendId, stream::Error> {
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            streams.send().open_uni().map(|id| super::SendId(id.id()))
        })
    }

    pub fn send(&mut self, id: impl Into<super::SendId>, data: &[u8]) -> Result<(), stream::Error> {
        let id = id.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams.view().resolve_send(id)?;
            streams.send().send(stream, data)
        })
    }

    pub fn try_buffer(
        &mut self,
        id: impl Into<super::SendId>,
        data: send::Buffer<storage::Shared>,
    ) -> stream::SendOutcome<send::Buffer<storage::Shared>> {
        let id = id.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = match streams.view().resolve_send(id) {
                Ok(stream) => stream,
                Err(error) => return stream::SendOutcome::Failed { owner: data, error },
            };
            streams.send().try_buffer(stream, data)
        })
    }

    pub fn try_parts(
        &mut self,
        id: impl Into<super::SendId>,
        parts: send::Parts<storage::Shared>,
    ) -> stream::SendOutcome<send::Parts<storage::Shared>> {
        let id = id.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = match streams.view().resolve_send(id) {
                Ok(stream) => stream,
                Err(error) => {
                    return stream::SendOutcome::Failed {
                        owner: parts,
                        error,
                    };
                }
            };
            streams.send().try_parts(stream, parts)
        })
    }

    pub fn finish(&mut self, id: impl Into<super::SendId>) -> Result<(), stream::Error> {
        let id = id.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams.view().resolve_send(id)?;
            streams.send().finish(stream)
        })
    }

    pub fn reset(&mut self, id: impl Into<super::SendId>, code: Code) -> Result<(), stream::Error> {
        let id = id.into().id();
        self.conn.with_scope(|mut scope| {
            let mut streams = scope.streams();
            let stream = streams.view().resolve_send(id)?;
            streams.send().reset(stream, code)
        })
    }
}
