use dope_quic::conn::{Connection, stream};
use dope_quic::errors::Code;
use dope_quic::stream::Recv;

pub struct View<'conn, const DOMAIN: u8, B: Recv> {
    conn: &'conn Connection<DOMAIN, B>,
}

impl<'conn, const DOMAIN: u8, B: Recv> View<'conn, DOMAIN, B> {
    pub(super) fn new(conn: &'conn Connection<DOMAIN, B>) -> Self {
        Self { conn }
    }

    pub fn recv_eof(&self, id: impl Into<super::ReceiveId>) -> Result<bool, stream::Error> {
        let id = id.into().id();
        self.conn.view().with_streams(|view| {
            let stream = view.resolve_recv(id)?;
            Ok(view.is_recv_eof(stream))
        })
    }

    pub fn stopped(&self, id: impl Into<super::SendId>) -> Result<Option<Code>, stream::Error> {
        let id = id.into().id();
        self.conn.view().with_streams(|view| {
            let stream = view.resolve_send(id)?;
            Ok(view.stopped(stream))
        })
    }

    pub fn has_events(&self) -> bool {
        self.conn.view().with_streams(|view| view.has_events())
    }

    pub fn wire_bytes(&self) -> usize {
        self.conn
            .view()
            .with_streams(|view| view.usage().wire_bytes())
    }

    pub fn resident(&self) -> usize {
        self.conn
            .view()
            .with_streams(|view| view.usage().resident())
    }

    pub fn active_bytes(&self) -> usize {
        self.conn.view().with_streams(|view| view.usage().active())
    }

    pub fn cached_bytes(&self) -> usize {
        self.conn.view().with_streams(|view| view.usage().cached())
    }

    pub fn segments(&self) -> usize {
        self.conn
            .view()
            .with_streams(|view| view.usage().segments())
    }
}
