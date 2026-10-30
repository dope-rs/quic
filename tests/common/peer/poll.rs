use dope_quic::conn::Connection;
use dope_quic::stream::Recv;

pub struct Poll<'conn, const DOMAIN: u8, B: Recv> {
    conn: &'conn mut Connection<DOMAIN, B>,
}

impl<'conn, const DOMAIN: u8, B: Recv> Poll<'conn, DOMAIN, B> {
    pub(super) fn new(conn: &'conn mut Connection<DOMAIN, B>) -> Self {
        Self { conn }
    }

    pub fn poll_event(&mut self) -> Option<super::Event> {
        self.conn
            .with_scope(|mut scope| scope.streams().events().poll().map(super::Event::from_item))
    }
}
