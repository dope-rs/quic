pub mod credit;
pub mod hold;

use crate::runtime::brand;

use o3::buffer::{self, resident};

use crate::conn;
use crate::conn::stream::{Error, id, state::receive};
use crate::errors;
use crate::stream;
use hold::{ErrorKind, Held, LocalReceipt, ReleaseError};
use receive::{credits, recv::map};
use std::mem;

/// Branded receive operations.
#[repr(transparent)]
pub struct Receive<
    'access,
    'conn,
    const DOMAIN: u8,
    B: stream::Recv = Vec<u8>,
    const RECONCILE: bool = false,
    D: buffer::raw::Segment = resident::Shared<'conn>,
> {
    connection: &'access mut conn::Machine<DOMAIN, B, D>,
    brand: brand::Token<'conn>,
}

/// The original connection and its positive debt remain paired through settlement.
pub(in crate::conn::stream) struct Source<
    'access,
    const DOMAIN: u8,
    B: stream::Recv,
    D: buffer::raw::Segment,
> {
    conn: &'access mut conn::Machine<DOMAIN, B, D>,
    loan: map::Loan,
}

impl<'access, const DOMAIN: u8, B: stream::Recv, D: buffer::raw::Segment>
    Source<'access, DOMAIN, B, D>
{
    pub(in crate::conn::stream) fn into_parts(
        self,
    ) -> (&'access mut conn::Machine<DOMAIN, B, D>, map::Loan) {
        (self.conn, self.loan)
    }
}

impl<'conn, const DOMAIN: u8, B: stream::Recv, const RECONCILE: bool, D: buffer::raw::Segment>
    Receive<'_, 'conn, DOMAIN, B, RECONCILE, D>
{
    pub(super) fn new<'access>(
        conn: &'access mut conn::Machine<DOMAIN, B, D>,
        brand: brand::Token<'conn>,
    ) -> Receive<'access, 'conn, DOMAIN, B, RECONCILE, D> {
        Receive {
            connection: conn,
            brand,
        }
    }

    fn kernel(&mut self) -> receive::Receive<'_, DOMAIN, B, D> {
        receive::Receive::new(self.connection)
    }

    fn track(&mut self) {
        self.connection.record::<RECONCILE>(conn::Effects::STREAMS);
    }

    pub fn recv(
        &mut self,
        id: id::Receive<'conn>,
        dst: &mut Vec<u8>,
    ) -> Result<usize, stream::Capacity> {
        let result = self.kernel().recv(id.id(), dst);
        self.track();
        result
    }

    pub fn recv_owned(
        &mut self,
        id: id::Receive<'conn>,
    ) -> Result<Option<Vec<u8>>, stream::Capacity> {
        let result = self.kernel().recv_owned(id.id());
        self.track();
        result
    }

    pub fn recv_buffer(&mut self, id: id::Receive<'conn>) -> Option<B> {
        let result = self.kernel().recv_buffer(id.id());
        self.track();
        result
    }

    pub fn hold(&mut self, id: id::Receive<'conn>) -> Option<Held<'conn, B>> {
        let held = self.kernel().hold_parts(id.id()).0;
        self.track();
        held.map(|held| Held::new(held, self.brand))
    }

    /// Receives and observes the resulting EOF through the same occupied slot.
    pub fn hold_eof(&mut self, id: id::Receive<'conn>) -> (Option<Held<'conn, B>>, bool) {
        let (held, eof) = self.kernel().hold_parts(id.id());
        self.track();
        let held = held.map(|held| Held::new(held, self.brand));
        (held, eof || self.connection.streams.is_recv_done(id.id()))
    }

    pub fn stop(&mut self, id: id::Receive<'conn>, code: errors::Code) -> Result<(), Error> {
        let result = self.kernel().stop(id.id(), code);
        if result.is_ok() {
            self.track();
        }
        result
    }

    fn apply<const CONNECTION: bool, K>(&mut self, credit: credit::Credit<'conn, K>) {
        let (credit, _) = credit.into_receipt().into_parts();
        if let Some(loan) = credit.into_loan() {
            map::Loan::settle::<DOMAIN, B, D, CONNECTION>(Source {
                conn: self.connection,
                loan,
            });
        }
        self.track();
    }

    pub(in crate::conn) fn commit_conn(
        &mut self,
        credit: credit::Credit<'conn>,
    ) -> credit::Credit<'conn, credit::Local> {
        self.release_conn(credit.bytes());
        credit.into_stream()
    }

    fn release_conn(&mut self, bytes: usize) {
        if bytes != 0 {
            receive::Update::new(&mut self.connection.streams.state)
                .release_conn(bytes as u64, &mut self.connection.control);
        }
        self.track();
    }

    pub(in crate::conn) fn commit_merge(&mut self, merge: map::Merge<'_>) {
        self.release_conn(merge.incoming_len());
        merge.commit();
    }

    pub(in crate::conn) fn detach<T>(&self, proof: LocalReceipt<'conn, T>) -> credits::Receipt<T> {
        credits::Receipt::new(
            self.connection.streams.state.receive.map.meta().origin(),
            proof.into_parts().0,
        )
    }

    pub(in crate::conn) fn is_origin<T>(&self, proof: &credits::Receipt<T>) -> bool {
        proof.belongs_to(self.connection.streams.state.receive.map.meta())
    }

    pub(in crate::conn) fn try_bind<T>(
        &self,
        proof: credits::Receipt<T>,
    ) -> Result<LocalReceipt<'conn, T>, ReleaseError<credits::Receipt<T>>> {
        if !self.is_origin(&proof) {
            return Err(ReleaseError::new(ErrorKind::ForeignConnection, proof));
        }
        Ok(LocalReceipt::new(self.brand, proof.into_parts().1))
    }
}

const _: () = {
    assert!(
        mem::size_of::<Receive<'static, 'static, 0>>()
            == mem::size_of::<&mut conn::Machine<0, Vec<u8>, resident::Shared<'_>>>()
    );
};
