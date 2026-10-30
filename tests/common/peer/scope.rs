use dope_quic::conn::Connection;
use dope_quic::conn::stream::recv::{credit, hold};
use dope_quic::stream::Recv;

pub trait Scope<const DOMAIN: u8, B: Recv> {
    fn send_streams(&mut self) -> super::Send<'_, DOMAIN, B>;
    fn recv(&mut self) -> super::Receive<'_, DOMAIN, B>;
    fn stream_state(&self) -> super::View<'_, DOMAIN, B>;
    fn poll(&mut self) -> super::Poll<'_, DOMAIN, B>;
    fn release_held(
        &mut self,
        held: hold::Detached<B>,
    ) -> Result<B, hold::ReleaseError<hold::Detached<B>>>;
    fn release_conn(
        &mut self,
        credit: credit::Detached,
    ) -> Result<credit::Detached<credit::Local>, hold::ReleaseError<credit::Detached>>;
    fn release(
        &mut self,
        credit: credit::Detached<credit::Local>,
    ) -> Result<(), hold::ReleaseError<credit::Detached<credit::Local>>>;
}

impl<const DOMAIN: u8, B: Recv> Scope<DOMAIN, B> for Connection<DOMAIN, B> {
    fn send_streams(&mut self) -> super::Send<'_, DOMAIN, B> {
        super::Send::new(self)
    }

    fn recv(&mut self) -> super::Receive<'_, DOMAIN, B> {
        super::Receive::new(self)
    }

    fn stream_state(&self) -> super::View<'_, DOMAIN, B> {
        super::View::new(self)
    }

    fn poll(&mut self) -> super::Poll<'_, DOMAIN, B> {
        super::Poll::new(self)
    }

    fn release_held(
        &mut self,
        held: hold::Detached<B>,
    ) -> Result<B, hold::ReleaseError<hold::Detached<B>>> {
        self.with_scope(|mut scope| held.release(&mut scope.streams().receive()))
    }

    fn release_conn(
        &mut self,
        credit: credit::Detached,
    ) -> Result<credit::Detached<credit::Local>, hold::ReleaseError<credit::Detached>> {
        self.with_scope(|mut scope| credit.release_conn(&mut scope.streams().receive()))
    }

    fn release(
        &mut self,
        credit: credit::Detached<credit::Local>,
    ) -> Result<(), hold::ReleaseError<credit::Detached<credit::Local>>> {
        self.with_scope(|mut scope| credit.release(&mut scope.streams().receive()))
    }
}
