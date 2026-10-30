use crate::conn::wire::tls::ciphers;

#[derive(Clone, Copy)]
pub(in crate::conn) struct Borrow<'a, const DOMAIN: u8> {
    pub(super) keys: &'a ciphers::State,
}

impl<'a, const DOMAIN: u8> Borrow<'a, DOMAIN> {
    pub(in crate::conn) const fn get(&self) -> &'a ciphers::State {
        self.keys
    }
}
