use std::mem;

use crate::conn::wire::path::setup;
use crate::wire::packet::cid;

pub(in crate::conn) struct State {
    pub(in crate::conn) original_dcid: cid::Id,
    pub(in crate::conn) peer_first_scid: Option<cid::Id>,
    pub(in crate::conn) retry_source_cid: Option<cid::Id>,
    pub(super) tokens: setup::Tokens,
}

impl State {
    pub(in crate::conn::wire::path) fn new(
        original: cid::Id,
        peer: Option<cid::Id>,
        tokens: setup::Tokens,
    ) -> Self {
        Self {
            original_dcid: original,
            peer_first_scid: peer,
            retry_source_cid: None,
            tokens,
        }
    }

    pub(in crate::conn) fn initial(&self) -> &[u8] {
        match &self.tokens {
            setup::Tokens::Client(token) => token,
            setup::Tokens::Server(_) => &[],
        }
    }

    pub(in crate::conn) fn retry(&mut self, mut wire: Vec<u8>) -> Vec<u8> {
        let setup::Tokens::Client(token) = &mut self.tokens else {
            wire.clear();
            return wire;
        };
        mem::swap(token, &mut wire);
        wire.clear();
        wire
    }

    pub(in crate::conn) const fn issued(&self) -> Option<&[u8]> {
        match &self.tokens {
            setup::Tokens::Client(_) | setup::Tokens::Server(None) => None,
            setup::Tokens::Server(Some(token)) => Some(token.as_slice()),
        }
    }
}

const _: () = assert!(mem::size_of::<setup::Tokens>() == 32);
