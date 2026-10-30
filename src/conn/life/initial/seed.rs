use crate::{conn, security::secrets, wire::packet::cid};
use conn::life;
use life::accept;
use std::ops;

pub(super) struct Seed<R> {
    base: Base,
    role: R,
}

pub(super) struct Base {
    pub(super) initial_dcid: cid::Id,
    pub(super) local_cid: cid::Id,
    pub(super) original_dcid: cid::Id,
    pub(super) retry_scid: Option<cid::Id>,
    pub(super) peer_address_validated: bool,
    pub(super) peer_cid: cid::Id,
    pub(super) peer_first_scid: Option<cid::Id>,
}

pub(super) struct Client;

pub(super) struct Server {
    pub(super) token: Option<[u8; secrets::Address::WIRE_LEN]>,
}

impl Seed<Client> {
    pub(super) fn client(initial: cid::Id, local: cid::Id) -> Self {
        Self {
            base: Base {
                initial_dcid: initial,
                local_cid: local,
                original_dcid: initial,
                retry_scid: None,
                peer_address_validated: true,
                peer_cid: initial,
                peer_first_scid: None,
            },
            role: Client,
        }
    }
}

impl Seed<Server> {
    pub(super) fn server(ids: accept::Ids) -> Self {
        let accept::Ids {
            initial_dcid: initial,
            local_cid: local,
            peer_cid: peer,
            tp_original_dcid: original,
            retry_scid: retry,
            peer_address_validated: valid,
            issued_address_token: token,
        } = ids;
        Self {
            base: Base {
                initial_dcid: initial,
                local_cid: local,
                original_dcid: original,
                retry_scid: retry,
                peer_address_validated: valid,
                peer_cid: peer,
                peer_first_scid: Some(peer),
            },
            role: Server { token },
        }
    }
}

impl<R> Seed<R> {
    pub(super) fn into_parts(self) -> (Base, R) {
        (self.base, self.role)
    }
}

impl<R> ops::Deref for Seed<R> {
    type Target = Base;

    fn deref(&self) -> &Self::Target {
        &self.base
    }
}
