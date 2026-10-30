use crate::conn::life::options;
use crate::runtime::routing;
use crate::security::secrets;
use crate::wire::packet::cid;
use crate::wire::stream::Initiator;

pub(in crate::conn) struct Setup<'a> {
    pub identities: Identities,
    pub tokens: Tokens,
    pub peer_shard: Option<routing::Shard>,
    pub stateless_reset_secret: Option<secrets::Reset>,
    pub options: options::Identity<'a>,
}

pub(in crate::conn) struct Identities {
    pub local_cid: cid::Id,
    pub original_dcid: cid::Id,
    pub peer_cid: cid::Id,
    pub peer_first_scid: Option<cid::Id>,
}

pub(in crate::conn) enum Tokens {
    Client(Vec<u8>),
    Server(Option<[u8; secrets::Address::WIRE_LEN]>),
}

impl Tokens {
    pub(in crate::conn) const fn initiator(&self) -> Initiator {
        match self {
            Self::Client(_) => Initiator::Client,
            Self::Server(_) => Initiator::Server,
        }
    }
}
