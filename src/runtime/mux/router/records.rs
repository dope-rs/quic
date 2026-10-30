use crate::wire::packet::cid;

pub(in crate::runtime::mux) enum AddressProof {
    Unvalidated,
    Retry { odcid: cid::Id },
    NewToken,
}
