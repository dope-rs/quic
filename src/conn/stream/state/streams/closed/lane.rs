use crate::conn::stream::state::streams::closed::half::Kind;

pub(super) trait Lane {
    const KIND: Kind;
}

pub(super) enum LocalRecv {}
pub(super) enum PeerBidiRecv {}
pub(super) enum PeerUniRecv {}
pub(super) enum PeerBidiSend {}

impl Lane for LocalRecv {
    const KIND: Kind = Kind::LocalBidiRecv;
}

impl Lane for PeerBidiRecv {
    const KIND: Kind = Kind::PeerBidiRecv;
}

impl Lane for PeerUniRecv {
    const KIND: Kind = Kind::PeerUniRecv;
}

impl Lane for PeerBidiSend {
    const KIND: Kind = Kind::PeerBidiSend;
}
