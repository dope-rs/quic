use crate::common::peer;
use dope_quic::conn::{
    self,
    life::{accept, options::Options},
};
use dope_quic::wire::packet::cid;
use o3::buffer::storage;
use peer::Setup;

pub const INITIAL_DCID: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce];
pub const CLIENT_SCID: [u8; 4] = [1, 2, 3, 4];
pub const SERVER_CID: [u8; 8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

pub struct Server {
    pub conn: conn::Connection,
    pub work: conn::Workspace,
}

impl Server {
    pub fn try_new() -> Result<Self, Setup> {
        let ids = accept::Ids::initial(
            cid::Id::try_from(INITIAL_DCID).map_err(Setup::Id)?,
            cid::Id::try_from(SERVER_CID).map_err(Setup::Id)?,
            cid::Id::try_from(CLIENT_SCID).map_err(Setup::Id)?,
        );
        let (signing, _) = peer::raw(0x61).map_err(Setup::Identity)?;
        let config = signing.server().map_err(Setup::Tls)?;
        let conn = accept::Authority::new(config, Options::default())
            .map_err(Setup::Authority)?
            .accept::<storage::Shared>(ids)
            .map_err(Setup::Accept)?;
        Ok(Self {
            conn,
            work: conn::Workspace::try_new().map_err(Setup::Workspace)?,
        })
    }
}
