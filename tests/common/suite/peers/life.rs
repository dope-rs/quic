use crate::common::peer::{Pair, Setup};
use dope_quic::conn::life::options::Options;
use dope_quic::proto::param;
use dope_quic::wire::packet::cid;

fn options(idle: u64) -> Result<Options, Setup> {
    let params = param::Set::builder()
        .idle_ms(idle)
        .datagram(Some(65_535))
        .try_build()
        .map_err(Setup::Params)?;
    Options::try_from(params).map_err(Setup::Options)
}

pub fn try_pair(idle: u64) -> Result<Pair, Setup> {
    let id = cid::Id::try_from([0x42; 8]).map_err(Setup::Id)?;
    Pair::try_with(options(idle)?, options(idle)?, id)
}
