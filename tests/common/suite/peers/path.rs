use crate::common::peer::{self, Pair, Receiver, Setup};
use crate::common::suite::peers::tls;
use dope_quic::conn::life::options::Options;
use dope_quic::conn::{self, output::transmit, wire::packet::Batch};
use dope_quic::errors::SendFailure;
use dope_quic::proto::param;
use dope_quic::runtime::routing;
use dope_quic::wire::packet::cid;
use o3::buffer::storage;
use std::time::{Duration, Instant};

pub const MTU_CID: [u8; 8] = [0x42; 8];
pub const ACK_DELAY: Duration = Duration::from_millis(20);
const CID: [u8; 8] = [0x44; 8];

#[derive(Debug)]
pub enum Error {
    Send(SendFailure<Vec<u8>>),
    Output(transmit::Error),
}

fn params(max: u64) -> param::Builder {
    param::Set::builder().idle_ms(30_000).datagram(Some(max))
}

fn try_options(draft: param::Builder) -> Result<Options, Setup> {
    let params = draft.try_build().map_err(Setup::Params)?;
    Options::try_from(params).map_err(Setup::Options)
}

fn try_limits<const CAP: usize>() -> Result<Options, Setup> {
    let params = params(65_535)
        .cid_limit(8)
        .try_build()
        .map_err(Setup::Params)?;
    Options::builder()
        .transport(|path| path.params(params))
        .journals(|journals| journals.control::<CAP>())
        .try_build()
        .map_err(Setup::Options)
}

pub fn try_pair<const CAP: usize>() -> Result<Pair, Setup> {
    let id = cid::Id::try_from(CID).map_err(Setup::Id)?;
    let mut pair = Pair::try_with(try_limits::<CAP>()?, try_limits::<CAP>()?, id)?;
    for _ in 0..2 {
        pair.server
            .receive_from(&mut pair.work, &mut pair.client, Instant::now())
            .map_err(Setup::Server)?;
        pair.client
            .receive_from(&mut pair.work, &mut pair.server, Instant::now())
            .map_err(Setup::Client)?;
    }
    pair.server
        .receive_from(&mut pair.work, &mut pair.client, Instant::now())
        .map_err(Setup::Server)?;
    Ok(pair)
}

pub fn try_initial() -> Result<conn::Connection, Setup> {
    let (_, key) = peer::raw(0x39).map_err(Setup::Identity)?;
    let id = cid::Id::try_from(CID).map_err(Setup::Id)?;
    tls::client(key)
        .map_err(Setup::Tls)?
        .connect::<0, Vec<u8>, storage::Shared>(id, id, try_limits::<8_192>()?, routing::Plain)
        .map_err(Setup::Connect)
}

pub fn try_mtu(local: u64, peer: u64) -> Result<Pair, Setup> {
    let id = cid::Id::try_from(MTU_CID).map_err(Setup::Id)?;
    Pair::try_with(try_options(params(peer))?, try_options(params(local))?, id)
}

pub fn try_ack() -> Result<(Pair, Instant), Setup> {
    let mut pair = Pair::try_new(
        try_options(params(65_535).ack_ms(ACK_DELAY.as_millis() as u64))?,
        try_options(params(65_535).ack_ms(ACK_DELAY.as_millis() as u64))?,
    )?;
    let at = Instant::now();
    let delay = Duration::from_secs(1);
    let start = at.checked_add(delay).ok_or(Setup::Deadline(at, delay))?;
    let mut now = start;
    for turn in 0..64 {
        let delay = Duration::from_millis(turn * 5);
        now = start
            .checked_add(delay)
            .ok_or(Setup::Deadline(start, delay))?;
        pair.exchange(now, 1)?;
    }
    Ok((
        pair,
        now.checked_add(delay).ok_or(Setup::Deadline(now, delay))?,
    ))
}

pub fn try_packets(
    server: &mut conn::Connection,
    now: Instant,
    packets: usize,
) -> Result<Batch, Error> {
    for byte in 0..packets as u8 {
        server
            .with_scope(|mut scope| scope.datagrams().try_send(vec![byte; 1_100]))
            .map_err(Error::Send)?;
    }
    let mut batch = Batch::default();
    server
        .with_scope(|mut scope| scope.output().send_batch(&mut batch, now, packets, 1_200))
        .map_err(Error::Output)?;
    Ok(batch)
}
