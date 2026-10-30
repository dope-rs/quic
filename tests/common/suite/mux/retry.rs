use crate::common::peer;
use crate::common::suite::peers::tls;
use crate::common::{peer::Setup, suite::retry::Capture};
use dope_quic::conn::Connection;
use dope_quic::conn::life::{accept, options::Options};
use dope_quic::proto::param;
use dope_quic::runtime::mux::{builder, router};
use dope_quic::runtime::routing::Plain;
use dope_quic::wire::packet::{QUIC_V1, cid, decode, long::retry};
use o3::alloc;
use o3::buffer::{
    storage,
    write::{Sink as _, consume},
};

pub const CLIENT_CID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
pub const UNKNOWN_TOKEN: [u8; 16] = [
    0xaa, 0xab, 0xa8, 0xa9, 0xae, 0xaf, 0xac, 0xad, 0xa2, 0xa3, 0xa0, 0xa1, 0xa6, 0xa7, 0xa4, 0xa5,
];
const CID: [u8; 8] = [0x55; 8];
pub const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
pub const RFC_HEADER: [u8; 20] = [
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
    0x6f, 0x6b, 0x65, 0x6e,
];
pub const RFC_TAG: [u8; 16] = [
    0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
];

pub fn try_server(
    options: Options,
    limits: builder::Plan,
) -> Result<router::Router<Capture>, Setup> {
    let (signing, _) = peer::raw(0x39).map_err(Setup::Identity)?;
    let auth = accept::Authority::new(signing.server().map_err(Setup::Tls)?, options)
        .map_err(Setup::Authority)?;
    builder::Builder::server(Capture { certificates: 0 }, auth)
        .limits(limits)
        .build()
        .map_err(Setup::ServerBuild)
}

pub fn try_required(secret: [u8; 32]) -> Result<router::Router<Capture>, Setup> {
    let cfg = Options::builder()
        .security(|security| security.retry(secret))
        .try_build()
        .map_err(Setup::Options)?;
    try_server(cfg, builder::Plan::standard())
}

pub fn try_reset(
    secret: [u8; 32],
    limits: builder::Plan,
) -> Result<router::Router<Capture>, Setup> {
    let cfg = Options::builder()
        .security(|security| security.reset(Some(secret)))
        .try_build()
        .map_err(Setup::Options)?;
    try_server(cfg, limits)
}

pub fn try_client(initial: &[u8], options: Options) -> Result<Connection, Setup> {
    tls::client([0xAB; 32])
        .map_err(Setup::Tls)?
        .connect::<0, Vec<u8>, storage::Shared>(
            cid::Id::try_from(initial).map_err(Setup::Id)?,
            cid::Id::try_from(CLIENT_CID).map_err(Setup::Id)?,
            options,
            Plain,
        )
        .map_err(Setup::Connect)
}

pub fn try_config(secret: Option<[u8; 32]>) -> Result<Options, Setup> {
    let params = param::Set::builder()
        .idle_ms(30_000)
        .datagram(Some(65535))
        .cid_limit(8)
        .try_build()
        .map_err(Setup::Params)?;
    Options::builder()
        .transport(|net| net.params(params))
        .security(|security| security.reset(secret))
        .try_build()
        .map_err(Setup::Options)
}

#[derive(Debug)]
pub enum Verify {
    Decode(decode::Error),
    Original(consume::Error),
    Destination(consume::Error),
    Storage(retry::Fault),
}

pub fn try_verify<'wire, 'storage>(
    wire: &'wire [u8],
    orig: &[u8],
    dest: &[u8],
    storage: &'storage mut Vec<u8>,
) -> Result<Option<retry::Verified<'wire, 'storage>>, Verify> {
    retry::Ref::decode(wire)
        .map_err(Verify::Decode)?
        .verify_into(
            cid::Ref::new(orig).map_err(Verify::Original)?,
            cid::Ref::new(dest).map_err(Verify::Destination)?,
            storage,
        )
        .map_err(Verify::Storage)
}

#[derive(Debug)]
pub enum Wire {
    Destination(consume::Error),
    Source(consume::Error),
    Original(consume::Error),
    Allocation(alloc::Error),
    Crypto(retry::Crypto),
}

pub fn try_tag(odcid: &[u8], head: &[u8]) -> Result<[u8; retry::INTEGRITY_TAG_LEN], Wire> {
    let odcid = cid::Ref::new(odcid).map_err(Wire::Original)?;
    let mut aad = Vec::new();
    aad.write_slices([&[odcid.length().get()], odcid.into_slice(), head])
        .map_err(Wire::Allocation)?;
    retry::Key::try_new()
        .map_err(Wire::Crypto)?
        .tag_from_aad(&aad)
        .map_err(Wire::Crypto)
}

pub fn try_wire(odcid: &[u8], echo: &[u8], new_scid: &[u8], token: &[u8]) -> Result<Vec<u8>, Wire> {
    let dcid = cid::Ref::new(echo).map_err(Wire::Destination)?;
    let scid = cid::Ref::new(new_scid).map_err(Wire::Source)?;
    let mut wire = retry::Suffix::encode_into(Vec::new(), QUIC_V1, dcid, scid, token)
        .map_err(|rejected| Wire::Allocation(rejected.into_parts().1))?;
    let tag = try_tag(odcid, wire.as_ref())?;
    wire.append().write_slice(&tag).map_err(Wire::Allocation)?;
    Ok(wire.into_storage())
}

pub fn try_tail(first: u8, len: usize, token: [u8; 16]) -> Option<Vec<u8>> {
    let mut wire = vec![first; len];
    *wire.last_chunk_mut::<16>()? = token;
    Some(wire)
}

pub fn short(dcid: &[u8], len: usize) -> Result<Vec<u8>, consume::Error> {
    consume::Error::check(1, len)?;
    consume::Error::check(dcid.len(), len - 1)?;
    let mut wire = vec![0x40; len];
    wire[1..1 + dcid.len()].copy_from_slice(dcid);
    Ok(wire)
}

pub fn handshake() -> Vec<u8> {
    let mut wire = vec![0u8; 30];
    wire[0] = 0xE0;
    wire[1..5].copy_from_slice(&1u32.to_be_bytes());
    wire[5] = 8;
    wire[6..14].copy_from_slice(&[0x91; 8]);
    wire[14] = 8;
    wire[15..23].copy_from_slice(&[0x92; 8]);
    wire
}

pub fn try_fresh() -> Result<Connection, Setup> {
    let (_, key) = peer::raw(0x39).map_err(Setup::Identity)?;
    let id = cid::Id::try_from(CID).map_err(Setup::Id)?;
    tls::client(key)
        .map_err(Setup::Tls)?
        .connect::<0, Vec<u8>, storage::Shared>(id, id, try_config(None)?, Plain)
        .map_err(Setup::Connect)
}

pub fn try_ceiling() -> Result<Options, Setup> {
    Options::builder()
        .transport(|net| net.max_pmtu(1200))
        .try_build()
        .map_err(Setup::Options)
}
