use crate::common::peer;
pub mod bytes;
mod pair;
pub mod params;
mod wire;
pub use pair::Pair;

use std::{mem, net::Ipv4Addr, sync::Arc};

use dope_quic::{
    conn::{Epoch, State},
    proto::param,
    wire::{
        frame::{self, decode::error},
        packet::{
            cid, decode,
            long::{initial, setup},
        },
        varint::{self, VarInt},
    },
};
use o3::{
    alloc,
    buffer::write::{Sink, consume},
};
use peer::{Initial, sealer};
use rustls::{ClientConfig, Side, pki_types::ServerName, quic};
use sealer::Raw;
use wire::Wire;

pub const CID: [u8; 8] = [0x59; 8];

#[derive(Debug)]
pub enum Error {
    Setup(peer::Setup),
    Allocation(alloc::Error),
    Tls(dope_tls::Error),
    Id(consume::Error),
    Header(decode::Error),
    VarInt(varint::Error),
    Frame(error::Error),
    Wire(peer::Wire),
    Key(sealer::NewError),
    Seal(sealer::SealError),
    Epoch(Epoch),
    Empty(Epoch),
    NotDone,
    Oid { length: usize, matches: usize },
    Offset { expected: u64, actual: u64 },
    Number(u64),
    State(State),
}

pub struct Session {
    tls: quic::Connection,
    wire: Wire,
    initial: Raw,
    local: cid::Id,
    target: cid::Id,
    offsets: [u64; 2],
    number: u64,
}

impl Session {
    pub fn try_new(config: ClientConfig, params: &param::Set) -> Result<Self, Error> {
        let local = cid::Id::try_from(CID).map_err(Error::Id)?;
        let mut encoded = Vec::new();
        params
            .bind_client(&local)
            .encode(&mut encoded)
            .map_err(Error::Allocation)?;
        Self::try_parts(config, local, encoded)
    }

    pub fn try_encoded(config: ClientConfig, encoded: Vec<u8>) -> Result<Self, Error> {
        let local = cid::Id::try_from(CID).map_err(Error::Id)?;
        Self::try_parts(config, local, encoded)
    }

    fn try_parts(config: ClientConfig, local: cid::Id, encoded: Vec<u8>) -> Result<Self, Error> {
        let tls = quic::ClientConnection::new(
            Arc::new(config),
            quic::Version::V1,
            ServerName::IpAddress(Ipv4Addr::LOCALHOST.into()),
            encoded,
        )
        .map_err(dope_tls::Error::Tls)
        .map_err(Error::Tls)?;
        let mut wire = Wire::default();
        wire.early = tls
            .zero_rtt_keys()
            .map(|keys| Raw::from_keys(keys, 0))
            .transpose()
            .map_err(Error::Key)?;
        let mut peer = Self {
            tls: tls.into(),
            wire,
            initial: Raw::initial(&CID, Side::Server, 0).map_err(Error::Key)?,
            local,
            target: local,
            offsets: [0; 2],
            number: 0,
        };
        peer.wire.write(&mut peer.tls, peer.number)?;
        Ok(peer)
    }

    pub fn initial(&mut self) -> Result<Vec<u8>, Error> {
        let bytes = mem::take(&mut self.wire.output[0]);
        if bytes.is_empty() {
            return Err(Error::Empty(Epoch::Initial));
        }
        let frame = bytes::crypto(VarInt::ZERO, &bytes)?;
        Initial::new(&CID, &CID, 0)
            .seal(&frame)
            .map_err(Error::Wire)
    }

    /// Decodes packet prefixes before accessing their validated extents.
    pub fn receive(&mut self, mut wire: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        while !wire.is_empty() {
            let first = wire[0];
            if first & 0x80 == 0 {
                let mut packet = Vec::new();
                packet.write_slice(wire).map_err(Error::Allocation)?;
                return Ok(Some(packet));
            }
            let kind = (first >> 4) & 3;
            if kind != 0 && kind != 2 {
                return Err(Error::Header(decode::Error::Type { first }));
            }
            let (mut offset, length) = if kind == 0 {
                let prefix = initial::Prefix::decode(wire).map_err(Error::Header)?;
                self.target = prefix.scid.into_owned();
                let offset = 7 + prefix.dcid.len() + prefix.scid.len();
                (
                    offset + (1usize << (wire[offset] >> 6)) + prefix.token.len(),
                    prefix.length,
                )
            } else {
                let prefix = setup::Prefix::decode(wire).map_err(Error::Header)?;
                self.target = prefix.scid.into_owned();
                (7 + prefix.dcid.len() + prefix.scid.len(), prefix.length)
            };
            offset += 1usize << (wire[offset] >> 6);
            let end = offset + length;
            let mut packet = wire[..end].to_vec();
            wire = &wire[end..];
            let (index, data) = if kind == 0 {
                (
                    0,
                    self.initial
                        .open(&mut packet, offset)
                        .map_err(Error::Seal)?
                        .1,
                )
            } else {
                let read = self
                    .wire
                    .read
                    .as_mut()
                    .ok_or(Error::Epoch(Epoch::Handshake))?;
                (1, read.open(&mut packet, offset).map_err(Error::Seal)?.1)
            };
            for frame in frame::Frame::decode_all(&data).map_err(Error::Frame)? {
                if let frame::View::Crypto { offset, data } = frame.view() {
                    if offset.get() != self.offsets[index] {
                        return Err(Error::Offset {
                            expected: self.offsets[index],
                            actual: offset.get(),
                        });
                    }
                    self.offsets[index] += data.len() as u64;
                    self.tls
                        .read_hs(data)
                        .map_err(dope_tls::Error::Tls)
                        .map_err(Error::Tls)?;
                    self.wire.write(&mut self.tls, self.number)?;
                }
            }
        }
        Ok(None)
    }

    pub fn finish(&mut self, corrupt: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        if self.tls.is_handshaking() {
            return Err(Error::NotDone);
        }
        let mut bytes = mem::take(&mut self.wire.output[1]);
        if bytes.is_empty() {
            return Err(Error::Empty(Epoch::Handshake));
        }
        if let Some(oid) = corrupt {
            if oid.is_empty() {
                return Err(Error::Oid {
                    length: 0,
                    matches: 0,
                });
            }
            let (matches, position) = bytes
                .windows(oid.len())
                .enumerate()
                .filter(|(_, bytes)| *bytes == oid)
                .fold((0, 0), |(count, _), (offset, _)| (count + 1, offset));
            if matches != 1 {
                return Err(Error::Oid {
                    length: oid.len(),
                    matches,
                });
            }
            bytes[position + oid.len() - 1] = 0x7f;
        }
        self.handshake(&bytes)
    }

    fn long_header(&self, first: u8, len: usize, number: u64) -> Result<Vec<u8>, Error> {
        let number = u32::try_from(number).map_err(|_| Error::Number(number))?;
        let mut header = vec![first, 0, 0, 0, 1];
        header.push(self.target.as_slice().len() as u8);
        header.extend(self.target.as_slice());
        header.push(self.local.as_slice().len() as u8);
        header.extend(self.local.as_slice());
        let length = (4 + len + 16) as u64;
        VarInt::new(length)
            .ok_or(Error::VarInt(varint::Error::TooLarge { value: length }))?
            .encode(&mut header)
            .map_err(Error::Allocation)?;
        header.extend(number.to_be_bytes());
        Ok(header)
    }

    fn handshake(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let frame = bytes::crypto(VarInt::ZERO, bytes)?;
        let header = self.long_header(0xe3, frame.len(), 0)?;
        self.wire
            .write
            .as_mut()
            .ok_or(Error::Epoch(Epoch::Handshake))?
            .seal(&header, &frame, 0, header.len() - 4, 4)
            .map_err(Error::Seal)
    }

    pub fn early(&mut self, frames: &[u8]) -> Result<Vec<u8>, Error> {
        let header = self.long_header(0xd3, frames.len(), self.number)?;
        let packet = self
            .wire
            .early
            .as_mut()
            .ok_or(Error::Epoch(Epoch::Application))?
            .seal(&header, frames, self.number, header.len() - 4, 4)
            .map_err(Error::Seal)?;
        self.number += 1;
        Ok(packet)
    }

    pub fn open(&mut self, packet: &mut [u8]) -> Result<(u64, Vec<u8>), Error> {
        let (read, _) = self
            .wire
            .application
            .as_mut()
            .ok_or(Error::Epoch(Epoch::Application))?;
        read.open(packet, 1 + self.local.as_slice().len())
            .map_err(Error::Seal)
    }

    pub fn packet(&mut self, frames: &[u8]) -> Result<Vec<u8>, Error> {
        let mut header = vec![0x43];
        header.extend(self.target.as_slice());
        let offset = header.len();
        let number = u32::try_from(self.number).map_err(|_| Error::Number(self.number))?;
        header.extend(number.to_be_bytes());
        let (_, seal) = self
            .wire
            .application
            .as_mut()
            .ok_or(Error::Epoch(Epoch::Application))?;
        let packet = seal
            .seal(&header, frames, self.number, offset, 4)
            .map_err(Error::Seal)?;
        self.number += 1;
        Ok(packet)
    }
}
